// Package ddm relays the DeclarativeManagement check-ins of devices to the
// brain, which runs the whole DDM engine (declarations, synchronisation
// tokens, status). The device's Endpoint is checked against an allow-list
// and travels as data: the target URL is fixed, so a device can never
// redirect the request. Requests and responses are signed with HMAC-SHA256
// over "<timestamp>.<body>" with a key shared with the brain (v1).
//
// Signature v2 of the response (review F100): v1 signs the response alone, so
// a signed response captured on the internal network could be replayed within
// its window as the answer to any other request. Every request now carries a
// random nonce (X-Edge-Nonce); a brain that knows v2 adds
// X-Edge-Response-Signature, an HMAC that binds the response (timestamp,
// HTTP status, body) to its request (timestamp, nonce, body). When that header
// is present it is the only one that counts: a wrong v2 is refused, never
// rescued by v1. When it is absent (a brain of an older version, during a
// rolling update), the v1 signature is accepted, with a warning and the
// counter apple_edge_ddm_relay_v1_fallback_total, unless
// EDGE_DDM_RESPONSE_SIGNATURE=require-v2.
//
// TODO(F100): once every brain in production signs v2 (the counter stays at
// zero), make require-v2 the default, then remove the v1 fallback.
package ddm

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/service"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ratelimit"
	"github.com/MeeJay/Obligarth/apple-edge/internal/reqctx"
)

// Relay limits.
const (
	DefaultTimeout   = 8 * time.Second
	MaxResponse      = 2 << 20
	SignatureWindow  = 60 * time.Second
	HeaderTimestamp  = "X-Edge-Timestamp"
	HeaderSignature  = "X-Edge-Signature"
	signatureVersion = "v1="
	// HeaderNonce is the random nonce of a request, echoed in the v2
	// signature of its response (a brain of an older version ignores it).
	HeaderNonce = "X-Edge-Nonce"
	// HeaderResponseSignature carries the v2 signature of a response, bound
	// to its request.
	HeaderResponseSignature = "X-Edge-Response-Signature"
	responseV2Version       = "v2="
	// responseV2Label separates the v2 response signature from every other
	// use of the key (the v1 signatures of both directions).
	responseV2Label = "obligarth-ddm-response-v2"
	// MinKeyBytes is the minimum size of the shared HMAC key.
	MinKeyBytes = 32
	// MaxStatusBytes is the largest status report relayed: a report of Apple
	// weighs a few tens of KiB, and the brain refuses one beyond 1 MiB
	// (integration-apple-edge, INT-B5a-R4).
	MaxStatusBytes = 1 << 20
	// StatusRate and StatusBurst bound the status reports of one device (per
	// second, burst): a device that posts them in a loop occupies a worker of
	// the brain's ingestion (INT-B5a-R4, option B).
	StatusRate  = 1.0 / 15
	StatusBurst = 20
)

// EndpointRe is the allow-list of the Endpoint sent by devices.
var EndpointRe = regexp.MustCompile(`^(tokens|declaration-items|status|declaration/(activation|asset|configuration|management)/[A-Za-z0-9][A-Za-z0-9._-]{0,254})$`)

// ValidEndpoint reports whether a device Endpoint may be relayed.
func ValidEndpoint(e string) bool { return EndpointRe.MatchString(e) }

// EndpointKind is the metric label of an endpoint.
func EndpointKind(e string) string {
	switch {
	case e == "tokens", e == "declaration-items", e == "status":
		return e
	case strings.HasPrefix(e, "declaration/"):
		return "declaration"
	}
	return "invalid"
}

// ParseKey decodes the shared key file content: base64 (standard or URL,
// padded or not) of at least 32 random bytes.
func ParseKey(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(text); err == nil {
			if len(raw) < MinKeyBytes {
				return nil, fmt.Errorf("ddm: HMAC key must decode to %d bytes at least", MinKeyBytes)
			}
			return raw, nil
		}
	}
	return nil, errors.New("ddm: HMAC key is not valid base64")
}

// Sign returns the X-Edge-Signature value of body at timestamp ts.
func Sign(key []byte, ts string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return signatureVersion + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Verify checks the timestamp (window around now) and signature headers of body.
func Verify(key []byte, ts, sig string, body []byte, now time.Time) bool {
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(n, 0)); d > SignatureWindow || d < -SignatureWindow {
		return false
	}
	return hmac.Equal([]byte(Sign(key, ts, body)), []byte(sig))
}

// Response signature policies (EDGE_DDM_RESPONSE_SIGNATURE).
const (
	// ResponseSigAcceptV1 verifies v2 when the brain sends it and falls back
	// to v1 when it does not (default: a rolling update keeps working).
	ResponseSigAcceptV1 = "accept-v1"
	// ResponseSigRequireV2 refuses a response without a v2 signature.
	ResponseSigRequireV2 = "require-v2"
)

// NewNonce returns a random request nonce (128 bits, base64url, unpadded).
func NewNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SignResponseV2 returns the X-Edge-Response-Signature of a response: "v2=" +
// base64(HMAC-SHA256(key, label LF respTs LF status LF reqTs LF nonce LF
// hex(sha256(reqBody)) LF hex(sha256(respBody)))). The request's body names
// the tenant, the enrollment and the endpoint; the method and the path are
// fixed (one POST route) and left out, so that a path prefix in EDGE_DDM_URL
// (a proxy in between) cannot break the check.
func SignResponseV2(key []byte, respTs string, status int, reqTs, nonce string, reqBody, respBody []byte) string {
	m := hmac.New(sha256.New, key)
	for i, part := range []string{responseV2Label, respTs, strconv.Itoa(status), reqTs, nonce, sha256Hex(reqBody), sha256Hex(respBody)} {
		if i > 0 {
			m.Write([]byte("\n"))
		}
		m.Write([]byte(part))
	}
	return responseV2Version + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// VerifyResponseV2 checks the timestamp window and the v2 signature of a
// response against the request it answers.
func VerifyResponseV2(key []byte, respTs, sig string, status int, reqTs, nonce string, reqBody, respBody []byte, now time.Time) bool {
	n, err := strconv.ParseInt(respTs, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(n, 0)); d > SignatureWindow || d < -SignatureWindow {
		return false
	}
	return hmac.Equal([]byte(SignResponseV2(key, respTs, status, reqTs, nonce, reqBody, respBody)), []byte(sig))
}

// NewV1FallbackCounter registers the counter of Relay.V1Fallback.
func NewV1FallbackCounter(reg *obs.Registry) *obs.CounterVec {
	return reg.Counter("apple_edge_ddm_relay_v1_fallback_total",
		"DDM relay responses accepted on their v1 signature alone (brain without the v2 response signature).", "tenant")
}

// Request is the JSON body sent to the brain.
type Request struct {
	V                  int     `json:"v"`
	TenantKey          string  `json:"tenant_key"`
	EnrollmentID       string  `json:"enrollment_id"`
	EnrollmentType     string  `json:"enrollment_type"`
	ParentEnrollmentID *string `json:"parent_enrollment_id"`
	Endpoint           string  `json:"endpoint"`
	DataB64            *string `json:"data_b64"`
}

// Relay implements NanoMDM's service.DeclarativeManagement.
type Relay struct {
	URL     string
	Key     []byte
	Client  *http.Client
	Timeout time.Duration
	Logger  *obs.Logger
	Metrics *obs.Metrics
	Now     func() time.Time
	// StatusLimiter bounds the status reports per device (nil: no bound).
	StatusLimiter *ratelimit.Limiter
	// ResponseSignature is ResponseSigAcceptV1 (empty: the same) or
	// ResponseSigRequireV2.
	ResponseSignature string
	// V1Fallback counts the responses accepted on their v1 signature alone,
	// by tenant (nil: not counted).
	V1Fallback *obs.CounterVec

	fallbackLoggedAt atomic.Int64 // Unix seconds of the last fallback warning
}

// verifyResponse applies the response signature policy: it reports whether
// the response is authentic and, with v2, bound to its request.
func (r *Relay) verifyResponse(tenant string, resp *http.Response, reqTs, nonce string, reqBody, payload []byte) bool {
	now := r.now()
	ts := resp.Header.Get(HeaderTimestamp)
	if v2 := resp.Header.Get(HeaderResponseSignature); v2 != "" {
		// Present: the only signature that counts, never rescued by v1.
		return VerifyResponseV2(r.Key, ts, v2, resp.StatusCode, reqTs, nonce, reqBody, payload, now)
	}
	if r.ResponseSignature == ResponseSigRequireV2 {
		return false
	}
	if !Verify(r.Key, ts, resp.Header.Get(HeaderSignature), payload, now) {
		return false
	}
	if r.V1Fallback != nil {
		r.V1Fallback.Inc(tenant)
	}
	// One warning a minute at most: every check-in falls back until the brain is updated.
	if last := r.fallbackLoggedAt.Load(); now.Unix()-last >= 60 && r.fallbackLoggedAt.CompareAndSwap(last, now.Unix()) {
		r.Logger.Info("msg", "DDM relay: response accepted on its v1 signature only (brain without the v2 response signature, update it)",
			"component", "ddm", "severity", "warning", "tenant", tenant)
	}
	return true
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func statusErr(code int, msg string) error { return service.NewHTTPStatusError(code, errors.New(msg)) }

// DeclarativeManagement relays one DDM check-in and returns the bytes for the device.
func (r *Relay) DeclarativeManagement(req *mdm.Request, m *mdm.DeclarativeManagement) ([]byte, error) {
	start := time.Now()
	kind := EndpointKind(m.Endpoint)
	tenant := ""
	outcome := "error"
	defer func() {
		if r.Metrics != nil {
			r.Metrics.DDMRelay.Inc(tenant, kind, outcome)
			if outcome != "invalid_endpoint" {
				r.Metrics.DDMRelayDuration.Observe(time.Since(start).Seconds())
			}
		}
	}()
	if req == nil || req.EnrollID == nil {
		return nil, statusErr(http.StatusBadRequest, "no enrollment")
	}
	device := req.ID
	if req.ParentID != "" {
		device = req.ParentID
	}
	key, _, ok := ids.SplitNamespaced(device)
	if !ok {
		return nil, statusErr(http.StatusBadRequest, "enrollment id is not namespaced")
	}
	tenant = key
	if !ValidEndpoint(m.Endpoint) {
		outcome = "invalid_endpoint"
		return nil, statusErr(http.StatusBadRequest, "endpoint not allowed")
	}
	if m.Endpoint == "status" {
		if len(m.Data) > MaxStatusBytes {
			outcome = "too_large"
			return nil, statusErr(http.StatusRequestEntityTooLarge, "status report too large")
		}
		if r.StatusLimiter != nil && !r.StatusLimiter.Allow(device) {
			outcome = "rate_limited"
			return nil, statusErr(http.StatusTooManyRequests, "too many status reports")
		}
	}
	body := Request{V: 1, TenantKey: key, EnrollmentID: req.ID, EnrollmentType: req.Type.String(), Endpoint: m.Endpoint}
	if req.ParentID != "" {
		p := req.ParentID
		body.ParentEnrollmentID = &p
	}
	if len(m.Data) > 0 {
		d := base64.StdEncoding.EncodeToString(m.Data)
		body.DataB64 = &d
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(r.now().Unix(), 10)
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set(HeaderTimestamp, ts)
	hreq.Header.Set(HeaderSignature, Sign(r.Key, ts, raw))
	hreq.Header.Set(HeaderNonce, nonce)
	if rid := reqctx.RequestID(req.Context()); rid != "" {
		hreq.Header.Set("X-Request-ID", rid)
	}
	resp, err := r.Client.Do(hreq)
	if err != nil {
		outcome = "unavailable"
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			outcome = "timeout"
		}
		r.Logger.Info("msg", "DDM relay: brain unreachable", "component", "ddm", "tenant", key, "outcome", outcome, "err", err)
		return nil, statusErr(http.StatusServiceUnavailable, "brain unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		outcome = "unavailable"
		return nil, statusErr(http.StatusServiceUnavailable, "brain unavailable")
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		outcome = "unavailable"
		if ctx.Err() != nil {
			outcome = "timeout"
		}
		return nil, statusErr(http.StatusServiceUnavailable, "brain unavailable")
	}
	if len(payload) > MaxResponse {
		outcome = "too_large"
		r.Logger.Error("msg", "DDM relay: response too large", "component", "ddm", "tenant", key)
		return nil, statusErr(http.StatusBadGateway, "response too large")
	}
	if !r.verifyResponse(key, resp, ts, nonce, raw, payload) {
		outcome = "bad_signature"
		r.Logger.Error("msg", "DDM relay: unsigned or badly signed response", "component", "ddm", "tenant", key, "status", resp.StatusCode)
		return nil, statusErr(http.StatusBadGateway, "invalid response signature")
	}
	switch resp.StatusCode {
	case http.StatusOK:
		outcome = "ok"
		return payload, nil
	case http.StatusNoContent:
		outcome = "ok"
		return []byte{}, nil
	case http.StatusNotFound:
		outcome = "not_found"
		return nil, statusErr(http.StatusNotFound, "not found")
	case http.StatusBadRequest:
		outcome = "bad_request"
		return nil, statusErr(http.StatusBadRequest, "refused by the brain")
	}
	outcome = "unexpected_status"
	r.Logger.Error("msg", "DDM relay: unexpected status from the brain", "component", "ddm", "tenant", key, "status", resp.StatusCode)
	return nil, statusErr(http.StatusBadGateway, "unexpected answer")
}
