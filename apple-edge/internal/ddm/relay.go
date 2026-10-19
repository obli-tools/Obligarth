// Package ddm relays the DeclarativeManagement check-ins of devices to the
// brain, which runs the whole DDM engine (declarations, synchronisation
// tokens, status). The device's Endpoint is checked against an allow-list
// and travels as data: the target URL is fixed, so a device can never
// redirect the request. Requests and responses are signed with HMAC-SHA256
// over "<timestamp>.<body>" with a key shared with the brain.
package ddm

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
	ts := strconv.FormatInt(r.now().Unix(), 10)
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set(HeaderTimestamp, ts)
	hreq.Header.Set(HeaderSignature, Sign(r.Key, ts, raw))
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
	if !Verify(r.Key, resp.Header.Get(HeaderTimestamp), resp.Header.Get(HeaderSignature), payload, r.now()) {
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
