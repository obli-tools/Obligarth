// Package mdm is the device surface of apple-edge: the router of
// /t/<key>/{mdm,checkin,scep}, the limits and rate limiters, the verifier
// that checks device identities against the CA of the tenant named in the
// URL, and the guard placed in front of NanoMDM's certauth and core
// services (topic, namespacing, cross-tenant policy, secrets, outbox).
package mdm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/cryptoutil"
	httpmdm "github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/plist"

	"github.com/MeeJay/Obligarth/apple-edge/internal/config"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ratelimit"
	"github.com/MeeJay/Obligarth/apple-edge/internal/reqctx"
	"github.com/MeeJay/Obligarth/apple-edge/internal/tenant"
)

// Rate limits of the device surface.
const (
	DeviceRate, DeviceBurst       = 5, 60
	TenantRate, TenantBurst       = 500, 2000
	SCEPRate, SCEPBurst           = 20, 100
	FailWindow, FailBlock         = time.Minute, 5 * time.Minute
	largeBody               int64 = 1 << 20
)

// Retry-After values (seconds).
const (
	retryOverload  = "30"
	retryDevice    = "60"
	retrySuspended = "3600"
)

type ctxKeyState struct{}

// state is the per-request state shared by the layers of the surface.
type state struct {
	tenant    *tenant.Tenant
	requestID string
	stage     string // signature, verified, refused
	certSHA   string
	issued    *issuedInfo
}

func stateFrom(ctx context.Context) *state {
	s, _ := ctx.Value(ctxKeyState{}).(*state)
	return s
}

// Surface is the HTTP handler of the device listener.
type Surface struct {
	reg      *tenant.Registry
	cfg      *config.Config
	logger   *obs.Logger
	metrics  *obs.Metrics
	verifier *Verifier
	mdm      http.Handler
	checkin  http.Handler
	inflight chan struct{}
	large    chan struct{}

	tenantLim *ratelimit.Limiter
	deviceLim *ratelimit.Limiter
	scepLim   *ratelimit.Limiter
	failLim   *ratelimit.FailLimiter
}

// NewSurface assembles the device surface around the guard and verifier.
func NewSurface(cfg *config.Config, reg *tenant.Registry, g *Guard, v *Verifier, logger *obs.Logger, m *obs.Metrics) *Surface {
	s := &Surface{
		reg: reg, cfg: cfg, logger: logger.With("component", "device"), metrics: m, verifier: v,
		inflight:  make(chan struct{}, cfg.MaxInflight),
		large:     make(chan struct{}, cfg.LargeBodySlots),
		tenantLim: ratelimit.New(TenantRate, TenantBurst, 100000),
		deviceLim: ratelimit.New(DeviceRate, DeviceBurst, 1000000),
		scepLim:   ratelimit.New(SCEPRate, SCEPBurst, 100000),
		failLim:   ratelimit.NewFailLimiter(cfg.FailLimitPerIP, FailWindow, FailBlock, 100000),
	}
	nano := logger.With("component", "nanomdm").Nano()
	sigVerifier := httpmdm.MdmSignatureVerifierFunc(cryptoutil.VerifyMdmSignature)
	wrap := func(h http.Handler) http.Handler {
		h = s.deviceLimit(h)
		h = httpmdm.CertVerifyMiddleware(h, v, nano)
		return httpmdm.CertExtractMdmSignatureMiddleware(h, sigVerifier, httpmdm.SigLogWithLogger(nano))
	}
	s.mdm = wrap(httpmdm.CheckinAndCommandHandler(g, nano))
	s.checkin = wrap(httpmdm.CheckinHandler(g, nano))
	return s
}

// SweepLimiters drops idle limiter entries (call periodically).
func (s *Surface) SweepLimiters() {
	s.tenantLim.Sweep()
	s.deviceLim.Sweep()
	s.scepLim.Sweep()
	s.failLim.Sweep()
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// uniformErrors hides error bodies written by libraries (the SCEP transport
// copies error texts): any status >= 400 gets the plain status text.
type uniformErrors struct {
	http.ResponseWriter
	failed bool
}

func (w *uniformErrors) WriteHeader(code int) {
	if code >= 400 && !w.failed {
		w.failed = true
		h := w.ResponseWriter.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Del("Content-Length")
		w.ResponseWriter.WriteHeader(code)
		_, _ = io.WriteString(w.ResponseWriter, http.StatusText(code)+"\n")
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *uniformErrors) Write(b []byte) (int, error) {
	if w.failed {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func fail(w http.ResponseWriter, code int, retryAfter string) {
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	http.Error(w, http.StatusText(code), code)
}

// ServeHTTP routes a device request.
func (s *Surface) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w := &statusWriter{ResponseWriter: rw}
	st := &state{requestID: reqctx.RequestIDFromHeader(r.Header.Get("X-Request-ID"))}
	route, tenantLabel := "other", ""
	defer func() {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		d := time.Since(start)
		s.metrics.HTTPRequests.Inc("device", route, strconv.Itoa(w.status), tenantLabel)
		s.metrics.HTTPDuration.Observe(d.Seconds(), "device", route)
		kv := []any{"msg", "request", "route", route, "method", r.Method, "status", w.status,
			"duration_ms", d.Milliseconds(), "tenant", tenantLabel, "request_id", st.requestID}
		if w.status >= 500 {
			s.logger.Info(kv...)
		} else {
			s.logger.Debug(kv...)
		}
	}()
	w.Header().Set("X-Request-ID", st.requestID)

	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.metrics.RateLimited.Inc("inflight")
		fail(w, http.StatusServiceUnavailable, retryOverload)
		return
	}
	if r.URL.Path == "/healthz" {
		route = "healthz"
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			fail(w, http.StatusMethodNotAllowed, "")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	source := s.clientAddr(r)
	if s.failLim.Blocked(source) {
		s.metrics.RateLimited.Inc("source")
		fail(w, http.StatusTooManyRequests, strconv.Itoa(int(FailBlock.Seconds())))
		return
	}
	key, op, ok := splitPath(r.URL.EscapedPath())
	if !ok {
		s.failLim.Fail(source)
		fail(w, http.StatusNotFound, "")
		return
	}
	t := s.reg.Get(key)
	if t == nil {
		route = "unknown"
		s.failLim.Fail(source)
		fail(w, http.StatusNotFound, "")
		return
	}
	tenantLabel = t.Key
	switch op {
	case "mdm", "checkin", "scep":
		route = op
	default: // including the reserved acme/ and ddm/ prefixes
		fail(w, http.StatusNotFound, "")
		return
	}
	if t.State == tenant.StateSuspended {
		fail(w, http.StatusServiceUnavailable, retrySuspended)
		return
	}
	if !t.Serviceable() {
		fail(w, http.StatusServiceUnavailable, retryOverload)
		return
	}
	if !s.tenantLim.Allow(t.Key) {
		s.metrics.RateLimited.Inc("tenant")
		fail(w, http.StatusServiceUnavailable, retryOverload)
		return
	}
	st.tenant = t
	ctx := context.WithValue(reqctx.WithRequestID(r.Context(), st.requestID), ctxKeyState{}, st)
	switch op {
	case "scep":
		s.serveSCEP(w, r.WithContext(ctx), t)
	default:
		s.serveMDM(w, r.WithContext(ctx), op, source, st)
	}
}

// splitPath parses "/t/<key>/<op>" (op may contain more segments).
func splitPath(p string) (key, op string, ok bool) {
	rest, found := strings.CutPrefix(p, "/t/")
	if !found {
		return "", "", false
	}
	key, op, found = strings.Cut(rest, "/")
	if !found || !ids.ValidTenantKey(key) || op == "" {
		return "", "", false
	}
	return key, op, true
}

func (s *Surface) serveMDM(w *statusWriter, r *http.Request, op, source string, st *state) {
	if r.Method != http.MethodPut {
		fail(w, http.StatusMethodNotAllowed, "")
		return
	}
	limit, timeout := s.cfg.BodyMDM, s.cfg.TimeoutMDM
	if op == "checkin" {
		limit, timeout = s.cfg.BodyCheckin, s.cfg.TimeoutCheckin
	}
	body, release, code := s.readBody(r, limit)
	if code != 0 {
		fail(w, code, retryIfOverload(code))
		return
	}
	defer release()
	// Query parameters would reach NanoMDM as forgeable Params.
	r.URL.RawQuery = ""
	isCheckin := op == "checkin" || strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-apple-aspen-mdm-checkin")
	if isCheckin {
		var mt struct{ MessageType string }
		if err := plist.Unmarshal(body, &mt); err == nil && mt.MessageType == "ReturnToService" {
			s.metrics.Checkins.Inc(st.tenant.Key, "ReturnToService", "refused")
			fail(w, http.StatusBadRequest, "")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	r = r.WithContext(ctx)
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	st.stage = "signature"
	if op == "checkin" {
		s.checkin.ServeHTTP(w, r)
	} else {
		s.mdm.ServeHTTP(w, r)
	}
	if w.status == http.StatusBadRequest && st.stage == "signature" {
		if h := r.Header.Get("Mdm-Signature"); h != "" {
			s.verifier.ReportSignatureFailure(r.Context(), st.tenant, h, body)
		}
	}
	if w.status == http.StatusBadRequest && (st.stage == "signature" || st.stage == "refused") {
		s.failLim.Fail(source)
	}
}

func retryIfOverload(code int) string {
	if code == http.StatusServiceUnavailable {
		return retryOverload
	}
	return ""
}

// readBody reads the whole body within limit. Bodies above 1 MiB need one
// of the large-body slots. It returns a status code on failure.
func (s *Surface) readBody(r *http.Request, limit int64) ([]byte, func(), int) {
	release := func() {}
	if r.ContentLength > limit {
		return nil, release, http.StatusRequestEntityTooLarge
	}
	takeSlot := func() bool {
		select {
		case s.large <- struct{}{}:
			release = func() { <-s.large }
			return true
		default:
			s.metrics.RateLimited.Inc("large_body")
			return false
		}
	}
	if r.ContentLength > largeBody && !takeSlot() {
		return nil, release, http.StatusServiceUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		release()
		return nil, func() {}, http.StatusBadRequest
	}
	if int64(len(body)) > limit {
		release()
		return nil, func() {}, http.StatusRequestEntityTooLarge
	}
	if r.ContentLength < 0 && int64(len(body)) > largeBody && !takeSlot() {
		return nil, func() {}, http.StatusServiceUnavailable
	}
	return body, release, 0
}

func (s *Surface) serveSCEP(w *statusWriter, r *http.Request, t *tenant.Tenant) {
	op := r.URL.Query().Get("operation")
	outcome := "error"
	defer func() {
		if w.status > 0 && w.status < 400 {
			outcome = "ok"
		}
		s.metrics.SCEPRequests.Inc(t.Key, op, outcome)
	}()
	switch {
	case r.Method == http.MethodGet && (op == "GetCACaps" || op == "GetCACert" || op == "PKIOperation"):
	case r.Method == http.MethodPost && op == "PKIOperation":
	case r.Method != http.MethodGet && r.Method != http.MethodPost:
		fail(w, http.StatusMethodNotAllowed, "")
		return
	default:
		op = "other"
		fail(w, http.StatusNotFound, "")
		return
	}
	if op == "PKIOperation" && !s.scepLim.Allow(t.Key) {
		s.metrics.RateLimited.Inc("scep")
		fail(w, http.StatusServiceUnavailable, retryOverload)
		return
	}
	if r.Method == http.MethodPost {
		body, release, code := s.readBody(r, s.cfg.BodySCEP)
		if code != 0 {
			fail(w, code, retryIfOverload(code))
			return
		}
		defer release()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	} else if len(r.URL.RawQuery) > int(s.cfg.BodySCEP) {
		fail(w, http.StatusRequestEntityTooLarge, "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.TimeoutSCEP)
	defer cancel()
	r2 := r.Clone(ctx)
	r2.URL.Path, r2.URL.RawPath = "/scep", ""
	t.SCEP.ServeHTTP(&uniformErrors{ResponseWriter: w}, r2)
}

// clientAddr returns the address used by the failure limiter: the address
// relayed by a trusted proxy, or the peer address.
func (s *Surface) clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	trusted := false
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(peer) {
			trusted = true
			break
		}
	}
	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.Unmap().String()
			}
		}
	}
	return peer.String()
}

// deviceLimit applies the per-device limiter (certificate fingerprint).
func (s *Surface) deviceLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := stateFrom(r.Context())
		if st != nil && st.certSHA != "" && !s.deviceLim.Allow(st.certSHA) {
			s.metrics.RateLimited.Inc("device")
			fail(w, http.StatusServiceUnavailable, retryDevice)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var errNoState = errors.New("mdm: request without surface state")
