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
	"github.com/MeeJay/Obligarth/apple-edge/internal/plistlimit"
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

// Bounds of a property list sent by a device, examined once its identity
// is verified and before any decoder. A check-in message holds a few dozen
// nodes; the largest command results (InstalledApplicationList of a few
// thousand applications) a few hundred thousand.
var (
	CheckinPlist = plistlimit.Limits{MaxDepth: 64, MaxElements: 10_000}
	CommandPlist = plistlimit.Limits{MaxDepth: 64, MaxElements: 500_000}
)

const (
	// HeavyPlist is the number of nodes above which decoding a body needs
	// one of the large-body slots, like a body above 1 MiB.
	HeavyPlist = 50_000
	// plistScanTimeout bounds the examination of a body.
	plistScanTimeout = 2 * time.Second
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
	body      []byte // buffered body, examined only once the identity is verified
	checkin   bool   // check-in message (route or Content-Type)
	// largeBytes is the reservation of the large-body budget held by the
	// request (0: none); largeDevice the identity that holds it, if any.
	largeBytes  int64
	largeDevice string
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
	large    *largeBudget

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
		large:     newLargeBudget(cfg.LargeBodyBudget, cfg.LargeBodyTenant, cfg.LargeBodySlots),
		tenantLim: ratelimit.New(TenantRate, TenantBurst, 100000),
		deviceLim: ratelimit.New(DeviceRate, DeviceBurst, 1000000),
		scepLim:   ratelimit.New(SCEPRate, SCEPBurst, 100000),
		failLim:   ratelimit.NewFailLimiter(cfg.FailLimitPerIP, FailWindow, FailBlock, 100000),
	}
	nano := logger.With("component", "nanomdm").Nano()
	sigVerifier := httpmdm.MdmSignatureVerifierFunc(cryptoutil.VerifyMdmSignature)
	// Signature over the raw body, identity checked against the URL
	// tenant, device limiter, then only the examination of the body.
	wrap := func(h http.Handler) http.Handler {
		h = s.bodyGate(h)
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

// jsonOnSuccess labels a non-empty successful answer as JSON.
type jsonOnSuccess struct {
	http.ResponseWriter
	wrote bool
}

func (w *jsonOnSuccess) WriteHeader(code int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *jsonOnSuccess) Write(b []byte) (int, error) {
	if !w.wrote && len(b) > 0 {
		w.wrote = true
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
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
	body, reserved, code := s.readBody(r, limit, st.tenant.Key)
	if code != 0 {
		fail(w, code, retryIfOverload(code))
		return
	}
	st.largeBytes = reserved
	defer func() {
		if st.largeDevice != "" {
			s.large.dropDevice(st.largeDevice)
		}
		if st.largeBytes > 0 {
			s.releaseLarge(st.tenant.Key, st.largeBytes)
		}
	}()
	// Query parameters would reach NanoMDM as forgeable Params.
	r.URL.RawQuery = ""
	// The body is only hashed (Mdm-Signature) until the identity of the
	// device is verified: bodyGate examines it afterwards.
	st.body = body
	st.checkin = op == "checkin" || strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-apple-aspen-mdm-checkin")
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

// tryLarge reserves n bytes of the large-body budget for tenant, without
// waiting.
func (s *Surface) tryLarge(tenant string, n int64) bool {
	if s.large.acquire(tenant, max(n, largeBody)) {
		return true
	}
	s.metrics.RateLimited.Inc("large_body")
	return false
}

func (s *Surface) releaseLarge(tenant string, n int64) { s.large.release(tenant, max(n, largeBody)) }

// readBody reads the whole body within limit. Beyond 1 MiB, announced or
// read (chunked body), a body needs a reservation of the large-body budget
// of its tenant, taken before the rest is read: its announced length, or
// the limit when the length is unknown. Without a reservation, a request
// holds at most 1 MiB. It returns the bytes reserved (the caller releases
// them), or a status code on failure.
func (s *Surface) readBody(r *http.Request, limit int64, tenant string) (body []byte, reserved int64, code int) {
	if r.ContentLength > limit {
		return nil, 0, http.StatusRequestEntityTooLarge
	}
	defer func() {
		if code != 0 && reserved > 0 {
			s.releaseLarge(tenant, reserved)
			reserved = 0
		}
	}()
	var err error
	if r.ContentLength > largeBody {
		if !s.tryLarge(tenant, r.ContentLength+1) {
			return nil, 0, http.StatusServiceUnavailable
		}
		reserved = r.ContentLength + 1
		// One buffer of the announced length (one byte more detects a
		// longer body), bounded by the budget.
		body, err = readInto(make([]byte, 0, r.ContentLength+1), r.Body)
	} else {
		// Grows with what arrives: an announced length costs nothing.
		body, err = io.ReadAll(io.LimitReader(r.Body, min(limit, largeBody)+1))
	}
	if err != nil {
		return nil, reserved, http.StatusBadRequest
	}
	if reserved == 0 && int64(len(body)) > largeBody && int64(len(body)) <= limit {
		// Unknown length beyond 1 MiB: a reservation of the limit before
		// the rest is read.
		if !s.tryLarge(tenant, limit+1) {
			return nil, 0, http.StatusServiceUnavailable
		}
		reserved = limit + 1
		full := make([]byte, len(body), limit+1)
		copy(full, body)
		if body, err = readInto(full, r.Body); err != nil {
			return nil, reserved, http.StatusBadRequest
		}
	}
	if int64(len(body)) > limit {
		return nil, reserved, http.StatusRequestEntityTooLarge
	}
	return body, reserved, 0
}

// readInto appends what r yields to buf, up to the capacity of buf.
func readInto(buf []byte, r io.Reader) ([]byte, error) {
	for len(buf) < cap(buf) {
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
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
		body, reserved, code := s.readBody(r, s.cfg.BodySCEP, t.Key)
		if code != 0 {
			fail(w, code, retryIfOverload(code))
			return
		}
		if reserved > 0 {
			defer s.releaseLarge(t.Key, reserved)
		}
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

// bodyGate examines the body of a device whose identity is verified,
// before any decoder: nesting, nodes and time are bounded (a heavy body
// takes a large-body slot). It then reads MessageType to refuse
// ReturnToService and to label DDM answers as JSON.
func (s *Surface) bodyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := stateFrom(r.Context())
		if st == nil || st.tenant == nil || st.stage != "verified" {
			fail(w, http.StatusBadRequest, "")
			return
		}
		lim := CommandPlist
		if st.checkin {
			lim = CheckinPlist
		}
		ctx, cancel := context.WithTimeout(r.Context(), plistScanTimeout)
		stats, err := plistlimit.Check(ctx, st.body, lim)
		cancel()
		switch {
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
			s.metrics.RateLimited.Inc("plist_scan")
			fail(w, http.StatusServiceUnavailable, retryOverload)
			return
		case err != nil:
			s.metrics.SecurityEvents.Inc(st.tenant.Key, "plist_refused")
			s.logger.Info("msg", "property list refused", "tenant", st.tenant.Key, "request_id", st.requestID, "err", err)
			fail(w, http.StatusBadRequest, "")
			return
		}
		if stats.Elements > HeavyPlist && st.largeBytes == 0 {
			n := max(int64(len(st.body)), largeBody)
			if !s.tryLarge(st.tenant.Key, n) {
				fail(w, http.StatusServiceUnavailable, retryOverload)
				return
			}
			st.largeBytes = n
		}
		// One reservation per device: what costs memory (decoding,
		// conversion, outbox) comes after this point.
		if st.largeBytes > 0 {
			if st.certSHA == "" || !s.large.holdDevice(st.certSHA) {
				s.metrics.RateLimited.Inc("large_body_device")
				fail(w, http.StatusServiceUnavailable, retryOverload)
				return
			}
			st.largeDevice = st.certSHA
		}
		if st.checkin {
			var mt struct{ MessageType string }
			if plist.Unmarshal(st.body, &mt) == nil {
				switch mt.MessageType {
				case "ReturnToService":
					s.metrics.Checkins.Inc(st.tenant.Key, "ReturnToService", "refused")
					fail(w, http.StatusBadRequest, "")
					return
				case "DeclarativeManagement":
					// DDM answers (tokens, items, declarations) are JSON.
					w = &jsonOnSuccess{ResponseWriter: w}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

var errNoState = errors.New("mdm: request without surface state")
