// Package api implements the internal API v1 of apple-edge, reserved to
// the brain: bearer token authentication (current and next token during a
// rotation), JSON in snake_case, errors as {"error": {"code", "message"}}.
package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ade"
	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/config"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/queue"
	"github.com/MeeJay/Obligarth/apple-edge/internal/reqctx"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/tenant"
)

// Evicter drops a certificate from the verifier cache after a revocation.
type Evicter interface{ Evict(sha string) }

// Disabler disables an enrollment and clears its queue (NanoMDM storage).
type Disabler interface {
	DisableEnrollment(ctx context.Context, deviceID string) error
}

// Pusher queues APNs pushes (the push scheduler).
type Pusher interface {
	Push(ctx context.Context, tenant string, enrollmentIDs []string, wait time.Duration) map[string]string
}

// Server is the internal API.
type Server struct {
	Cfg      *config.Config
	DB       *sql.DB
	Keys     *store.Keyring
	Tenants  *tenant.Service
	Reg      *tenant.Registry
	Queue    *queue.Queue
	Disabler Disabler
	Secrets  *store.Secrets
	Out      *outbox.Writer
	Verifier Evicter
	Push     Pusher
	ADE      *ade.Service
	Logger   *obs.Logger
	Metrics  *obs.Metrics
	Health   *Health
	Version  string

	tokens atomic.Pointer[[][]byte]
}

// MinTokenLength is the minimum length of an API token (32 random bytes in base64url).
const MinTokenLength = 43

// SetTokens sets the accepted bearer tokens (current, then next).
func (s *Server) SetTokens(tokens ...string) error {
	var out [][]byte
	for _, t := range tokens {
		if t == "" {
			continue
		}
		if len(t) < MinTokenLength {
			return errors.New("api: token too short (32 random bytes, 43 base64url characters at least)")
		}
		out = append(out, []byte(t))
	}
	if len(out) == 0 {
		return errors.New("api: no token")
	}
	s.tokens.Store(&out)
	return nil
}

func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return false
	}
	p := s.tokens.Load()
	if p == nil {
		return false
	}
	match := 0
	for _, t := range *p {
		match |= subtle.ConstantTimeCompare(t, []byte(tok))
	}
	return match == 1
}

// Handler returns the handler of the internal listener.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h func(http.ResponseWriter, *http.Request) error) {
		mux.Handle(pattern, s.authenticated(pattern, h))
	}
	route("GET /internal/v1/status", s.status)
	route("POST /internal/v1/tenants", s.createTenant)
	route("GET /internal/v1/tenants", s.listTenants)
	route("POST /internal/v1/device-id-transfers", s.createTransfer)
	route("POST /internal/v1/log-refs", s.logRefs)

	const t = "/internal/v1/tenants/{key}"
	route("GET "+t, s.getTenant)
	route("DELETE "+t, s.retireTenant)
	route("POST "+t+"/state", s.setState)
	route("POST "+t+"/commands-freeze", s.freeze)
	route("POST "+t+"/restore", s.restore)
	route("GET "+t+"/enrollment-config", s.enrollmentConfig)
	route("PUT "+t+"/push/certificate", s.importPushCert)
	route("GET "+t+"/push", s.listPush)
	route("POST "+t+"/scep-challenges", s.createChallenge)
	route("POST "+t+"/commands", s.enqueue)
	route("POST "+t+"/commands/{uuid}/cancel", s.cancel)
	route("GET "+t+"/enrollments", s.listEnrollments)
	route("GET "+t+"/enrollments/{id}", s.getEnrollment)
	route("POST "+t+"/enrollments/{id}/release", s.release)
	route("DELETE "+t+"/enrollments/{id}", s.purge)
	route("POST "+t+"/certificates/{sha256}/revoke", s.revoke)
	route("POST "+t+"/device-secrets/{ref}/reveal", s.reveal)

	route("POST "+t+"/push/csr", s.pushCSR)
	route("POST "+t+"/push-requests", s.pushRequests)
	route("POST "+t+"/ca/rotate", s.rotateCA)
	route("POST "+t+"/machine-info/verify", s.verifyMachineInfo)
	route("POST "+t+"/profiles/sign", s.signProfile)
	route("POST "+t+"/ade-tokens", s.createADEToken)
	route("GET "+t+"/ade-tokens", s.listADETokens)
	route("GET "+t+"/ade-tokens/{id}", s.getADEToken)
	route("PUT "+t+"/ade-tokens/{id}/token", s.uploadADEToken)
	route("DELETE "+t+"/ade-tokens/{id}", s.deleteADEToken)
	route("PUT "+t+"/ade-tokens/{id}/profiles/{usage}", s.defineADEProfile)
	route("POST "+t+"/ade-tokens/{id}/assignments", s.assignADEProfile)
	route("POST "+t+"/ade-tokens/{id}/sync", s.syncADEToken)
	route("PUT "+t+"/ade-tokens/{id}/account-driven-enrollment", s.accountDrivenEnrollment)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		s.refreshGauges(r.Context())
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = s.Metrics.Registry.WriteText(w)
	})
	return s.envelope(mux)
}

// envelope adds the version header, request ids and JSON 404/405 answers.
func (s *Server) envelope(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := reqctx.RequestIDFromHeader(r.Header.Get("X-Request-ID"))
		w.Header().Set("X-Request-ID", rid)
		w.Header().Set("X-Apple-Edge-Version", s.Version)
		r = r.WithContext(reqctx.WithRequestID(r.Context(), rid))
		sw := &statusWriter{ResponseWriter: w}
		h, pattern := mux.Handler(r)
		route := pattern
		if pattern == "" {
			route = "unmatched"
			rec := &codeRecorder{header: http.Header{}}
			h.ServeHTTP(rec, r)
			if allow := rec.header.Get("Allow"); allow != "" {
				sw.Header().Set("Allow", allow)
			}
			code := rec.code
			if code == 0 {
				code = http.StatusNotFound
			}
			errCode := "not_found"
			if code == http.StatusMethodNotAllowed {
				errCode = "method_not_allowed"
			}
			writeErrorBody(sw, code, errCode, http.StatusText(code))
		} else {
			mux.ServeHTTP(sw, r)
		}
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.Metrics.HTTPRequests.Inc("internal", route, strconv.Itoa(sw.status), "")
		s.Metrics.HTTPDuration.Observe(time.Since(start).Seconds(), "internal", route)
		if pattern != "GET /metrics" && pattern != "GET /readyz" && pattern != "GET /healthz" {
			s.Logger.Info("msg", "internal api", "component", "api", "route", route, "status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(), "request_id", rid, "actor", actorOf(r))
		}
	})
}

func actorOf(r *http.Request) string {
	a := r.Header.Get("X-Obligarth-Actor")
	if len(a) > 100 {
		a = a[:100]
	}
	return a
}

type codeRecorder struct {
	header http.Header
	code   int
}

func (c *codeRecorder) Header() http.Header         { return c.header }
func (c *codeRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (c *codeRecorder) WriteHeader(code int)        { c.code = code }

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

func (s *Server) authenticated(pattern string, h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			s.Metrics.APIAuthFailures.Inc()
			writeErrorBody(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		if err := h(w, r); err != nil {
			s.writeError(w, r, err)
		}
	})
}

func writeErrorBody(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// writeAPIError writes an API error; the targets it names, if any, go in
// "targets" (and "targets_truncated" when more were refused).
func writeAPIError(w http.ResponseWriter, e *apierr.Error) {
	if e.Targets == nil {
		writeErrorBody(w, e.Status, e.Code, e.Message)
		return
	}
	body := map[string]any{"code": e.Code, "message": e.Message, "targets": e.Targets}
	if e.TargetsTruncated {
		body["targets_truncated"] = true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": body})
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := apierr.As(err); ok {
		writeAPIError(w, e)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || store.IsLockTimeout(err) {
		writeErrorBody(w, http.StatusServiceUnavailable, "unavailable", "try again later")
		return
	}
	if store.IsUnavailable(err) {
		s.Logger.Error("msg", "database unavailable", "component", "api", "request_id", reqctx.RequestID(r.Context()), "err", err)
		writeErrorBody(w, http.StatusServiceUnavailable, "unavailable", "try again later")
		return
	}
	s.Logger.Error("msg", "internal api error", "component", "api", "request_id", reqctx.RequestID(r.Context()), "err", err)
	writeErrorBody(w, http.StatusInternalServerError, "internal", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// decode reads a JSON body of at most limit bytes into v.
func decode(r *http.Request, limit int64, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return apierr.BadRequest("Content-Type must be application/json")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return apierr.BadRequest("unreadable body")
	}
	if int64(len(body)) > limit {
		return apierr.New(http.StatusRequestEntityTooLarge, "payload_too_large", "body too large")
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return apierr.BadRequest("invalid JSON body")
	}
	return nil
}

const defaultBodyLimit = 1 << 20

// Health gathers the readiness conditions.
type Health struct {
	DB       *sql.DB
	Reg      *tenant.Registry
	SchemaOK atomic.Bool
	KeysOK   atomic.Bool
	Stopping atomic.Bool
}

// Ready checks the readiness conditions and returns the failing ones.
func (h *Health) Ready(ctx context.Context) []string {
	var causes []string
	if h.Stopping.Load() {
		causes = append(causes, "shutting_down")
	}
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if h.DB == nil || h.DB.PingContext(cctx) != nil {
		causes = append(causes, "database")
	}
	if !h.SchemaOK.Load() {
		causes = append(causes, "schema_version")
	}
	if !h.KeysOK.Load() {
		causes = append(causes, "keys")
	}
	if h.Reg == nil || !h.Reg.Loaded() {
		causes = append(causes, "registry")
	}
	return causes
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	causes := s.Health.Ready(r.Context())
	if len(causes) > 0 {
		_ = writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "causes": causes})
		return
	}
	_ = writeJSON(w, http.StatusOK, map[string]any{"ready": true})
}

func (s *Server) refreshGauges(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if lag, err := outbox.PendingLag(cctx, s.DB); err == nil {
		s.Metrics.OutboxPending.Set(float64(lag.Pending))
		s.Metrics.OutboxOldest.Set(lag.OldestSeconds)
	}
	st := s.DB.Stats()
	s.Metrics.DBPoolInUse.Set(float64(st.InUse), "main")
	s.Metrics.DBPoolWait.Set(st.WaitDuration.Seconds(), "main")
}
