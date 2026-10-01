package api

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/migrate"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/queue"
	"github.com/MeeJay/Obligarth/apple-edge/internal/reqctx"
	"github.com/MeeJay/Obligarth/apple-edge/internal/scep"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store/nanomdmsql"
	"github.com/MeeJay/Obligarth/apple-edge/internal/tenant"
)

// ---------------------------------------------------------------- platform

func (s *Server) status(w http.ResponseWriter, r *http.Request) error {
	lag, err := outbox.PendingLag(r.Context(), s.DB)
	if err != nil {
		return err
	}
	expected, err := migrate.Expected()
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.Version,
		"upstream": upstreamVersions(),
		"schema":   expected,
		"tenants":  len(s.Reg.Keys()),
		"outbox":   lag,
	})
}

func upstreamVersions() map[string]string {
	out := map[string]string{}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	for _, d := range bi.Deps {
		switch d.Path {
		case "github.com/micromdm/nanomdm", "github.com/micromdm/scep/v2", "github.com/smallstep/scep",
			"github.com/smallstep/pkcs7", "github.com/lib/pq", "github.com/micromdm/plist":
			out[d.Path] = d.Version
		}
	}
	out["go"] = bi.GoVersion
	return out
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ExternalRef string `json:"external_ref"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	c, created, err := s.Tenants.Create(r.Context(), strings.ToLower(req.ExternalRef))
	if err != nil {
		return err
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	return writeJSON(w, code, c)
}

func pageParams(r *http.Request) (cursor string, limit int, err error) {
	q := r.URL.Query()
	cursor = q.Get("cursor")
	limit = 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return "", 0, apierr.BadRequest("limit must be between 1 and 1000")
		}
		limit = n
	}
	return cursor, limit, nil
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) error {
	cursor, limit, err := pageParams(r)
	if err != nil {
		return err
	}
	list, err := s.Tenants.List(r.Context(), cursor, limit)
	if err != nil {
		return err
	}
	resp := map[string]any{"tenants": list, "next_cursor": nil}
	if len(list) == limit {
		resp["next_cursor"] = list[len(list)-1].Key
	}
	return writeJSON(w, http.StatusOK, resp)
}

const maxTransferValidity = 7 * 24 * time.Hour

func (s *Server) createTransfer(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		IDKind      string     `json:"id_kind"`
		ID          string     `json:"id"`
		FromTenant  string     `json:"from_tenant"`
		ToTenant    string     `json:"to_tenant"`
		ApprovalRef string     `json:"approval_ref"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if req.IDKind != store.KindUDID {
		return apierr.Unprocessable("validation_failed", `only "udid" identifiers can be transferred (EnrollmentIDs are random per enrollment)`)
	}
	if !ids.ValidRawID(req.ID) || req.ApprovalRef == "" || len(req.ApprovalRef) > 200 {
		return apierr.BadRequest("id and approval_ref are required")
	}
	if req.FromTenant == req.ToTenant || !ids.ValidTenantKey(req.FromTenant) || !ids.ValidTenantKey(req.ToTenant) {
		return apierr.BadRequest("from_tenant and to_tenant must be two different tenant keys")
	}
	now := time.Now()
	expires := now.Add(maxTransferValidity)
	if req.ExpiresAt != nil {
		if !req.ExpiresAt.After(now) || req.ExpiresAt.After(expires.Add(time.Minute)) {
			return apierr.BadRequest("expires_at must be in the next 7 days")
		}
		expires = *req.ExpiresAt
	}
	for _, k := range []string{req.FromTenant, req.ToTenant} {
		if _, err := s.liveTenant(r, k); err != nil {
			return err
		}
	}
	id, err := store.CreateTransfer(r.Context(), s.DB, store.Transfer{Kind: req.IDKind, RawID: req.ID, From: req.FromTenant, To: req.ToTenant, ApprovalRef: req.ApprovalRef, ExpiresAt: expires})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]any{"id": id, "expires_at": expires.UTC()})
}

func (s *Server) logRefs(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		EnrollmentIDs []string `json:"enrollment_ids"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if len(req.EnrollmentIDs) == 0 || len(req.EnrollmentIDs) > 1000 {
		return apierr.BadRequest("enrollment_ids must hold 1 to 1000 ids")
	}
	refs := map[string]string{}
	for _, id := range req.EnrollmentIDs {
		refs[id] = s.Logger.Eref(id)
	}
	return writeJSON(w, http.StatusOK, map[string]any{"refs": refs})
}

// ------------------------------------------------------------------ tenant

func tenantKey(r *http.Request) (string, error) {
	k := r.PathValue("key")
	if !ids.ValidTenantKey(k) {
		return "", apierr.TenantNotFound
	}
	return k, nil
}

// tenantExists checks that a tenant exists, whatever its state.
func (s *Server) tenantExists(r *http.Request, key string) error {
	var ok bool
	if err := s.DB.QueryRowContext(r.Context(), `SELECT EXISTS (SELECT 1 FROM apple_edge.tenants WHERE key = $1)`, key).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return apierr.TenantNotFound
	}
	return nil
}

// liveTenant returns the state of an active or suspended tenant.
func (s *Server) liveTenant(r *http.Request, key string) (string, error) {
	var st string
	err := s.DB.QueryRowContext(r.Context(), `SELECT state FROM apple_edge.tenants WHERE key = $1`, key).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", apierr.TenantNotFound
	}
	if err != nil {
		return "", err
	}
	if st != tenant.StateActive && st != tenant.StateSuspended {
		return st, apierr.Conflict("tenant_not_live", "the tenant is retiring or retired")
	}
	return st, nil
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	info, err := s.Tenants.Info(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, info)
}

func (s *Server) setState(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		State string `json:"state"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if err := s.Tenants.SetState(r.Context(), key, req.State); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"key": key, "state": req.State})
}

func (s *Server) freeze(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		Frozen *bool `json:"frozen"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if req.Frozen == nil {
		return apierr.BadRequest("frozen is required")
	}
	if err := s.Tenants.Freeze(r.Context(), key, *req.Frozen); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"key": key, "commands_frozen": *req.Frozen})
}

func (s *Server) retireTenant(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.Tenants.Retire(r.Context(), key); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"key": key, "state": tenant.StateRetiring})
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.Tenants.Restore(r.Context(), key); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"key": key, "state": tenant.StateActive})
}

func (s *Server) enrollmentConfig(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	ec, err := s.Tenants.EnrollmentConfig(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, ec)
}

func (s *Server) importPushCert(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		CertPEM          string `json:"cert_pem"`
		KeyPEM           string `json:"key_pem"`
		AllowTopicChange bool   `json:"allow_topic_change"`
	}
	if err := decode(r, 64<<10, &req); err != nil {
		return err
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		return apierr.BadRequest("cert_pem and key_pem are required (step 1: import)")
	}
	info, err := s.Tenants.ImportPushCert(r.Context(), key, tenant.PushImport{CertPEM: []byte(req.CertPEM), KeyPEM: []byte(req.KeyPEM), AllowTopicChange: req.AllowTopicChange})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, info)
}

func (s *Server) listPush(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.tenantExists(r, key); err != nil {
		return err
	}
	list, err := s.Tenants.PushCerts(r.Context(), key)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"certificates": list})
}

var serialRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

func (s *Server) createChallenge(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		SessionRef string `json:"session_ref"`
		TTLSeconds int    `json:"ttl_seconds"`
		Bind       struct {
			UDID   string `json:"udid"`
			Serial string `json:"serial"`
		} `json:"bind"`
		MachineInfoID string `json:"machine_info_id"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if len(req.SessionRef) > 200 || !utf8.ValidString(req.SessionRef) {
		return apierr.BadRequest("session_ref is too long")
	}
	if req.Bind.UDID != "" && !ids.ValidRawID(req.Bind.UDID) {
		return apierr.BadRequest("bind.udid is invalid")
	}
	if req.Bind.Serial != "" && !serialRe.MatchString(req.Bind.Serial) {
		return apierr.BadRequest("bind.serial is invalid")
	}
	if req.MachineInfoID != "" {
		return apierr.Unprocessable("machine_info_unsupported", "MachineInfo verification arrives with step 2")
	}
	if _, err := s.liveTenant(r, key); err != nil {
		return err
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if req.TTLSeconds != 0 && (ttl < scep.ChallengeMinTTL || ttl > scep.ChallengeMaxTTL) {
		return apierr.BadRequest("ttl_seconds must be between 60 and 3600")
	}
	ch, id, expires, err := scep.NewChallenge(r.Context(), s.DB, key, scep.ChallengeRequest{SessionRef: req.SessionRef, TTL: ttl, BindUDID: req.Bind.UDID, BindSerial: req.Bind.Serial})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]any{"challenge": ch, "challenge_id": id, "expires_at": expires.UTC()})
}

// ---------------------------------------------------------------- commands

func (s *Server) enqueue(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req queue.EnqueueRequest
	if err := decode(r, 6<<20, &req); err != nil {
		return err
	}
	plist, err := base64.StdEncoding.DecodeString(req.CommandPlistB64)
	if err != nil {
		return apierr.BadRequest("command_plist_b64 is not standard base64")
	}
	resp, created, err := s.Queue.Enqueue(r.Context(), key, plist, req)
	if err != nil {
		return err
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	return writeJSON(w, code, resp)
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	var req struct {
		Targets []string `json:"targets"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	for _, t := range req.Targets {
		if !ids.BelongsTo(key, t) {
			return apierr.Unprocessable("target_outside_tenant", "every target must be an enrollment of this tenant")
		}
	}
	res, err := s.Queue.Cancel(r.Context(), key, r.PathValue("uuid"), req.Targets)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"command_uuid": r.PathValue("uuid"), "targets": res})
}

// ------------------------------------------------------------- enrollments

type enrollmentView struct {
	EnrollmentID string     `json:"enrollment_id"`
	DeviceID     string     `json:"device_id"`
	Type         string     `json:"type"`
	Enabled      bool       `json:"enabled"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
	CertSHA256   string     `json:"cert_sha256,omitempty"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	Proof        string     `json:"proof"`
}

func view(e nanomdmsql.Enrollment, proofs map[string]string) enrollmentView {
	_, rest, _ := ids.SplitNamespaced(e.DeviceID)
	v := enrollmentView{EnrollmentID: e.ID, DeviceID: rest, Type: e.Type, Enabled: e.Enabled, LastSeenAt: e.LastSeenAt, CreatedAt: e.CreatedAt}
	if e.IdentityPEM.Valid {
		if blk, _ := pem.Decode([]byte(e.IdentityPEM.String)); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				sum := sha256.Sum256(c.Raw)
				v.CertSHA256 = hex.EncodeToString(sum[:])
				na := c.NotAfter.UTC()
				v.CertNotAfter = &na
			}
		}
	}
	v.Proof = proofs[e.DeviceID]
	if v.Proof == "" {
		v.Proof = store.ProofNone
	}
	return v
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	if err := s.tenantExists(r, key); err != nil {
		return err
	}
	cursor, limit, err := pageParams(r)
	if err != nil {
		return err
	}
	var since *time.Time
	if v := r.URL.Query().Get("seen_since"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return apierr.BadRequest("seen_since must be RFC 3339")
		}
		since = &t
	}
	list, err := nanomdmsql.ListEnrollments(r.Context(), s.DB, store.NamespacePrefix(key), cursor, limit, since)
	if err != nil {
		return err
	}
	deviceIDs := make([]string, 0, len(list))
	for _, e := range list {
		deviceIDs = append(deviceIDs, e.DeviceID)
	}
	proofs, err := store.ProofsOf(r.Context(), s.DB, key, deviceIDs)
	if err != nil {
		return err
	}
	out := make([]enrollmentView, 0, len(list))
	for _, e := range list {
		out = append(out, view(e, proofs))
	}
	resp := map[string]any{"enrollments": out, "next_cursor": nil}
	if len(list) == limit {
		resp["next_cursor"] = list[len(list)-1].ID
	}
	return writeJSON(w, http.StatusOK, resp)
}

// enrollmentParam returns the namespaced enrollment id of the path.
func enrollmentParam(r *http.Request, key string) (string, error) {
	id := r.PathValue("id")
	if !ids.BelongsTo(key, id) {
		return "", apierr.Unprocessable("target_outside_tenant", "the enrollment does not belong to this tenant")
	}
	return id, nil
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	id, err := enrollmentParam(r, key)
	if err != nil {
		return err
	}
	e, err := nanomdmsql.GetEnrollment(r.Context(), s.DB, id)
	if errors.Is(err, nanomdmsql.ErrNotFound) {
		return apierr.NotFound("enrollment_not_found", "enrollment not found")
	}
	if err != nil {
		return err
	}
	items, err := nanomdmsql.PendingQueue(r.Context(), s.DB, id)
	if err != nil {
		return err
	}
	now := time.Now()
	queueOut := make([]map[string]any, 0, len(items))
	for _, it := range items {
		queueOut = append(queueOut, map[string]any{
			"command_uuid": it.CommandUUID, "request_type": it.RequestType, "not_now": it.Status.String == "NotNow",
			"active": it.Active, "age_seconds": int64(now.Sub(it.CreatedAt).Seconds()),
		})
	}
	proofs, err := store.ProofsOf(r.Context(), s.DB, key, []string{e.DeviceID})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"enrollment": view(e, proofs), "queue": queueOut})
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	id, err := enrollmentParam(r, key)
	if err != nil {
		return err
	}
	if strings.Contains(id, ":") {
		return apierr.Unprocessable("validation_failed", "release a device channel enrollment")
	}
	if _, err := s.liveTenant(r, key); err != nil {
		return err
	}
	ctx := r.Context()
	exists, err := nanomdmsql.DeviceExists(ctx, s.DB, id)
	if err != nil {
		return err
	}
	active, err := store.EnrollmentIDActive(ctx, s.DB, key, id)
	if err != nil {
		return err
	}
	if !exists && !active {
		return apierr.NotFound("enrollment_not_found", "enrollment not found")
	}
	if exists {
		if err := s.Disabler.DisableEnrollment(ctx, id); err != nil {
			return err
		}
	}
	var released []store.ReleasedID
	var revoked []string
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		var err error
		if released, err = store.ReleaseEnrollment(ctx, tx, key, id, "retired"); err != nil {
			return err
		}
		if err := queue.CancelOpenTargets(ctx, tx, id); err != nil {
			return err
		}
		if revoked, err = s.revokeEnrollmentCerts(r, tx, key, id, "released"); err != nil {
			return err
		}
		var evs []outbox.Event
		for _, x := range released {
			evs = append(evs, outbox.T(key, "device.id_released", map[string]any{"id_kind": x.Kind, "reason": "retired"}).WithEnrollment(id))
		}
		return s.Out.Insert(ctx, tx, evs...)
	})
	if err != nil {
		return err
	}
	s.Out.Committed()
	for _, sha := range revoked {
		s.Verifier.Evict(sha)
	}
	out := make([]map[string]string, 0, len(released))
	for _, x := range released {
		out = append(out, map[string]string{"id_kind": x.Kind, "reason": "retired"})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"enrollment_id": id, "released": out, "revoked_certificates": len(revoked)})
}

// revokeEnrollmentCerts revokes the identities associated with an enrollment.
func (s *Server) revokeEnrollmentCerts(r *http.Request, q store.Querier, key, deviceID, reason string) ([]string, error) {
	hashes, err := nanomdmsql.CertHashes(r.Context(), q, deviceID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, h := range hashes {
		ok, err := store.RevokeCert(r.Context(), q, key, h, reason)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, h)
		}
	}
	return out, nil
}

func (s *Server) purge(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	id, err := enrollmentParam(r, key)
	if err != nil {
		return err
	}
	if strings.Contains(id, ":") {
		return apierr.Unprocessable("validation_failed", "purge a device channel enrollment")
	}
	ctx := r.Context()
	if err := s.tenantExists(r, key); err != nil {
		return err
	}
	active, err := store.EnrollmentIDActive(ctx, s.DB, key, id)
	if err != nil {
		return err
	}
	enabled, err := nanomdmsql.EnabledEnrollments(ctx, s.DB, []string{id})
	if err != nil {
		return err
	}
	if active || enabled[id] {
		return apierr.Conflict("enrollment_active", "release the enrollment before purging it")
	}
	var revoked []string
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		var err error
		if revoked, err = s.revokeEnrollmentCerts(r, tx, key, id, "purged"); err != nil {
			return err
		}
		if err := nanomdmsql.PurgeDevice(ctx, tx, id); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM apple_edge.device_secrets WHERE tenant_key = $1 AND (enrollment_id = $2 OR left(enrollment_id, length($2) + 1) = $2 || ':')`,
			`DELETE FROM apple_edge.device_ids WHERE tenant_key = $1 AND enrollment_id = $2 AND state = 'released'`,
		} {
			if _, err := tx.ExecContext(ctx, q, key, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, sha := range revoked {
		s.Verifier.Evict(sha)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	sha := strings.ToLower(r.PathValue("sha256"))
	if !shaRe.MatchString(sha) {
		return apierr.BadRequest("sha256 must be 64 hexadecimal characters")
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if err := s.tenantExists(r, key); err != nil {
		return err
	}
	if req.Reason == "" {
		req.Reason = "revoked"
	}
	ok, err := store.RevokeCert(r.Context(), s.DB, key, sha, req.Reason)
	if err != nil {
		return err
	}
	if !ok {
		exists, err := store.IssuedCertExists(r.Context(), s.DB, key, sha)
		if err != nil {
			return err
		}
		if !exists {
			return apierr.NotFound("certificate_not_found", "certificate not found")
		}
	}
	s.Verifier.Evict(sha)
	return writeJSON(w, http.StatusOK, map[string]any{"sha256": sha, "revoked": true})
}

func (s *Server) reveal(w http.ResponseWriter, r *http.Request) error {
	key, err := tenantKey(r)
	if err != nil {
		return err
	}
	ref := strings.ToLower(r.PathValue("ref"))
	if !ids.ValidUUID(ref) {
		return apierr.NotFound("secret_not_found", "secret not found")
	}
	var req struct {
		Reason      string `json:"reason"`
		ApprovalRef string `json:"approval_ref"`
	}
	if err := decode(r, defaultBodyLimit, &req); err != nil {
		return err
	}
	if req.Reason == "" || req.ApprovalRef == "" {
		return apierr.BadRequest("reason and approval_ref are required")
	}
	kind, enrollment, value, err := s.Secrets.Get(r.Context(), key, ref)
	if errors.Is(err, store.ErrSecretNotFound) {
		return apierr.NotFound("secret_not_found", "secret not found")
	}
	if err != nil {
		return err
	}
	s.Logger.Info("msg", "device secret revealed", "component", "api", "tenant", key, "request_id", reqctx.RequestID(r.Context()),
		"actor", actorOf(r), "outcome", kind, "id", enrollment)
	resp := map[string]any{"kind": kind, "enrollment_id": enrollment, "value_b64": base64.StdEncoding.EncodeToString(value)}
	if kind == store.SecretBypassCode {
		resp["value"] = string(value)
	}
	return writeJSON(w, http.StatusOK, resp)
}
