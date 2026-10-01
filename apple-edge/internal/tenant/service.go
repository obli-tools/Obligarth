package tenant

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/apierr"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store/nanomdmsql"
)

// Service implements the tenant lifecycle for the internal API.
type Service struct {
	Reg         *Registry
	DB          *sql.DB
	Keys        *store.Keyring
	Out         *outbox.Writer
	Logger      *obs.Logger
	CAYears     int
	RetireAfter time.Duration
	PublicBase  string
	Metrics     *obs.Metrics
	// APNsStatus returns the last APNs answer of a topic (nil if none).
	APNsStatus func(topic string) any
	Now        func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// CAInfo describes a CA in API responses.
type CAInfo struct {
	ID       string    `json:"id"`
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"not_after"`
	Status   string    `json:"status,omitempty"`
}

// Created is the result of Create.
type Created struct {
	Key   string `json:"key"`
	State string `json:"state"`
	CA    CAInfo `json:"ca"`
}

// Create creates a tenant with its CA and DEK, idempotently on externalRef.
// The CA key is generated before any transaction or lock.
func (s *Service) Create(ctx context.Context, externalRef string) (Created, bool, error) {
	if !ids.ValidUUID(externalRef) {
		return Created{}, false, apierr.BadRequest("external_ref must be a UUID")
	}
	if c, ok, err := s.byExternalRef(ctx, externalRef); err != nil || ok {
		if err == nil && c.State != StateActive && c.State != StateSuspended {
			return Created{}, false, errNotLive
		}
		return c, false, err
	}
	key := ids.NewTenantKey()
	cert, priv, err := NewCA(key, s.CAYears, s.now())
	if err != nil {
		return Created{}, false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Created{}, false, err
	}
	caID := ids.NewUUID()
	sum := sha256.Sum256(cert.Raw)
	ca := CAInfo{ID: caID, SHA256: hex.EncodeToString(sum[:]), NotAfter: cert.NotAfter.UTC()}
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO apple_edge.tenants (key, external_ref) VALUES ($1, $2)`, key, externalRef); err != nil {
			return err
		}
		dek, err := s.Keys.CreateDEK(ctx, tx, key)
		if err != nil {
			return err
		}
		enc, err := dek.Seal("apple_edge.tenant_cas", "key_enc", caID, key, keyDER)
		if err != nil {
			return err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.tenant_cas (id, tenant_key, status, cert_pem, key_enc, sha256, not_after)
VALUES ($1, $2, 'active', $3, $4, $5, $6)`, caID, key, string(certPEM), enc, ca.SHA256, ca.NotAfter); err != nil {
			return err
		}
		if err := s.Out.Insert(ctx, tx, outbox.P("tenant.created", map[string]any{"key": key, "state": StateActive, "external_ref": externalRef})); err != nil {
			return err
		}
		return store.Notify(ctx, tx, Channel, key)
	})
	if store.IsUniqueViolation(err, "tenants_external_ref_key") {
		c, _, err := s.byExternalRef(ctx, externalRef)
		return c, false, err
	}
	if err != nil {
		return Created{}, false, err
	}
	s.Out.Committed()
	if err := s.Reg.Reload(ctx, key); err != nil {
		s.Logger.Error("msg", "registry reload after creation", "tenant", key, "err", err)
	}
	return Created{Key: key, State: StateActive, CA: ca}, true, nil
}

func (s *Service) byExternalRef(ctx context.Context, ref string) (Created, bool, error) {
	var c Created
	err := s.DB.QueryRowContext(ctx, `
SELECT t.key, t.state, coalesce(ca.id::text, ''), coalesce(ca.sha256, ''), coalesce(ca.not_after, 'epoch'::timestamptz)
  FROM apple_edge.tenants t
  LEFT JOIN apple_edge.tenant_cas ca ON ca.tenant_key = t.key AND ca.status = 'active'
 WHERE t.external_ref = $1`, ref).Scan(&c.Key, &c.State, &c.CA.ID, &c.CA.SHA256, &c.CA.NotAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return c, false, nil
	}
	c.CA.NotAfter = c.CA.NotAfter.UTC()
	return c, err == nil, err
}

// Rotation is the result of RotateCA.
type Rotation struct {
	CA       CAInfo   `json:"ca"`
	Previous []CAInfo `json:"verify_only"`
}

// RotateCA gives a tenant a new issuing CA. The previous active CA keeps
// verifying the identities it issued (verify_only) and its private key,
// useless from now on, is destroyed; new enrollments use the new CA at
// once (registry reload, rebuilt SCEP service). The key is generated
// before any transaction or lock.
func (s *Service) RotateCA(ctx context.Context, key string) (Rotation, error) {
	if st, err := s.state(ctx, s.DB, key, false); err != nil {
		return Rotation{}, err
	} else if st != StateActive && st != StateSuspended {
		return Rotation{}, errNotLive
	}
	cert, priv, err := NewCA(key, s.CAYears, s.now())
	if err != nil {
		return Rotation{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Rotation{}, err
	}
	caID := ids.NewUUID()
	sum := sha256.Sum256(cert.Raw)
	out := Rotation{CA: CAInfo{ID: caID, SHA256: hex.EncodeToString(sum[:]), NotAfter: cert.NotAfter.UTC(), Status: "active"}}
	err = store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		st, err := s.state(ctx, tx, key, true)
		if err != nil {
			return err
		}
		if st != StateActive && st != StateSuspended {
			return errNotLive
		}
		rows, err := tx.QueryContext(ctx, `
UPDATE apple_edge.tenant_cas SET status = 'verify_only', key_enc = NULL
 WHERE tenant_key = $1 AND status = 'active'
RETURNING id, sha256, not_after`, key)
		if err != nil {
			return err
		}
		for rows.Next() {
			c := CAInfo{Status: "verify_only"}
			if err := rows.Scan(&c.ID, &c.SHA256, &c.NotAfter); err != nil {
				rows.Close()
				return err
			}
			c.NotAfter = c.NotAfter.UTC()
			out.Previous = append(out.Previous, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		dek, err := s.Keys.ActiveDEK(ctx, tx, key)
		if err != nil {
			return err
		}
		enc, err := dek.Seal("apple_edge.tenant_cas", "key_enc", caID, key, keyDER)
		if err != nil {
			return err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.tenant_cas (id, tenant_key, status, cert_pem, key_enc, sha256, not_after)
VALUES ($1, $2, 'active', $3, $4, $5, $6)`, caID, key, string(certPEM), enc, out.CA.SHA256, out.CA.NotAfter); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.tenants SET updated_at = now() WHERE key = $1`, key); err != nil {
			return err
		}
		prev := make([]string, 0, len(out.Previous))
		for _, p := range out.Previous {
			prev = append(prev, p.ID)
		}
		if err := s.Out.Insert(ctx, tx, outbox.T(key, "tenant.ca_rotated", map[string]any{
			"ca_id": caID, "sha256": out.CA.SHA256, "not_after": out.CA.NotAfter.Format(time.RFC3339), "verify_only": prev,
		})); err != nil {
			return err
		}
		return store.Notify(ctx, tx, Channel, key)
	})
	if err != nil {
		return Rotation{}, err
	}
	s.Out.Committed()
	if err := s.Reg.Reload(ctx, key); err != nil {
		s.Logger.Error("msg", "registry reload after CA rotation", "tenant", key, "err", err)
	}
	return out, nil
}

// Summary is a line of the tenant list.
type Summary struct {
	Key            string `json:"key"`
	ExternalRef    string `json:"external_ref"`
	State          string `json:"state"`
	CommandsFrozen bool   `json:"commands_frozen"`
}

// List pages through tenants by key.
func (s *Service) List(ctx context.Context, after string, limit int) ([]Summary, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT key, external_ref, state, commands_frozen FROM apple_edge.tenants
 WHERE key > $1 ORDER BY key LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Summary{}
	for rows.Next() {
		var x Summary
		if err := rows.Scan(&x.Key, &x.ExternalRef, &x.State, &x.CommandsFrozen); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// PushCertInfo describes a push certificate (never its key).
type PushCertInfo struct {
	ID          string     `json:"id"`
	State       string     `json:"state"`
	Topic       string     `json:"topic,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	// APNs is the last answer of APNs for the topic on this replica.
	APNs any `json:"apns,omitempty"`
}

// Info is the state of a tenant.
type Info struct {
	Key            string         `json:"key"`
	ExternalRef    string         `json:"external_ref"`
	State          string         `json:"state"`
	CommandsFrozen bool           `json:"commands_frozen"`
	RetiringSince  *time.Time     `json:"retiring_since,omitempty"`
	LoadFailed     bool           `json:"load_failed"`
	CAs            []CAInfo       `json:"cas"`
	PushCerts      []PushCertInfo `json:"push_certificates"`
	Counters       map[string]int `json:"counters"`
}

func (s *Service) state(ctx context.Context, q store.Querier, key string, forUpdate bool) (string, error) {
	var st string
	query := `SELECT state FROM apple_edge.tenants WHERE key = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query, key).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", apierr.TenantNotFound
	}
	return st, err
}

// Info returns the state of a tenant, including retiring and retired ones.
func (s *Service) Info(ctx context.Context, key string) (Info, error) {
	in := Info{Key: key, Counters: map[string]int{}}
	var retiring sql.NullTime
	err := s.DB.QueryRowContext(ctx, `SELECT external_ref, state, commands_frozen, retiring_since FROM apple_edge.tenants WHERE key = $1`, key).
		Scan(&in.ExternalRef, &in.State, &in.CommandsFrozen, &retiring)
	if errors.Is(err, sql.ErrNoRows) {
		return in, apierr.TenantNotFound
	}
	if err != nil {
		return in, err
	}
	if retiring.Valid {
		t := retiring.Time.UTC()
		in.RetiringSince = &t
	}
	if t := s.Reg.Get(key); t != nil {
		in.LoadFailed = t.LoadFailed
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, sha256, not_after, status FROM apple_edge.tenant_cas WHERE tenant_key = $1 ORDER BY created_at`, key)
	if err != nil {
		return in, err
	}
	for rows.Next() {
		var c CAInfo
		if err := rows.Scan(&c.ID, &c.SHA256, &c.NotAfter, &c.Status); err != nil {
			rows.Close()
			return in, err
		}
		c.NotAfter = c.NotAfter.UTC()
		in.CAs = append(in.CAs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}
	if in.PushCerts, err = s.PushCerts(ctx, key); err != nil {
		return in, err
	}
	var activeIDs, issued, enrollments int
	if err := s.DB.QueryRowContext(ctx, `
SELECT (SELECT count(*) FROM apple_edge.device_ids WHERE tenant_key = $1 AND state = 'active'),
       (SELECT count(*) FROM apple_edge.issued_certs WHERE tenant_key = $1 AND revoked_at IS NULL),
       (SELECT count(*) FROM nanomdm.enrollments WHERE left(id, 17) = $2 AND enabled)`, key, store.NamespacePrefix(key)).
		Scan(&activeIDs, &issued, &enrollments); err != nil {
		return in, err
	}
	in.Counters["active_device_ids"] = activeIDs
	in.Counters["issued_certificates"] = issued
	in.Counters["enabled_enrollments"] = enrollments
	var adeTokens int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM apple_edge.ade_tokens WHERE tenant_key = $1 AND state <> 'removed'`, key).Scan(&adeTokens); err != nil {
		return in, err
	}
	in.Counters["ade_tokens"] = adeTokens
	return in, nil
}

// changeState applies a lifecycle change in one transaction with its event.
func (s *Service) changeState(ctx context.Context, key string, fn func(tx *sql.Tx, st string) (newState string, err error)) error {
	err := store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		st, err := s.state(ctx, tx, key, true)
		if err != nil {
			return err
		}
		newState, err := fn(tx, st)
		if err != nil {
			return err
		}
		if newState != "" {
			if err := s.Out.Insert(ctx, tx, outbox.P("tenant.state_changed", map[string]any{"key": key, "state": newState})); err != nil {
				return err
			}
		}
		return store.Notify(ctx, tx, Channel, key)
	})
	if err != nil {
		return err
	}
	s.Out.Committed()
	return s.Reg.Reload(ctx, key)
}

var errNotLive = apierr.Conflict("tenant_not_live", "the tenant is retiring or retired")

// SetState switches a live tenant between active and suspended.
func (s *Service) SetState(ctx context.Context, key, state string) error {
	if state != StateActive && state != StateSuspended {
		return apierr.BadRequest(`state must be "active" or "suspended"`)
	}
	return s.changeState(ctx, key, func(tx *sql.Tx, st string) (string, error) {
		if st != StateActive && st != StateSuspended {
			return "", errNotLive
		}
		if st == state {
			return "", nil
		}
		_, err := tx.ExecContext(ctx, `UPDATE apple_edge.tenants SET state = $2, updated_at = now() WHERE key = $1`, key, state)
		return state, err
	})
}

// Freeze sets the emergency freeze of commands.
func (s *Service) Freeze(ctx context.Context, key string, frozen bool) error {
	return s.changeState(ctx, key, func(tx *sql.Tx, st string) (string, error) {
		if st != StateActive && st != StateSuspended {
			return "", errNotLive
		}
		_, err := tx.ExecContext(ctx, `UPDATE apple_edge.tenants SET commands_frozen = $2, updated_at = now() WHERE key = $1`, key, frozen)
		return "", err
	})
}

// Retire starts the 30-day soft deletion; refused while identifiers are active.
func (s *Service) Retire(ctx context.Context, key string) error {
	return s.changeState(ctx, key, func(tx *sql.Tx, st string) (string, error) {
		switch st {
		case StateRetiring:
			return "", nil
		case StateRetired:
			return "", errNotLive
		}
		n, err := store.CountActiveIDs(ctx, tx, key)
		if err != nil {
			return "", err
		}
		if n > 0 {
			return "", apierr.Conflict("tenant_has_active_enrollments", fmt.Sprintf("%d device identifiers are still active", n))
		}
		var tokens int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM apple_edge.ade_tokens WHERE tenant_key = $1 AND state <> 'removed'`, key).Scan(&tokens); err != nil {
			return "", err
		}
		if tokens > 0 {
			return "", apierr.Conflict("tenant_has_ade_tokens", fmt.Sprintf("%d ADE tokens are still present (delete them first)", tokens))
		}
		if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.tenants SET state = 'retiring', retiring_since = now(), updated_at = now() WHERE key = $1`, key); err != nil {
			return "", err
		}
		_, err = tx.ExecContext(ctx, `UPDATE apple_edge.data_keys SET destroy_after = now() + make_interval(secs => $2) WHERE tenant_key = $1 AND state = 'active'`, key, s.RetireAfter.Seconds())
		return StateRetiring, err
	})
}

// Restore cancels a retirement during the soft deletion.
func (s *Service) Restore(ctx context.Context, key string) error {
	return s.changeState(ctx, key, func(tx *sql.Tx, st string) (string, error) {
		if st != StateRetiring {
			return "", apierr.Conflict("tenant_not_retiring", "only a retiring tenant can be restored")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.tenants SET state = 'active', retiring_since = NULL, updated_at = now() WHERE key = $1`, key); err != nil {
			return "", err
		}
		_, err := tx.ExecContext(ctx, `UPDATE apple_edge.data_keys SET destroy_after = NULL WHERE tenant_key = $1 AND state = 'active'`, key)
		return StateActive, err
	})
}

// FinalizeRetired destroys the DEK and purges the data of tenants retiring
// for longer than RetireAfter (crypto-shredding). Singleton job.
func (s *Service) FinalizeRetired(ctx context.Context) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT key FROM apple_edge.tenants
 WHERE state = 'retiring' AND retiring_since < now() - make_interval(secs => $1)`, s.RetireAfter.Seconds())
	if err != nil {
		return 0, err
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return 0, err
		}
		keys = append(keys, k)
	}
	rows.Close()
	done := 0
	for _, key := range keys {
		err := store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
			ok, err := store.TryXactLock(ctx, tx, "retire:"+key)
			if err != nil || !ok {
				return err
			}
			st, err := s.state(ctx, tx, key, true)
			if err != nil || st != StateRetiring {
				return err
			}
			if err := nanomdmsql.PurgeTenant(ctx, tx, store.NamespacePrefix(key)); err != nil {
				return err
			}
			for _, q := range []string{
				`DELETE FROM apple_edge.machine_info_checks WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.ade_devices WHERE token_id IN (SELECT id FROM apple_edge.ade_tokens WHERE tenant_key = $1)`,
				`DELETE FROM apple_edge.ade_profiles WHERE token_id IN (SELECT id FROM apple_edge.ade_tokens WHERE tenant_key = $1)`,
				`DELETE FROM nanodep.dep_names WHERE name IN (SELECT id::text FROM apple_edge.ade_tokens WHERE tenant_key = $1)`,
				`DELETE FROM apple_edge.ade_tokens WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.apns_inactive WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.expiry_alerts WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.device_secrets WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.device_ids WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.commands WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.transfers WHERE from_tenant = $1 OR to_tenant = $1`,
				`DELETE FROM apple_edge.issued_certs WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.scep_challenges WHERE tenant_key = $1`,
				`DELETE FROM apple_edge.push_certs WHERE tenant_key = $1`,
				`UPDATE apple_edge.tenant_cas SET key_enc = NULL, status = 'retired' WHERE tenant_key = $1`,
				`UPDATE apple_edge.data_keys SET dek_wrapped = NULL, state = 'destroyed', destroyed_at = now() WHERE tenant_key = $1`,
				`UPDATE apple_edge.tenants SET state = 'retired', retired_at = now(), updated_at = now() WHERE key = $1`,
			} {
				if _, err := tx.ExecContext(ctx, q, key); err != nil {
					return err
				}
			}
			if err := s.Out.Insert(ctx, tx, outbox.P("tenant.state_changed", map[string]any{"key": key, "state": StateRetired})); err != nil {
				return err
			}
			done++
			return store.Notify(ctx, tx, Channel, key)
		})
		if err != nil {
			return done, err
		}
		s.Out.Committed()
	}
	return done, nil
}

// EnrollmentConfig is what the brain needs to compose enrollment profiles.
type EnrollmentConfig struct {
	ServerURL     string  `json:"server_url"`
	CheckinURL    string  `json:"checkin_url"`
	SCEPURL       string  `json:"scep_url"`
	Topic         *string `json:"topic"`
	SCEPCACertPEM string  `json:"scep_ca_cert_pem"`
	SCEPCASHA256  string  `json:"scep_ca_sha256"`
	KeySize       int     `json:"key_size"`
	SignMessage   bool    `json:"sign_message"`
}

// EnrollmentConfig returns the enrollment parameters of a live tenant.
func (s *Service) EnrollmentConfig(ctx context.Context, key string) (EnrollmentConfig, error) {
	var ec EnrollmentConfig
	st, err := s.state(ctx, s.DB, key, false)
	if err != nil {
		return ec, err
	}
	if st != StateActive && st != StateSuspended {
		return ec, errNotLive
	}
	base := s.PublicBase + "/t/" + key
	ec = EnrollmentConfig{ServerURL: base + "/mdm", CheckinURL: base + "/checkin", SCEPURL: base + "/scep", KeySize: 2048, SignMessage: true}
	err = s.DB.QueryRowContext(ctx, `SELECT cert_pem, sha256 FROM apple_edge.tenant_cas WHERE tenant_key = $1 AND status = 'active'`, key).Scan(&ec.SCEPCACertPEM, &ec.SCEPCASHA256)
	if err != nil {
		return ec, err
	}
	var topic sql.NullString
	err = s.DB.QueryRowContext(ctx, `SELECT topic FROM apple_edge.push_certs WHERE tenant_key = $1 AND state = 'active'`, key).Scan(&topic)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ec, err
	}
	if topic.Valid {
		ec.Topic = &topic.String
	}
	return ec, nil
}

// PushCerts lists the push certificates of a tenant, without any key.
func (s *Service) PushCerts(ctx context.Context, key string) ([]PushCertInfo, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, state, coalesce(topic, ''), not_after, activated_at FROM apple_edge.push_certs
 WHERE tenant_key = $1 ORDER BY created_at`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PushCertInfo{}
	for rows.Next() {
		var p PushCertInfo
		var na, act sql.NullTime
		if err := rows.Scan(&p.ID, &p.State, &p.Topic, &na, &act); err != nil {
			return nil, err
		}
		if na.Valid {
			t := na.Time.UTC()
			p.NotAfter = &t
		}
		if act.Valid {
			t := act.Time.UTC()
			p.ActivatedAt = &t
		}
		if s.APNsStatus != nil && p.Topic != "" && (p.State == "active" || p.State == "legacy") {
			p.APNs = s.APNsStatus(p.Topic)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
