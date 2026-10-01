package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
)

// Kinds of device secrets.
const (
	SecretUnlockToken    = "unlock_token"
	SecretBootstrapToken = "bootstrap_token"
	SecretBypassCode     = "activation_lock_bypass_code"
)

const secretsTable = "apple_edge.device_secrets"

// Secrets stores device secrets encrypted with the tenant DEK.
type Secrets struct {
	db   *sql.DB
	keys *Keyring
}

// NewSecrets returns the device secret store.
func NewSecrets(db *sql.DB, keys *Keyring) *Secrets { return &Secrets{db: db, keys: keys} }

// ErrSecretNotFound is returned when no current secret exists.
var ErrSecretNotFound = errors.New("secrets: not found")

// Put supersedes the current secret of this kind and stores value; it
// returns the id of the new row (the "$secret_ref" given to the brain).
func (s *Secrets) Put(ctx context.Context, tenant, enrollmentID, kind string, value []byte) (string, error) {
	var id string
	err := InTx(ctx, s.db, func(tx *sql.Tx) error {
		dek, err := s.keys.ActiveDEK(ctx, tx, tenant)
		if err != nil {
			return err
		}
		id = ids.NewUUID()
		enc, err := dek.Seal(secretsTable, "value_enc", id, tenant, value)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE apple_edge.device_secrets SET superseded_at = now()
 WHERE enrollment_id = $1 AND kind = $2 AND superseded_at IS NULL`, enrollmentID, kind); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO apple_edge.device_secrets (id, tenant_key, enrollment_id, kind, value_enc) VALUES ($1, $2, $3, $4, $5)`,
			id, tenant, enrollmentID, kind, enc)
		return err
	})
	return id, err
}

// Current returns the current secret of an enrollment.
func (s *Secrets) Current(ctx context.Context, tenant, enrollmentID, kind string) (id string, value []byte, err error) {
	var enc string
	err = s.db.QueryRowContext(ctx, `
SELECT id, value_enc FROM apple_edge.device_secrets
 WHERE tenant_key = $1 AND enrollment_id = $2 AND kind = $3 AND superseded_at IS NULL`, tenant, enrollmentID, kind).Scan(&id, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrSecretNotFound
	}
	if err != nil {
		return "", nil, err
	}
	value, err = s.keys.Open(ctx, s.db, tenant, secretsTable, "value_enc", id, enc)
	return id, value, err
}

// Has reports whether a current secret exists (no decryption).
func (s *Secrets) Has(ctx context.Context, tenant, enrollmentID, kind string) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM apple_edge.device_secrets
 WHERE tenant_key = $1 AND enrollment_id = $2 AND kind = $3 AND superseded_at IS NULL)`, tenant, enrollmentID, kind).Scan(&ok)
	return ok, err
}

// Get returns a secret by id, checking its tenant.
func (s *Secrets) Get(ctx context.Context, tenant, id string) (kind, enrollmentID string, value []byte, err error) {
	var enc string
	err = s.db.QueryRowContext(ctx, `
SELECT kind, enrollment_id, value_enc FROM apple_edge.device_secrets WHERE id = $1 AND tenant_key = $2`, id, tenant).Scan(&kind, &enrollmentID, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil, ErrSecretNotFound
	}
	if err != nil {
		return "", "", nil, err
	}
	value, err = s.keys.Open(ctx, s.db, tenant, secretsTable, "value_enc", id, enc)
	return kind, enrollmentID, value, err
}

// Supersede marks the current secret of this kind as superseded.
func (s *Secrets) Supersede(ctx context.Context, q Querier, enrollmentID, kind string) error {
	_, err := q.ExecContext(ctx, `
UPDATE apple_edge.device_secrets SET superseded_at = now()
 WHERE enrollment_id = $1 AND kind = $2 AND superseded_at IS NULL`, enrollmentID, kind)
	return err
}
