package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/MeeJay/Obligarth/apple-edge/internal/crypto/envelope"
	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
)

// Keyring gives access to the DEKs stored (wrapped) in apple_edge.data_keys.
// DEKs are unwrapped on demand and never cached in clear.
type Keyring struct {
	db  *sql.DB
	kek *envelope.KEK
}

// NewKeyring returns a key ring using kek.
func NewKeyring(db *sql.DB, kek *envelope.KEK) *Keyring { return &Keyring{db: db, kek: kek} }

// KEKID returns the id of the current KEK.
func (k *Keyring) KEKID() string { return k.kek.ID() }

// ErrNoActiveDEK is returned when a tenant has no usable DEK.
var ErrNoActiveDEK = errors.New("keys: no active data key")

// ActiveDEK returns the active DEK of tenant ("" for the instance).
func (k *Keyring) ActiveDEK(ctx context.Context, q Querier, tenant string) (*envelope.DEK, error) {
	var id, kekID string
	var wrapped sql.NullString
	err := q.QueryRowContext(ctx, `
SELECT id, kek_id, dek_wrapped FROM apple_edge.data_keys
 WHERE coalesce(tenant_key, '-') = $1 AND state = 'active'`, orDash(tenant)).Scan(&id, &kekID, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoActiveDEK
	}
	if err != nil {
		return nil, err
	}
	return k.unwrap(id, tenant, kekID, wrapped)
}

// DEKByID returns the DEK with the given id, checking that it belongs to tenant.
func (k *Keyring) DEKByID(ctx context.Context, q Querier, id, tenant string) (*envelope.DEK, error) {
	var kekID string
	var owner, wrapped sql.NullString
	err := q.QueryRowContext(ctx, `SELECT kek_id, tenant_key, dek_wrapped FROM apple_edge.data_keys WHERE id = $1`, id).Scan(&kekID, &owner, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoActiveDEK
	}
	if err != nil {
		return nil, err
	}
	if owner.String != tenant {
		return nil, errors.New("keys: data key of another tenant")
	}
	return k.unwrap(id, tenant, kekID, wrapped)
}

func (k *Keyring) unwrap(id, tenant, kekID string, wrapped sql.NullString) (*envelope.DEK, error) {
	if !wrapped.Valid {
		return nil, fmt.Errorf("keys: data key %s destroyed", id)
	}
	if kekID != k.kek.ID() {
		return nil, fmt.Errorf("keys: data key %s is wrapped by KEK %s, not by the current KEK %s (incomplete rotation?)", id, kekID, k.kek.ID())
	}
	raw, err := k.kek.Unwrap(id, tenant, wrapped.String)
	if err != nil {
		return nil, fmt.Errorf("keys: unwrap data key %s: %w", id, err)
	}
	return envelope.NewDEK(id, raw), nil
}

// CreateDEK inserts a new active DEK (version 1) for tenant ("" for the instance).
func (k *Keyring) CreateDEK(ctx context.Context, q Querier, tenant string) (*envelope.DEK, error) {
	id := ids.NewUUID()
	raw := envelope.NewKey()
	wrapped, err := k.kek.Wrap(id, tenant, raw)
	if err != nil {
		return nil, err
	}
	_, err = q.ExecContext(ctx, `
INSERT INTO apple_edge.data_keys (id, tenant_key, version, kek_id, dek_wrapped, state)
VALUES ($1, $2, 1, $3, $4, 'active')`, id, nullString(tenant), k.kek.ID(), wrapped)
	if err != nil {
		return nil, err
	}
	return envelope.NewDEK(id, raw), nil
}

// Open decrypts a column value, using the DEK named by the ciphertext.
func (k *Keyring) Open(ctx context.Context, q Querier, tenant, schemaTable, column, pk, ciphertext string) ([]byte, error) {
	kid, err := envelope.KeyID(ciphertext)
	if err != nil {
		return nil, err
	}
	dek, err := k.DEKByID(ctx, q, kid, tenant)
	if err != nil {
		return nil, err
	}
	return dek.Open(schemaTable, column, pk, tenant, ciphertext)
}

// EnsureInstance creates the instance DEK and the log pseudonym key if
// missing and returns the pseudonym key. It fails if the KEK cannot unwrap
// the instance DEK (wrong KEK).
func (k *Keyring) EnsureInstance(ctx context.Context) (pseudonymKey []byte, err error) {
	dek, err := k.ActiveDEK(ctx, k.db, "")
	if errors.Is(err, ErrNoActiveDEK) {
		_, cerr := k.CreateDEK(ctx, k.db, "")
		if cerr != nil && !IsUniqueViolation(cerr, "data_keys_one_active") {
			return nil, cerr
		}
		dek, err = k.ActiveDEK(ctx, k.db, "")
	}
	if err != nil {
		return nil, fmt.Errorf("instance data key (KEK check): %w", err)
	}
	const name = "log_pseudonym_key"
	aadPK := name
	var enc string
	err = k.db.QueryRowContext(ctx, `SELECT value_enc FROM apple_edge.instance_secrets WHERE name = $1`, name).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		sealed, serr := dek.Seal("apple_edge.instance_secrets", "value_enc", aadPK, "", envelope.NewKey())
		if serr != nil {
			return nil, serr
		}
		if _, err := k.db.ExecContext(ctx, `INSERT INTO apple_edge.instance_secrets (name, value_enc) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, name, sealed); err != nil {
			return nil, err
		}
		err = k.db.QueryRowContext(ctx, `SELECT value_enc FROM apple_edge.instance_secrets WHERE name = $1`, name).Scan(&enc)
	}
	if err != nil {
		return nil, err
	}
	return k.Open(ctx, k.db, "", "apple_edge.instance_secrets", "value_enc", aadPK, enc)
}

// RotateKEK re-wraps, row by row, every DEK wrapped by old with k's KEK.
// It returns the number of rows re-wrapped.
func RotateKEK(ctx context.Context, db *sql.DB, old, current *envelope.KEK) (int, error) {
	if old.ID() == current.ID() {
		return 0, errors.New("keys: the previous and the current KEK are identical")
	}
	type row struct {
		id, wrapped string
		tenant      sql.NullString
	}
	rows, err := db.QueryContext(ctx, `SELECT id, tenant_key, dek_wrapped FROM apple_edge.data_keys WHERE kek_id = $1 AND dek_wrapped IS NOT NULL ORDER BY created_at`, old.ID())
	if err != nil {
		return 0, err
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.tenant, &r.wrapped); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range todo {
		raw, err := old.Unwrap(r.id, r.tenant.String, r.wrapped)
		if err != nil {
			return n, fmt.Errorf("keys: unwrap %s with the previous KEK: %w", r.id, err)
		}
		w, err := current.Wrap(r.id, r.tenant.String, raw)
		if err != nil {
			return n, err
		}
		res, err := db.ExecContext(ctx, `UPDATE apple_edge.data_keys SET kek_id = $1, dek_wrapped = $2 WHERE id = $3 AND kek_id = $4`, current.ID(), w, r.id, old.ID())
		if err != nil {
			return n, err
		}
		if c, _ := res.RowsAffected(); c == 1 {
			n++
		}
	}
	var others int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM apple_edge.data_keys WHERE kek_id <> $1 AND dek_wrapped IS NOT NULL`, current.ID()).Scan(&others); err != nil {
		return n, err
	}
	if others > 0 {
		return n, fmt.Errorf("keys: %d data keys remain wrapped by an unknown KEK", others)
	}
	return n, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
