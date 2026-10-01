package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
)

// Kinds of device identifiers.
const (
	KindUDID         = "udid"
	KindEnrollmentID = "enrollment_id"
)

// Proofs of ownership.
const (
	ProofNone = "none"
	ProofADE  = "ade"
)

// ActiveID is the active row of a device identifier.
type ActiveID struct {
	Tenant       string
	Kind         string
	RawID        string
	EnrollmentID string
	Proof        string
	Since        time.Time
}

// ActiveDeviceID returns the tenant where (kind, raw) is active, or nil.
func ActiveDeviceID(ctx context.Context, q Querier, kind, raw string) (*ActiveID, error) {
	a := &ActiveID{Kind: kind, RawID: raw}
	err := q.QueryRowContext(ctx, `
SELECT tenant_key, enrollment_id, proof, since FROM apple_edge.device_ids
 WHERE id_kind = $1 AND raw_id = $2 AND state = 'active'`, kind, raw).Scan(&a.Tenant, &a.EnrollmentID, &a.Proof, &a.Since)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

// ErrIDConflict means the identifier is active in another tenant.
var ErrIDConflict = errors.New("store: device identifier active in another tenant")

// ActivateDeviceID marks (tenant, kind, raw) active for enrollmentID.
// It returns ErrIDConflict when another tenant holds the identifier.
func ActivateDeviceID(ctx context.Context, q Querier, tenant, kind, raw, enrollmentID, proof string) error {
	_, err := q.ExecContext(ctx, `
INSERT INTO apple_edge.device_ids (tenant_key, id_kind, raw_id, enrollment_id, proof, state)
VALUES ($1, $2, $3, $4, $5, 'active')
ON CONFLICT (tenant_key, id_kind, raw_id) DO UPDATE SET
    enrollment_id  = EXCLUDED.enrollment_id,
    proof          = CASE WHEN apple_edge.device_ids.state = 'active' AND apple_edge.device_ids.proof = 'ade'
                          THEN 'ade' ELSE EXCLUDED.proof END,
    since          = CASE WHEN apple_edge.device_ids.state = 'active' THEN apple_edge.device_ids.since ELSE now() END,
    state          = 'active',
    released_at    = NULL,
    release_reason = NULL`, tenant, kind, raw, enrollmentID, proof)
	if IsUniqueViolation(err, "device_ids_one_active") {
		return ErrIDConflict
	}
	return err
}

// ReleaseDeviceID releases (tenant, kind, raw) if active.
func ReleaseDeviceID(ctx context.Context, q Querier, tenant, kind, raw, reason string) (bool, error) {
	res, err := q.ExecContext(ctx, `
UPDATE apple_edge.device_ids SET state = 'released', released_at = now(), release_reason = $4
 WHERE tenant_key = $1 AND id_kind = $2 AND raw_id = $3 AND state = 'active'`, tenant, kind, raw, reason)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReleasedID is an identifier released by ReleaseEnrollment.
type ReleasedID struct {
	Kind  string
	RawID string
}

// ReleaseEnrollment releases every active identifier bound to an enrollment.
func ReleaseEnrollment(ctx context.Context, q Querier, tenant, enrollmentID, reason string) ([]ReleasedID, error) {
	rows, err := q.QueryContext(ctx, `
UPDATE apple_edge.device_ids SET state = 'released', released_at = now(), release_reason = $3
 WHERE tenant_key = $1 AND enrollment_id = $2 AND state = 'active'
RETURNING id_kind, raw_id`, tenant, enrollmentID, reason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReleasedID
	for rows.Next() {
		var r ReleasedID
		if err := rows.Scan(&r.Kind, &r.RawID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EnrollmentIDActive reports whether an enrollment still holds an active identifier.
func EnrollmentIDActive(ctx context.Context, q Querier, tenant, enrollmentID string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM apple_edge.device_ids WHERE tenant_key = $1 AND enrollment_id = $2 AND state = 'active')`, tenant, enrollmentID).Scan(&ok)
	return ok, err
}

// ProofsOf returns the proof recorded for each device enrollment id
// ("none" when the identifier was never activated).
func ProofsOf(ctx context.Context, q Querier, tenant string, enrollmentIDs []string) (map[string]string, error) {
	out := make(map[string]string, len(enrollmentIDs))
	for _, id := range enrollmentIDs {
		out[id] = ProofNone
	}
	rows, err := q.QueryContext(ctx, `
SELECT DISTINCT ON (enrollment_id) enrollment_id, proof FROM apple_edge.device_ids
 WHERE tenant_key = $1 AND enrollment_id = ANY($2)
 ORDER BY enrollment_id, (state = 'active') DESC, since DESC`, tenant, pq.Array(enrollmentIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, p string
		if err := rows.Scan(&id, &p); err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, rows.Err()
}

// CountActiveIDs counts the active identifiers of a tenant.
func CountActiveIDs(ctx context.Context, q Querier, tenant string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM apple_edge.device_ids WHERE tenant_key = $1 AND state = 'active'`, tenant).Scan(&n)
	return n, err
}

// Transfer is an approved move of an identifier between two tenants.
type Transfer struct {
	ID          string
	Kind        string
	RawID       string
	From        string
	To          string
	ApprovalRef string
	ExpiresAt   time.Time
}

// CreateTransfer records an approved transfer.
func CreateTransfer(ctx context.Context, q Querier, t Transfer) (string, error) {
	id := ids.NewUUID()
	_, err := q.ExecContext(ctx, `
INSERT INTO apple_edge.transfers (id, id_kind, raw_id, from_tenant, to_tenant, approval_ref, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, t.Kind, t.RawID, t.From, t.To, t.ApprovalRef, t.ExpiresAt.UTC())
	return id, err
}

// FindTransfer returns a valid (unused, unexpired) transfer from -> to, or nil.
func FindTransfer(ctx context.Context, q Querier, kind, raw, from, to string) (*Transfer, error) {
	t := &Transfer{Kind: kind, RawID: raw, From: from, To: to}
	err := q.QueryRowContext(ctx, `
SELECT id, approval_ref, expires_at FROM apple_edge.transfers
 WHERE id_kind = $1 AND raw_id = $2 AND from_tenant = $3 AND to_tenant = $4
   AND used_at IS NULL AND expires_at > now()
 ORDER BY created_at DESC LIMIT 1`, kind, raw, from, to).Scan(&t.ID, &t.ApprovalRef, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// UseTransfer marks a transfer as executed; false if it was already used.
func UseTransfer(ctx context.Context, q Querier, id string) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE apple_edge.transfers SET used_at = now() WHERE id = $1 AND used_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// IssuedCert is a device identity issued by a tenant CA.
type IssuedCert struct {
	SHA256      string
	Tenant      string
	CAID        string
	SerialHex   string
	ChallengeID string
	NotAfter    time.Time
	Revoked     bool
}

// LookupIssuedCert returns the issued certificate with this fingerprint, or nil.
func LookupIssuedCert(ctx context.Context, q Querier, sha string) (*IssuedCert, error) {
	c := &IssuedCert{SHA256: sha}
	var ch sql.NullString
	var revoked sql.NullTime
	err := q.QueryRowContext(ctx, `
SELECT tenant_key, ca_id, serial_hex, challenge_id, not_after, revoked_at
  FROM apple_edge.issued_certs WHERE sha256 = $1`, sha).Scan(&c.Tenant, &c.CAID, &c.SerialHex, &ch, &c.NotAfter, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ChallengeID = ch.String
	c.Revoked = revoked.Valid
	return c, nil
}

// RevokeCert revokes a device identity of tenant; false if unknown or already revoked.
func RevokeCert(ctx context.Context, q Querier, tenant, sha, reason string) (bool, error) {
	res, err := q.ExecContext(ctx, `
UPDATE apple_edge.issued_certs SET revoked_at = now(), revoke_reason = $3
 WHERE tenant_key = $1 AND sha256 = $2 AND revoked_at IS NULL`, tenant, sha, Truncate(reason, 200))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// IssuedCertExists reports whether a fingerprint belongs to tenant.
func IssuedCertExists(ctx context.Context, q Querier, tenant, sha string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM apple_edge.issued_certs WHERE tenant_key = $1 AND sha256 = $2)`, tenant, sha).Scan(&ok)
	return ok, err
}

// Challenge is the enrollment context attached to an issued certificate.
type Challenge struct {
	ID            string
	SessionRef    string
	BindUDID      string
	BindSerial    string
	MachineInfoID string
}

// ChallengeByID returns a challenge (bindings and session reference), or nil.
func ChallengeByID(ctx context.Context, q Querier, tenant, id string) (*Challenge, error) {
	if id == "" {
		return nil, nil
	}
	c := &Challenge{ID: id}
	var s, u, n, m sql.NullString
	err := q.QueryRowContext(ctx, `
SELECT session_ref, bind_udid, bind_serial, machine_info_id::text FROM apple_edge.scep_challenges WHERE id = $1 AND tenant_key = $2`, id, tenant).Scan(&s, &u, &n, &m)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.SessionRef, c.BindUDID, c.BindSerial, c.MachineInfoID = s.String, u.String, n.String, m.String
	return c, nil
}

// ADEProof reports whether a MachineInfo check proves that udid belongs to
// tenant: verified for this UDID, with a serial number that is, now, an
// ADE device of one of the tenant's tokens.
func ADEProof(ctx context.Context, q Querier, tenant, machineInfoID, udid string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM apple_edge.machine_info_checks m
    JOIN apple_edge.ade_devices d ON d.tenant_key = m.tenant_key AND d.serial = m.serial
    JOIN apple_edge.ade_tokens t ON t.id = d.token_id AND t.tenant_key = m.tenant_key AND t.state <> 'removed'
   WHERE m.id = $1 AND m.tenant_key = $2 AND m.udid = $3 AND m.token_id IS NOT NULL)`, machineInfoID, tenant, udid).Scan(&ok)
	return ok, err
}
