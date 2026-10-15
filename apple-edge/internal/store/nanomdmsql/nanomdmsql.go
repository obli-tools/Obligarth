// Package nanomdmsql holds every query of apple-edge that reads or writes
// the upstream NanoMDM tables directly. The set is deliberately small and
// must be re-tested at every upstream upgrade.
package nanomdmsql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"
)

// Querier is implemented by *sql.DB and *sql.Tx.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// EnabledEnrollments returns, for each id that exists, whether it is enabled.
func EnabledEnrollments(ctx context.Context, q Querier, enrollmentIDs []string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, enabled FROM nanomdm.enrollments WHERE id = ANY($1)`, pq.Array(enrollmentIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool, len(enrollmentIDs))
	for rows.Next() {
		var id string
		var enabled bool
		if err := rows.Scan(&id, &enabled); err != nil {
			return nil, err
		}
		out[id] = enabled
	}
	return out, rows.Err()
}

// CommandQueued reports whether the upstream queue holds a command.
func CommandQueued(ctx context.Context, q Querier, commandUUID string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM nanomdm.commands WHERE command_uuid = $1)`, commandUUID).Scan(&ok)
	return ok, err
}

// DeactivateQueueItem stops delivering a queued command to an enrollment
// (cancellation, expiry). It returns false when the item was not active.
func DeactivateQueueItem(ctx context.Context, q Querier, enrollmentID, commandUUID string) (bool, error) {
	res, err := q.ExecContext(ctx, `UPDATE nanomdm.enrollment_queue SET active = FALSE WHERE id = $1 AND command_uuid = $2 AND active`, enrollmentID, commandUUID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Seen is the last check-in of an enrollment.
type Seen struct {
	EnrollmentID string
	LastSeenAt   time.Time
}

// SeenSince returns the enrollments of a tenant seen after since (exclusive)
// and up to until (inclusive). nsPrefix is "<key>_".
func SeenSince(ctx context.Context, q Querier, nsPrefix string, since, until time.Time) ([]Seen, error) {
	rows, err := q.QueryContext(ctx, `
SELECT id, last_seen_at FROM nanomdm.enrollments
 WHERE left(id, $1) = $2 AND last_seen_at > $3 AND last_seen_at <= $4
 ORDER BY id`, len(nsPrefix), nsPrefix, since.UTC(), until.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Seen
	for rows.Next() {
		var s Seen
		if err := rows.Scan(&s.EnrollmentID, &s.LastSeenAt); err != nil {
			return nil, err
		}
		s.LastSeenAt = asUTC(s.LastSeenAt)
		out = append(out, s)
	}
	return out, rows.Err()
}

// asUTC re-labels a TIMESTAMP (without time zone) read from NanoMDM, whose
// sessions run in UTC.
func asUTC(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

// Enrollment is one row of nanomdm.enrollments with its device.
type Enrollment struct {
	ID          string
	DeviceID    string
	UserID      sql.NullString
	Type        string
	Enabled     bool
	LastSeenAt  time.Time
	CreatedAt   time.Time
	IdentityPEM sql.NullString
}

const enrollmentCols = `e.id, e.device_id, e.user_id, e.type, e.enabled, e.last_seen_at, coalesce(e.created_at, e.last_seen_at), d.identity_cert`

func scanEnrollment(sc interface{ Scan(...any) error }) (Enrollment, error) {
	var e Enrollment
	err := sc.Scan(&e.ID, &e.DeviceID, &e.UserID, &e.Type, &e.Enabled, &e.LastSeenAt, &e.CreatedAt, &e.IdentityPEM)
	e.LastSeenAt, e.CreatedAt = asUTC(e.LastSeenAt), asUTC(e.CreatedAt)
	return e, err
}

// ListEnrollments pages through a tenant's enrollments by id.
func ListEnrollments(ctx context.Context, q Querier, nsPrefix, after string, limit int, seenSince *time.Time) ([]Enrollment, error) {
	args := []any{len(nsPrefix), nsPrefix, after, limit}
	where := `left(e.id, $1) = $2 AND e.id > $3`
	if seenSince != nil {
		args = append(args, seenSince.UTC())
		where += ` AND e.last_seen_at >= $5`
	}
	rows, err := q.QueryContext(ctx, `
SELECT `+enrollmentCols+`
  FROM nanomdm.enrollments e JOIN nanomdm.devices d ON d.id = e.device_id
 WHERE `+where+`
 ORDER BY e.id LIMIT $4`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrNotFound is returned for an unknown enrollment.
var ErrNotFound = errors.New("nanomdmsql: not found")

// GetEnrollment returns one enrollment.
func GetEnrollment(ctx context.Context, q Querier, id string) (Enrollment, error) {
	e, err := scanEnrollment(q.QueryRowContext(ctx, `
SELECT `+enrollmentCols+`
  FROM nanomdm.enrollments e JOIN nanomdm.devices d ON d.id = e.device_id
 WHERE e.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// DeviceExists reports whether a device row exists (Authenticate stored).
func DeviceExists(ctx context.Context, q Querier, deviceID string) (bool, error) {
	var ok bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM nanomdm.devices WHERE id = $1)`, deviceID).Scan(&ok)
	return ok, err
}

// QueueItem is a pending command of an enrollment.
type QueueItem struct {
	CommandUUID string
	RequestType string
	Status      sql.NullString
	Active      bool
	CreatedAt   time.Time
}

// PendingQueue returns the queue of an enrollment (no command bodies).
func PendingQueue(ctx context.Context, q Querier, id string) ([]QueueItem, error) {
	rows, err := q.QueryContext(ctx, `
SELECT command_uuid, request_type, status, active, created_at
  FROM nanomdm.view_queue
 WHERE id = $1 AND (status IS NULL OR status = 'NotNow')
 ORDER BY priority DESC, created_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueueItem
	for rows.Next() {
		var it QueueItem
		if err := rows.Scan(&it.CommandUUID, &it.RequestType, &it.Status, &it.Active, &it.CreatedAt); err != nil {
			return nil, err
		}
		it.CreatedAt = asUTC(it.CreatedAt)
		out = append(out, it)
	}
	return out, rows.Err()
}

// CertHashes returns the certificate hashes associated with a device enrollment.
func CertHashes(ctx context.Context, q Querier, deviceID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT sha256 FROM nanomdm.cert_auth_associations WHERE id = $1`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DropOtherCertHashes removes the certificate associations of a device
// enrollment other than keep (the identity of an Authenticate accepted on
// it): NanoMDM's certauth only adds associations, so the identity of a
// previous holder (a device erased, a User Enrollment superseded by an ADE
// proof) would otherwise keep answering for the enrollment.
func DropOtherCertHashes(ctx context.Context, q Querier, deviceID, keep string) (int64, error) {
	res, err := q.ExecContext(ctx, `DELETE FROM nanomdm.cert_auth_associations WHERE id = $1 AND sha256 <> lower($2)`, deviceID, keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeDevice deletes a device and everything that cascades from it
// (enrollments, users, queue, results) plus its certificate associations.
func PurgeDevice(ctx context.Context, q Querier, deviceID string) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM nanomdm.devices WHERE id = $1`, deviceID); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `DELETE FROM nanomdm.cert_auth_associations WHERE id = $1`, deviceID)
	return err
}

// PurgeTenant deletes every upstream row of a tenant (retired tenants).
func PurgeTenant(ctx context.Context, q Querier, nsPrefix string) error {
	for _, s := range []string{
		`DELETE FROM nanomdm.devices WHERE left(id, $1) = $2`,
		`DELETE FROM nanomdm.cert_auth_associations WHERE left(id, $1) = $2`,
	} {
		if _, err := q.ExecContext(ctx, s, len(nsPrefix), nsPrefix); err != nil {
			return err
		}
	}
	return nil
}

// DeleteOrphanCommands removes upstream commands no queue item or result refers to.
func DeleteOrphanCommands(ctx context.Context, q Querier, commandUUIDs []string) error {
	_, err := q.ExecContext(ctx, `
DELETE FROM nanomdm.commands c
 WHERE c.command_uuid = ANY($1)
   AND NOT EXISTS (SELECT 1 FROM nanomdm.enrollment_queue q WHERE q.command_uuid = c.command_uuid)
   AND NOT EXISTS (SELECT 1 FROM nanomdm.command_results r WHERE r.command_uuid = c.command_uuid)`, pq.Array(commandUUIDs))
	return err
}

// DeleteInactiveQueueItems removes deactivated queue items of commands.
func DeleteInactiveQueueItems(ctx context.Context, q Querier, commandUUIDs []string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM nanomdm.enrollment_queue WHERE command_uuid = ANY($1) AND NOT active`, pq.Array(commandUUIDs))
	return err
}

// QueuedFor returns the request type of a command queued (active or not)
// for an enrollment; found is false if the enrollment never had it.
func QueuedFor(ctx context.Context, q Querier, enrollmentID, commandUUID string) (requestType string, found bool, err error) {
	err = q.QueryRowContext(ctx, `
SELECT c.request_type FROM nanomdm.enrollment_queue q JOIN nanomdm.commands c ON c.command_uuid = q.command_uuid
 WHERE q.id = $1 AND q.command_uuid = $2`, enrollmentID, commandUUID).Scan(&requestType)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return requestType, err == nil, err
}

// TokenUpdateTally returns the TokenUpdate count of an enrollment.
func TokenUpdateTally(ctx context.Context, q Querier, enrollmentID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT token_update_tally FROM nanomdm.enrollments WHERE id = $1`, enrollmentID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}
