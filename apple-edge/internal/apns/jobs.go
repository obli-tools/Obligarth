package apns

import (
	"context"
	"database/sql"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// CertExpiryThresholds are the days before expiry at which
// apns.certificate_expiring is emitted (once each).
var CertExpiryThresholds = []int{1, 3, 7, 14, 30, 60}

// ReleaseInactive releases the identifiers of device channels that APNs
// declared inactive (410, or 400 BadDeviceToken) at least after ago, with
// no check-in since the report. A device seen after the report clears it.
// Singleton job.
func ReleaseInactive(ctx context.Context, db *sql.DB, out *outbox.Writer, after time.Duration) (int, error) {
	released := 0
	events := 0
	err := store.InTx(ctx, db, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "apns-inactive")
		if err != nil || !ok {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
SELECT i.enrollment_id, i.tenant_key,
       coalesce(e.last_seen_at > i.reported_at, false) AS seen_after,
       i.reported_at <= now() - make_interval(secs => $1) AS due
  FROM apple_edge.apns_inactive i LEFT JOIN nanomdm.enrollments e ON e.id = i.enrollment_id
 ORDER BY i.reported_at
 LIMIT 5000
   FOR UPDATE OF i SKIP LOCKED`, after.Seconds())
		if err != nil {
			return err
		}
		type row struct {
			id, tenant     string
			seenAfter, due bool
		}
		var all []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.tenant, &r.seenAfter, &r.due); err != nil {
				rows.Close()
				return err
			}
			all = append(all, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var evs []outbox.Event
		for _, r := range all {
			switch {
			case r.seenAfter:
			case r.due:
				ids, err := store.ReleaseEnrollment(ctx, tx, r.tenant, r.id, "apns_inactive")
				if err != nil {
					return err
				}
				for _, x := range ids {
					evs = append(evs, outbox.T(r.tenant, "device.id_released", map[string]any{"id_kind": x.Kind, "reason": "apns_inactive"}).WithEnrollment(r.id))
					released++
				}
			default:
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM apple_edge.apns_inactive WHERE enrollment_id = $1`, r.id); err != nil {
				return err
			}
		}
		events = len(evs)
		return out.Insert(ctx, tx, evs...)
	})
	if err == nil && events > 0 {
		out.Committed()
	}
	return released, err
}

// CheckCertExpiry emits apns.certificate_expiring at the thresholds of
// CertExpiryThresholds, then apns.certificate_expired, once each per
// certificate, and refreshes the expiry gauge. Singleton job.
func CheckCertExpiry(ctx context.Context, db *sql.DB, out *outbox.Writer, m *obs.Metrics, now time.Time) (int, error) {
	n := 0
	err := store.InTx(ctx, db, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "apns-expiry")
		if err != nil || !ok {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
SELECT p.id, p.tenant_key, p.topic, p.not_after, p.state
  FROM apple_edge.push_certs p JOIN apple_edge.tenants t ON t.key = p.tenant_key
 WHERE p.state IN ('active', 'legacy') AND t.state IN ('active', 'suspended') AND p.not_after IS NOT NULL`)
		if err != nil {
			return err
		}
		type cert struct {
			id, tenant, topic, state string
			notAfter                 time.Time
		}
		var all []cert
		for rows.Next() {
			var c cert
			if err := rows.Scan(&c.id, &c.tenant, &c.topic, &c.notAfter, &c.state); err != nil {
				rows.Close()
				return err
			}
			all = append(all, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var evs []outbox.Event
		for _, c := range all {
			if c.state == "active" && m != nil {
				m.APNsCertExpiry.Set(float64(c.notAfter.Unix()), c.tenant)
			}
			th := store.ExpiryThreshold(c.notAfter, now, CertExpiryThresholds)
			if th < 0 {
				continue
			}
			first, err := store.MarkExpiryAlert(ctx, tx, c.tenant, "push_cert:"+c.id, th)
			if err != nil {
				return err
			}
			if !first {
				continue
			}
			payload := map[string]any{"topic": c.topic, "not_after": c.notAfter.UTC().Format(time.RFC3339)}
			if th == 0 {
				evs = append(evs, outbox.T(c.tenant, "apns.certificate_expired", payload))
				continue
			}
			payload["days_left"] = th
			evs = append(evs, outbox.T(c.tenant, "apns.certificate_expiring", payload))
		}
		n = len(evs)
		return out.Insert(ctx, tx, evs...)
	})
	if err == nil && n > 0 {
		out.Committed()
	}
	return n, err
}
