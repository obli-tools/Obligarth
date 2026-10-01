package outbox

import (
	"context"
	"database/sql"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store/nanomdmsql"
)

// PurgeConsumed deletes consumed events older than retention. Events not
// consumed are never purged. It returns false if another replica holds the job.
func PurgeConsumed(ctx context.Context, db *sql.DB, retention time.Duration) (deleted int64, ran bool, err error) {
	err = store.InTx(ctx, db, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "outbox-purge")
		if err != nil || !ok {
			return err
		}
		ran = true
		res, err := tx.ExecContext(ctx, `DELETE FROM apple_edge.outbox WHERE consumed_at IS NOT NULL AND consumed_at < now() - make_interval(secs => $1)`, retention.Seconds())
		if err != nil {
			return err
		}
		deleted, _ = res.RowsAffected()
		return nil
	})
	return deleted, ran, err
}

// Lag describes the events waiting for the brain.
type Lag struct {
	Pending       int64   `json:"pending"`
	OldestSeconds float64 `json:"oldest_pending_seconds"`
}

// PendingLag measures the outbox backlog.
func PendingLag(ctx context.Context, q store.Querier) (Lag, error) {
	var l Lag
	var oldest sql.NullFloat64
	err := q.QueryRowContext(ctx, `
SELECT count(*), extract(epoch FROM now() - min(occurred_at))
  FROM apple_edge.outbox WHERE consumed_at IS NULL`).Scan(&l.Pending, &oldest)
	if oldest.Valid && oldest.Float64 > 0 {
		l.OldestSeconds = oldest.Float64
	}
	return l, err
}

// SeenEntry is one enrollment of a presence batch.
type SeenEntry struct {
	EnrollmentID string    `json:"enrollment_id"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

const seenChunk = 1000

// SeenBatch emits, for each tenant, the enrollments seen in (since, until].
// It returns false if another replica holds the job.
func SeenBatch(ctx context.Context, db *sql.DB, w *Writer, tenants []string, since, until time.Time) (events int, ran bool, err error) {
	err = store.InTx(ctx, db, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "seen-batch")
		if err != nil || !ok {
			return err
		}
		ran = true
		for _, t := range tenants {
			seen, err := nanomdmsql.SeenSince(ctx, tx, store.NamespacePrefix(t), since, until)
			if err != nil {
				return err
			}
			for start := 0; start < len(seen); start += seenChunk {
				end := min(start+seenChunk, len(seen))
				entries := make([]SeenEntry, 0, end-start)
				for _, s := range seen[start:end] {
					entries = append(entries, SeenEntry{EnrollmentID: s.EnrollmentID, LastSeenAt: s.LastSeenAt})
				}
				if err := w.Insert(ctx, tx, T(t, "mdm.seen_batch", map[string]any{
					"since": since.UTC().Format(time.RFC3339Nano), "until": until.UTC().Format(time.RFC3339Nano), "enrollments": entries,
				})); err != nil {
					return err
				}
				events++
			}
		}
		return nil
	})
	if err == nil && events > 0 {
		w.Committed()
	}
	return events, ran, err
}
