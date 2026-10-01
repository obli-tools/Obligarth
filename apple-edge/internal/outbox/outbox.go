// Package outbox writes the events of apple-edge to apple_edge.outbox, in
// the transaction of the change they describe, and wakes the brain with a
// rate-limited NOTIFY once committed. The brain consumes the table in its
// own transactions: delivery is at least once, with no order guaranteed by
// seq (handlers must be idempotent and monotonic, ordered by occurred_at).
package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/MeeJay/Obligarth/apple-edge/internal/ids"
	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/reqctx"
)

// Channel is the NOTIFY channel that wakes the consumer.
const Channel = "apple_edge_outbox"

// Scopes.
const (
	ScopeTenant   = "tenant"
	ScopePlatform = "platform"
)

// Event is one outbox row.
type Event struct {
	Scope        string
	Tenant       string
	Type         string
	EnrollmentID string
	CommandUUID  string
	RequestID    string
	OccurredAt   time.Time
	Payload      any
}

// T returns a tenant-scoped event.
func T(tenant, typ string, payload any) Event {
	return Event{Scope: ScopeTenant, Tenant: tenant, Type: typ, Payload: payload}
}

// P returns a platform-scoped event.
func P(typ string, payload any) Event {
	return Event{Scope: ScopePlatform, Type: typ, Payload: payload}
}

// WithEnrollment sets the enrollment id.
func (e Event) WithEnrollment(id string) Event { e.EnrollmentID = id; return e }

// WithCommand sets the command UUID.
func (e Event) WithCommand(uuid string) Event { e.CommandUUID = uuid; return e }

// Querier is implemented by *sql.DB and *sql.Tx.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Writer inserts events and schedules the wake-up notification.
type Writer struct {
	db      *sql.DB
	metrics *obs.Metrics
	pending atomic.Bool
	wake    chan struct{}
	now     func() time.Time
}

// NewWriter returns a writer; call Run to deliver the notifications.
func NewWriter(db *sql.DB, m *obs.Metrics) *Writer {
	return &Writer{db: db, metrics: m, wake: make(chan struct{}, 1), now: time.Now}
}

// Insert writes events in the caller's transaction. Call Committed after
// the commit to wake the consumer.
func (w *Writer) Insert(ctx context.Context, q Querier, evs ...Event) error {
	rid := reqctx.RequestID(ctx)
	for _, e := range evs {
		if e.Scope == ScopeTenant && e.Tenant == "" {
			return fmt.Errorf("outbox: tenant event %s without tenant", e.Type)
		}
		if e.Scope == ScopePlatform {
			e.Tenant = ""
		}
		if e.OccurredAt.IsZero() {
			e.OccurredAt = w.now()
		}
		if e.RequestID == "" {
			e.RequestID = rid
		}
		payload := e.Payload
		if payload == nil {
			payload = map[string]any{}
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("outbox: payload of %s: %w", e.Type, err)
		}
		_, err = q.ExecContext(ctx, `
INSERT INTO apple_edge.outbox (event_id, scope, tenant_key, type, enrollment_id, command_uuid, request_id, occurred_at, payload)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			ids.NewUUID(), e.Scope, nullIf(e.Tenant), e.Type, nullIf(e.EnrollmentID), nullIf(e.CommandUUID),
			nullIf(e.RequestID), e.OccurredAt.UTC(), string(b))
		if err != nil {
			w.metrics.OutboxWrites.Inc("error")
			return fmt.Errorf("outbox: insert %s: %w", e.Type, err)
		}
	}
	return nil
}

// Committed schedules a notification (call after a successful commit).
func (w *Writer) Committed() {
	w.metrics.OutboxWrites.Inc("ok")
	w.pending.Store(true)
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Emit writes events in their own transaction and schedules the notification.
func (w *Writer) Emit(ctx context.Context, evs ...Event) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := w.Insert(ctx, tx, evs...); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	w.Committed()
	return nil
}

// Run sends at most ten NOTIFY per second while events are being written.
// Transactions that notify serialise at commit time: grouping them here
// keeps that cost off the device requests.
func (w *Writer) Run(ctx context.Context, logger *obs.Logger) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			w.flush(context.WithoutCancel(ctx), logger)
			return
		case <-w.wake:
		}
		select {
		case <-ctx.Done():
			w.flush(context.WithoutCancel(ctx), logger)
			return
		case <-tick.C:
		}
		w.flush(ctx, logger)
	}
}

func (w *Writer) flush(ctx context.Context, logger *obs.Logger) {
	if !w.pending.Swap(false) {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := w.db.ExecContext(cctx, `SELECT pg_notify($1, '')`, Channel); err != nil {
		logger.Info("msg", "outbox notify", "err", err)
		w.pending.Store(true)
	}
}

func nullIf(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
