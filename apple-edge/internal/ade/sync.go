package ade

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanodep/godep"

	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Synchronisation defaults.
const (
	DefaultPageLimit  = 500
	DefaultFetchEvery = 6 * 24 * time.Hour
	TermsRetry        = time.Hour
	maxPages          = 10000
	unauthorizedLimit = 3
	alertAfter        = 3
)

// errLockLost stops a loop whose advisory lock is no longer held.
var errLockLost = errors.New("ade: advisory lock of the token lost")

// Supervisor runs one synchronisation loop per runnable token on the
// replica that holds the token's advisory lock. The locks are session
// locks held on one dedicated connection, never pooled nor recycled; if it
// breaks, every loop stops and the locks are taken again. Each page
// transaction checks that the lock is still held (fencing).
type Supervisor struct {
	Svc        *Service
	LockDB     *sql.DB // single connection, no lifetime limits
	Notes      <-chan store.Notification
	Interval   time.Duration
	PageLimit  int
	FetchEvery time.Duration
	BackoffMin time.Duration
	BackoffMax time.Duration
	TermsRetry time.Duration
	Reconcile  time.Duration
	Logger     *obs.Logger

	conn  *sql.Conn
	pid   int
	loops map[string]*loop
	wg    sync.WaitGroup
}

type loop struct {
	id, tenant string
	key        int64
	cancel     context.CancelFunc
	wake       chan struct{}
	done       chan struct{}
}

func (l *loop) poke() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *loop) finished() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// lockKey derives the advisory lock key of a token.
func lockKey(id string) int64 {
	sum := sha256.Sum256([]byte("apple_edge:ade:" + id))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func (s *Supervisor) defaults() {
	if s.Interval <= 0 {
		s.Interval = 30 * time.Minute
	}
	if s.PageLimit <= 0 {
		s.PageLimit = DefaultPageLimit
	}
	if s.FetchEvery <= 0 {
		s.FetchEvery = DefaultFetchEvery
	}
	if s.BackoffMin <= 0 {
		s.BackoffMin = 30 * time.Second
	}
	if s.BackoffMax <= 0 {
		s.BackoffMax = 30 * time.Minute
	}
	if s.TermsRetry <= 0 {
		s.TermsRetry = TermsRetry
	}
	if s.Reconcile <= 0 {
		s.Reconcile = time.Minute
	}
	s.loops = map[string]*loop{}
}

// Run supervises the loops until ctx ends, then stops them and releases
// the locks. A cursor is never written outside its page transaction.
func (s *Supervisor) Run(ctx context.Context) {
	s.defaults()
	tick := time.NewTicker(s.Reconcile)
	defer tick.Stop()
	s.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			s.stopAll()
			s.closeConn()
			return
		case n := <-s.Notes:
			if l := s.loops[n.Payload]; l != nil && !n.Reconnected && !l.finished() {
				l.poke()
				continue
			}
			s.reconcile(ctx)
		case <-tick.C:
			s.reconcile(ctx)
		}
	}
}

func (s *Supervisor) closeConn() {
	if s.conn == nil {
		return
	}
	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.conn.ExecContext(cctx, `SELECT pg_advisory_unlock_all()`)
	_ = s.conn.Close()
	s.conn, s.pid = nil, 0
}

// ensureConn checks the lock connection; when it broke, the locks are gone:
// every loop is stopped before a new connection is opened.
func (s *Supervisor) ensureConn(ctx context.Context) error {
	if s.conn != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.conn.QueryRowContext(cctx, `SELECT pg_backend_pid()`).Scan(new(int))
		cancel()
		if err == nil {
			return nil
		}
		s.Logger.Error("msg", "ADE lock connection lost: loops stopped", "component", "ade", "err", err)
		s.stopAll()
		_ = s.conn.Close()
		s.conn, s.pid = nil, 0
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := s.LockDB.Conn(cctx)
	if err != nil {
		return err
	}
	var pid int
	if err := conn.QueryRowContext(cctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		_ = conn.Close()
		return err
	}
	s.conn, s.pid = conn, pid
	return nil
}

func (s *Supervisor) reconcile(ctx context.Context) {
	if err := s.ensureConn(ctx); err != nil {
		if ctx.Err() == nil {
			s.Logger.Error("msg", "ADE lock connection", "component", "ade", "err", err)
		}
		return
	}
	rows, err := s.Svc.DB.QueryContext(ctx, `
SELECT a.id::text, a.tenant_key FROM apple_edge.ade_tokens a JOIN apple_edge.tenants t ON t.key = a.tenant_key
 WHERE a.state IN ('active', 'terms_not_signed') AND t.state = 'active'`)
	if err != nil {
		if ctx.Err() == nil {
			s.Logger.Error("msg", "ADE token list", "component", "ade", "err", err)
		}
		return
	}
	runnable := map[string]string{}
	for rows.Next() {
		var id, tenant string
		if err := rows.Scan(&id, &tenant); err != nil {
			rows.Close()
			return
		}
		runnable[id] = tenant
	}
	rows.Close()
	for id, l := range s.loops {
		if _, ok := runnable[id]; !ok || l.finished() {
			s.stop(l)
		}
	}
	for id, tenant := range runnable {
		if s.loops[id] != nil {
			continue
		}
		key := lockKey(id)
		var got bool
		if err := s.conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
			s.Logger.Error("msg", "ADE lock", "component", "ade", "ade_token", id, "err", err)
			return
		}
		if !got {
			continue // another replica runs this token
		}
		lctx, cancel := context.WithCancel(ctx)
		l := &loop{id: id, tenant: tenant, key: key, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
		s.loops[id] = l
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer close(l.done)
			s.run(lctx, l)
		}()
	}
}

func (s *Supervisor) stop(l *loop) {
	l.cancel()
	<-l.done
	delete(s.loops, l.id)
	if s.conn != nil {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = s.conn.ExecContext(cctx, `SELECT pg_advisory_unlock($1)`, l.key)
		cancel()
	}
}

func (s *Supervisor) stopAll() {
	for _, l := range s.loops {
		l.cancel()
	}
	for _, l := range s.loops {
		<-l.done
		delete(s.loops, l.id)
	}
	s.wg.Wait()
}

// run is the loop of one token: a cycle at start, then every interval, on
// demand, or after the delay chosen by the last cycle.
func (s *Supervisor) run(ctx context.Context, l *loop) {
	for {
		next := s.cycle(ctx, l)
		if next < 0 || ctx.Err() != nil {
			return
		}
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-l.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// fence checks, inside a transaction, that this replica still holds the
// advisory lock of the token.
func (s *Supervisor) fence(ctx context.Context, tx *sql.Tx, l *loop) error {
	var ok bool
	k := uint64(l.key)
	err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = $1
                  AND classid = $2::bigint::oid AND objid = $3::bigint::oid AND objsubid = 1)`,
		s.pid, int64(k>>32), int64(k&0xffffffff)).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return errLockLost
	}
	return nil
}

type tokenState struct {
	tenant, state     string
	notAfter          sql.NullTime
	lastFetch         sql.NullTime
	consecutiveErrors int
}

func (s *Supervisor) load(ctx context.Context, id string) (*tokenState, error) {
	var t tokenState
	var tenantState string
	err := s.Svc.DB.QueryRowContext(ctx, `
SELECT a.tenant_key, a.state, a.token_not_after, a.last_fetch_at, a.consecutive_errors, t.state
  FROM apple_edge.ade_tokens a JOIN apple_edge.tenants t ON t.key = a.tenant_key WHERE a.id = $1`, id).
		Scan(&t.tenant, &t.state, &t.notAfter, &t.lastFetch, &t.consecutiveErrors, &tenantState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if tenantState != "active" || (t.state != StateActive && t.state != StateTerms) {
		return nil, nil
	}
	return &t, nil
}

// cycle runs one synchronisation (pages, then automatic assignment) and
// returns the delay before the next one; < 0 stops the loop.
func (s *Supervisor) cycle(ctx context.Context, l *loop) time.Duration {
	tok, err := s.load(ctx, l.id)
	if err != nil {
		if ctx.Err() != nil {
			return -1
		}
		s.Logger.Error("msg", "ADE token load", "component", "ade", "ade_token", l.id, "err", err)
		return s.BackoffMin
	}
	if tok == nil {
		return -1
	}
	now := s.Svc.now()
	if tok.notAfter.Valid && !now.Before(tok.notAfter.Time) {
		s.setState(ctx, l, StateExpired, "token_expired", nil)
		return -1
	}
	err = s.syncPages(ctx, l, tok)
	if err == nil {
		err = s.autoAssign(ctx, l)
	}
	m := s.Svc.Metrics
	if err == nil {
		if _, err := s.Svc.DB.ExecContext(ctx, `
UPDATE apple_edge.ade_tokens SET state = 'active', consecutive_errors = 0, last_error = NULL, updated_at = now()
 WHERE id = $1 AND state IN ('active', 'terms_not_signed')`, l.id); err != nil && ctx.Err() == nil {
			s.Logger.Error("msg", "ADE token update", "component", "ade", "ade_token", l.id, "err", err)
		}
		if m != nil {
			m.ADESync.Inc(l.tenant, "ok")
			m.ADELastSync.Set(float64(s.Svc.now().Unix()), l.tenant, l.id)
		}
		return s.Interval
	}
	if ctx.Err() != nil || errors.Is(err, errLockLost) {
		return -1
	}
	kind, code := Classify(err)
	if m != nil {
		m.ADESync.Inc(l.tenant, code)
	}
	s.Logger.Info("msg", "ADE synchronisation failed", "component", "ade", "tenant", l.tenant, "ade_token", l.id, "outcome", code, "err", err)
	n := tok.consecutiveErrors + 1
	switch kind {
	case KindTerms:
		if tok.state != StateTerms {
			s.setState(ctx, l, StateTerms, code, &outboxEvent{"ade.terms_not_signed", code})
		}
		return s.TermsRetry
	case KindAccessDenied:
		s.setState(ctx, l, StateError, code, &outboxEvent{"ade.sync_error", code})
		return -1
	case KindUnauthorized:
		if n >= unauthorizedLimit {
			s.setState(ctx, l, StateError, code, &outboxEvent{"ade.sync_error", code})
			return -1
		}
	}
	var ev *outboxEvent
	if n == alertAfter {
		ev = &outboxEvent{"ade.sync_error", code}
	}
	s.countError(ctx, l, code, ev)
	return s.backoff(n)
}

func (s *Supervisor) backoff(n int) time.Duration {
	d := s.BackoffMin << min(n-1, 20)
	d = min(d, s.BackoffMax)
	return d*4/5 + time.Duration(rand.Int64N(int64(d)*2/5+1))
}

type outboxEvent struct{ typ, code string }

func (s *Supervisor) setState(ctx context.Context, l *loop, state, code string, ev *outboxEvent) {
	err := store.InTx(ctx, s.Svc.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
UPDATE apple_edge.ade_tokens SET state = $2, last_error = $3, consecutive_errors = consecutive_errors + 1, updated_at = now()
 WHERE id = $1 AND state IN ('active', 'terms_not_signed')`, l.id, state, code); err != nil {
			return err
		}
		if ev == nil {
			return nil
		}
		return s.Svc.Out.Insert(ctx, tx, outbox.T(l.tenant, ev.typ, map[string]any{"token_id": l.id, "code": ev.code}))
	})
	if err != nil {
		s.Logger.Error("msg", "ADE token state", "component", "ade", "ade_token", l.id, "err", err)
		return
	}
	if ev != nil {
		s.Svc.Out.Committed()
	}
}

func (s *Supervisor) countError(ctx context.Context, l *loop, code string, ev *outboxEvent) {
	err := store.InTx(ctx, s.Svc.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
UPDATE apple_edge.ade_tokens SET consecutive_errors = consecutive_errors + 1, last_error = $2, updated_at = now() WHERE id = $1`, l.id, code); err != nil {
			return err
		}
		if ev == nil {
			return nil
		}
		return s.Svc.Out.Insert(ctx, tx, outbox.T(l.tenant, ev.typ, map[string]any{"token_id": l.id, "code": ev.code}))
	})
	if err != nil {
		s.Logger.Error("msg", "ADE token errors", "component", "ade", "ade_token", l.id, "err", err)
		return
	}
	if ev != nil {
		s.Svc.Out.Committed()
	}
}

// syncPages fetches (full list) or syncs (changes) page by page; each page
// is one transaction: devices, event and cursor together.
func (s *Supervisor) syncPages(ctx context.Context, l *loop, tok *tokenState) error {
	var cursor sql.NullString
	if err := s.Svc.DB.QueryRowContext(ctx, `SELECT syncer_cursor FROM nanodep.dep_names WHERE name = $1`, l.id).Scan(&cursor); err != nil {
		return err
	}
	cur := cursor.String
	fetch := cur == "" || !tok.lastFetch.Valid || s.Svc.now().Sub(tok.lastFetch.Time) > s.FetchEvery
	var fetchStart time.Time
	startFetch := func() error {
		fetch, cur = true, ""
		return s.Svc.DB.QueryRowContext(ctx, `SELECT now()`).Scan(&fetchStart)
	}
	if fetch {
		if err := startFetch(); err != nil {
			return err
		}
	}
	restarted := false
	client := s.Svc.Client()
	for page := 0; ; page++ {
		if page >= maxPages {
			return errors.New("ade: too many pages in one cycle")
		}
		opts := []godep.DeviceRequestOption{godep.WithLimit(s.PageLimit)}
		if cur != "" {
			opts = append(opts, godep.WithCursor(cur))
		}
		var resp *godep.FetchDeviceResponse
		var err error
		if fetch {
			resp, err = client.FetchDevices(ctx, l.id, opts...)
		} else {
			resp, err = client.SyncDevices(ctx, l.id, opts...)
		}
		if err != nil {
			switch {
			case fetch && cur != "" && godep.IsCursorExhausted(err):
				fetch = false
				continue
			case !restarted && (godep.IsCursorExpired(err) || godep.IsCursorInvalid(err)):
				restarted = true
				if err := startFetch(); err != nil {
					return err
				}
				continue
			}
			return err
		}
		last := !resp.MoreToFollow
		if err := s.commitPage(ctx, l, fetch, last, fetchStart, resp); err != nil {
			return err
		}
		cur = resp.Cursor
		if resp.MoreToFollow {
			continue
		}
		if fetch {
			fetch = false // then catch up with the changes made during the fetch
			continue
		}
		return nil
	}
}

func deref[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return
}

// deviceEvent keeps the fields of a device the brain receives (never
// device_assigned_by, the e-mail address of an Apple administrator).
func deviceEvent(d godep.Device) map[string]any {
	m := map[string]any{"serial_number": d.SerialNumber, "model": d.Model}
	str := func(k string, v *string) {
		if v != nil {
			m[k] = *v
		}
	}
	tm := func(k string, v *time.Time) {
		if v != nil {
			m[k] = v.UTC().Format(time.RFC3339)
		}
	}
	str("description", d.Description)
	str("color", d.Color)
	if d.DeviceFamily != nil {
		m["device_family"] = string(*d.DeviceFamily)
	}
	if d.OS != nil {
		m["os"] = string(*d.OS)
	}
	if d.ProfileStatus != nil {
		m["profile_status"] = string(*d.ProfileStatus)
	}
	str("profile_uuid", d.ProfileUUID)
	tm("profile_assign_time", d.ProfileAssignTime)
	tm("device_assigned_date", d.DeviceAssignedDate)
	if d.OpType != nil {
		m["op_type"] = string(*d.OpType)
	}
	tm("op_date", d.OpDate)
	tm("mdm_migration_deadline", d.MdmMigrationDeadline)
	if len(d.IMEI) > 0 {
		m["imei"] = d.IMEI
	}
	if len(d.MEID) > 0 {
		m["meid"] = d.MEID
	}
	str("eid", d.EID)
	str("wifi_mac_address", d.WiFiMACAddress)
	str("bluetooth_mac_address", d.BluetoothMACAddress)
	str("ethernet_mac_address", d.EthernetMACAddress)
	return m
}

func (s *Supervisor) commitPage(ctx context.Context, l *loop, fetch, last bool, fetchStart time.Time, resp *godep.FetchDeviceResponse) error {
	phase := "sync"
	if fetch {
		phase = "fetch"
	}
	events := 0
	err := store.InTx(ctx, s.Svc.DB, func(tx *sql.Tx) error {
		if err := s.fence(ctx, tx, l); err != nil {
			return err
		}
		devices := make([]map[string]any, 0, len(resp.Devices))
		for _, d := range resp.Devices {
			if d.SerialNumber == "" {
				continue
			}
			devices = append(devices, deviceEvent(d))
			op := strings.ToLower(string(deref(d.OpType)))
			var opDate any
			if d.OpDate != nil {
				opDate = d.OpDate.UTC()
			}
			if op == "deleted" {
				if _, err := tx.ExecContext(ctx, `
DELETE FROM apple_edge.ade_devices
 WHERE token_id = $1 AND serial = $2 AND (op_date IS NULL OR $3::timestamptz IS NULL OR op_date <= $3::timestamptz)`, l.id, d.SerialNumber, opDate); err != nil {
					return err
				}
				continue
			}
			var status any
			if d.ProfileStatus != nil {
				status = string(*d.ProfileStatus)
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.ade_devices (token_id, serial, tenant_key, op_type, op_date, profile_uuid, profile_status)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (token_id, serial) DO UPDATE SET op_type = EXCLUDED.op_type, op_date = EXCLUDED.op_date,
    profile_uuid = EXCLUDED.profile_uuid, profile_status = EXCLUDED.profile_status, updated_at = now()
 WHERE apple_edge.ade_devices.op_date IS NULL OR EXCLUDED.op_date IS NULL OR EXCLUDED.op_date >= apple_edge.ade_devices.op_date`,
				l.id, d.SerialNumber, l.tenant, nullIf(op), opDate, d.ProfileUUID, status); err != nil {
				return err
			}
		}
		var evs []outbox.Event
		if len(devices) > 0 {
			evs = append(evs, outbox.T(l.tenant, "ade.devices", map[string]any{"token_id": l.id, "phase": phase, "devices": devices}))
		}
		if fetch && !last {
			// A fetch in progress: an interruption restarts it from scratch.
			if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_tokens SET last_fetch_at = NULL WHERE id = $1`, l.id); err != nil {
				return err
			}
		}
		if fetch && last {
			// A complete fetch lists every device: the others left the server.
			rows, err := tx.QueryContext(ctx, `DELETE FROM apple_edge.ade_devices WHERE token_id = $1 AND updated_at < $2 RETURNING serial`, l.id, fetchStart)
			if err != nil {
				return err
			}
			var gone []map[string]any
			for rows.Next() {
				var sn string
				if err := rows.Scan(&sn); err != nil {
					rows.Close()
					return err
				}
				gone = append(gone, map[string]any{"serial_number": sn, "op_type": "deleted", "op_date": fetchStart.UTC().Format(time.RFC3339)})
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			if len(gone) > 0 {
				evs = append(evs, outbox.T(l.tenant, "ade.devices", map[string]any{"token_id": l.id, "phase": "fetch", "devices": gone}))
			}
			if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_tokens SET last_fetch_at = $2 WHERE id = $1`, l.id, fetchStart); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE nanodep.dep_names SET syncer_cursor = $2 WHERE name = $1`, l.id, nullIf(resp.Cursor)); err != nil {
			return err
		}
		if last && !fetch {
			if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_tokens SET last_sync_at = now() WHERE id = $1`, l.id); err != nil {
				return err
			}
		}
		events = len(evs)
		return s.Svc.Out.Insert(ctx, tx, evs...)
	})
	if err == nil && events > 0 {
		s.Svc.Out.Committed()
	}
	return err
}

// autoAssign gives every device of the token the profile it should have
// (its wanted usage, or the default profile) when it has none, when Apple
// removed it, or when the profile of its usage was redefined.
func (s *Supervisor) autoAssign(ctx context.Context, l *loop) error {
	rows, err := s.Svc.DB.QueryContext(ctx, `
SELECT d.serial, coalesce(p.usage, def.usage), coalesce(p.profile_uuid, def.profile_uuid)
  FROM apple_edge.ade_devices d
  LEFT JOIN apple_edge.ade_profiles p ON p.token_id = d.token_id AND p.usage = d.wanted_usage
  LEFT JOIN apple_edge.ade_profiles def ON def.token_id = d.token_id AND def.is_default AND d.wanted_usage IS NULL
 WHERE d.token_id = $1
   AND coalesce(p.profile_uuid, def.profile_uuid) IS NOT NULL
   AND (d.profile_uuid IS DISTINCT FROM coalesce(p.profile_uuid, def.profile_uuid)
        OR coalesce(d.profile_status, '') IN ('', 'empty', 'removed'))
 ORDER BY d.serial`, l.id)
	if err != nil {
		return err
	}
	type target struct{ usage, uuid string }
	groups := map[target][]string{}
	var order []target
	for rows.Next() {
		var sn string
		var t target
		if err := rows.Scan(&sn, &t.usage, &t.uuid); err != nil {
			rows.Close()
			return err
		}
		if _, ok := groups[t]; !ok {
			order = append(order, t)
		}
		groups[t] = append(groups[t], sn)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range order {
		serials := groups[t]
		for start := 0; start < len(serials); start += assignChunk {
			chunk := serials[start:min(start+assignChunk, len(serials))]
			resp, err := s.Svc.Client().AssignProfile(ctx, l.id, t.uuid, chunk...)
			if err != nil {
				return err
			}
			results := map[string]string{}
			for _, sn := range chunk {
				results[sn] = string(resp.Devices[sn])
			}
			if err := s.Svc.recordAssignment(ctx, l.tenant, l.id, t.usage, t.uuid, results, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// TokenExpiryThresholds are the days before expiry of an ADE token at
// which ade.token_expiring is emitted (then at expiry).
var TokenExpiryThresholds = []int{1, 7, 14, 30}

// CheckTokenExpiry emits ade.token_expiring at the thresholds, then at
// expiry (the token goes to "expired" and its loop stops). Singleton job.
func CheckTokenExpiry(ctx context.Context, db *sql.DB, out *outbox.Writer, m *obs.Metrics, now time.Time) (int, error) {
	n := 0
	err := store.InTx(ctx, db, func(tx *sql.Tx) error {
		ok, err := store.TryXactLock(ctx, tx, "ade-expiry")
		if err != nil || !ok {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
SELECT a.id::text, a.tenant_key, a.token_not_after, a.state
  FROM apple_edge.ade_tokens a JOIN apple_edge.tenants t ON t.key = a.tenant_key
 WHERE a.state IN ('active', 'terms_not_signed', 'error', 'expired') AND a.token_not_after IS NOT NULL
   AND t.state IN ('active', 'suspended')`)
		if err != nil {
			return err
		}
		type tok struct {
			id, tenant, state string
			notAfter          time.Time
		}
		var all []tok
		for rows.Next() {
			var t tok
			if err := rows.Scan(&t.id, &t.tenant, &t.notAfter, &t.state); err != nil {
				rows.Close()
				return err
			}
			all = append(all, t)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var evs []outbox.Event
		for _, t := range all {
			if m != nil {
				m.ADETokenExpiry.Set(float64(t.notAfter.Unix()), t.tenant, t.id)
			}
			th := store.ExpiryThreshold(t.notAfter, now, TokenExpiryThresholds)
			if th < 0 {
				continue
			}
			if th == 0 && t.state != StateExpired {
				if _, err := tx.ExecContext(ctx, `UPDATE apple_edge.ade_tokens SET state = 'expired', last_error = 'token_expired', updated_at = now() WHERE id = $1`, t.id); err != nil {
					return err
				}
				if err := store.Notify(ctx, tx, Channel, t.id); err != nil {
					return err
				}
			}
			first, err := store.MarkExpiryAlert(ctx, tx, t.tenant, "ade_token:"+t.id, th)
			if err != nil {
				return err
			}
			if !first {
				continue
			}
			code := "token_expiring"
			if th == 0 {
				code = "token_expired"
			}
			evs = append(evs, outbox.T(t.tenant, "ade.token_expiring", map[string]any{
				"token_id": t.id, "code": code, "days_left": th, "not_after": t.notAfter.UTC().Format(time.RFC3339)}))
		}
		n = len(evs)
		return out.Insert(ctx, tx, evs...)
	})
	if err == nil && n > 0 {
		out.Committed()
	}
	return n, err
}
