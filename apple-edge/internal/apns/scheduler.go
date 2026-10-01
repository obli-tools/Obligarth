package apns

import (
	"context"
	"database/sql"
	"errors"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/micromdm/nanomdm/push"
	pushsvc "github.com/micromdm/nanomdm/push/service"

	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Outcomes of a push request, as reported to the brain.
const (
	OutcomeSent     = "sent"     // accepted by APNs
	OutcomeDeferred = "deferred" // still queued (rate limit, back-off, retry)
	OutcomeDisabled = "disabled" // no usable certificate, or circuit open
	OutcomeError    = "error"    // refused by APNs, or given up
)

// Pusher sends pushes to enrollments: NanoMDM's push service.
type Pusher interface {
	Push(ctx context.Context, ids []string) (map[string]*push.Response, error)
}

// Scheduler queues push requests per tenant and sends them in batches:
// token buckets per tenant and global, round-robin between tenants (a large
// tenant never delays the others), at most one push per enrollment and per
// second, exponential back-off of a tenant after a 429, a few spaced
// attempts after 5xx and transport errors, and the outbox events of APNs
// answers (push_failed, token_inactive, throttled).
type Scheduler struct {
	Pusher  Pusher
	DB      *sql.DB
	Out     *outbox.Writer
	Logger  *obs.Logger
	Metrics *obs.Metrics
	Now     func() time.Time

	TenantRate, TenantBurst float64
	GlobalRate, GlobalBurst float64
	MaxBatch                int
	Parallel                int
	MaxAttempts             int
	RetryDelays             []time.Duration
	BackoffMin, BackoffMax  time.Duration
	Coalesce                time.Duration
	ThrottleReport          time.Duration

	once    sync.Once
	mu      sync.Mutex
	tenants map[string]*tenantQueue
	order   []string
	next    int
	global  bucket
	wake    chan struct{}
	sem     chan struct{}
	running sync.WaitGroup
}

type item struct {
	id        string
	notBefore time.Time
	attempts  int
	waiters   []chan string
}

type tenantQueue struct {
	key          string
	bucket       bucket
	queue        []*item
	pending      map[string]*item
	lastSent     map[string]time.Time
	inflight     bool
	backoffUntil time.Time
	backoffStep  int
	throttled    int
}

type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func (b *bucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.tokens, b.last = b.burst, now
		return
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(b.burst, b.tokens+d*b.rate)
		b.last = now
	}
}

// wait returns how long until one token is available.
func (b *bucket) wait() time.Duration {
	if b.tokens >= 1 || b.rate <= 0 {
		return 0
	}
	return time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}

func (s *Scheduler) init() {
	s.once.Do(func() {
		def := func(v *float64, d float64) {
			if *v <= 0 {
				*v = d
			}
		}
		def(&s.TenantRate, 50)
		def(&s.TenantBurst, 500)
		def(&s.GlobalRate, 500)
		def(&s.GlobalBurst, 1000)
		if s.MaxBatch <= 0 {
			s.MaxBatch = 100
		}
		if s.Parallel <= 0 {
			s.Parallel = 16
		}
		if s.MaxAttempts <= 0 {
			s.MaxAttempts = 3
		}
		if len(s.RetryDelays) == 0 {
			s.RetryDelays = []time.Duration{2 * time.Second, 10 * time.Second}
		}
		if s.BackoffMin <= 0 {
			s.BackoffMin = time.Second
		}
		if s.BackoffMax <= 0 {
			s.BackoffMax = 5 * time.Minute
		}
		if s.Coalesce <= 0 {
			s.Coalesce = time.Second
		}
		if s.ThrottleReport <= 0 {
			s.ThrottleReport = time.Minute
		}
		if s.Now == nil {
			s.Now = time.Now
		}
		s.tenants = map[string]*tenantQueue{}
		s.global = bucket{rate: s.GlobalRate, burst: s.GlobalBurst}
		s.wake = make(chan struct{}, 1)
		s.sem = make(chan struct{}, s.Parallel)
	})
}

func (s *Scheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Push queues pushes for enrollments of tenant and waits at most wait for
// their outcomes; pushes still queued then are reported "deferred" and
// sent later.
func (s *Scheduler) Push(ctx context.Context, tenant string, ids []string, wait time.Duration) map[string]string {
	s.init()
	chans := s.submit(tenant, ids)
	out := make(map[string]string, len(chans))
	timer := time.NewTimer(wait)
	defer timer.Stop()
	expired := false
	for id, ch := range chans {
		if expired {
			select {
			case o := <-ch:
				out[id] = o
			default:
				out[id] = OutcomeDeferred
			}
			continue
		}
		select {
		case o := <-ch:
			out[id] = o
		case <-timer.C:
			expired = true
		case <-ctx.Done():
			expired = true
		}
		if expired {
			select {
			case o := <-ch:
				out[id] = o
			default:
				out[id] = OutcomeDeferred
			}
		}
	}
	return out
}

func (s *Scheduler) submit(tenant string, ids []string) map[string]chan string {
	now := s.Now()
	chans := make(map[string]chan string, len(ids))
	s.mu.Lock()
	tq := s.tenants[tenant]
	if tq == nil {
		tq = &tenantQueue{key: tenant, bucket: bucket{rate: s.TenantRate, burst: s.TenantBurst},
			pending: map[string]*item{}, lastSent: map[string]time.Time{}}
		s.tenants[tenant] = tq
		s.order = append(s.order, tenant)
	}
	for _, id := range ids {
		if _, dup := chans[id]; dup {
			continue
		}
		ch := make(chan string, 1)
		chans[id] = ch
		if it := tq.pending[id]; it != nil {
			it.waiters = append(it.waiters, ch)
			continue
		}
		nb := now
		if last, ok := tq.lastSent[id]; ok && last.Add(s.Coalesce).After(now) {
			nb = last.Add(s.Coalesce)
		}
		it := &item{id: id, notBefore: nb, waiters: []chan string{ch}}
		tq.queue = append(tq.queue, it)
		tq.pending[id] = it
	}
	s.mu.Unlock()
	s.signal()
	return chans
}

type batch struct {
	tq    *tenantQueue
	items []*item
}

// Run dispatches the queued pushes until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	s.init()
	report := time.NewTicker(s.ThrottleReport)
	defer report.Stop()
	for {
		select {
		case <-report.C:
			s.reportThrottled(ctx)
		default:
		}
		now := s.Now()
		s.mu.Lock()
		batches, wait := s.pickLocked(now)
		s.mu.Unlock()
		for _, b := range batches {
			s.sem <- struct{}{}
			s.running.Add(1)
			go func(b batch) {
				defer s.running.Done()
				s.send(ctx, b)
				s.mu.Lock()
				b.tq.inflight = false
				s.mu.Unlock()
				<-s.sem
				s.signal()
			}(b)
		}
		if len(batches) > 0 {
			continue
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
		case <-t.C:
		case <-report.C:
			s.reportThrottled(ctx)
		}
		t.Stop()
	}
}

// pickLocked takes at most one ready batch per tenant, in round-robin
// order, and returns how long to wait when nothing is ready.
func (s *Scheduler) pickLocked(now time.Time) ([]batch, time.Duration) {
	var out []batch
	wait := time.Duration(0)
	soon := func(d time.Duration) {
		if d > 0 && (wait == 0 || d < wait) {
			wait = d
		}
	}
	free := cap(s.sem) - len(s.sem)
	s.global.refill(now)
	n := len(s.order)
	for i := 0; i < n && free > 0; i++ {
		tq := s.tenants[s.order[(s.next+i)%n]]
		if tq.inflight || len(tq.queue) == 0 {
			continue
		}
		if now.Before(tq.backoffUntil) {
			soon(tq.backoffUntil.Sub(now))
			continue
		}
		tq.bucket.refill(now)
		allowed := int(min(tq.bucket.tokens, s.global.tokens))
		if allowed < 1 {
			soon(max(tq.bucket.wait(), s.global.wait()))
			continue
		}
		allowed = min(allowed, s.MaxBatch)
		var take []*item
		rest := tq.queue[:0]
		for _, it := range tq.queue {
			// At most one push per enrollment and per Coalesce period.
			if last, ok := tq.lastSent[it.id]; ok && last.Add(s.Coalesce).After(it.notBefore) {
				it.notBefore = last.Add(s.Coalesce)
			}
			if len(take) < allowed && !it.notBefore.After(now) {
				take = append(take, it)
				continue
			}
			if it.notBefore.After(now) {
				soon(it.notBefore.Sub(now))
			}
			rest = append(rest, it)
		}
		tq.queue = rest
		if len(take) == 0 {
			continue
		}
		for _, it := range take {
			delete(tq.pending, it.id)
		}
		tq.bucket.tokens -= float64(len(take))
		s.global.tokens -= float64(len(take))
		tq.inflight = true
		free--
		out = append(out, batch{tq: tq, items: take})
	}
	if n > 0 {
		s.next = (s.next + 1) % n
	}
	if len(out) == 0 && wait == 0 {
		wait = time.Minute
	}
	return out, wait
}

type verdict struct {
	outcome string
	retry   bool // transient failure: try again later
	throttl bool // 429: back off the tenant and resend
}

func classify(r *push.Response, err error) verdict {
	if r == nil {
		if errors.Is(err, ErrDisabled) {
			return verdict{outcome: OutcomeDisabled}
		}
		if err != nil {
			return verdict{retry: true}
		}
		return verdict{outcome: OutcomeError}
	}
	if r.Err == nil {
		return verdict{outcome: OutcomeSent}
	}
	if errors.Is(r.Err, ErrCircuitOpen) {
		return verdict{outcome: OutcomeDisabled}
	}
	if errors.Is(r.Err, pushsvc.ErrIdNotFound) {
		return verdict{outcome: OutcomeError}
	}
	var ae *Error
	if !errors.As(r.Err, &ae) || ae.Transport() {
		return verdict{retry: true}
	}
	switch {
	case ae.Status == http.StatusForbidden:
		return verdict{outcome: OutcomeDisabled}
	case ae.Status == http.StatusTooManyRequests:
		return verdict{throttl: true}
	case ae.Status >= 500:
		return verdict{retry: true}
	}
	return verdict{outcome: OutcomeError}
}

type inactiveRow struct {
	enrollmentID, reason string
	apnsTime             time.Time
}

func (s *Scheduler) send(ctx context.Context, b batch) {
	tenant := b.tq.key
	ids := make([]string, len(b.items))
	for i, it := range b.items {
		ids[i] = it.id
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	resp, err := s.Pusher.Push(pctx, ids)
	cancel()
	if err != nil && !errors.Is(err, ErrDisabled) {
		s.Logger.Info("msg", "push batch", "component", "apns", "tenant", tenant, "count", len(ids), "err", err)
	}
	now := s.Now()
	var evs []outbox.Event
	var inactive []inactiveRow
	final := map[*item]string{}
	var requeue []*item
	throttled := 0
	sent := false
	for _, it := range b.items {
		var r *push.Response
		if resp != nil {
			r = resp[it.id]
		}
		v := classify(r, err)
		var ae *Error
		if r != nil {
			errors.As(r.Err, &ae)
		}
		switch {
		case v.throttl:
			throttled++
			requeue = append(requeue, it)
			continue
		case v.retry:
			it.attempts++
			if it.attempts < s.MaxAttempts {
				it.notBefore = now.Add(s.RetryDelays[min(it.attempts-1, len(s.RetryDelays)-1)])
				requeue = append(requeue, it)
				continue
			}
			v.outcome = OutcomeError
		}
		final[it] = v.outcome
		switch v.outcome {
		case OutcomeSent:
			sent = true
		case OutcomeDisabled:
			if r == nil && s.Metrics != nil {
				s.Metrics.APNsPushes.Inc(tenant, "disabled", "")
			}
		}
		if ae == nil || ae.Transport() {
			continue
		}
		switch {
		case ae.Status == http.StatusForbidden && ae.Opened:
			evs = append(evs, outbox.T(tenant, "apns.push_failed", map[string]any{
				"http_status": ae.Status, "reason": ae.Reason, "circuit_open": true}).WithEnrollment(it.id))
		case ae.Status == http.StatusGone:
			ts := any(nil)
			if !ae.Timestamp.IsZero() {
				ts = ae.Timestamp.Format(time.RFC3339Nano)
			}
			evs = append(evs, outbox.T(tenant, "apns.token_inactive", map[string]any{"apns_timestamp": ts, "reason": ae.Reason}).WithEnrollment(it.id))
			inactive = append(inactive, inactiveRow{it.id, "unregistered", ae.Timestamp})
		case ae.Status == http.StatusRequestEntityTooLarge:
			s.Logger.Error("msg", "APNs payload too large", "component", "apns", "tenant", tenant)
		case ae.Status >= 400 && ae.Status < 500 && ae.Status != http.StatusForbidden:
			evs = append(evs, outbox.T(tenant, "apns.push_failed", map[string]any{
				"http_status": ae.Status, "reason": ae.Reason, "circuit_open": false}).WithEnrollment(it.id))
			if ae.Reason == "BadDeviceToken" {
				inactive = append(inactive, inactiveRow{it.id, "bad_device_token", time.Time{}})
			}
		}
	}
	s.mu.Lock()
	tq := b.tq
	for it, o := range final {
		if o == OutcomeSent {
			tq.lastSent[it.id] = now
		}
	}
	if len(tq.lastSent) > 10000 {
		for id, t := range tq.lastSent {
			if now.Sub(t) > s.Coalesce {
				delete(tq.lastSent, id)
			}
		}
	}
	if throttled > 0 {
		tq.backoffStep++
		d := s.BackoffMin << min(tq.backoffStep-1, 20)
		d = min(d, s.BackoffMax)
		d = d*4/5 + time.Duration(rand.Int64N(int64(d)*2/5+1)) // +/- 20 % jitter
		tq.backoffUntil = now.Add(d)
		tq.throttled += throttled
	} else if sent {
		tq.backoffStep = 0
	}
	// Re-queued items go first, merged with requests that arrived meanwhile.
	var front []*item
	for _, it := range requeue {
		if other := tq.pending[it.id]; other != nil {
			other.waiters = append(other.waiters, it.waiters...)
			continue
		}
		tq.pending[it.id] = it
		front = append(front, it)
	}
	tq.queue = append(front, tq.queue...)
	s.mu.Unlock()
	if len(evs) > 0 || len(inactive) > 0 {
		if err := s.record(context.WithoutCancel(ctx), tenant, evs, inactive); err != nil {
			s.Logger.Error("msg", "recording APNs answers", "component", "apns", "tenant", tenant, "err", err)
		}
	}
	for it, o := range final {
		for _, w := range it.waiters {
			w <- o
		}
	}
}

// record writes the events of a batch and the proofs of inactivity of
// device channels in one transaction.
func (s *Scheduler) record(ctx context.Context, tenant string, evs []outbox.Event, inactive []inactiveRow) error {
	if s.DB == nil || s.Out == nil {
		return nil // no persistence configured
	}
	err := store.InTx(ctx, s.DB, func(tx *sql.Tx) error {
		for _, r := range inactive {
			if strings.Contains(r.enrollmentID, ":") {
				continue // user channel: the device channel holds the identifier
			}
			var ts any
			if !r.apnsTime.IsZero() {
				ts = r.apnsTime
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO apple_edge.apns_inactive (enrollment_id, tenant_key, reason, apns_timestamp)
VALUES ($1, $2, $3, $4) ON CONFLICT (enrollment_id) DO NOTHING`, r.enrollmentID, tenant, r.reason, ts); err != nil {
				return err
			}
		}
		return s.Out.Insert(ctx, tx, evs...)
	})
	if err == nil && len(evs) > 0 {
		s.Out.Committed()
	}
	return err
}

// reportThrottled emits apns.throttled, aggregated per tenant and period.
func (s *Scheduler) reportThrottled(ctx context.Context) {
	now := s.Now()
	var evs []outbox.Event
	s.mu.Lock()
	for _, tq := range s.tenants {
		if tq.throttled == 0 {
			continue
		}
		retry := max(0, int(tq.backoffUntil.Sub(now).Seconds()+0.5))
		evs = append(evs, outbox.T(tq.key, "apns.throttled", map[string]any{"count": tq.throttled, "retry_after_s": retry}))
		tq.throttled = 0
	}
	s.mu.Unlock()
	if len(evs) > 0 && s.Out != nil {
		if err := s.Out.Emit(context.WithoutCancel(ctx), evs...); err != nil {
			s.Logger.Error("msg", "apns.throttled", "component", "apns", "err", err)
		}
	}
}

// Wait waits for the batches in flight (at most until ctx ends), after Run returned.
func (s *Scheduler) Wait(ctx context.Context) error {
	s.init()
	done := make(chan struct{})
	go func() { s.running.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.New("apns: pushes still in flight at shutdown")
	}
}

// Queued returns the number of queued pushes of a tenant (tests, status).
func (s *Scheduler) Queued(tenant string) int {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	if tq := s.tenants[tenant]; tq != nil {
		return len(tq.queue)
	}
	return 0
}
