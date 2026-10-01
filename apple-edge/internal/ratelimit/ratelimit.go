// Package ratelimit provides in-memory token buckets keyed by string and a
// limiter of failures per source address. State is per replica and is
// never persisted nor logged.
package ratelimit

import (
	"hash/maphash"
	"sync"
	"time"
)

const shards = 32

// Limiter is a set of token buckets (rate per second, burst) keyed by string.
type Limiter struct {
	rate, burst float64
	maxKeys     int
	now         func() time.Time
	seed        maphash.Seed
	shard       [shards]shard
}

type shard struct {
	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter; maxKeys bounds memory (buckets of idle keys are
// dropped first, and beyond the bound new keys are refused).
func New(rate, burst float64, maxKeys int) *Limiter {
	l := &Limiter{rate: rate, burst: burst, maxKeys: maxKeys, now: time.Now, seed: maphash.MakeSeed()}
	for i := range l.shard {
		l.shard[i].m = map[string]*bucket{}
	}
	return l
}

func (l *Limiter) shardOf(key string) *shard {
	return &l.shard[maphash.String(l.seed, key)%shards]
}

// Allow takes one token for key.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	s := l.shardOf(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.m[key]
	if b == nil {
		if len(s.m) >= l.maxKeys/shards+1 {
			l.sweepLocked(s, now)
			if len(s.m) >= l.maxKeys/shards+1 {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		s.m[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops the buckets that are full again (idle keys).
func (l *Limiter) sweepLocked(s *shard, now time.Time) {
	for k, b := range s.m {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(s.m, k)
		}
	}
}

// Sweep drops idle buckets in every shard (call periodically).
func (l *Limiter) Sweep() {
	now := l.now()
	for i := range l.shard {
		s := &l.shard[i]
		s.mu.Lock()
		l.sweepLocked(s, now)
		s.mu.Unlock()
	}
}

// FailLimiter blocks a source after too many failures in a window.
type FailLimiter struct {
	limit   int
	window  time.Duration
	block   time.Duration
	maxKeys int
	now     func() time.Time
	mu      sync.Mutex
	m       map[string]*failEntry
}

type failEntry struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

// NewFailLimiter allows limit failures per window, then blocks for block.
// A limit of 0 disables the limiter.
func NewFailLimiter(limit int, window, block time.Duration, maxKeys int) *FailLimiter {
	return &FailLimiter{limit: limit, window: window, block: block, maxKeys: maxKeys, now: time.Now, m: map[string]*failEntry{}}
}

// Blocked reports whether source is currently blocked.
func (f *FailLimiter) Blocked(source string) bool {
	if f.limit <= 0 || source == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.m[source]
	return e != nil && f.now().Before(e.blockedUntil)
}

// Fail records one failure of source.
func (f *FailLimiter) Fail(source string) {
	if f.limit <= 0 || source == "" {
		return
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.m[source]
	if e == nil {
		if len(f.m) >= f.maxKeys {
			f.sweepLocked(now)
			if len(f.m) >= f.maxKeys {
				return
			}
		}
		e = &failEntry{windowStart: now}
		f.m[source] = e
	}
	if now.Sub(e.windowStart) > f.window {
		e.count, e.windowStart = 0, now
	}
	e.count++
	if e.count > f.limit {
		e.blockedUntil = now.Add(f.block)
	}
}

func (f *FailLimiter) sweepLocked(now time.Time) {
	for k, e := range f.m {
		if now.Sub(e.windowStart) > f.window && now.After(e.blockedUntil) {
			delete(f.m, k)
		}
	}
}

// Sweep drops expired entries (call periodically).
func (f *FailLimiter) Sweep() {
	f.mu.Lock()
	f.sweepLocked(f.now())
	f.mu.Unlock()
}
