// Package tenant holds the tenant registry of apple-edge: an immutable
// snapshot published through an atomic pointer (request paths never take a
// lock), rebuilt copy-on-write when a tenant changes, reloaded from
// PostgreSQL on NOTIFY and reconciled periodically. It also implements the
// tenant lifecycle (creation with its CA, states, freeze, retirement) and
// the import of push certificates.
package tenant

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"

	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
	"github.com/MeeJay/Obligarth/apple-edge/internal/outbox"
	"github.com/MeeJay/Obligarth/apple-edge/internal/scep"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Channel is the NOTIFY channel of registry changes (payload: tenant key).
const Channel = "apple_edge_registry"

// Tenant states.
const (
	StateActive    = "active"
	StateSuspended = "suspended"
	StateRetiring  = "retiring"
	StateRetired   = "retired"
)

// Topic states accepted by the guard.
const (
	TopicActive = "active"
	TopicLegacy = "legacy"
)

// CA is a CA of a tenant that verifies device identities.
type CA struct {
	ID     string
	Status string // active or verify_only
	Cert   *x509.Certificate
	SHA256 string
}

// Tenant is the in-memory view of a tenant. Values are immutable once published.
type Tenant struct {
	Key            string
	ExternalRef    string
	State          string // active or suspended; retiring tenants are absent
	CommandsFrozen bool
	UpdatedAt      time.Time
	LoadFailed     bool

	Roots  *x509.CertPool    // active + verify_only CAs of this tenant only
	CAs    []CA              // same, active first
	Topics map[string]string // topic -> active | legacy
	SCEP   http.Handler      // nil if LoadFailed
}

// HasTopic reports whether the guard accepts topic for this tenant.
func (t *Tenant) HasTopic(topic string) bool {
	_, ok := t.Topics[topic]
	return ok
}

// Serviceable reports whether devices may be served.
func (t *Tenant) Serviceable() bool { return t.State == StateActive && !t.LoadFailed }

type snapshot struct {
	byKey   map[string]*Tenant
	byTopic map[string]*Tenant
}

// Registry is the copy-on-write tenant registry.
type Registry struct {
	snap atomic.Pointer[snapshot]
	mu   sync.Mutex // serialises publications only

	db      *sql.DB
	keys    *store.Keyring
	scepCfg scep.Config
	out     *outbox.Writer
	logger  *obs.Logger
	metrics *obs.Metrics
	loaded  atomic.Bool

	failMu       sync.Mutex
	failReported map[string]time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry(db *sql.DB, keys *store.Keyring, scepCfg scep.Config, out *outbox.Writer, logger *obs.Logger, m *obs.Metrics) *Registry {
	r := &Registry{db: db, keys: keys, scepCfg: scepCfg, out: out, logger: logger.With("component", "registry"), metrics: m, failReported: map[string]time.Time{}}
	r.snap.Store(&snapshot{byKey: map[string]*Tenant{}, byTopic: map[string]*Tenant{}})
	return r
}

// Get returns the tenant with key (exact match), or nil. Lock-free.
func (r *Registry) Get(key string) *Tenant { return r.snap.Load().byKey[key] }

// ByTopic returns the tenant that owns topic, or nil. Lock-free.
func (r *Registry) ByTopic(topic string) *Tenant { return r.snap.Load().byTopic[topic] }

// Keys returns the keys of the tenants in the snapshot, sorted.
func (r *Registry) Keys() []string {
	s := r.snap.Load()
	out := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Loaded reports whether a full load succeeded (readiness).
func (r *Registry) Loaded() bool { return r.loaded.Load() }

// publish replaces (or removes, when t is nil) the entry of key, unless the
// snapshot already holds a newer version.
func (r *Registry) publish(key string, t *Tenant, seen time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.snap.Load()
	if cur := old.byKey[key]; cur != nil && cur.UpdatedAt.After(seen) {
		return
	}
	n := &snapshot{byKey: make(map[string]*Tenant, len(old.byKey)+1), byTopic: make(map[string]*Tenant, len(old.byTopic)+1)}
	for k, v := range old.byKey {
		if k != key {
			n.byKey[k] = v
		}
	}
	for topic, v := range old.byTopic {
		if v.Key != key {
			n.byTopic[topic] = v
		}
	}
	if t != nil {
		n.byKey[key] = t
		for topic := range t.Topics {
			n.byTopic[topic] = t
		}
	}
	r.snap.Store(n)
	r.updateGauge(n)
}

func (r *Registry) updateGauge(s *snapshot) {
	counts := map[string]int{StateActive: 0, StateSuspended: 0, "load_failed": 0}
	for _, t := range s.byKey {
		if t.LoadFailed {
			counts["load_failed"]++
		} else {
			counts[t.State]++
		}
	}
	for st, n := range counts {
		r.metrics.RegistryTenants.Set(float64(n), st)
	}
}

// Reload loads one tenant from the database and publishes it. Slow work
// (decrypting the CA key, building the SCEP service) happens before the
// publication lock.
func (r *Registry) Reload(ctx context.Context, key string) error {
	start := time.Now()
	t, seen, err := r.load(ctx, key)
	r.metrics.RegistryReloadDur.Observe(time.Since(start).Seconds())
	if err != nil {
		r.metrics.RegistryReloads.Inc("error")
		return err
	}
	r.publish(key, t, seen)
	r.metrics.RegistryReloads.Inc("ok")
	return nil
}

// ReloadAll reconciles the snapshot with the database: tenants whose
// updated_at changed are reloaded, removed ones are dropped.
func (r *Registry) ReloadAll(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `SELECT key, state, updated_at FROM apple_edge.tenants`)
	if err != nil {
		r.metrics.RegistryReloads.Inc("error")
		return err
	}
	type row struct {
		key, state string
		updated    time.Time
	}
	var all []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.key, &x.state, &x.updated); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	inDB := map[string]bool{}
	var firstErr error
	for _, x := range all {
		inDB[x.key] = true
		cur := r.Get(x.key)
		live := x.state == StateActive || x.state == StateSuspended
		switch {
		case !live && cur == nil:
			continue
		case cur != nil && cur.UpdatedAt.Equal(x.updated) && !cur.LoadFailed:
			continue
		}
		if err := r.Reload(ctx, x.key); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, k := range r.Keys() {
		if !inDB[k] {
			r.publish(k, nil, time.Now().Add(time.Hour))
		}
	}
	if firstErr == nil {
		r.loaded.Store(true)
	}
	return firstErr
}

// load reads a tenant. It returns a nil tenant when the tenant must not be
// in the snapshot (unknown, retiring or retired).
func (r *Registry) load(ctx context.Context, key string) (*Tenant, time.Time, error) {
	t := &Tenant{Key: key, Topics: map[string]string{}}
	err := r.db.QueryRowContext(ctx, `SELECT external_ref, state, commands_frozen, updated_at FROM apple_edge.tenants WHERE key = $1`, key).
		Scan(&t.ExternalRef, &t.State, &t.CommandsFrozen, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Now().Add(time.Hour), nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if t.State != StateActive && t.State != StateSuspended {
		return nil, t.UpdatedAt, nil
	}
	if err := r.loadCrypto(ctx, t); err != nil {
		r.logger.Error("msg", "tenant load failed", "tenant", key, "err", err)
		t.LoadFailed, t.SCEP = true, nil
		r.reportLoadFailure(ctx, key)
	}
	return t, t.UpdatedAt, nil
}

func (r *Registry) loadCrypto(ctx context.Context, t *Tenant) error {
	rows, err := r.db.QueryContext(ctx, `
SELECT id, status, cert_pem, key_enc FROM apple_edge.tenant_cas
 WHERE tenant_key = $1 AND status IN ('active', 'verify_only')
 ORDER BY (status = 'active') DESC, created_at DESC`, t.Key)
	if err != nil {
		return err
	}
	type caRow struct {
		CA
		keyEnc sql.NullString
	}
	var cas []caRow
	for rows.Next() {
		var c caRow
		var certPEM string
		if err := rows.Scan(&c.ID, &c.Status, &certPEM, &c.keyEnc); err != nil {
			rows.Close()
			return err
		}
		cert, err := parseCertPEM([]byte(certPEM))
		if err != nil {
			rows.Close()
			return fmt.Errorf("CA %s: %w", c.ID, err)
		}
		c.Cert = cert
		sum := sha256.Sum256(cert.Raw)
		c.SHA256 = hex.EncodeToString(sum[:])
		cas = append(cas, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(cas) == 0 || cas[0].Status != "active" {
		return errors.New("no active CA")
	}
	t.Roots = x509.NewCertPool()
	for _, c := range cas {
		t.Roots.AddCert(c.Cert)
		t.CAs = append(t.CAs, c.CA)
	}
	topicRows, err := r.db.QueryContext(ctx, `SELECT topic, state FROM apple_edge.push_certs WHERE tenant_key = $1 AND state IN ('active', 'legacy')`, t.Key)
	if err != nil {
		return err
	}
	for topicRows.Next() {
		var topic, st string
		if err := topicRows.Scan(&topic, &st); err != nil {
			topicRows.Close()
			return err
		}
		t.Topics[topic] = st
	}
	topicRows.Close()
	if err := topicRows.Err(); err != nil {
		return err
	}
	active := cas[0]
	if !active.keyEnc.Valid {
		return errors.New("active CA without key")
	}
	der, err := r.keys.Open(ctx, r.db, t.Key, "apple_edge.tenant_cas", "key_enc", active.ID, active.keyEnc.String)
	if err != nil {
		return fmt.Errorf("CA key: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return fmt.Errorf("CA key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return errors.New("CA key is not RSA")
	}
	h, err := scep.NewHandler(r.scepCfg, t.Key, scep.CA{ID: active.ID, Cert: active.Cert, Key: rk})
	if err != nil {
		return err
	}
	t.SCEP = h
	return nil
}

func (r *Registry) reportLoadFailure(ctx context.Context, key string) {
	r.failMu.Lock()
	last, seen := r.failReported[key]
	if seen && time.Since(last) < time.Hour {
		r.failMu.Unlock()
		return
	}
	r.failReported[key] = time.Now()
	r.failMu.Unlock()
	if err := r.out.Emit(ctx, outbox.P("tenant.load_failed", map[string]any{"key": key, "state": "load_failed"})); err != nil {
		r.logger.Error("msg", "outbox", "tenant", key, "err", err)
	}
}

// Run keeps the registry in sync: LISTEN on the registry channel through a
// dedicated connection (never pooled nor recycled), plus a full
// reconciliation every interval and after every reconnection.
func (r *Registry) Run(ctx context.Context, dsn string, interval time.Duration) {
	var reconnected atomic.Bool
	l := pq.NewListener(dsn, time.Second, 30*time.Second, func(ev pq.ListenerEventType, err error) {
		switch ev {
		case pq.ListenerEventReconnected:
			reconnected.Store(true)
			r.logger.Info("msg", "registry listener reconnected")
		case pq.ListenerEventDisconnected, pq.ListenerEventConnectionAttemptFailed:
			r.logger.Info("msg", "registry listener disconnected", "err", err)
		}
	})
	defer l.Close()
	if err := l.Listen(Channel); err != nil {
		r.logger.Error("msg", "registry listen", "err", err)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-l.Notify:
			if n == nil { // connection re-established: notifications may have been lost
				r.reconcile(ctx)
				continue
			}
			if n.Extra != "" && !r.upToDate(ctx, n.Extra) {
				if err := r.Reload(ctx, n.Extra); err != nil {
					r.logger.Error("msg", "registry reload", "tenant", n.Extra, "err", err)
				}
			}
		case <-tick.C:
			if reconnected.Swap(false) {
				r.logger.Info("msg", "registry reconciliation after reconnection")
			}
			r.reconcile(ctx)
		}
	}
}

// upToDate reports whether the snapshot already holds the current version
// of a tenant (the replica that made a change has applied it already).
func (r *Registry) upToDate(ctx context.Context, key string) bool {
	cur := r.Get(key)
	if cur == nil || cur.LoadFailed {
		return false
	}
	var updated time.Time
	var state string
	if err := r.db.QueryRowContext(ctx, `SELECT state, updated_at FROM apple_edge.tenants WHERE key = $1`, key).Scan(&state, &updated); err != nil {
		return false
	}
	return updated.Equal(cur.UpdatedAt) && state == cur.State
}

func (r *Registry) reconcile(ctx context.Context) {
	if err := r.ReloadAll(ctx); err != nil && ctx.Err() == nil {
		r.logger.Error("msg", "registry reconciliation", "err", err)
	}
}

func parseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}
