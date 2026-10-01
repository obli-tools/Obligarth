package apns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
	"golang.org/x/net/http2"

	"github.com/MeeJay/Obligarth/apple-edge/internal/obs"
)

// Provider defaults.
const (
	DefaultWorkers     = 8
	DefaultTimeout     = 10 * time.Second
	DefaultCircuitOpen = 15 * time.Minute
	maxErrorBody       = 4 << 10
)

// ErrCircuitOpen is returned without contacting APNs while the circuit of
// a certificate is open (after a 403).
var ErrCircuitOpen = errors.New("apns: circuit open after a 403")

// Error is an APNs answer other than 200, or a transport failure (Status 0).
type Error struct {
	Status    int
	Reason    string
	Timestamp time.Time // 410: last time the token was valid for the topic
	Opened    bool      // this 403 opened the circuit of the certificate
	Err       error     // transport error
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return "apns: transport: " + obs.ErrString(e.Err)
	}
	return fmt.Sprintf("apns: HTTP %d %s", e.Status, e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

// Transport reports a failure before any HTTP answer.
func (e *Error) Transport() bool { return e.Status == 0 }

// Factory implements NanoMDM's push.PushProviderFactory: one provider per
// push certificate, hence per tenant (and per topic).
type Factory struct {
	BaseURL     string
	Expiration  time.Duration
	RootCAs     *x509.CertPool // nil: system roots
	Workers     int
	Timeout     time.Duration
	CircuitOpen time.Duration
	Metrics     *obs.Metrics
	Logger      *obs.Logger
	TenantOf    func(topic string) string
	Now         func() time.Time

	mu        sync.Mutex
	providers map[string]*Provider
	last      map[string]Status
}

// Status is the last APNs answer seen for a topic on this replica.
type Status struct {
	HTTPStatus  int       `json:"http_status"`
	Reason      string    `json:"reason,omitempty"`
	At          time.Time `json:"at"`
	CircuitOpen bool      `json:"circuit_open"`
}

// LastStatus returns the last APNs answer for topic, if any.
func (f *Factory) LastStatus(topic string) (Status, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.last[topic]
	if p := f.providers[topic]; ok && p != nil {
		st.CircuitOpen = !p.circuit.closed()
	}
	return st, ok
}

func (f *Factory) record(topic string, status int, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		f.last = map[string]Status{}
	}
	f.last[topic] = Status{HTTPStatus: status, Reason: reason, At: f.now().UTC()}
}

func (f *Factory) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// NewPushProvider builds the HTTP/2 client of a push certificate.
func (f *Factory) NewPushProvider(cert *tls.Certificate) (push.PushProvider, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("apns: empty certificate")
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	topic, err := cryptoutil.TopicFromCert(leaf)
	if err != nil {
		return nil, fmt.Errorf("apns: push certificate without topic: %w", err)
	}
	// HTTP/2 only (APNs), one connection per certificate: concurrent first
	// requests share a single dial. PING after an hour without traffic
	// (Apple's advice), then 15 s to answer before the connection is
	// considered dead. Each dial resolves the name again.
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}}
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, RootCAs: f.RootCAs},
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := *dialer
			d.Config = cfg
			return d.DialContext(ctx, network, addr)
		},
		ReadIdleTimeout: time.Hour,
		PingTimeout:     15 * time.Second,
	}
	workers, timeout, open := f.Workers, f.Timeout, f.CircuitOpen
	if workers < 1 {
		workers = DefaultWorkers
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if open <= 0 {
		open = DefaultCircuitOpen
	}
	tenant := ""
	if f.TenantOf != nil {
		tenant = f.TenantOf(topic)
	}
	p := &Provider{f: f, topic: topic, tenant: tenant, transport: tr, client: &http.Client{Transport: tr},
		sem: make(chan struct{}, workers), timeout: timeout, circuit: circuit{openFor: open}}
	f.mu.Lock()
	if f.providers == nil {
		f.providers = map[string]*Provider{}
	}
	old := f.providers[topic]
	f.providers[topic] = p
	f.mu.Unlock()
	if old != nil {
		// Renewed certificate: the previous connection closes once idle.
		old.transport.CloseIdleConnections()
		time.AfterFunc(30*time.Second, old.transport.CloseIdleConnections)
	}
	if f.Metrics != nil && tenant != "" {
		f.Metrics.APNsCircuitOpen.Set(0, tenant)
	}
	return p, nil
}

// Close closes the idle connections of every provider (shutdown).
func (f *Factory) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.providers {
		p.transport.CloseIdleConnections()
	}
}

// Provider sends the pushes of one certificate.
type Provider struct {
	f         *Factory
	topic     string
	tenant    string
	transport *http2.Transport
	client    *http.Client
	sem       chan struct{}
	timeout   time.Duration
	circuit   circuit
}

// Push sends pushes concurrently (bounded by the workers of the provider)
// and returns the responses keyed by hex token.
func (p *Provider) Push(ctx context.Context, infos []*mdm.Push) (map[string]*push.Response, error) {
	if len(infos) == 0 {
		return nil, errors.New("apns: no push data")
	}
	out := make(map[string]*push.Response, len(infos))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, info := range infos {
		if info == nil {
			continue
		}
		select {
		case p.sem <- struct{}{}:
		case <-ctx.Done():
			mu.Lock()
			out[info.Token.String()] = &push.Response{Err: &Error{Err: ctx.Err()}}
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(info *mdm.Push) {
			defer wg.Done()
			defer func() { <-p.sem }()
			r := p.one(ctx, info)
			mu.Lock()
			out[info.Token.String()] = r
			mu.Unlock()
		}(info)
	}
	wg.Wait()
	return out, nil
}

func (p *Provider) one(ctx context.Context, info *mdm.Push) *push.Response {
	if info.Topic != p.topic {
		// Never push with the certificate of another topic.
		return &push.Response{Err: &Error{Err: errors.New("topic of the enrollment differs from the certificate")}}
	}
	ok, probe := p.circuit.allow(p.f.now())
	if !ok {
		p.count("circuit_open", 0)
		return &push.Response{Err: ErrCircuitOpen}
	}
	start := time.Now()
	id, aerr := p.send(ctx, info)
	if aerr != nil && aerr.Transport() && ctx.Err() == nil {
		// One more attempt, on a new connection.
		p.transport.CloseIdleConnections()
		id, aerr = p.send(ctx, info)
	}
	if p.f.Metrics != nil {
		p.f.Metrics.APNsPushDuration.Observe(time.Since(start).Seconds())
	}
	status := http.StatusOK
	if aerr != nil {
		status = aerr.Status
	}
	if p.circuit.result(probe, status, p.f.now()) {
		aerr.Opened = true
		if p.f.Metrics != nil && p.tenant != "" {
			p.f.Metrics.APNsCircuitOpen.Set(1, p.tenant)
		}
		if p.f.Logger != nil {
			p.f.Logger.Error("msg", "APNs refused the push certificate: circuit open", "component", "apns", "tenant", p.tenant, "topic", p.topic, "status", status)
		}
	} else if status != http.StatusForbidden && probe && p.f.Metrics != nil && p.tenant != "" && p.circuit.closed() {
		p.f.Metrics.APNsCircuitOpen.Set(0, p.tenant)
	}
	if aerr == nil {
		p.f.record(p.topic, http.StatusOK, "")
	} else if !aerr.Transport() {
		p.f.record(p.topic, aerr.Status, aerr.Reason)
	}
	if aerr != nil {
		outcome := "rejected"
		switch {
		case aerr.Transport():
			outcome = "transport"
		case aerr.Status == http.StatusTooManyRequests:
			outcome = "throttled"
		case aerr.Status >= 500:
			outcome = "unavailable"
		}
		p.count(outcome, aerr.Status)
		return &push.Response{Err: aerr}
	}
	p.count("sent", http.StatusOK)
	return &push.Response{Id: id}
}

func (p *Provider) count(outcome string, status int) {
	if p.f.Metrics == nil {
		return
	}
	s := ""
	if status > 0 {
		s = strconv.Itoa(status)
	}
	p.f.Metrics.APNsPushes.Inc(p.tenant, outcome, s)
}

type apnsReply struct {
	Reason    string `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}

// send performs one HTTP/2 request: {"mdm":"<PushMagic>"} without "aps",
// apns-push-type mdm and the topic of the certificate.
func (p *Provider) send(ctx context.Context, info *mdm.Push) (string, *Error) {
	body, err := json.Marshal(map[string]string{"mdm": info.PushMagic})
	if err != nil {
		return "", &Error{Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.f.BaseURL+"/3/device/"+info.Token.String(), bytes.NewReader(body))
	if err != nil {
		return "", &Error{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apns-push-type", "mdm")
	req.Header.Set("apns-topic", p.topic)
	if p.f.Expiration > 0 {
		req.Header.Set("apns-expiration", strconv.FormatInt(p.f.now().Add(p.f.Expiration).Unix(), 10))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", &Error{Err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if resp.StatusCode == http.StatusOK {
		return resp.Header.Get("apns-id"), nil
	}
	e := &Error{Status: resp.StatusCode}
	var r apnsReply
	if json.Unmarshal(raw, &r) == nil {
		e.Reason = r.Reason
		if r.Timestamp > 0 {
			e.Timestamp = time.UnixMilli(r.Timestamp).UTC()
		}
	}
	return "", e
}

// circuit is the breaker of one certificate: open for openFor after a 403,
// then one probe at a time until an answer proves the certificate works.
type circuit struct {
	mu      sync.Mutex
	openFor time.Duration
	open    bool
	half    bool
	probing bool
	until   time.Time
}

func (c *circuit) allow(now time.Time) (ok, probe bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		if now.Before(c.until) {
			return false, false
		}
		c.open, c.half = false, true
	}
	if c.half {
		if c.probing {
			return false, false
		}
		c.probing = true
		return true, true
	}
	return true, false
}

// result records an answer; it reports whether this answer opened the circuit.
func (c *circuit) result(probe bool, status int, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if status == http.StatusForbidden {
		if c.open {
			return false
		}
		c.open, c.half, c.probing, c.until = true, false, false, now.Add(c.openFor)
		return true
	}
	if probe {
		c.probing = false
		if status != 0 && status < 500 {
			c.half = false // any APNs verdict but 403 proves the certificate
		}
	}
	return false
}

func (c *circuit) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.open && !c.half
}
