package obs

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry holds metrics and renders them in the Prometheus text format.
type Registry struct {
	mu         sync.Mutex
	collectors []collector
	start      time.Time
}

type collector interface {
	name() string
	write(w *bufio.Writer)
}

// NewRegistry returns a registry with the process metrics.
func NewRegistry() *Registry {
	r := &Registry{start: time.Now()}
	r.GaugeFunc("go_goroutines", "Number of goroutines.", func() float64 { return float64(runtime.NumGoroutine()) })
	r.GaugeFunc("go_memstats_heap_alloc_bytes", "Heap bytes allocated and in use.", func() float64 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return float64(ms.HeapAlloc)
	})
	r.GaugeFunc("process_start_time_seconds", "Start time of the process (Unix seconds).", func() float64 {
		return float64(r.start.UnixNano()) / 1e9
	})
	return r
}

func (r *Registry) add(c collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.collectors {
		if x.name() == c.name() {
			panic("duplicate metric " + c.name())
		}
	}
	r.collectors = append(r.collectors, c)
}

// WriteText renders every metric.
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.Lock()
	cs := append([]collector(nil), r.collectors...)
	r.mu.Unlock()
	bw := bufio.NewWriter(w)
	for _, c := range cs {
		c.write(bw)
	}
	return bw.Flush()
}

type vec struct {
	metricName string
	help       string
	typ        string
	labels     []string
	mu         sync.Mutex
	series     map[string]*series
}

type series struct {
	values  []string
	value   float64
	buckets []uint64
	count   uint64
}

func (v *vec) name() string { return v.metricName }

func (v *vec) get(lv []string) *series {
	if len(lv) != len(v.labels) {
		panic(fmt.Sprintf("metric %s: %d label values for %d labels", v.metricName, len(lv), len(v.labels)))
	}
	k := strings.Join(lv, "\xff")
	s := v.series[k]
	if s == nil {
		s = &series{values: append([]string(nil), lv...)}
		v.series[k] = s
	}
	return s
}

func (v *vec) sortedSeries() []*series {
	out := make([]*series, 0, len(v.series))
	for _, s := range v.series {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b *series) int {
		return strings.Compare(strings.Join(a.values, "\xff"), strings.Join(b.values, "\xff"))
	})
	return out
}

func (v *vec) header(w *bufio.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", v.metricName, v.help, v.metricName, v.typ)
}

func labelString(names, values []string, extra ...string) string {
	if len(names) == 0 && len(extra) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	n := 0
	for i, name := range names {
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(name + `="` + escapeLabel(values[i]) + `"`)
		n++
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(extra[i] + `="` + escapeLabel(extra[i+1]) + `"`)
		n++
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// CounterVec is a counter with labels.
type CounterVec struct{ v *vec }

// Counter registers a counter.
func (r *Registry) Counter(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{&vec{metricName: name, help: help, typ: "counter", labels: labels, series: map[string]*series{}}}
	r.add(c.v)
	return c
}

// Add adds delta to the series with the given label values.
func (c *CounterVec) Add(delta float64, lv ...string) {
	c.v.mu.Lock()
	c.v.get(lv).value += delta
	c.v.mu.Unlock()
}

// Inc adds one.
func (c *CounterVec) Inc(lv ...string) { c.Add(1, lv...) }

// Value returns the current value of a series (tests and status).
func (c *CounterVec) Value(lv ...string) float64 {
	c.v.mu.Lock()
	defer c.v.mu.Unlock()
	return c.v.get(lv).value
}

func (v *vec) write(w *bufio.Writer) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.header(w)
	for _, s := range v.sortedSeries() {
		if v.typ == "histogram" {
			continue
		}
		fmt.Fprintf(w, "%s%s %s\n", v.metricName, labelString(v.labels, s.values), formatFloat(s.value))
	}
}

// GaugeVec is a gauge with labels.
type GaugeVec struct{ v *vec }

// Gauge registers a gauge.
func (r *Registry) Gauge(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{&vec{metricName: name, help: help, typ: "gauge", labels: labels, series: map[string]*series{}}}
	r.add(g.v)
	return g
}

// Set sets the value of a series.
func (g *GaugeVec) Set(val float64, lv ...string) {
	g.v.mu.Lock()
	g.v.get(lv).value = val
	g.v.mu.Unlock()
}

// Reset drops every series (used before re-publishing a full set).
func (g *GaugeVec) Reset() {
	g.v.mu.Lock()
	g.v.series = map[string]*series{}
	g.v.mu.Unlock()
}

type gaugeFunc struct {
	metricName, help string
	f                func() float64
}

func (g *gaugeFunc) name() string { return g.metricName }
func (g *gaugeFunc) write(w *bufio.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", g.metricName, g.help, g.metricName, g.metricName, formatFloat(g.f()))
}

// GaugeFunc registers a gauge computed at scrape time.
func (r *Registry) GaugeFunc(name, help string, f func() float64) {
	r.add(&gaugeFunc{metricName: name, help: help, f: f})
}

// HistogramVec is a histogram with fixed buckets and labels.
type HistogramVec struct {
	v       *vec
	buckets []float64
}

// DefBuckets suits request durations in seconds.
var DefBuckets = []float64{.005, .01, .025, .05, .1, .15, .25, .4, .5, 1, 2.5, 5, 10, 30}

// Histogram registers a histogram.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *HistogramVec {
	h := &HistogramVec{v: &vec{metricName: name, help: help, typ: "histogram", labels: labels, series: map[string]*series{}}, buckets: buckets}
	r.add(h)
	return h
}

func (h *HistogramVec) name() string { return h.v.metricName }

// Observe records one value.
func (h *HistogramVec) Observe(val float64, lv ...string) {
	h.v.mu.Lock()
	s := h.v.get(lv)
	if s.buckets == nil {
		s.buckets = make([]uint64, len(h.buckets))
	}
	for i, ub := range h.buckets {
		if val <= ub {
			s.buckets[i]++
		}
	}
	s.count++
	s.value += val
	h.v.mu.Unlock()
}

func (h *HistogramVec) write(w *bufio.Writer) {
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	h.v.header(w)
	for _, s := range h.v.sortedSeries() {
		for i, ub := range h.buckets {
			var n uint64
			if s.buckets != nil {
				n = s.buckets[i]
			}
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.v.metricName, labelString(h.v.labels, s.values, "le", formatFloat(ub)), n)
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.v.metricName, labelString(h.v.labels, s.values, "le", "+Inf"), s.count)
		fmt.Fprintf(w, "%s_sum%s %s\n", h.v.metricName, labelString(h.v.labels, s.values), formatFloat(s.value))
		fmt.Fprintf(w, "%s_count%s %d\n", h.v.metricName, labelString(h.v.labels, s.values), s.count)
	}
}

// Metrics groups the metrics of apple-edge.
type Metrics struct {
	Registry *Registry

	HTTPRequests      *CounterVec
	HTTPDuration      *HistogramVec
	Checkins          *CounterVec
	CommandResults    *CounterVec
	SecurityEvents    *CounterVec
	RateLimited       *CounterVec
	OutboxWrites      *CounterVec
	OutboxPending     *GaugeVec
	OutboxOldest      *GaugeVec
	SCEPRequests      *CounterVec
	SCEPRejected      *CounterVec
	DBPoolInUse       *GaugeVec
	DBPoolWait        *GaugeVec
	RegistryTenants   *GaugeVec
	RegistryReloads   *CounterVec
	RegistryReloadDur *HistogramVec
	APIAuthFailures   *CounterVec
}

// NewMetrics registers the metrics of apple-edge.
func NewMetrics() *Metrics {
	r := NewRegistry()
	return &Metrics{
		Registry:          r,
		HTTPRequests:      r.Counter("apple_edge_http_requests_total", "HTTP requests by surface, route, status code and tenant.", "surface", "route", "code", "tenant"),
		HTTPDuration:      r.Histogram("apple_edge_http_request_duration_seconds", "HTTP request duration.", DefBuckets, "surface", "route"),
		Checkins:          r.Counter("apple_edge_checkins_total", "Check-in messages by type and outcome.", "tenant", "message_type", "outcome"),
		CommandResults:    r.Counter("apple_edge_command_results_total", "Command results reported by devices.", "tenant", "status"),
		SecurityEvents:    r.Counter("apple_edge_security_events_total", "Security events emitted.", "tenant", "type"),
		RateLimited:       r.Counter("apple_edge_rate_limited_total", "Requests refused by a rate limiter.", "scope"),
		OutboxWrites:      r.Counter("apple_edge_outbox_writes_total", "Outbox write transactions.", "outcome"),
		OutboxPending:     r.Gauge("apple_edge_outbox_pending", "Events not consumed yet (sampled)."),
		OutboxOldest:      r.Gauge("apple_edge_outbox_oldest_pending_seconds", "Age of the oldest event not consumed yet (sampled)."),
		SCEPRequests:      r.Counter("apple_edge_scep_requests_total", "SCEP requests.", "tenant", "operation", "outcome"),
		SCEPRejected:      r.Counter("apple_edge_scep_challenges_rejected_total", "SCEP enrollments refused.", "tenant", "reason"),
		DBPoolInUse:       r.Gauge("apple_edge_db_pool_in_use", "Connections in use.", "pool"),
		DBPoolWait:        r.Gauge("apple_edge_db_pool_wait_seconds_total", "Total time waited for a connection.", "pool"),
		RegistryTenants:   r.Gauge("apple_edge_registry_tenants", "Tenants in the registry snapshot by state.", "state"),
		RegistryReloads:   r.Counter("apple_edge_registry_reloads_total", "Registry reloads.", "outcome"),
		RegistryReloadDur: r.Histogram("apple_edge_registry_reload_duration_seconds", "Registry reload duration.", DefBuckets),
		APIAuthFailures:   r.Counter("apple_edge_internal_api_auth_failures_total", "Internal API requests refused for authentication."),
	}
}
