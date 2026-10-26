// =============================================================================
// Metrics registry of the server (P0-13 T8, FND-14 subset; the S2 slice of the common phase): the one place that
// renders the Prometheus text format 0.0.4. The modules keep their own in-process counters (jobs, outbox, audit,
// guard, vault, Apple, DDM, Android, database context…) and register a collector here (registerMetricsCollector)
// that turns their snapshot into metric families; the internal listener (ops/listener.ts) renders them on
// GET /metrics. Rules, checked at the rendering:
//   - no tenant label, no identifier of a device, a user or an enrollment: a sample with such a label name is
//     dropped (and counted), whatever the collector;
//   - names and label names follow Prometheus' syntax; a family with an invalid name is dropped;
//   - a series rendered twice (same name and labels) keeps the last value (a scrape never fails on a duplicate);
//   - a collector that throws or does not answer within its timeout is skipped (obligarth_metrics_collector_up 0),
//     never the whole scrape; a collector that reads the database caches its result (cacheMs).
// Self-contained (no import of the server): the unit tests load it (npm run test:ops).
// =============================================================================

export type MetricType = 'counter' | 'gauge' | 'histogram' | 'summary';

export interface MetricSample {
  /** '' (default), '_bucket', '_sum' or '_count' (histograms and summaries). */
  suffix?: '' | '_bucket' | '_sum' | '_count';
  labels?: Readonly<Record<string, string | number>>;
  value: number;
}

export interface MetricFamily {
  name: string;
  help: string;
  type: MetricType;
  samples: MetricSample[];
}

export type MetricsCollector = () => MetricFamily[] | Promise<MetricFamily[]>;

export interface CollectorOptions {
  /** A result younger than this is served again (collectors that read the database). Default 0: none. */
  cacheMs?: number;
  /** Longest wait for the collector, in ms (default 5000). */
  timeoutMs?: number;
}

const NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const COLLECTOR_RE = /^[a-z][a-z0-9_.-]{0,40}$/;
/** Label names never accepted: a tenant, a device, a user, an enrollment (P0-13 §3.5, coordination §2). */
export const FORBIDDEN_LABEL_RE = /tenant|device_?id|udid|serial|imei|e_?mail|user_?(id|name)|enrollment|customer|client_?id/i;
/** Most series one family may render (a counter keyed by an unbounded value is cut here, not in the scrape). */
export const MAX_SERIES_PER_FAMILY = 2_000;
const DEFAULT_TIMEOUT_MS = 5_000;

/** Escapes a HELP text (backslash, line feed). */
export function escapeHelp(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}

/** Escapes a label value (backslash, double quote, line feed). */
export function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

/** A sample value in the text format: NaN, +Inf, -Inf, or the number. */
export function formatValue(v: number): string {
  if (Number.isNaN(v)) return 'NaN';
  if (v === Infinity) return '+Inf';
  if (v === -Infinity) return '-Inf';
  return String(v);
}

function labelsText(labels: Readonly<Record<string, string | number>> | undefined): string {
  if (!labels) return '';
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return '';
  return `{${keys.map((k) => `${k}="${escapeLabelValue(String(labels[k]))}"`).join(',')}}`;
}

export interface RenderReport {
  text: string;
  /** Samples dropped for a forbidden or invalid label name. */
  droppedSamples: number;
  /** Families dropped for an invalid name, or a type that contradicts an earlier family of the same name. */
  droppedFamilies: number;
}

/**
 * Renders the families in the text format 0.0.4. Families of the same name are merged (the first one gives HELP
 * and TYPE; one of another type is dropped); a series repeated keeps its last value.
 */
export function renderPrometheus(families: ReadonlyArray<MetricFamily>): RenderReport {
  const merged = new Map<string, { help: string; type: MetricType; series: Map<string, string> }>();
  let droppedSamples = 0;
  let droppedFamilies = 0;
  for (const f of families) {
    if (!f || typeof f.name !== 'string' || !NAME_RE.test(f.name)) { droppedFamilies++; continue; }
    let m = merged.get(f.name);
    if (!m) {
      m = { help: String(f.help ?? ''), type: f.type, series: new Map() };
      merged.set(f.name, m);
    } else if (m.type !== f.type) {
      droppedFamilies++;
      continue;
    }
    for (const s of f.samples ?? []) {
      const labels = s.labels ?? {};
      const names = Object.keys(labels);
      if (names.some((n) => !LABEL_RE.test(n) || n.startsWith('__') || FORBIDDEN_LABEL_RE.test(n))) { droppedSamples++; continue; }
      if (names.includes('le') && s.suffix !== '_bucket') { droppedSamples++; continue; }
      if (typeof s.value !== 'number') { droppedSamples++; continue; }
      const line = `${f.name}${s.suffix ?? ''}${labelsText(labels)}`;
      if (!m.series.has(line) && m.series.size >= MAX_SERIES_PER_FAMILY) { droppedSamples++; continue; }
      m.series.set(line, `${line} ${formatValue(s.value)}`);
    }
  }
  const out: string[] = [];
  for (const [name, m] of merged) {
    out.push(`# HELP ${name} ${escapeHelp(m.help)}`);
    out.push(`# TYPE ${name} ${m.type}`);
    for (const line of m.series.values()) out.push(line);
  }
  return { text: out.length ? `${out.join('\n')}\n` : '', droppedSamples, droppedFamilies };
}

// ── Helpers for the collectors ───────────────────────────────────────────────

/** One family of `type` from (labels, value) rows; rows with a non-finite value are left out. */
export function family(name: string, help: string, type: 'counter' | 'gauge',
  rows: ReadonlyArray<{ labels?: Record<string, string | number>; value: number | null | undefined }>): MetricFamily {
  const samples: MetricSample[] = [];
  for (const r of rows) {
    if (typeof r.value === 'number' && Number.isFinite(r.value)) samples.push({ labels: r.labels, value: r.value });
  }
  return { name, help, type, samples };
}

/** A family of one unlabelled sample (none when `value` is null or not finite). */
export function single(name: string, help: string, type: 'counter' | 'gauge', value: number | null | undefined): MetricFamily {
  return family(name, help, type, [{ value }]);
}

export interface HistogramSeries {
  labels?: Record<string, string | number>;
  /** Upper bounds in ascending order, with their CUMULATIVE counts (observations <= le). */
  buckets: ReadonlyArray<{ le: number; count: number }>;
  sum: number;
  count: number;
}

/** A histogram family: the buckets, the +Inf bucket (= count), _sum and _count of each series. */
export function histogram(name: string, help: string, series: ReadonlyArray<HistogramSeries>): MetricFamily {
  const samples: MetricSample[] = [];
  for (const s of series) {
    for (const b of s.buckets) samples.push({ suffix: '_bucket', labels: { ...(s.labels ?? {}), le: formatValue(b.le) }, value: b.count });
    samples.push({ suffix: '_bucket', labels: { ...(s.labels ?? {}), le: '+Inf' }, value: s.count });
    samples.push({ suffix: '_sum', labels: s.labels, value: s.sum });
    samples.push({ suffix: '_count', labels: s.labels, value: s.count });
  }
  return { name, help, type: 'histogram', samples };
}

/** Cumulative counts from per-bucket counts (`counts[i]` observations in bucket i; one more entry: past the last
 *  bound, counted in +Inf only). */
export function cumulate(bounds: ReadonlyArray<number>, counts: ReadonlyArray<number>): { buckets: Array<{ le: number; count: number }>; count: number } {
  let acc = 0;
  const buckets = bounds.map((le, i) => {
    acc += Number(counts[i] ?? 0);
    return { le, count: acc };
  });
  for (let i = bounds.length; i < counts.length; i++) acc += Number(counts[i] ?? 0);
  return { buckets, count: acc };
}

/**
 * Parses the keys of the audit and guard counters (`name{k=v,k2=v2}`, values already reduced to
 * [A-Za-z0-9_.:-]): null when the key is not of that form.
 */
export function parseKeyedName(key: string): { name: string; labels: Record<string, string> } | null {
  const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^{}]*)\})?$/.exec(key);
  if (!m) return null;
  const labels: Record<string, string> = {};
  if (m[2]) {
    for (const part of m[2].split(',')) {
      const i = part.indexOf('=');
      if (i <= 0) return null;
      labels[part.slice(0, i)] = part.slice(i + 1);
    }
  }
  return { name: m[1], labels };
}

/** Families from such keyed maps: counter when the name ends in _total, gauge otherwise. */
export function familiesFromKeyed(values: Readonly<Record<string, number>>, help: (name: string) => string): MetricFamily[] {
  const byName = new Map<string, MetricFamily>();
  for (const [key, value] of Object.entries(values)) {
    const p = parseKeyedName(key);
    if (!p || typeof value !== 'number' || !Number.isFinite(value)) continue;
    let f = byName.get(p.name);
    if (!f) {
      f = { name: p.name, help: help(p.name), type: p.name.endsWith('_total') ? 'counter' : 'gauge', samples: [] };
      byName.set(p.name, f);
    }
    f.samples.push({ labels: p.labels, value });
  }
  return [...byName.values()];
}

// ── Registry ─────────────────────────────────────────────────────────────────

interface Registered {
  name: string;
  collect: MetricsCollector;
  cacheMs: number;
  timeoutMs: number;
  cache: { at: number; families: MetricFamily[] } | null;
}

export class MetricsRegistry {
  private readonly collectors = new Map<string, Registered>();
  private readonly errors = new Map<string, number>();
  private droppedSamples = 0;
  private droppedFamilies = 0;

  /** Declares a collector (a module, at registration time; no I/O). A name registered twice throws. */
  register(name: string, collect: MetricsCollector, opts: CollectorOptions = {}): void {
    if (!COLLECTOR_RE.test(name)) throw new Error(`metrics collector ${JSON.stringify(name)}: invalid name`);
    if (this.collectors.has(name)) throw new Error(`metrics collector ${name} registered twice`);
    if (typeof collect !== 'function') throw new Error(`metrics collector ${name}: collect is not a function`);
    this.collectors.set(name, {
      name, collect,
      cacheMs: Math.max(0, Math.floor(opts.cacheMs ?? 0)),
      timeoutMs: Math.max(100, Math.floor(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)),
      cache: null,
    });
  }

  names(): string[] {
    return [...this.collectors.keys()];
  }

  private async run(c: Registered, now: number): Promise<{ ok: boolean; families: MetricFamily[] }> {
    if (c.cache && c.cacheMs > 0 && now - c.cache.at < c.cacheMs) return { ok: true, families: c.cache.families };
    let timer: NodeJS.Timeout | undefined;
    try {
      const families = await Promise.race([
        Promise.resolve().then(() => c.collect()),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), c.timeoutMs); }),
      ]);
      const list = Array.isArray(families) ? families : [];
      if (c.cacheMs > 0) c.cache = { at: now, families: list };
      return { ok: true, families: list };
    } catch {
      this.errors.set(c.name, (this.errors.get(c.name) ?? 0) + 1);
      return { ok: false, families: [] };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Runs every collector (in parallel) and renders the scrape, with the registry's own metrics. */
  async render(now = Date.now()): Promise<string> {
    const list = [...this.collectors.values()];
    const results = await Promise.all(list.map((c) => this.run(c, now)));
    const families: MetricFamily[] = results.flatMap((r) => r.families);
    families.push(
      family('obligarth_metrics_collector_up', 'Collector answered at this scrape (1) or failed (0)', 'gauge',
        list.map((c, i) => ({ labels: { collector: c.name }, value: results[i].ok ? 1 : 0 }))),
      family('obligarth_metrics_collector_errors_total', 'Scrapes where a collector threw or timed out', 'counter',
        [...this.errors].map(([collector, value]) => ({ labels: { collector }, value }))),
      single('obligarth_metrics_dropped_samples_total', 'Samples dropped for a forbidden or invalid label', 'counter', this.droppedSamples),
      single('obligarth_metrics_dropped_families_total', 'Families dropped for an invalid name or a conflicting type', 'counter', this.droppedFamilies),
    );
    const report = renderPrometheus(families);
    // Counted for the next scrape (this one is already rendered).
    this.droppedSamples += report.droppedSamples;
    this.droppedFamilies += report.droppedFamilies;
    return report.text;
  }

  /** Tests only. */
  clearCaches(): void {
    for (const c of this.collectors.values()) c.cache = null;
  }
}

/** The registry of this process. */
export const metricsRegistry = new MetricsRegistry();

/** Declares a collector of a module in the registry of this process (see MetricsRegistry.register). */
export function registerMetricsCollector(name: string, collect: MetricsCollector, opts?: CollectorOptions): void {
  metricsRegistry.register(name, collect, opts);
}

/** The content type of the text format 0.0.4. */
export const PROMETHEUS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';
