import { monitorEventLoopDelay, type IntervalHistogram } from 'node:perf_hooks';
import { db } from '../db';
import { asNone, dbContextMetrics } from '../db/context';
import { audit } from '../audit';
import { guard } from '../guard';
import { vault } from '../vault';
import { jobs } from '../jobs';
import { jobStatus } from '../jobs/status';
import { appleMetrics } from '../apple/metrics';
import { ddmMetrics } from '../apple/ddm/metrics';
import { edgeHealth } from '../apple/edge/health';
import { serverVersion } from '../apple/edge/version';
import { androidMetrics } from '../android/metrics';
import { httpMetrics } from './http';
import {
  cumulate, family, familiesFromKeyed, histogram, registerMetricsCollector, single, type MetricFamily,
} from './metrics';

// =============================================================================
// The collectors of the core (P0-13 T8): the in-process snapshots the modules already keep for the observability
// work (FND-14), turned into metric families under the names of their specs (file-durable §8.3, audit-durci §13.3,
// coffre-secrets §11.4, integration-apple-edge §5.2 and §9, android-amapi, rls-tenant). No tenant label, no
// identifier: queue names, route patterns, action keys, codes, table names, platforms and states only. The readers
// of the database (jobs and outbox, backlog of the commands, retention) run in the context 'none' of the actor
// j:ops.metrics and are cached, so that a scrape every 15 s costs a few statements a minute (file-durable L3).
// Registered once by modules/ops.ts.
// =============================================================================

const METRICS_ACTOR = { type: 'job', name: 'ops.metrics' } as const;
const JOBS_CACHE_MS = 15_000;
const COMMANDS_CACHE_MS = 60_000;
const RETENTION_QUEUE = 'privacy.retention-tenant';
/** A tenant row of the retention not touched for 8 days is a deleted tenant's (the job runs daily). */
const RETENTION_RECENT_MS = 8 * 86_400_000;

type Rows = { rows: Array<Record<string, unknown>> };

function jobsFamilies(s: Awaited<ReturnType<typeof jobs.metricsSnapshot>>): MetricFamily[] {
  const q = (field: 'ready' | 'deferred' | 'active' | 'failed') => s.queues.map((x) => ({ labels: { queue: x.queue }, value: x[field] }));
  const o = s.outbox;
  return [
    family('obligarth_job_runs_total', 'Runs of the background jobs, by queue and outcome', 'counter',
      s.runs.map((r) => ({ labels: { queue: r.queue, outcome: r.outcome }, value: r.value }))),
    histogram('obligarth_job_run_duration_seconds', 'Duration of the runs of the background jobs',
      s.durations.map((d) => ({ labels: { queue: d.queue }, buckets: d.buckets, sum: d.sum, count: d.count }))),
    family('obligarth_job_queue_ready', 'Jobs ready to run, by queue', 'gauge', q('ready')),
    family('obligarth_job_queue_deferred', 'Jobs waiting for their start time, by queue', 'gauge', q('deferred')),
    family('obligarth_job_queue_active', 'Jobs running, by queue', 'gauge', q('active')),
    family('obligarth_job_queue_failed', 'Jobs failed and kept, by queue', 'gauge', q('failed')),
    family('obligarth_job_oldest_ready_seconds', 'Age of the oldest ready job, by queue', 'gauge',
      s.oldestReady.map((r) => ({ labels: { queue: r.queue }, value: r.seconds }))),
    family('obligarth_job_dead_letters', 'Dead letters waiting, by source queue', 'gauge',
      s.deadLetters.map((r) => ({ labels: { source: r.source || 'unknown' }, value: r.count }))),
    family('obligarth_job_schedule_last_success_timestamp_seconds', 'Last success of a scheduled job (Unix time)', 'gauge',
      s.scheduleLastSuccess.map((r) => ({ labels: { queue: r.queue }, value: r.timestampSeconds }))),
    single('obligarth_job_heartbeat_age_seconds', 'Age of the last heartbeat of the scheduler', 'gauge', s.heartbeatAgeSeconds),
    family('obligarth_outbox_events_total', 'Events of the apple-edge outbox, by type and outcome', 'counter',
      o.events.map((e) => ({ labels: { type: e.type, outcome: e.outcome }, value: e.value }))),
    family('obligarth_outbox_dead_letters_total', 'Outbox events moved to the dead letters, by reason', 'counter',
      o.deadLetters.map((e) => ({ labels: { reason: e.reason }, value: e.value }))),
    histogram('obligarth_outbox_batch_duration_seconds', 'Duration of the batches of the outbox consumer',
      [{ buckets: o.batchDuration.buckets, sum: o.batchDuration.sum, count: o.batchDuration.count }]),
    single('obligarth_outbox_pending', 'Outbox events not consumed yet', 'gauge', o.pending),
    single('obligarth_outbox_retrying', 'Outbox events being retried', 'gauge', o.retrying),
    single('obligarth_outbox_oldest_pending_seconds', 'Age of the oldest outbox event not consumed', 'gauge', o.oldestPendingSeconds),
    single('obligarth_outbox_consumer_up', 'The outbox consumer of this instance runs', 'gauge', o.consumerUp),
  ];
}

/** The retention of the tenants (privacy.retention-tenant): the oldest last success among the tenants run in the
 *  last 8 days (0: one of them never succeeded), and how many of them failed at their last run. */
async function retentionFamilies(): Promise<MetricFamily[]> {
  const rows = (await jobStatus.list([RETENTION_QUEUE]))
    .filter((r) => r.key.startsWith('t:') && Date.now() - r.updatedAt.getTime() < RETENTION_RECENT_MS);
  if (rows.length === 0) return [];
  const oldest = Math.min(...rows.map((r) => (r.lastSucceededAt ? Math.floor(r.lastSucceededAt.getTime() / 1000) : 0)));
  return [
    single('obligarth_privacy_retention_last_success_timestamp_seconds',
      'Oldest last success of the retention among the tenants (Unix time; 0: a tenant never succeeded)', 'gauge', oldest),
    single('obligarth_privacy_retention_failing_tenants', 'Tenants whose last retention run failed', 'gauge',
      rows.filter((r) => r.consecutiveFailures > 0).length),
  ];
}

/** obligarth.ops_command_backlog(): open command targets per platform and state, counts only. */
export async function commandBacklog(): Promise<Array<{ platform: string; state: string; targets: number; oldestSeconds: number }>> {
  return asNone(METRICS_ACTOR, async () => {
    const r = await db.raw('SELECT platform, state, targets, oldest_seconds FROM obligarth.ops_command_backlog()') as Rows;
    return r.rows.map((x) => ({
      platform: String(x.platform), state: String(x.state), targets: Number(x.targets) || 0, oldestSeconds: Number(x.oldest_seconds) || 0,
    }));
  });
}

async function commandFamilies(): Promise<MetricFamily[]> {
  const rows = await commandBacklog();
  return [
    family('obligarth_mdm_command_targets_open', 'Open command targets, all tenants, by platform and state', 'gauge',
      rows.map((r) => ({ labels: { platform: r.platform, state: r.state }, value: r.targets }))),
    family('obligarth_mdm_command_oldest_open_seconds', 'Age of the oldest command target in each open state', 'gauge',
      rows.map((r) => ({ labels: { platform: r.platform, state: r.state }, value: r.oldestSeconds }))),
  ];
}

function appleFamilies(): MetricFamily[] {
  const a = appleMetrics.snapshot();
  const d = ddmMetrics.snapshot();
  const edge = edgeHealth();
  const notAfter = edge.signingIdentity ? Date.parse(edge.signingIdentity.notAfter) : NaN;
  const relay = cumulate(d.relayDurationMs.buckets.map((ms) => ms / 1000), d.relayDurationMs.counts);
  const pairs = (rows: Array<Record<string, string | number>>, label: string) =>
    rows.map((r) => ({ labels: { [label]: String(r[label]) }, value: Number(r.value) }));
  return [
    single('obligarth_apple_edge_up', 'The last probe of apple-edge answered', 'gauge', a.up),
    family('obligarth_apple_edge_info', 'Version of apple-edge seen last', 'gauge', a.info.map((i) => ({ labels: { version: i.version }, value: i.value }))),
    single('obligarth_apple_edge_circuit_open', 'The circuit of the apple-edge client is open', 'gauge', a.circuitOpen),
    single('obligarth_apple_edge_compatible', 'apple-edge is compatible with this server (1), not (0); absent: unknown', 'gauge',
      edge.compatible === null ? null : edge.compatible ? 1 : 0),
    family('obligarth_apple_edge_calls_total', 'Calls to apple-edge, by route pattern and outcome', 'counter',
      a.calls.map((c) => ({ labels: { route: c.route, outcome: c.outcome }, value: c.value }))),
    family('obligarth_apple_provisioning_total', 'Provisioning of the tenants in apple-edge, by outcome', 'counter', pairs(a.provisioning, 'outcome')),
    family('obligarth_apple_events_ignored_total', 'Outbox events without effect, by type', 'counter', pairs(a.eventsIgnored, 'type')),
    single('obligarth_apple_command_duplicate_results_total', 'Final command results repeated', 'counter', a.commandDuplicateResults),
    family('obligarth_apple_command_submissions_total', 'Submissions of the Apple command queue, by outcome', 'counter', pairs(a.commandSubmissions, 'outcome')),
    family('obligarth_apple_push_relaunches_total', 'Relaunch pushes asked of apple-edge, by answer', 'counter', pairs(a.pushRelaunches, 'outcome')),
    family('obligarth_apple_reconcile_fixes_total', 'Corrections of the reconciliation with apple-edge, by kind', 'counter', pairs(a.reconcileFixes, 'kind')),
    single('obligarth_apple_token_update_after_unenroll_total', 'TokenUpdate of a device already out of management', 'counter', a.tokenUpdateAfterUnenroll),
    single('obligarth_apple_apns_throttled_total', 'Pushes throttled by Apple', 'counter', a.apnsThrottled),
    single('obligarth_apple_signing_identity_not_after_seconds', 'End of validity of the profile signing identity (Unix time)', 'gauge',
      Number.isFinite(notAfter) ? Math.floor(notAfter / 1000) : null),
    family('obligarth_apple_ddm_relay_requests_total', 'Requests of the DDM relay, by endpoint kind and status', 'counter',
      d.relayRequests.map((r) => ({ labels: { endpoint: r.endpoint, status: r.status }, value: r.value }))),
    single('obligarth_apple_ddm_relay_auth_failures_total', 'Requests of the DDM relay whose signature was refused', 'counter', d.relayAuthFailures),
    // The relay keeps its buckets, not the sum of the durations: _sum is NaN.
    histogram('obligarth_apple_ddm_relay_duration_seconds', 'Duration of the authenticated requests of the DDM relay',
      [{ buckets: relay.buckets, sum: NaN, count: relay.count }]),
    single('obligarth_apple_ddm_baseline_used_total', 'Declaration sets computed with the reference capabilities of the OS', 'counter', d.baselineUsed),
    single('obligarth_apple_ddm_sets_computed_total', 'Declaration sets whose token changed', 'counter', d.setsComputed),
    family('obligarth_apple_ddm_declarations_dropped_total', 'Declarations set aside, by reason', 'counter', pairs(d.declarationsDropped, 'reason')),
    family('obligarth_apple_ddm_sync_commands_total', 'DeclarativeManagement commands, by outcome', 'counter', pairs(d.syncCommands, 'outcome')),
    family('obligarth_apple_ddm_status_reports_total', 'DDM status reports, by outcome', 'counter', pairs(d.statusReports, 'outcome')),
    family('obligarth_apple_ddm_status_errors_total', 'Errors of the DDM status reports, by item', 'counter', pairs(d.statusErrors, 'item')),
  ];
}

function androidFamilies(): MetricFamily[] {
  const s = androidMetrics.snapshot();
  const split = (k: string): [string, string] => {
    const i = k.lastIndexOf('|');
    return [k.slice(0, i), k.slice(i + 1)];
  };
  const latency = Object.entries(s.googleLatency);
  return [
    family('obligarth_android_google_requests_total', 'Requests to the Android Management API, by operation and status', 'counter',
      Object.entries(s.googleRequests).map(([k, value]) => { const [op, code] = split(k); return { labels: { op, code }, value }; })),
    {
      name: 'obligarth_android_google_latency_seconds', help: 'Latency of the requests to Google, by operation', type: 'summary',
      samples: latency.flatMap(([op, v]) => [
        { suffix: '_sum' as const, labels: { op }, value: v.avgSeconds * v.count },
        { suffix: '_count' as const, labels: { op }, value: v.count },
      ]),
    },
    single('obligarth_android_rate_wait_seconds_total', 'Time spent waiting for the rate limiter of the Google project', 'counter', s.rateWaitSeconds),
    single('obligarth_android_inbox_dead_total', 'Android notifications moved to the dead letters', 'counter', s.inboxDead),
    family('obligarth_android_events_total', 'Android notifications, by type and outcome', 'counter',
      Object.entries(s.events).map(([k, value]) => { const [type, outcome] = split(k); return { labels: { type, outcome }, value }; })),
  ];
}

function vaultFamilies(): MetricFamily[] {
  const v = vault.metricsSnapshot();
  return [
    single('obligarth_vault_ready', 'The vault is open', 'gauge', v.ready),
    family('obligarth_vault_seal_total', 'Secrets sealed, by table and outcome', 'counter', v.seal.map((r) => ({ labels: { table: String(r.table), outcome: String(r.outcome) }, value: r.count }))),
    family('obligarth_vault_open_total', 'Secrets opened, by table and outcome', 'counter', v.open.map((r) => ({ labels: { table: String(r.table), outcome: String(r.outcome) }, value: r.count }))),
    family('obligarth_vault_open_failures_total', 'Secrets that could not be opened, by table and code', 'counter',
      v.openFailures.map((r) => ({ labels: { table: String(r.table), code: String(r.code) }, value: r.count }))),
    family('obligarth_vault_backfill_remaining', 'Clear secrets left to seal, by column', 'gauge',
      Object.entries(v.backfillRemaining).map(([column, value]) => ({ labels: { column }, value }))),
    single('obligarth_vault_verify_failures', 'Failures of the last daily verification of the vault', 'gauge', v.verifyFailures),
    single('obligarth_vault_dek_cache_entries', 'Data keys held in memory', 'gauge', v.dekCacheEntries),
    family('obligarth_vault_dek_unwrap_total', 'Unwrapping of data keys, by outcome', 'counter',
      [{ labels: { outcome: 'ok' }, value: v.dekUnwrap.ok }, { labels: { outcome: 'failed' }, value: v.dekUnwrap.failed }]),
    single('obligarth_vault_dek_created_total', 'Data keys created', 'counter', v.dekCreated),
  ];
}

function coreFamilies(): MetricFamily[] {
  const a = audit.metricsSnapshot();
  const g = guard.metricsSnapshot();
  const c = dbContextMetrics();
  return [
    ...familiesFromKeyed({ ...a.counters, ...a.gauges }, (name) => `Audit journal: ${name.replace(/^obligarth_audit_/, '').replace(/_/g, ' ')}`),
    single('obligarth_audit_append_p95_seconds', 'Audit journal: 95th percentile of the append duration (recent window)', 'gauge',
      a.appendP95Ms === null ? null : a.appendP95Ms / 1000),
    ...familiesFromKeyed(g.counters, (name) => `Guards: ${name.replace(/^obligarth_guard_/, '').replace(/_/g, ' ')}`),
    single('obligarth_db_context_missing_total', 'Database statements without a context', 'counter', c.missing),
    single('obligarth_db_context_mismatch_total', 'Database statements on a lease of another context', 'counter', c.mismatch),
    family('obligarth_rls_denied_total', 'Writes refused by the row level security, by table', 'counter',
      Object.entries(c.rlsDenied).map(([table, value]) => ({ labels: { table }, value }))),
    ...httpMetrics.families(),
  ];
}

// ── Process ──────────────────────────────────────────────────────────────────

let loopDelay: IntervalHistogram | null = null;
const startedAt = Date.now();
/** Sampling period of the monitor, in ms: its samples include it, removed from the values reported. */
const LOOP_RESOLUTION_MS = 20;

/** Delay of the event loop since the previous scrape (p50, p99, max), in seconds; null before the monitor runs. */
export function eventLoopDelay(reset = false): { p50: number; p99: number; max: number } | null {
  if (!loopDelay || loopDelay.count === 0) return null;
  const s = (ns: number): number => Math.max(0, ns / 1e6 - LOOP_RESOLUTION_MS) / 1000;
  const out = { p50: s(loopDelay.percentile(50)), p99: s(loopDelay.percentile(99)), max: s(loopDelay.max) };
  if (reset) loopDelay.reset();
  return out;
}

function processFamilies(): MetricFamily[] {
  const m = process.memoryUsage();
  const cpu = process.cpuUsage();
  const lag = eventLoopDelay(true);
  return [
    family('obligarth_build_info', 'Version of this server', 'gauge', [{ labels: { version: serverVersion(), node: process.version }, value: 1 }]),
    single('obligarth_process_start_time_seconds', 'Start of this process (Unix time)', 'gauge', Math.floor(startedAt / 1000)),
    single('obligarth_process_cpu_seconds_total', 'CPU time of this process (user and system)', 'counter', (cpu.user + cpu.system) / 1e6),
    single('obligarth_process_resident_memory_bytes', 'Resident memory of this process', 'gauge', m.rss),
    single('obligarth_process_heap_used_bytes', 'Heap of the JavaScript engine in use', 'gauge', m.heapUsed),
    single('obligarth_process_heap_total_bytes', 'Heap of the JavaScript engine reserved', 'gauge', m.heapTotal),
    single('obligarth_process_external_memory_bytes', 'Memory of the buffers and native objects', 'gauge', m.external),
    family('obligarth_process_event_loop_delay_seconds', 'Delay of the event loop since the previous scrape', 'gauge',
      lag ? [{ labels: { quantile: '0.5' }, value: lag.p50 }, { labels: { quantile: '0.99' }, value: lag.p99 }, { labels: { quantile: '1' }, value: lag.max }] : []),
  ];
}

let registered = false;

/** Registers the collectors of the core (modules/ops.ts) and starts the monitor of the event loop. */
export function registerCoreCollectors(): void {
  if (registered) return;
  registered = true;
  loopDelay = monitorEventLoopDelay({ resolution: LOOP_RESOLUTION_MS });
  loopDelay.enable();
  registerMetricsCollector('process', processFamilies);
  registerMetricsCollector('core', coreFamilies);
  registerMetricsCollector('vault', vaultFamilies);
  registerMetricsCollector('apple', appleFamilies);
  registerMetricsCollector('android', androidFamilies);
  registerMetricsCollector('jobs', async () => jobsFamilies(await asNone(METRICS_ACTOR, () => jobs.metricsSnapshot())), { cacheMs: JOBS_CACHE_MS });
  registerMetricsCollector('retention', () => asNone(METRICS_ACTOR, retentionFamilies), { cacheMs: JOBS_CACHE_MS });
  registerMetricsCollector('commands', commandFamilies, { cacheMs: COMMANDS_CACHE_MS });
}
