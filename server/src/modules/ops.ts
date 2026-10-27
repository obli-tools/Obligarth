import { z } from 'zod';
import { registerAuditActions } from '../audit';
import { config } from '../config';
import { db } from '../db';
import { asNone } from '../db/context';
import { migrationStem, shippedMigrations } from '../db/migrationFiles';
import { registerJob, SCHEDULED_POLL_SECONDS, safeErr } from '../jobs';
import { registerStartTask, registerStopTask } from '../lifecycle';
import { vault } from '../vault';
import { edgeHealth } from '../apple/edge/health';
import { logger } from '../utils/logger';
import { backupFamilies, backupsReady, watchBackups } from '../ops/backups';
import { registerCoreCollectors } from '../ops/collectors';
import { readMetricsToken } from '../ops/config';
import { startMetricsListener, type MetricsListener } from '../ops/listener';
import { metricsRegistry, registerMetricsCollector } from '../ops/metrics';
import { registerReadinessCheck } from '../ops/ready';
import { signingReady, stageFamilies, watchSigning } from '../ops/signing';
import { registerOpsWatchCheck, runOpsWatch, watchReadiness } from '../ops/watch';

// =============================================================================
// OBSERVABILITY (P0-13 T8, decision D11; the S2 slice of the common phase) — its hooks into the core's registries:
//   - the collectors of the core in the metrics registry (ops/collectors.ts); the other modules register theirs
//     with registerMetricsCollector (ops/metrics.ts), never a tenant label;
//   - the internal listener of the metrics (GET /metrics on METRICS_PORT, optional bearer token), a start task, closed
//     by a stop task; a listener that cannot start is logged, the server runs on;
//   - the readiness checks of GET /health/ready: database, schema (no migration of this image missing), vault,
//     apple-edge (APPLE_EDGE_MODE=on: not known incompatible); the other modules add theirs with
//     registerReadinessCheck (ops/ready.ts);
//   - the job ops.watch (platform, every 5 minutes): readiness, then the checks the other modules add with
//     registerOpsWatchCheck (ops/watch.ts);
//   - the backups of the instance (P0-13 T9, ops/backups.ts): their readiness check when BACKUP_EXPECTED=true, the
//     check 'backups' of ops.watch (ops.backup_stale, ops.wal_stale, ops.disk_low, keeping of the reports), their
//     metrics (collector 'backups');
//   - the audit action of the recovery after a restore (P0-13 T10, ops/cli.ts restore-reconcile);
//   - the stage of the instance and the signed profiles (P0-13 T11, ops/signing.ts): outside lab with
//     APPLE_EDGE_MODE=on, the readiness check 'signing' and the check 'signing' of ops.watch (critical alert
//     signing.identity_missing while the profile signing identity is missing or expired); the metrics of the stage
//     (collector 'stage'). The start-up checks of the stage are startupConfigErrors' (config.ts, ops/stage.ts).
// GET /health/ready is mounted by app.ts, GET /api/admin/ops/status by routes/index.ts (ops/routes.ts). index.ts calls
// registerOpsModule() with the other modules, before anything starts.
// =============================================================================

const READY_ACTOR = { type: 'job', name: 'ops.ready' } as const;
const empty = z.object({}).strict();

let listener: MetricsListener | null = null;
let listenerFailed = false;

/** The internal listener of the metrics, for the ops status. */
export function opsListenerStatus(): { enabled: boolean; listening: boolean; port: number | null; tokenRequired: boolean } {
  const m = config.ops.metrics;
  return {
    enabled: m.port !== null,
    listening: listener !== null && !listenerFailed,
    port: listener?.address()?.port ?? m.port,
    tokenRequired: m.port !== null && m.tokenFile !== '',
  };
}

/** The migrations this image ships, read once (the image does not change while it runs). */
let shipped: string[] | null = null;
function shippedStems(): string[] {
  if (!shipped) shipped = shippedMigrations().map(migrationStem);
  return shipped;
}

let registered = false;

export function registerOpsModule(): void {
  if (registered) return;
  registered = true;

  // The recovery after a restore (ops/cli.ts): written once the steps ran, outcome success or failure.
  registerAuditActions([
    { name: 'ops.restore_reconciled', criticality: 'critical', label: 'Instance reconciled after a restore' },
  ]);

  registerCoreCollectors();

  // ── Readiness (GET /health/ready) ───────────────────────────────────────────
  registerReadinessCheck('database', () => asNone(READY_ACTOR, async () => {
    await db.raw('SELECT 1');
    return true;
  }));
  registerReadinessCheck('schema', () => asNone(READY_ACTOR, async () => {
    const applied = new Set((await db('obligarth_migrations').select('name') as Array<{ name: string }>).map((r) => migrationStem(r.name)));
    return shippedStems().every((m) => applied.has(m)) ? true : { ok: false, code: 'missing_migrations' };
  }));
  registerReadinessCheck('vault', () => (vault.isReady() ? true : { ok: false, code: 'locked' }));
  if (config.apple.mode === 'on') {
    // Unknown (not probed yet, unreachable): the edge's own alerts and obligarth_apple_edge_up tell it; only a version
    // known incompatible makes the instance not ready.
    registerReadinessCheck('apple-edge', () => (edgeHealth().compatible === false ? { ok: false, code: 'incompatible' } : true));
  }
  // The backups (P0-13 T9): last base backup of 26 h at most, WAL stream of 15 min at most, only when they are expected.
  if (config.ops.backups.expected) registerReadinessCheck('backups', backupsReady);
  registerMetricsCollector('backups', backupFamilies);
  // The signed profiles (P0-13 T11, D8): outside lab, a profile signing identity missing or expired makes the instance
  // not ready. In lab an unsigned profile is served with a warning (apple/enrollment/flow.ts).
  const watchSignature = config.stage !== 'lab' && config.apple.mode === 'on';
  if (watchSignature) registerReadinessCheck('signing', signingReady);
  registerMetricsCollector('stage', stageFamilies);

  // ── ops.watch ───────────────────────────────────────────────────────────────
  registerOpsWatchCheck('readiness', watchReadiness);
  registerOpsWatchCheck('backups', watchBackups);
  if (watchSignature) registerOpsWatchCheck('signing', watchSigning);
  registerJob({
    name: 'ops.watch',
    scope: 'platform',
    description: 'Watch of the instance: readiness, then the checks of the modules (backups, signing identity…); alerts of the master tenant',
    payload: empty,
    schedule: { cron: '*/5 * * * *' },
    notify: true,
    pollSeconds: SCHEDULED_POLL_SECONDS,
    retry: { limit: 0 },
    timeoutSeconds: 120,
    handler: runOpsWatch,
  });

  // ── Internal listener of the metrics ────────────────────────────────────────
  registerStartTask('ops.metrics-listener', async () => {
    const m = config.ops.metrics;
    if (m.port === null) {
      logger.info('metrics listener off (METRICS_PORT=off)');
      return;
    }
    try {
      listener = await startMetricsListener({
        port: m.port,
        host: m.host,
        token: readMetricsToken(m.tokenFile),
        render: () => metricsRegistry.render(),
        onError: (err) => logger.error({ err: safeErr(err) }, 'metrics: scrape failed'),
      });
      listenerFailed = false;
      logger.info({ port: m.port, host: m.host, token: m.tokenFile !== '' }, 'metrics listener started (internal, not published)');
    } catch (err) {
      listenerFailed = true;
      logger.error({ err: safeErr(err), port: m.port, host: m.host }, 'metrics listener not started: the server runs without /metrics');
    }
  });
  registerStopTask('ops.metrics-listener', async () => {
    const l = listener;
    listener = null;
    if (l) await l.close();
  });
}
