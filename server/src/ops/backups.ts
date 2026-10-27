import { MASTER_TENANT_ID, type OpsBackupsDto } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { asNone, asTenant, type DbActor } from '../db/context';
import { liveAlertService } from '../services/liveAlert.service';
import { logger } from '../utils/logger';
import type { JobContext } from '../jobs/types';
import {
  backupFindings, backupReadiness, diskOf, kindStatesOf, reportsOf, type BackupKindState, type BackupReport,
} from './backupRules';
import { family, single, type MetricFamily } from './metrics';

// =============================================================================
// The backups of the instance, as the server sees them (P0-13 T9, FND-09; decisions D9, D10): the reports the services
// of the compose profile backup insert in obligarth.ops_backup_reports (role obligarth_backup), read through
// obligarth.ops_backup_status() and ops_backup_recent() in the context 'none' of a job actor, cached 30 s.
//   readiness   GET /health/ready, when BACKUP_EXPECTED=true (registered by modules/ops.ts): backupReadiness;
//   ops.watch   the check 'backups': ops.backup_stale, ops.wal_stale (BACKUP_EXPECTED=true), ops.disk_low (live alerts
//               of the master tenant, stable keys: one unread alert per key, raised again at each run while it lasts);
//               once an hour, the reports past their keeping (ops_backup_prune);
//   metrics     obligarth_backup_last_success_timestamp_seconds{kind}, obligarth_backup_failures_since_success{kind},
//               obligarth_backup_disk_free_bytes, obligarth_backup_disk_total_bytes (no tenant, no value of a report);
//   ops status  OpsBackupsDto (GET /api/admin/ops/status).
// The restore drill (deadline backup_restore_drill) is the échéancier's (apple/integrations/schedule.ts).
// =============================================================================

const STATUS_ACTOR = { type: 'job', name: 'ops.backups' } as const;
const CACHE_MS = 30_000;
const RECENT_LIMIT = 20;
const PRUNE_EVERY_MS = 3_600_000;

export interface BackupsSnapshot {
  kinds: BackupKindState[];
  recent: BackupReport[];
}

let cache: { until: number; value: BackupsSnapshot } | null = null;
let inflight: Promise<BackupsSnapshot> | null = null;

async function readSnapshot(): Promise<BackupsSnapshot> {
  return asNone(STATUS_ACTOR, async () => {
    const status = await db.raw('SELECT * FROM obligarth.ops_backup_status()') as { rows: Array<Record<string, unknown>> };
    const recent = await db.raw('SELECT * FROM obligarth.ops_backup_recent(?)', [RECENT_LIMIT]) as { rows: Array<Record<string, unknown>> };
    return { kinds: kindStatesOf(status.rows), recent: reportsOf(recent.rows) };
  });
}

/** The status of the backups (cached 30 s; fresh: read now). Concurrent callers share one read. */
export async function backupsSnapshot(fresh = false): Promise<BackupsSnapshot> {
  const now = Date.now();
  if (!fresh && cache && now < cache.until) return cache.value;
  if (!inflight) {
    inflight = readSnapshot()
      .then((value) => { cache = { until: Date.now() + CACHE_MS, value }; return value; })
      .finally(() => { inflight = null; });
  }
  return inflight;
}

/** The readiness check 'backups' (BACKUP_EXPECTED=true). */
export async function backupsReady(): Promise<{ ok: boolean; code?: string }> {
  const s = await backupsSnapshot();
  return backupReadiness(s.kinds, new Date());
}

let lastPruneAt = 0;

async function raise(actor: DbActor, f: ReturnType<typeof backupFindings>[number]): Promise<void> {
  logger[f.severity === 'critical' ? 'error' : 'warn']({ alert: f.alert, key: f.key, severity: f.severity }, `ops alert: ${f.title}`);
  await asTenant(MASTER_TENANT_ID, actor, () => liveAlertService.add(MASTER_TENANT_ID, {
    severity: f.severity,
    title: f.title,
    message: f.message.slice(0, 500),
    navigateTo: null,
    stableKey: f.key,
  }));
}

/** The check 'backups' of ops.watch. A write that fails fails the check. */
export async function watchBackups(ctx: JobContext<unknown>): Promise<Record<string, string | number | boolean | null>> {
  const s = await backupsSnapshot(true);
  const now = new Date();
  const findings = backupFindings(s.kinds, diskOf(s.recent), now, config.ops.backups.expected);
  for (const f of findings) await raise(ctx.dbActor, f);
  let pruned: number | null = null;
  if (now.getTime() - lastPruneAt >= PRUNE_EVERY_MS) {
    const r = await asNone(ctx.dbActor, () => db.raw('SELECT obligarth.ops_backup_prune() AS n')) as { rows: Array<{ n: number }> };
    pruned = Number(r.rows[0]?.n ?? 0);
    lastPruneAt = now.getTime();
  }
  return {
    expected: config.ops.backups.expected,
    findings: findings.map((f) => f.alert).join(',').slice(0, 200) || null,
    ...(pruned !== null ? { pruned } : {}),
  };
}

/** The metric families of the backups (collector 'backups'). */
export async function backupFamilies(): Promise<MetricFamily[]> {
  const s = await backupsSnapshot();
  const disk = diskOf(s.recent);
  const seconds = (d: Date | null) => (d ? Math.floor(d.getTime() / 1000) : null);
  return [
    family('obligarth_backup_last_success_timestamp_seconds', 'Last successful backup report, by kind (Unix time)', 'gauge',
      s.kinds.filter((k) => k.lastSuccessAt).map((k) => ({ labels: { kind: k.kind }, value: seconds(k.lastSuccessAt) as number }))),
    family('obligarth_backup_failures_since_success', 'Backup reports that failed since the last success, by kind', 'gauge',
      s.kinds.filter((k) => k.lastReportAt).map((k) => ({ labels: { kind: k.kind }, value: k.failuresSinceSuccess }))),
    single('obligarth_backup_disk_free_bytes', 'Free space of the volumes of the backups (last report that gave it)', 'gauge', disk ? disk.freeBytes : null),
    single('obligarth_backup_disk_total_bytes', 'Size of the volumes of the backups (last report that gave it)', 'gauge', disk?.totalBytes ?? null),
  ];
}

/** The backups in the ops status (GET /api/admin/ops/status), read now. */
export async function opsBackups(): Promise<OpsBackupsDto> {
  const s = await backupsSnapshot(true);
  const iso = (d: Date | null) => (d ? d.toISOString() : null);
  const disk = diskOf(s.recent);
  return {
    expected: config.ops.backups.expected,
    kinds: s.kinds.map((k) => ({
      kind: k.kind, lastSuccessAt: iso(k.lastSuccessAt), lastReportAt: iso(k.lastReportAt), lastOk: k.lastOk,
      failuresSinceSuccess: k.failuresSinceSuccess, lastBytes: k.lastBytes,
    })),
    disk: disk ? { freeBytes: disk.freeBytes, totalBytes: disk.totalBytes, reportedAt: disk.reportedAt.toISOString() } : null,
    recent: s.recent.map((r) => ({
      id: r.id, kind: r.kind, startedAt: r.startedAt.toISOString(), finishedAt: r.finishedAt.toISOString(), ok: r.ok,
      bytes: r.bytes, diskFreeBytes: r.diskFreeBytes, detail: r.detail,
    })),
  };
}

/** The last successful drill of a restore (the échéancier's deadline backup_restore_drill). */
export async function lastRestoreDrillAt(actor: DbActor): Promise<Date | null> {
  const r = await asNone(actor, () => db.raw(`SELECT last_success_at FROM obligarth.ops_backup_status() WHERE kind = 'drill'`)) as
    { rows: Array<{ last_success_at: Date | null }> };
  const v = r.rows[0]?.last_success_at;
  return v ? new Date(v) : null;
}

/** Tests only. */
export function resetBackupsForTests(): void {
  cache = null;
  inflight = null;
  lastPruneAt = 0;
}
