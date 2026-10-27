import { BACKUP_FRESHNESS, BACKUP_REPORT_KINDS, type BackupReportKind } from '@obligarth/shared';

// =============================================================================
// The rules of the backups (P0-13 T9, FND-09), pure: what GET /health/ready, ops.watch and the metrics read in the
// status of the reports (obligarth.ops_backup_status(), ops_backup_recent()). With BACKUP_EXPECTED=true:
//   readiness       ready while the last base backup is 26 h old at most and the last report of the WAL stream (slot
//                   active, pg_receivewal connected) 15 min at most (the RPO); codes base_missing, base_stale,
//                   wal_missing, wal_stale;
//   ops.backup_stale  warning beyond 26 h, critical beyond 50 h (or none ever), for the base backup and for the
//                   encrypted offsite copy (a host lost with its disks leaves only it);
//   ops.wal_stale   critical beyond 15 min (or none ever).
// Whatever BACKUP_EXPECTED says, ops.disk_low (warning) when the last report of the hour that gave the space of the
// volumes of the backups finds less than 15 % free. Fixed texts: never a path, an address nor a value of a report but
// ages in hours and minutes and a percentage. No import of the server (unit tests).
// =============================================================================

const HOUR = 3_600_000;
const MINUTE = 60_000;
/** A report older than this does not tell the free space any more. */
const DISK_REPORT_MAX_AGE_MS = HOUR;

export interface BackupKindState {
  kind: BackupReportKind;
  lastSuccessAt: Date | null;
  lastReportAt: Date | null;
  lastOk: boolean | null;
  failuresSinceSuccess: number;
  lastBytes: number | null;
}

export interface BackupReport {
  id: number;
  kind: BackupReportKind;
  startedAt: Date;
  finishedAt: Date;
  ok: boolean;
  bytes: number | null;
  diskFreeBytes: number | null;
  detail: Record<string, unknown>;
}

export interface BackupDisk {
  freeBytes: number;
  totalBytes: number | null;
  reportedAt: Date;
}

export interface BackupFinding {
  /** Stable key of the live alert (one unread alert per key). */
  key: string;
  /** ops.backup_stale, ops.wal_stale, ops.disk_low. */
  alert: 'ops.backup_stale' | 'ops.wal_stale' | 'ops.disk_low';
  severity: 'warning' | 'critical';
  title: string;
  message: string;
}

const isKind = (k: unknown): k is BackupReportKind => (BACKUP_REPORT_KINDS as readonly string[]).includes(String(k));

const toDate = (v: unknown): Date | null => {
  if (v === null || v === undefined) return null;
  const d = v instanceof Date ? v : new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d;
};

const toCount = (v: unknown): number | null => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
};

/** The rows of obligarth.ops_backup_status(), every kind in its order (a kind without row: nothing reported). */
export function kindStatesOf(rows: ReadonlyArray<Record<string, unknown>>): BackupKindState[] {
  const byKind = new Map(rows.filter((r) => isKind(r.kind)).map((r) => [String(r.kind), r]));
  return BACKUP_REPORT_KINDS.map((kind) => {
    const r = byKind.get(kind);
    return {
      kind,
      lastSuccessAt: toDate(r?.last_success_at),
      lastReportAt: toDate(r?.last_report_at),
      lastOk: r?.last_ok === null || r?.last_ok === undefined ? null : r.last_ok === true,
      failuresSinceSuccess: toCount(r?.failures_since_success) ?? 0,
      lastBytes: toCount(r?.last_bytes),
    };
  });
}

/** The rows of obligarth.ops_backup_recent(). */
export function reportsOf(rows: ReadonlyArray<Record<string, unknown>>): BackupReport[] {
  const out: BackupReport[] = [];
  for (const r of rows) {
    const startedAt = toDate(r.started_at);
    const finishedAt = toDate(r.finished_at);
    if (!isKind(r.kind) || !startedAt || !finishedAt) continue;
    const detail = r.detail && typeof r.detail === 'object' && !Array.isArray(r.detail) ? r.detail as Record<string, unknown> : {};
    out.push({
      id: Number(r.id), kind: r.kind, startedAt, finishedAt, ok: r.ok === true,
      bytes: toCount(r.bytes), diskFreeBytes: toCount(r.disk_free_bytes), detail,
    });
  }
  return out;
}

/** The free space of the volumes of the backups: the most recent report that gave it (detail.disk_total_bytes: the
 *  size of the volume, when reported). */
export function diskOf(reports: ReadonlyArray<BackupReport>): BackupDisk | null {
  const r = [...reports].sort((a, b) => b.finishedAt.getTime() - a.finishedAt.getTime()).find((x) => x.diskFreeBytes !== null);
  if (!r) return null;
  const total = toCount(r.detail.disk_total_bytes);
  return { freeBytes: r.diskFreeBytes as number, totalBytes: total && total > 0 ? total : null, reportedAt: r.finishedAt };
}

const stateOf = (kinds: ReadonlyArray<BackupKindState>, kind: BackupReportKind): BackupKindState | undefined => kinds.find((k) => k.kind === kind);
const ageMs = (d: Date | null, now: Date): number => (d ? Math.max(0, now.getTime() - d.getTime()) : Infinity);

/** The readiness of the backups (only asked when BACKUP_EXPECTED=true). */
export function backupReadiness(kinds: ReadonlyArray<BackupKindState>, now: Date): { ok: boolean; code?: string } {
  const base = stateOf(kinds, 'base')?.lastSuccessAt ?? null;
  const wal = stateOf(kinds, 'wal')?.lastSuccessAt ?? null;
  if (!base) return { ok: false, code: 'base_missing' };
  if (ageMs(base, now) > BACKUP_FRESHNESS.baseWarningHours * HOUR) return { ok: false, code: 'base_stale' };
  if (!wal) return { ok: false, code: 'wal_missing' };
  if (ageMs(wal, now) > BACKUP_FRESHNESS.walMinutes * MINUTE) return { ok: false, code: 'wal_stale' };
  return { ok: true };
}

const hoursText = (ms: number): string => (Number.isFinite(ms) ? `${Math.floor(ms / HOUR)} h` : 'never');

/** What ops.watch raises now. */
export function backupFindings(kinds: ReadonlyArray<BackupKindState>, disk: BackupDisk | null, now: Date, expected: boolean): BackupFinding[] {
  const out: BackupFinding[] = [];
  if (expected) {
    for (const [kind, what] of [['base', 'base backup of the database'], ['offsite', 'offsite copy of the backups']] as const) {
      const age = ageMs(stateOf(kinds, kind)?.lastSuccessAt ?? null, now);
      if (age > BACKUP_FRESHNESS.baseCriticalHours * HOUR) {
        out.push({
          key: `ops:backup-stale:${kind}:critical`, alert: 'ops.backup_stale', severity: 'critical',
          title: 'Backups out of date',
          message: `The last successful ${what} is ${hoursText(age)} old (critical beyond ${BACKUP_FRESHNESS.baseCriticalHours} h): check the services of the compose profile backup.`,
        });
      } else if (age > BACKUP_FRESHNESS.baseWarningHours * HOUR) {
        out.push({
          key: `ops:backup-stale:${kind}:warning`, alert: 'ops.backup_stale', severity: 'warning',
          title: 'Backups out of date',
          message: `The last successful ${what} is ${hoursText(age)} old (expected every day, warning beyond ${BACKUP_FRESHNESS.baseWarningHours} h).`,
        });
      }
    }
    const wal = ageMs(stateOf(kinds, 'wal')?.lastSuccessAt ?? null, now);
    if (wal > BACKUP_FRESHNESS.walMinutes * MINUTE) {
      out.push({
        key: 'ops:wal-stale', alert: 'ops.wal_stale', severity: 'critical',
        title: 'Continuous backup of the database stopped',
        message: Number.isFinite(wal)
          ? `The stream of the WAL has not reported for ${Math.floor(wal / MINUTE)} min (recovery point objective: ${BACKUP_FRESHNESS.walMinutes} min): check the service backup-wal; its replication slot keeps the WAL on the disk of the database meanwhile, up to max_slot_wal_keep_size.`
          : 'The stream of the WAL has never reported: start the service backup-wal (compose profile backup).',
      });
    }
  }
  if (disk && disk.totalBytes && now.getTime() - disk.reportedAt.getTime() <= DISK_REPORT_MAX_AGE_MS) {
    const ratio = disk.freeBytes / disk.totalBytes;
    if (ratio < BACKUP_FRESHNESS.diskLowRatio) {
      out.push({
        key: 'ops:disk-low', alert: 'ops.disk_low', severity: 'warning',
        title: 'Disk space low',
        message: `The volumes of the backups have ${Math.floor(ratio * 100)} % free space left (warning below ${Math.round(BACKUP_FRESHNESS.diskLowRatio * 100)} %).`,
      });
    }
  }
  return out;
}

/** Half-yearly restore drill: the due date that follows a drill (P0-13, échéance backup_restore_drill). */
export const RESTORE_DRILL_PERIOD_DAYS = 182;

/** An open item of the deadline backup_restore_drill of the instance. */
export interface RestoreDrillItem {
  notAfter: Date;
  /** brain (the échéancier: the last successful drill + 182 days, or the start of the backups + 182 days), manual. */
  source: string;
  updatedAt: Date;
}

/** The deadline of the drill the console shows: the earliest open item, but a date typed in before the last successful
 *  drill, which that drill answered (the échéancier retires it at its next pass, apple/integrations/schedule.ts). */
export function restoreDrillDeadline(items: readonly RestoreDrillItem[], lastSuccessAt: string | null): { dueAt: Date | null; source: string | null } {
  const last = lastSuccessAt ? Date.parse(lastSuccessAt) : NaN;
  const open = items.filter((i) => !(i.source === 'manual' && Number.isFinite(last) && i.updatedAt.getTime() < last))
    .sort((a, b) => a.notAfter.getTime() - b.notAfter.getTime());
  return open[0] ? { dueAt: open[0].notAfter, source: open[0].source } : { dueAt: null, source: null };
}
