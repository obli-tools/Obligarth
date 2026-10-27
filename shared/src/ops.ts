// =============================================================================
// Observability of the instance (P0-13 T8): what GET /api/admin/ops/status returns to the platform administrators
// (master tenant). No tenant data: states, versions, fixed codes, counts. The backups joined it with P0-13 T9, the
// stage of the instance, the signed profiles and the restore drill with P0-13 T11.
// =============================================================================

export interface OpsReadinessCheckDto {
  /** database, schema, vault, apple-edge… (fixed names). */
  name: string;
  ok: boolean;
  /** Fixed code of a failure (timeout, error, failed, missing_migrations…), null when ok. */
  code: string | null;
}

export interface OpsCommandBacklogDto {
  platform: string;
  state: string;
  targets: number;
  oldestSeconds: number;
}

export interface OpsStatusDto {
  generatedAt: string;
  version: string;
  uptimeSeconds: number;
  /** GET /health/ready, detailed (evaluated afresh). */
  readiness: { ok: boolean; checkedAt: string; checks: OpsReadinessCheckDto[] };
  /** GET /health/jobs and the mode of the jobs. */
  jobs: { mode: string; healthy: boolean };
  /** The internal listener of the metrics (port of the container, never published). */
  metrics: { enabled: boolean; listening: boolean; port: number | null; tokenRequired: boolean };
  vault: { ready: boolean };
  appleEdge: {
    mode: string;
    up: boolean | null;
    compatible: boolean | null;
    version: string | null;
    /** End of validity of the profile signing identity (ISO), null: none announced. */
    signingIdentityNotAfter: string | null;
    /** The profile signing identity as apple-edge announces it (P0-13 T11; unknown: apple-edge not heard since the
     *  start, or APPLE_EDGE_MODE=off). */
    signingIdentityState: SigningIdentityState;
    /** APPLE_REQUIRE_SIGNED_PROFILES: an unsigned enrollment profile is refused. */
    requireSignedProfiles: boolean;
  };
  android: { mode: string };
  /** Open command targets of every tenant, per platform and state (null: not readable right now). */
  commands: OpsCommandBacklogDto[] | null;
  process: { rssBytes: number; heapUsedBytes: number; eventLoopDelayP99Seconds: number | null };
  /** The backups of the instance (P0-13 T9; null: their reports are not readable right now). */
  backups: OpsBackupsDto | null;
  /** The stage of the instance and the prerequisites of a pilot (P0-13 T11, D8). */
  stage: OpsStageDto;
  /** The half-yearly restore drill of the backups (deadline backup_restore_drill; null: not readable right now). */
  restoreDrill: OpsRestoreDrillDto | null;
}

// ── Backups of the instance (P0-13 T9, FND-09; decisions D9, D10) ──────────────────────────────────────────────
// The services of the compose profile backup (backup-wal, backup-base, backup-offsite) and, from P0-13 T10, the
// restore drill and the verification of a restore report to obligarth.ops_backup_reports (role obligarth_backup,
// insert only). Codes and counts only: never a secret, a path of the host nor an address of the storage.

/** Kinds of the reports (ops_backup_reports.kind). */
export const BACKUP_REPORT_KINDS = ['base', 'wal', 'offsite', 'prune', 'drill', 'restore_verify'] as const;
export type BackupReportKind = typeof BACKUP_REPORT_KINDS[number];

/** Freshness expected of the backups when BACKUP_EXPECTED=true (/health/ready, ops.watch). */
export const BACKUP_FRESHNESS = {
  /** Last base backup: warning (ops.backup_stale) and not ready beyond 26 h, critical beyond 50 h. */
  baseWarningHours: 26,
  baseCriticalHours: 50,
  /** Last report of the WAL stream with the slot active: critical (ops.wal_stale) and not ready beyond 15 min (RPO). */
  walMinutes: 15,
  /** Free space of the volumes of the backups, below which ops.disk_low is raised. */
  diskLowRatio: 0.15,
} as const;

export interface OpsBackupKindDto {
  kind: BackupReportKind;
  /** Last report that succeeded (ISO), null: none kept. */
  lastSuccessAt: string | null;
  /** Last report, whatever its outcome (ISO). */
  lastReportAt: string | null;
  lastOk: boolean | null;
  /** Reports that failed since the last success. */
  failuresSinceSuccess: number;
  /** Size of the last success (base backup, WAL behind the slot, offsite snapshot…), null when not reported. */
  lastBytes: number | null;
}

export interface OpsBackupReportDto {
  id: number;
  kind: BackupReportKind;
  startedAt: string;
  finishedAt: string;
  ok: boolean;
  bytes: number | null;
  diskFreeBytes: number | null;
  /** Codes and counters of the report (4 KiB at most). */
  detail: Record<string, unknown>;
}

export interface OpsBackupsDto {
  /** BACKUP_EXPECTED: the instance watches its backups (readiness, alerts). */
  expected: boolean;
  kinds: OpsBackupKindDto[];
  /** Free and total space of the volumes of the backups, from the last report that gave them. */
  disk: { freeBytes: number; totalBytes: number | null; reportedAt: string } | null;
  /** The last reports, most recent first. */
  recent: OpsBackupReportDto[];
}

// ── Stage of the instance (P0-13 D8, OBLIGARTH_STAGE) ──────────────────────────────────────────────────────────
// lab by default; the owners move to pilot before the pilot, then production. Outside lab the prerequisites of a
// pilot are imposed: a complete notice before any enrollment (D7, P0-13 T5), and at start the backups and, with
// APPLE_EDGE_MODE=on, the signed profiles (P0-13 T11); a profile signing identity missing or expired then makes the
// instance not ready (GET /health/ready) and raises the critical alert signing.identity_missing.

export const OBLIGARTH_STAGES = ['lab', 'pilot', 'production'] as const;
export type ObligarthStage = typeof OBLIGARTH_STAGES[number];

/** The profile signing identity apple-edge announces (its /status): unknown (not heard since the start, or Apple off),
 *  missing, expired, expiring (SIGNING_IDENTITY_EXPIRING_DAYS or less left), ok. */
export const SIGNING_IDENTITY_STATES = ['unknown', 'missing', 'expired', 'expiring', 'ok'] as const;
export type SigningIdentityState = typeof SIGNING_IDENTITY_STATES[number];

/** Days before its end from which the signing identity is expiring (as the deadline profile_signing_identity). */
export const SIGNING_IDENTITY_EXPIRING_DAYS = 30;

/** The prerequisites of a pilot, as the console of the platform shows them (fixed keys, translated as ops.pilot.<key>). */
export const PILOT_CHECK_KEYS = [
  'backups.expected', 'backups.fresh', 'restore.drill', 'signing.required', 'signing.identity', 'notice.complete',
  'notice.default_allowed',
] as const;
export type PilotCheckKey = typeof PILOT_CHECK_KEYS[number];

export interface OpsPilotCheckDto {
  key: PilotCheckKey;
  /** ok; warning (to do before the pilot, or soon due); error (blocking at this stage); not_applicable. */
  state: 'ok' | 'warning' | 'error' | 'not_applicable';
  /** Fixed code of what is missing ([a-z_]), null when ok or not applicable; translated as ops.codes.<code>. */
  code: string | null;
  /** Counts and days only (never a name). */
  params?: Record<string, number>;
}

export interface OpsStageDto {
  stage: ObligarthStage;
  /** BACKUP_EXPECTED. */
  backupsExpected: boolean;
  /** The prerequisites of a pilot, evaluated now whatever the stage (in lab: what remains to do before the pilot). */
  checks: OpsPilotCheckDto[];
}

export interface OpsRestoreDrillDto {
  /** Due date of the next drill (ISO), null: no deadline yet. */
  dueAt: string | null;
  /** Origin of the deadline: brain (182 days after the last successful drill, or after the backups were expected),
   *  manual (typed in by a platform administrator), null. */
  source: string | null;
  /** Last successful drill (report drill, ISO), null: none. */
  lastSuccessAt: string | null;
}
