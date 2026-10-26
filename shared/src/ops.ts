// =============================================================================
// Observability of the instance (P0-13 T8): what GET /api/admin/ops/status returns to the platform administrators
// (master tenant). No tenant data: states, versions, fixed codes, counts. The stage of the instance, the backups,
// the signed profiles and the deadlines join it with the next slices of P0-13 (T9 to T11).
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
  };
  android: { mode: string };
  /** Open command targets of every tenant, per platform and state (null: not readable right now). */
  commands: OpsCommandBacklogDto[] | null;
  process: { rssBytes: number; heapUsedBytes: number; eventLoopDelayP99Seconds: number | null };
}

// ── Stage of the instance (P0-13 D8, OBLIGARTH_STAGE) ──────────────────────────────────────────────────────────
// lab by default; the owners move to pilot before the pilot, then production. Outside lab the prerequisites of a
// pilot are imposed: a complete notice before any enrollment (D7, P0-13 T5), and at start the signed profiles and the
// backups (P0-13 T11).

export const OBLIGARTH_STAGES = ['lab', 'pilot', 'production'] as const;
export type ObligarthStage = typeof OBLIGARTH_STAGES[number];
