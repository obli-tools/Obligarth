// =============================================================================
// The recovery after a restore of the database (P0-13 T10, FND-09; integration-apple-edge §13.2, file-durable §10.6,
// audit-durci §7.5), pure: the orchestration of ops restore-reconcile and the rules of ops verify-restore (ops/cli.ts
// wires them to the server). No import of the server (unit tests).
//
// restore-reconcile: refused (exit 4) unless the jobs are paused (JOBS_MODE=paused: nothing runs before the recovery is
// done), in this process and in the database: a server whose jobs run (jobs.heartbeat succeeded less than
// JOBS_HEALTH_MAX_HEARTBEAT_AGE_S ago, what GET /health/jobs reads) refuses it too, whatever this process was given;
// then, in this order, each step with its JSON report, stopping at the first that fails:
//   context  the database accepts the signed context of the command (the probe of guard/cli.ts)
//   guard    every guarded action awaiting approval, scheduled or executing paused, every approval request expired
//   audit    one audit.chain_resumed per chain, export cursors brought back, an immediate seal; a chain already
//            resumed by this restore (a run stopped at a later step, run again) is left as it is
//   vault    every data key unwraps, one sealed value per column and key opens (vault verify)
//   queues   the jobs of the queues that are never replayed (redrivable: false, destructive) still waiting, listed
//   resume   the recovery work queued, run once the jobs are back to all: apple-edge.restore-check and vpp.sync-all
//            (APPLE_EDGE_MODE=on), android.reconcile-tenant requested for every linked tenant (ANDROID_MODE not off)
// then ops.restore_reconciled (critical, master tenant), outcome success or failure with the step that stopped, as soon
// as the context was accepted. Exit 0 done, 1 error (a step threw, or the entry not written), 2 a check failed, 4 the
// jobs not paused. The reports carry codes, counts, identifiers and hashes, never a secret.
//
// verify-restore (read only but for the journal's verification rows and the vault's first keys): the rules below
// turn the readings into failures (exit 2) and warnings, and the summary the report restore_verify keeps (2 KiB).
// =============================================================================

export const RESTORE_STEPS = ['context', 'guard', 'audit', 'vault', 'queues', 'resume'] as const;
export type RestoreStepName = (typeof RESTORE_STEPS)[number];

export const RESTORE_EXIT = { ok: 0, error: 1, failed: 2, notPaused: 4 } as const;

export interface StepOutcome {
  ok: boolean;
  /** Why it failed (a code), or a note when it passed (skipped…). */
  code?: string;
  report?: unknown;
}

export interface RestoreStep {
  name: RestoreStepName;
  run: () => Promise<StepOutcome>;
}

export interface RestoreStepReport {
  step: RestoreStepName;
  ok: boolean;
  code: string | null;
  startedAt: string;
  finishedAt: string;
  report: unknown;
}

export interface RestoreReconcileReport {
  ok: boolean;
  jobsMode: string;
  steps: RestoreStepReport[];
  /** The step that stopped the run (failed or threw), null when every step passed or none ran. */
  stoppedAt: RestoreStepName | null;
  /** ops.restore_reconciled: written, not written (the journal refused it), skipped (the context was refused or
   *  the jobs not paused: nothing was done). */
  audit: 'written' | 'not_written' | 'skipped';
  /** A server running its jobs against this database: seen (refused), not seen, or not checked (the database could
   *  not tell; the context step then says why). */
  scheduler: 'running' | 'not_seen' | 'not_checked';
}

/** The code of an error thrown by a step: its own code when it has a short one, never its message (which may hold a
 *  value of the database). */
export function errorCode(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(code)) return code;
  const name = (err as { name?: unknown } | null)?.name;
  return typeof name === 'string' && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name) ? name : 'error';
}

/**
 * Runs the steps of restore-reconcile in order (RESTORE_STEPS), each once, and stops at the first that fails or throws.
 * `record` writes ops.restore_reconciled; it is called once the context step has passed, whatever happens next.
 * `schedulerRunning` tells whether a server runs its jobs against the database (its heartbeat): refused (exit 4) when
 * it does; when it throws, not checked.
 */
export async function runRestoreReconcile(o: {
  jobsMode: string;
  steps: readonly RestoreStep[];
  record: (r: RestoreReconcileReport) => Promise<void>;
  schedulerRunning?: () => Promise<boolean>;
  now?: () => Date;
}): Promise<{ code: number; report: RestoreReconcileReport }> {
  const now = o.now ?? (() => new Date());
  const report: RestoreReconcileReport = {
    ok: false, jobsMode: o.jobsMode, steps: [], stoppedAt: null, audit: 'skipped', scheduler: 'not_checked',
  };
  if (o.jobsMode !== 'paused') return { code: RESTORE_EXIT.notPaused, report };
  if (o.schedulerRunning) {
    try {
      report.scheduler = (await o.schedulerRunning()) ? 'running' : 'not_seen';
    } catch {
      report.scheduler = 'not_checked';
    }
    if (report.scheduler === 'running') return { code: RESTORE_EXIT.notPaused, report };
  }
  const names = o.steps.map((s) => s.name);
  if (names.join(',') !== RESTORE_STEPS.join(',')) throw new Error(`restore-reconcile: the steps must be ${RESTORE_STEPS.join(', ')}`);

  let code: number = RESTORE_EXIT.ok;
  for (const s of o.steps) {
    const startedAt = now().toISOString();
    let outcome: StepOutcome;
    let threw = false;
    try {
      outcome = await s.run();
    } catch (err) {
      threw = true;
      outcome = { ok: false, code: errorCode(err) };
    }
    report.steps.push({
      step: s.name, ok: outcome.ok, code: outcome.code ?? null, startedAt, finishedAt: now().toISOString(), report: outcome.report ?? null,
    });
    if (!outcome.ok) {
      report.stoppedAt = s.name;
      code = threw ? RESTORE_EXIT.error : RESTORE_EXIT.failed;
      break;
    }
  }
  report.ok = code === RESTORE_EXIT.ok;
  // Nothing can be journaled when the database refused the context of the command.
  const contextPassed = report.steps[0]?.step === 'context' && report.steps[0].ok;
  if (contextPassed) {
    try {
      await o.record(report);
      report.audit = 'written';
    } catch {
      report.audit = 'not_written';
      report.ok = false;
      if (code === RESTORE_EXIT.ok) code = RESTORE_EXIT.error;
    }
  }
  return { code, report };
}

/** The details of ops.restore_reconciled: the outcome of each step that ran (codes), never their reports. */
export function restoreAuditDetails(r: RestoreReconcileReport): Record<string, unknown> {
  return {
    ok: r.ok,
    stoppedAt: r.stoppedAt,
    steps: r.steps.map((s) => ({ step: s.step, ok: s.ok, code: s.code })),
  };
}

// ── verify-restore ──────────────────────────────────────────────────────────────────────────────────────────────

export type KekComparison = 'match' | 'mismatch' | 'no_keys' | 'not_checked';

export interface MigrationComparison {
  applied: number;
  shipped: number;
  /** Shipped by this image, not applied: server-migrate applies them (a backup older than the image). */
  missing: string[];
  /** Applied, not shipped by this image: the database is newer than the image (restore the image of the backup). */
  unknown: string[];
  last: string | null;
}

/** The migrations of the database against the image's (names without extension). */
export function compareMigrations(shipped: readonly string[], applied: readonly string[]): MigrationComparison {
  const s = new Set(shipped);
  const a = new Set(applied);
  const sortedApplied = [...a].sort();
  return {
    applied: a.size,
    shipped: s.size,
    missing: [...s].filter((m) => !a.has(m)).sort(),
    unknown: sortedApplied.filter((m) => !s.has(m)),
    last: sortedApplied.length ? sortedApplied[sortedApplied.length - 1] : null,
  };
}

/** The kek_id of a key file against those of the live data keys of the database. */
export function compareKek(fileKekId: string | null, databaseKekIds: readonly string[]): KekComparison {
  if (fileKekId === null) return 'not_checked';
  if (!databaseKekIds.length) return 'no_keys';
  return databaseKekIds.every((id) => id === fileKekId) ? 'match' : 'mismatch';
}

export interface VerifyReadings {
  schema: MigrationComparison;
  serverKek: { result: KekComparison | 'unreadable' };
  /** checked: a connection of the edge's role was asked (--edge-password-file); error: it failed. */
  edge: { checked: boolean; error: boolean; schema: boolean; kek: KekComparison | 'unreadable' };
  vault: { ready: boolean; failures: number };
  audit: { chains: number; broken: number; errors: number };
  counts: { unreadable: number };
}

/** The failures (exit 2) and warnings of verify-restore, in a fixed order. */
export function verifyFindings(r: VerifyReadings): { failures: string[]; warnings: string[] } {
  const failures: string[] = [];
  const warnings: string[] = [];
  if (r.schema.unknown.length) failures.push('schema_newer_than_image');
  if (r.schema.missing.length) warnings.push('migrations_missing');
  if (r.serverKek.result === 'mismatch') failures.push('server_kek_mismatch');
  else if (r.serverKek.result === 'unreadable' || r.serverKek.result === 'not_checked') failures.push('server_kek_unreadable');
  else if (r.serverKek.result === 'no_keys') warnings.push('server_no_data_keys');
  if (!r.edge.checked) warnings.push('edge_not_checked');
  else if (r.edge.error) failures.push('edge_connection_failed');
  else if (!r.edge.schema) warnings.push('edge_schema_missing');
  else if (r.edge.kek === 'mismatch') failures.push('edge_kek_mismatch');
  else if (r.edge.kek === 'unreadable') failures.push('edge_kek_unreadable');
  else if (r.edge.kek === 'not_checked') warnings.push('edge_kek_not_checked');
  else if (r.edge.kek === 'no_keys') warnings.push('edge_no_data_keys');
  if (!r.vault.ready) failures.push('vault_not_ready');
  else if (r.vault.failures > 0) failures.push('vault_verify_failed');
  if (r.audit.broken > 0) failures.push('audit_chain_broken');
  if (r.audit.errors > 0) failures.push('audit_verify_error');
  if (r.counts.unreadable > 0) warnings.push('counts_unreadable');
  return { failures, warnings };
}

/** Largest summary (compact JSON): well under the 4 KiB of the CHECK of ops_backup_reports, which measures the text
 *  of the jsonb (a space after each colon and comma), and small enough for the report drill that embeds it (drill-report
 *  takes a summary of 2,600 bytes at most). */
export const SUMMARY_MAX_BYTES = 2048;

/** The detail of the report restore_verify: codes and counts, SUMMARY_MAX_BYTES at most (the lists of codes
 *  are cut first). */
export function verifySummary(v: {
  failures: string[];
  warnings: string[];
  schema: MigrationComparison;
  tenants: number;
  tables: number;
  rows: number;
  chains: number;
  chainsBroken: number;
  deks: number;
  vaultFailures: number;
  lastCommandAgeSeconds: number | null;
  seconds: number;
}): Record<string, unknown> {
  const detail: Record<string, unknown> = {
    code: v.failures[0] ?? 'ok',
    failures: v.failures,
    warnings: v.warnings,
    migrations: { applied: v.schema.applied, missing: v.schema.missing.length, unknown: v.schema.unknown.length, last: v.schema.last },
    tenants: v.tenants,
    tables: v.tables,
    rows: v.rows,
    chains: v.chains,
    chains_broken: v.chainsBroken,
    deks: v.deks,
    vault_failures: v.vaultFailures,
    last_command_age_s: v.lastCommandAgeSeconds,
    seconds: v.seconds,
  };
  const size = () => Buffer.byteLength(JSON.stringify(detail), 'utf8');
  while (size() > SUMMARY_MAX_BYTES && ((detail.failures as string[]).length > 1 || (detail.warnings as string[]).length > 0)) {
    if ((detail.warnings as string[]).length) detail.warnings = (detail.warnings as string[]).slice(0, -1);
    else detail.failures = (detail.failures as string[]).slice(0, -1);
  }
  if (size() > SUMMARY_MAX_BYTES) (detail.migrations as Record<string, unknown>).last = null;
  return detail;
}
