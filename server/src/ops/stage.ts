import {
  OBLIGARTH_STAGES, SIGNING_IDENTITY_EXPIRING_DAYS, type ObligarthStage, type OpsPilotCheckDto, type SigningIdentityState,
} from '@obligarth/shared';

// =============================================================================
// Stage of the instance (P0-13 D8: OBLIGARTH_STAGE = lab | pilot | production, lab by default) and its rules (P0-13
// T11). Pure: no import of the configuration nor of the database, the unit tests load this file.
//   readStageConfig       read once by config.ts (config.stage); a value that is not one of the three is refused at
//                         start (startupConfigErrors) and read meanwhile as the strictest stage (production)
//   instanceStage         the stage of this process, read from its environment: the CLIs (ops/cli.ts…) do not run
//                         startupConfigErrors, an invalid value fails closed (production), never open
//   stageStartupErrors    outside lab, the server refuses to start without the prerequisites of a pilot:
//                           - BACKUP_EXPECTED=true (the backups of the compose profile backup run and are watched),
//                             whatever the platforms;
//                           - with APPLE_EDGE_MODE=on, APPLE_REQUIRE_SIGNED_PROFILES=true (no unsigned enrollment
//                             profile) and APPLE_ALLOW_DEFAULT_NOTICE not true (incoherent since the generated notice);
//                         the notice of each tenant is checked at its enrollments (D7, privacy/notice/provider.ts), the
//                         signing identity by the readiness and ops.watch (ops/signing.ts): neither refuses the start
//                         (an identity that expires must not make the server loop on its start)
//   signingIdentityOf     the profile signing identity apple-edge announces (edgeHealth), as a state
//   pilotChecks           the prerequisites of a pilot for the console (GET /api/admin/ops/status), whatever the stage:
//                         in lab what remains to do (warning), beyond lab what blocks (error)
// =============================================================================

let override: ObligarthStage | null = null;

/** The stage of an environment: lab when OBLIGARTH_STAGE is absent or empty, production when it is not a stage. */
export function readInstanceStage(env: NodeJS.ProcessEnv): ObligarthStage {
  const raw = (env.OBLIGARTH_STAGE ?? '').trim().toLowerCase();
  if (raw === '') return 'lab';
  return (OBLIGARTH_STAGES as readonly string[]).includes(raw) ? raw as ObligarthStage : 'production';
}

/** The stage of an environment and why its value is refused at start (not one of the three). */
export function readStageConfig(env: NodeJS.ProcessEnv): { stage: ObligarthStage; errors: string[] } {
  const raw = (env.OBLIGARTH_STAGE ?? '').trim().toLowerCase();
  const errors = raw === '' || (OBLIGARTH_STAGES as readonly string[]).includes(raw)
    ? []
    : ['OBLIGARTH_STAGE must be lab (the default), pilot or production.'];
  return { stage: readInstanceStage(env), errors };
}

/** The stage of this instance. */
export function instanceStage(): ObligarthStage {
  return override ?? readInstanceStage(process.env);
}

/** Is this instance past the laboratory (pilot or production)? */
export const beyondLab = (): boolean => instanceStage() !== 'lab';

/** Test hook: a fixed stage (null: the environment again). */
export function setInstanceStageForTests(stage: ObligarthStage | null): void {
  override = stage;
}

export interface StageSettings {
  appleMode: 'on' | 'off';
  /** APPLE_REQUIRE_SIGNED_PROFILES. */
  requireSignedProfiles: boolean;
  /** APPLE_ALLOW_DEFAULT_NOTICE. */
  allowDefaultNotice: boolean;
  /** BACKUP_EXPECTED. */
  backupsExpected: boolean;
}

/** The settings the server refuses to start with at this stage (D8); none in lab. */
export function stageStartupErrors(stage: ObligarthStage, s: StageSettings): string[] {
  if (stage === 'lab') return [];
  const errors: string[] = [];
  if (!s.backupsExpected) {
    errors.push(`OBLIGARTH_STAGE=${stage} requires BACKUP_EXPECTED=true: start the backups (docker compose --profile backup up -d), ` +
      'check their first reports in the console (Security, Operations), then set BACKUP_EXPECTED=true; or keep OBLIGARTH_STAGE=lab.');
  }
  if (s.appleMode === 'on') {
    if (!s.requireSignedProfiles) {
      errors.push(`OBLIGARTH_STAGE=${stage} with APPLE_EDGE_MODE=on requires APPLE_REQUIRE_SIGNED_PROFILES=true: import the profile ` +
        'signing identity (apple-edge signing-identity import), then set APPLE_REQUIRE_SIGNED_PROFILES=true; or keep OBLIGARTH_STAGE=lab.');
    }
    if (s.allowDefaultNotice) {
      errors.push(`OBLIGARTH_STAGE=${stage} refuses APPLE_ALLOW_DEFAULT_NOTICE=true: the notice is generated for each tenant and must be ` +
        'complete before its enrollments; remove the variable (or set it to false).');
    }
  }
  return errors;
}

const DAY_MS = 86_400_000;

export interface SigningIdentityView {
  state: SigningIdentityState;
  /** End of validity announced (ISO), null: none. */
  notAfter: string | null;
  /** Whole days left (negative once expired), null: none. */
  daysLeft: number | null;
}

/** The signing identity of an edgeHealth() state: unknown while apple-edge has not answered since the start (its last
 *  announcement is kept while it is unreachable), missing when none is announced or its end is unreadable. */
export function signingIdentityOf(edge: { lastOkAt: string | null; signingIdentity: { notAfter: string } | null }, now: Date): SigningIdentityView {
  if (!edge.lastOkAt && !edge.signingIdentity) return { state: 'unknown', notAfter: null, daysLeft: null };
  if (!edge.signingIdentity) return { state: 'missing', notAfter: null, daysLeft: null };
  const end = Date.parse(edge.signingIdentity.notAfter);
  if (!Number.isFinite(end)) return { state: 'missing', notAfter: null, daysLeft: null };
  const notAfter = new Date(end).toISOString();
  const daysLeft = Math.floor((end - now.getTime()) / DAY_MS);
  if (end <= now.getTime()) return { state: 'expired', notAfter, daysLeft };
  return { state: daysLeft <= SIGNING_IDENTITY_EXPIRING_DAYS ? 'expiring' : 'ok', notAfter, daysLeft };
}

/** Is the signing identity unusable (missing or expired)? unknown is not: nothing was announced. */
export const signingUnusable = (state: SigningIdentityState): boolean => state === 'missing' || state === 'expired';

export interface PilotFacts extends StageSettings {
  stage: ObligarthStage;
  /** The readiness check 'backups' (BACKUP_EXPECTED=true), null: not evaluated. */
  backupsReadiness: { ok: boolean; code: string | null } | null;
  signing: SigningIdentityView;
  /** Tenants and tenants whose notice is incomplete, null: not readable. */
  notice: { tenants: number; incomplete: number } | null;
  /** The deadline of the restore drill, null: not readable. */
  drill: { dueAt: Date | null } | null;
  now: Date;
}

/** Days left before the drill from which it is due soon (the deadline warns at J-30, 14 and 7). */
const DRILL_SOON_DAYS = 30;

/** The prerequisites of a pilot, in the order of PILOT_CHECK_KEYS. */
export function pilotChecks(f: PilotFacts): OpsPilotCheckDto[] {
  const blocking = f.stage === 'lab' ? 'warning' : 'error';
  const out: OpsPilotCheckDto[] = [];
  const na = (key: OpsPilotCheckDto['key']): OpsPilotCheckDto => ({ key, state: 'not_applicable', code: null });

  out.push(f.backupsExpected ? { key: 'backups.expected', state: 'ok', code: null }
    : { key: 'backups.expected', state: blocking, code: 'backups_not_expected' });

  if (!f.backupsExpected) out.push(na('backups.fresh'));
  else if (!f.backupsReadiness) out.push({ key: 'backups.fresh', state: 'warning', code: 'unknown' });
  else out.push(f.backupsReadiness.ok ? { key: 'backups.fresh', state: 'ok', code: null }
    : { key: 'backups.fresh', state: 'error', code: f.backupsReadiness.code ?? 'failed' });

  if (!f.drill) out.push({ key: 'restore.drill', state: 'warning', code: 'unknown' });
  else if (!f.drill.dueAt) out.push(f.backupsExpected ? { key: 'restore.drill', state: 'warning', code: 'drill_not_scheduled' } : na('restore.drill'));
  else {
    const days = Math.floor((f.drill.dueAt.getTime() - f.now.getTime()) / DAY_MS);
    if (days < 0) out.push({ key: 'restore.drill', state: 'error', code: 'drill_overdue', params: { days: -days } });
    else if (days <= DRILL_SOON_DAYS) out.push({ key: 'restore.drill', state: 'warning', code: 'drill_due_soon', params: { daysLeft: days } });
    else out.push({ key: 'restore.drill', state: 'ok', code: null, params: { daysLeft: days } });
  }

  if (f.appleMode !== 'on') {
    out.push(na('signing.required'), na('signing.identity'));
  } else {
    out.push(f.requireSignedProfiles ? { key: 'signing.required', state: 'ok', code: null }
      : { key: 'signing.required', state: blocking, code: 'signed_profiles_not_required' });
    const s = f.signing;
    const days = s.daysLeft ?? 0;
    switch (s.state) {
      case 'ok': out.push({ key: 'signing.identity', state: 'ok', code: null, params: { daysLeft: days } }); break;
      case 'expiring': out.push({ key: 'signing.identity', state: 'warning', code: 'signing_identity_expiring', params: { daysLeft: Math.max(0, days) } }); break;
      case 'missing': out.push({ key: 'signing.identity', state: blocking, code: 'signing_identity_missing' }); break;
      case 'expired': out.push({ key: 'signing.identity', state: blocking, code: 'signing_identity_expired' }); break;
      default: out.push({ key: 'signing.identity', state: 'warning', code: 'signing_identity_unknown' });
    }
  }

  if (!f.notice) out.push({ key: 'notice.complete', state: 'warning', code: 'unknown' });
  else out.push(f.notice.incomplete === 0 ? { key: 'notice.complete', state: 'ok', code: null, params: { total: f.notice.tenants } }
    : { key: 'notice.complete', state: blocking, code: 'notice_incomplete', params: { incomplete: f.notice.incomplete, total: f.notice.tenants } });

  if (f.appleMode !== 'on') out.push(na('notice.default_allowed'));
  else out.push(f.allowDefaultNotice ? { key: 'notice.default_allowed', state: blocking, code: 'default_notice_allowed' }
    : { key: 'notice.default_allowed', state: 'ok', code: null });
  return out;
}
