import { randomBytes } from 'node:crypto';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  BENCH_ERROR_CODES, BENCH_LIMITS, BENCH_OWNER_MIN_VERSION_CODE, BENCH_ROLE_POLICIES, BENCH_STEP_IDS, BENCH_STEP_STATUSES,
  MASTER_TENANT_ID, benchRolePlan, truncateSerial,
  type BenchProvisioningKind, type BenchProvisioningState, type BenchRolePolicy, type BenchStepEntry,
} from '@obligarth/shared';
import { audit } from '../audit';
import { config } from '../config';
import { db } from '../db';
import { asNone, asTenant } from '../db/context';
import { raiseMasterInTx } from '../apple/alerts/service';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { currentServerKey } from '../legacyAgent/serverKey';
import { sha256Hex } from '../legacyAgent/signature';
import { stationActor, stationAuditContext } from './actor';
import { servedRelease } from './apk.service';
import type { StationLookup } from './stations.service';

// =============================================================================
// The provisionings of a station (lot BANC §3.5, §3.6): the plan of a device on the bench, the single-use enrollment
// token (under a bench session, quotas), the journal of the steps (a white list, never free text of the device), the
// outcome. Every route of a provisioning resolves its tenant first (bench_provisioning_tenant: only this station's), then
// works in that tenant's context as i:bench-station:<id>; a target removed or suspended meanwhile abandons it (422).
// No answer depends on another tenant: a serial held elsewhere goes to the audit of the platform only.
// =============================================================================

const SERIAL = z.string().trim().regex(/^[A-Za-z0-9._:-]{1,64}$/);
const LABEL = (max: number) => z.string().max(max).transform((s) => s.replace(/[\u0000-\u001f\u007f]/g, '').trim()).pipe(z.string().min(1).max(max));
const OPT_TEXT = (max: number) => z.string().max(max).transform((s) => s.replace(/[\u0000-\u001f\u007f]/g, '').trim() || null).nullable().optional();
const SHA = z.string().transform((s) => s.replace(/:/g, '').toLowerCase()).pipe(z.string().regex(/^[0-9a-f]{64}$/));
const PACKAGE = z.string().max(255).regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/);
/** A type of account (com.google, com.whatsapp…), never a name nor an address. */
const ACCOUNT_TYPE = z.string().regex(/^[A-Za-z0-9._-]{1,64}$/);

export const PlanBody = z.object({
  tenantId: z.number().int().positive(),
  groupId: z.number().int().positive(),
  device: z.object({
    adbSerial: SERIAL, hwSerial: SERIAL.nullable().optional(), model: LABEL(64), manufacturer: LABEL(64),
    sdkInt: z.number().int().min(21).max(100), osRelease: OPT_TEXT(32), oneUi: OPT_TEXT(32),
  }).strict(),
  agentInstalled: z.object({
    versionCode: z.number().int().min(1).max(2_000_000_000), signerSha256: SHA.nullable().optional(), adminActive: z.boolean(),
    phase: z.enum(['NEW', 'CONFIGURED', 'ENROLLED', 'TOKEN_REJECTED', 'REVOKED']).nullable().optional(),
  }).strict().nullable(),
  deviceName: z.string().max(100).nullable().optional(),
  preflight: z.object({
    users: z.number().int().min(0).max(100), accounts: z.number().int().min(0).max(1000), accountTypes: z.array(ACCOUNT_TYPE).max(32),
    deviceOwner: PACKAGE.nullable(), profileOwners: z.number().int().min(0).max(100), agentAdminActive: z.boolean(),
    setupComplete: z.boolean().nullable(),
  }).strict(),
}).strict();
export type PlanBody = z.infer<typeof PlanBody>;

/** A detail string of a step: 64 characters at most, no address, no control character. */
const DETAIL_TEXT = z.string().max(64).regex(/^[A-Za-z0-9._:-]*$/);
export const StepBody = z.object({
  step: z.enum(BENCH_STEP_IDS),
  status: z.enum(BENCH_STEP_STATUSES),
  at: z.string().max(40).datetime({ offset: true }),
  code: z.string().regex(/^[a-z_]{1,48}$/).optional(),
  detail: z.object({
    code: z.string().regex(/^[a-z_]{1,48}$/).optional(),
    counts: z.record(z.string().regex(/^[a-z_]{1,32}$/), z.number().int().min(0).max(1_000_000))
      .refine((o) => Object.keys(o).length <= 16, 'counts: 16 keys at most').optional(),
    accountTypes: z.array(DETAIL_TEXT.min(1)).max(16).optional(),
    sdk: z.number().int().min(1).max(100).optional(),
    versionCode: z.number().int().min(1).max(2_000_000_000).optional(),
    attempt: z.number().int().min(1).max(1000).optional(),
  }).strict().optional(),
}).strict();

export const ResultBody = z.object({
  outcome: z.enum(['completed', 'failed', 'abandoned']),
  roleDeclared: z.enum(['device_owner', 'device_admin']).optional(),
  errorCode: z.enum(BENCH_ERROR_CODES).optional(),
  detail: StepBody.shape.detail,
}).strict();

const OPEN_STATES = ['planned', 'token_issued', 'enrolled'];
/** The journal of a provisioning in bytes (bench_provisionings_steps_check: 32 768), with a margin for the jsonb text form. */
const STEPS_BYTE_BUDGET = 30_000;
const TERMINAL_STATES = ['completed', 'failed', 'abandoned', 'expired'];
const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const upper = (v: string | null | undefined): string | null => (v ? v.toUpperCase() : null);

interface Target {
  tenantId: number; tenantName: string; groupId: number; groupPath: string; rolePolicy: BenchRolePolicy; allowLegacyOwner: boolean;
  namePrefix: string | null; disableDevOptions: boolean;
}

/** The targets of a station not suspended, in every tenant (its definer function). */
export async function stationTargets(stationId: string): Promise<Target[]> {
  const r = await asNone(stationActor(stationId), () => db.raw('SELECT * FROM obligarth.bench_station_targets_of(?::uuid)', [stationId])) as
    { rows: Array<Record<string, any>> };
  return r.rows.map((t) => ({
    tenantId: Number(t.tenant_id), tenantName: String(t.tenant_name), groupId: Number(t.group_id), groupPath: t.group_path ?? '',
    rolePolicy: (BENCH_ROLE_POLICIES as readonly string[]).includes(t.role_policy) ? t.role_policy : 'owner_preferred',
    allowLegacyOwner: t.allow_legacy_owner === true, namePrefix: t.name_prefix ?? null, disableDevOptions: t.disable_dev_options === true,
  }));
}

/** The target of a tenant's group among the station's, in the tenant's transaction (tenant context): not suspended. */
async function targetIn(trx: Knex.Transaction, stationId: string, tenantId: number, groupId: number): Promise<Record<string, any> | null> {
  const t = await trx('bench_station_targets').where({ station_id: stationId, tenant_id: tenantId, group_id: groupId }).whereNull('suspended_at')
    .first('*') as Record<string, any> | undefined;
  return t ?? null;
}

/** The tenant of a provisioning of this station (null: not this station's, or unknown). */
export async function provisioningTenant(stationId: string, id: string): Promise<number | null> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
  const r = await asNone(stationActor(stationId), () => db.raw('SELECT obligarth.bench_provisioning_tenant(?::uuid, ?::uuid) AS t', [stationId, id])) as
    { rows: Array<{ t: number | null }> };
  return r.rows[0]?.t === null || r.rows[0]?.t === undefined ? null : Number(r.rows[0].t);
}

/** The audit origin of a station's request. */
export interface Origin { ip?: string; ua?: string; requestId?: string; route?: string }

const sessionUser = (station: StationLookup): number | null =>
  station.session && station.session.expiresAt.getTime() > Date.now() ? station.session.userId : null;

/** The technician of the session holds mdm.bench.operate in the tenant (a platform administrator always). The lookup
 *  gives no session for an account deactivated meanwhile; a session without its technician is refused all the same. */
async function technicianMayOperate(station: StationLookup, tenantId: number): Promise<boolean> {
  const s = station.session;
  if (!s || s.expiresAt.getTime() <= Date.now() || s.technician === null) return false;
  if (s.technicianPlatformAdmin) return true;
  return permissionService.userHasTenantCapability(s.userId, tenantId, 'mdm.bench.operate');
}

// ── Plan ──────────────────────────────────────────────────────────────────────

export interface PlanAnswer {
  provisioningId: string;
  kind: BenchProvisioningKind;
  roleTarget: 'device_owner' | 'device_admin';
  fallbackAllowed: boolean;
  fallbackConfirm: boolean;
  deviceName: string | null;
  existingDeviceUuid?: string;
  warnings: string[];
}

export async function planProvisioning(station: StationLookup, b: PlanBody, origin: Origin): Promise<PlanAnswer> {
  const adb = b.device.adbSerial;
  const hw = b.device.hwSerial ?? null;
  const open = await asNone(stationActor(station.id), () => db.raw('SELECT id, tenant_id FROM obligarth.bench_open_provisioning_of(?::uuid, ?)', [station.id, adb])) as
    { rows: Array<{ id: string }> };
  if (open.rows[0]) {
    throw new AppError(409, 'This device has an open provisioning on this station', 'open_provisioning', { provisioningId: String(open.rows[0].id) });
  }
  const target = (await stationTargets(station.id)).find((t) => t.tenantId === b.tenantId && t.groupId === b.groupId);
  if (!target) throw new AppError(422, 'This target is not one of the station', 'target_refused');
  const served = await servedRelease();
  const planVersion = served ? served.versionCode : (b.agentInstalled?.versionCode ?? 0);
  const serials = [upper(adb), upper(hw)].filter((s): s is string => !!s);
  const crossTenant = await asNone(stationActor(station.id), () => db.raw('SELECT obligarth.bench_identity_conflict(?::uuid, ?, ?::text[]) AS c',
    [station.id, b.tenantId, serials])) as { rows: Array<{ c: boolean }> };

  const tenantId = b.tenantId;
  const answer = await asTenant(tenantId, stationActor(station.id), () => db.transaction(async (trx): Promise<PlanAnswer> => {
    if (!(await targetIn(trx, station.id, tenantId, b.groupId))) throw new AppError(422, 'This target is not one of the station', 'target_refused');
    // The device already known in the tenant, by pairs of the same nature: the ADB serial (Build.SERIAL) against the
    // serial the agent declared and its hint; the serial of the label (ril.serialnumber) against Samsung's and the record's.
    const matches = await trx('devices as d')
      .leftJoin('legacy_agent_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where('d.tenant_id', tenantId).whereNot('d.enrollment_state', 'unenrolled')
      .where((w) => {
        w.whereRaw('upper(a.claimed_serial) = ?', [upper(adb)]).orWhereRaw("upper(a.hints->>'serial') = ?", [upper(adb)]);
        if (hw) w.orWhereRaw('upper(a.samsung_serial) = ?', [upper(hw)]).orWhereRaw('upper(d.serial_number) = ?', [upper(hw)]);
      })
      .select('d.id', 'd.uuid', 'd.group_id', 'd.management_channel', 'a.device_id as agent', 'a.revoked_at') as
      Array<{ id: number; uuid: string; group_id: number | null; management_channel: string; agent: number | null; revoked_at: Date | null }>;
    const warnings: string[] = [];
    const agentRecords = matches.filter((m) => m.management_channel === 'legacy_agent' && m.agent !== null && !m.revoked_at);
    if (matches.some((m) => m.management_channel !== 'legacy_agent')) warnings.push('identity_conflict');
    let kind: BenchProvisioningKind = 'new';
    let deviceId: number | null = null;
    let existingUuid: string | undefined;
    if (agentRecords.length > 0) {
      const inGroup = agentRecords.find((m) => Number(m.group_id) === b.groupId);
      if (!inGroup) throw new AppError(422, 'This device is managed outside the target group', 'device_outside_target');
      if (!b.agentInstalled) throw new AppError(422, 'This device is managed but its agent is missing', 'agent_already_enrolled');
      kind = 'convert';
      deviceId = Number(inGroup.id);
      existingUuid = String(inGroup.uuid);
    } else if (b.agentInstalled && (b.agentInstalled.phase === 'ENROLLED'
      || ((b.agentInstalled.phase === null || b.agentInstalled.phase === undefined) && b.agentInstalled.adminActive))) {
      // An agent enrolled elsewhere would refuse the configuration (Enrollment.kt): revoke it where it is, or reset.
      throw new AppError(422, 'The agent of this device is enrolled elsewhere', 'agent_already_enrolled');
    }
    const plan = benchRolePlan(target.rolePolicy, b.device.sdkInt, planVersion, target.allowLegacyOwner);
    if (kind === 'convert' && plan.target === 'device_owner' && planVersion < BENCH_OWNER_MIN_VERSION_CODE) {
      throw new AppError(422, 'The agent served to the bench cannot own the device: no conversion', 'agent_too_old');
    }
    const given = typeof b.deviceName === 'string' ? b.deviceName.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, BENCH_LIMITS.nameMax) : '';
    const deviceName = (given || `${target.namePrefix ?? ''}${adb}`).slice(0, BENCH_LIMITS.nameMax) || null;
    if (deviceName && kind === 'new') {
      const taken = await trx('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled').where('label', deviceName).first('id');
      if (taken) warnings.push('name_taken');
    }
    if (b.preflight.setupComplete === false) warnings.push('setup_incomplete');
    const session = sessionUser(station);
    const [row] = await trx('bench_provisionings').insert({
      tenant_id: tenantId, group_id: b.groupId, station_id: station.id, session_id: session ? station.session!.id : null, kind,
      state: kind === 'convert' ? 'enrolled' : 'planned', adb_serial: adb, hw_serial: hw, model: b.device.model,
      manufacturer: b.device.manufacturer, sdk_int: b.device.sdkInt, os_release: b.device.osRelease ?? null, one_ui: b.device.oneUi ?? null,
      device_name: deviceName, role_target: plan.target, preflight: JSON.stringify(b.preflight), device_id: deviceId,
    }).returning(['id']) as Array<{ id: string }>;
    const id = String(row.id).toLowerCase();
    const ctx = await stationAuditContext(station.id, station.name, tenantId, origin);
    await audit.appendInTx(trx, {
      tenantId, action: 'bench.provisioning_planned', target: { type: 'bench_provisioning', id, ...(deviceId ? { device: deviceId } : {}) },
      details: {
        provisioningId: id, stationId: station.id, kind, adbSerial: truncateSerial(adb), hwSerial: truncateSerial(hw), model: b.device.model,
        sdk: b.device.sdkInt, roleTarget: plan.target, groupId: b.groupId, warnings,
        ...(session ? { technicianUserId: session } : {}),
      },
    }, ctx, { onFailure: 'spool' });
    return {
      provisioningId: id, kind, roleTarget: plan.target, fallbackAllowed: plan.fallbackAllowed, fallbackConfirm: plan.fallbackConfirm,
      deviceName, ...(existingUuid ? { existingDeviceUuid: existingUuid } : {}), warnings,
    };
  })).catch((err) => {
    if ((err as { code?: string; constraint?: string })?.code === '23505' && /bench_provisionings_open/.test(String((err as { constraint?: string }).constraint ?? ''))) {
      throw new AppError(409, 'This device has an open provisioning on this station', 'open_provisioning');
    }
    throw err;
  });

  // A serial held by a managed device of another tenant: the audit of the platform only, never the station's answer.
  if (crossTenant.rows[0]?.c === true) {
    const ctx = await stationAuditContext(station.id, station.name, MASTER_TENANT_ID, origin);
    await audit.append({
      tenantId: MASTER_TENANT_ID, action: 'bench.identity_conflict_cross_tenant', target: { type: 'bench_station', id: station.id },
      details: { stationId: station.id, provisioningId: answer.provisioningId, tenantId, adbSerial: truncateSerial(adb), hwSerial: truncateSerial(hw) },
    }, ctx);
  }
  return answer;
}

// ── Read ──────────────────────────────────────────────────────────────────────

/** Locks the provisioning of this station in its tenant. */
async function lockedProvisioning(trx: Knex.Transaction, station: StationLookup, tenantId: number, id: string): Promise<Record<string, any>> {
  const p = await trx('bench_provisionings').where({ tenant_id: tenantId, id, station_id: station.id }).forUpdate().first('*') as Record<string, any> | undefined;
  if (!p) throw new AppError(404, 'Provisioning not found', 'not_found');
  return p;
}

class TargetGone extends Error {}

async function withProvisioning<T>(station: StationLookup, id: string, fn: (trx: Knex.Transaction, p: Record<string, any>, tenantId: number) => Promise<T>): Promise<T> {
  const tenantId = await provisioningTenant(station.id, id);
  if (tenantId === null) throw new AppError(404, 'Provisioning not found', 'not_found');
  try {
    return await asTenant(tenantId, stationActor(station.id), () => db.transaction(async (trx) => {
      const p = await lockedProvisioning(trx, station, tenantId, id);
      // An open provisioning whose target was removed or suspended is abandoned (422 target_refused, after the commit of
      // the abandonment). A terminal one stays readable, and its result can be sent again (idempotent, §3.5).
      if (OPEN_STATES.includes(p.state) && !(await targetIn(trx, station.id, tenantId, Number(p.group_id)))) throw new TargetGone();
      return fn(trx, p, tenantId);
    }));
  } catch (err) {
    if (err instanceof TargetGone) {
      // The abandonment of an open provisioning, in its own transaction (the one above rolled back with the throw).
      await asTenant(tenantId, stationActor(station.id), () => db.transaction(async (trx) => {
        const p = await lockedProvisioning(trx, station, tenantId, id);
        if (OPEN_STATES.includes(p.state)) {
          await trx('bench_provisionings').where({ tenant_id: tenantId, id }).update({
            state: 'abandoned', error_code: 'target_refused', outcome_at: new Date(), updated_at: new Date(),
          });
          await revokeOpenToken(trx, tenantId, p, sessionUser(station));
        }
      }));
      throw new AppError(422, 'The target of this provisioning is no longer one of the station', 'target_refused');
    }
    throw err;
  }
}

/**
 * A target suspended or removed (a protective action of the platform or of the tenant), in that action's transaction (the
 * tenant's context): the open provisionings of (station, tenant, group) abandoned (target_refused) and their bench tokens
 * not consumed revoked by the user who acted, so that no device enrolls into the group with a token already issued.
 */
export async function closeTargetProvisionings(trx: Knex.Transaction, tenantId: number, stationId: string, groupId: number, userId: number):
  Promise<{ provisioningsAbandoned: number; enrollmentsRevoked: number }> {
  const open = await trx('bench_provisionings').where({ tenant_id: tenantId, station_id: stationId, group_id: groupId }).whereIn('state', OPEN_STATES)
    .forUpdate().select('id', 'enrollment_token_id') as Array<Record<string, any>>;
  let enrollmentsRevoked = 0;
  for (const p of open) if (await revokeOpenToken(trx, tenantId, p, userId)) enrollmentsRevoked++;
  if (open.length > 0) {
    const now = new Date();
    await trx('bench_provisionings').where({ tenant_id: tenantId }).whereIn('id', open.map((p) => p.id))
      .update({ state: 'abandoned', error_code: 'target_refused', outcome_at: now, updated_at: now });
  }
  return { provisioningsAbandoned: open.length, enrollmentsRevoked };
}

/** The token of a provisioning not consumed, revoked by the technician of the session (none: it expires by itself). */
async function revokeOpenToken(trx: Knex.Transaction, tenantId: number, p: Record<string, any>, technician: number | null): Promise<boolean> {
  if (!p.enrollment_token_id || technician === null) return false;
  const n = await trx('legacy_agent_enrollment_tokens').where({ tenant_id: tenantId, id: p.enrollment_token_id }).whereNull('revoked_at')
    .where('uses', '<', trx.raw('max_uses')).update({ revoked_at: new Date(), revoked_by: technician });
  return n > 0;
}

export interface ProvisioningState {
  state: BenchProvisioningState;
  kind: BenchProvisioningKind;
  deviceUuid: string | null;
  managementMode: string | null;
  identityState: string | null;
  agent: { deviceOwner: boolean; adminActive: boolean; versionCode: number; lastSeenAt: string | null; knoxState: string; adbEnabled: boolean | null } | null;
  tokenExpiresAt: string | null;
  errorCode: string | null;
}

export async function provisioningState(station: StationLookup, id: string): Promise<ProvisioningState> {
  return withProvisioning(station, id, async (trx, p, tenantId) => {
    const dev = p.device_id ? await trx('devices as d')
      .leftJoin('legacy_agent_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.id': p.device_id })
      .first('d.uuid', 'd.management_mode', 'a.identity_state', 'a.device_owner', 'a.admin_active', 'a.agent_version_code', 'a.last_poll_at',
        'a.knox_state', 'a.adb_enabled', 'a.device_id as agent') as Record<string, any> | undefined : undefined;
    const tok = p.enrollment_token_id ? await trx('legacy_agent_enrollment_tokens').where({ tenant_id: tenantId, id: p.enrollment_token_id })
      .first('expires_at', 'revoked_at', 'uses', 'max_uses') as Record<string, any> | undefined : undefined;
    return {
      state: p.state, kind: p.kind, deviceUuid: dev?.uuid ? String(dev.uuid) : null, managementMode: dev?.management_mode ?? null,
      identityState: dev?.identity_state ?? null,
      agent: dev?.agent ? {
        deviceOwner: dev.device_owner === true, adminActive: dev.admin_active === true, versionCode: Number(dev.agent_version_code),
        lastSeenAt: iso(dev.last_poll_at), knoxState: dev.knox_state, adbEnabled: typeof dev.adb_enabled === 'boolean' ? dev.adb_enabled : null,
      } : null,
      tokenExpiresAt: tok && !tok.revoked_at && Number(tok.uses) < Number(tok.max_uses) ? iso(tok.expires_at) : null,
      errorCode: p.error_code ?? null,
    };
  });
}

// ── Token ─────────────────────────────────────────────────────────────────────

/** The tokens a station issued since a time, in every tenant (its definer function, in the token's transaction: the
 *  actor is the station's). */
const tokenCount = async (trx: Knex.Transaction, stationId: string, sinceMs: number): Promise<number> => {
  const r = await trx.raw('SELECT obligarth.bench_station_token_count(?::uuid, ?::timestamptz) AS n',
    [stationId, new Date(Date.now() - sinceMs).toISOString()]) as { rows: Array<{ n: number }> };
  return Number(r.rows[0]?.n ?? 0);
};

export async function issueToken(station: StationLookup, id: string, origin: Origin): Promise<{ config: string; expiresAt: string }> {
  const technician = sessionUser(station);
  if (technician === null) throw new AppError(409, 'No bench session is open for this station', 'no_session');
  const key = await currentServerKey();
  if (!key) throw new AppError(503, 'The instance key of the Android agents is unavailable', 'server_unavailable');
  const publicId = randomBytes(16).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const token = `OLE1.${publicId}.${secret}`;

  const out = await withProvisioning(station, id, async (trx, p, tenantId) => {
    if (p.kind !== 'new' || !['planned', 'token_issued'].includes(p.state)) throw new AppError(409, 'No token for this provisioning in its state', 'bad_state');
    if (!(await technicianMayOperate(station, tenantId))) {
      throw new AppError(422, 'The technician of the session may not enroll into this tenant', 'target_refused');
    }
    // The quotas of the station, counted under its lock in the token's transaction: cards asking at the same time never
    // pass the cap, and the 80 % crossing is seen once.
    await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`bench_tokens:${station.id}`]);
    const hour = await tokenCount(trx, station.id, 3_600_000);
    const day = await tokenCount(trx, station.id, 86_400_000);
    if (hour >= BENCH_LIMITS.tokensPerStationPerHour || day >= BENCH_LIMITS.tokensPerStationPerDay) {
      throw new AppError(429, 'The token quota of the station is reached', 'rate_limited');
    }
    const ctx = await stationAuditContext(station.id, station.name, tenantId, origin);
    if (await revokeOpenToken(trx, tenantId, p, technician)) {
      await audit.appendInTx(trx, {
        tenantId, action: 'legacy_agent.token_revoked', target: { type: 'legacy_agent_token', id: String(p.enrollment_token_id) },
        details: { reason: 'bench_reissue', provisioningId: id, technicianUserId: technician },
      }, ctx);
    }
    const label = `Banc ${station.name} · ${id.slice(0, 8)}`.slice(0, 100);
    const [tok] = await trx('legacy_agent_enrollment_tokens').insert({
      tenant_id: tenantId, public_id: publicId, secret_sha256: sha256Hex(Buffer.from(secret, 'utf8')), label, group_id: p.group_id,
      max_uses: 1, expires_at: trx.raw('now() + make_interval(mins => ?)', [BENCH_LIMITS.tokenTtlMinutes]), created_by: technician, origin: 'bench',
      bench_provisioning_id: id, created_by_station: station.id,
    }).returning(['id', 'expires_at']) as Array<{ id: string; expires_at: Date }>;
    // Critical: written before the answer, in the token's transaction (a failure gives no token).
    await audit.appendInTx(trx, {
      tenantId, action: 'bench.token_issued', target: { type: 'bench_provisioning', id },
      details: { provisioningId: id, stationId: station.id, tokenId: String(tok.id), technicianUserId: technician, adbSerial: truncateSerial(p.adb_serial) },
    }, ctx);
    await trx('bench_provisionings').where({ tenant_id: tenantId, id }).update({
      state: 'token_issued', enrollment_token_id: tok.id, session_id: station.session!.id, updated_at: new Date(),
    });
    return { expiresAt: new Date(tok.expires_at).toISOString(), deviceName: p.device_name ?? null, adbSerial: String(p.adb_serial), day };
  });
  const day = out.day;

  // 80 % of the daily quota: a platform alert and its audit entry (protective), once per crossing.
  if (day + 1 >= Math.ceil(BENCH_LIMITS.tokensPerStationPerDay * 0.8) && day < Math.ceil(BENCH_LIMITS.tokensPerStationPerDay * 0.8)) {
    try {
      await asNone(stationActor(station.id), () => db.transaction(async (trx) => {
        await raiseMasterInTx(trx, 'bench.token_quota', {
          discriminant: station.id, params: { count: day + 1, quota: BENCH_LIMITS.tokensPerStationPerDay }, navigateTo: '/manage/bench-stations',
        }, stationActor(station.id), null);
      }));
      await audit.append({
        tenantId: MASTER_TENANT_ID, action: 'bench.token_quota', target: { type: 'bench_station', id: station.id },
        details: { stationId: station.id, count: day + 1, quota: BENCH_LIMITS.tokensPerStationPerDay },
      }, await stationAuditContext(station.id, station.name, MASTER_TENANT_ID, origin));
    } catch { /* the quota itself holds */ }
  }

  // The configuration v1 the console already gives (base64url): shown once, never readable again.
  const conf = {
    v: 1, server: config.apple.mdmPublicBase ?? '', token, serverKeySha256: key.sha256, knoxLicenseKey: null,
    hints: { deviceName: out.deviceName, serial: out.adbSerial, imei: null, provisioningId: id },
  };
  return { config: Buffer.from(JSON.stringify(conf), 'utf8').toString('base64url'), expiresAt: out.expiresAt };
}

// ── Steps ─────────────────────────────────────────────────────────────────────

export async function appendStep(station: StationLookup, id: string, entry: z.infer<typeof StepBody>): Promise<{ steps: number; dropped: number }> {
  return withProvisioning(station, id, async (trx, p, tenantId) => {
    const current: BenchStepEntry[] = Array.isArray(p.steps) ? p.steps : (typeof p.steps === 'string' ? JSON.parse(p.steps) : []);
    const next = [...current, entry as BenchStepEntry];
    // The oldest entries leave first: beyond the count, then beyond the byte budget (under the CHECK of 32 KiB), so that
    // an entry never fails the update and the station's queue never blocks (§3.5).
    let over = Math.max(0, next.length - BENCH_LIMITS.maxStepsPerProvisioning);
    while (over < next.length - 1 && Buffer.byteLength(JSON.stringify(next.slice(over)), 'utf8') > STEPS_BYTE_BUDGET) over++;
    const kept = next.slice(over);
    await trx('bench_provisionings').where({ tenant_id: tenantId, id }).update({
      steps: JSON.stringify(kept), steps_dropped: Number(p.steps_dropped ?? 0) + over, updated_at: new Date(),
    });
    return { steps: kept.length, dropped: Number(p.steps_dropped ?? 0) + over };
  });
}

// ── Outcome ───────────────────────────────────────────────────────────────────

export async function recordResult(station: StationLookup, id: string, b: z.infer<typeof ResultBody>, origin: Origin):
  Promise<{ state: BenchProvisioningState; warnings: string[] }> {
  return withProvisioning(station, id, async (trx, p, tenantId) => {
    if (TERMINAL_STATES.includes(p.state)) {
      if (p.state === b.outcome && (b.errorCode ?? null) === (p.error_code ?? null)) return { state: p.state, warnings: [] };
      throw new AppError(409, 'This provisioning has another outcome already', 'bad_state');
    }
    const warnings: string[] = [];
    const set: Record<string, unknown> = { state: b.outcome, outcome_at: new Date(), updated_at: new Date(), role_declared: b.roleDeclared ?? null };
    if (b.outcome === 'completed') {
      if (p.state !== 'enrolled' || !p.device_id) throw new AppError(409, 'The device is not enrolled', 'not_enrolled');
      const sat = await trx('legacy_agent_devices').where({ tenant_id: tenantId, device_id: p.device_id })
        .first('device_owner', 'agent_version_code') as { device_owner: boolean; agent_version_code: number } | undefined;
      if (!sat) throw new AppError(409, 'The device is not enrolled', 'not_enrolled');
      if (p.kind === 'convert' && p.role_target === 'device_owner' && sat.device_owner !== true) {
        throw new AppError(409, 'The agent has not reported the owner role yet', 'not_verified');
      }
      // An agent older than 1.4.0 declared owner (exception D3): a warning of the console only, never the mode; and only
      // when the provisioning aimed at the owner on a target that carries the exception (allow_legacy_owner). Any other
      // such declaration is ignored (kept in the audit entry below).
      const legacyOwner = b.roleDeclared === 'device_owner' && Number(sat.agent_version_code) < BENCH_OWNER_MIN_VERSION_CODE;
      const exception = legacyOwner && p.role_target === 'device_owner'
        && (await targetIn(trx, station.id, tenantId, Number(p.group_id)))?.allow_legacy_owner === true;
      if (legacyOwner && !exception) warnings.push('owner_declaration_ignored');
      if (exception) {
        await trx('legacy_agent_devices').where({ tenant_id: tenantId, device_id: p.device_id }).update({ bench_owner_declared: true, updated_at: new Date() });
        warnings.push('owner_unconfirmed');
      }
      set.error_code = null;
    } else {
      set.error_code = b.errorCode ?? null;
      await revokeOpenToken(trx, tenantId, p, sessionUser(station));
    }
    await trx('bench_provisionings').where({ tenant_id: tenantId, id }).update(set);
    const ctx = await stationAuditContext(station.id, station.name, tenantId, origin);
    const technician = sessionUser(station);
    await audit.appendInTx(trx, {
      tenantId, action: `bench.provisioning_${b.outcome}`, target: { type: 'bench_provisioning', id, ...(p.device_id ? { device: Number(p.device_id) } : {}) },
      details: {
        provisioningId: id, stationId: station.id, kind: p.kind, roleTarget: p.role_target, roleDeclared: b.roleDeclared ?? null,
        errorCode: set.error_code ?? null, warnings, ...(technician ? { technicianUserId: technician } : {}),
      },
    }, ctx, { onFailure: 'spool' });
    return { state: b.outcome, warnings };
  });
}
