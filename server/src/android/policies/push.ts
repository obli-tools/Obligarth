// Delivery of the Android policies (sections 9.1, 9.3, 9.4; §22.6): the provider of the channel 'amapi' as an
// autonomous module. The common artifact store of lot AN-P (mdm/policies/artifacts.ts, registerArtifactChannel) does
// not exist yet: this module compiles with the compiler of AN-C1a from the settings a source gives it, keeps the
// state of the device's policy in android_devices (policy_state, pushed version and rendered hash) until part 5
// widens mdm_artifacts and device_artifacts to the channel amapi, and exposes the provider shape of §22.6
// (amapiChannelProvider) for registerArtifactChannel at the junction.
//   android.policies.push-device: compile, render (variables, then the secrets read from the tenant's vault in the
//     job), rendered hash (secrets excluded); same hash and same policy name: nothing; else policies.patch
//     d-<device uuid> (never logged nor stored), then devices.patch policyName at the first push; a device pending
//     approval receives nothing (AN17); a 400 of Google puts the policy in error (amapi_rejected) with a tenant
//     alert, three automatic attempts per rendered version at most.
//   android.policies.enrollment-policy: e-<profile uuid> compiled for a fictitious device of the profile, without any
//     secret (enrollmentPolicySecret refused: §22.3), pushed; android_enrollment_policies records it (rule of the 5
//     minutes: no token without it, section 10.7).
// Kiosk (lot AN-G1): a dedicated device is compiled with the kiosk app of its enrollment profile (when it is a live app
// of the tenant's catalog) and with its running kiosk exit (the lock lifted until the exit ends); so is the enrollment
// policy of a kiosk profile (its app, never an exit). Review AN-G1 (G1-R1): an exit is never applied to a policy that
// carries a wipe-capable setting (the compiler keeps the lock, the exit ends as wipe_policy), and the lock of an ended
// exit is said restored only once Google accepted the policy that holds it (markKioskLockRestored).
// Second review AN-G1 (G1-S1, G1-S2): the return of the lock is never blocked by a freeze. When the lock of a kiosk is
// pending under a freeze of its tenant (kioskLockPendingUnderFreeze, read just before the call) and its locked policy
// carries a wipe-capable setting, that policy is pushed without its wipe-capable paths (withoutWipeSettings,
// module-private): it passes the freeze lock of AN15 without easing it, and Google holds no wipe-capable setting for
// the device that the push would add (an unlocked policy never carries one, G1-R1). The degraded rendering is audited
// (android.kiosk_wipe_settings_withheld) and the full policy follows after the unfreeze (android.maintenance; audit
// android.kiosk_wipe_settings_applied once Google accepts it). No other case, no option of a caller, reaches it.
// No call to Google inside a transaction (G-A1).
import type { Knex } from 'knex';
import { POLICY_VARIABLES, type JsonValue, type PolicyVariable } from '@obligarth/shared';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { compileAndroid, AndroidCompileError, type AndroidDeviceFacts, type AndroidEffectiveSetting, type CompiledAndroidPolicy } from '../../mdm/android/compile';
import { renderAndroidPolicy, RenderError } from '../../mdm/android/render';
import type { VariableValues } from '../../mdm/apple/variables';
import { loadGroupAncestors, loadResolutionInput } from '../../mdm/policies/loader';
import { indexAssignments, resolveDevice, variableValue, type ResolutionDevice, type ResolvedSetting } from '../../mdm/policies/resolver';
import { vault } from '../../vault';
import { raiseAndroidTenantAlert } from '../alerts';
import { readEnterprise, readEnterpriseRow } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import { parseOwnedName } from '../gateway/names';
import type { AndroidGateway } from '../gateway/types';
import { DEFAULT_PRIVACY } from '../inventory/privacy';
import { kioskAppInCatalog, readAndroidProfile, snapshotOf } from '../enrollment/profiles';
import {
  endKioskExitForWipePolicy, kioskLockPendingUnderFreeze, markKioskLockRestored, markKioskWipeSettingsApplied, runningKioskExit,
} from '../kiosk/exits';
import { FAILED_PASSWORDS_FOR_WIPE, policyHasWipeSettings, PRIVATE_SPACE_DISALLOWED } from '../../mdm/android/overlay';
import { androidSenders } from '../enrollment/senders';
import { byodPolicy } from '../byod/policy';

export const PUSH_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.policies.push-device' }) as DbActor;
export const ENROLLMENT_POLICY_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.policies.enrollment-policy' }) as DbActor;
/** Automatic attempts per rendered version after a refusal of Google (section 9.4 step 6). */
export const MAX_PUSH_FAILURES = 3;

/** What the resolution retained for a device (or for the fictitious device of a profile), and its variables. */
export interface AndroidDesired { settings: AndroidEffectiveSetting[]; variables: VariableValues }

export type AndroidDeviceSettingsSource = (trx: Knex.Transaction, tenantId: number, deviceId: number) => Promise<AndroidDesired>;
export type AndroidProfileSettingsSource = (trx: Knex.Transaction, tenantId: number, profile: { id: string; defaultGroupId: number | null;
  mode: string; ownership: string }) => Promise<AndroidDesired>;

const toAndroid = (s: ResolvedSetting): AndroidEffectiveSetting => ({
  settingKey: s.settingKey, removed: s.removed,
  availability: s.availability.status === 'available' ? { status: 'available' }
    : { status: 'not_applicable', reason: s.availability.reason, ...(s.availability.detail ? { detail: s.availability.detail } : {}) },
  ...(s.value !== undefined ? { value: s.value as JsonValue } : {}),
  source: { type: s.source.type, id: s.source.id, tenantId: s.source.tenantId, assignmentId: s.source.assignmentId, rank: s.source.rank, priority: s.source.priority },
});

function variablesOf(d: ResolutionDevice, tenant: { name: string; slug: string }): VariableValues {
  const out: VariableValues = {};
  for (const name of POLICY_VARIABLES as readonly PolicyVariable[]) {
    const v = variableValue(name, d, tenant);
    if (v !== null) out[name] = v;
  }
  return out;
}

/**
 * The default source: the common resolver, keeping the android:* keys (the contributions of the android section,
 * mdm/policies/contributions.ts since the junction AN-A2).
 */
export const resolverDeviceSource: AndroidDeviceSettingsSource = async (trx, tenantId, deviceId) => {
  const input = await loadResolutionInput(trx, tenantId, [deviceId]);
  const d = input.devices.find((x) => x.id === deviceId);
  if (!d) return { settings: [], variables: {} };
  const r = resolveDevice(input, d, indexAssignments(input.assignments));
  return { settings: r.settings.filter((s) => s.settingKey.startsWith('android:')).map(toAndroid), variables: variablesOf(d, input.tenant) };
};

/** The default source of an enrollment policy: the fictitious device of the profile in its default group. */
export const resolverProfileSource: AndroidProfileSettingsSource = async (trx, tenantId, p) => {
  const input = await loadResolutionInput(trx, tenantId, []);
  const ancestors = await loadGroupAncestors(trx, tenantId, p.defaultGroupId === null ? [] : [p.defaultGroupId]);
  const fictitious: ResolutionDevice = {
    id: 0, uuid: p.id, label: '', groupId: p.defaultGroupId, platform: 'android', osVersion: null, mode: p.mode, supervised: false,
    ownership: p.ownership, serialNumber: null, udid: null, modelName: null, ddmEnabled: false, declarationTypes: null, endUser: null,
  };
  const r = resolveDevice({ ...input, groupAncestors: ancestors }, fictitious, indexAssignments(input.assignments));
  // An enrollment policy has the tenant's variables only (no device variable).
  const variables: VariableValues = { 'tenant.name': input.tenant.name, 'tenant.slug': input.tenant.slug } as VariableValues;
  return { settings: r.settings.filter((s) => s.settingKey.startsWith('android:')).map(toAndroid), variables };
};

let deviceSource: AndroidDeviceSettingsSource = resolverDeviceSource;
let profileSource: AndroidProfileSettingsSource = resolverProfileSource;
export function setAndroidSettingsSources(o: { device?: AndroidDeviceSettingsSource; profile?: AndroidProfileSettingsSource }): void {
  if (o.device) deviceSource = o.device;
  if (o.profile) profileSource = o.profile;
}

export type PushResult = 'pushed' | 'unchanged' | 'pending_approval' | 'not_managed' | 'error' | 'no_enterprise';

interface DeviceRow {
  id: number; uuid: string; enrollment_profile_id: string | null; management_mode: string; ownership: string; usage: string; enrollment_state: string;
  amapi_name: string; api_level: number | null; approval_state: string; policy_name: string | null; pushed_rendered_hash: string | null;
  pushed_policy_version: string | null; policy_push_failures: number; policy_state_reasons: string[]; state: string | null; released_at: Date | null;
}

async function setPolicyError(tenantId: number, deviceId: number, reasons: string[], countFailure: boolean): Promise<void> {
  await db.transaction((trx) => trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({
    policy_state: 'error', policy_state_reasons: JSON.stringify(reasons.slice(0, 20)), updated_at: trx.fn.now(),
    ...(countFailure ? { policy_push_failures: trx.raw('policy_push_failures + 1') } : {}),
  }));
}

const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * The locked policy of a kiosk without its wipe-capable settings (the closed list of WIPE_CAPABLE_PATHS, §22.4), and
 * the paths left out (second review AN-G1, G1-S1). Module-private on purpose: pushDevicePolicy alone calls it, behind
 * kioskLockPendingUnderFreeze, and checks the result with policyHasWipeSettings (fail closed).
 */
function withoutWipeSettings(body: Record<string, JsonValue>): { body: Record<string, JsonValue>; paths: string[] } {
  const out = structuredClone(body);
  const paths: string[] = [];
  const rules = out.policyEnforcementRules;
  if (Array.isArray(rules) && rules.some((r) => isObject(r) && r.wipeAction !== undefined)) {
    paths.push('policyEnforcementRules[].wipeAction');
    // A rule keeps its blockAction (AMAPI requires one with a wipeAction); a rule left with no action goes.
    const kept = rules.map((r) => {
      if (!isObject(r)) return r;
      const { wipeAction: _w, ...rest } = r;
      return rest;
    }).filter((r) => isObject(r) && r.blockAction !== undefined);
    if (kept.length) out.policyEnforcementRules = kept; else delete out.policyEnforcementRules;
  }
  const pp = out.passwordPolicies;
  if (Array.isArray(pp) && pp.some((r) => isObject(r) && r.maximumFailedPasswordsForWipe !== undefined)) {
    paths.push('passwordPolicies[].maximumFailedPasswordsForWipe');
    out.passwordPolicies = pp.map((r) => {
      if (!isObject(r)) return r;
      const { maximumFailedPasswordsForWipe: _m, ...rest } = r;
      return rest;
    });
  }
  const pr = out.passwordRequirements;
  if (isObject(pr) && pr.maximumFailedPasswordsForWipe !== undefined) {
    paths.push('passwordRequirements.maximumFailedPasswordsForWipe');
    const { maximumFailedPasswordsForWipe: _m, ...rest } = pr;
    out.passwordRequirements = rest;
  }
  for (const k of ['frpAdminEmails', 'setupActions', 'wipeDataFlags'] as const) {
    if (out[k] !== undefined) { paths.push(k); delete out[k]; }
  }
  const pu = out.personalUsagePolicies;
  if (isObject(pu) && pu.privateSpacePolicy === PRIVATE_SPACE_DISALLOWED) {
    paths.push(`personalUsagePolicies.privateSpacePolicy=${PRIVATE_SPACE_DISALLOWED}`);
    const { privateSpacePolicy: _p, ...rest } = pu;
    if (Object.keys(rest).length) out.personalUsagePolicies = rest; else delete out.personalUsagePolicies;
  }
  return { body: out, paths };
}

/**
 * android.policies.push-device for one device (section 9.4). `onboard`: the first push after the enrollment or the
 * approval (devices.patch policyName, and state ACTIVE for a device approved while DISABLED).
 */
export async function pushDevicePolicy(tenantId: number, deviceId: number, o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<PushResult> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, o.actor ?? PUSH_ACTOR, async () => {
    const prep = await db.transaction(async (trx) => {
      const e = await readEnterprise(trx);
      const row = await trx('devices as d').join('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
        .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
        .first('d.id', 'd.uuid', 'd.enrollment_profile_id', 'd.management_mode', 'd.ownership', 'd.usage', 'd.enrollment_state', 'a.amapi_name', 'a.api_level', 'a.approval_state',
          'a.policy_name', 'a.pushed_rendered_hash', 'a.pushed_policy_version', 'a.policy_push_failures', 'a.policy_state_reasons', 'a.state', 'a.released_at') as DeviceRow | undefined;
      if (!row || row.released_at || row.enrollment_state !== 'enrolled') return { kind: 'not_managed' as const };
      if (row.approval_state === 'pending' || row.approval_state === 'rejected') return { kind: 'pending_approval' as const };
      if (!e || e.state !== 'linked') return { kind: 'no_enterprise' as const };
      const enterprise = await readEnterpriseRow(trx);
      const desired = await deviceSource(trx, tenantId, deviceId);
      // Lot AN-D1 (review AN-C1b, R8): a device the operator disabled (mdm.android_disable) is never reactivated by a push.
      const operatorDisabled = !!(await trx('android_device_controls').where({ tenant_id: tenantId, device_id: deviceId }).first('device_id'));
      // Lot AN-G1: the kiosk of a dedicated device.
      let kiosk: { app: string | null; appInCatalog: boolean; exit: boolean } | undefined;
      if (row.usage === 'kiosk') {
        const profile = row.enrollment_profile_id ? await readAndroidProfile(trx, String(row.enrollment_profile_id), tenantId) : null;
        const app = profile?.settings.deviceUsage === 'kiosk' ? profile.settings.kioskApp ?? null : null;
        kiosk = { app, appInCatalog: app ? await kioskAppInCatalog(trx, tenantId, app) : false, exit: !!(await runningKioskExit(trx, tenantId, deviceId)) };
      }
      return { kind: 'ok' as const, e, row, desired, adminDomain: enterprise?.admin_domain ?? null, operatorDisabled, kiosk };
    });
    if (prep.kind !== 'ok') return prep.kind;
    const { e, row, desired } = prep;
    const facts: AndroidDeviceFacts = {
      platform: 'android', mode: row.management_mode, ownership: row.ownership, apiLevel: row.api_level, uuid: String(row.uuid), usage: row.usage,
    };
    let compiled: CompiledAndroidPolicy;
    try {
      compiled = compileAndroid(desired.settings, facts, {
        purpose: 'device', variables: desired.variables,
        privacy: { networkInfo: DEFAULT_PRIVACY[row.ownership as 'corporate' | 'corporate_personal' | 'personal']?.networkInfo ?? false },
        guards: { adminDomain: prep.adminDomain, minFailedPasswordsForWipe: FAILED_PASSWORDS_FOR_WIPE.defaultFloor }, ...(prep.kiosk ? { kiosk: prep.kiosk } : {}),
      });
    } catch (err) {
      await setPolicyError(tenantId, deviceId, [`compile:${err instanceof AndroidCompileError ? err.code : 'invalid_value'}`], false);
      return 'error';
    }
    if (compiled.problems.length) {
      await setPolicyError(tenantId, deviceId, compiled.problems, false);
      return 'error';
    }
    // G1-R1: the exit is ended before the push of the locked policy (never an unlocked policy with a wipe-capable setting).
    if (compiled.kioskExitWithheld) await endKioskExitForWipePolicy(tenantId, deviceId);
    // The lock of a kiosk is on Google's side as compiled: an ended exit's lock is restored (G1-R1).
    const lockHeld = !!compiled.kioskLock && !compiled.kioskExit;
    // G1-S1, G1-S2: the return of the lock is never blocked by the freeze. The lock pending under a freeze and the
    // locked policy carrying a wipe-capable setting: that policy goes without its wipe-capable paths (the only case).
    // Lot AN-F1: the own policy of a personal device (« politique propre au BYOD »): nothing that acts on the whole
    // device, the status reporting of a personal device (the gateway refuses a body that still carries one).
    let body = row.ownership === 'personal' ? byodPolicy(compiled.body).body as Record<string, JsonValue> : compiled.body;
    let wipeWithheld: string[] | null = null;
    if (lockHeld && policyHasWipeSettings(compiled.body) && await kioskLockPendingUnderFreeze(tenantId, deviceId)) {
      const stripped = withoutWipeSettings(compiled.body);
      if (!stripped.paths.length || policyHasWipeSettings(stripped.body)) {
        await setPolicyError(tenantId, deviceId, ['kiosk_wipe_withhold_failed'], false);
        return 'error';
      }
      body = stripped.body;
      wipeWithheld = stripped.paths;
    }
    // The secrets of the tenant, read in the job (never another tenant's: readTenantSecret refuses it).
    const secrets = new Map<string, Buffer>();
    let rendered;
    try {
      for (const ref of compiled.secretRefs) secrets.set(ref, await vault.readTenantSecret(tenantId, ref));
      rendered = renderAndroidPolicy(body, desired.variables, secrets);
    } catch (err) {
      await setPolicyError(tenantId, deviceId, [`render:${err instanceof RenderError ? err.code : 'secret_unavailable'}`], false);
      return 'error';
    } finally {
      for (const b of secrets.values()) b.fill(0);
    }
    // The degraded rendering is checked once more after the rendering (fail closed).
    if (wipeWithheld && policyHasWipeSettings(rendered.policy as Record<string, unknown>)) {
      await setPolicyError(tenantId, deviceId, ['kiosk_wipe_withhold_failed'], false);
      return 'error';
    }
    let lockMarked = 0;
    const lockAccepted = async () => {
      if (lockHeld) lockMarked += await markKioskLockRestored(tenantId, deviceId, wipeWithheld ? { wipeWithheld } : {});
    };
    // Third review AN-G1: a degraded rendering accepted while no pending lock was left to mark (another push of the
    // device, not serialised with this one, restored the lock with the full policy after the unfreeze): nothing
    // records the withheld settings, so the push of the full policy is sent again now (refused while frozen, which
    // then means the other push was degraded too and recorded them).
    const settleDegraded = async () => {
      if (wipeWithheld && !lockMarked) await db.transaction((trx) => androidSenders.push(trx, { tenantId, deviceId }));
    };
    const sameRender = rendered.renderedHash === row.pushed_rendered_hash && row.pushed_policy_version !== null;
    const attach = row.policy_name !== compiled.policyId;
    const activate = row.approval_state === 'approved' && row.state === 'DISABLED' && !prep.operatorDisabled;
    if (sameRender && !attach && !activate) {
      await lockAccepted();
      if (!wipeWithheld) await markKioskWipeSettingsApplied(tenantId, deviceId);
      await settleDegraded();
      return 'unchanged';
    }
    const p = parseOwnedName(e, row.amapi_name);
    if (p.kind !== 'device') throw new Error('android: malformed device name');
    if (!sameRender) {
      // The same rendering refused three times by Google waits for a change of the policy (a new rendering).
      const mark = `rejected:${rendered.renderedHash.slice(0, 16)}`;
      const reasons = Array.isArray(row.policy_state_reasons) ? row.policy_state_reasons : [];
      const sameAsRefused = reasons.includes(mark);
      if (row.policy_push_failures >= MAX_PUSH_FAILURES && sameAsRefused) return 'error';
      let version: string;
      try {
        ({ version } = await gw.putPolicy(e, compiled.policyId, rendered.policy));
      } catch (err) {
        if (err instanceof AndroidError && err.kind === 'request') {
          const field = typeof err.details.field === 'string' ? `:${err.details.field.slice(0, 80)}` : '';
          // The attempts count per rendering: a new rendering starts again at one.
          await db.transaction((trx) => trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({
            policy_state: 'error', policy_state_reasons: JSON.stringify([`amapi_rejected${field}`, mark]),
            policy_push_failures: sameAsRefused ? trx.raw('policy_push_failures + 1') : 1, updated_at: trx.fn.now(),
          }));
          void raiseAndroidTenantAlert(tenantId, 'android.policy_push_failed', { deviceId });
          return 'error';
        }
        throw err;
      }
      await db.transaction((trx) => trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({
        pushed_policy_version: Number(version) || null, pushed_rendered_hash: rendered.renderedHash, pushed_at: trx.fn.now(),
        policy_state: 'delivering', policy_state_reasons: wipeWithheld ? JSON.stringify(['kiosk_wipe_withheld']) : '[]', policy_push_failures: 0,
        updated_at: trx.fn.now(),
      }));
      // The device already holds this policy: its lock is back now (an activation refused under a freeze waits alone).
      if (!attach) await lockAccepted();
    }
    if (attach || activate) {
      const patched = await gw.patchDevice(e, p.deviceId, { policyName: compiled.policyId, ...(activate ? { state: 'ACTIVE' as const } : {}) });
      await db.transaction((trx) => trx('android_devices').where({ tenant_id: tenantId, device_id: deviceId }).update({
        policy_name: compiled.policyId, ...(activate ? { state: typeof patched?.state === 'string' ? patched.state : 'ACTIVE' } : {}), updated_at: trx.fn.now(),
      }));
    }
    await lockAccepted();
    if (!wipeWithheld) await markKioskWipeSettingsApplied(tenantId, deviceId);
    await settleDegraded();
    return 'pushed';
  });
}

/**
 * Why a dedicated device cannot leave its kiosk because of its policy (review AN-G1, G1-R1), null when it can: the
 * device's own policy, compiled with its lock, carries a wipe-capable setting (kiosk_wipe_policy: under a freeze the
 * gateway would refuse the policy that locks it again, AN15), or does not compile (policy_error: fail closed).
 * Called in the caller's transaction, tenant context.
 */
export async function kioskExitPolicyRefusal(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<string | null> {
  const row = await trx('devices as d').join('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
    .first('d.uuid', 'd.enrollment_profile_id', 'd.management_mode', 'd.ownership', 'd.usage', 'a.api_level') as
    { uuid: string; enrollment_profile_id: string | null; management_mode: string; ownership: string; usage: string; api_level: number | null } | undefined;
  if (!row) return 'not_found';
  const desired = await deviceSource(trx, tenantId, deviceId);
  const profile = row.enrollment_profile_id ? await readAndroidProfile(trx, String(row.enrollment_profile_id), tenantId) : null;
  const app = profile?.settings.deviceUsage === 'kiosk' ? profile.settings.kioskApp ?? null : null;
  try {
    const compiled = compileAndroid(desired.settings, {
      platform: 'android', mode: row.management_mode, ownership: row.ownership, apiLevel: row.api_level, uuid: String(row.uuid), usage: row.usage,
    }, {
      purpose: 'device', variables: desired.variables,
      privacy: { networkInfo: DEFAULT_PRIVACY[row.ownership as 'corporate' | 'corporate_personal' | 'personal']?.networkInfo ?? false },
      kiosk: { app, appInCatalog: app ? await kioskAppInCatalog(trx, tenantId, app) : false, exit: false },
    });
    if (compiled.problems.length || !compiled.kioskLock) return 'policy_error';
    return policyHasWipeSettings(compiled.body) ? 'kiosk_wipe_policy' : null;
  } catch {
    return 'policy_error';
  }
}

/** android.policies.enrollment-policy for one profile (sections 9.3, 10.7, §22.3). */
export async function pushEnrollmentPolicy(tenantId: number, profileId: string, o: { gateway?: AndroidGateway; actor?: DbActor } = {}):
  Promise<'pushed' | 'unchanged' | 'error' | 'no_profile' | 'no_enterprise'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, o.actor ?? ENROLLMENT_POLICY_ACTOR, async () => {
    const prep = await db.transaction(async (trx) => {
      const e = await readEnterprise(trx);
      const profile = await readAndroidProfile(trx, profileId, tenantId);
      if (!profile) return { kind: 'no_profile' as const };
      if (!e || e.state !== 'linked') return { kind: 'no_enterprise' as const };
      const snap = snapshotOf(profile);
      const desired = await profileSource(trx, tenantId, { id: profile.id, defaultGroupId: profile.defaultGroupId, mode: snap.mode, ownership: snap.ownership });
      const current = await trx('android_enrollment_policies').where({ profile_id: profile.id }).first('compiled_hash', 'state');
      const app = snap.usage === 'kiosk' ? profile.settings.kioskApp ?? null : null;
      const kiosk = { app, appInCatalog: app ? await kioskAppInCatalog(trx, tenantId, app) : false };
      return { kind: 'ok' as const, e, profile, snap, desired, kiosk, current: current as { compiled_hash: string | null; state: string } | undefined };
    });
    if (prep.kind !== 'ok') return prep.kind;
    const { e, profile, snap, desired } = prep;
    const record = (patch: Record<string, unknown>) => db.transaction((trx) => trx('android_enrollment_policies')
      .insert({ tenant_id: tenantId, profile_id: profile.id, enterprise_id: e.id, policy_id: `e-${profile.id}`, ...patch, updated_at: trx.fn.now() })
      .onConflict(['tenant_id', 'profile_id']).merge({ enterprise_id: e.id, ...patch, updated_at: trx.fn.now() }));
    let compiled: CompiledAndroidPolicy;
    try {
      compiled = compileAndroid(desired.settings, {
        platform: 'android', mode: snap.mode, ownership: snap.ownership, apiLevel: null, uuid: profile.id, usage: snap.usage,
      }, { purpose: 'enrollment', profileUuid: profile.id, variables: desired.variables, privacy: { networkInfo: DEFAULT_PRIVACY[snap.ownership].networkInfo },
        kiosk: prep.kiosk });
    } catch (err) {
      await record({ state: 'error', last_error: err instanceof AndroidCompileError ? err.code : 'invalid_value' });
      return 'error';
    }
    // §22.3: never a $secret reference in an enrollment policy (the compiler defers them; a second barrier here).
    if (compiled.secretRefs.length || compiled.problems.length) {
      await record({ state: 'error', last_error: compiled.secretRefs.length ? 'enrollmentPolicySecret' : compiled.problems[0].slice(0, 64) });
      return 'error';
    }
    if (prep.current?.state === 'pushed' && prep.current.compiled_hash === compiled.hash) return 'unchanged';
    let policy;
    try {
      // Lot AN-F1: the enrollment policy of a BYOD profile follows the rules of a personal device too.
      const body = snap.ownership === 'personal' ? byodPolicy(compiled.body).body as Record<string, JsonValue> : compiled.body;
      ({ policy } = renderAndroidPolicy(body, desired.variables, new Map()));
    } catch (err) {
      await record({ state: 'error', last_error: `render:${err instanceof RenderError ? err.code : 'invalid'}`.slice(0, 64) });
      return 'error';
    }
    try {
      const { version } = await gw.putPolicy(e, compiled.policyId, policy);
      await record({ state: 'pushed', compiled_hash: compiled.hash, pushed_version: Number(version) || 1, pushed_at: new Date(), last_error: null });
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'request') {
        await record({ state: 'error', last_error: 'amapi_rejected' });
        return 'error';
      }
      throw err;
    }
    return 'pushed';
  });
}

/**
 * The provider shape of the channel 'amapi' (§22.6) for registerArtifactChannel (lot AN-P): onDesiredChanged sends the
 * push of each device in the caller's transaction (stately per device: the changes that arrive while a push waits are
 * absorbed by it).
 */
export const amapiChannelProvider = {
  channel: 'amapi' as const,
  async onDesiredChanged(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<void> {
    for (const deviceId of deviceIds) await androidSenders.push(trx, { tenantId, deviceId });
  },
};
