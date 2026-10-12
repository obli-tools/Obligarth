import type { Knex } from 'knex';
import { POLICY_PROFILE_PREFIXES, h16, type JsonValue } from '@obligarth/shared';
import { mdmCommands } from '../../apple/commands/bus';
import type { ResultIngestContext } from '../../apple/commands/results';
import { isFinalTargetState, type TargetFinalContext } from '../../apple/commands/targets';
import { AppError } from '../../middleware/errorHandler';
import {
  REMOVED, hashOf, isCompileError, loadRenderContext, lockDeviceRows, reasonsOf, rollupConfigState, storedArtifactOf, type ArtifactRow,
} from './artifacts';
import { parseProfileRef, profileRefOf } from './profileSource';
import { profileUuid, settingsItem } from './render';
import { requestArtifactReconcile, requestComplianceEvaluation } from './requests';
import { RenderError } from './variables';

// =============================================================================
// Reconciliation of the profiles and settings of a device (docs:
// modele-donnees-mdm §6.3, §7.10): the one creator of the commands of origin
// 'policy'. For each artifact of the channels 'profile' and 'setting':
//   pending    no command waits for the device with this version: InstallProfile
//              (profileRef '<artifact key>@<hash>', resolved by the profile
//              source 'policy') or Settings; the artifact is 'delivering';
//   error      a new attempt 24 hours after the last one, three at most per
//              desired version, then it waits for an intervention;
//   removing   RemoveProfile (an install still waiting is withdrawn first);
//   delivering nothing while its command is open.
// The end of a command comes back through the hook of the final state of its
// target (onPolicyTargetFinal): acknowledged: applied (or removed); error: the
// codes of its ErrorChain; expired, cancelled, refused: pending again.
// Every command carries an idempotency key
// (pol:<device>:<h16(artifact key)>:<h16(version)>:<operation>[:<n>]): a run
// replayed for the same attempt adds nothing. "Last state wins" is the bus's:
// an InstallProfile of the same profile identifier withdraws the one still
// waiting. A command of another origin that already delivers the version (the
// setup plan of an ADE device) is adopted, never doubled.
// Drift (ProfileList): a profile of the policies on the device that is not
// desired is removed; one desired and applied that is absent, or installed
// under another PayloadUUID, is pending again; one being removed that a later
// list no longer shows is removed without a command. The enrollment profile, and
// any profile outside the two prefixes of the policies, is never touched.
// Locks, in this order: the open targets of the device's policy commands, the
// device's row, the rows of its artifacts (artifacts.ts).
// =============================================================================

export const RECONCILE_QUEUE = 'apple.artifacts.reconcile-device';
const ACTOR = `j:${RECONCILE_QUEUE}`;
const POLICY_REQUEST_TYPES = ['InstallProfile', 'RemoveProfile', 'Settings'];
const OPEN_STATES = ['pending', 'queued', 'sent', 'notnow'];
/** Attempts per desired version, then an intervention is needed (section 7.10). */
export const MAX_ATTEMPTS = 3;
/** An artifact in error is tried again this long after its last attempt. */
export const RETRY_AFTER_MS = 24 * 3600_000;
/** Idempotency keys of one version (attempts of every epoch: a drift starts the count again). */
const KEY_SLOTS = 12;
/** Refusals of the bus that tell the device cannot take the artifact at all. */
const NOT_APPLICABLE_REFUSALS = new Set(['not_apple', 'ownership', 'not_supervised']);
/** Errors of a RemoveProfile that tell the profile is not on the device [to confirm on a device, annex B2]. */
const PROFILE_ABSENT_CODES = new Set(['MCProfileErrorDomain:1001']);
/** One ProfileList per device and per window after an installation. */
const PROFILE_LIST_WINDOW_MS = 10 * 60_000;

const isPolicyProfileKey = (key: string): boolean => POLICY_PROFILE_PREFIXES.some((p) => key.startsWith(`profile:${p}`));
const parse = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  if (typeof v !== 'string') return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};

interface LinkedCommand {
  id: string;
  requestType: string;
  params: Record<string, unknown>;
  idempotencyKey: string | null;
  state: string;
  rejectCode: string | null;
  errorChain: unknown;
  completedAt: Date | null;
}

/** A command and its target for the device; null when either is gone. */
async function linkedCommand(trx: Knex.Transaction, tenantId: number, commandId: string, deviceId: number): Promise<LinkedCommand | null> {
  const r = await trx('mdm_command_targets as t')
    .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .where({ 't.tenant_id': tenantId, 't.command_id': commandId, 't.device_id': deviceId })
    .first('c.id', 'c.request_type', 'c.params', 'c.idempotency_key', 't.state', 't.reject_code', 't.error_chain', 't.completed_at') as Record<string, any> | undefined;
  if (!r) return null;
  return {
    id: String(r.id).toLowerCase(), requestType: r.request_type, params: parse<Record<string, unknown>>(r.params, {}) ?? {}, state: r.state,
    idempotencyKey: r.idempotency_key ?? null,
    rejectCode: r.reject_code ?? null, errorChain: parse<unknown>(r.error_chain, null), completedAt: r.completed_at ? new Date(r.completed_at) : null,
  };
}

/** '<ErrorDomain>:<ErrorCode>' of each link of an ErrorChain (bounded, of a plain alphabet): never a description. */
export function errorCodes(chain: unknown): string[] {
  const out: string[] = [];
  for (const e of Array.isArray(chain) ? chain : []) {
    if (!e || typeof e !== 'object') continue;
    const o = e as Record<string, unknown>;
    const domain = o.domain ?? o.ErrorDomain;
    const code = o.code ?? o.ErrorCode;
    if (typeof domain !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(domain) || !(typeof code === 'number' || typeof code === 'string')) continue;
    const text = `${domain}:${String(code).slice(0, 20)}`;
    if (/^[A-Za-z0-9._-]+:-?[A-Za-z0-9]+$/.test(text) && !out.includes(text)) out.push(text);
    if (out.length >= 8) break;
  }
  return out.length ? out : ['error'];
}

/** The artifact a command of the policies delivers or removes, from its parameters; null: not one of theirs. */
export function artifactOfCommand(requestType: string, params: Record<string, unknown>): { key: string; hash: string | null; removal: boolean } | null {
  if (requestType === 'InstallProfile') {
    const ref = params.source === 'policy' && typeof params.profileRef === 'string' ? parseProfileRef(params.profileRef) : null;
    return ref ? { key: ref.artifactKey, hash: ref.hash, removal: false } : null;
  }
  if (requestType === 'RemoveProfile') {
    const key = typeof params.identifier === 'string' ? `profile:${params.identifier}` : '';
    return isPolicyProfileKey(key) ? { key, hash: null, removal: true } : null;
  }
  if (requestType === 'Settings') {
    const m = typeof params.policyRef === 'string' ? /^(setting:[a-z][a-z0-9_]{0,63})@([0-9a-f]{64})$/.exec(params.policyRef) : null;
    return m ? { key: m[1], hash: m[2], removal: false } : null;
  }
  return null;
}

/** What tells a version of an artifact for a device apart in the idempotency key of its commands: its desired hash
 *  and its rendered hash (the value of a variable may change without the body). */
const versionTag = (row: Pick<ArtifactRow, 'desired_hash' | 'rendered_hash'>): string => h16(`${hashOf(row.desired_hash) ?? ''}:${hashOf(row.rendered_hash) ?? ''}`);

/** The version tag in the idempotency key of a command of the reconciliation; null for a command of another origin. */
const tagOfKey = (key: string | null): string | null => /^pol:[0-9]+:[0-9a-f]{16}:([0-9a-f]{16}):(?:install|settings)(?::[0-9]+)?$/.exec(key ?? '')?.[1] ?? null;

/** Does a command deliver the version of the artifact the device wants now? */
function deliversCurrent(row: ArtifactRow, hash: string | null, key: string | null): boolean {
  if (hash !== hashOf(row.desired_hash)) return false;
  const tag = tagOfKey(key);
  return tag === null || tag === versionTag(row);
}

interface Settled { changed: boolean; retry: boolean; installed: boolean }

/** Writes what the end of a command means for its artifact (section 6.3). The row is locked by the caller. */
async function settle(trx: Knex.Transaction, row: ArtifactRow, cmd: LinkedCommand, now: Date): Promise<Settled> {
  const none: Settled = { changed: false, retry: false, installed: false };
  if (!isFinalTargetState(cmd.state)) return none;
  const of = artifactOfCommand(cmd.requestType, cmd.params);
  if (!of || of.key !== row.artifact_key) return none;
  const set = async (update: Record<string, unknown>): Promise<void> => {
    await trx('device_artifacts').where({ tenant_id: row.tenant_id, device_id: row.device_id, artifact_key: row.artifact_key }).update({ ...update, state_at: now });
  };
  const why = [cmd.rejectCode && /^[a-z][a-z0-9_]{0,47}$/.test(cmd.rejectCode) ? cmd.rejectCode : cmd.state];
  if (of.removal) {
    // A removal that ends while the artifact is desired again changes nothing: its installation follows.
    if (row.desired_hash !== null || (row.state !== 'removing' && row.state !== 'error')) return none;
    if (cmd.state === 'acknowledged') { await set({ ...REMOVED }); return { ...none, changed: true }; }
    if (cmd.state === 'error') {
      const codes = errorCodes(cmd.errorChain);
      if (codes.some((c) => PROFILE_ABSENT_CODES.has(c))) await set({ ...REMOVED });
      else await set({ state: 'error', state_reasons: JSON.stringify(codes) });
      return { ...none, changed: true };
    }
    await set({ state: 'removing', state_reasons: JSON.stringify(why) });
    return { changed: true, retry: cmd.state === 'expired', installed: false };
  }
  // An installation. No longer desired: the removal deals with whatever reached the device.
  if (row.desired_hash === null) return none;
  if (!deliversCurrent(row, of.hash, cmd.idempotencyKey)) {
    // The command of an older version: the desired one is still to deliver.
    if (row.state !== 'delivering') return none;
    await set({ state: 'pending', state_reasons: '[]' });
    return { changed: true, retry: true, installed: false };
  }
  if (cmd.state === 'acknowledged') {
    await set({ state: 'applied', state_reasons: '[]', delivered_hash: hashOf(row.rendered_hash) ?? hashOf(row.desired_hash), delivered_at: cmd.completedAt ?? now });
    return { changed: true, retry: false, installed: true };
  }
  if (cmd.state === 'error') {
    await set({ state: 'error', state_reasons: JSON.stringify(errorCodes(cmd.errorChain)) });
    return { ...none, changed: true };
  }
  await set({ state: 'pending', state_reasons: JSON.stringify(why) });
  return { changed: true, retry: cmd.state === 'expired', installed: false };
}

/** A ProfileList of the device after an installation, one per window (the drift is read from it). Never fails the caller. */
async function requestProfileList(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<void> {
  try {
    await mdmCommands.enqueue(trx, {
      tenantId, requestType: 'ProfileList', deviceIds: [deviceId], origin: 'policy', actor: ACTOR,
      idempotencyKey: `pol:${deviceId}:profilelist:${Math.floor(Date.now() / PROFILE_LIST_WINDOW_MS)}`,
    });
  } catch (err) {
    if (!(err instanceof AppError)) throw err;
  }
}

/**
 * onPolicyTargetFinal(ctx): the hook of the final state of a target (integration §7.6), in the transaction that
 * wrote it. The artifact is the one whose last command this is, or, for a command another origin created (a setup
 * plan), the one its parameters name.
 */
export async function onPolicyTargetFinal(ctx: TargetFinalContext): Promise<void> {
  if (!POLICY_REQUEST_TYPES.includes(ctx.requestType)) return;
  const { trx, tenantId, deviceId } = ctx;
  const commandId = ctx.commandId.toLowerCase();
  let key = (await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, last_command_id: commandId })
    .first('artifact_key') as { artifact_key: string } | undefined)?.artifact_key ?? null;
  let cmd: LinkedCommand | null = null;
  if (key === null) {
    cmd = await linkedCommand(trx, tenantId, commandId, deviceId);
    const of = cmd ? artifactOfCommand(cmd.requestType, cmd.params) : null;
    if (!of) return;
    const known = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: of.key }).first('artifact_key');
    if (!known) return;
    key = of.key;
  }
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const row = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: key }).forUpdate().first('*') as ArtifactRow | undefined;
  if (!row) return;
  // Another command is the artifact's last one: this one was superseded, its end says nothing of the artifact.
  if (row.last_command_id && String(row.last_command_id).toLowerCase() !== commandId) return;
  cmd = cmd ?? await linkedCommand(trx, tenantId, commandId, deviceId);
  if (!cmd) return;
  const r = await settle(trx, row, cmd, new Date());
  if (!r.changed) return;
  await rollupConfigState(trx, [deviceId]);
  await requestComplianceEvaluation(trx, tenantId, [deviceId]);
  if (r.retry) await requestArtifactReconcile(trx, tenantId, [deviceId]);
  if (r.installed && cmd.requestType === 'InstallProfile') await requestProfileList(trx, tenantId, deviceId);
}

/**
 * The ingestor of the result of a Settings command (inline): the device answers a status per item under the key
 * Settings [form to confirm on a device, annex B1]. An item in error puts the artifact the command delivered in
 * error, although the command itself was acknowledged.
 */
export async function ingestSettingsResult(c: ResultIngestContext): Promise<void> {
  if (c.status !== 'Acknowledged') return;
  const failed = (Array.isArray(c.result.Settings) ? c.result.Settings : [])
    .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && typeof (x as Record<string, unknown>).Status === 'string'
      && (x as Record<string, unknown>).Status !== 'Acknowledged');
  if (failed.length === 0) return;
  const { trx, tenantId, deviceId } = c;
  const commandId = c.commandId.toLowerCase();
  const any = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, channel: 'setting', last_command_id: commandId }).first('artifact_key');
  if (!any) return;
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const codes = [...new Set(failed.flatMap((f) => errorCodes(f.ErrorChain)))].slice(0, 8);
  const n = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, channel: 'setting', last_command_id: commandId })
    .whereNotNull('desired_hash')
    // The hook of the acknowledgement held it as applied: nothing of it is on the device.
    .update({ state: 'error', state_reasons: JSON.stringify(codes), state_at: new Date(), delivered_hash: null, delivered_at: null });
  if (!n) return;
  await rollupConfigState(trx, [deviceId]);
  await requestComplianceEvaluation(trx, tenantId, [deviceId]);
}

// ── The reconciliation of one device ───────────────────────────────────────────

export interface ReconcileOutcome {
  outcome: 'not_managed' | 'done';
  installs: number;
  removals: number;
  adopted: number;
  waiting: number;
  changed: boolean;
}

interface Run {
  trx: Knex.Transaction;
  tenantId: number;
  deviceId: number;
  actor: string;
  now: Date;
  out: ReconcileOutcome;
  /** The profiles of the policies the last ProfileList showed on the device, and when; null: no list yet. */
  listed: { at: number; keys: Set<string> } | null;
}

async function setRow(x: Run, row: ArtifactRow, update: Record<string, unknown>): Promise<void> {
  await x.trx('device_artifacts').where({ tenant_id: x.tenantId, device_id: x.deviceId, artifact_key: row.artifact_key }).update({ ...update, state_at: x.now });
  x.out.changed = true;
}

/** The idempotency keys of the attempts of one version: the first free one, and how many were used since `since`. */
async function attemptsOf(x: Run, prefix: string, since: Date): Promise<{ free: string | null; recent: number }> {
  const keys = Array.from({ length: KEY_SLOTS }, (_, i) => (i === 0 ? prefix : `${prefix}:${i + 1}`));
  const used = await x.trx('mdm_commands').where({ tenant_id: x.tenantId }).whereIn('idempotency_key', keys).select('idempotency_key', 'created_at') as
    Array<{ idempotency_key: string; created_at: Date }>;
  const taken = new Set(used.map((u) => u.idempotency_key));
  return {
    free: keys.find((k) => !taken.has(k)) ?? null,
    recent: used.filter((u) => new Date(u.created_at).getTime() >= since.getTime()).length,
  };
}

/** An open command of the device that already delivers this version of the artifact, whatever its origin. */
async function openDelivery(x: Run, row: ArtifactRow, ref: string): Promise<string | null> {
  const q = x.trx('mdm_command_targets as t')
    .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .where({ 't.tenant_id': x.tenantId, 't.device_id': x.deviceId, 'c.request_type': row.channel === 'profile' ? 'InstallProfile' : 'Settings' })
    .whereIn('t.state', OPEN_STATES);
  if (row.channel === 'profile') q.whereRaw("c.params->>'profileRef' = ?", [ref]);
  else q.whereRaw("c.params->>'policyRef' = ?", [ref]);
  const r = await q.orderBy('c.created_at', 'desc').select('c.id', 'c.idempotency_key') as Array<{ id: string; idempotency_key: string | null }>;
  const hit = r.find((c) => deliversCurrent(row, hashOf(row.desired_hash), c.idempotency_key));
  return hit ? String(hit.id).toLowerCase() : null;
}

/** What the bus answered for the one device of a request. */
async function enqueue(x: Run, requestType: string, params: Record<string, unknown>, idempotencyKey: string):
  Promise<{ commandId: string } | { refused: string } | { failed: string }> {
  try {
    const o = await mdmCommands.enqueue(x.trx, { tenantId: x.tenantId, requestType, deviceIds: [x.deviceId], params, origin: 'policy', actor: x.actor, idempotencyKey });
    if (o.commandIds[0]) return { commandId: o.commandIds[0].toLowerCase() };
    return { refused: o.refused[0]?.code ?? 'refused' };
  } catch (err) {
    // A refusal of the request itself (a version no longer desired, a profile that cannot be rendered, a secret the
    // scanner found in clear): codes only. Anything else fails the job, which is retried.
    if (!(err instanceof AppError) || err.statusCode >= 500) throw err;
    const reason = (err.details as { reason?: unknown } | undefined)?.reason;
    return { failed: err.code === 'profileRenderFailed' && typeof reason === 'string' ? `render:${reason}` : `command:${String(err.code ?? 'refused').slice(0, 60)}` };
  }
}

async function install(x: Run, row: ArtifactRow): Promise<void> {
  const desired = hashOf(row.desired_hash) as string;
  const ref = profileRefOf(row.artifact_key, desired);
  const adopted = await openDelivery(x, row, ref);
  if (adopted) {
    await setRow(x, row, { state: 'delivering', state_reasons: '[]', last_command_id: adopted });
    x.out.adopted++;
    return;
  }
  const op = row.channel === 'profile' ? 'install' : 'settings';
  const attempts = await attemptsOf(x, `pol:${x.deviceId}:${h16(row.artifact_key)}:${versionTag(row)}:${op}`, new Date(row.desired_at));
  if (attempts.recent >= MAX_ATTEMPTS || attempts.free === null) {
    if (row.state !== 'error') await setRow(x, row, { state: 'error', state_reasons: JSON.stringify(['attempts_exhausted']) });
    return;
  }
  if (row.state === 'error' && x.now.getTime() - new Date(row.state_at).getTime() < RETRY_AFTER_MS) return;

  let params: Record<string, unknown>;
  if (row.channel === 'profile') {
    params = { source: 'policy', profileRef: ref };
  } else {
    const body = await x.trx('mdm_artifacts').where({ tenant_id: x.tenantId, hash: desired })
      .first('channel', 'artifact_type', 'identifier', 'body', 'encrypt') as
      { channel: string; artifact_type: string; identifier: string; body: unknown; encrypt: boolean } | undefined;
    const render = body ? await loadRenderContext(x.trx, x.tenantId, x.deviceId) : null;
    if (!body || !render) return;
    let item: { item: string; values: Record<string, JsonValue> };
    try {
      item = settingsItem(storedArtifactOf(body), render.vars);
    } catch (err) {
      if (!(err instanceof RenderError)) throw err;
      await setRow(x, row, { state: 'error', state_reasons: JSON.stringify([`render:${err.code}`]) });
      return;
    }
    params = { items: [item], policyRef: ref };
  }
  const r = await enqueue(x, row.channel === 'profile' ? 'InstallProfile' : 'Settings', params, attempts.free);
  if ('commandId' in r) {
    await setRow(x, row, { state: 'delivering', state_reasons: '[]', last_command_id: r.commandId });
    x.out.installs++;
  } else if ('failed' in r) {
    // The version moved on meanwhile: the resolution that changed it asked for another run.
    if (r.failed === 'command:staleProfileRef') return;
    await setRow(x, row, { state: 'error', state_reasons: JSON.stringify([r.failed]) });
  } else if (NOT_APPLICABLE_REFUSALS.has(r.refused)) {
    await setRow(x, row, { state: 'not_applicable', state_reasons: JSON.stringify([r.refused]) });
  } else if (row.state !== 'pending' || reasonsOf(row).join('|') !== r.refused) {
    // identity_unavailable, not_enrolled…: tried again at the next run.
    await setRow(x, row, { state: 'pending', state_reasons: JSON.stringify([r.refused]) });
    x.out.waiting++;
  }
}

async function remove(x: Run, row: ArtifactRow, linked: LinkedCommand | null): Promise<void> {
  if (row.channel !== 'profile' || !isPolicyProfileKey(row.artifact_key)) {
    // Nothing unsets a setting: it is simply no longer managed.
    await setRow(x, row, { ...REMOVED });
    return;
  }
  if (linked && OPEN_STATES.includes(linked.state)) {
    if (linked.requestType === 'RemoveProfile') return;  // its removal waits for the device
    // An installation still waiting is withdrawn; one that never left the brain installed nothing.
    await mdmCommands.cancel(x.trx, x.tenantId, linked.id, [x.deviceId], x.actor, { silent: true });
    if (linked.state === 'pending' && row.delivered_hash === null) {
      await setRow(x, row, { ...REMOVED });
      return;
    }
  } else if (x.listed && !x.listed.keys.has(row.artifact_key) && x.listed.at > new Date(row.state_at).getTime()) {
    // A ProfileList later than the request of the removal no longer shows it (and no installation may still land).
    await setRow(x, row, { ...REMOVED });
    return;
  }
  if (row.state === 'error' && x.now.getTime() - new Date(row.state_at).getTime() < RETRY_AFTER_MS) return;
  const prefix = `pol:${x.deviceId}:${h16(row.artifact_key)}:remove:${h16(hashOf(row.delivered_hash) ?? 'none')}`;
  const attempts = await attemptsOf(x, prefix, new Date(row.state_at));
  if (attempts.recent >= MAX_ATTEMPTS || attempts.free === null) {
    if (row.state !== 'error') await setRow(x, row, { state: 'error', state_reasons: JSON.stringify(['attempts_exhausted']) });
    return;
  }
  const r = await enqueue(x, 'RemoveProfile', { identifier: row.artifact_key.slice('profile:'.length) }, attempts.free);
  if ('commandId' in r) {
    await x.trx('device_artifacts').where({ tenant_id: x.tenantId, device_id: x.deviceId, artifact_key: row.artifact_key })
      .update({ state: 'removing', state_reasons: '[]', last_command_id: r.commandId });
    x.out.changed = true;
    x.out.removals++;
  } else {
    const why = 'failed' in r ? r.failed : r.refused;
    if (reasonsOf(row).join('|') !== why) {
      await x.trx('device_artifacts').where({ tenant_id: x.tenantId, device_id: x.deviceId, artifact_key: row.artifact_key })
        .update({ state_reasons: JSON.stringify([why]) });
    }
    x.out.waiting++;
  }
}

/** The drift a ProfileList shows (section 7.10): profiles of the policies only. */
async function applyDrift(x: Run): Promise<void> {
  const sat = await x.trx('apple_devices').where({ tenant_id: x.tenantId, device_id: x.deviceId }).first('last_profiles_at') as
    { last_profiles_at: Date | null } | undefined;
  if (!sat?.last_profiles_at) return;
  const listAt = new Date(sat.last_profiles_at).getTime();
  const installed = new Map<string, string | null>((await x.trx('apple_device_profiles').where({ tenant_id: x.tenantId, device_id: x.deviceId }).whereNotNull('artifact_key')
    .select('artifact_key', 'payload_uuid') as Array<{ artifact_key: string; payload_uuid: string | null }>)
    .filter((p) => isPolicyProfileKey(p.artifact_key)).map((p): [string, string | null] => [p.artifact_key, p.payload_uuid]));
  x.listed = { at: listAt, keys: new Set(installed.keys()) };
  const rows = await x.trx('device_artifacts').where({ tenant_id: x.tenantId, device_id: x.deviceId, channel: 'profile' })
    .orderBy('artifact_key').forUpdate().select('*') as ArtifactRow[];
  const known = new Map(rows.map((r) => [r.artifact_key, r]));
  for (const key of installed.keys()) {
    const row = known.get(key);
    if (!row) {
      // On the device, wanted by nothing: removed.
      await x.trx('device_artifacts').insert({ tenant_id: x.tenantId, device_id: x.deviceId, artifact_key: key, channel: 'profile', desired_hash: null,
        state: 'removing', state_reasons: JSON.stringify(['drift']), state_at: x.now }).onConflict(['tenant_id', 'device_id', 'artifact_key']).ignore();
      x.out.changed = true;
    } else if (row.state === 'removed' && listAt > new Date(row.state_at).getTime()) {
      await setRow(x, row, { state: 'removing', state_reasons: JSON.stringify(['drift']), last_command_id: null });
    }
  }
  for (const row of rows) {
    const onDevice = installed.has(row.artifact_key);
    if (row.desired_hash !== null && row.state === 'applied' && row.delivered_at && listAt > new Date(row.delivered_at).getTime()) {
      const uuid = installed.get(row.artifact_key);
      const delivered = hashOf(row.delivered_hash);
      const reason = !onDevice ? 'drift_absent'
        : uuid && delivered && uuid.toUpperCase() !== profileUuid(delivered) ? 'drift_changed' : null;
      if (reason) await setRow(x, row, { state: 'pending', state_reasons: JSON.stringify([reason]), desired_at: x.now });
    }
  }
}

/**
 * reconcileDevice(trx, tenantId, deviceId): one pass over the profiles and settings of a device (section 7.10), in
 * the tenant's context. No network: the bus writes the commands, their submission is its job's.
 */
export async function reconcileDevice(trx: Knex.Transaction, tenantId: number, deviceId: number, actor = ACTOR, now = new Date()): Promise<ReconcileOutcome> {
  const x: Run = { trx, tenantId, deviceId, actor, now, listed: null, out: { outcome: 'done', installs: 0, removals: 0, adopted: 0, waiting: 0, changed: false } };
  await trx.raw(`
    SELECT t.command_id
      FROM obligarth.mdm_command_targets t
      JOIN obligarth.mdm_commands c ON c.id = t.command_id AND c.tenant_id = t.tenant_id
     WHERE t.tenant_id = ? AND t.device_id = ? AND t.state = ANY (?::text[]) AND c.request_type = ANY (?::text[])
     ORDER BY t.command_id
       FOR UPDATE OF t`, [tenantId, deviceId, OPEN_STATES, POLICY_REQUEST_TYPES]);
  const [device] = await lockDeviceRows(trx, tenantId, [deviceId]);
  if (!device || (device.enrollment_state !== 'enrolled' && device.enrollment_state !== 'awaiting_configuration')) return { ...x.out, outcome: 'not_managed' };
  await applyDrift(x);
  const rows = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('channel', ['profile', 'setting'])
    .whereIn('state', ['pending', 'delivering', 'error', 'removing']).orderBy('artifact_key').forUpdate().select('*') as ArtifactRow[];
  for (let row of rows) {
    if (isCompileError(row)) continue;
    let linked = row.last_command_id ? await linkedCommand(trx, tenantId, String(row.last_command_id), deviceId) : null;
    if (row.state === 'delivering') {
      if (linked && OPEN_STATES.includes(linked.state)) continue;
      // Its command ended without its hook (a target closed by a direct statement), or is gone (purged).
      if (linked && (await settle(trx, row, linked, now)).changed) x.out.changed = true;
      else await setRow(x, row, { state: row.desired_hash === null ? 'removing' : 'pending', state_reasons: '[]' });
      row = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: row.artifact_key }).first('*') as ArtifactRow;
      linked = null;
      if (!row || (row.state !== 'pending' && row.state !== 'error' && row.state !== 'removing')) continue;
    }
    if (row.desired_hash === null) await remove(x, row, linked);
    else if (row.state === 'pending' || row.state === 'error') await install(x, row);
  }
  if (x.out.changed) {
    await rollupConfigState(trx, [deviceId]);
    await requestComplianceEvaluation(trx, tenantId, [deviceId]);
  }
  return x.out;
}

/** The devices of a tenant whose artifacts wait without anything moving them: asked again by the daily sweep
 *  (an error to try again after 24 hours, a refusal of the bus that may have lifted). */
export async function stuckDevices(q: Knex | Knex.Transaction, tenantId: number, limit: number): Promise<number[]> {
  const rows = await q('device_artifacts').where({ tenant_id: tenantId }).whereIn('channel', ['profile', 'setting'])
    .whereIn('state', ['pending', 'error', 'removing', 'delivering']).whereRaw("state_at < now() - interval '1 hour'")
    .distinct('device_id').orderBy('device_id').limit(limit) as Array<{ device_id: number }>;
  return rows.map((r) => Number(r.device_id));
}
