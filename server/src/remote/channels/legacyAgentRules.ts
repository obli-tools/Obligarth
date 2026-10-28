import type { Knex } from 'knex';
import { REMOTE_LEGACY_INJECT_ITEM, REMOTE_LIMITS, type RemoteMode } from '@obligarth/shared';
import type { RemoteChannelSession, RemoteDeviceFacts, RemoteEligibility } from '../channels';

// =============================================================================
// The rules of the channel legacy_agent of the remote assistance (P0-15 §4.1, §4.3, §8, D4), without the queue: the
// eligibility of a device (read in the caller's transaction), the version of the agent, the params of remote.open.
// channels/legacyAgent.ts registers them; the unit tests load this file alone.
// =============================================================================

/** a.b.c ≥ min.b.c (numeric parts; a missing part counts 0, a non numeric name never passes). */
export function versionAtLeast(name: string | null | undefined, min: string): boolean {
  if (typeof name !== 'string' || !/^\d+(\.\d+){0,3}([-+].*)?$/.test(name.trim())) return false;
  const a = name.trim().split(/[-+]/)[0].split('.').map(Number);
  const b = min.split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return true;
}

const jsonOf = (v: unknown): unknown => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };

/** The params of remote.open (§4.3): filled by the server (the technician and the organisation told by the
 *  notifications of the device, §0.1 rule 2), never typed by the operator but the reason, absent when none was given
 *  (§0.1 rule 3); no secret. */
export function remoteOpenParams(s: RemoteChannelSession): Record<string, unknown> {
  return {
    sessionId: s.id, mode: s.mode, operator: s.requestedByName.slice(0, 80), operatorOrg: s.operatorOrg.slice(0, 120),
    controllerName: s.controllerName.slice(0, 200), ...(s.reason ? { reason: s.reason } : {}), maxMinutes: s.maxMinutes,
  };
}

/** The name of a versionCode of the bridge agent (major × 10000 + minor × 100 + patch, agent-android/app/build.gradle.kts). */
export function agentVersionNameOf(code: number): string {
  const c = Math.max(0, Math.floor(Number(code) || 0));
  return `${Math.floor(c / 10000)}.${Math.floor(c / 100) % 100}.${c % 100}`;
}

/** The eligibility of a device of the bridge agent (see channels/legacyAgent.ts). The version is the versionCode the
 *  last interrogation announced (legacy_agent_devices.agent_version_code): the name is the enrollment's, which an
 *  agent.update never changes (a 1.0.x enrolled then updated to 1.1.0 would stay agentTooOld). */
export async function legacyAgentEligible(trx: Knex.Transaction, tenantId: number, device: RemoteDeviceFacts, mode: RemoteMode): Promise<RemoteEligibility> {
  const a = await trx('legacy_agent_devices').where({ tenant_id: tenantId, device_id: device.deviceId })
    .first('agent_version_code', 'api_level', 'knox_state', 'revoked_at') as
    { agent_version_code: number; api_level: number | null; knox_state: string; revoked_at: Date | null } | undefined;
  if (!a) return { ok: false, reason: 'platformUnsupported' };
  if (a.revoked_at) return { ok: false, reason: 'revoked' };
  if (!(Number(a.agent_version_code) >= REMOTE_LIMITS.minAgentVersionCode)) {
    return { ok: false, reason: 'agentTooOld', details: { minAgentVersion: REMOTE_LIMITS.minAgentVersion, agentVersion: agentVersionNameOf(a.agent_version_code) } };
  }
  if (mode === 'control') {
    if (a.api_level !== null && Number(a.api_level) > REMOTE_LIMITS.controlMaxApiLevel) return { ok: false, reason: 'platformUnsupported' };
    const item = await trx('device_status_items').where({ tenant_id: tenantId, device_id: device.deviceId, item: REMOTE_LEGACY_INJECT_ITEM })
      .first('value') as { value: unknown } | undefined;
    if (jsonOf(item?.value) !== true) return { ok: false, reason: a.knox_state === 'licensed' ? 'injectUnavailable' : 'knoxRequired' };
  }
  return { ok: true };
}
