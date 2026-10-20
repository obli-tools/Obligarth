// The provider of the channel amapi in the common artifact store (android-amapi §9.1, §22.6; COH-2, lot AN-P): each
// Android device under the channel amapi wants one artifact, amapi:policy (identifier 'policy'), its own policy
// d-<device uuid>. The store holds its desired version: the body is the list of the android:* settings the resolution
// retained for the device (key, value hash, removal, availability, source; never a value), its hash the address of
// mdm_artifacts. The policy itself is compiled, rendered (variables, secrets) and pushed by android.policies.push-device
// (push.ts), which the provider sends in the resolution's transaction when the desired version changes (stately per
// device: the changes that arrive while a push waits are absorbed by it).
// The state of the push lives in android_devices (policy_state, pushed version); syncPolicyArtifact mirrors it on the
// artifact (pending, delivering, applied, error) for the version it served only, then the aggregate state of the
// device (devices.config_state) is computed again like any other writer of device_artifacts.
// No network, no I/O in compile.
import { createHash } from 'node:crypto';
import type { Knex } from 'knex';
import { ANDROID_SETTING_PREFIX } from '@obligarth/shared';
import { canonicalJson } from '../../audit/canonical';
import { lockDeviceRows, rollupConfigState, type ArtifactChannelProvider, type ChannelArtifact } from '../../mdm/policies/artifacts';
import type { ResolvedSetting } from '../../mdm/policies/resolver';
import { androidSenders } from '../enrollment/senders';

export const AMAPI_POLICY_KEY = 'amapi:policy';

/** The line of a setting in the body of amapi:policy (what changes the compiled policy; never its value). */
function lineOf(s: ResolvedSetting): Record<string, unknown> {
  const a = s.availability as { status: string; reason?: string };
  return {
    key: s.settingKey, hash: s.valueHash ?? null, removed: s.removed === true,
    availability: a.status, ...(a.reason ? { reason: a.reason } : {}),
    // The compiler orders the conflicting preferred activities by the order of the resolution (rank, priority, resource).
    source: { type: s.source.type, id: s.source.id, tenantId: s.source.tenantId, assignmentId: s.source.assignmentId, rank: s.source.rank,
      priority: (s.source as { priority?: number }).priority ?? null },
  };
}

/** The artifact amapi:policy of a device from its android:* settings. */
export function amapiPolicyArtifact(settings: ResolvedSetting[]): ChannelArtifact {
  const lines = settings.filter((s) => s.settingKey.startsWith(ANDROID_SETTING_PREFIX))
    .sort((x, y) => (x.settingKey < y.settingKey ? -1 : x.settingKey > y.settingKey ? 1 : 0)).map(lineOf);
  const body = { settings: lines } as unknown as ChannelArtifact['body'];
  const hash = createHash('sha256').update(canonicalJson({ channel: 'amapi', identifier: 'policy', body })).digest('hex');
  return {
    artifactKey: AMAPI_POLICY_KEY, channel: 'amapi', artifactType: 'android.policy', identifier: 'policy', body, hash,
    secretRefs: [], hasVariables: false, encrypt: false, sources: lines.map((l) => String(l.key)), rendered: hash, problems: [],
  };
}

/** The provider of the channel amapi (registered by registerAndroidModule, whatever ANDROID_MODE: the push sender is a
 *  no-op while it is off). */
export const amapiArtifactProvider: ArtifactChannelProvider = {
  name: 'amapi',
  channels: ['amapi'],
  claimsSetting: (key) => key.startsWith(ANDROID_SETTING_PREFIX),
  servesDevice: (d) => d.channel === 'amapi',
  compile(devices) {
    return new Map(devices.map(({ device, settings }) => [device.id, [amapiPolicyArtifact(settings)]]));
  },
  async onDesiredChanged(trx, tenantId, deviceIds) {
    for (const deviceId of deviceIds) await androidSenders.push(trx, { tenantId, deviceId });
  },
};

/** The desired hash of the device's amapi:policy (null: none written yet). */
export async function policyArtifactHash(q: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<string | null> {
  const r = await q('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: AMAPI_POLICY_KEY })
    .first('desired_hash') as { desired_hash: string | null } | undefined;
  return r?.desired_hash ? String(r.desired_hash).trim() : null;
}

/**
 * The state of the push of the device's policy (android_devices.policy_state) on its artifact amapi:policy, then the
 * aggregate state of the device. `desiredHash`: only while the artifact still wants that version (the push served
 * it); `delivered`: only when the version desired was the one pushed (a status report). In the caller's transaction
 * (tenant context); the device's row is locked first, as every writer of device_artifacts does. Returns whether the
 * artifact changed.
 */
export async function syncPolicyArtifact(trx: Knex.Transaction, tenantId: number, deviceId: number,
  o: { desiredHash?: string; delivered?: boolean }): Promise<boolean> {
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const r = await trx.raw(`
    UPDATE obligarth.device_artifacts x
       SET state = a.policy_state, state_reasons = a.policy_state_reasons, state_at = now(),
           delivered_hash = CASE WHEN a.policy_state IN ('delivering', 'applied') THEN x.desired_hash ELSE x.delivered_hash END,
           delivered_at = CASE WHEN a.policy_state IN ('delivering', 'applied') AND x.delivered_hash IS DISTINCT FROM x.desired_hash
                               THEN now() ELSE x.delivered_at END
      FROM obligarth.android_devices a
     WHERE a.tenant_id = x.tenant_id AND a.device_id = x.device_id
       AND x.tenant_id = ? AND x.device_id = ? AND x.artifact_key = ? AND x.desired_hash IS NOT NULL
       AND (?::text IS NULL OR x.desired_hash = ?::text)
       AND (NOT ?::boolean OR x.delivered_hash = x.desired_hash)
       AND (x.state IS DISTINCT FROM a.policy_state OR x.state_reasons IS DISTINCT FROM a.policy_state_reasons
            OR (a.policy_state IN ('delivering', 'applied') AND x.delivered_hash IS DISTINCT FROM x.desired_hash))`,
  [tenantId, deviceId, AMAPI_POLICY_KEY, o.desiredHash ?? null, o.desiredHash ?? null, o.delivered === true]) as { rowCount?: number };
  const changed = Number(r.rowCount ?? 0) > 0;
  if (changed) await rollupConfigState(trx, [deviceId]);
  return changed;
}

/** Is the device still to onboard (enrolled under the channel amapi, not attached to its own policy yet)? Its push job
 *  then runs the onboarding steps of the channel first (registry by channel, lot AN-P). Tenant context of the caller. */
export async function awaitsOnboarding(q: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<boolean> {
  const r = await q('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.device_id': deviceId, 'd.enrollment_state': 'enrolled', 'd.management_channel': 'amapi' })
    .whereNull('a.released_at').whereNull('a.policy_name').first('a.device_id');
  return !!r;
}
