import type { JsonValue } from '@obligarth/shared';
import type { SetupCommand, SetupContributor } from '../../apple/commands/setup';
import { resolveDeviceInTx } from '../policies/jobs';
import { hashOf, isCompileError, loadRenderContext, storedArtifactOf, type ArtifactRow } from './artifacts';
import { profileRefOf } from './profileSource';
import { settingsItem } from './render';
import { RenderError } from './variables';

// =============================================================================
// The contributor of the policies to the setup plan of an ADE device (docs:
// modele-donnees-mdm §7.10; integration-apple-edge §8.9): the profiles and the
// settings its policies want are installed before DeviceConfigured, so that
// the device leaves the setup assistant already configured. The device is
// resolved here, in the plan's transaction (its first resolution may not have
// run yet), then one InstallProfile or Settings per artifact still to deliver
// is handed to the plan, which enqueues them (origin 'setup'). The
// reconciliation that follows the resolution adopts these commands instead of
// sending its own; their end comes back through the same hook. The
// declarations follow by the first DDM synchronisation.
// =============================================================================

export const policiesSetupContributor: SetupContributor = {
  name: 'policies',
  async contribute(trx, c): Promise<SetupCommand[]> {
    await resolveDeviceInTx(trx, c.tenantId, [c.deviceId]);
    const rows = await trx('device_artifacts').where({ tenant_id: c.tenantId, device_id: c.deviceId, state: 'pending' })
      .whereIn('channel', ['profile', 'setting']).whereNotNull('desired_hash').orderBy('artifact_key').select('*') as ArtifactRow[];
    const out: SetupCommand[] = [];
    let vars: Awaited<ReturnType<typeof loadRenderContext>> | undefined;
    for (const row of rows) {
      if (isCompileError(row)) continue;
      const hash = hashOf(row.desired_hash) as string;
      const ref = profileRefOf(row.artifact_key, hash);
      if (row.channel === 'profile') {
        out.push({ requestType: 'InstallProfile', params: { source: 'policy', profileRef: ref } });
        continue;
      }
      const body = await trx('mdm_artifacts').where({ tenant_id: c.tenantId, hash })
        .first('channel', 'artifact_type', 'identifier', 'body', 'encrypt') as
        { channel: string; artifact_type: string; identifier: string; body: unknown; encrypt: boolean } | undefined;
      vars = vars ?? await loadRenderContext(trx, c.tenantId, c.deviceId);
      if (!body || !vars) continue;
      let item: { item: string; values: Record<string, JsonValue> };
      try {
        item = settingsItem(storedArtifactOf(body), vars.vars);
      } catch (err) {
        if (!(err instanceof RenderError)) throw err;
        continue;                                       // the reconciliation records why
      }
      out.push({ requestType: 'Settings', params: { items: [item], policyRef: ref } });
    }
    return out;
  },
};
