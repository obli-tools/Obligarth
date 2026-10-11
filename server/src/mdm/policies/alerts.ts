import type { Knex } from 'knex';
import { h16 } from '@obligarth/shared';
import { raiseInTx, resolveInTx } from '../../apple/alerts/service';

// =============================================================================
// Alert of a conflict at run time (docs: modele-donnees-mdm §7.7): a conflict
// that reached the effective state (a write that bypassed the API: a
// restoration, a script; dynamic groups and the library in v1) is broken by
// the resolution, stored with the key, and signalled to the tenant by the
// alert policy.conflict of the integration's catalogue, deduplicated by
// (winning resource, setting key). The resolution of the tenant resolves the
// alerts whose conflict is gone. Identifiers only in the alert (a policy, a
// setting key), never a value.
// =============================================================================

const MAX_RAISED = 100;

const discriminantOf = (type: string, id: number, settingKey: string): string => `${type === 'app' ? 'a' : 'p'}${id}-${h16(settingKey)}`;

/** Raises the alerts of the conflicts stored for the devices (all of the tenant when `deviceIds` is null) and, for
 *  the whole tenant, resolves those whose conflict is gone. In the tenant's transaction. */
export async function syncConflictAlerts(trx: Knex.Transaction, tenantId: number, deviceIds: number[] | null): Promise<{ raised: number; resolved: number }> {
  const q = trx('device_effective_settings').where({ tenant_id: tenantId }).whereNotNull('conflict')
    .distinct('source_type', 'source_id', 'setting_key');
  if (deviceIds) q.whereIn('device_id', deviceIds);
  const present = await q as Array<{ source_type: string; source_id: number; setting_key: string }>;
  const keep = new Set<string>();
  let raised = 0;
  for (const c of present) {
    const d = discriminantOf(c.source_type, Number(c.source_id), c.setting_key);
    keep.add(`apple:policy.conflict:${d}`);
    if (raised >= MAX_RAISED) continue;
    const r = await raiseInTx(trx, tenantId, 'policy.conflict', {
      discriminant: d, params: { policyId: Number(c.source_id), settingKey: c.setting_key.slice(0, 200) },
    });
    if (r.created) raised++;
  }
  let resolved = 0;
  if (deviceIds === null) {
    const open = await trx('live_alerts').where({ tenant_id: tenantId, kind: 'policy.conflict' }).whereNull('resolved_at')
      .select('stable_key') as Array<{ stable_key: string }>;
    for (const a of open) {
      if (keep.has(a.stable_key)) continue;
      const d = a.stable_key.slice('apple:policy.conflict:'.length);
      if (!d) continue;
      resolved += (await resolveInTx(trx, tenantId, 'policy.conflict', d)).length;
    }
  }
  return { raised, resolved };
}
