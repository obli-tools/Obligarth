import type { Request } from 'express';
import type { Knex } from 'knex';
import { compileAgentPolicy } from '../../legacyAgent/policyChannel';
import { restrictionService } from '../../services/restriction.service';
import { customFieldsOf, loadResolutionInput } from '../policies/loader';
import { strictest, type Level } from '../policies/publishGuard';
import { resolveDevices } from '../policies/resolver';
import { DEVICE_VALUES_ACTION, labelOf, type DevicePatch } from './devicePatch';

// =============================================================================
// The name and the custom fields of ONE device as the bridge agent's templates read them ({{device.name}},
// {{device.custom.<key>}}; review F116): PATCH /api/mdm/devices/:id may rewrite the files deposited on the phone, as
// the import of per-device values does (legacyAgent/policyRoutes.ts, legacy_agent.device_values_import) and as the
// change of site of one device (sites.device_site). The same opt-in rule as the latter: the restrictable action
// sites.device_values has no level by default (an operator renames a phone from its record as before); a tenant may
// ask a second factor ('sensitive') or a second person ('restricted') for it, and then only when the change rewrites
// the device's agent policy. The governed circuit of the facts (mdm/groups/governance.ts) applies the level.
// =============================================================================

type Q = Knex | Knex.Transaction;

export { DEVICE_VALUES_ACTION };

/** Does a patch change a field the agent's templates read (the name, the custom fields)? */
export const touchesAgentValues = (patch: DevicePatch): boolean => patch.displayName !== undefined || patch.customFields !== undefined;

/**
 * Does the patch change the agent policy compiled for the device (its hash before and after, in memory, its dynamic
 * groups unchanged: a move of groups is the governed circuit's own preview)? False for a device without agent policy,
 * out of management or unknown.
 */
export async function patchChangesAgentPolicy(q: Q, tenantId: number, deviceId: number, patch: DevicePatch): Promise<boolean> {
  if (!touchesAgentValues(patch)) return false;
  const input = await loadResolutionInput(q, tenantId, [deviceId]);
  const d = input.devices.find((x) => x.id === deviceId);
  if (!d) return false;
  let label = d.label;
  if (patch.displayName !== undefined) {
    const row = await q('devices').where({ tenant_id: tenantId, id: deviceId }).first('uuid', 'device_name', 'model_name', 'model') as
      { uuid: string; device_name: string | null; model_name: string | null; model: string | null } | undefined;
    if (!row) return false;
    label = labelOf({
      displayName: patch.displayName === null ? null : String(patch.displayName).slice(0, 500),
      deviceName: row.device_name ?? null, modelName: row.model_name ?? null, model: row.model ?? null, uuid: String(row.uuid),
    });
  }
  const patched = { ...d, label, customFields: patch.customFields !== undefined ? customFieldsOf(patch.customFields) : d.customFields };
  const devices = input.devices.map((x) => (x.id === deviceId ? patched : x));
  const before = resolveDevices(input);
  const after = resolveDevices({ ...input, devices });
  const i = input.devices.findIndex((x) => x.id === deviceId);
  const a = compileAgentPolicy(d, before.devices[i].settings, input.tenant, tenantId)?.hash ?? null;
  const b = compileAgentPolicy(patched, after.devices[i].settings, input.tenant, tenantId)?.hash ?? null;
  return a !== b;
}

/**
 * The level the restriction sites.device_values asks for a patch of one device: the stricter of the device's tenant
 * and the request's (the global view never skips the device tenant's matrix), 'none' when the tenant did not opt in,
 * when the patch names neither the name nor the custom fields, or when it leaves the agent policy as it is.
 */
export async function deviceValuesLevel(q: Q, req: Request, tenantId: number, deviceId: number, patch: DevicePatch): Promise<Level> {
  if (!touchesAgentValues(patch)) return 'none';
  let level: Level = await restrictionService.getLevelFor({ tenantId, actionKey: DEVICE_VALUES_ACTION, deviceIds: [deviceId] });
  const own = Number(req.tenantId);
  if (Number.isSafeInteger(own) && own > 0 && own !== tenantId && level !== 'restricted') {
    level = strictest(level, await restrictionService.getLevelFor({ tenantId: own, actionKey: DEVICE_VALUES_ACTION, deviceIds: [deviceId] }));
  }
  if (level === 'none') return 'none';
  return (await patchChangesAgentPolicy(q, tenantId, deviceId, patch)) ? level : 'none';
}
