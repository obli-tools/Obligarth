import type { Knex } from 'knex';
import { z } from 'zod';
import type { RuleFacts } from '../rules/facts';

// =============================================================================
// The operator's fields of a device record (PATCH /api/mdm/devices/:id; docs: modele-donnees-mdm §10.6): its name,
// description, tags, custom fields and asset. The body, the columns it writes, and what it changes of the facts the
// rule language reads (P0-5 T7, D11): the name (devices.label, generated from display_name), the tags, the custom
// fields, the lifecycle and warranty statuses. A change of those facts that makes the device enter or leave a dynamic
// group an assignment targets goes through the governed circuit (mdm/groups/governance.ts, kind device_facts); the
// request of a second approver keeps the body (DevicePatchBody), parsed again by its executor.
// Pure but for writeDevicePatch (the caller's transaction and tenant context). No AppError here: the unit tests load
// this module.
// =============================================================================

/** An asset date (a DATE column): a calendar day YYYY-MM-DD that exists, years 1900 to 9999. Any other text went
 *  to PostgreSQL as is and was answered 500. */
const assetDay = z.string().max(10).refine((v) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const at = new Date(Date.UTC(y, mo - 1, d));
  return y >= 1900 && at.getUTCFullYear() === y && at.getUTCMonth() === mo - 1 && at.getUTCDate() === d;
}, 'a calendar day YYYY-MM-DD');

export const DevicePatchBody = z.object({
  displayName: z.string().max(500).nullable().optional(),
  description: z.string().max(10_000).nullable().optional(),
  tags: z.array(z.string().max(100)).max(50).optional(),
  customFields: z.record(z.string().max(100), z.string().max(1000)).optional(),
  purchaseDate: assetDay.nullable().optional(),
  warrantyExpiry: assetDay.nullable().optional(),
  warrantyVendor: z.string().max(200).nullable().optional(),
  warrantyStatus: z.enum(['active', 'expired', 'unknown']).nullable().optional(),
  expectedLifetimeYears: z.number().int().min(0).max(100).nullable().optional(),
  lifecycleStatus: z.enum(['active', 'aging', 'end_of_life', 'retired', 'unknown']).nullable().optional(),
}).strict();
export type DevicePatch = z.infer<typeof DevicePatchBody>;

/** The fields of a patch the rule language reads (name, tags, custom_field, lifecycle_status, warranty_status). */
export const RULE_FACT_PATCH_FIELDS = ['displayName', 'tags', 'customFields', 'lifecycleStatus', 'warrantyStatus'] as const;

/** Does a patch change a field a rule may compare? Otherwise no dynamic group can change with it. */
export const touchesRuleFacts = (patch: DevicePatch): boolean => RULE_FACT_PATCH_FIELDS.some((k) => patch[k] !== undefined);

/** The columns of devices a patch writes (updated_at included). */
export function devicePatchColumns(data: DevicePatch): Record<string, unknown> {
  const updates: Record<string, unknown> = { updated_at: new Date() };
  if (data.displayName !== undefined) updates.display_name = data.displayName === null ? null : String(data.displayName).slice(0, 500);
  if (data.description !== undefined) updates.description = data.description;
  if (data.tags !== undefined) updates.tags = JSON.stringify(data.tags);
  if (data.customFields !== undefined) updates.custom_fields = JSON.stringify(data.customFields);
  if (data.purchaseDate !== undefined) updates.purchase_date = data.purchaseDate;
  if (data.warrantyExpiry !== undefined) updates.warranty_expiry = data.warrantyExpiry;
  if (data.warrantyVendor !== undefined) updates.warranty_vendor = data.warrantyVendor;
  if (data.warrantyStatus !== undefined) updates.warranty_status = data.warrantyStatus;
  if (data.expectedLifetimeYears !== undefined) updates.expected_lifetime_years = data.expectedLifetimeYears;
  if (data.lifecycleStatus !== undefined) updates.lifecycle_status = data.lifecycleStatus;
  return updates;
}

/** Writes a patch on a device of the tenant, in `trx`; false when the tenant has no such device. */
export async function writeDevicePatch(trx: Knex.Transaction, tenantId: number, deviceId: number, patch: DevicePatch): Promise<boolean> {
  const n = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update(devicePatchColumns(patch));
  return Number(n) > 0;
}

/** What devices.label is generated from (migration mdm_model_expand): the name chosen, the name reported, the model. */
export interface LabelParts {
  displayName: string | null;
  deviceName: string | null;
  modelName: string | null;
  model: string | null;
  uuid: string;
}

/** btrim(): the spaces only, as PostgreSQL's default. */
const btrim = (s: string): string => s.replace(/^ +| +$/g, '');
const nonBlank = (s: string | null): string | null => (s === null ? null : (btrim(s) === '' ? null : btrim(s)));

/** devices.label as the base generates it: COALESCE(NULLIF(btrim(display_name), ''), NULLIF(btrim(device_name), ''),
 *  model_name, model, 'device-' || left(uuid::text, 8)). */
export function labelOf(p: LabelParts): string {
  return nonBlank(p.displayName) ?? nonBlank(p.deviceName) ?? p.modelName ?? p.model ?? `device-${p.uuid.slice(0, 8)}`;
}

/**
 * The facts of a device once a patch is written (pure): the name (the label generated again from the display name
 * proposed), the tags, the custom fields and the asset statuses the patch gives; the rest as it is. `parts`: what the
 * label is generated from, needed only when the patch names the device.
 */
export function factsWithPatch(facts: RuleFacts, patch: DevicePatch, parts?: Omit<LabelParts, 'displayName'>): RuleFacts {
  const next: RuleFacts = { ...facts };
  if (patch.displayName !== undefined && parts) {
    next.name = labelOf({ ...parts, displayName: patch.displayName === null ? null : String(patch.displayName).slice(0, 500) });
  }
  if (patch.tags !== undefined) next.tags = [...patch.tags];
  if (patch.customFields !== undefined) next.customFields = { ...patch.customFields };
  if (patch.lifecycleStatus !== undefined) next.lifecycleStatus = patch.lifecycleStatus;
  if (patch.warrantyStatus !== undefined) next.warrantyStatus = patch.warrantyStatus;
  return next;
}
