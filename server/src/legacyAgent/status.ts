import { createHash } from 'node:crypto';
import type { Knex } from 'knex';

// =============================================================================
// Status items of an agent's device (docs: agent-pont-android §4.5, §4.6):
// device_status_items (one row per item, value and its SHA-256), and
// device_status_history for the items whose changes matter (administrator,
// Knox, security patch), written only when the value changes. The item names
// follow the CHECK of device_status_items (^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$):
// agent.install.unknown-sources (RC-7) carries a hyphen, not an underscore.
// =============================================================================

export const HISTORY_ITEMS = new Set(['agent.admin.active', 'agent.knox.state', 'agent.security.patch', 'agent.owner.active', 'agent.adb.enabled']);

const sha = (v: unknown): string => createHash('sha256').update(JSON.stringify(v ?? null)).digest('hex');

export async function writeStatusItems(trx: Knex.Transaction, tenantId: number, deviceId: number, at: Date,
  items: Record<string, string | number | boolean | null>): Promise<void> {
  const names = Object.keys(items);
  if (names.length === 0) return;
  const current = await trx('device_status_items').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('item', names)
    .select('item', 'value_sha256') as Array<{ item: string; value_sha256: string | null }>;
  const before = new Map(current.map((c) => [c.item, c.value_sha256]));
  const rows = names.map((item) => ({
    tenant_id: tenantId, device_id: deviceId, item, value: JSON.stringify(items[item]), value_sha256: sha(items[item]), error: null,
    observed_at: at, updated_at: at,
  }));
  await trx('device_status_items').insert(rows).onConflict(['tenant_id', 'device_id', 'item'])
    .merge(['value', 'value_sha256', 'error', 'observed_at', 'updated_at']);
  const changed = rows.filter((r) => HISTORY_ITEMS.has(r.item) && before.get(r.item) !== r.value_sha256);
  if (changed.length > 0) {
    await trx('device_status_history').insert(changed.map((r) => ({ tenant_id: tenantId, device_id: deviceId, item: r.item, value: r.value, observed_at: at })));
  }
}
