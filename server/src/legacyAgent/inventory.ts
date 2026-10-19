import type { Knex } from 'knex';
import { audit } from '../audit';
import { raiseInTx } from '../apple/alerts/service';
import { LEGACY_AGENT_ACTOR } from './actor';
import { managedPackages } from './commands';
import { InventoryBody } from './schemas';
import { withAgentTransaction } from './session';
import { writeStatusItems } from './status';
import { errorReply, type AgentIdentity, type Exchange, type Reply } from './surface';

// =============================================================================
// POST /agent/v1/inventory (docs: agent-pont-android §4.6, PB13, RC-7): the
// projection of a full inventory onto the record (devices), the satellite,
// the apps (device_apps, source 'agent_report': the absent ones are deleted;
// managed = installed by a successful app.install) and the status items. A
// serial number never takes the record of another managed device, nor
// replaces the one a record already carries: identity_conflict and an alert.
// Neither the SSID, the MAC address nor the operator are kept (no personal
// data beyond the company device, §8.7).
// =============================================================================

const clean = (v: string | null | undefined, max: number): string | null => {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s ? s.slice(0, max) : null;
};

const SERIAL_JUNK = new Set(['', 'unknown', '0', 'null', 'none', '0123456789abcdef', '0123456789ABCDEF']);
function serialOf(v: string | null | undefined): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return SERIAL_JUNK.has(s) || !/^[A-Za-z0-9-]{3,64}$/.test(s) ? null : s;
}

/** The serial the record may take: free in the tenant (no other record carries it) and not replacing another one. */
async function serialDecision(trx: Knex.Transaction, tenantId: number, deviceId: number, current: string | null, reported: string | null):
  Promise<{ set: string | null; conflict: boolean }> {
  if (!reported || reported === current) return { set: null, conflict: false };
  if (current) return { set: null, conflict: true };
  const held = await trx('devices').where({ tenant_id: tenantId, serial_number: reported }).whereNot('id', deviceId)
    .select('id', 'enrollment_state', 'management_channel') as Array<{ id: number; enrollment_state: string; management_channel: string }>;
  if (held.some((h) => h.enrollment_state !== 'unenrolled')) return { set: null, conflict: true };
  const old = held.filter((h) => h.management_channel === 'legacy_agent').map((h) => Number(h.id));
  if (old.length > 0) await trx('devices').where({ tenant_id: tenantId }).whereIn('id', old).update({ serial_number: null, updated_at: new Date() });
  return { set: reported, conflict: false };
}

export async function handleInventory(who: AgentIdentity, ex: Exchange, raw: Buffer): Promise<Reply> {
  let json: unknown;
  try { json = JSON.parse(raw.toString('utf8')); } catch { return errorReply(400, 'badRequest', 'Malformed JSON'); }
  const parsed = InventoryBody.safeParse(json);
  if (!parsed.success) return errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200));
  const b = parsed.data;

  return withAgentTransaction(who, ex, async (trx, sat) => {
    const now = new Date();
    const d = b.device;
    const rec = await trx('devices').where({ tenant_id: who.tenantId, id: who.deviceId }).first('serial_number') as { serial_number: string | null };
    const reported = serialOf(d.samsungSerial) ?? serialOf(d.serial);
    const serial = await serialDecision(trx, who.tenantId, who.deviceId, rec?.serial_number ?? null, reported);
    const manufacturer = clean(d.manufacturer, 64);
    const model = clean(d.model, 64);
    await trx('devices').where({ tenant_id: who.tenantId, id: who.deviceId }).update({
      model, model_name: [manufacturer, model].filter(Boolean).join(' ').slice(0, 128) || null,
      os_version: clean(d.osVersion, 32), os_build: clean(d.build, 32), device_name: clean(d.deviceName, 255),
      storage_capacity_bytes: b.storage?.totalBytes ?? null, storage_available_bytes: b.storage?.freeBytes ?? null,
      ...(serial.set ? { serial_number: serial.set } : {}),
      last_checkin_at: now, updated_at: now,
    });
    const imeis = [...new Set(d.imeis ?? [])];
    await trx('legacy_agent_devices').where({ tenant_id: who.tenantId, device_id: who.deviceId }).update({
      api_level: d.apiLevel ?? null, security_patch: d.securityPatch ?? null, android_id: d.androidId ? d.androidId.toLowerCase() : null,
      claimed_serial: serialOf(d.serial), samsung_serial: serialOf(d.samsungSerial), imeis,
      knox_state: b.knox.state, knox_info: JSON.stringify({ version: clean(b.knox.version, 64), mdmApiLevel: clean(b.knox.mdmApiLevel, 64), error: clean(b.knox.error, 200) }),
      admin_active: b.admin.active, last_inventory_at: now, inventory_requested_at: null,
      ...(serial.conflict ? { identity_conflict: true } : {}), updated_at: now,
    });
    if (serial.conflict && !sat.revoked_at) {
      const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, who.tenantId);
      await audit.appendInTx(trx, {
        tenantId: who.tenantId, action: 'legacy_agent.identity_conflict', target: { type: 'device', id: String(who.deviceId), device: who.deviceId },
        details: { at: 'inventory' },
      }, ctx, { onFailure: 'spool' });
      await raiseInTx(trx, who.tenantId, 'legacy_agent.identity_conflict', { discriminant: who.deviceId, navigateTo: `/legacy-agent?device=${who.deviceId}` });
    }

    // The apps: replaced as a whole (the absent ones leave), managed when a successful app.install put them there.
    const managed = await managedPackages(trx, who.tenantId, who.deviceId);
    const seen = new Map<string, (typeof b.apps)[number]>();
    for (const a of b.apps) seen.set(a.package, a);
    const ids = [...seen.keys()];
    await trx('device_apps').where({ tenant_id: who.tenantId, device_id: who.deviceId, source: 'agent_report' })
      .modify((q) => { if (ids.length > 0) q.whereNotIn('identifier', ids); }).delete();
    const rows = [...seen.values()].map((a) => ({
      tenant_id: who.tenantId, device_id: who.deviceId, identifier: a.package, name: clean(a.label, 255), version: clean(a.versionName, 64),
      short_version: a.versionCode === null || a.versionCode === undefined ? null : String(a.versionCode), managed: managed.has(a.package),
      management_status: a.system ? 'system' : null, source: 'agent_report', first_seen_at: now, last_seen_at: now,
    }));
    for (let i = 0; i < rows.length; i += 500) {
      await trx('device_apps').insert(rows.slice(i, i + 500)).onConflict(['tenant_id', 'device_id', 'identifier'])
        .merge(['name', 'version', 'short_version', 'managed', 'management_status', 'source', 'last_seen_at']);
    }

    await writeStatusItems(trx, who.tenantId, who.deviceId, now, {
      'agent.battery.level': b.battery?.level ?? null,
      'agent.battery.charging': b.battery?.charging ?? null,
      'agent.storage.free': b.storage?.freeBytes ?? null,
      'agent.network.type': clean(b.network?.type, 16),
      'agent.network.ip': clean(b.network?.ip, 45),
      'agent.admin.active': b.admin.active,
      'agent.knox.state': b.knox.state,
      'agent.security.patch': d.securityPatch ?? null,
      'agent.install.unknown-sources': b.install?.unknownSources ?? null,
    });
    return { status: 200, body: { accepted: true } };
  });
}
