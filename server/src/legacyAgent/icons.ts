import type { Knex } from 'knex';
import { canonicalPng, ICON_FAILED_DAYS, ICON_MAX_BYTES } from '../mdm/inventory/pngIcon';
import { IconsBody } from './schemas';
import { withAgentTransaction } from './session';
import { errorReply, type AgentIdentity, type Exchange, type Reply } from './surface';

// =============================================================================
// The icons of the apps of the bridge agents (plan « onglet Applications », T1):
//   - leaseIcons (in the transaction of an inventory, agent 1.0.2 and later):
//     the apps whose icon the tenant lacks (no https icon in the catalog, no
//     icon stored for this version or in the last 7 days, none older than 30
//     days, no « none » of the last 30 days, no lease held by another device
//     for less than an hour, no failure of THIS device in the last 30 days),
//     launchable first, then the user's apps; 60 at most. Each one gets a
//     lease on its app_icons row (requested_device_id, requested_at): one
//     device sends an icon, not the whole fleet. Answered as iconsWanted.
//     Quotas (a device declares its own packages: an agent, or its key, may be
//     hostile): a device creates 200 rows a day at most, a tenant holds 20 000
//     rows and 64 MiB of icons at most (no new lease beyond). A lease of this
//     device that expired unanswered is a failure of its own: ended, never
//     given back to it for 30 days (failed_device_id, failed_at).
//   - POST /agent/v1/icons (handleIcons): 16 icons at most, each one a PNG
//     (base64), none or failed. An icon is taken only for a package of THIS
//     device's inventory whose lease THIS device holds for less than 2 hours
//     (else rejected notRequested); the PNG goes through canonicalPng (a
//     device's bytes are never trusted: re-encoded, 32 KiB at most, square,
//     16 to 192 px, 1 MiB of decoded pixels per request at most), its row
//     becomes 'stored' (or 'none': never over a stored icon) and the lease
//     ends. Its version is the one this device inventoried (never more: the
//     versionCode of the body only lowers it). A refusal (format, size, the
//     tenant's quota) or failed ends the lease too, as a failure of this
//     device: it is not asked again for 30 days, another device may be.
// Logged by the surface's line only (route, status, duration, tenant); never
// a content.
// =============================================================================

/** The first agent that renders icons (1.0.2): an older one never gets a lease. */
export const ICONS_MIN_VERSION_CODE = 10_002;
export const MAX_LEASES_PER_INVENTORY = 60;
/** Rows (new apps) a device may create per day, rows and bytes of icons a tenant may hold. */
export const ICON_NEW_ROWS_PER_DEVICE_DAY = 200;
export const ICON_TENANT_MAX_ROWS = 20_000;
export const ICON_TENANT_MAX_BYTES = 64 * 1024 * 1024;
/** Pixels decoded per request of /icons at most (16 icons of 96 px RGBA: about 600 KB). */
export const ICON_REQUEST_RAW_BYTES = 1024 * 1024;
const LEASE_ACTIVE_MS = 3_600_000;
const LEASE_VALID_MS = 2 * 3_600_000;
const STORED_FRESH_MS = 7 * 86_400_000;
/** A stored icon is asked again past this age whatever its version (a wrong icon never stays for good). */
const STORED_MAX_AGE_MS = 30 * 86_400_000;
const NONE_FRESH_MS = 30 * 86_400_000;
const FAILED_MS = ICON_FAILED_DAYS * 86_400_000;
const DAY_MS = 86_400_000;

interface InventoryApp { package: string; versionCode?: number | null; system?: boolean; launchable?: boolean }
interface IconRow {
  identifier: string; state: string; version_code: string | number | null; updated_at: Date;
  requested_device_id: number | null; requested_at: Date | null; failed_device_id: number | null; failed_at: Date | null;
}

/** Rows and bytes of icons of the tenant. */
async function tenantUsage(trx: Knex.Transaction, tenantId: number): Promise<{ rows: number; bytes: number }> {
  const r = await trx('app_icons').where({ tenant_id: tenantId })
    .first(trx.raw('count(*)::bigint AS n'), trx.raw('COALESCE(sum(octet_length(bytes)), 0)::bigint AS b')) as { n: string | number; b: string | number };
  return { rows: Number(r?.n ?? 0), bytes: Number(r?.b ?? 0) };
}

/** The icons this device is asked for after its inventory: leases taken, [{ package, versionCode }]. */
export async function leaseIcons(trx: Knex.Transaction, who: AgentIdentity, apps: readonly InventoryApp[], now: Date):
  Promise<Array<{ package: string; versionCode: number | null }>> {
  if (apps.length === 0) return [];
  const usage = await tenantUsage(trx, who.tenantId);
  if (usage.bytes >= ICON_TENANT_MAX_BYTES) return [];
  const t = now.getTime();
  // New rows: within the tenant's room and the device's daily quota.
  let newRows = Math.max(0, ICON_TENANT_MAX_ROWS - usage.rows);
  if (newRows > 0) {
    const created = await trx('app_icons').where({ tenant_id: who.tenantId, created_device_id: who.deviceId })
      .where('created_at', '>', new Date(t - DAY_MS)).first(trx.raw('count(*)::int AS n')) as { n: number } | undefined;
    newRows = Math.min(newRows, Math.max(0, ICON_NEW_ROWS_PER_DEVICE_DAY - Number(created?.n ?? 0)));
  }
  const rank = (a: InventoryApp): number => (a.launchable === true ? 0 : a.system !== true ? 1 : 2);
  const candidates = [...new Map(apps.map((a) => [a.package, a])).values()].sort((x, y) => rank(x) - rank(y));
  const names = candidates.map((a) => a.package);
  const withCatalogIcon = new Set<string>();
  for (let i = 0; i < names.length; i += 500) {
    const slice = names.slice(i, i + 500);
    const rows = await trx('apps').where({ platform_family: 'android' }).whereNull('archived_at').whereIn('identifier', slice)
      .where('icon_url', 'like', 'https://%')
      .where((w) => w.where('tenant_id', who.tenantId).orWhereRaw('target_tenant_ids @> ARRAY[?]::integer[]', [who.tenantId]))
      .pluck('identifier') as string[];
    for (const r of rows) withCatalogIcon.add(r);
  }
  const icons = new Map<string, IconRow>();
  for (let i = 0; i < names.length; i += 500) {
    const rows = await trx('app_icons').where({ tenant_id: who.tenantId, platform_family: 'android' }).whereIn('identifier', names.slice(i, i + 500))
      .select('identifier', 'state', 'version_code', 'updated_at', 'requested_device_id', 'requested_at', 'failed_device_id', 'failed_at') as IconRow[];
    for (const r of rows) icons.set(r.identifier, r);
  }
  const wanted: InventoryApp[] = [];
  const expired: string[] = [];
  for (const a of candidates) {
    if (withCatalogIcon.has(a.package)) continue;
    const ic = icons.get(a.package);
    if (ic) {
      const mine = Number(ic.requested_device_id) === who.deviceId;
      // This device's lease expired unanswered: its failure (ended below), not given back to it.
      if (mine && ic.requested_at && t - new Date(ic.requested_at).getTime() >= LEASE_VALID_MS) { expired.push(a.package); continue; }
      if (wanted.length >= MAX_LEASES_PER_INVENTORY) continue;
      if (Number(ic.failed_device_id) === who.deviceId && ic.failed_at && t - new Date(ic.failed_at).getTime() < FAILED_MS) continue;
      const age = t - new Date(ic.updated_at).getTime();
      const reported = a.versionCode ?? null;
      if (ic.state === 'stored' && (age < STORED_FRESH_MS || (age < STORED_MAX_AGE_MS
        && (reported === null || (ic.version_code !== null && Number(ic.version_code) >= reported))))) continue;
      if (ic.state === 'none' && age < NONE_FRESH_MS) continue;
      if (ic.requested_at && t - new Date(ic.requested_at).getTime() < LEASE_ACTIVE_MS && !mine) continue;
    } else {
      if (wanted.length >= MAX_LEASES_PER_INVENTORY || newRows <= 0) continue;
      newRows--;
    }
    wanted.push(a);
  }
  if (expired.length) {
    for (let i = 0; i < expired.length; i += 500) {
      await trx('app_icons').where({ tenant_id: who.tenantId, platform_family: 'android', requested_device_id: who.deviceId })
        .whereIn('identifier', expired.slice(i, i + 500))
        .update({ requested_device_id: null, requested_at: null, failed_device_id: who.deviceId, failed_at: now });
    }
  }
  if (wanted.length === 0) return [];
  // The lease: taken when free, expired or already this device's (two inventories at once: one of them wins). Rows in
  // the order of their key, like the lock of handleIcons (no deadlock between two devices).
  const ordered = [...wanted].sort((x, y) => (x.package < y.package ? -1 : x.package > y.package ? 1 : 0));
  const leased = await trx('app_icons').insert(ordered.map((a) => ({
    tenant_id: who.tenantId, platform_family: 'android', identifier: a.package, state: 'pending', source: 'agent',
    requested_device_id: who.deviceId, requested_at: now, created_device_id: who.deviceId, created_at: now,
  }))).onConflict(['tenant_id', 'platform_family', 'identifier']).merge(['requested_device_id', 'requested_at'])
    .where((w) => w.whereNull('app_icons.requested_at').orWhere('app_icons.requested_at', '<', new Date(t - LEASE_ACTIVE_MS))
      .orWhere('app_icons.requested_device_id', who.deviceId))
    .returning('identifier') as Array<{ identifier: string }>;
  const got = new Set(leased.map((r) => r.identifier));
  return wanted.filter((a) => got.has(a.package)).map((a) => ({ package: a.package, versionCode: a.versionCode ?? null }));
}

const B64_STD = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** The bytes of a strict standard base64 (canonical: re-encoding gives the same text), or null. */
function strictBase64(text: string): Buffer | null {
  if (!B64_STD.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : null;
}

/** The versionCode this device inventoried for a package (device_apps.short_version), or null. */
const inventoried = (v: string | null): number | null => (v !== null && /^\d{1,16}$/.test(v) && Number.isSafeInteger(Number(v)) ? Number(v) : null);

export async function handleIcons(who: AgentIdentity, ex: Exchange, raw: Buffer): Promise<Reply> {
  let json: unknown;
  try { json = JSON.parse(raw.toString('utf8')); } catch { return errorReply(400, 'badRequest', 'Malformed JSON'); }
  const parsed = IconsBody.safeParse(json);
  if (!parsed.success) return errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200));
  const icons = parsed.data.icons;

  return withAgentTransaction(who, ex, async (trx) => {
    const now = new Date();
    const names = [...new Set(icons.map((i) => i.package))];
    const present = new Map((await trx('device_apps').where({ tenant_id: who.tenantId, device_id: who.deviceId, source: 'agent_report' })
      .whereIn('identifier', names).select('identifier', 'short_version') as Array<{ identifier: string; short_version: string | null }>)
      .map((r) => [r.identifier, inventoried(r.short_version)]));
    const leases = new Map((await trx('app_icons').where({ tenant_id: who.tenantId, platform_family: 'android' }).whereIn('identifier', names)
      .orderByRaw('identifier COLLATE "C"').forUpdate()
      .select('identifier', 'state', 'requested_device_id', 'requested_at', trx.raw('COALESCE(octet_length(bytes), 0)::int AS size')) as
      Array<Pick<IconRow, 'identifier' | 'state' | 'requested_device_id' | 'requested_at'> & { size: number }>)
      .map((r) => [r.identifier, r]));
    let tenantBytes = (await tenantUsage(trx, who.tenantId)).bytes;
    let rawLeft = ICON_REQUEST_RAW_BYTES;
    const rejected: Array<{ package: string; reason: string }> = [];
    const done = new Set<string>();
    let accepted = 0;
    for (const icon of icons) {
      const lease = leases.get(icon.package);
      const held = !!lease && Number(lease.requested_device_id) === who.deviceId && !!lease.requested_at
        && now.getTime() - new Date(lease.requested_at).getTime() < LEASE_VALID_MS;
      if (done.has(icon.package) || !present.has(icon.package) || !held || !lease) {
        rejected.push({ package: icon.package, reason: 'notRequested' });
        continue;
      }
      done.add(icon.package);
      const key = { tenant_id: who.tenantId, platform_family: 'android', identifier: icon.package };
      // The version of the icon: the one this device inventoried, lowered by the body's (an icon of an older build).
      const known = present.get(icon.package) ?? null;
      const versionCode = known === null ? null : Math.min(known, icon.versionCode);
      const endLease = { requested_device_id: null, requested_at: null };
      // A refusal or a failure ends the lease as a failure of this device (not asked again for 30 days).
      const failure = async (reason: string | null) => {
        await trx('app_icons').where(key).update({ ...endLease, failed_device_id: who.deviceId, failed_at: now });
        if (reason) rejected.push({ package: icon.package, reason }); else accepted++;
      };
      if (icon.failed) { await failure(null); continue; }
      if (icon.none) {
        // Never over a stored icon (a device cannot erase the icon of the tenant): the lease ends, the icon stays.
        if (lease.state === 'stored') await trx('app_icons').where(key).update({ ...endLease, version_code: versionCode, updated_at: now });
        else await trx('app_icons').where(key).update({ ...endLease, state: 'none', bytes: null, sha256: null, width: null, source_device_id: who.deviceId, version_code: versionCode, updated_at: now });
        accepted++;
        continue;
      }
      const bytes = strictBase64(icon.png ?? '');
      if (!bytes) { await failure('badFormat'); continue; }
      if (bytes.length > ICON_MAX_BYTES) { await failure('tooLarge'); continue; }
      const png = canonicalPng(bytes, { maxRawBytes: rawLeft });
      rawLeft -= png.rawBytes ?? 0;
      if (!png.ok) { await failure(png.reason); continue; }
      if (tenantBytes - lease.size + png.png.length > ICON_TENANT_MAX_BYTES) { await failure('quota'); continue; }
      tenantBytes += png.png.length - lease.size;
      await trx('app_icons').where(key).update({ ...endLease, state: 'stored', bytes: png.png, sha256: png.sha256, width: png.width, source_device_id: who.deviceId, version_code: versionCode, updated_at: now });
      accepted++;
    }
    return { status: 200, body: { accepted, rejected } };
  });
}
