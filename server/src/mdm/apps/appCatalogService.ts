import type { Knex } from 'knex';
import { z } from 'zod';
import {
  APPLE_APP_KINDS_MVP, APPLE_APP_OPTION_DEFAULTS, appArtifactKey, isSecretRef,
  type AppCatalogEntry, type AppDetail, type AppleAppOptions, type JsonValue,
} from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';
import { platformsOfAsset } from '../../apple/integrations/vppRules';

// =============================================================================
// The catalog of apps (docs: modele-donnees-mdm §8.1, §8.2, §8.4; lot C4):
// the apps of a tenant (Apple at the MVP: App Store and Custom Apps of Apple
// Business, licence mode 'vpp'), their metadata (refreshed by the
// synchronisation of Apps and Books: the platforms), the options of an app
// assignment (AppleAppOptionsSchema) and what the inventory shows of an app
// (GROUP BY on device_apps, never a device listed). Writes: capability
// mdm.apps.manage (routes), entries app.created, app.updated, app.archived.
// An app with assignments is not archived (appHasAssignments); an archived
// app accepts no assignment (trigger check_assignment_reference).
// =============================================================================

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const STORE_ID_RE = /^[0-9]{1,20}$/;
const PLATFORMS = ['ios', 'ipados', 'macos', 'tvos', 'visionos'] as const;
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_CONFIG_DEPTH = 10;

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);

// ── Options of an app assignment (section 8.2) ─────────────────────────────────

/** A value of a managed configuration: plist-compatible (no null), variables allowed in strings. */
function checkConfigValue(v: unknown, depth: number, path: string): string | null {
  if (depth > MAX_CONFIG_DEPTH) return `${path}: too deep`;
  if (v === null || v === undefined) return `${path}: null is not a plist value`;
  if (typeof v === 'string' || typeof v === 'boolean') return null;
  if (typeof v === 'number') return Number.isFinite(v) ? null : `${path}: not a finite number`;
  if (Array.isArray(v)) {
    for (const [i, x] of v.entries()) { const e = checkConfigValue(x, depth + 1, `${path}[${i}]`); if (e) return e; }
    return null;
  }
  if (typeof v === 'object') {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (!k || k.length > 255) return `${path}: key length`;
      const e = checkConfigValue(x, depth + 1, `${path}.${k}`);
      if (e) return e;
    }
    return null;
  }
  return `${path}: not a plist value`;
}

/** Does a value hold a secret (a reference, or a value typed to become one)? */
function holdsSecret(v: unknown, depth = 0): boolean {
  if (depth > MAX_CONFIG_DEPTH + 1 || !v || typeof v !== 'object') return false;
  if (isSecretRef(v) || Object.prototype.hasOwnProperty.call(v, '$secretValue')) return true;
  return (Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)).some((x) => holdsSecret(x, depth + 1));
}

export const AppleAppOptionsSchema = z.object({
  install: z.literal('required').default('required'),
  removable: z.boolean().default(APPLE_APP_OPTION_DEFAULTS.removable),
  removeOnUnenroll: z.boolean().default(APPLE_APP_OPTION_DEFAULTS.removeOnUnenroll),
  preventBackup: z.boolean().default(APPLE_APP_OPTION_DEFAULTS.preventBackup),
  takeOver: z.boolean().default(APPLE_APP_OPTION_DEFAULTS.takeOver),
  config: z.record(z.string(), z.unknown()).optional(),
}).strict();

/** The options of an app assignment, validated, defaults filled (what assignments.options stores). */
export function normalizeAppOptions(raw: unknown): AppleAppOptions & Record<string, JsonValue> {
  if (raw && typeof raw === 'object' && holdsSecret((raw as Record<string, unknown>).config)) {
    throw new AppError(422, 'A managed app configuration carries no secret at this stage', 'appConfigSecretUnsupported');
  }
  const r = AppleAppOptionsSchema.safeParse(raw ?? {});
  if (!r.success) {
    const i = r.error.issues[0];
    throw new AppError(400, `options.${i?.path.join('.') || ''}: ${i?.message ?? 'invalid'}`, 'invalidRequest', { field: 'options' });
  }
  const o = r.data;
  if (o.config !== undefined) {
    const err = checkConfigValue(o.config, 0, 'config');
    if (err) throw new AppError(400, `options.${err}`, 'invalidRequest', { field: 'options' });
    if (Buffer.byteLength(JSON.stringify(o.config), 'utf8') > MAX_CONFIG_BYTES) throw new AppError(400, 'options.config: too large', 'invalidRequest', { field: 'options' });
  }
  const out: Record<string, JsonValue> = {
    install: o.install, removable: o.removable, removeOnUnenroll: o.removeOnUnenroll, preventBackup: o.preventBackup, takeOver: o.takeOver,
  };
  if (o.config !== undefined && Object.keys(o.config).length > 0) out.config = o.config as Record<string, JsonValue>;
  return out as AppleAppOptions & Record<string, JsonValue>;
}

// ── Catalog ────────────────────────────────────────────────────────────────────

export const AppCreateBody = z.object({
  kind: z.enum(APPLE_APP_KINDS_MVP),
  storeId: z.string().regex(STORE_ID_RE),
  identifier: z.string().regex(IDENTIFIER_RE),
  name: z.string().trim().min(1).max(255),
  publisher: z.string().trim().max(255).nullable().optional(),
  iconUrl: z.string().url().max(1024).refine((u) => u.startsWith('https://'), 'iconUrl must be an HTTPS URL').nullable().optional(),
  supportedPlatforms: z.array(z.enum(PLATFORMS)).max(PLATFORMS.length).optional(),
  minimumOsVersion: z.string().regex(/^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$/).nullable().optional(),
  licenseMode: z.enum(['vpp', 'none']).optional(),
}).strict();

export const AppPatchBody = z.object({
  name: z.string().trim().min(1).max(255).optional(),
  publisher: z.string().trim().max(255).nullable().optional(),
  iconUrl: z.string().url().max(1024).refine((u) => u.startsWith('https://'), 'iconUrl must be an HTTPS URL').nullable().optional(),
  supportedPlatforms: z.array(z.enum(PLATFORMS)).max(PLATFORMS.length).optional(),
  minimumOsVersion: z.string().regex(/^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$/).nullable().optional(),
}).strict();

interface AppRow {
  id: number; uuid: string; tenant_id: number; platform_family: 'apple' | 'android'; kind: string; identifier: string; store_id: string | null;
  name: string; publisher: string | null; icon_url: string | null; supported_platforms: string[] | null; minimum_os_version: string | null;
  license_mode: 'vpp' | 'none'; metadata_refreshed_at: Date | null; created_at: Date; updated_at: Date; archived_at: Date | null;
}

export function parseAppId(raw: unknown): number {
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n <= 0) throw new AppError(404, 'App not found', 'appNotFound');
  return n;
}

async function appRow(q: Knex | Knex.Transaction, tenantId: number, id: number, lock = false): Promise<AppRow> {
  let qb = q('apps').where({ tenant_id: tenantId, id });
  if (lock) qb = qb.forUpdate();
  const r = await qb.first() as AppRow | undefined;
  if (!r) throw new AppError(404, 'App not found', 'appNotFound');
  return r;
}

async function entries(q: Knex | Knex.Transaction, tenantId: number, rows: AppRow[]): Promise<AppCatalogEntry[]> {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => Number(r.id));
  const counts = new Map((await q('assignments').where({ tenant_id: tenantId, resource_type: 'app', resource_tenant_id: tenantId }).whereIn('resource_id', ids)
    .groupBy('resource_id').select('resource_id').count({ n: '*' }) as Array<{ resource_id: number; n: string | number }>)
    .map((x) => [Number(x.resource_id), Number(x.n)]));
  const storeIds = [...new Set(rows.map((r) => r.store_id).filter((s): s is string => !!s))];
  const lic = storeIds.length ? await q('vpp_assets as a')
    .join('tenant_apple_vpp_tokens as t', function on() { this.on('t.id', 'a.vpp_token_id').andOn('t.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId }).whereNot('t.state', 'removed').whereIn('a.adam_id', storeIds).groupBy('a.adam_id')
    .select('a.adam_id').sum({ total: 'a.total_count', assigned: 'a.assigned_count', available: 'a.available_count' }) as
    Array<{ adam_id: string; total: string | number; assigned: string | number; available: string | number }> : [];
  const licOf = new Map(lic.map((l) => [String(l.adam_id), { total: Number(l.total), assigned: Number(l.assigned), available: Number(l.available) }]));
  return rows.map((r) => ({
    id: Number(r.id), uuid: r.uuid, tenantId: Number(r.tenant_id), platformFamily: r.platform_family, kind: r.kind, identifier: r.identifier,
    storeId: r.store_id, name: r.name, publisher: r.publisher, iconUrl: r.icon_url, supportedPlatforms: r.supported_platforms ?? [],
    minimumOsVersion: r.minimum_os_version, licenseMode: r.license_mode, metadataRefreshedAt: iso(r.metadata_refreshed_at),
    createdAt: iso(r.created_at)!, updatedAt: iso(r.updated_at)!, archivedAt: iso(r.archived_at), assignments: counts.get(Number(r.id)) ?? 0,
    licenses: r.store_id ? licOf.get(r.store_id) ?? null : null,
  }));
}

export async function listApps(q: Knex | Knex.Transaction, tenantId: number, o: { archived?: boolean; q?: string } = {}): Promise<AppCatalogEntry[]> {
  let qb = q('apps').where({ tenant_id: tenantId });
  if (!o.archived) qb = qb.whereNull('archived_at');
  if (o.q && o.q.trim()) {
    const like = `%${o.q.trim().replace(/[\\%_]/g, (c) => `\\${c}`).slice(0, 100)}%`;
    qb = qb.where((w) => w.whereILike('name', like).orWhereILike('identifier', like).orWhere('store_id', o.q!.trim()));
  }
  const rows = await qb.orderBy([{ column: 'archived_at', order: 'desc', nulls: 'first' }, { column: 'name' }]).limit(2000).select() as AppRow[];
  return entries(q, tenantId, rows);
}

export async function getApp(q: Knex | Knex.Transaction, tenantId: number, id: number): Promise<AppDetail> {
  const r = await appRow(q, tenantId, id);
  const [entry] = await entries(q, tenantId, [r]);
  const inv = await q('device_apps').where({ tenant_id: tenantId, identifier: r.identifier })
    .select(q.raw('count(*)::int AS installed'), q.raw('count(*) FILTER (WHERE managed)::int AS managed'),
      q.raw("count(*) FILTER (WHERE management_status IN ('Failed', 'UserRejected'))::int AS failed")).first() as
    { installed: number; managed: number; failed: number } | undefined;
  const versions = await q('device_apps').where({ tenant_id: tenantId, identifier: r.identifier }).whereNotNull('short_version')
    .groupBy('short_version').select('short_version').count({ n: '*' }).orderBy('n', 'desc').limit(20) as Array<{ short_version: string; n: string | number }>;
  const keys = [`app:${r.identifier}`, appArtifactKey(r.identifier, true)];
  const delivery = await q('device_artifacts').where({ tenant_id: tenantId }).whereIn('artifact_key', keys).whereNot('state', 'removed')
    .groupBy('state').select('state').count({ n: '*' }) as Array<{ state: string; n: string | number }>;
  return {
    ...entry,
    installs: { installed: Number(inv?.installed ?? 0), managed: Number(inv?.managed ?? 0), failed: Number(inv?.failed ?? 0),
      versions: versions.map((v) => ({ version: v.short_version, devices: Number(v.n) })) },
    delivery: Object.fromEntries(delivery.map((d) => [d.state, Number(d.n)])),
  };
}

/** « Ajouter une app » : from a licence of the tenant (the platforms of the asset) or by its App Store id. */
export async function createApp(trx: Knex.Transaction, tenantId: number, userId: number | null, raw: unknown): Promise<AppCatalogEntry> {
  const r = AppCreateBody.safeParse(raw ?? {});
  if (!r.success) {
    const i = r.error.issues[0];
    throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
  }
  const b = r.data;
  if (b.licenseMode === 'none') throw new AppError(422, 'An app without a licence of Apps and Books comes in a later version', 'licenseModeUnsupported');
  let platforms: string[] = b.supportedPlatforms ?? [];
  if (!b.supportedPlatforms) {
    const asset = await trx('vpp_assets').where({ tenant_id: tenantId, adam_id: b.storeId }).first('supported_platforms') as { supported_platforms: unknown } | undefined;
    const list = asset ? (typeof asset.supported_platforms === 'string' ? JSON.parse(asset.supported_platforms) : asset.supported_platforms) : [];
    platforms = Array.isArray(list) ? platformsOfAsset(list.filter((x: unknown): x is string => typeof x === 'string')) : [];
  }
  try {
    const [row] = await trx('apps').insert({
      tenant_id: tenantId, platform_family: 'apple', kind: b.kind, identifier: b.identifier, store_id: b.storeId, name: b.name,
      publisher: b.publisher ?? null, icon_url: b.iconUrl ?? null, supported_platforms: trx.raw('?::varchar[]', [platforms]),
      minimum_os_version: b.minimumOsVersion ?? null, license_mode: 'vpp', created_by: userId,
    }).returning('*') as AppRow[];
    return (await entries(trx, tenantId, [row]))[0];
  } catch (err) {
    if ((err as { code?: string }).code === '23505') throw new AppError(409, 'An app of the catalog already has this identifier', 'appIdentifierExists');
    throw err;
  }
}

export async function patchApp(trx: Knex.Transaction, tenantId: number, id: number, raw: unknown): Promise<{ entry: AppCatalogEntry; fields: string[] }> {
  const r = AppPatchBody.safeParse(raw ?? {});
  if (!r.success) {
    const i = r.error.issues[0];
    throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
  }
  const cur = await appRow(trx, tenantId, id, true);
  if (cur.archived_at) throw new AppError(409, 'An archived app does not change', 'appArchived');
  const b = r.data;
  const set: Record<string, unknown> = {};
  if (b.name !== undefined) set.name = b.name;
  if (b.publisher !== undefined) set.publisher = b.publisher;
  if (b.iconUrl !== undefined) set.icon_url = b.iconUrl;
  if (b.minimumOsVersion !== undefined) set.minimum_os_version = b.minimumOsVersion;
  if (b.supportedPlatforms !== undefined) set.supported_platforms = trx.raw('?::varchar[]', [b.supportedPlatforms]);
  const fields = Object.keys(set);
  if (fields.length) await trx('apps').where({ tenant_id: tenantId, id }).update({ ...set, updated_at: new Date() });
  return { entry: (await entries(trx, tenantId, [await appRow(trx, tenantId, id)]))[0], fields };
}

/** « Archiver » : refused while the app has assignments (appHasAssignments). */
export async function archiveApp(trx: Knex.Transaction, tenantId: number, id: number): Promise<AppCatalogEntry> {
  const cur = await appRow(trx, tenantId, id, true);
  if (cur.archived_at) throw new AppError(409, 'This app is archived already', 'appArchived');
  const n = await trx('assignments').where({ resource_type: 'app', resource_tenant_id: tenantId, resource_id: id }).count({ n: '*' }).first() as { n: string | number };
  if (Number(n?.n ?? 0) > 0) throw new AppError(409, 'Remove the assignments of this app before archiving it', 'appHasAssignments');
  await trx('apps').where({ tenant_id: tenantId, id }).update({ archived_at: new Date(), updated_at: new Date() });
  return (await entries(trx, tenantId, [await appRow(trx, tenantId, id)]))[0];
}

/** The app an assignment names (the tenant's, or the master's library shared with it), not archived. */
export async function assignableApp(q: Knex | Knex.Transaction, tenantId: number, resourceTenantId: number, id: number):
  Promise<{ id: number; tenantId: number; identifier: string; name: string; platformFamily: 'apple' | 'android' }> {
  const r = await q('apps').where({ id, tenant_id: resourceTenantId }).first('id', 'tenant_id', 'identifier', 'name', 'archived_at', 'platform_family', 'target_tenant_ids') as
    (Pick<AppRow, 'id' | 'tenant_id' | 'identifier' | 'name' | 'archived_at' | 'platform_family'> & { target_tenant_ids: number[] | null }) | undefined;
  if (!r || (resourceTenantId !== tenantId && !(r.target_tenant_ids ?? []).includes(tenantId))) throw new AppError(404, 'App not found', 'appNotFound');
  if (r.archived_at) throw new AppError(409, 'An archived app is not assigned', 'appArchived');
  // Lot AN-C1 (raccord of AN-E1): an app of the tenant's own Android catalog is assigned too (never shared from the
  // master tenant: apps_android_identifier); its options are checked by the Android module (publish.ts).
  if (r.platform_family === 'android') {
    if (resourceTenantId !== tenantId) throw new AppError(404, 'App not found', 'appNotFound');
    return { id: Number(r.id), tenantId: Number(r.tenant_id), identifier: r.identifier, name: r.name, platformFamily: 'android' };
  }
  if (r.platform_family !== 'apple') throw new AppError(422, 'Only Apple and Android apps are assigned', 'invalidRequest');
  return { id: Number(r.id), tenantId: Number(r.tenant_id), identifier: r.identifier, name: r.name, platformFamily: 'apple' };
}
