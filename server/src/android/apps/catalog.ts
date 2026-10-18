// The Android apps of a tenant's catalog (android-amapi §9.6; lot AN-E1), rows of the existing table apps
// (platform_family 'android', kinds play, private and web already admitted by the model; the package in
// identifier, store_id null, license_mode 'none'; COH-4). An app is added by its package, chosen in the managed
// Google Play iframe: the instance reads it at Google for the tenant's enterprise (applications.get, outside any
// transaction) before writing anything. That read is the proof the app is visible to the enterprise: a private app
// of another tenant's enterprise answers 404 and is never written. The kind is derived from Google's answer, never
// taken from the client. Metadata are refreshed once a day at most (android.app-metadata).
// The common catalog (POST /api/mdm/apps, mdm.apps.manage) is a junction point (AN-A2/AN-P): it calls addAndroidApp
// for the family android. Until then only the router of this module (not mounted) and the testbed call it.
import type { Knex } from 'knex';
import { isAndroidPackage } from '@obligarth/shared/dist/android/policy.js';
import { ANDROID_APP_KINDS, type AndroidAppKind } from '@obligarth/shared/dist/android/apps.js';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { RESERVED_PACKAGES } from '../../mdm/android/overlay';
import { readEnterprise } from '../enterprises/registry';
import { androidGateway } from '../gateway';
import { AndroidError } from '../gateway/errors';
import type { AndroidGateway } from '../gateway/types';
import { kindOf, metadataOf, minimizeApplication, type AndroidAppMetadata } from './metadata';

export const APPS_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.app-metadata' }) as DbActor;
/** Metadata are read again at Google once a day at most. */
export const METADATA_TTL_MS = 24 * 3_600_000;
const LANG_RE = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class AndroidAppError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'AndroidAppError';
    this.status = status;
    this.code = code;
  }
}

export interface AndroidAppRow {
  id: number;
  uuid: string;
  tenant_id: number;
  kind: AndroidAppKind;
  identifier: string;
  name: string;
  publisher: string | null;
  icon_url: string | null;
  metadata: unknown;
  metadata_refreshed_at: Date | null;
  archived_at: Date | null;
}

const COLUMNS = ['id', 'uuid', 'tenant_id', 'kind', 'identifier', 'name', 'publisher', 'icon_url', 'metadata', 'metadata_refreshed_at', 'archived_at'];

/** What a route shows of an Android app (never Google's whole answer). */
export interface AndroidAppView {
  id: number;
  uuid: string;
  kind: AndroidAppKind;
  packageName: string;
  name: string;
  publisher: string | null;
  iconUrl: string | null;
  managedConfiguration: 'json' | 'iframe' | 'none';
  oemConfig: boolean;
  tracks: Array<{ trackId: string; trackAlias: string | null }>;
  permissions: string[];
  minAndroidSdkVersion: number | null;
  metadataRefreshedAt: string | null;
  unavailable: boolean;
}

export function appView(r: AndroidAppRow): AndroidAppView {
  const m = metadataOf(r.metadata);
  const managed: AndroidAppView['managedConfiguration'] = !m || r.kind === 'web' ? 'none'
    : m.oemConfig || m.managedPropertiesTruncated ? 'iframe' : (m.managedProperties?.length ?? 0) > 0 ? 'json' : 'none';
  return {
    id: Number(r.id), uuid: String(r.uuid), kind: r.kind, packageName: r.identifier, name: r.name, publisher: r.publisher,
    iconUrl: r.icon_url, managedConfiguration: managed, oemConfig: !!m?.oemConfig, tracks: m?.tracks ?? [], permissions: m?.permissions ?? [],
    minAndroidSdkVersion: m?.minAndroidSdkVersion ?? null,
    metadataRefreshedAt: r.metadata_refreshed_at ? new Date(r.metadata_refreshed_at).toISOString() : null,
    unavailable: !!(m as (AndroidAppMetadata & { unavailableSince?: string }) | null)?.unavailableSince,
  };
}

/** A live Android app of the tenant's own catalog (context tenant), by id or uuid; null otherwise. */
/** forShare: the batch of assignments holds the app live until it commits (archiveAndroidApp waits for it, then sees
 *  the assignment: review AN-E1, never an assignment to an archived app). */
export async function readAndroidApp(q: Knex | Knex.Transaction, tenantId: number, ref: number | string, o: { forUpdate?: boolean; forShare?: boolean } = {}): Promise<AndroidAppRow | null> {
  const b = q('apps').where({ tenant_id: tenantId, platform_family: 'android' }).whereNull('archived_at');
  if (typeof ref === 'number') b.where({ id: ref }); else if (UUID_RE.test(ref)) b.where({ uuid: ref }); else return null;
  if (o.forUpdate) b.forUpdate(); else if (o.forShare) b.forShare();
  return (await b.first(COLUMNS) as AndroidAppRow | undefined) ?? null;
}

export async function listAndroidApps(tenantId: number, actor: DbActor): Promise<AndroidAppView[]> {
  return asTenant(tenantId, actor, async () => {
    const rows = await db('apps').where({ tenant_id: tenantId, platform_family: 'android' }).whereNull('archived_at')
      .orderBy([{ column: 'name' }, { column: 'id' }]).select(COLUMNS) as AndroidAppRow[];
    return rows.map(appView);
  });
}

export interface AddAndroidAppRequest {
  packageName: string;
  /** The kind the console believes (from the iframe's event): checked against Google's answer. */
  kind?: AndroidAppKind;
  languageCode?: string;
}

const routeErrorOfGoogle = (err: unknown): never => {
  if (err instanceof AndroidError && err.kind === 'not_found') throw new AndroidAppError(404, 'androidAppNotFound', 'no such app for the enterprise');
  throw err;
};

/**
 * Adds an Android app to the tenant's catalog: package checked, enterprise linked, app read at Google for this
 * enterprise (outside any transaction), kind derived from its distribution channel, row and audit entry in one
 * transaction. An app already in the catalog is returned as it is (created: false).
 */
export async function addAndroidApp(tenantId: number, userId: number | null, req: AddAndroidAppRequest, auditCtx: AuditWriteContext,
  o: { gateway?: AndroidGateway; actor?: DbActor } = {}): Promise<{ app: AndroidAppView; created: boolean }> {
  const pkg = req.packageName;
  if (!isAndroidPackage(pkg)) throw new AndroidAppError(422, 'androidPackageInvalid');
  if (RESERVED_PACKAGES.has(pkg)) throw new AndroidAppError(422, 'androidPackageReserved');
  if (req.kind !== undefined && !(ANDROID_APP_KINDS as readonly string[]).includes(req.kind)) throw new AndroidAppError(422, 'androidAppKindInvalid');
  const lang = typeof req.languageCode === 'string' && LANG_RE.test(req.languageCode) ? req.languageCode : 'en';
  const gw = o.gateway ?? androidGateway();
  const actor: DbActor = o.actor ?? (userId ? { type: 'user', userId } : APPS_ACTOR);
  return asTenant(tenantId, actor, async () => {
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') throw new AndroidAppError(409, 'androidNotLinked', 'no linked Android enterprise');
    const existing = await readAndroidAppByPackage(db, tenantId, pkg);
    if (existing) return { app: appView(existing), created: false };
    const app = await gw.getApplication(e, pkg, lang).catch(routeErrorOfGoogle);
    const min = minimizeApplication(pkg, app, lang);
    const derived = kindOf(pkg, app.distributionChannel);
    // Distribution channel absent [AR]: the declared kind, never 'play' for a web app's package (kindOf).
    const kind: AndroidAppKind = derived ?? req.kind ?? 'play';
    if (req.kind !== undefined && req.kind !== kind) throw new AndroidAppError(422, 'androidAppKindMismatch', 'the app is not of the declared kind');
    try {
      return await db.transaction(async (trx) => {
        const [row] = await trx('apps').insert({
          tenant_id: tenantId, platform_family: 'android', kind, identifier: pkg, store_id: null, name: min.title,
          publisher: min.author, icon_url: min.iconUrl, supported_platforms: ['android'], license_mode: 'none',
          metadata: JSON.stringify(min.metadata), metadata_refreshed_at: trx.fn.now(), created_by: userId,
        }).returning(COLUMNS) as AndroidAppRow[];
        await audit.appendInTx(trx, {
          tenantId, action: 'android.app_added', target: { type: 'app', id: String(row.id) },
          details: { appId: Number(row.id), packageName: pkg, kind },
        }, auditCtx);
        return { app: appView(row), created: true };
      });
    } catch (err) {
      // Two additions of the same package at once: the second finds the first's row (apps_identifier_uq).
      if ((err as { code?: string }).code === '23505') {
        const row = await readAndroidAppByPackage(db, tenantId, pkg);
        if (row) return { app: appView(row), created: false };
      }
      throw err;
    }
  });
}

async function readAndroidAppByPackage(q: Knex | Knex.Transaction, tenantId: number, pkg: string): Promise<AndroidAppRow | null> {
  return (await q('apps').where({ tenant_id: tenantId, platform_family: 'android', identifier: pkg }).whereNull('archived_at')
    .first(COLUMNS) as AndroidAppRow | undefined) ?? null;
}

/**
 * Reads the app at Google again (once a day at most, unless forced) and replaces its minimized metadata. An app
 * Google no longer serves to the enterprise (404: a private app unpublished, an app withdrawn) keeps its last
 * metadata, marked unavailable. Returns 'fresh' (nothing done), 'refreshed', 'unavailable' or 'gone'.
 */
export async function refreshAndroidAppMetadata(tenantId: number, appId: number, o: { force?: boolean; minAgeMs?: number; gateway?: AndroidGateway; actor?: DbActor } = {}):
  Promise<'fresh' | 'refreshed' | 'unavailable' | 'gone'> {
  const gw = o.gateway ?? androidGateway();
  return asTenant(tenantId, o.actor ?? APPS_ACTOR, async () => {
    const row = await readAndroidApp(db, tenantId, appId);
    if (!row) return 'gone';
    // A forced refresh (the operator's) still waits minAgeMs after the previous one (5 minutes by the route).
    const age = row.metadata_refreshed_at ? Date.now() - new Date(row.metadata_refreshed_at).getTime() : Infinity;
    if (age < (o.force ? o.minAgeMs ?? 0 : METADATA_TTL_MS)) return 'fresh';
    const e = await readEnterprise();
    if (!e || e.state !== 'linked') return 'gone';
    const previous = metadataOf(row.metadata);
    const lang = previous?.languageCode ?? 'en';
    let next: { title: string; author: string | null; iconUrl: string | null; metadata: Record<string, unknown> } | null = null;
    try {
      const app = await gw.getApplication(e, row.identifier, lang);
      const min = minimizeApplication(row.identifier, app, lang);
      next = { ...min, metadata: { ...min.metadata } };
    } catch (err) {
      if (!(err instanceof AndroidError && err.kind === 'not_found')) throw err;
    }
    await db.transaction(async (trx) => {
      const patch = next
        ? { name: next.title, publisher: next.author, icon_url: next.iconUrl, metadata: JSON.stringify(next.metadata) }
        : { metadata: JSON.stringify({ ...(previous ?? { v: 1 }), unavailableSince: new Date().toISOString() }) };
      await trx('apps').where({ tenant_id: tenantId, id: row.id }).whereNull('archived_at')
        .update({ ...patch, metadata_refreshed_at: trx.fn.now(), updated_at: trx.fn.now() });
    });
    return next ? 'refreshed' : 'unavailable';
  });
}

/** After a failed read at Google (other than 404), an app is read again an hour later, not at the next minute. */
export const METADATA_RETRY_MS = 3_600_000;

/**
 * android.app-metadata of a tenant: the apps whose metadata are a day old or never read, 50 at a time. Review AN-E1: an
 * app whose read fails (anything but a 404 and Google's quota) is put off for an hour (metadata_refreshed_at moved so
 * that it is due again in METADATA_RETRY_MS) and the run goes on with the next apps: the maintenance sends the job
 * again each minute while an app is due, and one app in error would otherwise be read every minute and keep the apps
 * after it from ever being read. Google's quota (rate_limited) stops the run without putting anything off.
 */
export async function refreshDueAndroidApps(tenantId: number, o: { gateway?: AndroidGateway; limit?: number } = {}): Promise<{ refreshed: number; unavailable: number; failed: number; remaining: boolean }> {
  const limit = Math.max(1, Math.min(o.limit ?? 50, 200));
  const due = await asTenant(tenantId, APPS_ACTOR, () => db('apps').where({ tenant_id: tenantId, platform_family: 'android' })
    .whereNull('archived_at')
    .where((w) => w.whereNull('metadata_refreshed_at').orWhere('metadata_refreshed_at', '<', db.raw("now() - interval '24 hours'")))
    .orderByRaw('metadata_refreshed_at ASC NULLS FIRST, id').limit(limit + 1).pluck('id')) as number[];
  const out = { refreshed: 0, unavailable: 0, failed: 0, remaining: due.length > limit };
  for (const id of due.slice(0, limit)) {
    let r: Awaited<ReturnType<typeof refreshAndroidAppMetadata>>;
    try {
      r = await refreshAndroidAppMetadata(tenantId, Number(id), { gateway: o.gateway });
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'rate_limited') throw err;
      out.failed++;
      await asTenant(tenantId, APPS_ACTOR, () => db('apps').where({ tenant_id: tenantId, id: Number(id) }).whereNull('archived_at').update({
        metadata_refreshed_at: db.raw("now() - interval '1 millisecond' * ?", [METADATA_TTL_MS - METADATA_RETRY_MS]),
      }));
      continue;
    }
    if (r === 'refreshed') out.refreshed++;
    if (r === 'unavailable') out.unavailable++;
  }
  return out;
}

/** Archives an app of the catalog; refused while an assignment names it (its removal goes through the assignments,
 *  their preview and their guard). */
export async function archiveAndroidApp(tenantId: number, userId: number, ref: string, auditCtx: AuditWriteContext): Promise<'archived'> {
  return asTenant(tenantId, { type: 'user', userId }, () => db.transaction(async (trx) => {
    const row = await readAndroidApp(trx, tenantId, ref, { forUpdate: true });
    if (!row) throw new AndroidAppError(404, 'notFound', 'app not found');
    const assigned = await trx('assignments').where({ resource_type: 'app', resource_tenant_id: tenantId, resource_id: row.id }).first('id');
    if (assigned) throw new AndroidAppError(409, 'androidAppAssigned', 'the app is still assigned');
    await trx('apps').where({ tenant_id: tenantId, id: row.id }).update({ archived_at: trx.fn.now(), updated_at: trx.fn.now() });
    await audit.appendInTx(trx, {
      tenantId, action: 'android.app_archived', target: { type: 'app', id: String(row.id) },
      details: { appId: Number(row.id), packageName: row.identifier, kind: row.kind },
    }, auditCtx);
    return 'archived' as const;
  }));
}
