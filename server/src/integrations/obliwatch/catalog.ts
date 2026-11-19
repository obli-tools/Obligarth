import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  OBLIWATCH_AI_CATALOG_MAX, OBLIWATCH_BUNDLE_ID_RE, OBLIWATCH_SLUG_RE, type ObliwatchCatalogPlatform, type ObliwatchCatalogStatus,
} from '@obligarth/shared';
import { db } from '../../db';
import { asIdentity, type DbActor } from '../../db/context';
import { forEachTenant } from '../../db/tenantContext';
import type { JobContext, JobResult } from '../../jobs/types';
import { logger } from '../../utils/logger';
import { OBLIWATCH_ACTOR, obliwatchIntegrationEnabled } from './config';
import { obliwatchClient } from './push';

// =============================================================================
// The AI catalog of Obliwatch (brief GTH-06; plan L4): the bundle identifiers of the mobile AI apps, compared by
// GET /apps/ai-summary with the inventory of the devices.
//   - the daily job integrations.obliwatch.catalog-sync (registered with OBLIWATCH_INTEGRATION=on only) reads
//     GET {obliwatch}/api/external/v1/catalogues/ai-domains with a fresh Obligate token of the pair obligarth:obliwatch
//     (client.ts, aud obliwatch), whose `ost` is the slug of a tenant that consented to be read (none: nothing is
//     fetched). No tenant data leaves: the request has no body.
//   - tolerant parser: {version, bundles:[{platform:'android'|'ios', bundleId, name}]}, at the top or under `data`;
//     another platform, a malformed bundle id (OBLIWATCH_BUNDLE_ID_RE) or a duplicate is skipped; more than 5 000
//     bundles: the catalog is refused (the previous one is kept). No version: the hash of the bundles stands for it.
//   - conditional read: the ETag of the stored catalog goes as If-None-Match; a 304 only refreshes fetched_at.
//   - stored in obliwatch_ai_catalog (one row, class catalog: written in the identity context of i:obliwatch). The
//     route of Obliwatch does not exist yet: a 404 (or 401/403 while the pair is not configured) leaves the stored
//     catalog as it is and records the status, never a failure of the job (no daily alert for a known gap).
// =============================================================================

export const CATALOG_QUEUE = 'integrations.obliwatch.catalog-sync';
export const CatalogJobPayload = z.object({}).strict();

/** A catalog older than this is served as 'stale'. */
const STALE_MS = 3 * 86_400_000;
const NAME_MAX = 200;

export interface CatalogBundle { platform: ObliwatchCatalogPlatform; bundleId: string; name: string | null }

export type ParsedCatalog =
  | { ok: true; version: string; bundles: CatalogBundle[]; skipped: number }
  | { ok: false; reason: string };

const cleanName = (v: unknown): string | null => {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, NAME_MAX);
  return s || null;
};

/** The catalog in an answer of Obliwatch, validated field by field (never trusted as is). */
export function parseCatalog(json: unknown): ParsedCatalog {
  let o = json && typeof json === 'object' ? json as Record<string, unknown> : null;
  if (o && !Array.isArray(o.bundles) && o.data && typeof o.data === 'object') o = o.data as Record<string, unknown>;
  if (!o || !Array.isArray(o.bundles)) return { ok: false, reason: 'no_bundles' };
  if (o.bundles.length > OBLIWATCH_AI_CATALOG_MAX) return { ok: false, reason: 'too_many_bundles' };
  const seen = new Set<string>();
  const bundles: CatalogBundle[] = [];
  let skipped = 0;
  for (const raw of o.bundles) {
    const b = raw && typeof raw === 'object' ? raw as Record<string, unknown> : {};
    const platform = typeof b.platform === 'string' ? b.platform.toLowerCase() : '';
    const bundleId = typeof b.bundleId === 'string' ? b.bundleId.trim() : '';
    if ((platform !== 'android' && platform !== 'ios') || bundleId.length > 255 || !OBLIWATCH_BUNDLE_ID_RE.test(bundleId)) { skipped++; continue; }
    const key = `${platform}|${bundleId}`;
    if (seen.has(key)) { skipped++; continue; }
    seen.add(key);
    bundles.push({ platform, bundleId, name: cleanName(b.name) });
  }
  bundles.sort((a, b) => (a.platform === b.platform ? (a.bundleId < b.bundleId ? -1 : a.bundleId > b.bundleId ? 1 : 0) : a.platform < b.platform ? -1 : 1));
  const v = typeof o.version === 'string' || typeof o.version === 'number' ? String(o.version).trim() : '';
  const version = /^[\x21-\x7e]{1,128}$/.test(v) ? v
    : `sha256:${createHash('sha256').update(JSON.stringify(bundles)).digest('hex').slice(0, 16)}`;
  return { ok: true, version, bundles, skipped };
}

// ── Storage ─────────────────────────────────────────────────────────────────────────────────────────────

export interface StoredCatalog {
  version: string | null;
  bundles: CatalogBundle[];
  fetchedAt: Date | null;
  status: ObliwatchCatalogStatus;
}

let cached: { key: string; catalog: StoredCatalog } | null = null;

/** Tests: forget the catalog kept in memory. */
export function _resetCatalogCacheForTests(): void { cached = null; }

/**
 * The stored catalog (in the caller's database context: the table is readable everywhere). The bundles are kept in
 * memory per fetched_at (the row is read whole only when it changed).
 */
export async function loadCatalog(now = Date.now()): Promise<StoredCatalog> {
  const head = await db('obliwatch_ai_catalog').where({ id: 1 }).first('version', 'fetched_at') as { version: string | null; fetched_at: Date | null } | undefined;
  if (!head || !head.fetched_at) return { version: null, bundles: [], fetchedAt: null, status: 'unavailable' };
  const fetchedAt = new Date(head.fetched_at);
  const key = `${fetchedAt.toISOString()}|${head.version ?? ''}`;
  let catalog = cached?.key === key ? cached.catalog : null;
  if (!catalog) {
    const row = await db('obliwatch_ai_catalog').where({ id: 1 }).first('bundles') as { bundles: unknown } | undefined;
    // Validated again: the table is written by this module only, read as untrusted all the same.
    const parsed = parseCatalog({ version: head.version ?? undefined, bundles: Array.isArray(row?.bundles) ? row!.bundles : [] });
    catalog = { version: head.version ?? null, bundles: parsed.ok ? parsed.bundles : [], fetchedAt, status: 'ok' };
    cached = { key, catalog };
  }
  return { ...catalog, status: now - fetchedAt.getTime() > STALE_MS ? 'stale' : 'ok' };
}

async function writeCatalog(values: Record<string, unknown>): Promise<void> {
  await asIdentity(OBLIWATCH_ACTOR, () => db('obliwatch_ai_catalog').insert({ id: 1, ...values }).onConflict('id').merge(Object.keys(values)));
}

// ── The job ─────────────────────────────────────────────────────────────────────────────────────────────

/** The slug of a tenant that consented to be read (and fits Obliwatch's format), or null. */
async function consentingSlug(actor: DbActor): Promise<string | null> {
  let slug: string | null = null;
  await forEachTenant(actor, async (tenantId) => {
    if (slug) return;
    const c = await db('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first('read_enabled') as { read_enabled?: boolean } | undefined;
    if (c?.read_enabled !== true) return;
    const t = await db('tenants').where({ id: tenantId }).first('slug') as { slug?: string } | undefined;
    if (t?.slug && OBLIWATCH_SLUG_RE.test(t.slug)) slug = t.slug;
  });
  return slug;
}

export interface CatalogSyncResult { status: string; bundles?: number; skipped?: number; version?: string }

/** Fetches and stores the catalog (the job's work; the tests call it directly). Throws on a transient failure only. */
export async function syncCatalog(actor: DbActor = OBLIWATCH_ACTOR): Promise<CatalogSyncResult> {
  if (!obliwatchIntegrationEnabled()) return { status: 'integration_off' };
  const slug = await consentingSlug(actor);
  if (!slug) return { status: 'no_consent' };
  // The ETag of the stored catalog (only when one is stored): sent as If-None-Match, a 304 keeps the bundles as they are.
  const head = await asIdentity(OBLIWATCH_ACTOR, () => db('obliwatch_ai_catalog').where({ id: 1 }).first('etag', 'fetched_at')) as { etag: string | null; fetched_at: Date | null } | undefined;
  const storedEtag = head?.fetched_at && head.etag ? head.etag : null;
  const r = await obliwatchClient.aiCatalog(slug, storedEtag);
  const at = new Date();
  if (r.ok && r.notModified) {
    // Unchanged at Obliwatch: the stored catalog is fresh again (no longer 'stale').
    await writeCatalog({ fetched_at: at, checked_at: at, last_status: 'ok', etag: r.etag });
    return { status: 'not_modified' };
  }
  if (!r.ok) {
    // The route of Obliwatch is not built yet (404), or the pair is not configured at Obligate / Obliwatch (401, 403):
    // a known state, recorded, the stored catalog kept. Anything else is retried by the job.
    if (r.status === 404 || r.status === 401 || r.status === 403) {
      const status = r.status === 404 ? 'absent' : 'refused';
      await writeCatalog({ checked_at: at, last_status: status });
      logger.info({ status: r.status }, 'obliwatch catalog: not available at Obliwatch (the stored catalog is kept)');
      return { status };
    }
    await writeCatalog({ checked_at: at, last_status: 'failed' });
    throw new Error(`obliwatch catalog not fetched: ${r.error}`);
  }
  const parsed = parseCatalog(r.json);
  if (!parsed.ok) {
    await writeCatalog({ checked_at: at, last_status: parsed.reason });
    logger.warn({ reason: parsed.reason }, 'obliwatch catalog: answer refused (the stored catalog is kept)');
    return { status: parsed.reason };
  }
  await writeCatalog({
    version: parsed.version, etag: r.etag, bundles: JSON.stringify(parsed.bundles), bundle_count: parsed.bundles.length,
    fetched_at: at, checked_at: at, last_status: 'ok',
  });
  cached = null;
  return { status: 'ok', bundles: parsed.bundles.length, skipped: parsed.skipped, version: parsed.version };
}

export async function runCatalogJob(ctx: JobContext<z.infer<typeof CatalogJobPayload>>): Promise<JobResult> {
  const r = await syncCatalog(ctx.dbActor);
  return { output: { ...r } };
}
