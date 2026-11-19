import type { Request, Response } from 'express';
import type {
  ObliwatchAiSummaryItem, ObliwatchAiSummaryResponse, ObliwatchAppsCoverage, ObliwatchCatalogPlatform,
} from '@obligarth/shared';
import { db } from '../../db';
import { asTenant } from '../../db/context';
import { auditRead } from './audit';
import { sendError } from './auth';
import { loadCatalog } from './catalog';
import { OBLIWATCH_ACTOR } from './config';
import { readConsent } from './consent';
import { appsCoverage } from './coverage';
import { CollectedCache, factsOf, personalSide } from './devices';
import { obliwatchClient } from './push';

// =============================================================================
// GET /apps/ai-summary[?nominative=1] (brief GTH-06; plan L4), app token + consent 'read' (router): the AI apps of
// Obliwatch's catalog (catalog.ts) seen on the devices of the tenant of `ost`, in AGGREGATES by default:
//   {catalogVersion, catalogStatus, catalogFetchedAt, nominative, items:[{bundleId, platform, devices}],
//    coverage:{full, managed_only, none}}
// The devices: those of the tenant not unenrolled. An app counts on a device when it is MANAGED, or when every app of
// the device is collected (apps coverage 'full') on a work-only device; an app of the personal side (a personal
// device, a work profile, a User Enrollment) is never counted unless it is managed (devices.ts personalSide). The
// catalog's platform 'android' matches the Android devices, 'ios' every Apple device. `coverage` counts the devices per
// apps coverage, so that a zero is read with what Obligarth sees. No catalog fetched yet (Obliwatch's route does not
// exist yet): catalogVersion null, items [], catalogStatus 'unavailable'.
// The nominative form (?nominative=1) adds the uuids of the devices to each item (never a name), and only when the
// tenant turned nominativeAiApps on (else 403 consent_required) AND Obliwatch's producer-config attests it
// (attestations.nominativeAiApps true; absent or false: 403 attestation_required; producer-config unreachable: 503
// attestation_unavailable). Journaled obliwatch.read with the counts only.
// =============================================================================

const ENDPOINT = 'apps/ai-summary';

type Row = Record<string, any>;

/** The devices of the tenant and the facts of their apps coverage (never an identifier but the uuid, the join key). */
const DEVICES_SQL = String.raw`
SELECT d.id, d.uuid::text AS uuid, d.platform, d.management_channel, d.ownership, d.management_mode,
       CASE WHEN an.released_at IS NULL THEN an.security_posture END AS amapi_posture,
       an.last_status_report_at AS amapi_report_at,
       la.last_inventory_at AS agent_inventory_at,
       ap.last_apps_at AS apple_apps_at, ap.last_managed_apps_at AS apple_managed_apps_at,
       EXISTS (SELECT 1 FROM obligarth.device_apps x WHERE x.tenant_id = d.tenant_id AND x.device_id = d.id) AS has_apps
  FROM obligarth.devices d
  LEFT JOIN obligarth.android_devices an ON an.tenant_id = d.tenant_id AND an.device_id = d.id
  LEFT JOIN obligarth.legacy_agent_devices la ON la.tenant_id = d.tenant_id AND la.device_id = d.id
  LEFT JOIN obligarth.apple_devices ap ON ap.tenant_id = d.tenant_id AND ap.device_id = d.id
 WHERE d.tenant_id = ? AND d.enrollment_state <> 'unenrolled'`;

const familyOf = (platform: string): ObliwatchCatalogPlatform => (platform === 'android' ? 'android' : 'ios');

/**
 * The gate of the nominative view of the AI apps (GTH-06): the tenant's consent nominativeAiApps AND Obliwatch's
 * attestation in producer-config (cached 5 minutes per tenant by the client). Shared by ai-summary?nominative=1 and by
 * GET /devices/:uuid/apps (devices.ts), which withholds the catalog's bundles unless the gate is 'ok', so that the
 * per-device list never rebuilds what the nominative view refuses.
 */
export async function nominativeAiAppsGate(tenantId: number, ost: string):
  Promise<'ok' | 'consent_required' | 'attestation_required' | 'attestation_unavailable'> {
  const c = await readConsent(tenantId);
  if (!c.nominativeAiApps) return 'consent_required';
  const cfg = await obliwatchClient.producerConfig(ost);
  if (!cfg.ok) return 'attestation_unavailable';
  return cfg.config.nominativeAiAppsAttested === true ? 'ok' : 'attestation_required';
}

export async function aiSummary(req: Request, res: Response): Promise<void> {
  const caller = req.obliwatch!;
  const raw = req.query.nominative;
  if (raw !== undefined && raw !== '0' && raw !== '1') { sendError(res, 400, 'nominative_invalid', 'nominative: 0 or 1'); return; }
  const nominative = raw === '1';
  if (nominative) {
    const gate = await nominativeAiAppsGate(caller.tenantId, caller.ost);
    if (gate === 'consent_required') { sendError(res, 403, 'consent_required', 'The tenant has not consented to the nominative view'); return; }
    if (gate === 'attestation_unavailable') { sendError(res, 503, 'attestation_unavailable', 'The attestation of the tenant could not be read at Obliwatch'); return; }
    if (gate === 'attestation_required') {
      sendError(res, 403, 'attestation_required', 'Obliwatch does not attest the nominative view for this tenant'); return;
    }
  }

  const body = await asTenant(caller.tenantId, OBLIWATCH_ACTOR, async (): Promise<ObliwatchAiSummaryResponse> => {
    const catalog = await loadCatalog();
    const devices = (await db.raw(DEVICES_SQL, [caller.tenantId]) as { rows: Row[] }).rows;
    const collected = new CollectedCache(caller.tenantId);
    const coverage: Record<ObliwatchAppsCoverage, number> = { full: 0, managed_only: 0, none: 0 };
    const byId = new Map<number, { row: Row; apps: ObliwatchAppsCoverage; everything: boolean }>();
    for (const r of devices) {
      const fields = await collected.get(String(r.management_channel), String(r.ownership), String(r.management_mode));
      const apps = appsCoverage(factsOf(r), fields);
      coverage[apps]++;
      byId.set(Number(r.id), { row: r, apps, everything: apps === 'full' && !personalSide(String(r.ownership), String(r.management_mode)) });
    }
    const items: ObliwatchAiSummaryItem[] = [];
    if (catalog.bundles.length > 0 && devices.length > 0) {
      const platformsOf = new Map<string, Set<ObliwatchCatalogPlatform>>();
      for (const b of catalog.bundles) {
        let s = platformsOf.get(b.bundleId);
        if (!s) { s = new Set(); platformsOf.set(b.bundleId, s); }
        s.add(b.platform);
      }
      // The inventory rows of the catalog's bundles only (index device_apps_identifier (tenant_id, identifier)).
      const seen = await db('device_apps').where('tenant_id', caller.tenantId).whereIn('identifier', [...platformsOf.keys()])
        .select('device_id', 'identifier', 'managed') as Array<{ device_id: number; identifier: string; managed: boolean }>;
      const hits = new Map<string, { bundleId: string; platform: ObliwatchCatalogPlatform; uuids: Set<string> }>();
      for (const a of seen) {
        const d = byId.get(Number(a.device_id));
        if (!d || d.apps === 'none') continue;
        // Never an app of the personal side, never an app the profile did not collect: managed, or all apps seen.
        if (a.managed !== true && !d.everything) continue;
        const platform = familyOf(String(d.row.platform));
        if (!platformsOf.get(a.identifier)?.has(platform)) continue;
        const key = `${platform}|${a.identifier}`;
        let h = hits.get(key);
        if (!h) { h = { bundleId: a.identifier, platform, uuids: new Set() }; hits.set(key, h); }
        h.uuids.add(String(d.row.uuid).toLowerCase());
      }
      for (const h of [...hits.values()].sort((x, y) => y.uuids.size - x.uuids.size || (x.bundleId < y.bundleId ? -1 : x.bundleId > y.bundleId ? 1 : 0))) {
        items.push({
          bundleId: h.bundleId, platform: h.platform, devices: h.uuids.size,
          ...(nominative ? { deviceUuids: [...h.uuids].sort() } : {}),
        });
      }
    }
    return {
      catalogVersion: catalog.version,
      catalogStatus: catalog.status,
      catalogFetchedAt: catalog.fetchedAt ? catalog.fetchedAt.toISOString() : null,
      nominative,
      items,
      coverage,
    };
  });
  auditRead(req, caller.tenantId, ENDPOINT, {
    count: body.items.length, devices: body.items.reduce((n, i) => n + i.devices, 0), nominative, catalogVersion: body.catalogVersion,
  });
  res.json(body);
}
