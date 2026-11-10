import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { LEGACY_AGENT_TOKEN_BOUNDS, SITE_LIMITS as L, SITE_SHEET_DEFAULTS, SITE_VALUE_KEY_RE, type SiteEnrollmentSheet } from '@obligarth/shared';
import { audit } from '../audit';
import { AppError } from '../middleware/errorHandler';
import { adoptHeaderStepUpProof } from '../middleware/captureStepUpProof';
import { requireTenantCapability } from '../middleware/rbac';
import { permissionService } from '../services/permission.service';
import { parseRequestDeviceId } from '../services/deviceScope.service';
import { consumeBatch, insertBatch } from './batches';
import {
  CONSOLE_IMPORT_TOOL, SiteChangeBody, guardSiteWrite, prevDigestOf, requireGroupWrite, requirePolicyManage, whoOf,
} from './guard';
import { checkSite } from './model';
import {
  applyFromDevices, applyImport, archiveSite, createSite, fromDevicesImpact, fromDevicesUpdatedSites, importImpactChange, importPlanNow,
  importUpdatedSites, listSites, managedDevicesOfSites, planChanged, previewFromDevices, previewImport, requireSiteReach, setDevicesSite,
  siteAfter, siteChanges, siteDetail, sitePolicyImpact, siteRow, siteValueKeys, updateSite, usableSiteInTx, type Visible,
} from './service';
import { db } from '../db';
import { agentApkUrl, enrollmentQrPng, issueEnrollmentToken, tokenLimiter } from '../legacyAgent/tokens';

// =============================================================================
// Console API of the sites (lot P1-SITE §2.3), mounted at /api/sites in the tenant of the session; the site of one
// device at /api/mdm/devices/:id/site (createDeviceSiteRouter, before the registry's router):
//   GET    /sites?q=&archived=          the sites, with the counts of their devices by state (any member: the devices the
//                                       caller sees)
//   GET    /sites/value-keys            the keys of the values of the sites (variable picker of the templates)
//   GET    /sites/:id                   one site, its devices, their state and what to do
//   POST   /sites                       devices.manage: a site (write access on the group it names)
//   PATCH  /sites/:id                   devices.manage: its fields (values replaced as a whole)
//   POST   /sites/:id/archive|restore   devices.manage: an archived site keeps its row, refused while it has devices
//   POST   /sites/:id/devices           devices.manage: { deviceIds[] } attached (500 at most, write access on each)
//   POST   /sites/import?dryRun=&digest= devices.manage: a CSV file (text/csv, 2 MiB): the plan (dry run, the default,
//                                       with its digest and policy impact), or applied with dryRun=false (the digest of
//                                       the dry run shown: 409 planChanged when the plan made again differs)
//   POST   /sites/from-devices          devices.manage: { codeKey, nameKey, valuesKeys, dryRun, digest } the sites made
//                                       from the custom fields of the devices, the devices attached (dry run by default)
//   POST   /sites/:id/enrollment-sheet  mdm.enrollment.manage: { label?, days?, maxUses? } the printable sheet of the site
//                                       (lot P1-QR §3.2): a token of the site in its group (30 days, 5 phones by
//                                       default), its QR code, the sheets of the site still active revoked; shown once
//   PUT    /mdm/devices/:id/site        devices.manage: { siteId | null }
// A write that changes what the templates of a site's devices read (code, name, city or values of a site, an import
// that updates sites, the sites from the custom fields) is guarded as the import of per-device values (sites/guard.ts):
// mdm.policies.manage, the caller's rights on every device of the sites changed, the restrictable action sites.apply
// (a second factor), a second person beyond the publication thresholds (202 pending_approval).
// A change of site never moves the device: the answer names the group of the site and the devices outside it, the
// console then asks for the guarded move (POST /api/mdm/devices/:id/group or the batch, S12).
// =============================================================================

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

/** The devices the caller sees ('all': an administrator). */
async function visibleOf(req: Request): Promise<Visible> {
  if (req.session.role === 'admin') return 'all';
  return permissionService.getVisibleDeviceIds(req.session.userId!, false);
}

/** Every device is one of the tenant the caller may write, else 404 (unknown or unseen) or 403. */
export async function requireDevicesWrite(req: Request, tenantId: number, ids: number[]): Promise<void> {
  const unique = [...new Set(ids)];
  const found = (await db('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [unique]).pluck('id') as number[]).map(Number);
  if (found.length !== unique.length) throw new AppError(404, 'Device not found');
  if (req.session.role === 'admin') return;
  const userId = req.session.userId!;
  for (const id of unique) {
    if (!(await permissionService.canReadDevice(userId, id, false))) throw new AppError(404, 'Device not found');
    if (!(await permissionService.canWriteDevice(userId, id, false))) throw new AppError(403, 'Insufficient permissions');
  }
}

const DevicesBody = z.object({ deviceIds: z.array(z.number().int().positive()).min(1).max(L.bulkDevices) }).strict();
const DeviceSiteBody = z.object({ siteId: z.string().uuid().nullable() }).strict();
const keyName = z.string().regex(SITE_VALUE_KEY_RE);
const digestText = z.string().regex(/^[0-9a-f]{64}$/);
const FromDevicesBody = z.object({
  codeKey: keyName.optional(), nameKey: keyName.optional(), valuesKeys: z.array(keyName).max(L.valuesMax).optional(),
  dryRun: z.boolean().optional(), digest: digestText.optional(),
}).strict();
const SheetBody = z.object({
  label: z.string().trim().min(1).max(100).optional(),
  days: z.number().int().min(1).max(LEGACY_AGENT_TOKEN_BOUNDS.daysMax).optional(),
  maxUses: z.number().int().min(1).max(LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax).optional(),
}).strict();
const isDryRun = (v: unknown): boolean => !(v === 'false' || v === '0' || v === false);
/** The digest of the dry run a console apply sends back (?digest=), or none. */
function digestOfQuery(v: unknown): string | undefined {
  if (v === undefined || v === '') return undefined;
  const p = digestText.safeParse(v);
  if (!p.success) throw new AppError(400, 'Invalid digest', 'invalidRequest');
  return p.data;
}

export function createSitesRouter(): Router {
  const router = Router();
  const manage = requireTenantCapability('devices.manage');

  router.get('/', wrap(async (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q.slice(0, 200) : undefined;
    const archived = req.query.archived === 'true' || req.query.archived === '1';
    res.json({ success: true, data: await listSites(req.tenantId!, { q, archived, visible: await visibleOf(req) }) });
  }));

  router.get('/value-keys', wrap(async (req, res) => {
    res.json({ success: true, data: await siteValueKeys(req.tenantId!) });
  }));

  router.post('/import', manage, express.text({ type: ['text/csv', 'text/plain', 'application/csv'], limit: L.importBytes }), wrap(async (req, res) => {
    // A raw body: the proof of a second factor comes in the header (the client sends the same bytes again).
    adoptHeaderStepUpProof(req);
    const csv = typeof req.body === 'string' ? req.body : '';
    if (!csv.trim()) throw new AppError(400, 'A CSV file is required (Content-Type text/csv)', 'invalidRequest');
    const lines = csv.split(/\r?\n/).filter((l) => l.trim()).length;
    if (lines - 1 > L.importRows) throw new AppError(413, `At most ${L.importRows} lines per import`, 'importTooLarge');
    const tenantId = req.tenantId!;
    res.setHeader('Cache-Control', 'no-store');
    if (isDryRun(req.query.dryRun)) { res.json({ success: true, data: await previewImport(tenantId, csv) }); return; }
    const expected = digestOfQuery(req.query.digest);
    const { plan, existing } = await importPlanNow(tenantId, csv);
    if (expected !== undefined && plan.result.digest !== expected) throw planChanged();
    const updated = importUpdatedSites(plan);
    const who = whoOf(req);
    const ctx = await audit.fromRequest(req, tenantId);
    // Only new sites: no device reads them yet, nothing rendered changes.
    if (!updated.length) {
      res.json({ success: true, data: await applyImport(tenantId, csv, ctx, { expectDigest: plan.result.digest, source: 'console', who }) });
      return;
    }
    await requirePolicyManage(req, tenantId);
    await requireSiteReach(db, tenantId, who, updated);
    const impact = await sitePolicyImpact(db, tenantId, importImpactChange(plan, existing));
    // The CSV text is kept for a second person (too large for the sealed part of an approval); consumed by the apply.
    const batchId = await db.transaction((trx) => insertBatch(trx, {
      tenantId, userId: who.userId, tool: CONSOLE_IMPORT_TOOL, request: { csv }, digest: plan.result.digest,
    }));
    const ok = await guardSiteWrite(req, res, {
      tenantId, deviceIds: await managedDevicesOfSites(db, tenantId, updated), impact,
      description: `Import sites: ${plan.result.created} to create, ${plan.result.updated} to update (${impact} device(s) whose agent policy changes)`,
      payload: { op: 'import', created: plan.result.created, updated: plan.result.updated, codes: plan.writes.map((w) => w.site.code).slice(0, 100) },
      sealed: { op: 'import', batchId, digest: plan.result.digest },
    });
    if (!ok) {
      // A second factor asked (the request comes again): the batch kept for nobody goes. Filed for approval: it stays.
      if (res.statusCode !== 202) await db('site_batches').where({ tenant_id: tenantId, id: batchId }).delete().catch(() => undefined);
      return;
    }
    res.json({ success: true, data: await applyImport(tenantId, csv, ctx, { expectDigest: plan.result.digest, source: 'console', who },
      (trx) => consumeBatch(trx, tenantId, batchId)) });
  }));

  router.post('/from-devices', manage, wrap(async (req, res) => {
    const b = body(FromDevicesBody, req);
    const tenantId = req.tenantId!;
    const keys = { code: b.codeKey ?? 'codeMag', name: b.nameKey ?? 'nameMag', values: b.valuesKeys ?? [] };
    const visible = await visibleOf(req);
    const plan = await previewFromDevices(tenantId, keys, visible);
    if (b.dryRun !== false) { res.json({ success: true, data: { ...plan.result, policyImpact: await fromDevicesImpact(tenantId, plan) } }); return; }
    if (b.digest !== undefined && plan.result.digest !== b.digest) throw planChanged();
    const who = whoOf(req);
    const canWrite = (ids: number[]): Promise<void> => (ids.length ? requireDevicesWrite(req, tenantId, ids) : Promise.resolve());
    const ctx = await audit.fromRequest(req, tenantId);
    const apply = () => applyFromDevices(tenantId, keys, visible, ctx, { expectDigest: plan.result.digest, source: 'console', canWrite, who });
    const updated = fromDevicesUpdatedSites(plan);
    const attach = plan.attach.map((a) => a.deviceId);
    if (!plan.writes.length && !attach.length) { res.json({ success: true, data: await apply() }); return; }
    await requirePolicyManage(req, tenantId);
    await canWrite(attach);
    await requireSiteReach(db, tenantId, who, updated);
    const impact = await fromDevicesImpact(tenantId, plan);
    const created = plan.writes.filter((w) => w.kind === 'create').length;
    const ok = await guardSiteWrite(req, res, {
      tenantId, deviceIds: [...new Set([...attach, ...(await managedDevicesOfSites(db, tenantId, updated))])], impact,
      description: `Sites from the custom fields ${keys.code} / ${keys.name}: ${created} site(s) to create, ${updated.length} to complete, ${attach.length} device(s) to attach (${impact} device(s) whose agent policy changes)`,
      payload: { op: 'from_devices', keys, created, completed: updated.length, attach: attach.length },
      sealed: { op: 'from_devices', keys, digest: plan.result.digest },
    });
    if (!ok) return;
    res.json({ success: true, data: await apply() });
  }));

  router.get('/:id', wrap(async (req, res) => {
    res.json({ success: true, data: await siteDetail(req.tenantId!, String(req.params.id), await visibleOf(req)) });
  }));

  router.post('/', manage, wrap(async (req, res) => {
    const b = body(SiteChangeBody, req);
    const tenantId = req.tenantId!;
    await requireGroupWrite(whoOf(req), b.groupId);
    const row = await createSite(tenantId, b, await audit.fromRequest(req, tenantId));
    res.status(201).json({ success: true, data: await siteDetail(tenantId, row.id, await visibleOf(req)) });
  }));

  router.patch('/:id', manage, wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    // The site of the route first: an unknown one (or another tenant's) answers 404 whatever the body.
    const prev = await siteRow(db, tenantId, String(req.params.id));
    const b = body(SiteChangeBody, req);
    const who = whoOf(req);
    const ctx = await audit.fromRequest(req, tenantId);
    const { site, issues } = checkSite(b, false);
    const diff = issues.length ? null : siteChanges(prev, site);
    if (diff?.fields.includes('groupId')) await requireGroupWrite(who, site.groupId);
    const prevDigest = prevDigestOf(prev);
    // The site the guard looked at is the one changed (another write in between: planChanged).
    const before = async (_trx: unknown, current: typeof prev): Promise<void> => { if (prevDigestOf(current) !== prevDigest) throw planChanged(); };
    if (diff?.rendered && !prev.archived) {
      await requirePolicyManage(req, tenantId);
      await requireSiteReach(db, tenantId, who, [prev.id]);
      const impact = await sitePolicyImpact(db, tenantId, { sites: [siteAfter(prev, site)] });
      const ok = await guardSiteWrite(req, res, {
        tenantId, deviceIds: await managedDevicesOfSites(db, tenantId, [prev.id]), impact,
        description: `Change the site ${prev.code}: ${diff.fields.join(', ')}${diff.valueKeys.length ? ` (${diff.valueKeys.slice(0, 10).join(', ')})` : ''} (${impact} device(s) whose agent policy changes)`,
        payload: { op: 'update', siteId: prev.id, code: prev.code, fields: diff.fields, valueKeys: diff.valueKeys },
        sealed: { op: 'update', siteId: prev.id, body: b, prevDigest },
      });
      if (!ok) return;
    }
    const row = await updateSite(tenantId, prev.id, b, ctx, undefined, { who, before });
    res.json({ success: true, data: await siteDetail(tenantId, row.id, await visibleOf(req)) });
  }));

  for (const [path, archived] of [['archive', true], ['restore', false]] as const) {
    router.post(`/:id/${path}`, manage, wrap(async (req, res) => {
      const tenantId = req.tenantId!;
      const row = await archiveSite(tenantId, String(req.params.id), await audit.fromRequest(req, tenantId), archived);
      res.json({ success: true, data: await siteDetail(tenantId, row.id, await visibleOf(req)) });
    }));
  }

  // The enrollment sheet (lot P1-QR §3.2): the capability of the tokens, as POST /api/legacy-agent/tokens. The site is
  // read again under the sites lock in the token's transaction (an archive in between: 409 siteArchived).
  router.post('/:id/enrollment-sheet', requireTenantCapability('mdm.enrollment.manage'), tokenLimiter, wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    // The site of the route first: an unknown one (or another tenant's) answers 404 whatever the body.
    const site = await siteRow(db, tenantId, String(req.params.id));
    const b = body(SheetBody, req);
    let current = site;
    // No group on the sheet: the enrollment reads the site's (a change of its group reaches the sheets already printed).
    const { token, revokedPrevious } = await issueEnrollmentToken(req, tenantId, {
      label: b.label ?? `Fiche ${site.code}`.slice(0, 100), groupId: null, siteId: site.id, siteSheet: true,
      days: b.days ?? SITE_SHEET_DEFAULTS.days, maxUses: b.maxUses ?? SITE_SHEET_DEFAULTS.maxUses,
    }, async (trx) => { current = await usableSiteInTx(trx, tenantId, site.id); });
    const apkUrl = agentApkUrl();
    const out: SiteEnrollmentSheet = {
      site: { id: current.id, code: current.code, name: current.name, city: current.city }, token, revokedPrevious,
      apkUrl, apkQrPng: apkUrl ? await enrollmentQrPng(apkUrl) : null,
    };
    res.setHeader('Cache-Control', 'no-store');
    res.status(201).json({ success: true, data: out });
  }));

  router.post('/:id/devices', manage, wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    // The site of the route first: an unknown one (or another tenant's) answers 404 whatever the body.
    const site = await siteRow(db, tenantId, String(req.params.id));
    const b = body(DevicesBody, req);
    await requireDevicesWrite(req, tenantId, b.deviceIds);
    res.json({ success: true, data: await setDevicesSite(tenantId, b.deviceIds, site.id, await audit.fromRequest(req, tenantId)) });
  }));

  return router;
}

/** PUT /api/mdm/devices/:id/site — { siteId | null }, in the session's tenant. */
export function createDeviceSiteRouter(): Router {
  const router = Router();
  router.put('/devices/:id/site', requireTenantCapability('devices.manage'), wrap(async (req, res) => {
    const id = parseRequestDeviceId(req.params.id);
    if (id === null) throw new AppError(404, 'Device not found');
    const tenantId = req.tenantId!;
    // The device of the route first: an unknown one (or another tenant's) answers 404 whatever the body.
    await requireDevicesWrite(req, tenantId, [id]);
    const b = body(DeviceSiteBody, req);
    res.json({ success: true, data: await setDevicesSite(tenantId, [id], b.siteId, await audit.fromRequest(req, tenantId)) });
  }));
  return router;
}
