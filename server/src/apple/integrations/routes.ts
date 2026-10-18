import { raw as expressRaw, Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { INTEGRATION_LIMITS, isMasterTenant, MANUAL_DEADLINE_KINDS } from '@obligarth/shared';
import { audit } from '../../audit';
import { config } from '../../config';
import { db } from '../../db';
import { asIdentity, asPlatform, userActor } from '../../db/context';
import { globalViewGrant } from '../../db/platformAccess';
import { AppError } from '../../middleware/errorHandler';
import { requireAnyTenantCapability, requireTenantCapability } from '../../middleware/rbac';
import { applyRestriction, restrictionService } from '../../services/restriction.service';
import { vault } from '../../vault';
import { realtime } from '../realtime';
import {
  adeServerPublicKey, checkAdeServerDeletable, createAdeServer, declareAdeServerByod, getAdeServer, listAdeServers, serverId,
  syncAdeServer, uploadAdeServerToken,
} from './ade';
import { recordInstanceDeadline } from './deadlines';
import { allDeadlines, integrationsSummary, readiness, tenantDeadlines } from './overview';
import {
  abandonPushRequest, checkCertificateForRequest, createPushRequest, getPushRequest, holdTopicChange, importAndActivate, importVendorSigned,
  importWithKey, pushAppleFile, pushOverview, pushVendorFile, requestId,
} from './push';
import { recordVendorDeadline } from './vendor';

// =============================================================================
// Console API of the Apple integrations (docs: integration-apple-edge §11.6),
// mounted at /api/apple behind the session and the tenant. Reading: 'settings'
// or mdm.integrations.manage; writing: mdm.integrations.manage and the
// restriction apple.integrations (recommended level 'sensitive', no floor);
// a change of push topic and the deletion of an ADE server: a second approver
// (floors apple.push_topic_change and apple.ade_token_delete, request type
// 'apple_integration').
//   GET  /integrations, /readiness, /deadlines
//   GET  /push; POST /push/requests; GET /push/requests/:id/vendor-file;
//   POST /push/requests/:id/vendor-signed (the JSON file, raw); GET
//   /push/requests/:id/apple-file; POST /push/requests/:id/certificate (PEM,
//   raw, 16 KiB); POST /push/requests/:id/abandon; POST /push/import
//   (laboratory: certificate and key, platform administrator,
//   APPLE_ALLOW_PUSH_KEY_IMPORT)
//   GET /ade-tokens; POST /ade-tokens; GET /ade-tokens/:id/public-key; PUT
//   /ade-tokens/:id/token (.p7m, raw, 64 KiB); POST /ade-tokens/:id/sync
//   (once a minute); PUT /ade-tokens/:id/account-driven-enrollment; DELETE
//   /ade-tokens/:id
// /api/admin/apple (master tenant, platform administrators): GET /deadlines
// (every tenant's and the instance's, context 'platform' under the
// administrator's grant), PUT /deadlines/:kind (mdm_domain,
// profile_signing_identity typed by hand). Binary bodies: express.raw of the
// route only, never logged; no route ever returns a token or a key.
// =============================================================================

const read = requireAnyTenantCapability('settings', 'mdm.integrations.manage');
const manage = requireTenantCapability('mdm.integrations.manage');
const rawParser = expressRaw({ type: () => true, limit: INTEGRATION_LIMITS.fileBytes });
/** The raw body of a file route (64 KiB at most): a larger one answers 413 fileTooLarge, never a 500. */
function raw(req: Request, res: Response, next: NextFunction): void {
  rawParser(req, res, (err?: unknown) => {
    if (!err) { next(); return; }
    const type = (err as { type?: string }).type;
    next(type === 'entity.too.large' ? new AppError(413, 'The file is too large', 'fileTooLarge') : new AppError(400, 'The file cannot be read', 'fileMissing'));
  });
}
const HINT = z.string().trim().max(INTEGRATION_LIMITS.accountHint).nullable().optional();

const PushRequestBody = z.object({ purpose: z.enum(['initial', 'renewal', 'topic_change']), appleAccountHint: HINT }).strict();
const PushImportBody = z.object({ certPem: z.string().min(1).max(INTEGRATION_LIMITS.certificateBytes), keyPem: z.string().min(1).max(INTEGRATION_LIMITS.certificateBytes) }).strict();
const AdeServerBody = z.object({ label: z.string().trim().min(1).max(INTEGRATION_LIMITS.label), appleAccountHint: HINT }).strict();
const ManualDeadlineBody = z.object({ notAfter: z.string().datetime({ offset: true }).nullable(), label: z.string().trim().min(1).max(200).optional() }).strict();

function parse<S extends z.ZodTypeAny>(schema: S, v: unknown): z.infer<S> {
  const r = schema.safeParse(v ?? {});
  if (!r.success) {
    const i = r.error.issues[0];
    throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
  }
  return r.data;
}

/** The raw body of a file route (Buffer), within `max` bytes. */
function fileBody(req: Request, max: number = INTEGRATION_LIMITS.fileBytes): Buffer {
  const b = req.body;
  if (!Buffer.isBuffer(b) || b.length === 0) throw new AppError(400, 'The file is missing (send its bytes as the body)', 'fileMissing');
  if (b.length > max) throw new AppError(413, 'The file is too large', 'fileTooLarge');
  return b;
}

type Handler = (req: Request, res: Response) => Promise<void>;
/** A function declaration (hoisted), like the other routers of the module. */
function h(fn: Handler) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

/** The integration must be on for anything that calls apple-edge. */
function requireOn(): void {
  if (config.apple.mode !== 'on') throw new AppError(503, 'The Apple integration is turned off on this instance', 'appleIntegrationDisabled');
}

/** The restriction of every write of the integrations (apple.integrations): false when the response is written. */
async function integrationsAllowed(req: Request, res: Response, description: string): Promise<boolean> {
  return applyRestriction(res, { req, actionKey: 'apple.integrations', approvalDescription: description });
}

function attachment(res: Response, filename: string, type: string): void {
  res.setHeader('Content-Type', type);
  res.setHeader('Content-Disposition', `attachment; filename="${filename.replace(/[^A-Za-z0-9._-]/g, '_')}"`);
  res.setHeader('Cache-Control', 'no-store');
}

/** 'Synchroniser maintenant': once a minute and per server. */
const syncLimiter = rateLimit({
  windowMs: 60_000, limit: 1, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => `${req.tenantId ?? 0}:${String(req.params.id ?? '').toLowerCase()}`,
  handler: (_q, res) => { res.status(429).json({ success: false, error: 'This server was synchronised less than a minute ago', code: 'rateLimited' }); },
});

export function createAppleIntegrationsRouter(): Router {
  const router = Router();

  router.get('/integrations', read, h(async (req, res) => {
    res.json({ data: await integrationsSummary(db, req.tenantId!) });
  }));

  router.get('/readiness', read, h(async (req, res) => {
    res.json({ data: await readiness(db, req.tenantId!) });
  }));

  router.get('/deadlines', read, h(async (req, res) => {
    res.json({ data: await tenantDeadlines(db, req.tenantId!, { retired: req.query.retired === '1' }) });
  }));

  // ── Push certificate (§11.1) ────────────────────────────────────────────────
  router.get('/push', read, h(async (req, res) => {
    res.json({ data: await pushOverview(db, req.tenantId!) });
  }));

  router.post('/push/requests', manage, h(async (req, res) => {
    requireOn();
    const tenantId = req.tenantId!;
    const b = parse(PushRequestBody, req.body);
    await vault.requireEscrow();                                       // V14 first: nothing asked of the user before
    if (!(await integrationsAllowed(req, res, `Create a push certificate request (${b.purpose})`))) return;
    const view = await createPushRequest(tenantId, req.session.userId!, { purpose: b.purpose, appleAccountHint: b.appleAccountHint }, userActor(req.session.userId!));
    await audit.append({
      tenantId, action: 'integration.push_request_created', target: { type: 'push_request', id: view.id }, details: { purpose: b.purpose },
    }, await audit.fromRequest(req, tenantId));
    res.status(201).json({ data: view });
  }));

  router.get('/push/requests/:id/vendor-file', read, h(async (req, res) => {
    const { filename, file } = await pushVendorFile(db, req.tenantId!, requestId(req.params.id));
    attachment(res, filename, 'application/json; charset=utf-8');
    res.send(`${JSON.stringify(file, null, 2)}\n`);
  }));

  router.post('/push/requests/:id/vendor-signed', manage, raw, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = requestId(req.params.id);
    await getPushRequest(db, tenantId, id);
    const text = fileBody(req).toString('utf8');
    if (!(await integrationsAllowed(req, res, 'Import the vendor-signed push request'))) return;
    const { view, check } = await importVendorSigned(tenantId, id, text);
    await recordVendorDeadline(userActor(req.session.userId!), check);
    await audit.append({
      tenantId, action: 'integration.push_vendor_file_imported', target: { type: 'push_request', id },
      details: { vendorCertSha256: check.vendorCertSha256, vendorCertNotAfter: check.vendorCertNotAfter.toISOString() },
    }, await audit.fromRequest(req, tenantId));
    res.json({ data: view });
  }));

  router.get('/push/requests/:id/apple-file', read, h(async (req, res) => {
    const { filename, content } = await pushAppleFile(db, req.tenantId!, requestId(req.params.id));
    attachment(res, filename, 'application/octet-stream');
    res.send(content);
  }));

  router.post('/push/requests/:id/certificate', manage, raw, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = requestId(req.params.id);
    const current = await getPushRequest(db, tenantId, id);
    // A change of topic already waits for its approval: the kept certificate is the one the approver is shown; another
    // one would replace it under the same approval (review of lot C3, R1). Abandon the request to start again.
    if (current.topicChangePending) {
      throw new AppError(409, 'A change of topic of this request already waits for its approval', 'pushTopicChangePending');
    }
    const pem = fileBody(req, INTEGRATION_LIMITS.certificateBytes).toString('utf8');
    // Every check before a second factor or a second approver is asked (the request of another tenant: 404 first).
    const c = await checkCertificateForRequest(db, tenantId, id, pem);
    requireOn();
    const ctx = await audit.fromRequest(req, tenantId);
    if (c.topicChange) {
      // A change of topic: never without a second approver (floor apple.push_topic_change, I23); the certificate
      // (public) waits on the request. The intent is written before the approval request is filed.
      const out = await audit.withIntent({
        tenantId, action: 'integration.push_topic_change_requested', target: { type: 'push_request', id },
        details: { topic: c.check.topic, previousTopic: c.activeTopic, notAfter: c.check.notAfter.toISOString() },
      }, ctx, () => restrictionService.enforce({
        req, actionKey: 'apple.push_topic_change', approvalRequestType: 'apple_integration',
        approvalDescription: `Replace the push certificate of topic ${c.activeTopic} by one of topic ${c.check.topic}: devices enrolled under the previous topic must enroll again`,
        approvalPayload: { action: 'apple_integration', op: 'push_topic_change', requestId: id, topic: c.check.topic, previousTopic: c.activeTopic },
      }), { resultDetails: (o) => ({ outcome: o.ok ? 'allowed' : 'approval' in o ? 'approval' : 'refused' }) });
      if ('approval' in out && out.approval) {
        await db.transaction((trx) => holdTopicChange(trx, tenantId, id, c.check.certPem, Number(out.approval.id)));
        realtime.integrationChanged(tenantId, 'push');
        res.status(202).json({ data: { approvalId: out.approval.id, status: 'pending_approval' } });
        return;
      }
      if (!out.ok) {
        const o = out as { status: number; body: unknown; headers?: Record<string, string> };
        for (const [k, v] of Object.entries(o.headers ?? {})) res.setHeader(k, v);
        res.status(o.status).json(o.body);
        return;
      }
      // A floor never lets a change of topic through without its approval; kept for a future level.
      throw new AppError(403, 'A change of push topic needs a second approver', 'approvalRequired');
    }
    if (!(await integrationsAllowed(req, res, 'Import the push certificate of Apple'))) return;
    const view = await audit.withIntent({
      tenantId, action: 'integration.push_certificate_imported', target: { type: 'push_request', id },
      details: { topic: c.check.topic, purpose: c.row.purpose, certSha256: c.check.sha256, notAfter: c.check.notAfter.toISOString() },
    }, ctx, () => importAndActivate(tenantId, id, c.check, userActor(req.session.userId!)));
    res.json({ data: view });
  }));

  router.post('/push/requests/:id/abandon', manage, h(async (req, res) => {
    const id = requestId(req.params.id);
    if (!(await integrationsAllowed(req, res, 'Abandon a push certificate request'))) return;
    res.json({ data: await abandonPushRequest(req.tenantId!, id) });
  }));

  // Laboratory only: a certificate with its key, handed to apple-edge once (never kept, never logged).
  router.post('/push/import', manage, h(async (req, res) => {
    if (!config.apple.allowPushKeyImport || req.session.role !== 'admin') throw new AppError(404, 'Not found');
    requireOn();
    const tenantId = req.tenantId!;
    const b = parse(PushImportBody, req.body);
    await vault.requireEscrow();
    if (!(await integrationsAllowed(req, res, 'Import a push certificate with its key (laboratory)'))) return;
    const view = await audit.withIntent({
      tenantId, action: 'integration.push_certificate_imported', target: { type: 'tenant', id: String(tenantId) }, details: { purpose: 'import', laboratory: true },
    }, await audit.fromRequest(req, tenantId), () => importWithKey(tenantId, b.certPem, b.keyPem, userActor(req.session.userId!)),
    { resultDetails: (v) => ({ topic: v?.topic ?? null, notAfter: v?.notAfter ?? null }) });
    res.json({ data: view });
  }));

  // ── ADE servers (§11.2) ─────────────────────────────────────────────────────
  router.get('/ade-tokens', read, h(async (req, res) => {
    res.json({ data: await listAdeServers(db, req.tenantId!) });
  }));

  router.post('/ade-tokens', manage, h(async (req, res) => {
    requireOn();
    const tenantId = req.tenantId!;
    const b = parse(AdeServerBody, req.body);
    await vault.requireEscrow();
    if (!(await integrationsAllowed(req, res, `Add the ADE server ${b.label}`))) return;
    const view = await createAdeServer(tenantId, req.session.userId!, b, userActor(req.session.userId!));
    await audit.append({ tenantId, action: 'integration.ade_token_created', target: { type: 'ade_token', id: view.id }, details: { label: view.label } },
      await audit.fromRequest(req, tenantId));
    res.status(201).json({ data: view });
  }));

  router.get('/ade-tokens/:id/public-key', read, h(async (req, res) => {
    const { filename, pem } = await adeServerPublicKey(db, req.tenantId!, serverId(req.params.id));
    attachment(res, filename, 'application/x-pem-file');
    res.send(pem);
  }));

  router.put('/ade-tokens/:id/token', manage, raw, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = serverId(req.params.id);
    const before = await getAdeServer(db, tenantId, id);
    const p7m = fileBody(req);
    requireOn();
    if (!(await integrationsAllowed(req, res, `Upload the server token of the ADE server ${before.label}`))) return;
    const view = await audit.withIntent({
      tenantId, action: 'integration.ade_token_uploaded', target: { type: 'ade_token', id }, details: { renewal: before.state !== 'awaiting_token' },
    }, await audit.fromRequest(req, tenantId), () => uploadAdeServerToken(tenantId, id, p7m, userActor(req.session.userId!)),
    { resultDetails: (v) => ({ state: v.state, notAfter: v.notAfter }) });
    res.json({ data: view });
  }));

  router.post('/ade-tokens/:id/sync', manage, syncLimiter, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = serverId(req.params.id);
    await getAdeServer(db, tenantId, id);
    requireOn();
    await syncAdeServer(tenantId, id, userActor(req.session.userId!));
    await audit.append({ tenantId, action: 'integration.ade_sync_requested', target: { type: 'ade_token', id }, details: {} }, await audit.fromRequest(req, tenantId));
    res.status(202).json({ data: { id, requested: true } });
  }));

  router.put('/ade-tokens/:id/account-driven-enrollment', manage, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = serverId(req.params.id);
    await getAdeServer(db, tenantId, id);
    requireOn();
    if (!(await integrationsAllowed(req, res, 'Declare the account-driven enrollment at Apple'))) return;
    const view = await declareAdeServerByod(tenantId, id, userActor(req.session.userId!));
    await audit.append({ tenantId, action: 'integration.ade_byod_discovery_declared', target: { type: 'ade_token', id }, details: {} },
      await audit.fromRequest(req, tenantId));
    res.json({ data: view });
  }));

  router.delete('/ade-tokens/:id', manage, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const id = serverId(req.params.id);
    const { label } = await checkAdeServerDeletable(db, tenantId, id);
    requireOn();
    // Never without a second approver (floor apple.ade_token_delete): the executor deletes and writes the entry.
    const ok = await applyRestriction(res, {
      req, actionKey: 'apple.ade_token_delete', approvalRequestType: 'apple_integration',
      approvalDescription: `Delete the ADE server ${label}: its devices of Apple Business are no longer listed here`,
      approvalPayload: { action: 'apple_integration', op: 'ade_token_delete', serverId: id, label },
    });
    if (!ok) return;
    throw new AppError(403, 'The deletion of an ADE server needs a second approver', 'approvalRequired');
  }));

  return router;
}

// ── Administration (/api/admin/apple) ───────────────────────────────────────────

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

export function createAppleAdminIntegrationsRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/deadlines', h(async (req, res) => {
    const grant = await globalViewGrant(req, 'admin.apple.deadlines');
    res.json({ data: await asPlatform(grant, () => allDeadlines(db, { retired: req.query.retired === '1' })) });
  }));

  router.put('/deadlines/:kind', h(async (req, res) => {
    const kind = String(req.params.kind ?? '');
    if (!(MANUAL_DEADLINE_KINDS as readonly string[]).includes(kind)) throw new AppError(404, 'Not found', 'deadlineKindNotManual');
    const b = parse(ManualDeadlineBody, req.body);
    const k = kind as typeof MANUAL_DEADLINE_KINDS[number];
    const actor = userActor(req.session.userId!);
    await asIdentity(actor, () => db.transaction(async (trx) => {
      if (b.notAfter === null) {
        await trx('integration_deadline_items').whereNull('tenant_id').where({ kind: k, source: 'manual' }).whereNull('retired_at')
          .update({ retired_at: new Date(), updated_at: new Date() });
        return;
      }
      await recordInstanceDeadline(trx, {
        kind: k, subjectRef: 'manual', label: b.label ?? (k === 'mdm_domain' ? 'Domain of the device service' : 'Profile signing identity'),
        notAfter: new Date(b.notAfter), source: 'manual', replace: true,
      });
    }));
    await audit.append({
      tenantId: req.tenantId!, action: 'integration.deadline_set', target: { type: 'deadline', id: k }, details: { kind: k, notAfter: b.notAfter },
    }, await audit.fromRequest(req, req.tenantId!));
    realtime.integrationChanged(req.tenantId!, 'deadlines');
    res.json({ data: { kind: k, notAfter: b.notAfter } });
  }));

  return router;
}

