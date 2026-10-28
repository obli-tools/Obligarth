import { Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import {
  MASTER_TENANT_ID, REMOTE_LIMITS, REMOTE_MODES, REMOTE_REQUESTER_SIDES, REMOTE_SESSION_STATES, remoteEffectiveMode,
  type RemoteMode, type RemoteSessionCreated, type RemoteSettingsDto,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { userActor } from '../db/context';
import { alertRemoteBurst } from '../guard/anomalies';
import { personFacts } from '../guard/people';
import { AppError } from '../middleware/errorHandler';
import { requireAnyTenantCapability, requireTenantCapability } from '../middleware/rbac';
import { noticeSettingsOf } from '../privacy/notice/provider';
import { approvalService } from '../services/approval.service';
import { resolveRequestDevice } from '../services/deviceScope.service';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { permissionService } from '../services/permission.service';
import { restrictionService, type RestrictionLevel } from '../services/restriction.service';
import { userLabels } from '../services/userLabels.service';
import { clientIp } from '../utils/clientIp';
import { logger } from '../utils/logger';
import { sessionHash } from '../utils/sessionHash';
import { safeErr } from '../jobs/errors';
import { REMOTE_SETTINGS_REQUEST_TYPE, remoteRequiredSide } from './approvals';
import { checkOpenable, type Openable } from './guard';
import { remoteMetrics } from './metrics';
import {
  RemoteEffects, VIEWER_TOKEN_UNISSUED, endSession, escalate, flushRemoteEffects, issueViewerToken, lockSession, releaseControl, requestSession,
  sessionDto, type SessionRow, type Transition,
} from './sessions';
import { RemoteSettingsInputSchema, readRemoteSettings, settingsChanges } from './settings';

// =============================================================================
// Console API of the remote assistance (P0-15 §4.2; §0.1 of the spec, the MSP model of the owners' decision of 27/10:
// the technician is strongly authenticated and traced, the user of the device accepts nothing), mounted at
// /api/remote-sessions behind the session and the tenant (routes/index.ts):
//   POST /                     { deviceId, mode, reason?, ticket? } (both optional, §0.1 rule 3): the capability of the
//                              mode (remote/guard.ts: a team's grant, or an administrator of the tenant or of the
//                              platform, as Obliance), the conditions (checkOpenable), a STRICT step-up of the
//                              technician at every request whatever the matrix says (remote.view and remote.control:
//                              floor 'sensitive', strictStepUp: never the trusted-IP shortcut), then held for approval
//                              when the matrix raised the mode to 'restricted' (a control session: remote.control or
//                              remote.view, the control includes the view) or, for a session of the MSP, when the
//                              tenant set mspSessionsNeedClientApproval (requiredSide 'client'); 201 { session,
//                              viewerToken } (the token here only, once; its SHA-256 kept), 202 { session, approvalId }
//   GET  /                     the journal: every session of the tenant with audit.read (the client approver, the
//                              auditor or DPO, the administrators); otherwise the sessions of the visible devices on which
//                              the caller holds mdm:remote_view or mdm:remote_control. ?deviceId=&state=&requestedBy=
//                              &side=&from=&to=&page=
//   GET  /:id                  one session, same scope (404 outside, whether it exists or not), as every /:id/* route
//   POST /:id/end              its requester, or an administrator of the tenant (emergency end, even outside the scope)
//   POST /:id/escalate         its requester: a live session in effective view → control, granted by the server after
//                              the conditions and the restriction of a control session and a strict step-up (§0.1 rule
//                              1: nothing asked of the device, which receives the frame mode)
//   POST /:id/release          its requester: a live session in effective control → view (frame mode view)
//   POST /:id/viewer-token     its requester, once, a session approved later, before the attachment (strict step-up)
//   GET  /settings             the tenant's settings (settings or audit.read) and the change waiting
//   PUT  /settings             (settings) a change: always an approval request (remote.settings_change, floor
//                              'restricted'); one of the MSP that touches mspSessionsNeedClientApproval reviewed by a
//                              client approver only (409 clientApproverRequired without one)
// Errors: 400 invalidRequest; 401 the step-up (twoFactorRequired…); 403 capabilityMissing; 404; 409 remoteSessionOpen,
// remoteUnavailable { reason }, remoteSessionState { state }, viewerTokenIssued, escalationRestricted,
// clientApproverRequired, approverFallbackHeld, remoteSettingsUnchanged, remoteSettingsChangePending { approvalId };
// 423 frozen; 429 remoteQuota { scope, limit }, rateLimited. REMOTE_SESSION_CHANGED to the requester and the tenant's
// administrators after each change (never a token).
// =============================================================================

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
const limitedHandler = (_q: Request, res: Response): void => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); };
const requestLimiter = rateLimit({ windowMs: 60_000, max: 60, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: limitedHandler });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const PAGE_SIZE = 50;

type Handler = (req: Request, res: Response) => Promise<void>;
const h = (fn: Handler) => (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

function body<S extends z.ZodTypeAny>(schema: S, req: Request): z.infer<S> {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

const noControl = (s: string): boolean => !CONTROL_RE.test(s);
const CreateBody = z.object({
  deviceId: z.union([z.number(), z.string()]),
  mode: z.enum(REMOTE_MODES),
  // Optional (§0.1 rule 3); blank is none.
  reason: z.string().trim().max(REMOTE_LIMITS.reasonMax).refine(noControl, 'reason: no control character').optional().nullable(),
  ticket: z.string().trim().max(REMOTE_LIMITS.ticketMax).refine(noControl, 'ticket: no control character').optional().nullable(),
}).strict();

/** A text shown to the user of the device: control characters removed, trimmed, cut. */
const clean = (s: string | null | undefined, max: number): string => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);

/** The answer of a session that cannot be opened (the reason of checkOpenable). */
function unavailable(o: Exclude<Openable, { ok: true }>): AppError {
  remoteMetrics.refused(o.reason);
  switch (o.reason) {
    case 'capabilityMissing': return new AppError(403, 'You do not hold this remote assistance on this device', 'capabilityMissing');
    case 'sessionOpen': return new AppError(409, 'A remote session is already open on this device', 'remoteSessionOpen');
    case 'frozen': return new AppError(423, 'The tenant is frozen: no remote session until it is unfrozen', 'frozen');
    case 'quota': return new AppError(429, 'Too many remote sessions are open', 'remoteQuota', o.details);
    default: return new AppError(409, 'A remote session is not available on this device', 'remoteUnavailable', { reason: o.reason, ...(o.details ?? {}) });
  }
}

/** The strict step-up of the technician (§0.1 rule 3): at every opening and every move to the control, whatever the
 *  matrix says (its floor 'sensitive' cannot be lowered), never the trusted-IP shortcut. Answers the 401 itself and
 *  returns false when the proof is missing or wrong. */
async function strictStepUp(req: Request, res: Response, mode: RemoteMode, deviceId: number): Promise<boolean> {
  const proof = await checkSecondFactor(req, {
    actionKey: mode === 'control' ? 'remote.control' : 'remote.view', deviceIds: [deviceId], allowTrustedIp: false, allowDevice: true,
  });
  if (!proof.ok) { sendStepUpFailure(res, proof); return false; }
  req.stepUpVia = proof.via;
  return true;
}

/** The restriction level of a session in this mode: a control session includes the view, so it is held at least as
 *  strictly as remote.view (a tenant that raised the view to 'restricted' is not bypassed by asking the control). */
async function remoteLevel(tenantId: number, mode: RemoteMode, deviceId: number): Promise<RestrictionLevel> {
  const view = await restrictionService.getLevelFor({ tenantId, actionKey: 'remote.view', deviceIds: [deviceId] });
  if (mode !== 'control') return view;
  const control = await restrictionService.getLevelFor({ tenantId, actionKey: 'remote.control', deviceIds: [deviceId] });
  const rank: Record<RestrictionLevel, number> = { none: 0, sensitive: 1, restricted: 2 };
  return rank[view] > rank[control] ? view : control;
}

/** The journal the caller reads: every session of the tenant (audit.read), or those of these devices. */
async function journalScope(req: Request): Promise<'all' | number[]> {
  if (req.session.role === 'admin') return 'all';
  const userId = req.session.userId!;
  if (await permissionService.userHasTenantCapability(userId, req.tenantId!, 'audit.read')) return 'all';
  const seen = await permissionService.getVisibleDeviceIds(userId, false);
  if (seen === 'all') return 'all';
  if (seen.length === 0) return [];
  const noView = new Set(await permissionService.devicesLackingCapability(userId, seen, 'mdm:remote_view'));
  const noControl = new Set(await permissionService.devicesLackingCapability(userId, seen, 'mdm:remote_control'));
  return seen.filter((id) => !noView.has(id) || !noControl.has(id));
}

const inScope = (scope: 'all' | number[], deviceId: number): boolean => scope === 'all' || scope.includes(Number(deviceId));

/** The session of a /:id route, in the caller's scope (404 otherwise, whether it exists or not). `admin`: an
 *  administrator of the tenant reaches it outside the scope (emergency end). */
async function sessionOf(req: Request, o: { tenantAdmin?: boolean } = {}): Promise<SessionRow> {
  const id = String(req.params.id ?? '');
  if (!UUID_RE.test(id)) throw new AppError(404, 'Session not found');
  const row = await db('remote_sessions').where({ tenant_id: req.tenantId!, id: id.toLowerCase() }).first() as SessionRow | undefined;
  if (!row) throw new AppError(404, 'Session not found');
  if (Number(row.requested_by) === Number(req.session.userId)) return row;
  if (o.tenantAdmin && await isTenantAdmin(req)) return row;
  if (!inScope(await journalScope(req), Number(row.device_id))) throw new AppError(404, 'Session not found');
  return row;
}

/** A platform administrator, or an administrator of the session's tenant. */
async function isTenantAdmin(req: Request): Promise<boolean> {
  if (req.session.role === 'admin') return true;
  const f = await personFacts(req.session.userId!, req.tenantId!);
  return f.active && f.tenantRole === 'admin';
}

/** The names a session copies at its request (told to the user of the device by its notifications, kept when the
 *  account is deleted). The data controller: the notice's, else the tenant's name (never a refusal, §0.1 rule 5). */
async function namesOf(req: Request, side: 'msp' | 'client'): Promise<{ requestedByName: string; operatorOrg: string; controllerName: string }> {
  const tenantId = req.tenantId!;
  const userId = req.session.userId!;
  const label = (await userLabels([userId])).get(userId);
  const tenant = await db('tenants').where({ id: tenantId }).first('name') as { name: string } | undefined;
  const tenantName = clean(tenant?.name, 200) || `Tenant ${tenantId}`;
  // The MSP: the master tenant's name when the caller may read it (a member of the master tenant), else the tenant's.
  const master = side === 'msp' && tenantId !== MASTER_TENANT_ID
    ? await db('tenants').where({ id: MASTER_TENANT_ID }).first('name') as { name: string } | undefined : undefined;
  return {
    requestedByName: clean(label?.displayName || label?.username || `User ${userId}`, 100) || `User ${userId}`,
    operatorOrg: clean(master?.name, 120) || tenantName.slice(0, 120),
    controllerName: clean((await noticeSettingsOf(db, tenantId)).settings.controllerName, 200) || tenantName,
  };
}

/** The answer of a transition that could not run (its state, a condition lost). */
const transitionError = (t: Extract<Transition, { ok: false }>): AppError =>
  new AppError(t.status, t.code === 'remoteUnavailable' ? 'The control is not available on this device' : `The session is ${t.row.state}`, t.code, t.details);

export function createRemoteSessionsRouter(): Router {
  const router = Router();

  // ── Settings (§4.1, §4.6, §0.1 rule 4) ─────────────────────────────────────

  router.get('/settings', requireAnyTenantCapability('settings', 'audit.read'), h(async (req, res) => {
    const tenantId = req.tenantId!;
    const s = await readRemoteSettings(db, tenantId);
    const p = await db('pending_approvals').where({ tenant_id: tenantId, request_type: REMOTE_SETTINGS_REQUEST_TYPE, status: 'pending' })
      .where('expires_at', '>', new Date()).orderBy('id', 'desc').first('id', 'payload') as { id: number; payload: unknown } | undefined;
    const payload = typeof p?.payload === 'string' ? JSON.parse(p.payload) : p?.payload;
    const dto: RemoteSettingsDto = {
      mspSessionsNeedClientApproval: s.mspSessionsNeedClientApproval, maxMinutes: s.maxMinutes, waitChannel: s.waitChannel,
      updatedAt: s.updatedAt ? s.updatedAt.toISOString() : null,
      pending: p ? { approvalId: Number(p.id), settings: (payload as { settings?: Record<string, unknown> })?.settings ?? {} } : null,
    };
    res.json({ success: true, data: dto });
  }));

  router.put('/settings', requireTenantCapability('settings'), requestLimiter, h(async (req, res) => {
    const input = body(RemoteSettingsInputSchema, req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const current = await readRemoteSettings(db, tenantId);
    const changes = settingsChanges(current, input);
    if (Object.keys(changes).length === 0) throw new AppError(409, 'The settings already hold these values', 'remoteSettingsUnchanged');
    const waiting = await db('pending_approvals').where({ tenant_id: tenantId, request_type: REMOTE_SETTINGS_REQUEST_TYPE, status: 'pending' })
      .where('expires_at', '>', new Date()).first('id') as { id: number } | undefined;
    if (waiting) throw new AppError(409, 'A change of these settings is already waiting for its approval', 'remoteSettingsChangePending', { approvalId: Number(waiting.id) });
    // The setting that protects the client from the MSP's sessions is changed by the MSP with a client approver only.
    const required = await remoteRequiredSide(tenantId, userId, changes.mspSessionsNeedClientApproval !== undefined);
    const settings = Object.fromEntries(Object.entries(changes).map(([k, v]) => [k, v.to]));
    const description = `Remote assistance settings: ${Object.entries(changes).map(([k, v]) => `${k} ${String(v.from)} → ${String(v.to)}`).join(', ')}`;
    const auditCtx = await audit.fromRequest(req, tenantId);
    const approval = await db.transaction(async (trx) => {
      const a = await approvalService.createInTx(trx, {
        tenantId, userId, requestType: REMOTE_SETTINGS_REQUEST_TYPE, description,
        payload: { action: REMOTE_SETTINGS_REQUEST_TYPE, settings, requiredSide: required.side, approverFallback: required.fallback },
        auditCtx,
      });
      await audit.appendInTx(trx, {
        tenantId, action: 'remote.settings_change_requested', target: { type: 'tenant', id: String(tenantId) }, approvalIds: [a.id],
        details: { changes, requiredSide: required.side, approverFallback: required.fallback },
      }, auditCtx);
      return a;
    });
    approvalService.announceCreated(approval);
    res.status(202).json({ success: true, data: { approvalId: approval.id, status: 'pending_approval', requiredSide: required.side } });
  }));

  // ── Sessions ───────────────────────────────────────────────────────────────

  router.post('/', requestLimiter, h(async (req, res) => {
    const b = body(CreateBody, req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const mode: RemoteMode = b.mode;
    const outcome = await resolveRequestDevice(req, b.deviceId, {});
    if (!outcome.ok || Number(outcome.device.tenant_id) !== tenantId) throw new AppError(404, 'Device not found');
    const deviceId = Number(outcome.device.id);
    // The conditions first (the clearest answer, before any second factor), again under the lock below.
    const pre = await db.transaction((trx) => checkOpenable(trx, { tenantId, userId, deviceId, mode, phase: 'request' }));
    if (!pre.ok) throw unavailable(pre);
    // The technician's strict step-up at every opening (§0.1 rule 3), held for approval or not.
    if (!(await strictStepUp(req, res, mode, deviceId))) return;

    // The restriction of the mode (at least 'sensitive': the step-up above; in control, the stricter of remote.control and
    // remote.view), raised to 'restricted' by the matrix, and the tenant's setting for the sessions of the MSP: held for approval.
    const level = await remoteLevel(tenantId, mode, deviceId);
    const facts = await personFacts(userId, tenantId);
    const settings = await readRemoteSettings(db, tenantId);
    const forced = settings.mspSessionsNeedClientApproval && facts.side === 'msp' && tenantId !== MASTER_TENANT_ID;
    const held = level === 'restricted' || forced;
    const required = held ? await remoteRequiredSide(tenantId, userId, forced) : null;
    const side = facts.side === 'client' ? 'client' : 'msp';
    const names = await namesOf(req, side);
    const reason = b.reason ? b.reason : null;
    const ticket = b.ticket ? b.ticket : null;
    const auditCtx = await audit.fromRequest(req, tenantId);
    const fx = new RemoteEffects();
    const out = await db.transaction(async (trx) => {
      // One request of the tenant at a time: its quotas and the one session per device hold under concurrency.
      await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`remote.sessions:${tenantId}`]);
      const check = await checkOpenable(trx, { tenantId, userId, deviceId, mode, phase: 'request' });
      if (!check.ok) throw unavailable(check);
      return requestSession(trx, fx, {
        tenantId, userId, deviceId, channel: check.channel, mode, reason, ticket, requesterSide: side, ...names,
        stepUpVia: req.stepUpVia ?? null, consoleIp: clientIp(req) || null, consoleSession: req.sessionID ? sessionHash(req.sessionID) : null,
        approval: required ? {
          description: `Remote assistance (${mode}) on device #${deviceId}${reason ? `: ${reason}` : ''}`,
          payload: {
            action: 'remote_session', deviceId, mode, reason, ticket, requiredSide: required.side, approverFallback: required.fallback,
            clientApprovalSetting: forced,
          },
        } : null,
        auditCtx,
      });
    });
    await flushRemoteEffects(fx, userActor(userId), auditCtx);
    // remote.burst: more than burstPerHour sessions of this operator in this tenant within the hour.
    try {
      const [{ n }] = await db('remote_sessions').where({ tenant_id: tenantId, requested_by: userId })
        .where('created_at', '>', new Date(Date.now() - 3_600_000)).count<{ n: string }[]>('id as n');
      if (Number(n) > REMOTE_LIMITS.burstPerHour) await alertRemoteBurst(tenantId, userId, Number(n));
    } catch (err) {
      logger.warn({ err: safeErr(err), tenantId }, 'remote: burst check failed');
    }
    const data: RemoteSessionCreated = {
      session: sessionDto(out.row), ...(out.viewerToken ? { viewerToken: out.viewerToken } : {}), ...(out.approval ? { approvalId: out.approval.id } : {}),
    };
    res.setHeader('Cache-Control', 'no-store');
    res.status(out.approval ? 202 : 201).json({ success: true, data });
  }));

  const ListQuery = z.object({
    deviceId: z.string().regex(/^[1-9][0-9]{0,9}$/).optional(),
    state: z.enum(REMOTE_SESSION_STATES).optional(),
    requestedBy: z.string().regex(/^[1-9][0-9]{0,9}$/).optional(),
    side: z.enum(REMOTE_REQUESTER_SIDES).optional(),
    from: z.string().datetime({ offset: true }).optional(),
    to: z.string().datetime({ offset: true }).optional(),
    page: z.string().regex(/^[1-9][0-9]{0,4}$/).optional(),
  }).strip();

  router.get('/', h(async (req, res) => {
    const parsed = ListQuery.safeParse(req.query ?? {});
    if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const f = parsed.data;
    const scope = await journalScope(req);
    const page = Number(f.page ?? 1);
    let q = db('remote_sessions').where({ tenant_id: req.tenantId! });
    if (scope !== 'all') q = q.whereRaw('device_id = ANY (?::int[])', [scope]);
    if (f.deviceId) q = q.where('device_id', Number(f.deviceId));
    if (f.state) q = q.where('state', f.state);
    if (f.requestedBy) q = q.where('requested_by', Number(f.requestedBy));
    if (f.side) q = q.where('requester_side', f.side);
    if (f.from) q = q.where('created_at', '>=', new Date(f.from));
    if (f.to) q = q.where('created_at', '<', new Date(f.to));
    const [{ n }] = await q.clone().count<{ n: string }[]>('id as n');
    const rows = await q.orderBy('created_at', 'desc').orderBy('id').limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE).select('*') as SessionRow[];
    const now = new Date();
    res.json({ success: true, data: { items: rows.map((r) => sessionDto(r, now)), page, pageSize: PAGE_SIZE, total: Number(n) } });
  }));

  router.get('/:id', h(async (req, res) => {
    const row = await sessionOf(req);
    res.json({ success: true, data: sessionDto(row) });
  }));

  router.post('/:id/end', h(async (req, res) => {
    const found = await sessionOf(req, { tenantAdmin: true });
    const userId = req.session.userId!;
    const requester = Number(found.requested_by) === Number(userId);
    if (!requester && !(await isTenantAdmin(req))) throw new AppError(403, 'Only its requester or an administrator of the tenant ends a session', 'capabilityMissing');
    const tenantId = req.tenantId!;
    const auditCtx = await audit.fromRequest(req, tenantId);
    const fx = new RemoteEffects();
    const row = await db.transaction(async (trx) => {
      const r = await lockSession(trx, tenantId, found.id);
      if (!r) throw new AppError(404, 'Session not found');
      return endSession(trx, fx, r, { reason: 'operator', by: 'operator', byUserId: userId, auditCtx, details: requester ? {} : { emergency: true } });
    });
    await flushRemoteEffects(fx, userActor(userId), auditCtx);
    res.json({ success: true, data: sessionDto(row) });
  }));

  router.post('/:id/escalate', h(async (req, res) => {
    const found = await sessionOf(req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const deviceId = Number(found.device_id);
    if (Number(found.requested_by) !== Number(userId)) throw new AppError(403, 'Only the requester of the session takes the control', 'capabilityMissing');
    // The clearest answer before any second factor (read again under the lock by escalate).
    if (found.state !== 'live' || remoteEffectiveMode(found.mode, found.consented_mode) !== 'view') {
      throw new AppError(409, `The session is ${found.state}`, 'remoteSessionState', { state: found.state });
    }
    // The restriction of a control session; an escalation is never held for an approval (the session is live): at
    // 'restricted', or under the tenant's setting for the MSP, open a control session instead.
    const level = await restrictionService.getLevelFor({ tenantId, actionKey: 'remote.control', deviceIds: [deviceId] });
    const facts = await personFacts(userId, tenantId);
    const settings = await readRemoteSettings(db, tenantId);
    if (level === 'restricted' || (settings.mspSessionsNeedClientApproval && facts.side === 'msp' && tenantId !== MASTER_TENANT_ID)) {
      throw new AppError(409, 'The control is held for approval in this tenant: end this session and ask a control session', 'escalationRestricted');
    }
    // The technician's strict step-up at every move to the control (§0.1 rule 3).
    if (!(await strictStepUp(req, res, 'control', deviceId))) return;
    const auditCtx = await audit.fromRequest(req, tenantId);
    const fx = new RemoteEffects();
    const t = await db.transaction(async (trx) => {
      const r = await lockSession(trx, tenantId, found.id);
      if (!r) throw new AppError(404, 'Session not found');
      return escalate(trx, fx, r, { userId, auditCtx, stepUpVia: req.stepUpVia ?? null, consoleIp: clientIp(req) || null });
    });
    await flushRemoteEffects(fx, userActor(userId), auditCtx);
    if (!t.ok) throw transitionError(t);
    res.json({ success: true, data: sessionDto(t.row) });
  }));

  router.post('/:id/release', h(async (req, res) => {
    const found = await sessionOf(req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    if (Number(found.requested_by) !== Number(userId)) throw new AppError(403, 'Only the requester of the session releases the control', 'capabilityMissing');
    const auditCtx = await audit.fromRequest(req, tenantId);
    const fx = new RemoteEffects();
    const t = await db.transaction(async (trx) => {
      const r = await lockSession(trx, tenantId, found.id);
      if (!r) throw new AppError(404, 'Session not found');
      return releaseControl(trx, fx, r, { userId, auditCtx });
    });
    await flushRemoteEffects(fx, userActor(userId), auditCtx);
    if (!t.ok) throw transitionError(t);
    res.json({ success: true, data: sessionDto(t.row) });
  }));

  router.post('/:id/viewer-token', h(async (req, res) => {
    const found = await sessionOf(req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    if (Number(found.requested_by) !== Number(userId)) throw new AppError(404, 'Session not found');
    // The clearest answers before any second factor (read again under the lock by issueViewerToken).
    if (!['queued', 'awaiting_consent', 'connecting'].includes(found.state)) {
      throw new AppError(409, `The session is ${found.state}`, 'remoteSessionState', { state: found.state });
    }
    if (found.viewer_token_sha256 !== VIEWER_TOKEN_UNISSUED) throw new AppError(409, 'The viewer token of this session was already handed', 'viewerTokenIssued');
    // The opening of a session approved later: the technician's strict step-up again (§0.1 rule 3).
    if (!(await strictStepUp(req, res, found.mode, Number(found.device_id)))) return;
    const out = await db.transaction(async (trx) => {
      const r = await lockSession(trx, tenantId, found.id);
      if (!r) throw new AppError(404, 'Session not found');
      return issueViewerToken(trx, r, userId, req.stepUpVia ?? null, req.sessionID ? sessionHash(req.sessionID) : null);
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, data: { session: sessionDto(out.row), viewerToken: out.token } });
  }));

  return router;
}
