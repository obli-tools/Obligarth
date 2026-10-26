import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  DEFAULT_PRIVACY_PROFILE, IMPOSED_RULES, OWNERSHIPS, PRIVACY_BOOLEAN_RULES, PRIVACY_COLLECTION_SCOPES, PRIVACY_RULE_KEYS,
  RETENTION_CATEGORY_KEYS, RETENTION_LOWERING_DELAY_DAYS, retentionCategoryDef, retentionChanges, retentionValueErrors,
  type Ownership, type PrivacyOwnershipProfileDto, type PrivacyProfileRules, type PrivacyProfileVersionDto, type PrivacyProfilesDto,
  type PrivacyRuleKey, type RetentionCategory, type RetentionPolicyDto,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { requireAnyTenantCapability, requireTenantCapability } from '../middleware/rbac';
import { permissionService } from '../services/permission.service';
import { restrictionService } from '../services/restriction.service';
import { privacyReviewerSide } from './approvals';
import { profileImpact } from './impact';
import { PrivacyProfileRulesSchema, checkProfileRules, currentProfile, effectiveProfileRules } from './profiles';
import { PROFILE_CHANGE_REQUEST_TYPE, RETENTION_CHANGE_REQUEST_TYPE, type ProfileChange, type RetentionChange } from './requests';
import { retentionValues } from './retention';
import { pendingActive, retentionPolicyDto, retentionRequestWaiting, retentionRow } from './retentionPolicy';

// =============================================================================
// Console API of the privacy profiles (P0-13 T3, CNF-02), mounted at /api/privacy behind the session and the tenant.
//   GET  /profiles                     the three ownerships: current version (null: the defaults), defaults, rules in
//                                      force, imposed keys, change waiting for its approval, last versions
//   GET  /profiles/:ownership/impact   the impact of proposed rules (query: the keys that change, the others are the
//                                      rules in force): keys narrowed and widened, devices, rows removed
//   POST /profiles/:ownership          { rules, justification }: always an approval request (restriction
//                                      privacy.profile_change, floor 'restricted', D3), examined by a client approver of
//                                      the tenant, else by another platform administrator (privacy/approvals.ts); 202
//   GET  /retention                    (P0-13 T4, CNF-04) the categories: value in force, value set, default, range,
//                                      decrease waiting and its date; the request waiting; the retentions of the
//                                      platform (read only, D16); the audit log's retention
//   PUT  /retention                    { values, justification }: always an approval request (restriction
//                                      privacy.retention_change, floor 'restricted', D3), same examination as the
//                                      profiles; an increase applies at the approval, a decrease 7 days later (D4); 202.
//                                      A decrease waiting is cancelled by such a request asking the value in force
//                                      (restored): a change of the retention as any other, approved (D3, D4)
// Reading: settings, audit.read (the DPO, the auditor) or mdm.privacy.manage; requesting: mdm.privacy.manage. Errors:
// 400 invalidRequest, justificationRequired, invalidPrivacyRules, privacyRuleImposed (details.keys), retentionOutOfRange
// (details.keys, details.ranges); 404 for an unknown ownership; 409 privacyProfileUnchanged, privacyProfileChangePending
// (details.approvalId: null while another request of the same kind is being filed, filedAlone), retentionUnchanged,
// privacyRetentionChangePending (details.approvalId, likewise), approverFallbackHeld.
// =============================================================================

const read = requireAnyTenantCapability('settings', 'audit.read', 'mdm.privacy.manage');
const manage = requireTenantCapability('mdm.privacy.manage');

/** Versions of an ownership shown in its history. */
const HISTORY = 20;

type Handler = (req: Request, res: Response) => Promise<void>;
function h(fn: Handler) {
  return (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };
}

function ownershipParam(req: Request): Ownership {
  const o = String(req.params.ownership ?? '');
  if (!(OWNERSHIPS as readonly string[]).includes(o)) throw new AppError(404, 'Unknown ownership', 'notFound');
  return o as Ownership;
}

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);
const imposedKeys = (o: Ownership): PrivacyRuleKey[] => PRIVACY_RULE_KEYS.filter((k) => IMPOSED_RULES[o][k] !== undefined);

/** 400 of rules that are not valid for the ownership. */
function rulesOrThrow(ownership: Ownership, value: unknown): PrivacyProfileRules {
  const c = checkProfileRules(ownership, value);
  if (c.ok) return c.rules;
  throw c.code === 'privacyRuleImposed'
    ? new AppError(400, `Imposed rules cannot change for ${ownership}: ${c.keys.join(', ')}`, 'privacyRuleImposed', { keys: c.keys })
    : new AppError(400, `Invalid privacy rules${c.keys.length ? `: ${c.keys.join(', ')}` : ''}`, 'invalidPrivacyRules', { keys: c.keys });
}

/** The rules of a query of the impact: each key given replaces the one in force; any other parameter is refused. */
function rulesOfQuery(query: Request['query'], base: PrivacyProfileRules): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(query)) {
    if (!(PRIVACY_RULE_KEYS as readonly string[]).includes(k) || typeof v !== 'string') {
      throw new AppError(400, `Unknown parameter: ${k}`, 'invalidRequest');
    }
    if ((PRIVACY_BOOLEAN_RULES as readonly string[]).includes(k)) {
      if (v !== 'true' && v !== 'false') throw new AppError(400, `${k}: true or false`, 'invalidPrivacyRules', { keys: [k] });
      out[k] = v === 'true';
    } else {
      if (!(PRIVACY_COLLECTION_SCOPES as readonly string[]).includes(v)) throw new AppError(400, `${k}: all or managed_only`, 'invalidPrivacyRules', { keys: [k] });
      out[k] = v;
    }
  }
  return out;
}

const ChangeBody = z.object({
  rules: z.unknown(),
  justification: z.string().max(1000).optional().nullable(),
}).strict();

const RetentionBody = z.object({
  values: z.record(z.string().max(64), z.unknown()).refine((v) => Object.keys(v).length <= 32, 'too many categories'),
  justification: z.string().max(1000).optional().nullable(),
}).strict();

type VersionRow = {
  id: string; ownership: string; version: number; rules: unknown; justification: string | null; approval_id: number | null;
  created_by: number | null; approved_by: number | null; created_at: Date; superseded_at: Date | null;
};

function versionDto(r: VersionRow): PrivacyProfileVersionDto {
  const rules = PrivacyProfileRulesSchema.safeParse(r.rules);
  // The CHECKs of the table make it impossible: refuse rather than show something else.
  if (!rules.success) throw new AppError(500, 'Unreadable privacy profile version', 'privacyProfileInvalid');
  return {
    id: r.id, version: Number(r.version), rules: rules.data, justification: r.justification ?? null,
    approvalId: r.approval_id === null ? null : Number(r.approval_id), createdBy: r.created_by === null ? null : Number(r.created_by),
    approvedBy: r.approved_by === null ? null : Number(r.approved_by), createdAt: iso(r.created_at)!, supersededAt: iso(r.superseded_at),
  };
}

type PendingRow = { id: number; requested_by: number; created_at: Date; expires_at: Date; payload: unknown };
const payloadOf = (v: unknown): Record<string, unknown> => {
  const p = typeof v === 'string' ? (() => { try { return JSON.parse(v); } catch { return null; } })() : v;
  return p && typeof p === 'object' && !Array.isArray(p) ? p as Record<string, unknown> : {};
};

/** The requests of the tenant waiting for their approval, per ownership (the latest one). */
async function pendingRequests(tenantId: number): Promise<Map<string, PendingRow>> {
  const rows = await db('pending_approvals').where({ tenant_id: tenantId, request_type: PROFILE_CHANGE_REQUEST_TYPE, status: 'pending' })
    .where('expires_at', '>', new Date()).orderBy('created_at', 'desc')
    .select('id', 'requested_by', 'created_at', 'expires_at', 'payload') as PendingRow[];
  const out = new Map<string, PendingRow>();
  for (const r of rows) {
    const o = String(payloadOf(r.payload).ownership ?? '');
    if (!out.has(o)) out.set(o, r);
  }
  return out;
}

/** Files a request of `kind` (a profile's ownership, the retention) alone in the tenant (constat de relecture): the
 *  check of the request waiting and the filing run under a lock of the tenant and the kind, held by a transaction of
 *  its own while the approval service files and commits the request, so that two requests sent at once never both pass
 *  the check (one change waiting per kind, examined against the screen that shows it). The lock is only tried: a
 *  request sent while another one of the same kind is being filed is refused as waiting (409 `pendingCode`, no
 *  approvalId yet), never queued behind it on a second connection of the pool. */
async function filedAlone<T>(tenantId: number, kind: string, pendingCode: string, fn: () => Promise<T>): Promise<T> {
  return db.transaction(async (trx) => {
    const r = await trx.raw('SELECT pg_try_advisory_xact_lock(hashtext(?), ?) AS ok', [`privacy.request:${kind}`, tenantId]) as
      { rows: Array<{ ok: boolean }> };
    if (!r.rows[0]?.ok) throw new AppError(409, `A request (${kind}) is being filed`, pendingCode, { approvalId: null });
    return fn();
  });
}

export function createPrivacyRouter(): Router {
  const router = Router();

  router.get('/profiles', read, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const rows = await db('privacy_profile_versions').where({ tenant_id: tenantId }).orderBy([{ column: 'ownership' }, { column: 'version', order: 'desc' }])
      .select('id', 'ownership', 'version', 'rules', 'justification', 'approval_id', 'created_by', 'approved_by', 'created_at', 'superseded_at') as VersionRow[];
    const pending = await pendingRequests(tenantId);
    const profiles: PrivacyOwnershipProfileDto[] = [];
    for (const ownership of OWNERSHIPS) {
      const mine = rows.filter((r) => r.ownership === ownership);
      const current = mine.find((r) => r.superseded_at === null);
      const p = pending.get(ownership);
      const pendingRules = p ? PrivacyProfileRulesSchema.safeParse(payloadOf(p.payload).rules) : null;
      profiles.push({
        ownership,
        current: current ? versionDto(current) : null,
        defaults: { ...DEFAULT_PRIVACY_PROFILE[ownership] },
        effective: current ? versionDto(current).rules : { ...DEFAULT_PRIVACY_PROFILE[ownership] },
        imposed: imposedKeys(ownership),
        pending: p && pendingRules?.success ? {
          approvalId: Number(p.id), requestedBy: Number(p.requested_by), requestedAt: iso(p.created_at)!, expiresAt: iso(p.expires_at)!,
          rules: pendingRules.data,
        } : null,
        history: mine.slice(0, HISTORY).map(versionDto),
      });
    }
    const canManage = req.session.role === 'admin'
      || await permissionService.userHasTenantCapability(req.session.userId!, tenantId, 'mdm.privacy.manage');
    const out: PrivacyProfilesDto = { profiles, canManage };
    res.json({ data: out });
  }));

  router.get('/profiles/:ownership/impact', read, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const ownership = ownershipParam(req);
    const proposed = rulesOrThrow(ownership, rulesOfQuery(req.query, await effectiveProfileRules(db, tenantId, ownership)));
    res.json({ data: await profileImpact(db, tenantId, ownership, proposed) });
  }));

  router.post('/profiles/:ownership', manage, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const userId = Number(req.session.userId);
    const ownership = ownershipParam(req);
    const body = ChangeBody.safeParse(req.body ?? {});
    if (!body.success) {
      const i = body.error.issues[0];
      throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
    }
    const justification = body.data.justification?.trim() ?? '';
    if (justification.length < 10) {
      throw new AppError(400, 'A justification of 10 characters at least is required', 'justificationRequired');
    }
    const rules = rulesOrThrow(ownership, body.data.rules);
    // Every check before the request is filed.
    const current = await currentProfile(db, tenantId, ownership);
    if (current && PRIVACY_RULE_KEYS.every((k) => current.rules[k] === rules[k])) {
      throw new AppError(409, `The profile ${ownership} already has these rules (version ${current.version})`, 'privacyProfileUnchanged',
        { version: current.version });
    }
    // One request at a time (filedAlone): the check of the request waiting and the filing, under a lock of the tenant.
    const { outcome, impact, reviewerSide } = await filedAlone(tenantId, `profile:${ownership}`, 'privacyProfileChangePending', async () => {
      const waiting = (await pendingRequests(tenantId)).get(ownership);
      if (waiting) {
        throw new AppError(409, `A change of the profile ${ownership} already waits for its approval`, 'privacyProfileChangePending',
          { approvalId: Number(waiting.id) });
      }
      const impact = await profileImpact(db, tenantId, ownership, rules);
      const reviewerSide = await privacyReviewerSide(tenantId, userId);
      const payload: ProfileChange = {
        action: PROFILE_CHANGE_REQUEST_TYPE, ownership, rules, justification, baseVersion: impact.baseVersion, reviewerSide,
        narrowed: impact.narrowed, widened: impact.widened,
      };
      const list = (keys: string[]): string => (keys.length ? keys.join(', ') : 'nothing');
      const description = `Privacy profile ${ownership}: version ${impact.baseVersion === null ? '1 (replaces the defaults)' : impact.baseVersion + 1}`
        + ` for ${impact.devices.total} device(s); collects less: ${list(impact.narrowed)}; collects more: ${list(impact.widened)}`
        + ` (removed: ${impact.scrub.apps} application(s), ${impact.scrub.locations} position(s)) — justification: ${justification}`;
      const outcome = await restrictionService.enforce({
        req, actionKey: 'privacy.profile_change', approvalRequestType: PROFILE_CHANGE_REQUEST_TYPE,
        approvalDescription: description, approvalPayload: payload as unknown as Record<string, unknown>,
      });
      return { outcome, impact, reviewerSide };
    });
    if (outcome.ok || !('approval' in outcome)) {
      if (!outcome.ok) {
        const o = outcome as { status: number; body: unknown; headers?: Record<string, string> };
        for (const [k, v] of Object.entries(o.headers ?? {})) res.setHeader(k, v);
        res.status(o.status).json(o.body);
        return;
      }
      // The floor 'restricted' never lets a change through without its approval.
      throw new AppError(403, 'A change of a privacy profile needs a second approver', 'approvalRequired');
    }
    const approvalId = Number(outcome.approval.id);
    await audit.append({
      tenantId, action: 'privacy.profile_change_requested', target: { type: 'privacy_profile', id: ownership }, approvalIds: [approvalId],
      reason: justification.slice(0, 500),
      details: {
        ownership, baseVersion: impact.baseVersion, narrowed: impact.narrowed, widened: impact.widened, reviewerSide,
        devices: impact.devices.total, apps: impact.scrub.apps, locations: impact.scrub.locations,
      },
    }, await audit.fromRequest(req, tenantId));
    res.status(202).json({ data: { approvalId, status: 'pending_approval', reviewerSide } });
  }));

  // ── Retention (P0-13 T4, CNF-04) ─────────────────────────────────────────

  router.get('/retention', read, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const canManage = req.session.role === 'admin'
      || await permissionService.userHasTenantCapability(req.session.userId!, tenantId, 'mdm.privacy.manage');
    const out: RetentionPolicyDto = await retentionPolicyDto(db, tenantId, canManage);
    res.json({ data: out });
  }));

  router.put('/retention', manage, h(async (req, res) => {
    const tenantId = req.tenantId!;
    const userId = Number(req.session.userId);
    const body = RetentionBody.safeParse(req.body ?? {});
    if (!body.success) {
      const i = body.error.issues[0];
      throw new AppError(400, `${i?.path.join('.') || 'request'}: ${i?.message ?? 'invalid'}`, 'invalidRequest');
    }
    const justification = body.data.justification?.trim() ?? '';
    if (justification.length < 10) {
      throw new AppError(400, 'A justification of 10 characters at least is required', 'justificationRequired');
    }
    const asked = body.data.values;
    const errors = retentionValueErrors(asked);
    if (Object.keys(asked).length === 0 || errors.unknown.length) {
      throw new AppError(400, `Unknown retention categories: ${errors.unknown.join(', ') || 'none given'}`, 'invalidRequest',
        { keys: errors.unknown });
    }
    if (errors.outOfRange.length) {
      throw new AppError(400, `Retention outside its range: ${errors.outOfRange.join(', ')}`, 'retentionOutOfRange', {
        keys: errors.outOfRange,
        ranges: Object.fromEntries(errors.outOfRange.map((k) => { const d = retentionCategoryDef(k); return [k, { min: d.min, max: d.max, unit: d.unit }]; })),
      });
    }
    // Every check before the request is filed; only the categories that change are requested.
    const row = await retentionRow(db, tenantId);
    const inForce = await retentionValues(db, tenantId);
    const changes = retentionChanges(inForce, pendingActive(row), asked as Partial<Record<RetentionCategory, number>>);
    const changed = [...changes.raised, ...changes.lowered, ...changes.restored];
    if (changed.length === 0) {
      throw new AppError(409, 'The retention already has these values', 'retentionUnchanged', { version: row.version });
    }
    // One request at a time (filedAlone): the check of the request waiting and the filing, under a lock of the tenant.
    const { outcome, values, reviewerSide } = await filedAlone(tenantId, 'retention', 'privacyRetentionChangePending', async () => {
      const waiting = await retentionRequestWaiting(db, tenantId);
      if (waiting) {
        throw new AppError(409, 'A change of the retention already waits for its approval', 'privacyRetentionChangePending',
          { approvalId: Number(waiting.id) });
      }
      const values: Partial<Record<RetentionCategory, number>> = {};
      for (const k of RETENTION_CATEGORY_KEYS) if (changed.includes(k)) values[k] = asked[k] as number;
      const reviewerSide = await privacyReviewerSide(tenantId, userId);
      const payload: RetentionChange = {
        action: RETENTION_CHANGE_REQUEST_TYPE, values, justification, baseVersion: row.version, reviewerSide,
        raised: changes.raised, lowered: changes.lowered, restored: changes.restored,
      };
      const unitOf = (k: RetentionCategory): string => (retentionCategoryDef(k).unit === 'months' ? 'month(s)' : 'day(s)');
      const list = (keys: RetentionCategory[]): string => (keys.length
        ? keys.map((k) => `${k} ${inForce[k]} → ${values[k]} ${unitOf(k)}`).join(', ') : 'nothing');
      const description = `Retention of the tenant: longer at once: ${list(changes.raised)}; shorter ${RETENTION_LOWERING_DELAY_DAYS} days after the`
        + ` approval: ${list(changes.lowered)}${changes.restored.length ? `; decrease cancelled: ${changes.restored.join(', ')}` : ''}`
        + ` — justification: ${justification}`;
      const outcome = await restrictionService.enforce({
        req, actionKey: 'privacy.retention_change', approvalRequestType: RETENTION_CHANGE_REQUEST_TYPE,
        approvalDescription: description, approvalPayload: payload as unknown as Record<string, unknown>,
      });
      return { outcome, values, reviewerSide };
    });
    if (outcome.ok || !('approval' in outcome)) {
      if (!outcome.ok) {
        const o = outcome as { status: number; body: unknown; headers?: Record<string, string> };
        for (const [k, v] of Object.entries(o.headers ?? {})) res.setHeader(k, v);
        res.status(o.status).json(o.body);
        return;
      }
      // The floor 'restricted' never lets a change through without its approval.
      throw new AppError(403, 'A change of the retention needs a second approver', 'approvalRequired');
    }
    const approvalId = Number(outcome.approval.id);
    await audit.append({
      tenantId, action: 'privacy.retention_change_requested', target: { type: 'privacy_retention', id: String(tenantId) },
      approvalIds: [approvalId], reason: justification.slice(0, 500),
      details: { values, baseVersion: row.version, raised: changes.raised, lowered: changes.lowered, restored: changes.restored, reviewerSide },
    }, await audit.fromRequest(req, tenantId));
    res.status(202).json({ data: { approvalId, status: 'pending_approval', reviewerSide } });
  }));

  return router;
}
