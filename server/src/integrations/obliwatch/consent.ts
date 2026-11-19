import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { OBLIWATCH_SLUG_RE, type ObliwatchConsentFlags, type ObliwatchConsentView } from '@obligarth/shared';
import { audit, isAuditUnavailable } from '../../audit';
import { db } from '../../db';
import { asTenant, switchToIdentity } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { applyRestriction } from '../../services/restriction.service';
import { tenantService } from '../../services/tenant.service';
import { OBLIWATCH_ACTOR } from './config';
import { sendError } from './auth';
import { pushStatusOf, requeueDeadInTx, withdrawPushInTx } from './push';
import { bootstrapSignalStateInTx, invalidatePushConsent, requestPushAfterCommit, requestReconcileInTx } from './signals';
import { requestSecurityLogPoliciesInTx } from './securityLogs';
import { closeOpenRequests } from './actionTrack';
import { logger } from '../../utils/logger';

// =============================================================================
// The consent of a tenant (plan §0 F5): read, push, actions, nominative AI apps, each off until a manager of the
// tenant turns it on. No row: everything off.
//   - the read API checks it per route (requireConsent), after the authentication: 403 consent_required;
//   - the console (current tenant, capability 'settings'):
//       GET /api/integrations/obliwatch/consent
//       PUT /api/integrations/obliwatch/consent  {read, push, actions, nominativeAiApps}
//     a change goes through the restriction obliwatch.settings_change (floor sensitive, strict step-up: a fresh second
//     factor, never a trusted IP), then the row and obliwatch.consent.changed (critical, from/to of each changed flag)
//     in ONE transaction: a journal that cannot be written leaves the consent unchanged (503 auditUnavailable).
//     Turning anything on is refused while the tenant's slug does not fit Obliwatch's format (422 slugIncompatible):
//     Obliwatch would refuse every token minted for it.
//   - the nominative view of the AI apps (peer request AR-55/AR-57, decision of the owner of Obliwatch) is ON by default
//     for a tenant that consents to be read: the read access turned on turns it on too, unless the same request changes it
//     or the tenant turned it off on purpose before (nominative_ai_apps_opted_out, set when it goes from on to off or when
//     the read access is turned on with it explicitly off, cleared when it goes on). Only a body that leaves
//     nominativeAiApps out gets the default (kept, or on with the read access); an explicit value always wins. The
//     console turns it on in its draft when the read access is switched on and sends the value it shows. Still
//     revocable, and journaled in the same entry (changes.nominativeAiApps).
//   - the consent to the actions withdrawn (lot L5): every open action request of Obliwatch is withdrawn at once
//     (actionTrack.ts closeOpenRequests: consent_revoked).
// =============================================================================

export type ObliwatchConsentFlag = keyof ObliwatchConsentFlags;

const COLUMN: Record<ObliwatchConsentFlag, string> = {
  read: 'read_enabled', push: 'push_enabled', actions: 'actions_enabled', nominativeAiApps: 'nominative_ai_apps',
};
const FLAGS = Object.keys(COLUMN) as ObliwatchConsentFlag[];
const OFF: ObliwatchConsentFlags = { read: false, push: false, actions: false, nominativeAiApps: false };

type Row = Record<string, unknown> | undefined;

function flagsOf(row: Row): ObliwatchConsentFlags {
  if (!row) return { ...OFF };
  return {
    read: row.read_enabled === true, push: row.push_enabled === true,
    actions: row.actions_enabled === true, nominativeAiApps: row.nominative_ai_apps === true,
  };
}

/** The consent of a tenant, in the caller's database context (a tenant context of that tenant). */
async function readRow(tenantId: number): Promise<Row> {
  return db('tenant_obliwatch_settings').where({ tenant_id: tenantId }).first() as Promise<Row>;
}

/** The consent of a tenant, for the read API and the push (context of the integration). */
export async function readConsent(tenantId: number): Promise<ObliwatchConsentFlags> {
  return flagsOf(await asTenant(tenantId, OBLIWATCH_ACTOR, () => readRow(tenantId)));
}

/**
 * The route needs this consent of the tenant of `ost` (after obliwatchAuth). 403 consent_required otherwise; a
 * database failure is a 503, never a pass.
 */
export function requireConsent(flag: ObliwatchConsentFlag) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const caller = req.obliwatch;
    if (!caller) { sendError(res, 401, 'token_missing'); return; }
    readConsent(caller.tenantId).then((c) => {
      if (!c[flag]) { sendError(res, 403, 'consent_required', 'The tenant has not consented to this access'); return; }
      next();
    }).catch(() => { if (!res.headersSent) sendError(res, 503, 'internal_error'); });
  };
}

// ── Console ─────────────────────────────────────────────────────────────────────

const Body = z.object({
  read: z.boolean(), push: z.boolean(), actions: z.boolean(), nominativeAiApps: z.boolean().optional(),
}).strict();

/** The flags a PUT asks, the default of the nominative view applied (see the header). */
function nextFlags(body: z.infer<typeof Body>, before: ObliwatchConsentFlags, optedOut: boolean): ObliwatchConsentFlags {
  const next: ObliwatchConsentFlags = { read: body.read, push: body.push, actions: body.actions, nominativeAiApps: body.nominativeAiApps ?? before.nominativeAiApps };
  const readTurnsOn = body.read && !before.read;
  // Only a body that leaves the field out gets the default: an explicit value is the manager's choice, even when it equals
  // the stored one (the console sends the value it shows).
  if (readTurnsOn && body.nominativeAiApps === undefined && !optedOut) next.nominativeAiApps = true;
  return next;
}

async function viewOf(tenantId: number, row: Row): Promise<ObliwatchConsentView> {
  const tenant = await tenantService.getById(tenantId);
  if (!tenant) throw new AppError(404, 'Tenant not found');
  const by = row?.changed_by != null ? Number(row.changed_by) : null;
  const username = by !== null
    ? ((await switchToIdentity(() => db('users').where({ id: by }).first('username'))) as { username?: string } | undefined)?.username ?? null
    : null;
  let pushStatus: ObliwatchConsentView['pushStatus'] = null;
  try { pushStatus = await pushStatusOf(db, tenantId); } catch (err) {
    logger.warn({ err: { message: (err as Error)?.message?.slice(0, 200) } }, 'obliwatch: push status not read');
  }
  return {
    tenantId, slug: tenant.slug, slugCompatible: OBLIWATCH_SLUG_RE.test(tenant.slug), ...flagsOf(row),
    changedAt: row?.changed_at ? new Date(row.changed_at as string).toISOString() : null,
    changedBy: by !== null ? { userId: by, username } : null,
    pushStatus,
  };
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

/** Mounted at /api/integrations/obliwatch under the tenant router (session, current tenant), when the integration is on. */
export function createObliwatchConsoleRouter(): Router {
  const router = Router();
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  router.get('/consent', requireTenantCapability('settings'), wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    res.json({ success: true, data: await viewOf(tenantId, await readRow(tenantId)) });
  }));

  router.put('/consent', requireTenantCapability('settings'), wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    const p = Body.safeParse(req.body ?? {});
    if (!p.success) throw new AppError(400, p.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const tenant = await tenantService.getById(tenantId);
    if (!tenant) throw new AppError(404, 'Tenant not found');
    const beforeRow = await readRow(tenantId);
    const before = flagsOf(beforeRow);
    const next = nextFlags(p.data, before, beforeRow?.nominative_ai_apps_opted_out === true);
    const turnsOn = FLAGS.some((f) => next[f] && !before[f]);
    if (turnsOn && !OBLIWATCH_SLUG_RE.test(tenant.slug)) {
      throw new AppError(422, 'The slug of this tenant does not fit the format Obliwatch requires (a-z, 0-9, -; 64 at most)',
        'slugIncompatible', { slug: tenant.slug });
    }
    const changes: Record<string, { from: boolean; to: boolean }> = {};
    for (const f of FLAGS) if (next[f] !== before[f]) changes[f] = { from: before[f], to: next[f] };
    if (Object.keys(changes).length === 0) {
      res.json({ success: true, data: await viewOf(tenantId, await readRow(tenantId)) });
      return;
    }
    if (!(await applyRestriction(res, { req, actionKey: 'obliwatch.settings_change' }))) return;
    const ctx = await audit.fromRequest(req, tenantId);
    let actionsWithdrawn = false;
    try {
      await db.transaction(async (trx) => {
        await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`obliwatch_consent:${tenantId}`]);
        const row = await trx('tenant_obliwatch_settings').where({ tenant_id: tenantId }).forUpdate().first() as Row;
        const current = flagsOf(row);
        // Read again under the lock: the default of the nominative view decided on the row as it is now.
        Object.assign(next, nextFlags(p.data, current, row?.nominative_ai_apps_opted_out === true));
        const diff: Record<string, { from: boolean; to: boolean }> = {};
        for (const f of FLAGS) if (next[f] !== current[f]) diff[f] = { from: current[f], to: next[f] };
        if (Object.keys(diff).length === 0) return;
        const values = {
          read_enabled: next.read, push_enabled: next.push, actions_enabled: next.actions, nominative_ai_apps: next.nominativeAiApps,
          ...(diff.nominativeAiApps ? { nominative_ai_apps_opted_out: !diff.nominativeAiApps.to }
            // The read access turned on with the view explicitly off: that refusal remembered too.
            : diff.read?.to && p.data.nominativeAiApps === false ? { nominative_ai_apps_opted_out: true } : {}),
          changed_by: req.session.userId!, changed_at: new Date(),
        };
        await trx('tenant_obliwatch_settings').insert({ tenant_id: tenantId, ...values }).onConflict('tenant_id').merge(Object.keys(values));
        // The push turns on (lot L3): the state of the D-MOB-* rules filled from the current data, silently (no burst
        // of signals that are not transitions). A failure refuses the change.
        // A second, normal pass two minutes later catches what a hot path changed meanwhile without recording it (a
        // transaction in flight, the consent cache of another process).
        if (diff.push && diff.push.to) {
          await bootstrapSignalStateInTx(trx, tenantId);
          await requestReconcileInTx(trx, tenantId);
        }
        // The push turns off: what waits and the dead letters are never sent, the alert of the dead letters resolved.
        if (diff.push && !diff.push.to) await withdrawPushInTx(trx, tenantId);
        // Lot L5 (GTH-08, SEC-13): the security logs follow the push consent, both ways: the policies of the company-owned
        // fully managed AMAPI devices pushed again (their usageLog added or removed).
        if (diff.push) await requestSecurityLogPoliciesInTx(trx, tenantId);
        actionsWithdrawn = !!diff.actions && !diff.actions.to;
        await audit.appendInTx(trx, {
          tenantId, action: 'obliwatch.consent.changed', outcome: 'success',
          target: { type: 'tenant', id: String(tenantId) }, details: { changes: diff },
        }, ctx);
      });
    } catch (err) {
      if (isAuditUnavailable(err)) {
        throw new AppError(503, 'Audit unavailable: the consent was not changed', 'auditUnavailable');
      }
      throw err;
    }
    invalidatePushConsent(tenantId);
    // Lot L5 (GTH-04): the consent to the actions withdrawn: every open request of Obliwatch withdrawn now (what it would
    // still send cancelled, the request closed 'cancelled', consent_revoked, journaled under this manager). The guard
    // engine refuses their guarded actions anyway, and the minute step closes what this pass could not.
    if (actionsWithdrawn) await closeOpenRequests(tenantId, 'consent_revoked', ctx);
    res.json({ success: true, data: await viewOf(tenantId, await readRow(tenantId)) });
  }));

  // The dead letters of the push put back in the queue (a new window of 72 hours), journaled; the alert resolved.
  router.post('/push/retry-dead', requireTenantCapability('settings'), wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    const ctx = await audit.fromRequest(req, tenantId);
    let requeued = 0;
    try {
      await db.transaction(async (trx) => {
        requeued = await requeueDeadInTx(trx, tenantId);
        if (requeued > 0) {
          await audit.appendInTx(trx, {
            tenantId, action: 'obliwatch.push.requeued', outcome: 'success',
            target: { type: 'tenant', id: String(tenantId) }, details: { count: requeued },
          }, ctx);
          requestPushAfterCommit(trx, tenantId);
        }
      });
    } catch (err) {
      if (isAuditUnavailable(err)) throw new AppError(503, 'Audit unavailable: nothing was requeued', 'auditUnavailable');
      throw err;
    }
    res.json({ success: true, data: { requeued } });
  }));

  return router;
}
