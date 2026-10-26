import type { Knex } from 'knex';
import { MASTER_TENANT_ID, privacyRuleChanges, type Ownership } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asTenant, userActor } from '../db/context';
import { fallbackHold, personFacts, reviewerFacts } from '../guard/people';
import { reviewerRefusal } from '../guard/policy';
import { AppError } from '../middleware/errorHandler';
import { refuse, requireTenantCapability, type ApprovalExecution, type ApprovalReviewCheck } from '../services/approval.service';
import { requestProfileApplication } from './apply';
import { checkProfileRules, effectiveProfileRules, invalidatePrivacyProfiles, publishProfile } from './profiles';
import { ProfileChangePayload, type PrivacyReviewerSide } from './requests';

// =============================================================================
// Changes of the privacy profiles under a second person (P0-13 T3, CNF-02; D3: level 'restricted', not configurable).
//   - Who examines (privacyReviewerSide at the filing, privacyReviewerPolicy at the decision), as the journal's
//     requests (audit/module.ts journalReviewerPolicy): a designated client approver of the tenant when it has one
//     besides the requester (strict second factor of the reviewer); otherwise another platform administrator, unless the
//     client lost a client approver recently through someone else's act (AUD-A7-R4: the fallback stays closed,
//     409 approverFallbackHeld, nothing filed). A request filed on the platform side is approved there only while the
//     tenant still has no other client approver (one designated since: 409 approverSideRequired, file it again) and the
//     fallback is not held. The requester never reviews; an account in its 72-hour cooldown neither. A refusal stays
//     open to both sides (protective).
//   - The executor (request type privacy_profile_change), as the requester: mdm.privacy.manage read again, the rules
//     checked again (imposed rules), the profile unchanged since the request (else refused: file it again), then in one
//     transaction the publication (obligarth.privacy_profile_publish, which checks the request itself), the application
//     to the fleet (privacy.apply-profile, privacy/apply.ts), the hooks of the publication (the notice, T5) and the
//     entry privacy.profile_changed (critical, P1: nothing is published when it cannot be written).
// =============================================================================

/** Designated client approvers of the tenant able to examine a request of `requesterId` (an active account of a client
 *  role, never a platform administrator, never the requester). In the tenant's context. */
export async function clientApproversBesides(tenantId: number, requesterId: number): Promise<number> {
  const ids = await db('tenant_approvers').where({ tenant_id: tenantId, side: 'client' }).whereNull('revoked_at').pluck('user_id') as number[];
  let n = 0;
  for (const id of new Set(ids.map(Number))) {
    if (id === requesterId) continue;
    const f = await personFacts(id, tenantId);
    if (f.active && f.audience === 'client' && !f.platformAdmin) n++;
  }
  return n;
}

/** The side that examines a request of `requesterId` filed now in `tenantId` (its context): 409 approverFallbackHeld
 *  when nobody could approve it. */
export async function privacyReviewerSide(tenantId: number, requesterId: number): Promise<PrivacyReviewerSide> {
  if (tenantId === MASTER_TENANT_ID) return 'platform';
  if ((await clientApproversBesides(tenantId, requesterId)) > 0) return 'client';
  const hold = await fallbackHold(tenantId);
  if (hold) {
    throw new AppError(409, 'No client approver: a client approver was removed recently, and the fallback on another platform administrator '
      + `stays closed until ${hold.until.toISOString()} (designate a client approver, or wait)`, 'approverFallbackHeld', { until: hold.until.toISOString() });
  }
  return 'platform';
}

const REVIEWER_MESSAGES: Record<string, string> = {
  selfApproval: 'The requester cannot review this request',
  reviewerInactive: 'Your account cannot review this request',
  privilegeCooldown: 'Your approver or administrator rights are too recent to review this request',
  approverSideRequired: 'This request needs a designated client approver of the tenant, or another platform administrator when the tenant has none',
};

const reviewError = (status: number, code: string, message: string, details?: Record<string, unknown>): Error =>
  Object.assign(new Error(message), { status, code, ...(details ? { details } : {}) });

/** The examination policy of the requests of the privacy pages (the strict step-up is the type's). */
export async function privacyReviewerPolicy(x: ApprovalReviewCheck): Promise<void> {
  const tenantId = x.approval.tenantId;
  const side: PrivacyReviewerSide = (x.approval.payload as { reviewerSide?: unknown } | null)?.reviewerSide === 'client' ? 'client' : 'platform';
  const seen = await asTenant(tenantId, userActor(x.reviewerId), async () => {
    const facts = await reviewerFacts(x.reviewerId, tenantId);
    const now = side === 'platform' && x.decision === 'approve' && tenantId !== MASTER_TENANT_ID
      ? await (async () => {
        const clients = await clientApproversBesides(tenantId, x.approval.requestedBy);
        return { clients, hold: clients === 0 ? await fallbackHold(tenantId) : null };
      })()
      : null;
    return { facts, now };
  });
  if (seen.now?.clients) {
    throw reviewError(409, 'approverSideRequired', 'The tenant has a client approver now: file the request again, it will be reviewed by the client');
  }
  if (seen.now?.hold) {
    throw reviewError(409, 'approverFallbackHeld',
      `The client lost its client approver recently: the fallback stays closed until ${seen.now.hold.until.toISOString()}`,
      { until: seen.now.hold.until.toISOString() });
  }
  // A refusal is protective: either side. An approval: the side of the request; the platform side is another platform
  // administrator only (not a designated MSP approver).
  const required = x.decision === 'deny' ? 'any' : side === 'client' ? 'client' : 'msp';
  const refusal = reviewerRefusal(required, [x.approval.requestedBy], seen.facts);
  if (refusal) {
    throw reviewError(403, refusal, REVIEWER_MESSAGES[refusal] ?? 'Not allowed to review this request',
      refusal === 'privilegeCooldown' && seen.facts.cooldownUntil ? { until: seen.facts.cooldownUntil.toISOString() } : undefined);
  }
  if (x.decision === 'approve' && side === 'platform' && !seen.facts.platformAdmin) {
    throw reviewError(403, 'approverSideRequired', REVIEWER_MESSAGES.approverSideRequired);
  }
}

// ── Execution ──────────────────────────────────────────────────────────────

/** What else a publication starts, in its transaction (the regeneration of the notice, P0-13 T5). */
export type ProfilePublishedHook = (trx: Knex.Transaction, p: { tenantId: number; ownership: Ownership; profileId: string; version: number }) => Promise<void>;
const publishedHooks: Array<{ name: string; run: ProfilePublishedHook }> = [];

export function onProfilePublished(name: string, run: ProfilePublishedHook): void {
  if (publishedHooks.some((h) => h.name === name)) throw new Error(`privacy profile hook '${name}' registered twice`);
  publishedHooks.push({ name, run });
}

/** The current version of an ownership, read in `trx` under the lock of the publications of the tenant (the one of
 *  obligarth.privacy_profile_publish: taken again there, in the same transaction). */
async function lockedCurrentVersion(trx: Knex.Transaction, tenantId: number, ownership: Ownership): Promise<number | null> {
  await trx.raw("SELECT pg_advisory_xact_lock(hashtext('obligarth.privacy_profile_publish'), ?)", [tenantId]);
  const r = await trx.raw('SELECT version FROM obligarth.privacy_profile_current(?) WHERE ownership = ?', [tenantId, ownership]) as
    { rows: Array<{ version: number }> };
  return r.rows[0] ? Number(r.rows[0].version) : null;
}

/** An approved change of a profile, executed as the requester (in the approval's tenant context). */
export async function executeProfileChange(x: ApprovalExecution): Promise<void> {
  const parsed = ProfileChangePayload.safeParse(x.payload ?? {});
  if (!parsed.success) refuse('Malformed privacy profile request');
  const p = parsed.data;
  if (!x.approvalId) refuse('A privacy profile is published from its approval only');
  await requireTenantCapability(x.requesterId, x.tenantId, 'mdm.privacy.manage');
  const check = checkProfileRules(p.ownership, p.rules);
  if (!check.ok) refuse(`${check.code}: ${check.keys.join(', ')}`);
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await db.transaction(async (trx) => {
    const base = await lockedCurrentVersion(trx, x.tenantId, p.ownership);
    if (base !== p.baseVersion) {
      refuse(`privacyProfileChanged: the profile ${p.ownership} changed since the request (version ${base ?? 'none'} now); file it again`);
    }
    // What changes against the rules in force now (the same as at the filing, the version being unchanged), read from
    // the base (another process may have published since this one cached the tenant).
    invalidatePrivacyProfiles(x.tenantId);
    const changes = privacyRuleChanges(await effectiveProfileRules(trx, x.tenantId, p.ownership), p.rules);
    const out = await publishProfile(trx, x.tenantId, {
      ownership: p.ownership, rules: p.rules, justification: p.justification, approvalId: x.approvalId!,
    });
    await requestProfileApplication(trx, x.tenantId, p.ownership, base);
    for (const h of publishedHooks) await h.run(trx, { tenantId: x.tenantId, ownership: p.ownership, profileId: out.id, version: out.version });
    await audit.appendInTx(trx, {
      tenantId: x.tenantId, action: 'privacy.profile_changed', target: { type: 'privacy_profile', id: p.ownership },
      approvalIds: [x.approvalId!],
      details: {
        ownership: p.ownership, version: out.version, previousVersion: base, narrowed: changes.narrowed, widened: changes.widened,
        reviewerSide: p.reviewerSide, viaApproval: true,
      },
    }, ctx);
  });
}
