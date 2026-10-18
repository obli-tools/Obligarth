// Adoption of an orphan enterprise of the project (lot AN-H1; android-amapi §6.2 step 5, AN51, RR-3): an enterprise
// Google created whose binding never committed (signup interrupted between enterprises.create and the transaction 4),
// or a refused managed Google Play Accounts enterprise of a tenant that holds the exception AN8.
//   - Platform action under the restriction android.enterprise_adopt (floor restricted): a platform administrator
//     files the request in the tenant to adopt for (approval of type android_enterprise_adopt), another platform
//     administrator approves it with a strict step-up; audited android.enterprise_adopted (critical).
//   - Proof required (RR-3; the display name of a tenant is neither unique nor secret): the enterprise must carry, in
//     its display name (BASIC field of enterprises.list), the marker of a signup of THIS tenant that failed as
//     interrupted (or mgpa_refused with the exception), and its name must never have figured in the registry (no
//     state, no tenant: android_enterprise_known, and android_enterprise_bind refuses a name of another tenant anyway).
//   - Binding by android_enterprise_bind with the actor j:android.enterprise-adopt (the only other actor the function
//     admits), the project pinned, android.enterprise-setup sent (topic, display name without the marker, default
//     policy). The type is read at Google once bound: a managed Google Play Accounts enterprise without the exception
//     ends unlinked at once (its name stays in the registry, never bound again).
import { MASTER_TENANT_ID } from '@obligarth/shared';
import { ANDROID_APPROVAL_TYPES } from '@obligarth/shared/dist/android/operations.js';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit/types';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import {
  approvalService, registerApprovalRequestType, requirePlatformAdmin, type ApprovalExecution, type ApprovalRequestType,
} from '../../services/approval.service';
import { raiseAndroidTenantAlert } from '../alerts';
import { androidConfig } from '../config';
import { MAINTENANCE_ACTOR, adoptableBy } from '../enterprises/orphans';
import { pinProject, readEnterprise } from '../enterprises/registry';
import { sendSetupInTx } from '../enterprises/signup';
import { androidGateway } from '../gateway';
import type { AndroidGateway } from '../gateway/types';

export const ADOPT_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.enterprise-adopt' }) as DbActor;
const NAME_RE = /^enterprises\/[A-Za-z0-9_-]{1,100}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class AdoptionError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.name = 'AdoptionError';
    this.status = status;
    this.code = code;
  }
}

interface AdoptRequest { tenantId: number; enterpriseName: string; signupId: string; reason: string }

function parse(raw: Record<string, unknown>): AdoptRequest {
  const tenantId = Number(raw.tenantId);
  const enterpriseName = String(raw.enterpriseName ?? '');
  const signupId = String(raw.signupId ?? '');
  const reason = typeof raw.reason === 'string' ? raw.reason.trim() : '';
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0 || !NAME_RE.test(enterpriseName) || !UUID_RE.test(signupId)) {
    throw new AdoptionError(400, 'invalidInput', 'tenant, enterprise name and signup required');
  }
  if (reason.length < 5 || reason.length > 500) throw new AdoptionError(400, 'reasonRequired', 'A reason of 5 to 500 characters is required');
  return { tenantId, enterpriseName, signupId, reason };
}

interface SignupFacts { id: string; enterprise_id: number; state: string; failure_code: string | null; mgpa_exception: boolean; enterprise_state: string }

/** The failed signup of the tenant and its enterprise row (tenant context). */
async function signupFacts(signupId: string): Promise<SignupFacts | null> {
  const r = await db('android_signups as s').join('android_enterprises as e', function j() { this.on('e.id', '=', 's.enterprise_id').andOn('e.tenant_id', '=', 's.tenant_id'); })
    .where('s.id', signupId).first('s.id', 's.enterprise_id', 's.state', 's.failure_code', 'e.mgpa_exception', 'e.state as enterprise_state') as SignupFacts | undefined;
  return r ?? null;
}

/** Why this signup cannot found an adoption (null: it can). */
export function signupRefusal(f: SignupFacts | null, tenantId: number): string | null {
  if (!f) return 'androidSignupNotFound';
  if (f.state !== 'failed') return 'androidSignupNotInterrupted';
  if (f.failure_code === 'interrupted') return null;
  if (f.failure_code === 'mgpa_refused' && (f.mgpa_exception || tenantId === MASTER_TENANT_ID)) return null;
  return 'androidSignupNotInterrupted';
}

/**
 * The orphans of the project adoptable by a tenant: the enterprises Google lists whose name never figured in the
 * registry and whose display name carries the marker of a failed signup of this tenant. Platform administrator only
 * (the route of the master tenant); the listing itself runs in the context 'none' of the maintenance.
 */
export async function listAdoptable(tenantId: number, o: { gateway?: AndroidGateway } = {}): Promise<Array<{ enterpriseName: string; signupId: string }>> {
  const gw = o.gateway ?? androidGateway();
  const signups = await asTenant(tenantId, ADOPT_ACTOR, () => db('android_signups').where({ tenant_id: tenantId, state: 'failed' })
    .whereIn('failure_code', ['interrupted', 'mgpa_refused']).pluck('id')) as string[];
  if (!signups.length) return [];
  const orphans = await projectOrphans(gw);
  const out: Array<{ enterpriseName: string; signupId: string }> = [];
  for (const o2 of orphans) {
    const id = adoptableBy(o2, signups);
    if (id) out.push({ enterpriseName: o2.name, signupId: id });
  }
  return out;
}

/** enterprises.list of the project minus every name the registry ever knew (context 'none'). */
async function projectOrphans(gw: AndroidGateway) {
  return asNone(MAINTENANCE_ACTOR, async () => {
    const all: Array<{ name: string; enterpriseDisplayName?: string }> = [];
    let token: string | undefined;
    for (let page = 0; page < 100; page++) {
      const r = await gw.listProjectEnterprises(token);
      all.push(...r.items);
      token = r.nextPageToken;
      if (!token) break;
    }
    if (!all.length) return [];
    const r = await db.raw('SELECT obligarth.android_enterprise_known(?::text[]) AS k', [all.map((e) => e.name)]) as { rows: Array<{ k: string[] }> };
    const known = new Set(r.rows[0]?.k ?? []);
    return all.filter((e) => !known.has(e.name));
  });
}

/** POST /api/admin/android/orphans/adopt (platform administrator of the master tenant): the restricted request. */
export async function requestAdoption(userId: number, raw: Record<string, unknown>, auditCtx: AuditWriteContext) {
  await requirePlatformAdmin(userId).catch(() => { throw new AdoptionError(403, 'notAllowed', 'platform administrators only'); });
  const r = parse(raw);
  const facts = await asTenant(r.tenantId, ADOPT_ACTOR, () => signupFacts(r.signupId));
  const refusal = signupRefusal(facts, r.tenantId);
  if (refusal) throw new AdoptionError(409, refusal);
  const approval = await asTenant(r.tenantId, { type: 'user', userId }, () => db.transaction((trx) => approvalService.createInTx(trx, {
    tenantId: r.tenantId, userId, requestType: ANDROID_APPROVAL_TYPES.adopt as ApprovalRequestType,
    description: `Adopt the orphan Android enterprise ${r.enterpriseName} — reason: ${r.reason}`,
    payload: { action: ANDROID_APPROVAL_TYPES.adopt, enterpriseName: r.enterpriseName, signupId: r.signupId, reason: r.reason, tenantId: r.tenantId },
    auditCtx,
  })));
  approvalService.announceCreated(approval);
  return approval;
}

export type AdoptOutcome = 'adopted' | 'mgpa_refused';

/** The adoption itself (executor of android_enterprise_adopt, or a test): proofs checked again, then the binding. */
export async function adoptEnterprise(tenantId: number, raw: Record<string, unknown>, o: { gateway?: AndroidGateway; requesterId?: number; approvalId?: number } = {}):
  Promise<AdoptOutcome> {
  const gw = o.gateway ?? androidGateway();
  const r = parse({ ...raw, tenantId });
  const cfg = androidConfig();
  // 1. The signup of this tenant, failed as interrupted (or MGPA refused with the exception).
  const facts = await asTenant(tenantId, ADOPT_ACTOR, () => signupFacts(r.signupId));
  const refusal = signupRefusal(facts, tenantId);
  if (refusal || !facts) throw new AdoptionError(409, refusal ?? 'androidSignupNotFound');
  // 2. An orphan of the project that never figured in the registry, carrying the marker of that signup (RR-3).
  const orphan = (await projectOrphans(gw)).find((x) => x.name === r.enterpriseName);
  if (!orphan) throw new AdoptionError(409, 'androidNotAnOrphan', 'not an enterprise of the project outside the registry');
  if (adoptableBy(orphan, [r.signupId]) !== r.signupId) throw new AdoptionError(409, 'androidMarkerMismatch', 'the enterprise does not carry the marker of this signup');
  // 3. The binding, in the tenant, by android_enterprise_bind (actor j:android.enterprise-adopt).
  const ctx = o.requesterId ? await audit.fromDbActor({ type: 'user', userId: o.requesterId }, tenantId)
    : audit.fromJob({ name: 'android.enterprise-adopt', requestId: `android-adopt-${tenantId}-${r.signupId}` });
  const type = facts.failure_code === 'mgpa_refused' ? 'MANAGED_GOOGLE_PLAY_ACCOUNTS_ENTERPRISE' : 'ENTERPRISE_TYPE_UNSPECIFIED';
  const enterpriseId = await asTenant(tenantId, ADOPT_ACTOR, () => db.transaction(async (trx) => {
    const live = await trx('android_enterprises').where({ tenant_id: tenantId }).whereIn('state', ['linked', 'unlinking', 'error']).first('id');
    if (live) throw new AdoptionError(409, 'androidAlreadyLinked', 'the tenant already has an Android enterprise');
    if (await trx('android_signups').where({ tenant_id: tenantId }).whereIn('state', ['requested', 'url_issued', 'consuming']).first('id')) {
      throw new AdoptionError(409, 'androidSignupInProgress', 'a signup is in progress');
    }
    const pending = await trx('android_enterprises').where({ tenant_id: tenantId, state: 'pending' }).forUpdate().first('id') as { id: number } | undefined;
    if (!pending) throw new AdoptionError(409, 'androidSignupNotFound', 'no pending enterprise row for this tenant');
    const pinned = await pinProject(trx, String(cfg.projectId));
    await trx.raw('SELECT obligarth.android_enterprise_bind(?, ?, ?, ?, ?, ?)', [tenantId, pending.id, r.enterpriseName, type, cfg.projectId, null]);
    await sendSetupInTx(trx, tenantId);
    await audit.appendInTx(trx, {
      tenantId, action: 'android.enterprise_adopted', target: { type: 'android_enterprise', id: String(pending.id) },
      ...(o.approvalId ? { approvalIds: [o.approvalId] } : {}),
      details: { enterpriseName: r.enterpriseName, signupId: r.signupId, reason: r.reason },
    }, ctx);
    if (pinned === 'pinned') {
      await audit.appendInTx(trx, { tenantId, action: 'android.project_pinned', target: { type: 'android_enterprise', id: String(pending.id) }, details: { projectId: cfg.projectId } }, ctx);
    }
    return pending.id;
  }));
  // 4. The type read at Google once bound (enterprises.list gives the BASIC view only).
  return asTenant(tenantId, ADOPT_ACTOR, async () => {
    const e = await readEnterprise();
    if (!e) return 'adopted';
    const g = await gw.getEnterprise(e);
    const realType = g.enterpriseType ?? 'ENTERPRISE_TYPE_UNSPECIFIED';
    const mgpaRefused = realType === 'MANAGED_GOOGLE_PLAY_ACCOUNTS_ENTERPRISE' && !facts.mgpa_exception && tenantId !== MASTER_TENANT_ID;
    await db('android_enterprises').where({ tenant_id: tenantId, id: enterpriseId }).update({
      enterprise_type: realType, domain_type: g.managedGoogleDomainType ?? null, updated_at: db.fn.now(),
      ...(mgpaRefused ? { state: 'unlinked', unlink_reason: 'offboarding', unlinked_at: db.fn.now() } : {}),
    });
    if (mgpaRefused) {
      void raiseAndroidTenantAlert(tenantId, 'android.signup_failed', { code: 'mgpa_refused' });
      return 'mgpa_refused';
    }
    return 'adopted';
  });
}

/** Executor of android_enterprise_adopt: the requester must still be a platform administrator. */
export async function executeAdoption(x: ApprovalExecution): Promise<string | void> {
  await requirePlatformAdmin(x.requesterId);
  const r = await adoptEnterprise(x.tenantId, x.payload as Record<string, unknown>, { requesterId: x.requesterId, approvalId: x.approvalId });
  return r === 'mgpa_refused' ? 'managed Google Play Accounts enterprise without the exception: left unlinked' : undefined;
}

let registered = false;
/** The approval request type of the adoption (registered by registerAndroidModule): another platform administrator. */
export function registerAndroidAdoptionApprovals(): void {
  if (registered) return;
  registered = true;
  registerApprovalRequestType(ANDROID_APPROVAL_TYPES.adopt, executeAdoption, { reviewerStepUp: 'strict', expiryMinutes: 24 * 60 });
}
