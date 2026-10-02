// The rules of the guard engine that need no database (docs: audit-durci
// §10.2 to §10.6; unit tests U11, U12): bulk or single, the burst
// requalification, the whole fleet, the hourly cap, the typed confirmation,
// the level, and the side an approver must be on. The engine feeds them with
// what it read.
import {
  GUARD_BULK_THRESHOLD, GUARD_REASON_MAX, GUARD_REASON_MIN, GUARD_TICKET_MAX,
  type GuardApproverSide, type GuardLevel, type GuardSelection, type GuardSide,
} from '@obligarth/shared';

/** A matrix level ('none' below the floors). */
export type MatrixLevel = 'none' | GuardLevel;

const RANK: Record<MatrixLevel, number> = { none: 0, sensitive: 1, restricted: 2 };

/** The stricter of two levels. */
export function stricter(a: MatrixLevel, b: MatrixLevel): MatrixLevel {
  return RANK[a] >= RANK[b] ? a : b;
}

/** A selection by group or by tenant is a batch whatever its count. */
export function selectsByGroupOrTenant(selection: GuardSelection): boolean {
  return selection.tenant === true || (Array.isArray(selection.groupIds) && selection.groupIds.length > 0);
}

/**
 * Bulk or single (§10.3 step 7): bulk from `threshold` targets (3, D23), or
 * any group or tenant selection; a single request is requalified as bulk
 * when its requester already made `priorSingles` (two or more) single
 * requests of the same family in the last 15 minutes (J22: no mass erase cut
 * into unit requests).
 */
export function classify(count: number, selection: GuardSelection, priorSingles: number,
  threshold = GUARD_BULK_THRESHOLD): { bulk: boolean; requalified: boolean } {
  const byShape = count >= threshold || selectsByGroupOrTenant(selection);
  if (byShape) return { bulk: true, requalified: false };
  if (priorSingles >= 2) return { bulk: true, requalified: true };
  return { bulk: false, requalified: false };
}

/** The whole fleet (§10.3 step 6): a tenant selection, or targets covering
 *  every active device of a fleet of 3 or more. */
export function isWholeFleet(selection: GuardSelection, count: number, fleetSize: number): boolean {
  if (selection.tenant === true) return true;
  return count >= GUARD_BULK_THRESHOLD && fleetSize > 0 && count >= fleetSize;
}

/** The hourly cap (§10.6): 10 % of the active fleet by default, at least 5
 *  devices (percent and minimum from the tenant's settings). */
export function hourlyCap(fleetSize: number, percent: number, minimum: number): number {
  const byPercent = Math.ceil((Math.max(0, fleetSize) * percent) / 100);
  return Math.max(minimum, byPercent);
}

/** May `count` more targets be engaged when `used` already are? */
export function capAllows(cap: number, used: number, count: number): boolean {
  return used + count <= cap;
}

/** What the requester must type (§10.3 step 9): the device's displayed name
 *  for one device of a single request, the number of targets otherwise. */
export function expectedConfirmation(bulk: boolean, count: number, singleName: string | null): string {
  if (!bulk && count === 1 && singleName) return singleName;
  return String(count);
}

/** The typed confirmation, exact once trimmed. */
export function confirmationMatches(typed: unknown, expected: string): boolean {
  return typeof typed === 'string' && typed.trim() === expected.trim() && expected.trim() !== '';
}

/** Level of a request (§10.3 step 10): the stricter of the matrix (already
 *  floored by the action's single floor) and of the floor of the request's
 *  kind; a batch is always 'restricted'. */
export function requestLevel(matrix: MatrixLevel, singleFloor: GuardLevel, bulk: boolean): GuardLevel {
  const floor: GuardLevel = bulk ? 'restricted' : singleFloor;
  const level = stricter(matrix, floor);
  return level === 'none' ? floor : level;
}

/** The reason and the ticket of a request (§10.3 step 1). */
export function checkReason(reason: unknown, ticket: unknown): { ok: true; reason: string; ticket: string | null } | { ok: false; code: 'reasonRequired' | 'invalidTicket' } {
  const r = typeof reason === 'string' ? reason.trim() : '';
  if (r.length < GUARD_REASON_MIN || r.length > GUARD_REASON_MAX) return { ok: false, code: 'reasonRequired' };
  if (ticket !== undefined && ticket !== null && ticket !== '') {
    if (typeof ticket !== 'string' || ticket.trim().length > GUARD_TICKET_MAX) return { ok: false, code: 'invalidTicket' };
    return { ok: true, reason: r, ticket: ticket.trim() || null };
  }
  return { ok: true, reason: r, ticket: null };
}

/**
 * The side an approver must be on (§10.4, D24): a requester of the MSP needs
 * the tenant's mass_approver_side (the client by default), and falls back on
 * the MSP side (marked) when the client side is required while the tenant
 * has no designated client approver; a client requester may be approved by
 * any designated approver of either side. The fallback is held (AUD-A7-R4)
 * while a loss of a client approver that the approver did not decide is
 * recent (`fallbackHeldUntil` in the future): the client side stays
 * required, with nobody to approve, and the caller refuses the request
 * (approverFallbackHeld) — the MSP cannot remove the client approvers and
 * then approve alone.
 */
export function requiredApproverSide(requesterSide: GuardSide, massApproverSide: GuardSide,
  activeClientApprovers: number, fallbackHeldUntil: Date | null = null, now: Date = new Date()): RequiredApproverSide {
  if (requesterSide === 'client') return { side: 'any', fallback: false };
  if (massApproverSide === 'client') {
    if (activeClientApprovers > 0) return { side: 'client', fallback: false };
    if (fallbackHeldUntil && fallbackHeldUntil.getTime() > now.getTime()) {
      return { side: 'client', fallback: false, heldUntil: fallbackHeldUntil };
    }
    return { side: 'msp', fallback: true };
  }
  return { side: 'msp', fallback: false };
}

/** The side a request requires; `heldUntil`: no client approver, and the
 *  fallback on the MSP side held until then (AUD-A7-R4). */
export interface RequiredApproverSide {
  side: GuardApproverSide;
  fallback: boolean;
  heldUntil?: Date;
}

/** What a reviewer is, for the guard's examination policy. */
export interface ReviewerFacts {
  userId: number;
  active: boolean;
  platformAdmin: boolean;
  /** Audience of the reviewer's role in the tenant (null: no role there). */
  audience: GuardSide | null;
  /** Active designations in the tenant. */
  designatedClient: boolean;
  designatedMsp: boolean;
  /** End of a 72-hour cooldown (platform_admin, tenant_admin, approver), or null. */
  cooldownUntil: Date | null;
}

export type ReviewerRefusal =
  | 'selfApproval' | 'reviewerInactive' | 'privilegeCooldown' | 'approverSideRequired';

/**
 * May this reviewer approve (or deny) a request of the guard (§10.4 points 1
 * to 3)? The requester never reviews; an inactive account or one in its
 * cooldown never does; the client side takes a designated client approver
 * holding a client-audience role in the tenant, never a platform
 * administrator (always on the MSP side, §9.1, whatever its role in the
 * tenant); the MSP side a platform administrator or a designated MSP
 * approver; 'any' either.
 */
export function reviewerRefusal(required: GuardApproverSide, requesterIds: readonly number[], r: ReviewerFacts,
  now: Date = new Date()): ReviewerRefusal | null {
  if (requesterIds.includes(r.userId)) return 'selfApproval';
  if (!r.active) return 'reviewerInactive';
  if (r.cooldownUntil && r.cooldownUntil.getTime() > now.getTime()) return 'privilegeCooldown';
  const client = r.designatedClient && r.audience === 'client' && !r.platformAdmin;
  const msp = r.platformAdmin || r.designatedMsp;
  const ok = required === 'client' ? client : required === 'msp' ? msp : (client || msp);
  return ok ? null : 'approverSideRequired';
}
