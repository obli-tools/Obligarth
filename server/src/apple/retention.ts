import type { Knex } from 'knex';
import { db } from '../db';
import type { MdmRetentionRule } from '../mdm/inventory/retention';
import { monthsBefore, retentionCutoff } from '../privacy/retention';
import { logger } from '../utils/logger';
import { isAppleEdgeError } from './edge/errors';
import { appleEdge } from './edge/instance';

// =============================================================================
// Retention of the Apple integration (docs: integration-apple-edge §4.9, §13.3;
// modele-donnees-mdm §5.5, §6.1, DM19), handed to the generic retention
// (CNF-04, modules/privacy.ts), tenant by tenant, in slices (motif M8):
//   - appleRetentionRules: the commands of the queue and their targets
//     (technical_log_months of the tenant after their end, 6 by default; 30
//     days for the origin 'inventory', fixed: DM19), the timeline of the
//     devices (technical_log_months), the devices removed from Apple Business
//     (90 days, fixed); the months are the tenant's (P0-13 T4, CNF-04:
//     privacy/retention.ts, read at each slice);
//   - purgeEnrollmentSessionsSlice, purgeEnrollmentTokensSlice: the job
//     enrollment.purge-expired (sessions 30 days after their end, tokens 90
//     days after their expiry or their revocation);
//   - purgeDeviceInEdge: appleDevices.purgeInEdge of §13.3, called for each
//     record due before the brain deletes it.
// Same contract as the rules of the data model (mdm/inventory/retention.ts):
// at most `limit` rows of one tenant per call, in the caller's transaction and
// the tenant's context. Never logs an enrollment id.
// =============================================================================

/** Days the commands of the origin 'inventory' are kept after their end (modele DM19; fixed, not a tenant's setting). */
export const INVENTORY_COMMAND_RETENTION_DAYS = 30;
/** Days a device removed from Apple Business stays listed (apple_ade_devices.removed_at). */
export const ADE_REMOVED_RETENTION_DAYS = 90;
/** Days an enrollment session is kept after it ended, or after the expiry of an abandoned one. */
export const ENROLLMENT_SESSION_RETENTION_DAYS = 30;
/** Days an enrollment token is kept after it expired or was revoked. */
export const ENROLLMENT_TOKEN_RETENTION_DAYS = 90;

/** Target states that are not final (rank < 3): a command with one of them is never purged. */
const OPEN_TARGET_STATES = ['pending', 'queued', 'sent', 'notnow'];
/** Submission states of a command that will not be submitted again ('pending' and 'held' still may). */
const SETTLED_SUBMIT_STATES = ['submitted', 'failed', 'cancelled'];
const SESSION_FINAL_STATES = ['enrolled', 'failed', 'expired'];

const daysBefore = (now: Date, n: number): Date => new Date(now.getTime() - n * 86_400_000);

/** `now` minus `months` calendar months (UTC), the day clamped to the end of the month (privacy/retention.ts). */
export { monthsBefore };

// ── The commands of the queue ───────────────────────────────────────────────

/** Ids of at most `limit` commands that ended before `cutoff`: created before it, past their expiry, their
 *  submission settled, and every target final since before it (none pending, queued, sent or notnow, none
 *  whose last event is more recent). `inventory`: the origin 'inventory' only, or every other origin. */
async function endedCommands(trx: Knex.Transaction, tenantId: number, now: Date, cutoff: Date, inventory: boolean,
  limit: number): Promise<string[]> {
  const q = trx('mdm_commands as c').where('c.tenant_id', tenantId)
    .whereIn('c.submit_state', SETTLED_SUBMIT_STATES)
    .where('c.created_at', '<', cutoff)
    .where('c.expires_at', '<', now)
    .whereNotExists(function recentOrOpenTargets() {
      this.select('t.command_id').from('mdm_command_targets as t')
        .whereRaw('t.tenant_id = c.tenant_id AND t.command_id = c.id')
        .where((w) => w.whereIn('t.state', OPEN_TARGET_STATES).orWhere('t.state_event_at', '>=', cutoff));
    });
  if (inventory) void q.where('c.origin', 'inventory');
  else void q.whereNot('c.origin', 'inventory');
  return (await q.orderBy('c.created_at', 'asc').limit(limit).pluck('c.id')) as string[];
}

/**
 * mdm_commands and their targets (cascade), integration §4.9 and modele §6.1: a command is purged
 * technical_log_months of the tenant after its end (6 by default; 30 days for the origin 'inventory', DM19: the
 * bulk of the volume, of no use to the audit). Every platform (the Android commands are in the same queue).
 * Never a command still waiting for its submission ('pending', 'held') or with a target in flight.
 */
const commandRetentionRule: MdmRetentionRule = {
  name: 'mdm_commands',
  description: `Commands of the queue ended technical_log_months ago (${INVENTORY_COMMAND_RETENTION_DAYS} days for the inventory), every target final`,
  async purge(trx, tenantId, now, limit) {
    let removed = 0;
    for (const [cutoff, inventory] of [
      [daysBefore(now, INVENTORY_COMMAND_RETENTION_DAYS), true],
      [await retentionCutoff(trx, tenantId, 'technical_log_months', now), false],
    ] as Array<[Date, boolean]>) {
      if (removed >= limit) break;
      const ids = await endedCommands(trx, tenantId, now, cutoff, inventory, limit - removed);
      if (ids.length) removed += await trx('mdm_commands').where({ tenant_id: tenantId }).whereIn('id', ids).del();
    }
    return removed;
  },
};

export const appleRetentionRules: readonly MdmRetentionRule[] = Object.freeze([
  commandRetentionRule,
  {
    name: 'apple_device_events',
    description: 'Timeline of the devices older than the months of the tenant (technical_log_months)',
    async purge(trx, tenantId, now, limit) {
      const cutoff = await retentionCutoff(trx, tenantId, 'technical_log_months', now);
      const ids = await trx('apple_device_events').where({ tenant_id: tenantId }).where('occurred_at', '<', cutoff)
        .orderBy('occurred_at', 'asc').limit(limit).pluck('id') as string[];
      return ids.length ? trx('apple_device_events').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
    },
  },
  {
    name: 'apple_ade_devices.removed',
    description: `Devices removed from Apple Business for ${ADE_REMOVED_RETENTION_DAYS} days`,
    async purge(trx, tenantId, now, limit) {
      const cutoff = daysBefore(now, ADE_REMOVED_RETENTION_DAYS);
      const ids = await trx('apple_ade_devices').where({ tenant_id: tenantId }).whereNotNull('removed_at')
        .where('removed_at', '<', cutoff).orderBy('removed_at', 'asc').limit(limit).pluck('id') as string[];
      return ids.length ? trx('apple_ade_devices').where({ tenant_id: tenantId }).whereIn('id', ids).del() : 0;
    },
  },
]);

// ── Enrollment sessions and tokens (job enrollment.purge-expired) ─────────────

/** One slice: sessions ended (enrolled, failed, expired) more than 30 days ago, then sessions never ended,
 *  without a device, expired more than 30 days ago (abandoned). The satellite and the episodes that name a
 *  purged session lose the reference only (ON DELETE SET NULL). */
export async function purgeEnrollmentSessionsSlice(trx: Knex.Transaction, tenantId: number, now: Date, limit: number): Promise<number> {
  const cutoff = daysBefore(now, ENROLLMENT_SESSION_RETENTION_DAYS);
  const ended = await trx('enrollment_sessions').where({ tenant_id: tenantId })
    .whereIn('state', SESSION_FINAL_STATES).where('state_at', '<', cutoff)
    .orderBy('state_at', 'asc').limit(limit).pluck('id') as string[];
  const abandoned = ended.length >= limit ? [] : await trx('enrollment_sessions').where({ tenant_id: tenantId })
    .whereNotIn('state', SESSION_FINAL_STATES).whereNull('device_id').where('expires_at', '<', cutoff)
    .orderBy('expires_at', 'asc').limit(limit - ended.length).pluck('id') as string[];
  const ids = [...ended, ...abandoned];
  if (!ids.length) return 0;
  return trx('enrollment_sessions').where({ tenant_id: tenantId }).whereIn('id', ids).del();
}

/** One slice: enrollment tokens (links, invitations) unusable for more than 90 days, since their expiry or
 *  their revocation, whichever came first. The sessions opened with one lose the reference only. */
export async function purgeEnrollmentTokensSlice(trx: Knex.Transaction, tenantId: number, now: Date, limit: number): Promise<number> {
  const cutoff = daysBefore(now, ENROLLMENT_TOKEN_RETENTION_DAYS);
  const ids = await trx('enrollment_tokens').where({ tenant_id: tenantId })
    .where((w) => w.where('expires_at', '<', cutoff).orWhere('revoked_at', '<', cutoff))
    .orderBy('expires_at', 'asc').limit(limit).pluck('id') as string[];
  if (!ids.length) return 0;
  return trx('enrollment_tokens').where({ tenant_id: tenantId }).whereIn('id', ids).del();
}

// ── Device records: purge at apple-edge first (integration §13.3) ───────────

/** 'purged': every enrollment of the record is gone at apple-edge (or is another record's to purge): the
 *  record may be deleted. 'deferred': this record waits for the next run. The two others stop the device
 *  records of the tenant for this run. */
export type EdgePurgeOutcome = 'purged' | 'deferred' | 'edge_unavailable' | 'tenant_unknown_at_edge';

/** What purgeDeviceInEdge needs of the job that runs it (a JobContext of a tenant job). */
export interface EdgePurgeContext {
  readonly actor: string;
  readonly requestId: string;
  readonly signal: AbortSignal;
  throwIfAborted(): void;
  /** fn in the tenant's database context, each statement its own lease (no transaction held open). */
  inTenant<T>(fn: () => Promise<T>): Promise<T>;
}

const enrollmentGone = (err: unknown): boolean => isAppleEdgeError(err) && err.code === 'enrollment_not_found';
const tenantUnknown = (err: unknown): boolean => isAppleEdgeError(err) && err.code === 'tenant_not_found';
const edgeUnavailable = (err: unknown): boolean => isAppleEdgeError(err)
  && (err.retryable || err.code === 'disabled' || err.code === 'incompatible' || err.status === 401);
const edgeCode = (err: unknown): string => (isAppleEdgeError(err) ? String(err.code) : 'error');
const fingerprint = (v: unknown): string => (typeof v === 'string' ? v.trim().toLowerCase() : '');

/** Is the record still due (out of management, retention passed)? */
async function stillDue(tenantId: number, deviceId: number, now: Date): Promise<boolean> {
  const row = await db('devices').where({ tenant_id: tenantId, id: deviceId, enrollment_state: 'unenrolled' })
    .whereNotNull('retention_until').where('retention_until', '<=', now).first('id');
  return Boolean(row);
}

/** Those of `ids` that another record of the tenant holds too (its satellite or one of its episodes) while
 *  that record is not itself due for purge: a device still under management, or one whose retention runs.
 *  Such an enrollment is that record's: this purge neither purges nor releases it at apple-edge. */
async function heldByLiveRecords(tenantId: number, deviceId: number, ids: readonly string[], now: Date): Promise<Set<string>> {
  if (!ids.length) return new Set();
  const notDue = (q: Knex.QueryBuilder): void => {
    void q.whereNot('d.enrollment_state', 'unenrolled').orWhereNull('d.retention_until').orWhere('d.retention_until', '>', now);
  };
  const sat = await db('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId).whereIn('a.enrollment_id', ids).whereNot('a.device_id', deviceId).where(notDue)
    .pluck('a.enrollment_id') as string[];
  const episodes = await db('device_enrollments as e')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'e.device_id').andOn('d.tenant_id', '=', 'e.tenant_id'); })
    .where('e.tenant_id', tenantId).whereIn('e.channel_enrollment_id', ids).whereNot('e.device_id', deviceId).where(notDue)
    .distinct().pluck('e.channel_enrollment_id') as string[];
  return new Set([...sat, ...episodes]);
}

/**
 * appleDevices.purgeInEdge (integration §13.3) for one record due: every enrollment id of its episodes and of
 * its satellite is purged at apple-edge (an enrollment apple-edge no longer knows is done).
 *   - 409 enrollment_active: the enrollment is released, then purged again, but only while the record is
 *     still due, no other live record holds the enrollment, and apple-edge shows it under an identity
 *     certificate this record knows. Under another certificate the device enrolled again and the brain has
 *     not recorded that cycle yet (an event late or in the dead letters): releasing it would take a device
 *     out of management, so the record waits.
 *   - An enrollment id also held by a record that is not due (the device came back under another record)
 *     is left alone: that record purges it at its own retention.
 *   - An id that is not of this tenant's key, an open episode, any refusal of apple-edge: the record waits.
 * Outside any transaction; the caller deletes the record only on 'purged'.
 */
export async function purgeDeviceInEdge(ctx: EdgePurgeContext, tenantId: number, key: string, deviceId: number, now: Date):
  Promise<EdgePurgeOutcome> {
  const found = await ctx.inTenant(async () => {
    if (!(await stillDue(tenantId, deviceId, now))) return null;
    const episodes = await db('device_enrollments').where({ tenant_id: tenantId, device_id: deviceId })
      .select('channel_enrollment_id', 'cert_sha256', 'ended_at') as
      Array<{ channel_enrollment_id: string | null; cert_sha256: string | null; ended_at: Date | null }>;
    const sat = await db('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('enrollment_id', 'cert_sha256') as
      { enrollment_id: string | null; cert_sha256: string | null } | undefined;
    // Each enrollment id of the record, with the identity certificates the record knows for it.
    const certs = new Map<string, Set<string>>();
    const note = (id: string | null | undefined, cert: string | null | undefined): void => {
      if (typeof id !== 'string' || id === '') return;
      const set = certs.get(id) ?? new Set<string>();
      if (fingerprint(cert)) set.add(fingerprint(cert));
      certs.set(id, set);
    };
    for (const e of episodes) note(e.channel_enrollment_id, e.cert_sha256);
    note(sat?.enrollment_id, sat?.cert_sha256);
    const ids = [...certs.keys()];
    return { open: episodes.some((e) => e.ended_at === null), ids, certs, held: await heldByLiveRecords(tenantId, deviceId, ids, now) };
  });
  if (!found) return 'deferred';                       // back under management meanwhile: not deleted
  if (found.open) {
    logger.warn({ tenantId, deviceId }, 'retention: record out of management with an open episode: postponed');
    return 'deferred';
  }
  if (found.ids.some((id) => !id.startsWith(`${key}_`) || id.length <= key.length + 1)) {
    logger.warn({ tenantId, deviceId }, 'retention: an enrollment of the record is not of this tenant: postponed');
    return 'deferred';
  }
  const o = { actor: ctx.actor, requestId: ctx.requestId, signal: ctx.signal };
  /** The outcome for an error of apple-edge that ends the work on this record (null: the enrollment is gone). */
  const refusal = (err: unknown, step: string): EdgePurgeOutcome | null => {
    if (enrollmentGone(err)) return null;
    if (tenantUnknown(err)) return 'tenant_unknown_at_edge';
    if (edgeUnavailable(err)) return 'edge_unavailable';
    if (!isAppleEdgeError(err)) throw err;
    logger.warn({ tenantId, deviceId, step, code: edgeCode(err) }, 'retention: apple-edge refused: record postponed');
    return 'deferred';
  };
  for (const enrollmentId of found.ids) {
    ctx.throwIfAborted();
    if (found.held.has(enrollmentId)) continue;        // another record's enrollment: never touched here
    try {
      await appleEdge.purgeEnrollment(key, enrollmentId, o);
      continue;
    } catch (err) {
      if (!(isAppleEdgeError(err) && err.code === 'enrollment_active')) {
        const r = refusal(err, 'purge');
        if (r) return r;
        continue;
      }
    }
    // enrollment_active. Released only for a record still due, an enrollment no live record took since, and
    // the identity this record knows.
    const mine = await ctx.inTenant(async () => (await stillDue(tenantId, deviceId, now))
      && !(await heldByLiveRecords(tenantId, deviceId, [enrollmentId], now)).has(enrollmentId));
    if (!mine) return 'deferred';
    try {
      const detail = await appleEdge.getEnrollment(key, enrollmentId, o);
      const atEdge = fingerprint(detail.enrollment.cert_sha256);
      if (!atEdge || !found.certs.get(enrollmentId)?.has(atEdge)) {
        logger.warn({ tenantId, deviceId },
          'retention: enrollment active at apple-edge under an identity the record does not know (enrolled again?): postponed');
        return 'deferred';
      }
    } catch (err) {
      const r = refusal(err, 'read');
      if (r) return r;
      continue;                                        // gone meanwhile
    }
    try {
      await appleEdge.releaseEnrollment(key, enrollmentId, o);
    } catch (err) {
      const r = refusal(err, 'release');
      if (r) return r;                                 // enrollment_not_found: nothing to release, purge below
    }
    try {
      await appleEdge.purgeEnrollment(key, enrollmentId, o);
    } catch (err) {
      const r = refusal(err, 'purge_after_release');
      if (r) return r;
    }
  }
  return 'purged';
}
