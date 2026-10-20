import { db } from '../../db';
import { asTenant, type DbActor } from '../../db/context';
import { withTenantTransaction } from '../../db/tenantContext';
import { edgeActorOf } from '../actors';
import { finalizeTargets } from '../commands/targets';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import { appleMetrics } from '../metrics';
import { realtime } from '../realtime';
import { pendingEnrollments } from './tenant';

// =============================================================================
// Open targets that apple-edge no longer holds (docs: integration-apple-edge
// §13.1, step 3; apple-edge.open-targets-check, and the second step of
// apple-edge.restore-check). A target 'queued', 'sent' or 'notnow' open for
// more than 24 hours (all of them after a restore) whose command is no longer
// in its device's queue at apple-edge, with no event of its end waiting in the
// outbox, becomes 'expired' (reject_code 'missing_in_edge'); the relaunches
// stay the business of §8.7. One getEnrollment per device, outside any
// transaction; 100 devices at most per tenant and pass, each at most once a
// day (the caller's once()).
// =============================================================================

/** A target is looked at once it has been open this long. */
export const OPEN_TARGET_AGE_MS = 24 * 3_600_000;
/** Devices looked at per tenant and pass. */
export const OPEN_TARGETS_PER_PASS = 100;

const OPEN = ['queued', 'sent', 'notnow'] as const;

export interface OpenTargetsOptions {
  actor: DbActor;
  requestId?: string;
  signal?: AbortSignal;
  /** After a restore: every open target, whatever its age, every device. */
  all?: boolean;
  /** Runs `check` for a device unless it was looked at today (job_once); absent: always. */
  oncePerDay?: (deviceId: number, check: () => Promise<void>) => Promise<'done' | 'skipped'>;
}

export async function checkOpenTargets(tenantId: number, o: OpenTargetsOptions): Promise<{ devices: number; expired: number }> {
  const t = await asTenant(tenantId, o.actor, () => db('tenants').where({ id: tenantId }).first('mdm_key')) as { mdm_key: string | null } | undefined;
  if (!t?.mdm_key) return { devices: 0, expired: 0 };
  const key = t.mdm_key;
  const before = new Date(Date.now() - (o.all ? 0 : OPEN_TARGET_AGE_MS));
  // The targets of Apple commands only (lot AN-D: an Android target, amapi_request_type set, is followed by its polling).
  const devices = await asTenant(tenantId, o.actor, () => db('mdm_command_targets')
    .where({ tenant_id: tenantId }).whereNull('amapi_request_type').whereIn('state', OPEN as unknown as string[])
    .where((q) => q.where('queued_at', '<', before).orWhere((w) => w.whereNull('queued_at').where('state_event_at', '<', before)))
    .groupBy('device_id').orderByRaw('min(coalesce(queued_at, state_event_at))')
    .limit(o.all ? 100_000 : OPEN_TARGETS_PER_PASS)
    .pluck('device_id')) as number[];
  if (devices.length === 0) return { devices: 0, expired: 0 };
  const pending = await pendingEnrollments(key);
  let looked = 0;
  let expired = 0;
  for (const raw of devices) {
    o.signal?.throwIfAborted();
    const deviceId = Number(raw);
    const check = async (): Promise<void> => {
      const targets = await asTenant(tenantId, o.actor, () => db('mdm_command_targets')
        .where({ tenant_id: tenantId, device_id: deviceId }).whereNull('amapi_request_type').whereIn('state', OPEN as unknown as string[])
        .where((q) => q.where('queued_at', '<', before).orWhere((w) => w.whereNull('queued_at').where('state_event_at', '<', before)))
        .select('command_id', 'enrollment_id')) as Array<{ command_id: string; enrollment_id: string }>;
      if (targets.length === 0) return;
      const enrollmentId = String(targets[0].enrollment_id);
      if (!enrollmentId.startsWith(`${key}_`) || pending.has(enrollmentId)) return;     // T-3; an event of its end may wait
      looked += 1;
      let queue: Set<string>;
      try {
        const detail = await appleEdge.getEnrollment(key, enrollmentId, { actor: edgeActorOf(o.actor), requestId: o.requestId, signal: o.signal });
        queue = new Set(detail.queue.map((q) => String(q.command_uuid).toUpperCase()));
      } catch (err) {
        if (isAppleEdgeError(err) && (err.code === 'enrollment_not_found' || err.status === 404)) queue = new Set();
        else throw err;
      }
      const missing = targets.filter((x) => String(x.enrollment_id) === enrollmentId && !queue.has(String(x.command_id).toUpperCase()));
      if (missing.length === 0) return;
      const at = new Date();
      const changed = await withTenantTransaction(tenantId, o.actor, async (trx) => {
        const out: string[] = [];
        for (const m of missing) {
          const d = await finalizeTargets(trx, {
            tenantId, commandId: String(m.command_id).toLowerCase(), deviceIds: [deviceId], from: OPEN, to: 'expired', rejectCode: 'missing_in_edge', at,
          });
          if (d.length > 0) out.push(String(m.command_id).toLowerCase());
        }
        return out;
      });
      if (changed.length > 0) {
        expired += changed.length;
        appleMetrics.reconcileFix('missing_in_edge', changed.length);
        realtime.commandChanged(tenantId, changed, [deviceId]);
      }
    };
    if (o.oncePerDay) await o.oncePerDay(deviceId, check);
    else await check();
  }
  return { devices: looked, expired };
}
