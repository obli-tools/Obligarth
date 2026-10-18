// Handler of the USAGE_LOGS notifications (amapi.usage_logs, sections 8.1, 11.2; lot AN-F2; criterion 6): the events of
// the lost mode only (the usage logs of the policy are not collected otherwise in v1).
//   - LOST_MODE_LOCATION: the position of a company device in lost mode (fully managed 11+, COPE 13+), kept 30 days
//     (lost_mode_locations, purge_at); never for a personal device (the device is ignored as a whole; the table refuses
//     it too, lost_mode_locations_guard), never for a device whose lost mode is off (a late event);
//   - STOP_LOST_MODE_USER_ATTEMPT with ATTEMPT_SUCCEEDED: the user left the lost mode on the device: lost mode off, and
//     the time of the exit kept (android_lost_mode_exits): Google refuses START_LOST_MODE for 12 hours after it
//     (USER_EXIT_LOST_MODE_RECENTLY), the bus refuses it before any call.
// No network call (G-A3); identifiers only in the logs (G-A4): never a coordinate.
import type { z } from 'zod';
import { registerAndroidEventHandler, type AndroidEventContext } from '../inbox/handlers';
import { UsageLogsSchema } from '../inbox/schemas';

type Logs = z.infer<typeof UsageLogsSchema>;
type Ctx = AndroidEventContext<Logs>;

/** Positions are kept 30 days (lost_mode_locations_purge_cap allows 62). */
export const LOST_MODE_LOCATION_DAYS = 30;
/** Events read per notification (a batch of usage logs may hold thousands of events of other kinds). */
const MAX_EVENTS = 500;
const MAX_POSITIONS = 50;

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
const time = (v: unknown): Date | null => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? new Date(v) : null);

export interface LostModePosition { latitude: number; longitude: number; observedAt: Date }

/** The lost mode events of a batch, pure: the positions (valid coordinates only) and the last successful user exit. */
export function lostModeEvents(events: unknown, receivedAt: Date): { positions: LostModePosition[]; userExitAt: Date | null } {
  const positions: LostModePosition[] = [];
  let userExitAt: Date | null = null;
  for (const raw of (Array.isArray(events) ? events : []).slice(0, MAX_EVENTS)) {
    const e = obj(raw);
    const at = time(e.eventTime);
    // A time in the future (clock of the device) counts as the reception.
    const when = at && at.getTime() <= receivedAt.getTime() + 300_000 ? at : receivedAt;
    if (e.eventType === 'LOST_MODE_LOCATION') {
      const loc = obj(obj(e.lostModeLocationEvent).location);
      const lat = Number(loc.latitude);
      const lon = Number(loc.longitude);
      if (typeof loc.latitude === 'number' && typeof loc.longitude === 'number' && Number.isFinite(lat) && Number.isFinite(lon)
        && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 && positions.length < MAX_POSITIONS) {
        positions.push({ latitude: lat, longitude: lon, observedAt: when });
      }
    } else if (e.eventType === 'STOP_LOST_MODE_USER_ATTEMPT' && obj(e.stopLostModeUserAttemptEvent).status === 'ATTEMPT_SUCCEEDED') {
      if (!userExitAt || when.getTime() > userExitAt.getTime()) userExitAt = when;
    }
  }
  return { positions, userExitAt };
}

export async function onUsageLogs(ctx: Ctx): Promise<'applied' | 'ignored'> {
  const { trx, tenantId } = ctx;
  const p = ctx.event.payload;
  const row = await trx('android_devices as a').join('devices as dv', function j() { this.on('dv.id', '=', 'a.device_id').andOn('dv.tenant_id', '=', 'a.tenant_id'); })
    .where('a.amapi_name', p.device).whereNull('a.released_at').first('a.device_id', 'dv.ownership', 'dv.lost_mode_state') as
    { device_id: number; ownership: string; lost_mode_state: string | null } | undefined;
  // Unknown (quarantined, released, not enrolled yet) or personal: nothing is written, ever (criterion 6).
  if (!row || row.ownership === 'personal') return 'ignored';
  const deviceId = Number(row.device_id);
  const { positions, userExitAt } = lostModeEvents(p.usageLogEvents, ctx.event.receivedAt);
  let state = row.lost_mode_state ?? 'off';
  if (userExitAt) {
    await trx.raw(
      `INSERT INTO obligarth.android_lost_mode_exits AS x (tenant_id, device_id, exited_at) VALUES (?, ?, ?)
       ON CONFLICT (tenant_id, device_id) DO UPDATE SET exited_at = GREATEST(x.exited_at, EXCLUDED.exited_at)`,
      [tenantId, deviceId, userExitAt]);
    const n = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).whereIn('lost_mode_state', ['enabling', 'on', 'disabling'])
      .whereNot('ownership', 'personal').where((q) => q.whereNull('lost_mode_changed_at').orWhere('lost_mode_changed_at', '<=', userExitAt))
      .update({ lost_mode_state: 'off', lost_mode_changed_at: userExitAt });
    if (Number(n) > 0) state = 'off';
  }
  if (positions.length && (state === 'on' || state === 'enabling')) {
    const purge = new Date(Date.now() + LOST_MODE_LOCATION_DAYS * 86_400_000);
    await trx('lost_mode_locations').insert(positions.map((x) => ({
      tenant_id: tenantId, device_id: deviceId, latitude: x.latitude, longitude: x.longitude, observed_at: x.observedAt, purge_at: purge,
    })));
  }
  return 'applied';
}

let registered = false;

export function registerUsageLogsHandler(): void {
  if (registered) return;
  registered = true;
  registerAndroidEventHandler({
    type: 'amapi.usage_logs',
    payload: UsageLogsSchema,
    async handle(ctx) { await onUsageLogs(ctx); },
  });
}
