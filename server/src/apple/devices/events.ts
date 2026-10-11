import type { Knex } from 'knex';

// =============================================================================
// Timeline of an Apple device (docs: integration-apple-edge §7.4, column
// « Chronologie », §12.4; PLT-15): what happened to its enrollment, identity
// and push channel, written by the outbox handlers in the event's savepoint
// (apple_device_events, one row per event and kind: apple_device_events_dedup
// makes a replayed event write nothing). The details are internal values
// only (reasons, codes, counts, directions; 2 KiB at most): never an
// identifier of the device, a serial number, an address nor a name (T-4,
// T-5). The unified timeline (§12.4) merges these entries with the targets of
// the device's commands and its status history: deviceTimeline(), read by
// the console API of the commands (§8.12).
// =============================================================================

export const DEVICE_EVENT_KINDS = [
  'enrollment_started', 'enrolled', 'awaiting_configuration', 'configured', 'checked_out', 'released', 'transferred',
  'identity_expired', 'identity_revoked', 'id_conflict', 'push_failed', 'push_inactive', 'setup_timeout',
] as const;
export type DeviceEventKind = typeof DEVICE_EVENT_KINDS[number];

/** Largest details of an entry (bytes of its JSON). */
const MAX_DETAILS_BYTES = 2048;
const KIND_RE = /^[a-z][a-z0-9_]{0,47}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type TimelineDetails = Record<string, string | number | boolean | null>;

/** Scalars only, names of 40 characters, strings of 200; the whole under 2 KiB (else dropped). */
function cleanDetails(details: TimelineDetails | undefined): TimelineDetails {
  const out: TimelineDetails = {};
  for (const [k, v] of Object.entries(details ?? {}).slice(0, 16)) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(k)) continue;
    if (typeof v === 'string') out[k] = v.slice(0, 200);
    else if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'boolean' || v === null) out[k] = v;
  }
  return Buffer.byteLength(JSON.stringify(out)) <= MAX_DETAILS_BYTES ? out : {};
}

export const deviceEvents = {
  /**
   * One entry of the timeline of `deviceId`, in the caller's transaction (the tenant's context). Returns true
   * when written, false when the event already wrote this kind (a replay): the caller writes the effects that
   * go with the entry (an audit entry) on true only.
   */
  async add(trx: Knex.Transaction, tenantId: number, deviceId: number, kind: DeviceEventKind | string, occurredAt: Date,
    eventId: string | null, details?: TimelineDetails): Promise<boolean> {
    if (!KIND_RE.test(kind)) throw new Error(`timeline: invalid kind ${JSON.stringify(kind)}`);
    const source = eventId && UUID_RE.test(eventId) ? eventId.toLowerCase() : null;
    const res = await trx.raw(`
      INSERT INTO obligarth.apple_device_events (tenant_id, device_id, kind, occurred_at, source_event_id, details)
      VALUES (?, ?, ?, ?, ?, ?::jsonb)
      ON CONFLICT (source_event_id, kind) WHERE source_event_id IS NOT NULL DO NOTHING
      RETURNING id`, [tenantId, deviceId, kind, occurredAt, source, JSON.stringify(cleanDetails(details))]) as { rows: unknown[] };
    return res.rows.length > 0;
  },

  /** Has the current enrollment cycle of the device (since its Authenticate) an entry of `kind` already? */
  async inCurrentCycle(trx: Knex.Transaction, tenantId: number, deviceId: number, kind: DeviceEventKind): Promise<boolean> {
    const res = await trx.raw(`
      SELECT 1 FROM obligarth.apple_device_events e
        JOIN obligarth.apple_devices a ON a.device_id = e.device_id AND a.tenant_id = e.tenant_id
       WHERE e.tenant_id = ? AND e.device_id = ? AND e.kind = ? AND e.occurred_at >= a.authenticated_at
       LIMIT 1`, [tenantId, deviceId, kind]) as { rows: unknown[] };
    return res.rows.length > 0;
  },
};

/** One entry of the unified timeline (§12.4). */
export interface TimelineEntry {
  at: string;
  source: 'device_event' | 'command' | 'status';
  kind: string;
  /** Translation key of the console: apple.timeline.<kind> for an entry of the device, apple.timeline.command_requested,
   *  command_delivered and command_<final state> for a command, apple.status.<item> for a status item (an open set, the
   *  DDM status channel's: the console falls back on the item's name). */
  i18nKey: string;
  params: Record<string, unknown>;
  /** Reference of the entry in its source (event row id, command id, status history row id). */
  ref: string;
}

const iso = (v: unknown): string => new Date(v as string | Date).toISOString();

/**
 * The unified timeline of a device, newest first (§12.4): its apple_device_events, the targets of its commands
 * (requested, delivered, ended, with type, origin and state) and its status history, before `before`, `limit`
 * entries at most (1 to 200). In the caller's connection or transaction and the tenant's context.
 */
export async function deviceTimeline(q: Knex | Knex.Transaction, tenantId: number, deviceId: number,
  opts: { before?: Date | null; limit?: number } = {}): Promise<TimelineEntry[]> {
  const limit = Math.min(200, Math.max(1, Math.floor(opts.limit ?? 50)));
  const before = opts.before && !Number.isNaN(opts.before.getTime()) ? opts.before : new Date(8.64e15);
  const events = await q('apple_device_events').where({ tenant_id: tenantId, device_id: deviceId })
    .where('occurred_at', '<', before).orderBy('occurred_at', 'desc').orderBy('id', 'desc').limit(limit)
    .select('id', 'kind', 'occurred_at', 'details') as Array<{ id: number; kind: string; occurred_at: Date; details: Record<string, unknown> | null }>;
  const targets = await q('mdm_command_targets as t')
    .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
    .where({ 't.tenant_id': tenantId, 't.device_id': deviceId })
    .where('c.created_at', '<', before)
    // By the latest entry of the target before `before` (its request, delivery or end): a command requested long ago
    // and ended lately belongs to the page of its end, whatever the number of commands requested since.
    .orderByRaw(`GREATEST(c.created_at, CASE WHEN t.delivered_at < ? THEN t.delivered_at END,
                          CASE WHEN t.completed_at < ? THEN t.completed_at END) DESC`, [before, before])
    .limit(limit)
    .select('t.command_id', 't.state', 't.delivered_at', 't.completed_at', 't.reject_code', 'c.request_type', 'c.origin',
      'c.requested_by', 'c.created_at') as Array<Record<string, any>>;
  const status = await q('device_status_history').where({ tenant_id: tenantId, device_id: deviceId })
    .where('observed_at', '<', before).orderBy('observed_at', 'desc').limit(limit)
    .select('id', 'item', 'value', 'observed_at') as Array<{ id: number; item: string; value: unknown; observed_at: Date }>;
  const out: TimelineEntry[] = [];
  for (const e of events) {
    out.push({ at: iso(e.occurred_at), source: 'device_event', kind: e.kind, i18nKey: `apple.timeline.${e.kind}`,
      params: e.details ?? {}, ref: String(e.id) });
  }
  for (const t of targets) {
    const params = { requestType: t.request_type, origin: t.origin, state: t.state, requestedBy: t.requested_by ?? null,
      rejectCode: t.reject_code ?? null };
    out.push({ at: iso(t.created_at), source: 'command', kind: 'command_requested', i18nKey: 'apple.timeline.command_requested',
      params, ref: String(t.command_id) });
    if (t.delivered_at && new Date(t.delivered_at) < before) {
      out.push({ at: iso(t.delivered_at), source: 'command', kind: 'command_delivered', i18nKey: 'apple.timeline.command_delivered',
        params, ref: String(t.command_id) });
    }
    if (t.completed_at && new Date(t.completed_at) < before) {
      out.push({ at: iso(t.completed_at), source: 'command', kind: 'command_ended', i18nKey: `apple.timeline.command_${t.state}`,
        params, ref: String(t.command_id) });
    }
  }
  for (const s of status) {
    out.push({ at: iso(s.observed_at), source: 'status', kind: s.item, i18nKey: `apple.status.${s.item}`,
      params: { value: s.value ?? null }, ref: String(s.id) });
  }
  return out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0)).slice(0, limit);
}
