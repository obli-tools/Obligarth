import type { Knex } from 'knex';
import { z } from 'zod';
import { db } from '../db';
import { isMasterTenant } from '@obligarth/shared';
import { logger } from '../utils/logger';
import { userLabels } from './userLabels.service';

/**
 * Change-event timeline — "what changed on this device, when, and who did it".
 *
 * Answers "what was DONE to the machine around T", so an incident can be
 * correlated with the change that caused it (Oblidesk's Blame Ribbon).
 *
 * ── Endpoints (registered in `routes/device.routes.ts`) ──────────────────────
 *
 *   GET /api/devices/:id/change-events?from=<iso>&to=<iso>&kinds=<csv>&limit=<n>
 *     → { data: { formatVersion, deviceId, from, to, order, kinds, limit,
 *                 truncated, count, events: ChangeEvent[] } }
 *
 *   GET /api/devices/:id/change-events/summary?from=<iso>&to=<iso>
 *     → { data: { formatVersion, deviceId, from, to, kinds, total,
 *                 counts: Record<ChangeEventKind, number> } }
 *
 *   Guard: `requireDeviceRead()`, as the device itself.
 *   `from`/`to` accept ISO-8601 or epoch-ms. Defaults: to = now, from = to-24h.
 *   Window is capped at 30 days and the list at 2000 rows; hitting the row cap
 *   sets `truncated: true` and drops the OLDEST events (the ribbon cares about
 *   what happened closest to the incident), never silently.
 *   Events are returned NEWEST FIRST (`order: 'desc'`), like every other
 *   listing in this codebase.
 *
 * ── Read-through union, no new storage ──────────────────────────────────────
 * Nothing is ingested, backfilled or denormalised: every kind is a live read
 * over the table that already owns that fact (modele-donnees-mdm §11.1: kinds
 * added without a new formatVersion, the addition being compatible).
 *
 *   config_change      audit_logs                      ← ADMIN ONLY, see below
 *   enrollment         device_enrollments              (a cycle starts, a cycle ends)
 *   mdm_command        mdm_command_targets             (final targets of the integration's queue)
 *   os_change          device_status_history           (device.operating-system.version)
 *
 * ── Permissions ─────────────────────────────────────────────────────────────
 * `requireDeviceRead()` is necessary but not sufficient: a source protected
 * more tightly elsewhere MUST NOT become readable here. `audit_logs` is
 * admin-only (`routes/audit.routes.ts` mounts `requireRole('admin')` on the
 * whole router), so `config_change` is dropped for non-admins. The kinds
 * actually served are echoed back in `kinds` so the caller can tell "no
 * events" apart from "not allowed to see that kind".
 *
 * ── formatVersion ───────────────────────────────────────────────────────────
 * Currently 4. Never change the exported shape silently — bump
 * `FORMAT_VERSION` below (and tell Oblidesk) when a field is renamed, removed
 * or restructured. `title`/`detail` are English fallbacks: consumers should
 * localise from `kind` + `payload`, which are the stable machine-readable part.
 * Version 1 also had the kinds patch_deployed, script_run, schedule_run,
 * scenario_run, compliance_drift, software_installed and software_removed,
 * and the actor types schedule, scenario and api (removed modules). Version 2
 * also had the kinds agent_upgraded and reboot (the agent's command queue and
 * its reported boot time) and the actor type agent (removed agent). Version 3
 * also had the kind remote_session (the remote sessions table of the removed
 * remote access).
 */

const FORMAT_VERSION = 4 as const;

export const CHANGE_EVENT_KINDS = [
  'config_change',
  'enrollment',
  'mdm_command',
  'os_change',
] as const;

export type ChangeEventKind = (typeof CHANGE_EVENT_KINDS)[number];
export type ChangeEventActorType = 'user' | 'system';
export type ChangeEventSeverityHint = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface ChangeEvent {
  id: string;
  kind: ChangeEventKind;
  at: string;
  title: string;
  detail: string | null;
  actor: string | null;
  actorType: ChangeEventActorType;
  severityHint: ChangeEventSeverityHint;
  resourceType: string | null;
  resourceId: string | null;
  resourcePath: string | null;
  payload: Record<string, unknown>;
}

const MAX_WINDOW_DAYS = 30;
const MAX_WINDOW_MS = MAX_WINDOW_DAYS * 24 * 60 * 60 * 1000;
const DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LIMIT = 500;
const MAX_LIMIT = 2000;

// ── Query helpers ────────────────────────────────────────────────────────────

/** Tenant-scoped base query on an aliased device-owned table. Only the global
 *  view (a platform administrator on the master tenant: hasGlobalView, passed
 *  by the route) keeps the device filter alone; anyone else, a member or a
 *  tenant administrator of the master tenant included, reads the rows of
 *  `tenantId` only. */
function scope(table: string, alias: string, ctx: SourceContext): Knex.QueryBuilder {
  const q = db(`${table} as ${alias}`).where(`${alias}.device_id`, ctx.deviceId);
  if (!(ctx.globalView && isMasterTenant(ctx.tenantId))) q.where(`${alias}.tenant_id`, ctx.tenantId);
  return q;
}

function toIso(v: unknown): string {
  return new Date(v as any).toISOString();
}

function toObj(v: unknown): Record<string, unknown> {
  if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  if (typeof v === 'string') {
    try {
      const p = JSON.parse(v);
      return p && typeof p === 'object' && !Array.isArray(p) ? p : {};
    } catch { return {}; }
  }
  return {};
}

function actorName(row: any): string | null {
  return row.actor_display_name || row.actor_username || null;
}

/** Truncate free text so a single stderr-ish blob can't bloat the timeline. */
function short(v: unknown, max = 300): string | null {
  if (v == null) return null;
  const s = String(v).trim();
  if (!s) return null;
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Destroying or moving a device is a far better blame candidate than a
 *  routine setting tweak. */
function auditSeverityHint(action: string): ChangeEventSeverityHint {
  if (/\.(deleted|refused|suspended|transferred|cleared)$/.test(action)) return 'high';
  return 'medium';
}

// ── Sources ──────────────────────────────────────────────────────────────────

interface EventSource {
  /** Source table — echoed in the event id so a row is always traceable. */
  table: string;
  /** WHERE predicates only; no select/order/limit (the count path reuses it). */
  base: () => Knex.QueryBuilder;
  /** Columns for the list path — must include the event instant `as at`. */
  columns: (string | Knex.Raw)[];
  /** Raw SQL expression the rows are ordered/windowed on. */
  order: string;
  /** Column counted by the summary path. */
  countOn: string;
  map: (row: any) => ChangeEvent;
}

interface SourceContext {
  deviceId: number;
  tenantId: number;
  from: Date;
  to: Date;
  callerUserId: number;
  callerIsAdmin: boolean;
  /** The caller holds audit.read in the device's tenant (audit-durci §9.7). */
  callerReadsAudit: boolean;
  /** The master tenant's global view (hasGlobalView(req)): see scope(). */
  globalView: boolean;
}

// The actors' names come from obligarth.user_labels (rls-tenant §5.3.3): an
// MSP administrator who acted on a client's device is named, an account of
// another client never (a join on users would only name the members the row
// level security shows).

/** Every source for a kind, in the order they are merged. A kind absent from
 *  the returned map is one the caller is not allowed to read (config_change
 *  for non-admins) — never one that silently returned nothing. */
function buildSources(ctx: SourceContext): Partial<Record<ChangeEventKind, EventSource[]>> {
  const { from, to } = ctx;

  const sources: Partial<Record<ChangeEventKind, EventSource[]>> = {};

  // The journal is read by the platform administrators and by the holders of
  // audit.read in the device's tenant (routes/audit.routes.ts, audit-durci
  // §9.7) — do not widen it here. Anyone else gets the kind omitted from
  // `kinds`.
  if (ctx.callerIsAdmin || ctx.callerReadsAudit) {
    sources.config_change = [{
      table: 'audit_logs',
      base: () => scope('audit_logs', 'al', ctx)
        .whereBetween('al.created_at', [from, to]),
      columns: [
        'al.id', 'al.action', 'al.resource_type', 'al.resource_path', 'al.details',
        'al.user_id', 'al.ip_address', 'al.created_at as at',
      ],
      order: 'al.created_at',
      countOn: 'al.id',
      map: (r) => ({
        id: `config_change:audit_logs:${r.id}`,
        kind: 'config_change',
        at: toIso(r.at),
        title: `Configuration change — ${r.action}`,
        detail: short(r.resource_path),
        actor: actorName(r),
        actorType: r.user_id ? 'user' : 'system',
        severityHint: auditSeverityHint(r.action),
        resourceType: r.resource_type ?? null,
        resourceId: r.resource_path ?? null,
        resourcePath: (r.resource_type === 'file' || r.resource_type === 'directory') ? r.resource_path : null,
        payload: { action: r.action, details: toObj(r.details), ipAddress: r.ip_address ?? null },
      }),
    }];
  }

  // Enrollment cycles (modele-donnees-mdm §4.7): a cycle that starts, a cycle that ends. The device's own
  // facts, readable by whoever reads the device.
  sources.enrollment = [{
    table: 'device_enrollments',
    base: () => scope('device_enrollments', 'de', ctx).whereBetween('de.started_at', [from, to]),
    columns: ['de.id', 'de.enrollment_type', 'de.management_mode', 'de.ownership', 'de.started_at as at'],
    order: 'de.started_at',
    countOn: 'de.id',
    map: (r) => ({
      id: `enrollment:device_enrollments:${r.id}:start`,
      kind: 'enrollment',
      at: toIso(r.at),
      title: `Enrollment started — ${r.enrollment_type}`,
      detail: `${r.ownership} · ${r.management_mode}`,
      actor: null,
      actorType: 'system',
      severityHint: 'medium',
      resourceType: 'enrollment',
      resourceId: String(r.id),
      resourcePath: null,
      payload: { phase: 'started', method: r.enrollment_type, mode: r.management_mode, ownership: r.ownership },
    }),
  }, {
    table: 'device_enrollments',
    base: () => scope('device_enrollments', 'de', ctx).whereNotNull('de.ended_at').whereBetween('de.ended_at', [from, to]),
    columns: ['de.id', 'de.end_reason', 'de.ended_at as at'],
    order: 'de.ended_at',
    countOn: 'de.id',
    map: (r) => ({
      id: `enrollment:device_enrollments:${r.id}:end`,
      kind: 'enrollment',
      at: toIso(r.at),
      title: r.end_reason === 'replaced' ? 'Enrollment replaced by a new cycle' : `Left management — ${r.end_reason}`,
      detail: null,
      actor: null,
      actorType: 'system',
      severityHint: r.end_reason === 'replaced' ? 'medium' : 'high',
      resourceType: 'enrollment',
      resourceId: String(r.id),
      resourcePath: null,
      payload: { phase: 'ended', reason: r.end_reason },
    }),
  }];

  // MDM commands that reached a final state on the device (the integration's queue). No parameter, no result:
  // the request type, the origin and the outcome only.
  sources.mdm_command = [{
    table: 'mdm_command_targets',
    base: () => scope('mdm_command_targets', 't', ctx)
      .join('mdm_commands as c', function joinCommand() { this.on('c.id', '=', 't.command_id').andOn('c.tenant_id', '=', 't.tenant_id'); })
      .whereIn('t.state', ['acknowledged', 'error', 'expired', 'cancelled', 'rejected'])
      .whereNotNull('t.completed_at')
      .whereBetween('t.completed_at', [from, to]),
    columns: ['t.command_id', 't.state', 't.reject_code', 'c.request_type', 'c.origin', 't.completed_at as at',
      db.raw("CASE WHEN c.actor ~ '^u:[0-9]{1,9}$' THEN substring(c.actor from 3)::int END AS user_id")],
    order: 't.completed_at',
    countOn: 't.command_id',
    map: (r) => ({
      id: `mdm_command:mdm_command_targets:${String(r.command_id).toUpperCase()}`,
      kind: 'mdm_command',
      at: toIso(r.at),
      title: `MDM command ${r.request_type} — ${r.state}`,
      detail: r.reject_code ? short(r.reject_code, 64) : null,
      actor: actorName(r),
      actorType: r.user_id ? 'user' : 'system',
      severityHint: /^(EraseDevice|DeviceLock|EnableLostMode|DisableLostMode|ClearPasscode|RemoveProfile|RemoveApplication|WIPE|LOCK|RESET_PASSWORD|START_LOST_MODE|STOP_LOST_MODE|RELINQUISH_OWNERSHIP|CLEAR_APP_DATA)$/.test(String(r.request_type)) ? 'high' : 'medium',
      resourceType: 'mdm_command',
      resourceId: String(r.command_id).toUpperCase(),
      resourcePath: null,
      payload: { requestType: r.request_type, state: r.state, origin: r.origin, rejectCode: r.reject_code ?? null },
    }),
  }];

  // OS version changes reported by the device's DDM status channel (history kept at the changes only).
  sources.os_change = [{
    table: 'device_status_history',
    base: () => scope('device_status_history', 'h', ctx)
      .where('h.item', 'device.operating-system.version')
      .whereBetween('h.observed_at', [from, to]),
    columns: ['h.id', 'h.value', 'h.observed_at as at'],
    order: 'h.observed_at',
    countOn: 'h.id',
    map: (r) => {
      const v = typeof r.value === 'string' ? r.value : (r.value !== null && r.value !== undefined ? JSON.stringify(r.value) : null);
      return {
        id: `os_change:device_status_history:${r.id}`,
        kind: 'os_change',
        at: toIso(r.at),
        title: `OS version — ${short(v, 40) ?? 'unknown'}`,
        detail: null,
        actor: null,
        actorType: 'system',
        severityHint: 'medium',
        resourceType: 'os',
        resourceId: null,
        resourcePath: null,
        payload: { version: short(v, 40) },
      };
    },
  }];

  return sources;
}

// ── Validation ───────────────────────────────────────────────────────────────

/** Accepts ISO-8601 or epoch-ms. */
const tsParam = z.preprocess(
  (v) => (typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v),
  z.coerce.date(),
);

const kindsParam = z
  .string()
  .max(500)
  .transform((s) => s.split(',').map((k) => k.trim()).filter(Boolean))
  .pipe(z.array(z.enum(CHANGE_EVENT_KINDS)).min(1));

function refineWindow(w: { from: Date; to: Date }, ctx: z.RefinementCtx): void {
  if (w.from.getTime() >= w.to.getTime()) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: '`from` must be strictly before `to`' });
  } else if (w.to.getTime() - w.from.getTime() > MAX_WINDOW_MS) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `Window too large — max ${MAX_WINDOW_DAYS} days` });
  }
}

export const changeEventsQuerySchema = z
  .object({
    from: tsParam.optional(),
    to: tsParam.optional(),
    kinds: kindsParam.optional(),
    limit: z.coerce.number().int().min(1).max(MAX_LIMIT).optional(),
  })
  .transform((q) => {
    const to = q.to ?? new Date();
    return { to, from: q.from ?? new Date(to.getTime() - DEFAULT_WINDOW_MS), kinds: q.kinds, limit: q.limit ?? DEFAULT_LIMIT };
  })
  .superRefine(refineWindow);

export const changeEventsSummaryQuerySchema = z
  .object({
    from: tsParam.optional(),
    to: tsParam.optional(),
  })
  .transform((q) => {
    const to = q.to ?? new Date();
    return { to, from: q.from ?? new Date(to.getTime() - DEFAULT_WINDOW_MS) };
  })
  .superRefine(refineWindow);

export interface ChangeEventQueryOptions {
  from: Date;
  to: Date;
  kinds?: ChangeEventKind[];
  limit?: number;
  callerUserId: number;
  callerIsAdmin: boolean;
  /** Holds audit.read in the device's tenant (audit-durci §9.7). */
  callerReadsAudit?: boolean;
  /** hasGlobalView(req) of the route: never inferred from the tenant id. */
  globalView?: boolean;
}

// ── Service ──────────────────────────────────────────────────────────────────

export const changeEventService = {
  /** One ordered timeline (NEWEST FIRST) unioning every change kind the caller
   *  is allowed to read. Each source is fetched with `limit + 1` rows so the
   *  merge can tell "exactly full" from "truncated": since every source is
   *  ordered newest-first, a row dropped by a per-source cap is necessarily
   *  older than `limit + 1` rows already in the merge, so it could never have
   *  survived the final slice anyway. */
  async getTimeline(deviceId: number, tenantId: number, opts: ChangeEventQueryOptions) {
    const limit = Math.min(MAX_LIMIT, Math.max(1, opts.limit ?? DEFAULT_LIMIT));
    const ctx: SourceContext = {
      deviceId, tenantId, from: opts.from, to: opts.to,
      callerUserId: opts.callerUserId, callerIsAdmin: opts.callerIsAdmin, callerReadsAudit: !!opts.callerReadsAudit, globalView: !!opts.globalView,
    };
    const sources = buildSources(ctx);
    const kinds = resolveKinds(sources, opts.kinds);

    const batches = await Promise.all(
      kinds.flatMap((kind) => (sources[kind] ?? []).map(async (src) => {
        const rows = await src.base()
          .select(src.columns)
          .orderByRaw(`${src.order} DESC`)
          .limit(limit + 1);
        const labels = await userLabels(rows.map((r: any) => r.user_id).filter((id: unknown) => id != null));
        return rows.map((r: any) => {
          const label = r.user_id != null ? labels.get(Number(r.user_id)) : undefined;
          return src.map({ ...r, actor_username: label?.username ?? null, actor_display_name: label?.displayName ?? null });
        });
      })),
    );

    const merged = batches.flat().sort((a, b) => {
      const d = Date.parse(b.at) - Date.parse(a.at);
      return d !== 0 ? d : a.id.localeCompare(b.id); // stable across identical instants
    });

    const truncated = merged.length > limit;
    if (truncated) {
      logger.warn({ deviceId, tenantId, limit, found: merged.length }, 'change-events timeline truncated');
    }

    return {
      formatVersion: FORMAT_VERSION,
      deviceId,
      from: opts.from.toISOString(),
      to: opts.to.toISOString(),
      order: 'desc' as const,
      kinds,
      limit,
      truncated,
      count: Math.min(merged.length, limit),
      events: truncated ? merged.slice(0, limit) : merged,
    };
  },

  /** Exact counts per kind — no row cap applies, so the Blame Ribbon can size
   *  itself without pulling the timeline. */
  async getSummary(deviceId: number, tenantId: number, opts: Omit<ChangeEventQueryOptions, 'kinds' | 'limit'>) {
    const ctx: SourceContext = {
      deviceId, tenantId, from: opts.from, to: opts.to,
      callerUserId: opts.callerUserId, callerIsAdmin: opts.callerIsAdmin, callerReadsAudit: !!opts.callerReadsAudit, globalView: !!opts.globalView,
    };
    const sources = buildSources(ctx);
    const kinds = resolveKinds(sources, undefined);

    const counts = {} as Record<ChangeEventKind, number>;
    await Promise.all(kinds.map(async (kind) => {
      const perSource = await Promise.all((sources[kind] ?? []).map(async (src) => {
        const [row] = await src.base().count<{ c: string }[]>({ c: src.countOn });
        return parseInt((row as any)?.c ?? '0', 10);
      }));
      counts[kind] = perSource.reduce((a, b) => a + b, 0);
    }));

    return {
      formatVersion: FORMAT_VERSION,
      deviceId,
      from: opts.from.toISOString(),
      to: opts.to.toISOString(),
      kinds,
      counts,
      total: Object.values(counts).reduce((a: number, b: number) => a + b, 0),
    };
  },
};

/** Requested kinds ∩ kinds the caller may read, in canonical order. An
 *  explicitly requested but forbidden kind is dropped rather than 403'd — the
 *  response echoes `kinds`, so the caller can see it was not served. */
function resolveKinds(
  sources: Partial<Record<ChangeEventKind, EventSource[]>>,
  requested: ChangeEventKind[] | undefined,
): ChangeEventKind[] {
  const wanted = requested ? new Set(requested) : null;
  return CHANGE_EVENT_KINDS.filter((k) => sources[k] && (!wanted || wanted.has(k)));
}
