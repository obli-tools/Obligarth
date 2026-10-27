import type { Knex } from 'knex';
import { z } from 'zod';
import {
  DEVICE_LIST_SORT_KEYS, DEVICE_VIEW_LIMITS, canonicalRule,
  type DeviceView, type DeviceViewDefinition, type DeviceViewFilters,
} from '@obligarth/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import {
  deviceListFilters, deviceListFiltersVersion, parseError, ruleObject, type DeviceListFilters,
} from '../../services/deviceListFilters';

// =============================================================================
// Saved views of the device list (P0-5 T2, §4.1, D6): CRUD, the default view of a user, and the filters of a view for
// GET /api/mdm/devices and its export (?viewId=). In the caller's tenant (its context: RLS keeps the tenants apart);
// the visibility is checked here, on every read and write: a view is the owner's, or every member's once shared. A
// view the caller does not see answers like an unknown one (404 deviceViewNotFound); a shared view the caller sees but may not change
// answers 403 (its owner, or a tenant administrator, changes it). Bounds: 50 private views per user, 100 shared views
// per tenant (one writer at a time per tenant, the defaults included: advisory lock). The definition is the one the list's filter registry
// parses (services/deviceListFilters.ts), normalised, its rule in canonical form; parsed again when a list uses it, so a
// view that no longer parses (a filter's values changed since) is refused (409 deviceViewInvalid), never half applied.
// =============================================================================

type Q = Knex | Knex.Transaction;

/** Filters a view keeps apart from `filters` (the group, the rule), and those it never keeps (the global view's tenants
 *  are a choice of the session, not of the view). */
const TOP_LEVEL_KEYS = new Set(['groupId', 'includeSubgroups', 'ungrouped', 'smartGroupId', 'rule']);
/** The group of the list: a static group (with its subgroups or not), the devices of no group, a dynamic group (P0-5 T4). */
const GROUP_KEYS = ['groupId', 'includeSubgroups', 'ungrouped', 'smartGroupId'] as const;
const SORT_KEYS = ['sortBy', 'sortOrder'] as const;

/** A column key of the console's catalog (utils/deviceLine2Fields.ts): the server keeps them, never interprets them. */
const ColumnKey = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,31}$/);

let cached: { version: number; schema: z.ZodTypeAny } | null = null;
/** The schema of a definition, from the filters registered (rebuilt when a lot registers one). */
function definitionSchema(): z.ZodTypeAny {
  const v = deviceListFiltersVersion();
  if (cached?.version === v) return cached.schema;
  const filters = Object.fromEntries(deviceListFilters().filter((d) => !TOP_LEVEL_KEYS.has(d.key)).map((d) => [d.key, d.query]));
  const schema = z.object({
    v: z.literal(1),
    filters: z.object(filters).strict(),
    rule: ruleObject.optional(),
    groupId: z.number().int().positive().max(2_147_483_647).optional(),
    includeSubgroups: z.boolean().optional(),
    ungrouped: z.boolean().optional(),
    smartGroupId: z.number().int().positive().max(2_147_483_647).optional(),
    sort: z.object({ by: z.enum(DEVICE_LIST_SORT_KEYS), order: z.enum(['asc', 'desc']) }).strict().optional(),
    columns: z.array(ColumnKey).max(DEVICE_VIEW_LIMITS.columnsMax).optional(),
  }).strict();
  cached = { version: v, schema };
  return schema;
}

/** The bytes of a JSON value as PostgreSQL prints a jsonb (', ' and ': ' between the members): the measure of
 *  device_views_definition_check. */
export function jsonbTextBytes(value: unknown): number {
  const text = (v: unknown): string => {
    if (Array.isArray(v)) return `[${v.map(text).join(', ')}]`;
    if (v && typeof v === 'object') {
      return `{${Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined)
        .map(([k, x]) => `${JSON.stringify(k)}: ${text(x)}`).join(', ')}}`;
    }
    return JSON.stringify(v) ?? 'null';
  };
  return Buffer.byteLength(text(value), 'utf8');
}

/** A definition received (POST, PATCH) or stored, parsed and normalised: undefined values dropped, the rule canonical,
 *  the columns without duplicates. A refusal throws the parse's 400 (invalidRequest, invalidRule), or
 *  deviceViewTooLarge. */
export function normalizeDefinition(input: unknown): DeviceViewDefinition {
  const parsed = definitionSchema().safeParse(input);
  if (!parsed.success) throw parseError(parsed.error);
  const d = parsed.data as DeviceViewDefinition;
  const filters: DeviceViewFilters = Object.fromEntries(Object.entries(d.filters).filter(([, v]) => v !== undefined));
  const out: DeviceViewDefinition = { v: 1, filters };
  if (d.rule !== undefined) out.rule = canonicalRule(d.rule);
  if (d.groupId !== undefined) out.groupId = d.groupId;
  if (d.includeSubgroups !== undefined) out.includeSubgroups = d.includeSubgroups;
  if (d.ungrouped !== undefined) out.ungrouped = d.ungrouped;
  if (d.smartGroupId !== undefined) out.smartGroupId = d.smartGroupId;
  if (d.sort !== undefined) out.sort = d.sort;
  if (d.columns !== undefined) out.columns = [...new Set(d.columns)];
  if (jsonbTextBytes(out) > DEVICE_VIEW_LIMITS.definitionMaxBytes) {
    throw new AppError(400, 'The definition of the view is too large', 'deviceViewTooLarge',
      { maxBytes: DEVICE_VIEW_LIMITS.definitionMaxBytes });
  }
  return out;
}

/** The filters of GET /api/mdm/devices a view gives, merged under the request's own: an explicit parameter wins, and
 *  the group (groupId, includeSubgroups, ungrouped, smartGroupId) and the sort (sortBy, sortOrder) go as a whole: one of them in the
 *  request replaces the view's. A stored definition that no longer parses: 409 deviceViewInvalid. */
export function mergeViewFilters(stored: unknown, explicit: DeviceListFilters): DeviceListFilters {
  let def: DeviceViewDefinition;
  try {
    def = normalizeDefinition(stored);
  } catch (err) {
    if (err instanceof AppError && err.statusCode === 400) {
      throw new AppError(409, 'This view no longer matches the filters of the list: edit it again', 'deviceViewInvalid');
    }
    throw err;
  }
  const fromView: DeviceListFilters = { ...(def.filters as DeviceListFilters) };
  if (def.rule !== undefined) fromView.rule = def.rule;
  if (def.groupId !== undefined) fromView.groupId = def.groupId;
  if (def.includeSubgroups !== undefined) fromView.includeSubgroups = def.includeSubgroups;
  if (def.ungrouped !== undefined) fromView.ungrouped = def.ungrouped;
  if (def.smartGroupId !== undefined) fromView.smartGroupId = def.smartGroupId;
  if (def.sort) { fromView.sortBy = def.sort.by; fromView.sortOrder = def.sort.order; }
  const given = (k: string) => (explicit as Record<string, unknown>)[k] !== undefined;
  if (GROUP_KEYS.some(given)) for (const k of GROUP_KEYS) delete fromView[k];
  if (SORT_KEYS.some(given)) for (const k of SORT_KEYS) delete fromView[k];
  const out: DeviceListFilters = { ...fromView };
  for (const [k, v] of Object.entries(explicit)) if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  return out;
}

// ── Rows ─────────────────────────────────────────────────────────────────────

interface ViewRow {
  id: number;
  uuid: string;
  tenant_id: number;
  owner_user_id: number;
  owner_name: string | null;
  name: string;
  description: string | null;
  shared: boolean;
  definition: unknown;
  is_default: boolean;
  created_at: Date;
  updated_at: Date;
}

/** A view's reference in a path or a query: its id, or its uuid (the console's links). */
export type DeviceViewRef = { id: number } | { uuid: string };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function parseViewRef(raw: unknown): DeviceViewRef | null {
  const s = typeof raw === 'string' ? raw.trim() : '';
  if (/^[1-9][0-9]{0,9}$/.test(s) && Number(s) <= 2_147_483_647) return { id: Number(s) };
  if (UUID_RE.test(s)) return { uuid: s.toLowerCase() };
  return null;
}

const iso = (v: Date | string): string => (v instanceof Date ? v : new Date(v)).toISOString();
const asObject = (v: unknown): unknown => (typeof v === 'string' ? JSON.parse(v) : v);

/** The views of the tenant the user sees (theirs, the shared ones), with the owner's name and the user's default.
 *  `anyOwner`: every view of the tenant (the row a change just wrote, which its writer may no longer see). */
function visibleViews(q: Q, tenantId: number, userId: number, anyOwner = false): Knex.QueryBuilder {
  const query = q('device_views as v')
    .leftJoin('users as u', 'u.id', 'v.owner_user_id')
    .leftJoin('device_view_defaults as d', function joinDefault() {
      this.on('d.tenant_id', '=', 'v.tenant_id').andOn('d.view_id', '=', 'v.id').andOnVal('d.user_id', '=', userId);
    })
    .where('v.tenant_id', tenantId)
    .select('v.id', 'v.uuid', 'v.tenant_id', 'v.owner_user_id', 'v.name', 'v.description', 'v.shared', 'v.definition',
      'v.created_at', 'v.updated_at', q.raw('COALESCE(u.display_name, u.username) AS owner_name'),
      q.raw('(d.view_id IS NOT NULL) AS is_default'));
  if (!anyOwner) query.where(function visible() { this.where('v.owner_user_id', userId).orWhere('v.shared', true); });
  return query;
}

const byRef = (query: Knex.QueryBuilder, ref: DeviceViewRef): Knex.QueryBuilder =>
  ('id' in ref ? query.where('v.id', ref.id) : query.where('v.uuid', ref.uuid));

function toView(r: ViewRow, userId: number, isAdmin: boolean): DeviceView {
  const mine = Number(r.owner_user_id) === userId;
  return {
    id: Number(r.id), uuid: r.uuid, name: r.name, description: r.description ?? null, shared: !!r.shared,
    owner: { id: Number(r.owner_user_id), name: r.owner_name ?? null },
    mine, editable: mine || (!!r.shared && isAdmin), isDefault: !!r.is_default,
    definition: asObject(r.definition) as DeviceViewDefinition,
    createdAt: iso(r.created_at), updatedAt: iso(r.updated_at),
  };
}

/** The caller of a view's route: their tenant, account, and whether they administer the tenant. */
export interface ViewCaller { tenantId: number; userId: number; isAdmin: boolean }

const Name = z.string().trim().min(1).max(DEVICE_VIEW_LIMITS.nameMax).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), 'no control character');
const Description = z.string().trim().max(DEVICE_VIEW_LIMITS.descriptionMax)
  .refine((s) => !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(s), 'no control character')
  .transform((s) => (s === '' ? null : s)).nullable();
export const DeviceViewCreateBody = z.object({
  name: Name,
  description: Description.optional(),
  shared: z.boolean().optional(),
  definition: z.unknown(),
}).strict();
export const DeviceViewPatchBody = DeviceViewCreateBody.partial().strict();
export const DeviceViewDefaultBody = z.object({ viewId: z.union([z.number().int().positive(), z.string().max(36)]).nullable() }).strict();

/** A write of the tenant's views: one at a time (the bounds are counted in it). */
async function lockTenantViews(trx: Knex.Transaction, tenantId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`device_views:${tenantId}`]);
}

/** 409 deviceViewLimit when the owner's private views or the tenant's shared views would go beyond their bound. */
async function checkBounds(trx: Knex.Transaction, tenantId: number, ownerId: number, shared: boolean): Promise<void> {
  if (shared) {
    const n = Number((await trx('device_views').where({ tenant_id: tenantId, shared: true }).count<{ n: string }[]>('id as n').first())?.n ?? 0);
    if (n >= DEVICE_VIEW_LIMITS.sharedPerTenant) {
      throw new AppError(409, 'Too many shared views in this tenant', 'deviceViewLimit', { kind: 'shared', limit: DEVICE_VIEW_LIMITS.sharedPerTenant });
    }
  } else {
    const n = Number((await trx('device_views').where({ tenant_id: tenantId, owner_user_id: ownerId, shared: false })
      .count<{ n: string }[]>('id as n').first())?.n ?? 0);
    if (n >= DEVICE_VIEW_LIMITS.privatePerUser) {
      throw new AppError(409, 'Too many private views for this user', 'deviceViewLimit', { kind: 'private', limit: DEVICE_VIEW_LIMITS.privatePerUser });
    }
  }
}

/** 23505 on device_views_name_uq: the owner already has a view of that name. */
function nameTaken(err: unknown): boolean {
  const e = err as { code?: string; constraint?: string };
  return e?.code === '23505' && e.constraint === 'device_views_name_uq';
}
const NAME_TAKEN = () => new AppError(409, 'A view of this name already exists', 'deviceViewNameTaken');
/** A view the caller does not see (unknown, another user's private view, another tenant's): 404 deviceViewNotFound
 *  (the routes and the list's ?viewId= too: the console tells it apart, reloads its views and lets the view go). */
export const deviceViewNotFound = (): AppError => new AppError(404, 'View not found', 'deviceViewNotFound');
const NOT_FOUND = deviceViewNotFound;
const READ_ONLY = () => new AppError(403, 'Only the owner of this view, or a tenant administrator for a shared view, changes it', 'deviceViewReadOnly');

export const deviceViewService = {
  /** The views the caller sees: theirs first, then the shared ones, by name. */
  async list(c: ViewCaller): Promise<DeviceView[]> {
    const rows = await visibleViews(db, c.tenantId, c.userId)
      .orderByRaw('(v.owner_user_id = ?) DESC, lower(v.name) ASC, v.id ASC', [c.userId]) as ViewRow[];
    return rows.map((r) => toView(r, c.userId, c.isAdmin));
  },

  /** One view the caller sees, or null. */
  async get(c: ViewCaller, ref: DeviceViewRef, q: Q = db): Promise<DeviceView | null> {
    const row = await byRef(visibleViews(q, c.tenantId, c.userId), ref).first() as ViewRow | undefined;
    return row ? toView(row, c.userId, c.isAdmin) : null;
  },

  /** The stored definition of a view the caller sees (the list and the export: ?viewId=), or null. */
  async definitionFor(tenantId: number, userId: number, ref: DeviceViewRef): Promise<unknown | null> {
    const row = await byRef(db('device_views as v')
      .where('v.tenant_id', tenantId)
      .where(function visible() { this.where('v.owner_user_id', userId).orWhere('v.shared', true); }), ref)
      .first('v.definition') as { definition: unknown } | undefined;
    return row ? asObject(row.definition) : null;
  },

  async create(c: ViewCaller, body: z.infer<typeof DeviceViewCreateBody>): Promise<DeviceView> {
    const definition = normalizeDefinition(body.definition);
    const shared = body.shared === true;
    try {
      return await db.transaction(async (trx) => {
        await lockTenantViews(trx, c.tenantId);
        await checkBounds(trx, c.tenantId, c.userId, shared);
        const [r] = await trx('device_views').insert({
          tenant_id: c.tenantId, owner_user_id: c.userId, name: body.name, description: body.description ?? null, shared,
          definition: JSON.stringify(definition),
        }).returning('id') as Array<{ id: number }>;
        return (await this.get(c, { id: Number(r.id) }, trx))!;
      });
    } catch (err) {
      if (nameTaken(err)) throw NAME_TAKEN();
      throw err;
    }
  },

  /** Changes a view: the before and after (for the audit of a shared view). */
  async update(c: ViewCaller, ref: DeviceViewRef, body: z.infer<typeof DeviceViewPatchBody>):
    Promise<{ before: DeviceView; after: DeviceView; fields: string[] }> {
    const definition = body.definition !== undefined ? normalizeDefinition(body.definition) : undefined;
    try {
      return await db.transaction(async (trx) => {
        await lockTenantViews(trx, c.tenantId);
        const before = await this.get(c, ref, trx);
        if (!before) throw NOT_FOUND();
        if (!before.editable) throw READ_ONLY();
        const updates: Record<string, unknown> = {};
        if (body.name !== undefined && body.name !== before.name) updates.name = body.name;
        if (body.description !== undefined && (body.description ?? null) !== before.description) updates.description = body.description ?? null;
        if (body.shared !== undefined && body.shared !== before.shared) {
          await checkBounds(trx, c.tenantId, before.owner.id, body.shared);
          updates.shared = body.shared;
        }
        if (definition !== undefined && JSON.stringify(definition) !== JSON.stringify(normalizeStored(before.definition))) {
          updates.definition = JSON.stringify(definition);
        }
        const fields = Object.keys(updates);
        if (fields.length === 0) return { before, after: before, fields };
        await trx('device_views').where({ tenant_id: c.tenantId, id: before.id }).update({ ...updates, updated_at: trx.fn.now() });
        // Read back whatever its visibility now: an administrator who unshares a member's view no longer sees it.
        const row = await visibleViews(trx, c.tenantId, c.userId, true).where('v.id', before.id).first() as ViewRow;
        return { before, after: toView(row, c.userId, c.isAdmin), fields };
      });
    } catch (err) {
      if (nameTaken(err)) throw NAME_TAKEN();
      throw err;
    }
  },

  /** Deletes a view (its defaults go with it): the view deleted. */
  async remove(c: ViewCaller, ref: DeviceViewRef): Promise<DeviceView> {
    return db.transaction(async (trx) => {
      await lockTenantViews(trx, c.tenantId);
      const view = await this.get(c, ref, trx);
      if (!view) throw NOT_FOUND();
      if (!view.editable) throw READ_ONLY();
      await trx('device_views').where({ tenant_id: c.tenantId, id: view.id }).delete();
      return view;
    });
  },

  /** The caller's default view (a view they see), or none. Under the tenant's lock, like the writes of the views: a
   *  view whose sharing is being withdrawn is read once that change is committed (else the default would name a view
   *  the caller no longer sees, which device_view_defaults_visible, reading the committed row, would let through). */
  async setDefault(c: ViewCaller, ref: DeviceViewRef | null): Promise<DeviceView | null> {
    return db.transaction(async (trx) => {
      await lockTenantViews(trx, c.tenantId);
      if (ref === null) {
        await trx('device_view_defaults').where({ tenant_id: c.tenantId, user_id: c.userId }).delete();
        return null;
      }
      const view = await this.get(c, ref, trx);
      if (!view) throw NOT_FOUND();
      await trx('device_view_defaults')
        .insert({ tenant_id: c.tenantId, user_id: c.userId, view_id: view.id })
        .onConflict(['tenant_id', 'user_id'])
        .merge({ view_id: view.id, updated_at: trx.fn.now() });
      return { ...view, isDefault: true };
    });
  },
};

/** A stored definition in its normalised form, for the comparison of a PATCH (unchanged when it no longer parses). */
function normalizeStored(def: unknown): unknown {
  try { return normalizeDefinition(def); } catch { return def; }
}
