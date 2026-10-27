import type { Knex } from 'knex';
import { z } from 'zod';
import {
  RULE_FIELDS, SMART_GROUP_LIMITS, canonicalRule, ruleFamiliesOf, ruleFieldsNotAllowed, ruleFieldsOf, ruleGroupIdsOf,
  ruleSha256, validateRule,
  type DirtyFamily, type RuleNode, type SmartGroup, type SmartGroupCause, type SmartGroupDeletePreview,
  type SmartGroupPreview, type SmartGroupSampleDevice, type SmartGroupState, type SmartGroupStateReason,
  type SmartGroupWriteResult,
} from '@obligarth/shared';
import { db } from '../../db';
import { audit, type AuditWriteContext } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { raiseInTx, resolveInTx } from '../../apple/alerts/service';
import { logger } from '../../utils/logger';
import { parseError, ruleObject } from '../../services/deviceListFilters';
import { signImpactToken } from '../policies/impactToken';
import { withConfigurationLock } from '../policies/configLock';
import { requestDeviceResolution } from '../policies/triggers';
import { compileRule } from '../rules/compile';
import { NO_RULE_PRIVACY, loadRulePrivacy, type RulePrivacy } from '../rules/facts';

// =============================================================================
// Dynamic groups (P0-5 T4, §4.2; D3, D8, D9, D10): CRUD, the full computation of the members, the preview of a rule.
// In the caller's tenant (its context: RLS keeps the tenants apart; one tenant per group, D10).
//   - A rule is validated by the rule language (400 invalidRule, its issues), its static groups must be groups of the
//     tenant (400 smartGroupUnknownGroup); it is stored in canonical form, with its families of marking (rule_fields:
//     shared smartGroups.ts), its SHA-256 and its version (up by one at each change).
//   - The members of an untargeted group are computed in the transaction of the request that creates it or changes its
//     rule: the compiled rule on the devices of the tenant under management (D9: never a device out of management),
//     compared with the members, the differences written with their journal (smart_group_membership_log, cause 'rule').
//     computeMembers is the one computation: the incremental one of P0-5 T5 (evaluate.ts) calls it on a slice of
//     devices, and the hourly schedule on the whole tenant.
//   - A group an assignment targets (P0-5 T6: requireTargetableGroup, called by the writes of the assignments) changes
//     its rule, is deleted or released through the governed circuit (P0-5 T7, governance.ts: preview, step-up, second
//     approver beyond DM23), which writes with writeRuleInTx, deleteInTx and releaseInTx under the lock of the
//     configuration; its rule must stay targetable (D2: 409 smartGroupNotTargetable, the fields at fault). The plain
//     writes below refuse such a group (409 smartGroupTargeted: an assignment came meanwhile; submit again).
//   - Bounds: 200 groups per tenant (one writer at a time per tenant: advisory lock); one name per tenant.
//   - Audit: smart_group.created, smart_group.updated, smart_group.deleted; critical (in the transaction) when the group
//     carries an assignment, as group.moved; standard (after it) otherwise. Identifiers, field names and counters only.
//   - A static group deleted while a rule names it (groupService.delete): the group goes to 'error', its members frozen
//     (the computations pass a group that is not active), alert smart_group.rule_invalid; a new rule makes it active
//     again and resolves the alert.
//   - Counts (D3): for a non-administrator (visible devices given), the members, the entries and exits of a write, the
//     preview and its sample cover only the devices their teams see; the pending changes of a held group (counted on
//     the tenant) are not given to them. A dynamic group gives no team scope (D8). Only a tenant administrator (or a
//     platform administrator) renames or describes again a group an assignment targets (D3: 403 smartGroupAdminOnly).
//   - Locks: every write of a group (create, update, remove, and the governed ones) takes the lock of the tenant's
//     configuration first, then the tenant's writers of groups, then the group's row. The writes of the assignments
//     (publish.ts) and the deletion of a static group (group.service.ts) hold the same lock: an assignment never
//     targets a rule its preview did not see, nor a group deleted meanwhile; a rule never names a static group
//     deleted meanwhile.
//   - A rule written (created or changed) is computed with the snapshot of its statement: an inventory change committed
//     meanwhile is not marked when no committed group read its family yet. Once committed, markDrift compares the rule
//     with the members again and marks the devices that differ, for the incremental computation (P0-5 T5).
// =============================================================================

type Q = Knex | Knex.Transaction;

/** The caller of a route: their tenant and account, the devices their teams see (undefined or 'all': every one), and
 *  whether they administer the tenant or the platform (when not given: a caller who sees every device does). */
export interface SmartGroupCaller {
  tenantId: number;
  userId: number;
  visibleIds?: number[] | 'all';
  admin?: boolean;
}

/** A list of ids as one PostgreSQL array literal ('{1,2,3}'): a single binding whatever the number of ids. */
const pgIntArray = (ids: readonly number[]): string => `{${ids.map(Number).filter((n) => Number.isSafeInteger(n)).join(',')}}`;
const scoped = (c: { visibleIds?: number[] | 'all' }): number[] | null => (Array.isArray(c.visibleIds) ? c.visibleIds : null);
const isAdmin = (c: SmartGroupCaller): boolean => c.admin ?? !Array.isArray(c.visibleIds);

/** How many of `ids` a caller scoped to `visible` sees (all of them: null). */
export function visibleCount(ids: readonly number[], visible: readonly number[] | null): number {
  if (!visible) return ids.length;
  const v = new Set(visible.map(Number));
  return ids.reduce((n, id) => n + (v.has(Number(id)) ? 1 : 0), 0);
}

// ── Bodies ───────────────────────────────────────────────────────────────────

const Name = z.string().trim().min(1).max(SMART_GROUP_LIMITS.nameMax).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), 'no control character');
const Description = z.string().trim().max(SMART_GROUP_LIMITS.descriptionMax)
  .refine((s) => !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(s), 'no control character')
  .transform((s) => (s === '' ? null : s)).nullable();
export const SmartGroupCreateBody = z.object({
  name: Name,
  description: Description.optional(),
  rule: ruleObject,
}).strict();
export const SmartGroupPatchBody = z.object({
  name: Name.optional(),
  description: Description.optional(),
  rule: ruleObject.optional(),
}).strict();
export const SmartGroupPreviewBody = z.object({
  rule: ruleObject,
  /** Against the members of this group: what the rule would add and remove. */
  smartGroupId: z.number().int().positive().max(2_147_483_647).optional(),
}).strict();

/** A body parsed by `schema`, or the parse's 400 (invalidRequest, invalidRule with its issues). */
export function parseBody<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value ?? {});
  if (!parsed.success) throw parseError(parsed.error);
  return parsed.data;
}

// ── Errors ───────────────────────────────────────────────────────────────────

/** A group of another tenant, or unknown: 404 alike. */
export const smartGroupNotFound = (): AppError => new AppError(404, 'Dynamic group not found', 'smartGroupNotFound');
const NAME_TAKEN = () => new AppError(409, 'A dynamic group of this name already exists', 'smartGroupNameTaken');
const TARGETED = () => new AppError(409,
  'An assignment targets this dynamic group: its rule changes and its deletion go through the preview of their impact', 'smartGroupTargeted');
/** 403 smartGroupAdminOnly: a member who is not an administrator of the tenant changes a group an assignment targets (D3). */
export const smartGroupAdminOnly = (): AppError => new AppError(403,
  'Only an administrator of the tenant changes, deletes or releases a dynamic group an assignment targets', 'smartGroupAdminOnly');
/** 409 smartGroupNotHeld: the release of a group the mass guard does not hold. */
export const smartGroupNotHeld = (): AppError => new AppError(409, 'This dynamic group is not held: nothing to release', 'smartGroupNotHeld');

/** 23505 on smart_groups_name_uq: the tenant already has a group of that name. */
function nameTaken(err: unknown): boolean {
  const e = err as { code?: string; constraint?: string };
  return e?.code === '23505' && e.constraint === 'smart_groups_name_uq';
}

// ── Rules ────────────────────────────────────────────────────────────────────

/** Does a rule compare a datum of the privacy rules (serial number, applications)? */
export const readsPrivacy = (rule: RuleNode): boolean => ruleFieldsOf(rule).some((k) => RULE_FIELDS[k].privacy !== undefined);

/** The compiled rule over the devices of a tenant (the privacy context loaded only when the rule needs it, unless the
 *  caller gives the tenant's: the incremental computation loads it once for its groups). */
async function compiledFor(q: Q, tenantId: number, rule: RuleNode, now: Date, given?: RulePrivacy):
  Promise<{ sql: string; bindings: Knex.Value[] }> {
  const privacy = !readsPrivacy(rule) ? NO_RULE_PRIVACY : given ?? await loadRulePrivacy(q, [tenantId]);
  return compileRule(rule, { now, privacy });
}

/** 400 smartGroupUnknownGroup when the rule names a static group that is not one of the tenant's. */
export async function checkRuleGroups(q: Q, tenantId: number, rule: RuleNode): Promise<void> {
  const ids = ruleGroupIdsOf(rule);
  if (ids.length === 0) return;
  const found = new Set((await q('device_groups').where({ tenant_id: tenantId }).whereIn('id', ids).pluck('id') as number[]).map(Number));
  const missing = ids.filter((id) => !found.has(id));
  if (missing.length) {
    throw new AppError(400, 'The rule names a static group that does not exist', 'smartGroupUnknownGroup', { groupIds: missing });
  }
}

/** The columns of a rule as stored: canonical, its families, its SHA-256. */
function ruleColumns(rule: RuleNode): { rule: string; rule_fields: DirtyFamily[]; rule_sha256: string; canonical: RuleNode } {
  const canonical = canonicalRule(rule);
  return { rule: JSON.stringify(canonical), rule_fields: ruleFamiliesOf(canonical), rule_sha256: ruleSha256(canonical), canonical };
}

/** 409 smartGroupNotTargetable when a rule may not define a group an assignment targets (D2): the fields at fault. */
export function requireTargetable(rule: RuleNode): void {
  const fields = ruleFieldsNotAllowed(rule, 'targetable');
  if (fields.length) {
    throw new AppError(409, 'This rule cannot define a dynamic group an assignment targets', 'smartGroupNotTargetable', { fields });
  }
}

/**
 * A dynamic group an assignment may target (P0-5 T6; publish.ts, normalizeChanges): one of the tenant's (404
 * smartGroupNotFound), whose stored rule the catalog validates and names no field a target does not permit (D2: 409
 * smartGroupNotTargetable, the fields at fault; none listed for a rule the catalog no longer validates). Held or not:
 * its members are what applies. The decision is read under the lock of the configuration (changeAssignments): every
 * write of a group takes it too, so its rule cannot change, nor the group go, before the assignment is committed.
 */
export async function requireTargetableGroup(q: Q, tenantId: number, id: number): Promise<void> {
  const row = await q('smart_groups').where({ tenant_id: tenantId, id }).first('rule') as { rule: unknown } | undefined;
  if (!row) throw smartGroupNotFound();
  const rule = asObject(row.rule) as RuleNode;
  if (validateRule(rule).length > 0) {
    throw new AppError(409, 'This rule cannot define a dynamic group an assignment targets', 'smartGroupNotTargetable', { fields: [] });
  }
  requireTargetable(rule);
}

// ── Members ──────────────────────────────────────────────────────────────────

/** A slice of devices, of members (one array binding). The only text the computations add to the compiled rule's. */
const DEVICE_SLICE_SQL = ' AND devices.id = ANY(?::integer[])';
const MEMBER_SLICE_SQL = ' AND m.device_id = ANY(?::integer[])';

/** The change a computation wrote: the devices that entered and left the group, and the devices the rule selects (in
 *  the slice computed, all of the tenant's for a full computation). */
export interface MembershipChange {
  added: number[];
  removed: number[];
  total: number;
}

/**
 * Computes the members of a group with `rule` and writes the difference with its journal (cause), in `trx` (the
 * tenant's context; the caller holds the group's row). The devices of the tenant under management (D9) the compiled
 * rule selects become members, the others leave. `deviceIds`: only these devices are computed (a slice of the
 * incremental computation, P0-5 T5); the others keep their membership. Does not write member_count (the caller: the
 * total of a full computation, or a count). `privacy`: the tenant's privacy context, when the caller loaded it.
 */
export async function computeMembers(trx: Knex.Transaction, tenantId: number, groupId: number, rule: RuleNode,
  cause: SmartGroupCause, opts: { deviceIds?: readonly number[]; now?: Date; privacy?: RulePrivacy } = {}): Promise<MembershipChange> {
  const compiled = await compiledFor(trx, tenantId, rule, opts.now ?? new Date(), opts.privacy);
  const slice = opts.deviceIds ? pgIntArray(opts.deviceIds) : null;
  const deviceSlice = slice ? DEVICE_SLICE_SQL : '';
  const memberSlice = slice ? MEMBER_SLICE_SQL : '';
  const res = await trx.raw(`
    WITH want AS MATERIALIZED (
      SELECT devices.id FROM devices
       WHERE devices.tenant_id = ?::integer AND devices.enrollment_state <> 'unenrolled'${deviceSlice}
         AND ${compiled.sql}),
    added AS (
      INSERT INTO smart_group_members (tenant_id, smart_group_id, device_id)
      SELECT ?::integer, ?::integer, w.id FROM want w
      ON CONFLICT DO NOTHING
      RETURNING device_id),
    removed AS (
      DELETE FROM smart_group_members m
       WHERE m.tenant_id = ?::integer AND m.smart_group_id = ?::integer${memberSlice}
         AND NOT EXISTS (SELECT 1 FROM want w WHERE w.id = m.device_id)
      RETURNING m.device_id),
    logged AS (
      INSERT INTO smart_group_membership_log (tenant_id, smart_group_id, device_id, change, cause)
      SELECT ?::integer, ?::integer, a.device_id, '+', ?::varchar FROM added a
      UNION ALL
      SELECT ?::integer, ?::integer, r.device_id, '-', ?::varchar FROM removed r)
    SELECT (SELECT count(*)::int FROM want) AS total,
           COALESCE((SELECT array_agg(a.device_id ORDER BY a.device_id) FROM added a), '{}'::integer[]) AS added,
           COALESCE((SELECT array_agg(r.device_id ORDER BY r.device_id) FROM removed r), '{}'::integer[]) AS removed`,
  [
    tenantId, ...(slice ? [slice] : []), ...compiled.bindings,
    tenantId, groupId,
    tenantId, groupId, ...(slice ? [slice] : []),
    tenantId, groupId, cause, tenantId, groupId, cause,
  ]) as { rows: Array<{ total: number; added: number[]; removed: number[] }> };
  const row = res.rows[0];
  return { total: Number(row.total), added: (row.added ?? []).map(Number), removed: (row.removed ?? []).map(Number) };
}

/** The full computation of a group (its row held by the caller): members, member_count, computed_at. */
async function computeAll(trx: Knex.Transaction, tenantId: number, groupId: number, rule: RuleNode, cause: SmartGroupCause):
  Promise<MembershipChange> {
  const change = await computeMembers(trx, tenantId, groupId, rule, cause);
  await trx('smart_groups').where({ tenant_id: tenantId, id: groupId })
    .update({ member_count: change.total, computed_at: trx.fn.now() });
  return change;
}

/** What a rule selects, without writing: its count, against a group's members when given, and a sample (D3: the
 *  devices `visible` only, when given). The pending changes of a held group too (P0-5 T5: evaluate.ts). */
export async function previewRule(q: Q, tenantId: number, rule: RuleNode, groupId: number | null, visible: number[] | null,
  privacy?: RulePrivacy): Promise<Omit<SmartGroupPreview, 'scope' | 'devicesToken'>> {
  const compiled = await compiledFor(q, tenantId, rule, new Date(), privacy);
  const vis = visible ? pgIntArray(visible) : null;
  const deviceSlice = vis ? DEVICE_SLICE_SQL : '';
  const memberSlice = vis ? MEMBER_SLICE_SQL : '';
  const res = await q.raw(`
    WITH want AS MATERIALIZED (
      SELECT devices.id FROM devices
       WHERE devices.tenant_id = ?::integer AND devices.enrollment_state <> 'unenrolled'${deviceSlice}
         AND ${compiled.sql}),
    cur AS MATERIALIZED (
      SELECT m.device_id FROM smart_group_members m
       WHERE m.tenant_id = ?::integer AND m.smart_group_id = ?::integer${memberSlice})
    SELECT (SELECT count(*)::int FROM want) AS total,
           (SELECT count(*)::int FROM want w WHERE NOT EXISTS (SELECT 1 FROM cur c WHERE c.device_id = w.id)) AS added,
           (SELECT count(*)::int FROM cur c WHERE NOT EXISTS (SELECT 1 FROM want w WHERE w.id = c.device_id)) AS removed,
           (SELECT COALESCE(json_agg(s ORDER BY s.id), '[]'::json) FROM (
              SELECT d.id, d.uuid, d.label AS name, d.platform FROM devices d JOIN want w ON w.id = d.id
               WHERE d.tenant_id = ?::integer ORDER BY d.id LIMIT ?::integer) s) AS sample`,
  [
    tenantId, ...(vis ? [vis] : []), ...compiled.bindings,
    tenantId, groupId ?? 0, ...(vis ? [vis] : []),
    tenantId, SMART_GROUP_LIMITS.previewSample,
  ]) as { rows: Array<{ total: number; added: number; removed: number; sample: unknown }> };
  const row = res.rows[0];
  const sample = (typeof row.sample === 'string' ? JSON.parse(row.sample) : row.sample) as Array<Record<string, unknown>>;
  return {
    total: Number(row.total),
    added: groupId === null ? null : Number(row.added),
    removed: groupId === null ? null : Number(row.removed),
    sample: sample.map((s): SmartGroupSampleDevice => ({ id: Number(s.id), uuid: String(s.uuid), name: String(s.name ?? ''), platform: String(s.platform) })),
  };
}

/** The devices of the tenant under management a rule selects (D9), by id, without writing: the members a governed
 *  change proposes (P0-5 T7, governance.ts). */
export async function selectMembers(q: Q, tenantId: number, rule: RuleNode, now = new Date()): Promise<number[]> {
  const compiled = await compiledFor(q, tenantId, rule, now);
  const res = await q.raw(`
    SELECT devices.id FROM devices
     WHERE devices.tenant_id = ?::integer AND devices.enrollment_state <> 'unenrolled'
       AND ${compiled.sql}
     ORDER BY devices.id`, [tenantId, ...compiled.bindings]) as { rows: Array<{ id: number }> };
  return res.rows.map((r) => Number(r.id));
}

/** The members of a group, by id. */
export async function memberIdsOf(q: Q, tenantId: number, groupId: number): Promise<number[]> {
  return (await q('smart_group_members').where({ tenant_id: tenantId, smart_group_id: groupId }).orderBy('device_id')
    .pluck('device_id') as number[]).map(Number);
}

/**
 * Once a rule written (a group created, a new rule) is committed: the devices whose membership no longer follows it
 * (an inventory change committed while the rule was computed, which the marking did not see: no committed group of the
 * tenant read its family yet) are marked for the incremental computation (smart_group_dirty with the families of the
 * rule, 'new' for a rule that reads none), which writes them with its mass guard, and the queue is woken. Nothing when
 * the group changed meanwhile (its rule, its state). Never throws (the hourly schedule computes the drift again):
 * returns the devices that differed.
 */
export async function markDrift(tenantId: number, groupId: number, ruleSha: string): Promise<number> {
  try {
    return await db.transaction(async (trx) => {
      const g = await trx('smart_groups').where({ tenant_id: tenantId, id: groupId })
        .first('rule', 'rule_sha256', 'rule_fields', 'state') as { rule: unknown; rule_sha256: string; rule_fields: string[] | null; state: string } | undefined;
      if (!g || g.state !== 'active' || g.rule_sha256.trim() !== ruleSha) return 0;
      const rule = asObject(g.rule) as RuleNode;
      if (validateRule(rule).length > 0) return 0;
      const compiled = await compiledFor(trx, tenantId, rule, new Date());
      const families = (g.rule_fields ?? []).filter((f) => /^[a-z_]{1,32}$/.test(f));
      const reasons = `{${(families.length ? families : ['new']).join(',')}}`;
      const res = await trx.raw(`
        WITH want AS MATERIALIZED (
          SELECT devices.id FROM devices
           WHERE devices.tenant_id = ?::integer AND devices.enrollment_state <> 'unenrolled'
             AND ${compiled.sql}),
        cur AS MATERIALIZED (
          SELECT m.device_id AS id FROM smart_group_members m WHERE m.tenant_id = ?::integer AND m.smart_group_id = ?::integer),
        drift AS MATERIALIZED (
          (SELECT id FROM want EXCEPT SELECT id FROM cur) UNION (SELECT id FROM cur EXCEPT SELECT id FROM want)),
        marked AS (
          INSERT INTO smart_group_dirty AS d (tenant_id, device_id, reasons)
          SELECT ?::integer, x.id, ?::text[] FROM drift x
          ON CONFLICT (tenant_id, device_id) DO UPDATE
            SET reasons = ARRAY(SELECT DISTINCT r FROM unnest(d.reasons || EXCLUDED.reasons) AS u(r) ORDER BY r)
            WHERE NOT d.reasons @> EXCLUDED.reasons
          RETURNING d.device_id)
        SELECT (SELECT count(*)::int FROM drift) AS n, (SELECT count(*)::int FROM marked) AS marked`,
      [tenantId, ...compiled.bindings, tenantId, groupId, tenantId, reasons]) as { rows: Array<{ n: number }> };
      const n = Number(res.rows[0]?.n ?? 0);
      if (n > 0) {
        const { requestGroupEvaluation } = await import('./triggers');
        await requestGroupEvaluation(trx, tenantId);
      }
      return n;
    });
  } catch (err) {
    logger.warn({ tenantId, smartGroupId: groupId, err: { message: (err as Error)?.message } },
      'dynamic group: the drift after its rule was written was not marked (the hourly schedule computes it again)');
    return 0;
  }
}

/** Does an assignment target the group (the target smart_group)? */
export async function isTargeted(q: Q, tenantId: number, groupId: number): Promise<boolean> {
  return !!(await q('assignments').where({ tenant_id: tenantId, target_scope: 'smart_group', target_id: groupId }).first('id'));
}

// ── Rows ─────────────────────────────────────────────────────────────────────

interface GroupRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  description: string | null;
  rule: unknown;
  rule_fields: string[] | null;
  rule_version: number;
  rule_sha256: string;
  state: SmartGroupState;
  state_reason: SmartGroupStateReason | null;
  state_since: Date | null;
  pending_added: number;
  pending_removed: number;
  member_count: number;
  computed_at: Date | null;
  created_by: number | null;
  created_by_name: string | null;
  updated_by: number | null;
  updated_by_name: string | null;
  created_at: Date;
  updated_at: Date;
  assignment_count: number;
  visible_count?: number;
}

const iso = (v: Date | string): string => (v instanceof Date ? v : new Date(v)).toISOString();
const asObject = (v: unknown): unknown => (typeof v === 'string' ? JSON.parse(v) : v);

/** The assignments that target a group (the target smart_group, P0-5 T6). */
const ASSIGNMENT_COUNT_SQL = `(SELECT count(*)::int FROM assignments a
  WHERE a.tenant_id = g.tenant_id AND a.target_scope = 'smart_group' AND a.target_id = g.id) AS assignment_count`;

/** The groups of the tenant, with their authors, their assignments and, for a caller scoped to some devices, the
 *  members they see. */
function groupsQuery(q: Q, tenantId: number, visible: number[] | null): Knex.QueryBuilder {
  const query = q('smart_groups as g')
    .leftJoin('users as cu', 'cu.id', 'g.created_by')
    .leftJoin('users as uu', 'uu.id', 'g.updated_by')
    .where('g.tenant_id', tenantId)
    .select('g.id', 'g.uuid', 'g.tenant_id', 'g.name', 'g.description', 'g.rule', 'g.rule_fields', 'g.rule_version', 'g.rule_sha256',
      'g.state', 'g.state_reason', 'g.state_since', 'g.pending_added', 'g.pending_removed', 'g.member_count', 'g.computed_at',
      'g.created_by', 'g.updated_by', 'g.created_at', 'g.updated_at',
      q.raw('COALESCE(cu.display_name, cu.username) AS created_by_name'),
      q.raw('COALESCE(uu.display_name, uu.username) AS updated_by_name'),
      q.raw(ASSIGNMENT_COUNT_SQL));
  if (visible) {
    query.select(q.raw(`(SELECT count(*)::int FROM smart_group_members m
      WHERE m.tenant_id = g.tenant_id AND m.smart_group_id = g.id AND m.device_id = ANY(?::integer[])) AS visible_count`, [pgIntArray(visible)]));
  }
  return query;
}

function toGroup(r: GroupRow): SmartGroup {
  const stored = asObject(r.rule) as RuleNode;
  // A stored rule the catalog no longer validates is never compiled; it is shown as it is, not targetable. A valid one
  // in canonical form (a jsonb keeps its keys in its own order).
  const valid = validateRule(stored).length === 0;
  const rule = valid ? canonicalRule(stored) : stored;
  const notTargetable = valid ? ruleFieldsNotAllowed(rule, 'targetable') : [];
  const scopedCount = r.visible_count !== undefined && r.visible_count !== null;
  return {
    id: Number(r.id), uuid: r.uuid, name: r.name, description: r.description ?? null, rule,
    ruleFields: (r.rule_fields ?? []) as DirtyFamily[], ruleVersion: Number(r.rule_version), ruleSha256: r.rule_sha256.trim(),
    state: r.state, stateReason: r.state_reason ?? null, stateSince: r.state_since ? iso(r.state_since) : null,
    // Counted on the tenant (evaluate.ts): not given to a caller scoped to some devices (D3).
    pendingAdded: scopedCount ? null : Number(r.pending_added), pendingRemoved: scopedCount ? null : Number(r.pending_removed),
    memberCount: Number(scopedCount ? r.visible_count : r.member_count), memberCountScope: scopedCount ? 'visible' : 'all',
    computedAt: r.computed_at ? iso(r.computed_at) : null,
    assignmentCount: Number(r.assignment_count ?? 0),
    targetable: valid && notTargetable.length === 0, notTargetableFields: notTargetable,
    createdBy: r.created_by ? { id: Number(r.created_by), name: r.created_by_name ?? null } : null,
    updatedBy: r.updated_by ? { id: Number(r.updated_by), name: r.updated_by_name ?? null } : null,
    createdAt: iso(r.created_at), updatedAt: iso(r.updated_at),
  };
}

/** A write of the tenant's groups: one at a time (the bound is counted in it). */
async function lockTenantGroups(trx: Knex.Transaction, tenantId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`smart_groups:${tenantId}`]);
}

export interface LockedGroup {
  id: number; uuid: string; name: string; description: string | null; rule: RuleNode; rule_sha256: string; rule_version: number;
  state: SmartGroupState; member_count: number; assignment_count: number;
}

/** The group's row held for a change of its rule or its deletion (FOR UPDATE: a computation holds it FOR NO KEY UPDATE).
 *  Its assignments are counted in the same statement: the caller holds the lock of the configuration, which every
 *  writer of the assignments takes first, so none is being written. */
async function lockGroup(trx: Knex.Transaction, tenantId: number, id: number): Promise<LockedGroup> {
  const row = await trx('smart_groups as g').where({ 'g.tenant_id': tenantId, 'g.id': id }).forUpdate()
    .first('g.id', 'g.uuid', 'g.name', 'g.description', 'g.rule', 'g.rule_sha256', 'g.rule_version', 'g.state', 'g.member_count',
      trx.raw(ASSIGNMENT_COUNT_SQL)) as (Omit<LockedGroup, 'rule'> & { rule: unknown }) | undefined;
  if (!row) throw smartGroupNotFound();
  return { ...row, id: Number(row.id), rule: asObject(row.rule) as RuleNode, rule_sha256: row.rule_sha256.trim(),
    rule_version: Number(row.rule_version), member_count: Number(row.member_count), assignment_count: Number(row.assignment_count) };
}

/** An entry of the journal: critical in the transaction when the group carries an assignment, standard after it. */
export interface PendingEntry { action: string; groupId: number; details: Record<string, unknown>; approvalId?: number }
async function journal(trx: Knex.Transaction, tenantId: number, ctx: AuditWriteContext, critical: boolean, e: PendingEntry): Promise<PendingEntry | null> {
  if (!critical) return e;
  await audit.appendInTx(trx, {
    tenantId, action: e.action, target: { type: 'smart_group', id: String(e.groupId) }, details: e.details,
    approvalIds: e.approvalId ? [e.approvalId] : undefined,
  }, ctx, { criticality: 'critical' });
  return null;
}
/** The standard entry a write left for after its commit (null: none, or written in the transaction). */
export async function journalAfter(tenantId: number, ctx: AuditWriteContext, e: PendingEntry | null): Promise<void> {
  if (!e) return;
  await audit.append({
    tenantId, action: e.action, target: { type: 'smart_group', id: String(e.groupId) }, details: e.details,
    approvalIds: e.approvalId ? [e.approvalId] : undefined,
  }, ctx);
}

// ── Governed writes (P0-5 T7: governance.ts, in a transaction that holds the lock of the configuration) ──────────────

/** The group a governed change is about, its row held (FOR UPDATE) after the tenant's writers of groups (the order of
 *  every writer: the configuration, then the groups of the tenant, then the group's row). 404 smartGroupNotFound. */
export async function lockForGovernance(trx: Knex.Transaction, tenantId: number, id: number): Promise<LockedGroup> {
  await lockTenantGroups(trx, tenantId);
  return lockGroup(trx, tenantId, id);
}

/** What a governed write did: the entries and exits, and the entry of its journal left for after the commit. */
export interface GovernedWrite {
  change: MembershipChange | null;
  /** The members of the group before (a deletion: those who left it). */
  members: number[];
  entry: PendingEntry | null;
}

/** The devices whose targeted groups changed: their resolution in `trx` (the tenant's beyond 50). */
async function resolveMoved(trx: Knex.Transaction, tenantId: number, targeted: boolean, ids: number[]): Promise<void> {
  if (targeted && ids.length) await requestDeviceResolution(trx, tenantId, [...new Set(ids)]);
}

/**
 * A new rule for a group (its row held: lockForGovernance), with its name and description when given: stored, its
 * version up by one, the group active again (an error or a hold settled, their alerts resolved), its members computed
 * again (journal cause 'rule'), the devices that entered or left resolved again when an assignment targets it, the entry
 * smart_group.updated (critical in the transaction when targeted). `details`: what the governed circuit adds (the
 * summary of its preview).
 */
export async function writeRuleInTx(trx: Knex.Transaction, tenantId: number, g: LockedGroup, rule: RuleNode,
  fields: { name?: string; description?: string | null }, ctx: AuditWriteContext,
  o: { userId: number; approvalId?: number; details?: Record<string, unknown> }): Promise<GovernedWrite> {
  const cols = ruleColumns(rule);
  await checkRuleGroups(trx, tenantId, cols.canonical);
  const targeted = g.assignment_count > 0;
  if (targeted) requireTargetable(cols.canonical);
  const updates: Record<string, unknown> = {
    rule: cols.rule, rule_fields: cols.rule_fields, rule_sha256: cols.rule_sha256, rule_version: g.rule_version + 1,
    state: 'active', state_reason: null, state_since: null, pending_added: 0, pending_removed: 0,
  };
  const changed = ['rule'];
  if (fields.name !== undefined && fields.name !== g.name) { updates.name = fields.name; changed.unshift('name'); }
  if (fields.description !== undefined && (fields.description ?? null) !== (g.description ?? null)) {
    updates.description = fields.description ?? null;
    changed.splice(changed.indexOf('rule'), 0, 'description');
  }
  try {
    await trx('smart_groups').where({ tenant_id: tenantId, id: g.id }).update({ ...updates, updated_by: o.userId, updated_at: trx.fn.now() });
  } catch (err) {
    if (nameTaken(err)) throw NAME_TAKEN();
    throw err;
  }
  const change = await computeAll(trx, tenantId, g.id, cols.canonical, 'rule');
  if (g.state === 'error') await resolveInTx(trx, tenantId, 'smart_group.rule_invalid', g.id);
  if (g.state === 'held') await resolveInTx(trx, tenantId, 'smart_group.mass_change', g.id);
  await resolveMoved(trx, tenantId, targeted, [...change.added, ...change.removed]);
  const entry = await journal(trx, tenantId, ctx, targeted, {
    action: 'smart_group.updated', groupId: g.id, approvalId: o.approvalId,
    details: {
      smartGroupUuid: g.uuid, fields: changed, ruleSha256: cols.rule_sha256, ruleFields: cols.rule_fields, ruleVersion: g.rule_version + 1,
      added: change.added.length, removed: change.removed.length, memberCount: change.total, approvalId: o.approvalId ?? null,
      ...(o.details ?? {}),
    },
  });
  return { change, members: [], entry };
}

/** Deletes a group (its row held): its members and their journal go with it, its assignments too (the trigger
 *  smart_groups_assignments_cleanup); its members resolved again when an assignment targeted it; smart_group.deleted. */
export async function deleteInTx(trx: Knex.Transaction, tenantId: number, g: LockedGroup, ctx: AuditWriteContext,
  o: { approvalId?: number; details?: Record<string, unknown> } = {}): Promise<GovernedWrite> {
  const targeted = g.assignment_count > 0;
  const members = targeted ? await memberIdsOf(trx, tenantId, g.id) : [];
  await trx('smart_groups').where({ tenant_id: tenantId, id: g.id }).delete();
  if (g.state === 'error') await resolveInTx(trx, tenantId, 'smart_group.rule_invalid', g.id);
  if (g.state === 'held') await resolveInTx(trx, tenantId, 'smart_group.mass_change', g.id);
  await resolveMoved(trx, tenantId, targeted, members);
  const entry = await journal(trx, tenantId, ctx, targeted, {
    action: 'smart_group.deleted', groupId: g.id, approvalId: o.approvalId,
    details: {
      smartGroupUuid: g.uuid, memberCount: g.member_count, assignmentCount: g.assignment_count, approvalId: o.approvalId ?? null,
      ...(o.details ?? {}),
    },
  });
  return { change: null, members, entry };
}

/**
 * Releases a held group (its row held; 409 smartGroupNotHeld otherwise): its stored rule computed on the tenant and
 * written at once (journal cause 'release'), the group active again with a new window for the mass guard (the changes
 * released were looked at: they do not count against the next hour), its alert resolved, the devices that entered or
 * left resolved again when an assignment targets it; smart_group.released (critical in the transaction when targeted).
 */
export async function releaseInTx(trx: Knex.Transaction, tenantId: number, g: LockedGroup, ctx: AuditWriteContext,
  o: { approvalId?: number; details?: Record<string, unknown> } = {}): Promise<GovernedWrite> {
  if (g.state !== 'held') throw smartGroupNotHeld();
  if (validateRule(g.rule).length > 0) throw new AppError(409, 'The stored rule of this group is no longer valid: give it a new rule', 'invalidRule');
  const targeted = g.assignment_count > 0;
  await trx('smart_groups').where({ tenant_id: tenantId, id: g.id }).update({
    state: 'active', state_reason: null, state_since: null, pending_added: 0, pending_removed: 0,
    guard_window_start: null, guard_window_changes: 0,
  });
  const change = await computeAll(trx, tenantId, g.id, g.rule, 'release');
  await resolveInTx(trx, tenantId, 'smart_group.mass_change', g.id);
  await resolveMoved(trx, tenantId, targeted, [...change.added, ...change.removed]);
  const entry = await journal(trx, tenantId, ctx, targeted, {
    action: 'smart_group.released', groupId: g.id, approvalId: o.approvalId,
    details: {
      smartGroupUuid: g.uuid, ruleSha256: g.rule_sha256, ruleVersion: g.rule_version,
      added: change.added.length, removed: change.removed.length, memberCount: change.total, approvalId: o.approvalId ?? null,
      ...(o.details ?? {}),
    },
  });
  return { change, members: [], entry };
}

export const smartGroupService = {
  /** The groups of the caller's tenant, by name. */
  async list(c: SmartGroupCaller): Promise<SmartGroup[]> {
    const rows = await groupsQuery(db, c.tenantId, scoped(c)).orderByRaw('lower(g.name) ASC, g.id ASC') as GroupRow[];
    return rows.map(toGroup);
  },

  /** One group of the caller's tenant, or null. */
  async get(c: SmartGroupCaller, id: number, q: Q = db): Promise<SmartGroup | null> {
    const row = await groupsQuery(q, c.tenantId, scoped(c)).where('g.id', id).first() as GroupRow | undefined;
    return row ? toGroup(row) : null;
  },

  /** What a rule selects (POST /preview), against a group's members when given (a group of the tenant: 404 otherwise). */
  async preview(c: SmartGroupCaller, body: z.infer<typeof SmartGroupPreviewBody>): Promise<SmartGroupPreview> {
    await checkRuleGroups(db, c.tenantId, body.rule);
    if (body.smartGroupId !== undefined
      && !(await db('smart_groups').where({ tenant_id: c.tenantId, id: body.smartGroupId }).first('id'))) {
      throw smartGroupNotFound();
    }
    const visible = scoped(c);
    const p = await previewRule(db, c.tenantId, body.rule, body.smartGroupId ?? null, visible);
    // A group an assignment targets (P0-5 T7): the token of the devices whose configuration the rule would change (the
    // governed change smart_group_rule, computed again by GET /api/mdm/impact/:token/devices, the caller's scopes).
    let devicesToken: string | null = null;
    if (body.smartGroupId !== undefined && await isTargeted(db, c.tenantId, body.smartGroupId)) {
      const canonical = canonicalRule(body.rule);
      devicesToken = signImpactToken(c.tenantId, c.userId,
        { kind: 'smart_group_rule', smartGroupId: body.smartGroupId, rule: canonical, ruleSha256: ruleSha256(canonical) });
    }
    return { ...p, scope: visible ? 'visible' : 'all', devicesToken };
  },

  /** Creates a group and computes its members in the same transaction. */
  async create(c: SmartGroupCaller, body: z.infer<typeof SmartGroupCreateBody>, ctx: AuditWriteContext): Promise<SmartGroupWriteResult> {
    const cols = ruleColumns(body.rule);
    try {
      const out = await withConfigurationLock(c.tenantId, async (trx) => {
        await lockTenantGroups(trx, c.tenantId);
        const n = Number((await trx('smart_groups').where({ tenant_id: c.tenantId }).count<{ n: string }[]>('id as n').first())?.n ?? 0);
        if (n >= SMART_GROUP_LIMITS.perTenant) {
          throw new AppError(409, 'Too many dynamic groups in this tenant', 'smartGroupLimit', { limit: SMART_GROUP_LIMITS.perTenant });
        }
        await checkRuleGroups(trx, c.tenantId, cols.canonical);
        const [r] = await trx('smart_groups').insert({
          tenant_id: c.tenantId, name: body.name, description: body.description ?? null,
          rule: cols.rule, rule_fields: cols.rule_fields, rule_sha256: cols.rule_sha256,
          created_by: c.userId, updated_by: c.userId,
        }).returning(['id', 'uuid']) as Array<{ id: number; uuid: string }>;
        const id = Number(r.id);
        const change = await computeAll(trx, c.tenantId, id, cols.canonical, 'rule');
        const group = (await this.get(c, id, trx))!;
        return { group, change };
      });
      // A new group carries no assignment: standard, after the creation.
      await journalAfter(c.tenantId, ctx, {
        action: 'smart_group.created', groupId: out.group.id,
        details: { smartGroupUuid: out.group.uuid, ruleSha256: cols.rule_sha256, ruleFields: cols.rule_fields, memberCount: out.change.total },
      });
      await markDrift(c.tenantId, out.group.id, cols.rule_sha256);
      const visible = scoped(c);
      return { group: out.group, added: visibleCount(out.change.added, visible), removed: visibleCount(out.change.removed, visible) };
    } catch (err) {
      if (nameTaken(err)) throw NAME_TAKEN();
      throw err;
    }
  },

  /** Changes a group: its name, its description, its rule (the members computed again in the same transaction). */
  async update(c: SmartGroupCaller, id: number, body: z.infer<typeof SmartGroupPatchBody>, ctx: AuditWriteContext): Promise<SmartGroupWriteResult> {
    try {
      const out = await withConfigurationLock(c.tenantId, async (trx) => {
        await lockTenantGroups(trx, c.tenantId);
        const before = await lockGroup(trx, c.tenantId, id);
        const targeted = before.assignment_count > 0;
        const updates: Record<string, unknown> = {};
        if (body.name !== undefined && body.name !== before.name) updates.name = body.name;
        if (body.description !== undefined && (body.description ?? null) !== (before.description ?? null)) updates.description = body.description ?? null;
        // A group an assignment targets is the configuration's (D3): renamed or described again by an administrator only
        // (its name is what the lists of assignments, the previews and the requests for approval show).
        if (targeted && (updates.name !== undefined || updates.description !== undefined) && !isAdmin(c)) throw smartGroupAdminOnly();
        let cols: ReturnType<typeof ruleColumns> | null = null;
        if (body.rule !== undefined) {
          const next = ruleColumns(body.rule);
          // The same rule again leaves the group as it is (an error stays: the static group it names is still gone).
          if (next.rule_sha256 !== before.rule_sha256) cols = next;
        }
        if (cols) {
          await checkRuleGroups(trx, c.tenantId, cols.canonical);
          if (targeted) {
            requireTargetable(cols.canonical);
            // A targeted group's rule changes through the governed circuit (governance.ts, smart_group_rule): the route sends it
            // there; an assignment that came meanwhile is refused here (submit again).
            throw TARGETED();
          }
          Object.assign(updates, {
            rule: cols.rule, rule_fields: cols.rule_fields, rule_sha256: cols.rule_sha256, rule_version: before.rule_version + 1,
            state: 'active', state_reason: null, state_since: null, pending_added: 0, pending_removed: 0,
          });
        }
        const fields = Object.keys(updates).filter((k) => ['name', 'description', 'rule'].includes(k));
        if (fields.length === 0) return { group: (await this.get(c, id, trx))!, change: null, entry: null, sha: null };
        await trx('smart_groups').where({ tenant_id: c.tenantId, id }).update({ ...updates, updated_by: c.userId, updated_at: trx.fn.now() });
        const change = cols ? await computeAll(trx, c.tenantId, id, cols.canonical, 'rule') : null;
        // A group in error or held with a new rule: active again, its alert resolved.
        if (cols && before.state === 'error') await resolveInTx(trx, c.tenantId, 'smart_group.rule_invalid', id);
        if (cols && before.state === 'held') await resolveInTx(trx, c.tenantId, 'smart_group.mass_change', id);
        const group = (await this.get(c, id, trx))!;
        const entry = await journal(trx, c.tenantId, ctx, targeted, {
          action: 'smart_group.updated', groupId: id,
          details: {
            smartGroupUuid: before.uuid, fields,
            ...(cols ? { ruleSha256: cols.rule_sha256, ruleFields: cols.rule_fields, ruleVersion: before.rule_version + 1 } : {}),
            ...(change ? { added: change.added.length, removed: change.removed.length, memberCount: change.total } : {}),
          },
        });
        return { group, change, entry, sha: cols ? cols.rule_sha256 : null };
      });
      await journalAfter(c.tenantId, ctx, out.entry);
      if (out.sha) await markDrift(c.tenantId, id, out.sha);
      const visible = scoped(c);
      return {
        group: out.group,
        added: out.change ? visibleCount(out.change.added, visible) : null,
        removed: out.change ? visibleCount(out.change.removed, visible) : null,
      };
    } catch (err) {
      if (nameTaken(err)) throw NAME_TAKEN();
      throw err;
    }
  },

  /** What deleting a group would do (?dryRun=true): its members leave it, its assignments go with it. */
  async deletePreview(c: SmartGroupCaller, id: number): Promise<SmartGroupDeletePreview> {
    const g = await this.get(c, id);
    if (!g) throw smartGroupNotFound();
    return { outcome: 'preview', memberCount: g.memberCount, assignmentCount: g.assignmentCount };
  },

  /** Deletes a group (its members and their journal go with it). */
  async remove(c: SmartGroupCaller, id: number, ctx: AuditWriteContext): Promise<void> {
    const out = await withConfigurationLock(c.tenantId, async (trx) => {
      await lockTenantGroups(trx, c.tenantId);
      const g = await lockGroup(trx, c.tenantId, id);
      // A targeted group is deleted through the governed circuit (governance.ts, smart_group_delete): see update().
      if (g.assignment_count > 0) throw TARGETED();
      await trx('smart_groups').where({ tenant_id: c.tenantId, id }).delete();
      if (g.state === 'error') await resolveInTx(trx, c.tenantId, 'smart_group.rule_invalid', id);
      if (g.state === 'held') await resolveInTx(trx, c.tenantId, 'smart_group.mass_change', id);
      return journal(trx, c.tenantId, ctx, false, {
        action: 'smart_group.deleted', groupId: id,
        details: { smartGroupUuid: g.uuid, memberCount: g.member_count, assignmentCount: g.assignment_count },
      });
    });
    await journalAfter(c.tenantId, ctx, out);
  },
};

/**
 * A static group deleted (groupService.delete, in its transaction, the tenant's context): the dynamic groups whose rule
 * names it go to 'error' (group_deleted), their members frozen, with the alert smart_group.rule_invalid each. Returns
 * the groups put in error.
 */
export async function onStaticGroupDeleted(trx: Knex.Transaction, tenantId: number, groupId: number): Promise<number[]> {
  const rows = await trx('smart_groups').where({ tenant_id: tenantId }).whereNot('state', 'error')
    .whereRaw("'group' = ANY(rule_fields)").orderBy('id').forUpdate().select('id', 'name', 'rule') as Array<{ id: number; name: string; rule: unknown }>;
  const hit = rows.filter((r) => {
    const rule = asObject(r.rule) as RuleNode;
    return validateRule(rule).length === 0 && ruleGroupIdsOf(rule).includes(groupId);
  });
  for (const r of hit) {
    await trx('smart_groups').where({ tenant_id: tenantId, id: r.id })
      .update({ state: 'error', state_reason: 'group_deleted', state_since: trx.fn.now(), pending_added: 0, pending_removed: 0 });
    // A held group in error: its pending changes went with its rule.
    await resolveInTx(trx, tenantId, 'smart_group.mass_change', Number(r.id));
    await raiseInTx(trx, tenantId, 'smart_group.rule_invalid', {
      discriminant: Number(r.id), params: { name: r.name.slice(0, 200), smartGroupId: Number(r.id) },
      navigateTo: `/groups/smart/${Number(r.id)}`,
    });
  }
  return hit.map((r) => Number(r.id));
}
