import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { MDM_STALE_AFTER_DAYS_DEFAULT, isMasterTenant } from '@obligarth/shared';
import type { DeviceGroup, DeviceGroupTreeNode, DeviceGroupConfig, MetricThresholds } from '@obligarth/shared';
import type { TenantView } from './deviceScope.service';

// Tenant rule: a group tree never spans two tenants — a parent is always a
// group of the child's tenant (create, move) — so the closure never hands
// the teams of one tenant a scope on another tenant's groups or devices.
// The master tenant's global view (every tenant) is an explicit flag of
// the caller (platform administrators only, deviceScope.service
// hasGlobalView), never inferred from the tenant id.

interface GroupRow {
  id: number;
  tenant_id: number;
  parent_id: number | null;
  name: string;
  slug: string;
  description: string | null;
  sort_order: number;
  group_notifications: boolean;
  always_on: boolean;
  group_config: DeviceGroupConfig | null;
  thresholds: MetricThresholds | string | null;
  uuid: string;
  created_at: Date;
  updated_at: Date;
}

// always_on, group_config, thresholds and metric_alerts_enabled were the
// RMM configuration of a group: no longer written, still mapped (the shared
// DeviceGroup type declares them) until the future base migration.
function rowToGroup(row: GroupRow & { tenant_name?: string | null }): DeviceGroup {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    tenantName: row.tenant_name ?? null,
    parentId: row.parent_id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    sortOrder: row.sort_order,
    groupNotifications: row.group_notifications,
    alwaysOn: (row as any).always_on ?? false,
    groupConfig: row.group_config
      ? (typeof row.group_config === 'string' ? JSON.parse(row.group_config) : row.group_config)
      : {},
    thresholds: row.thresholds
      ? (typeof row.thresholds === 'string' ? JSON.parse(row.thresholds) : row.thresholds)
      : {},
    metricAlertsEnabled: typeof (row as any).metric_alerts_enabled === 'boolean' ? (row as any).metric_alerts_enabled : null,
    uuid: row.uuid,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

/** A slug free in `tenantId` — the unique key is (slug, tenant_id). Another
 *  tenant's groups are never looked at: the suffix picked here would tell
 *  which names they use. */
async function ensureUniqueSlug(slug: string, tenantId: number, excludeId?: number): Promise<string> {
  let candidate = slug;
  let i = 1;
  while (true) {
    const q = db('device_groups').where({ slug: candidate, tenant_id: tenantId });
    if (excludeId) q.whereNot({ id: excludeId });
    const exists = await q.first();
    if (!exists) return candidate;
    candidate = `${slug}-${i++}`;
  }
}

export const groupService = {
  async getAll(tenantId: number, view?: TenantView): Promise<DeviceGroup[]> {
    // The global view gets every group across the install — joined with
    // `tenants` so each row carries `tenant_name` for the UI to render
    // tenant headers above the group sub-tree. Every other caller stays
    // strictly scoped.
    const isMaster = !!view?.globalView && isMasterTenant(tenantId);
    const q = db('device_groups')
      .leftJoin('tenants', 'device_groups.tenant_id', 'tenants.id')
      .select('device_groups.*', 'tenants.name as tenant_name')
      .orderBy('device_groups.sort_order')
      .orderBy('device_groups.name');
    if (!isMaster) q.where('device_groups.tenant_id', tenantId);
    const rows = await q;
    return rows.map(rowToGroup);
  },

  async getById(id: number): Promise<DeviceGroup | null> {
    const row = await db<GroupRow>('device_groups').where({ id }).first();
    return row ? rowToGroup(row) : null;
  },

  /**
   * Creates a group of `tenantId`. A parent must be a group of the same
   * tenant: another tenant's parent answers like an unknown one (400). The
   * row and its closure paths are written together.
   */
  async create(data: {
    name: string;
    description?: string | null;
    parentId?: number | null;
    sortOrder?: number;
    groupNotifications?: boolean;
  }, tenantId: number): Promise<DeviceGroup> {
    const slug = await ensureUniqueSlug(slugify(data.name), tenantId);

    const row = await db.transaction(async (trx) => {
      if (data.parentId) {
        const parent = await trx('device_groups').where({ id: data.parentId, tenant_id: tenantId }).first('id');
        if (!parent) throw new AppError(400, 'Parent group not found');
      }

      const [created] = await trx<GroupRow>('device_groups')
        .insert({
          name: data.name,
          slug,
          description: data.description ?? null,
          parent_id: data.parentId ?? null,
          sort_order: data.sortOrder ?? 0,
          group_notifications: data.groupNotifications ?? false,
          tenant_id: tenantId,
        })
        .returning('*');

      // Maintain closure table
      // Self-reference (depth 0)
      await trx('device_group_closure').insert({
        tenant_id: tenantId,
        ancestor_id: created.id,
        descendant_id: created.id,
        depth: 0,
      });

      // Copy ancestor paths from parent
      if (data.parentId) {
        await trx.raw(
          `INSERT INTO device_group_closure (tenant_id, ancestor_id, descendant_id, depth)
           SELECT gc.tenant_id, gc.ancestor_id, ?, gc.depth + 1
           FROM device_group_closure gc
           WHERE gc.descendant_id = ? AND gc.tenant_id = ?`,
          [created.id, data.parentId, tenantId],
        );
      }
      return created;
    });

    return rowToGroup(row);
  },

  async update(
    id: number,
    data: {
      name?: string;
      description?: string | null;
      sortOrder?: number;
      groupNotifications?: boolean;
    },
  ): Promise<DeviceGroup | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };

    if (data.name !== undefined) {
      const current = await db('device_groups').where({ id }).first('tenant_id') as { tenant_id: number } | undefined;
      if (!current) return null;
      updateData.name = data.name;
      updateData.slug = await ensureUniqueSlug(slugify(data.name), Number(current.tenant_id), id);
    }
    if (data.description !== undefined) updateData.description = data.description;
    if (data.sortOrder !== undefined) updateData.sort_order = data.sortOrder;
    if (data.groupNotifications !== undefined) updateData.group_notifications = data.groupNotifications;

    const [row] = await db<GroupRow>('device_groups')
      .where({ id })
      .update(updateData)
      .returning('*');

    return row ? rowToGroup(row) : null;
  },

  /**
   * Moves a group under `newParentId` (null: root). The new parent must be a
   * group of the moved group's tenant — another tenant's answers like an
   * unknown one (400) — and not one of its descendants. The closure is
   * rewritten in one transaction.
   */
  async move(id: number, newParentId: number | null): Promise<DeviceGroup | null> {
    const row = await db.transaction(async (trx) => {
      // Get current group
      const group = await trx<GroupRow>('device_groups').where({ id }).first();
      if (!group) return null;

      if (newParentId !== null) {
        const parent = await trx('device_groups').where({ id: newParentId, tenant_id: group.tenant_id }).first('id');
        if (!parent) throw new AppError(400, 'Parent group not found');
        // Prevent circular reference: newParentId must not be a descendant of id
        const isDescendant = await trx('device_group_closure')
          .where({ ancestor_id: id, descendant_id: newParentId })
          .first();
        if (isDescendant) {
          throw new AppError(400, 'Cannot move group into its own descendant');
        }
      }

      // Get all descendants of the subtree (including self)
      const subtreeIds = await trx('device_group_closure')
        .where({ ancestor_id: id })
        .select('descendant_id');
      const descIds = subtreeIds.map((r) => r.descendant_id);

      // Remove all closure entries where ancestor is NOT in the subtree
      // but descendant IS in the subtree (these are the "outside" links)
      await trx('device_group_closure')
        .whereIn('descendant_id', descIds)
        .whereNotIn('ancestor_id', descIds)
        .del();

      // Reconnect: for each ancestor of newParent, create links to every node in subtree
      if (newParentId !== null) {
        await trx.raw(
          `INSERT INTO device_group_closure (tenant_id, ancestor_id, descendant_id, depth)
           SELECT p.tenant_id, p.ancestor_id, s.descendant_id, p.depth + s.depth + 1
           FROM device_group_closure p
           CROSS JOIN device_group_closure s
           WHERE p.descendant_id = ?
             AND s.ancestor_id = ?
             AND p.tenant_id = ? AND s.tenant_id = ?`,
          [newParentId, id, group.tenant_id, group.tenant_id],
        );
      }

      // Update the parent_id column
      const [updated] = await trx<GroupRow>('device_groups')
        .where({ id })
        .update({ parent_id: newParentId, updated_at: new Date() })
        .returning('*');
      // The ancestry of the subtree's devices changed: the inheritance of the policies follows
      // (modele-donnees-mdm §7.6, §7.12), requested in this transaction.
      const { requestTenantResolution } = await import('../mdm/policies/triggers');
      await requestTenantResolution(trx, Number(group.tenant_id));
      return updated ?? null;
    });

    return row ? rowToGroup(row) : null;
  },

  async delete(id: number): Promise<boolean> {
    const group = await db('device_groups').where({ id }).first('tenant_id') as { tenant_id: number } | undefined;
    // CASCADE in the DB handles closure table and child groups
    const count = await db('device_groups').where({ id }).del();
    if (count > 0 && group) {
      // Its assignments went with it (assignments_cleanup) and its devices left it: the policies follow
      // (modele-donnees-mdm §7.5, §7.12).
      const { requestTenantResolution } = await import('../mdm/policies/triggers');
      await requestTenantResolution(null, Number(group.tenant_id));
    }
    return count > 0;
  },

  // ── Tree queries using closure table ──

  async getAncestors(groupId: number): Promise<DeviceGroup[]> {
    const rows = await db<GroupRow>('device_groups')
      .join('device_group_closure', 'device_groups.id', 'device_group_closure.ancestor_id')
      .where('device_group_closure.descendant_id', groupId)
      .where('device_group_closure.depth', '>', 0)
      .orderBy('device_group_closure.depth', 'desc')
      .select('device_groups.*');
    return rows.map(rowToGroup);
  },

  async getDescendantIds(groupId: number): Promise<number[]> {
    const rows = await db('device_group_closure')
      .where({ ancestor_id: groupId })
      .select('descendant_id');
    return rows.map((r) => r.descendant_id);
  },

  async getChildren(parentId: number | null): Promise<DeviceGroup[]> {
    const query = db<GroupRow>('device_groups').orderBy('sort_order').orderBy('name');
    if (parentId === null) {
      query.whereNull('parent_id');
    } else {
      query.where({ parent_id: parentId });
    }
    const rows = await query;
    return rows.map(rowToGroup);
  },

  async getTree(tenantId: number, view?: TenantView): Promise<DeviceGroupTreeNode[]> {
    const allGroups = await this.getAll(tenantId, view);
    const groupMap = new Map<number, DeviceGroupTreeNode>();

    // Count the devices under management per group (direct members only; MDM counters of
    // modele-donnees-mdm §11.3). The global view sees counts across every tenant; every other caller stays
    // strictly scoped. 'stale': no contact for the default mdmStaleAfterDays (the tenant's own threshold
    // qualifies the list and the summary of the registry).
    const isMaster = !!view?.globalView && isMasterTenant(tenantId);
    const countQ = db('devices')
      .whereNot('enrollment_state', 'unenrolled')
      .whereNotNull('group_id')
      .groupBy('group_id')
      .select('group_id', db.raw('count(*) as total'))
      .select(
        db.raw("count(*) filter (where enrollment_state = 'enrolled') as enrolled_count"),
        db.raw("count(*) filter (where compliance_state = 'non_compliant') as non_compliant_count"),
        db.raw("count(*) filter (where config_state = 'error') as config_error_count"),
        db.raw("count(*) filter (where last_checkin_at < now() - make_interval(days => ?::int)) as stale_count", [MDM_STALE_AFTER_DAYS_DEFAULT]),
      );
    if (!isMaster) countQ.where('tenant_id', tenantId);
    const countRows = await countQ;
    type Counts = { total: number; enrolled: number; nonCompliant: number; configErrors: number; stale: number };
    const zero = (): Counts => ({ total: 0, enrolled: 0, nonCompliant: 0, configErrors: 0, stale: 0 });
    const directCounts = new Map<number, Counts>();
    for (const row of countRows) {
      directCounts.set(row.group_id, {
        total: parseInt(row.total), enrolled: parseInt(row.enrolled_count), nonCompliant: parseInt(row.non_compliant_count),
        configErrors: parseInt(row.config_error_count), stale: parseInt(row.stale_count),
      });
    }

    // Initialize nodes with direct counts
    for (const g of allGroups) {
      const dc = directCounts.get(g.id) ?? zero();
      groupMap.set(g.id, {
        ...g, children: [],
        deviceCount: dc.total, total: dc.total,
        enrolledCount: dc.enrolled, nonCompliantCount: dc.nonCompliant, configErrorCount: dc.configErrors, staleCount: dc.stale,
        onlineCount: 0, offlineCount: 0, warningCount: 0, criticalCount: 0,
      });
    }

    // Build tree
    const roots: DeviceGroupTreeNode[] = [];
    for (const node of groupMap.values()) {
      if (node.parentId && groupMap.has(node.parentId)) {
        groupMap.get(node.parentId)!.children.push(node);
      } else {
        roots.push(node);
      }
    }

    // Accumulate counts from children (bottom-up)
    function accumulate(node: DeviceGroupTreeNode): Counts {
      const totals: Counts = {
        total: node.deviceCount ?? 0, enrolled: node.enrolledCount ?? 0, nonCompliant: node.nonCompliantCount ?? 0,
        configErrors: node.configErrorCount ?? 0, stale: node.staleCount ?? 0,
      };
      for (const child of node.children) {
        const c = accumulate(child);
        totals.total += c.total;
        totals.enrolled += c.enrolled;
        totals.nonCompliant += c.nonCompliant;
        totals.configErrors += c.configErrors;
        totals.stale += c.stale;
      }
      node.total = totals.total;
      node.enrolledCount = totals.enrolled;
      node.nonCompliantCount = totals.nonCompliant;
      node.configErrorCount = totals.configErrors;
      node.staleCount = totals.stale;
      return totals;
    }
    for (const root of roots) accumulate(root);

    return roots;
  },

  /**
   * Batch-update sortOrder for multiple groups at once — all of them groups
   * of `tenantId` (of any tenant for the global view). One id out of reach
   * and nothing is written: returns false.
   */
  async reorder(items: { id: number; sortOrder: number }[], tenantId: number, view?: TenantView): Promise<boolean> {
    const isMaster = !!view?.globalView && isMasterTenant(tenantId);
    const ids = [...new Set(items.map((i) => i.id))];
    return db.transaction(async (trx) => {
      const found = trx('device_groups').whereIn('id', ids);
      if (!isMaster) found.where({ tenant_id: tenantId });
      if ((await found.pluck('id')).length !== ids.length) return false;
      for (const item of items) {
        const q = trx('device_groups').where({ id: item.id });
        if (!isMaster) q.where({ tenant_id: tenantId });
        await q.update({ sort_order: item.sortOrder, updated_at: new Date() });
      }
      return true;
    });
  },

  /**
   * The teams through which `userId` may create a group in `tenantId`:
   * its teams OF THAT TENANT with can_create — a team is mono-tenant, and
   * can_create granted elsewhere gives nothing here — while the user is
   * still a member of the tenant. The new group's rw scope goes to these
   * teams, and to no other.
   */
  async creatorTeamIds(userId: number, tenantId: number): Promise<number[]> {
    const member = await db('user_tenants').where({ user_id: userId, tenant_id: tenantId }).first('user_id');
    if (!member) return [];
    const rows = await db('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where({ 'team_memberships.user_id': userId, 'user_teams.tenant_id': tenantId, 'user_teams.can_create': true })
      .orderBy('user_teams.id')
      .select('user_teams.id') as Array<{ id: number }>;
    return rows.map((r) => Number(r.id));
  },

  /**
   * Find the nearest ancestor (or self) with group_notifications = true.
   * Uses the closure table, ordered by depth ASC (self = depth 0 first).
   * Returns the group if found, null otherwise.
   */
  async findGroupNotificationAncestor(groupId: number): Promise<DeviceGroup | null> {
    const row = await db<GroupRow>('device_groups')
      .join('device_group_closure', 'device_groups.id', 'device_group_closure.ancestor_id')
      .where('device_group_closure.descendant_id', groupId)
      .where('device_groups.group_notifications', true)
      .orderBy('device_group_closure.depth', 'asc')
      .first('device_groups.*');
    return row ? rowToGroup(row) : null;
  },
};
