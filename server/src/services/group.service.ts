import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { isMasterTenant } from '@obligarth/shared';
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
      return updated ?? null;
    });

    return row ? rowToGroup(row) : null;
  },

  async delete(id: number): Promise<boolean> {
    // CASCADE in the DB handles closure table and child groups
    const count = await db('device_groups').where({ id }).del();
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

    // Count devices per group (direct members only). The global view sees
    // counts across every tenant; every other caller stays strictly scoped.
    const isMaster = !!view?.globalView && isMasterTenant(tenantId);
    const countQ = db('devices')
      .where({ approval_status: 'approved' })
      .whereNot({ status: 'pending_uninstall' })
      .whereNotNull('group_id')
      .groupBy('group_id')
      .select('group_id', db.raw('count(*) as total'))
      .select(
        db.raw("count(*) filter (where status = 'online') as online_count"),
        db.raw("count(*) filter (where status = 'offline') as offline_count"),
        db.raw("count(*) filter (where status = 'warning') as warning_count"),
        db.raw("count(*) filter (where status = 'critical') as critical_count"),
      );
    if (!isMaster) countQ.where('tenant_id', tenantId);
    const countRows = await countQ;
    const directCounts = new Map<number, { total: number; online: number; offline: number; warning: number; critical: number }>();
    for (const row of countRows) {
      directCounts.set(row.group_id, {
        total: parseInt(row.total), online: parseInt(row.online_count),
        offline: parseInt(row.offline_count), warning: parseInt(row.warning_count),
        critical: parseInt(row.critical_count),
      });
    }

    // Initialize nodes with direct counts
    for (const g of allGroups) {
      const dc = directCounts.get(g.id) ?? { total: 0, online: 0, offline: 0, warning: 0, critical: 0 };
      groupMap.set(g.id, {
        ...g, children: [],
        deviceCount: dc.total, total: dc.total,
        onlineCount: dc.online, offlineCount: dc.offline,
        warningCount: dc.warning, criticalCount: dc.critical,
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
    function accumulate(node: DeviceGroupTreeNode): { total: number; online: number; offline: number; warning: number; critical: number } {
      let totals = {
        total: node.deviceCount ?? 0, online: node.onlineCount ?? 0,
        offline: node.offlineCount ?? 0, warning: node.warningCount ?? 0,
        critical: node.criticalCount ?? 0,
      };
      for (const child of node.children) {
        const childTotals = accumulate(child);
        totals.total += childTotals.total;
        totals.online += childTotals.online;
        totals.offline += childTotals.offline;
        totals.warning += childTotals.warning;
        totals.critical += childTotals.critical;
      }
      node.total = totals.total;
      node.onlineCount = totals.online;
      node.offlineCount = totals.offline;
      node.warningCount = totals.warning;
      node.criticalCount = totals.critical;
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
