import type { Assignment, AssignmentTargetScope, JsonValue } from '@obligarth/shared';
import { db } from '../../db';
import { permissionService } from '../../services/permission.service';

// =============================================================================
// Reading the assignments (docs: modele-donnees-mdm §7.5, §10.6): by resource
// or by target, with the names of the resource and of the target. A member
// who is not an administrator sees the assignments whose target lies in their
// scopes (the whole tenant, their groups and devices): the name of a group or
// of a device out of reach is never shown. A dynamic group (P0-5 T6) is read
// by every member of the tenant (its list is: it gives no team scope, D8),
// like the whole tenant.
// =============================================================================

export interface AssignmentFilter {
  resourceType?: 'policy' | 'app';
  resourceId?: number;
  targetScope?: AssignmentTargetScope;
  targetId?: number | null;
}

export interface Viewer { userId: number; isAdmin: boolean }

export async function listAssignments(tenantId: number, f: AssignmentFilter, viewer: Viewer): Promise<Assignment[]> {
  const q = db('assignments as a').where('a.tenant_id', tenantId).orderBy('a.id')
    .leftJoin('policies as p', function joinPolicy() {
      this.on('p.id', '=', 'a.resource_id').andOn('p.tenant_id', '=', 'a.resource_tenant_id').andOn(db.raw("a.resource_type = 'policy'"));
    })
    .leftJoin('apps as ap', function joinApp() {
      this.on('ap.id', '=', 'a.resource_id').andOn('ap.tenant_id', '=', 'a.resource_tenant_id').andOn(db.raw("a.resource_type = 'app'"));
    })
    .leftJoin('device_groups as g', function joinGroup() {
      this.on('g.id', '=', 'a.target_id').andOn('g.tenant_id', '=', 'a.tenant_id').andOn(db.raw("a.target_scope = 'group'"));
    })
    .leftJoin('devices as d', function joinDevice() {
      this.on('d.id', '=', 'a.target_id').andOn('d.tenant_id', '=', 'a.tenant_id').andOn(db.raw("a.target_scope = 'device'"));
    })
    .leftJoin('smart_groups as sg', function joinSmartGroup() {
      this.on('sg.id', '=', 'a.target_id').andOn('sg.tenant_id', '=', 'a.tenant_id').andOn(db.raw("a.target_scope = 'smart_group'"));
    })
    .select('a.*', 'p.name as policy_name', 'ap.name as app_name', 'g.name as group_name', 'd.label as device_label', 'sg.name as smart_group_name');
  if (f.resourceType) q.where('a.resource_type', f.resourceType);
  if (f.resourceId !== undefined) q.where('a.resource_id', f.resourceId);
  if (f.targetScope) q.where('a.target_scope', f.targetScope);
  if (f.targetId !== undefined) {
    if (f.targetId === null) q.whereNull('a.target_id'); else q.where('a.target_id', f.targetId);
  }
  let rows = await q as Array<Record<string, any>>;
  if (!viewer.isAdmin) {
    const groups = await permissionService.getVisibleGroupIds(viewer.userId, false);
    const devices = await permissionService.getVisibleDeviceIds(viewer.userId, false);
    const inGroups = groups === 'all' ? null : new Set(groups.map(Number));
    const inDevices = devices === 'all' ? null : new Set(devices.map(Number));
    rows = rows.filter((r) => r.target_scope === 'tenant' || r.target_scope === 'smart_group'
      || (r.target_scope === 'group' && (!inGroups || inGroups.has(Number(r.target_id))))
      || (r.target_scope === 'device' && (!inDevices || inDevices.has(Number(r.target_id)))));
  }
  return rows.map((r) => ({
    id: Number(r.id),
    tenantId: Number(r.tenant_id),
    resourceType: r.resource_type,
    resourceId: Number(r.resource_id),
    resourceTenantId: Number(r.resource_tenant_id),
    resourceName: (r.resource_type === 'policy' ? r.policy_name : r.app_name) ?? null,
    targetScope: r.target_scope,
    targetId: r.target_id === null ? null : Number(r.target_id),
    targetName: r.target_scope === 'group' ? r.group_name ?? null : r.target_scope === 'device' ? r.device_label ?? null
      : r.target_scope === 'smart_group' ? r.smart_group_name ?? null : null,
    mode: r.mode,
    priority: Number(r.priority),
    options: (typeof r.options === 'string' ? JSON.parse(r.options) : r.options ?? {}) as Record<string, JsonValue>,
    createdBy: r.created_by ?? null,
    createdAt: new Date(r.created_at).toISOString(),
    updatedAt: new Date(r.updated_at).toISOString(),
  }));
}
