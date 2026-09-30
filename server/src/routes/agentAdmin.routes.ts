import { Router, type Request, type Response } from 'express';
import crypto from 'crypto';
import { isMasterTenant } from '@obligarth/shared';
import { db } from '../db';
import { requireRole, requireAnyTenantCapability } from '../middleware/rbac';

const router = Router();

// API keys (agent_api_keys): the enrollment credentials of a tenant. A key
// may carry a default group, which is also the pre-approval claim of the
// devices enrolled with it (permissionService).

async function listKeys(req: Request, res: Response): Promise<void> {
  // Master tenant gets every API key across the install. Other tenants
  // stay strictly scoped to their own keys.
  const isMaster = isMasterTenant(req.tenantId!);
  const q = db('agent_api_keys')
    .leftJoin('devices', function () {
      this.on('devices.api_key_id', '=', 'agent_api_keys.id')
          .andOn('devices.approval_status', db.raw("'approved'"));
    })
    .leftJoin('device_groups', 'device_groups.id', 'agent_api_keys.default_group_id')
    .groupBy('agent_api_keys.id', 'device_groups.name')
    .select(
      'agent_api_keys.*',
      db.raw('COUNT(devices.id)::int as device_count'),
      'device_groups.name as default_group_name',
    )
    .orderBy('agent_api_keys.created_at', 'desc');
  if (!isMaster) q.where({ 'agent_api_keys.tenant_id': req.tenantId });
  const rows = await q;

  const data = rows.map((r: any) => ({
    id: r.id,
    tenantId: r.tenant_id,
    name: r.name,
    key: r.key,
    defaultGroupId: r.default_group_id ?? null,
    defaultGroupName: r.default_group_name ?? null,
    createdBy: r.created_by,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
    deviceCount: r.device_count ?? 0,
  }));
  res.json({ success: true, data });
}

async function createKey(req: Request, res: Response): Promise<void> {
  const { name, defaultGroupId } = req.body as { name: string; defaultGroupId?: number | null };
  if (!name?.trim()) {
    res.status(400).json({ success: false, error: 'Name is required' });
    return;
  }
  const userId = req.session?.userId ?? 0;
  const rawKey = crypto.randomBytes(32).toString('hex');
  const [row] = await db('agent_api_keys').insert({
    tenant_id: req.tenantId,
    name: name.trim(),
    key: rawKey,
    default_group_id: defaultGroupId ?? null,
    created_by: userId,
  }).returning('*');
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReq(req, 'api_key.created', {
      resourceType: 'api_key', resourcePath: String(row.id), details: { name: row.name },
    });
  } catch {}
  res.status(201).json({
    success: true,
    data: {
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      key: row.key,
      defaultGroupId: row.default_group_id ?? null,
      defaultGroupName: null,
      createdBy: row.created_by,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at ?? null,
      deviceCount: 0,
    },
  });
}

async function updateKey(req: Request, res: Response): Promise<void> {
  const id = Number(req.params.id);
  const { name, defaultGroupId } = req.body as { name?: string; defaultGroupId?: number | null };
  const updates: any = {};
  if (name !== undefined) updates.name = name.trim();
  if (defaultGroupId !== undefined) updates.default_group_id = defaultGroupId;
  if (Object.keys(updates).length === 0) {
    res.status(400).json({ success: false, error: 'Nothing to update' });
    return;
  }
  const affected = await db('agent_api_keys')
    .where({ id, tenant_id: req.tenantId })
    .update(updates);
  if (!affected) { res.status(404).json({ success: false, error: 'Key not found' }); return; }
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReq(req, 'api_key.updated', {
      resourceType: 'api_key', resourcePath: String(id),
      details: { changes: Object.keys(updates) },
    });
  } catch {}
  res.json({ success: true });
}

async function deleteKey(req: Request, res: Response): Promise<void> {
  const id = Number(req.params.id);
  const deleted = await db('agent_api_keys')
    .where({ id, tenant_id: req.tenantId })
    .delete();
  if (!deleted) {
    res.status(404).json({ success: false, error: 'API key not found' });
    return;
  }
  try {
    const { auditService } = await import('../services/audit.service');
    await auditService.logReq(req, 'api_key.deleted', {
      resourceType: 'api_key', resourcePath: String(id),
    });
  } catch {}
  res.json({ success: true });
}

// GET    /api/agent/keys        — list API keys for the current tenant
// POST   /api/agent/keys        — create a new API key
// PUT    /api/agent/keys/:id    — update API key (name, default group)
// DELETE /api/agent/keys/:id    — revoke an API key
//
// GET is needed by the "Add agent" modal to populate the key picker —
// we accept either `agent_config:keys` (existing manage cap) or
// `agent_config:approval` (since approving agents naturally implies
// being able to enroll them too). CUD on keys stays admin-only —
// minting and revoking enrolment credentials is takeover-level.
router.get('/keys', requireAnyTenantCapability('agent_config:keys', 'agent_config:approval'), listKeys);
router.post('/keys',       requireRole('admin'), createKey);
router.put('/keys/:id',    requireRole('admin'), updateKey);
router.delete('/keys/:id', requireRole('admin'), deleteKey);

export default router;
