import { clientIp } from '../utils/clientIp';
import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { tenantService, forgetTenantMemberships } from '../services/tenant.service';
import { permissionService } from '../services/permission.service';
import { db } from '../db';
import { asMember, asPlatform, switchToIdentity } from '../db/context';
import { globalViewGrant } from '../db/platformAccess';
import { AppError } from '../middleware/errorHandler';

// Database contexts (rls-tenant §8.2): these routes are outside the tenant
// router. The list and one tenant: the request's base context (the tenants
// the user may see); locate-device: across tenants; settings: the tenant's
// own context (tenantService.update); members: identity; creation and
// deletion: definer functions (tenantService).

const router = Router();

// All tenant routes require auth
router.use(requireAuth);

// ── Locate a device across the user's tenants ─────────────────────────────
// GET /api/tenants/locate-device/:id
//
// Resolves which tenant a device belongs to, used when the user follows a
// shared deep-link (`/devices/123`) while connected to the wrong tenant.
// We deliberately collapse "device doesn't exist" and "user has no access"
// into the same 404 to avoid leaking the existence of devices the caller
// can't see.
//
// Returns: { deviceId, hostname, displayName, tenantId, tenantName,
//            tenantSlug, currentTenantId } on success.
router.get('/locate-device/:id', async (req, res, next) => {
  try {
    const deviceId = parseInt(req.params.id);
    if (!Number.isFinite(deviceId)) throw new AppError(400, 'Invalid device ID');

    const userId = req.session.userId!;
    const isPlatformAdmin = req.session.role === 'admin';

    // Across tenants: a platform administrator reads with a grant (context
    // 'platform'), anyone else within its own tenants (context 'member').
    const lookup = async () => {
      const row = await db('devices')
        .leftJoin('tenants', 'devices.tenant_id', 'tenants.id')
        .where('devices.id', deviceId)
        .first(
          'devices.id as id',
          'devices.tenant_id as tenantId',
          'devices.hostname as hostname',
          'devices.display_name as displayName',
          'tenants.name as tenantName',
          'tenants.slug as tenantSlug',
        );
      if (!row) return null;

      // Access gate: platform admins always pass; otherwise the user must
      // be a member of the device's tenant AND have device-read permission
      // through one of their teams. Mirrors the requireDeviceRead middleware
      // used by /api/devices/:id, so no privilege escalation here.
      let allowed = isPlatformAdmin;
      if (!allowed) {
        const hasTenantMembership = await tenantService.userHasAccess(userId, row.tenantId);
        if (hasTenantMembership) {
          allowed = await permissionService.canReadDevice(userId, deviceId, false);
        }
      }
      return allowed ? row : null;
    };
    const row = isPlatformAdmin
      ? await asPlatform(await globalViewGrant(req, 'console.locate_device'), lookup)
      : await asMember(userId, lookup);
    if (!row) return res.status(404).json({ error: 'Device not found' });

    res.json({
      data: {
        deviceId: row.id,
        hostname: row.hostname,
        displayName: row.displayName,
        tenantId: row.tenantId,
        tenantName: row.tenantName,
        tenantSlug: row.tenantSlug,
        currentTenantId: req.session.currentTenantId ?? null,
      },
    });
  } catch (err) { next(err); }
});

// ── Tenant switch ──────────────────────────────────────────────────────────
// POST /api/tenant/switch  { tenantId: number }
router.post('/switch', async (req, res, next) => {
  try {
    const { tenantId } = req.body as { tenantId: number };
    // A tenant id the database can hold (integer column): any other value
    // would only fail later, on every request of the session.
    if (typeof tenantId !== 'number' || !Number.isInteger(tenantId) || tenantId <= 0 || tenantId > 2147483647) {
      throw new AppError(400, 'tenantId is required');
    }

    const userId = req.session.userId!;

    // Platform admins can switch to any tenant; others only to their own
    if (req.session.role !== 'admin') {
      const hasAccess = await tenantService.userHasAccess(userId, tenantId);
      if (!hasAccess) throw new AppError(403, 'Access denied to this tenant');
    }

    req.session.currentTenantId = tenantId;
    // requireTenant re-checks the membership from here on: start from the
    // answer just read, not from one cached before.
    forgetTenantMemberships(userId);
    res.json({ success: true, data: { currentTenantId: tenantId } });
  } catch (err) {
    next(err);
  }
});

// ── List tenants ───────────────────────────────────────────────────────────
// GET /api/tenants  (admin: all, user: their tenants with role)
router.get('/', async (req, res, next) => {
  try {
    const userId = req.session.userId!;
    const isAdmin = req.session.role === 'admin';

    if (isAdmin) {
      const tenants = await tenantService.getAll();
      res.json({ success: true, data: tenants });
    } else {
      const tenants = await tenantService.getTenantsForUser(userId);
      res.json({ success: true, data: tenants });
    }
  } catch (err) {
    next(err);
  }
});

// ── Create tenant (platform admin only) ───────────────────────────────────
router.post('/', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const { name, slug } = req.body as { name: string; slug: string };
    if (!name || !slug) throw new AppError(400, 'name and slug are required');
    const tenant = await tenantService.create({ name, slug }, { ipAddress: clientIp(req) || undefined });
    res.status(201).json({ success: true, data: tenant });
  } catch (err) {
    next(err);
  }
});

// ── Get one tenant ─────────────────────────────────────────────────────────
router.get('/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const tenant = await tenantService.getById(id);
    if (!tenant) throw new AppError(404, 'Tenant not found');

    // Non-admins can only see their own tenants: another tenant answers like
    // an unknown one (its existence is not told).
    if (req.session.role !== 'admin') {
      const hasAccess = await tenantService.userHasAccess(req.session.userId!, id);
      if (!hasAccess) throw new AppError(404, 'Tenant not found');
    }

    res.json({ success: true, data: tenant });
  } catch (err) {
    next(err);
  }
});

// ── Update tenant (platform admin only) ───────────────────────────────────
router.put('/:id', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const id = parseInt(req.params.id);
    const before = await tenantService.getById(id);
    const { name, slug, twoStepApproval } = req.body as { name?: string; slug?: string; twoStepApproval?: boolean };
    const tenant = await tenantService.update(id, { name, slug, twoStepApproval });
    if (!tenant) throw new AppError(404, 'Tenant not found');
    try {
      const { auditService } = await import('../services/audit.service');
      const changes: Record<string, unknown> = {};
      if (name !== undefined && name !== before?.name) changes.name = { from: before?.name, to: name };
      if (slug !== undefined && slug !== before?.slug) changes.slug = { from: before?.slug, to: slug };
      if (twoStepApproval !== undefined && twoStepApproval !== before?.twoStepApproval) {
        changes.twoStepApproval = { from: before?.twoStepApproval, to: twoStepApproval };
      }
      if (Object.keys(changes).length > 0) {
        await auditService.log({
          tenantId: id,
          userId: req.session.userId,
          action: 'tenant.settings_changed',
          resourceType: 'tenant',
          resourcePath: String(id),
          details: changes,
          ipAddress: clientIp(req) || undefined,
        });
      }
    } catch {}
    res.json({ success: true, data: tenant });
  } catch (err) {
    next(err);
  }
});

// ── Delete tenant (platform admin only, cannot delete tenant 1) ───────────
router.delete('/:id', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const id = parseInt(req.params.id);
    if (id === 1) throw new AppError(400, 'Cannot delete the default tenant');
    await tenantService.delete(id, { ipAddress: clientIp(req) || undefined });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ── Tenant members ─────────────────────────────────────────────────────────
// GET /api/tenants/:id/members
router.get('/:id/members', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const tenantId = parseInt(req.params.id);
    const members = await tenantService.getMembers(tenantId);
    res.json({ success: true, data: members });
  } catch (err) {
    next(err);
  }
});

// The tenant role of a membership is 'admin' (tenant administrator) or the
// slug of a permission set, checked by tenantService: 'member' (the pre-091
// name the panel still sends) and a missing role are stored as 'user', any
// other unknown slug is refused (400) — an orphan slug gives no capability.

// POST /api/tenants/:id/members  { userId, role }
router.post('/:id/members', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const tenantId = parseInt(req.params.id);
    const { userId, role } = req.body as { userId: number; role?: unknown };
    if (!userId) throw new AppError(400, 'userId is required');
    if (!Number.isInteger(userId) || userId <= 0) throw new AppError(400, 'Invalid userId');
    if (!Number.isInteger(tenantId) || tenantId <= 0 || !(await tenantService.getById(tenantId))) {
      throw new AppError(404, 'Tenant not found');
    }
    if (!(await switchToIdentity(() => db('users').where({ id: userId }).first('id')))) throw new AppError(404, 'User not found');
    await tenantService.addUser(tenantId, userId, role);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// PUT /api/tenants/:id/members/:uid  { role }
router.put('/:id/members/:uid', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const tenantId = parseInt(req.params.id);
    const userId = parseInt(req.params.uid);
    const { role } = req.body as { role?: unknown };
    if (!role) throw new AppError(400, 'role is required');
    await tenantService.updateUserRole(tenantId, userId, role);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/tenants/:id/members/:uid
// The user's teams of that tenant go with it, and its sessions end
// (tenantService.removeUser).
router.delete('/:id/members/:uid', async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const tenantId = parseInt(req.params.id);
    const userId = parseInt(req.params.uid);
    await tenantService.removeUser(tenantId, userId);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

export default router;
