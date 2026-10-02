import { db } from '../db';
import { switchToIdentity } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import type { TenantCapability } from '@obligarth/shared';

// Permission sets are a catalog (rls-tenant §5.2): read in any context,
// written in the identity context (after the route's checks).
import { TENANT_CAPABILITIES, TENANT_CAPABILITY_LABELS, knownTenantCapabilities } from '@obligarth/shared';

interface PermissionSetRow {
  id: number;
  name: string;
  slug: string;
  capabilities: unknown;
  is_default: boolean;
  audience?: string;
  created_at: Date;
}

/** What a set of audience 'client' may hold (D42, option 1: the approver and
 *  the auditor of a client). An operational capability would make its holders
 *  requesters of the client side, whose batches any approver approves (D24):
 *  refused here and by the database (permission_sets_client_capabilities). */
export const CLIENT_SET_CAPABILITIES: readonly string[] = ['approvals.review', 'audit.read'];

export interface PermissionSet {
  id: number;
  name: string;
  slug: string;
  capabilities: TenantCapability[];
  isDefault: boolean;
  createdAt: string;
}

interface CapabilityDef {
  key: TenantCapability;
  label: string;
}

// The PermissionSets matrix lists the shared tenant capabilities, each one
// checked at runtime (requireTenantCapability). A set may still store
// capabilities removed since (the seeded sets carry the RMM ones): a set is
// returned without them, and a write stores only the shared ones.

function rowToPermissionSet(row: PermissionSetRow): PermissionSet {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    capabilities: knownTenantCapabilities(row.capabilities),
    isDefault: row.is_default,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
  };
}

export const permissionSetService = {
  async getAll(): Promise<PermissionSet[]> {
    const rows = await db('permission_sets')
      .orderBy('is_default', 'desc')
      .orderBy('name', 'asc') as PermissionSetRow[];
    return rows.map(rowToPermissionSet);
  },

  async getBySlug(slug: string): Promise<PermissionSet | null> {
    const row = await db('permission_sets').where({ slug }).first() as PermissionSetRow | undefined;
    return row ? rowToPermissionSet(row) : null;
  },

  async create(data: { name: string; slug: string; capabilities: unknown }): Promise<PermissionSet> {
    const [row] = await switchToIdentity(() => db('permission_sets')
      .insert({
        name: data.name,
        slug: data.slug,
        capabilities: JSON.stringify(knownTenantCapabilities(data.capabilities)),
        is_default: false,
      })
      .returning('*')) as PermissionSetRow[];
    return rowToPermissionSet(row);
  },

  async update(id: number, data: { name?: string; capabilities?: unknown }): Promise<PermissionSet | null> {
    const existing = await db('permission_sets').where({ id }).first() as PermissionSetRow | undefined;
    if (!existing) return null;

    const update: Record<string, unknown> = {};
    if (data.name !== undefined) update.name = data.name;
    if (data.capabilities !== undefined) {
      const caps = knownTenantCapabilities(data.capabilities);
      if (existing.audience === 'client' && caps.some((c) => !CLIENT_SET_CAPABILITIES.includes(c))) {
        throw new AppError(400, `A client set holds only ${CLIENT_SET_CAPABILITIES.join(', ')}`, 'clientSetCapabilities',
          { allowed: [...CLIENT_SET_CAPABILITIES] });
      }
      update.capabilities = JSON.stringify(caps);
    }

    if (Object.keys(update).length > 0) {
      await switchToIdentity(() => db('permission_sets').where({ id }).update(update));
    }

    const row = await db('permission_sets').where({ id }).first() as PermissionSetRow;
    return rowToPermissionSet(row);
  },

  async delete(id: number): Promise<{ success: boolean; error?: string }> {
    const existing = await db('permission_sets').where({ id }).first() as PermissionSetRow | undefined;
    if (!existing) return { success: false, error: 'Permission set not found' };
    if (existing.is_default) return { success: false, error: 'Cannot delete default permission sets' };

    await switchToIdentity(() => db('permission_sets').where({ id }).del());
    return { success: true };
  },

  getAvailableCapabilities(): CapabilityDef[] {
    return TENANT_CAPABILITIES.map((key) => ({ key, label: TENANT_CAPABILITY_LABELS[key] }));
  },
};
