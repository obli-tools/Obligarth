import { db } from '../db';
import type { DeviceLicense } from '@obligarth/shared';
import { vault, type SecretLocator } from '../vault';

// Software licenses (dormant: routes not mounted, design §6.1). The license
// key is sealed by the vault (docs: coffre-secrets V9): device_licenses
// .license_key_enc under the DEK of the row's tenant; registered by the
// device module (modules/devices.ts). A future route needs a capability first.

const keyAt = (id: number, tenantId: number): SecretLocator =>
  ({ table: 'device_licenses', column: 'license_key_enc', pk: id, tenantId });

/** Every column but the sealed key (and the inherited clear one). */
const COLUMNS = ['id', 'device_id', 'tenant_id', 'software_name', 'license_type', 'seats', 'expiry_date',
  'vendor', 'notes', 'created_at', 'updated_at'] as const;
const columns = (prefix = ''): string[] => COLUMNS.map((c) => `${prefix}${c}`);

async function rowToLicense(row: any): Promise<DeviceLicense> {
  return {
    id: row.id,
    deviceId: row.device_id,
    tenantId: row.tenant_id,
    softwareName: row.software_name,
    licenseKey: row.license_key_enc
      ? await vault.openString(keyAt(Number(row.id), Number(row.tenant_id)), row.license_key_enc, { requestTenantId: Number(row.tenant_id) })
      : null,
    licenseType: row.license_type,
    seats: row.seats,
    expiryDate: row.expiry_date,
    vendor: row.vendor,
    notes: row.notes,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export const licenseService = {
  async listForDevice(deviceId: number, tenantId: number): Promise<DeviceLicense[]> {
    const rows = await db('device_licenses')
      .where({ device_id: deviceId, tenant_id: tenantId })
      .select([...columns(), 'license_key_enc'])
      .orderBy('software_name');
    return Promise.all(rows.map(rowToLicense));
  },

  async listAll(tenantId: number): Promise<(DeviceLicense & { deviceName: string | null })[]> {
    const rows = await db('device_licenses as dl')
      .join('devices as d', 'd.id', 'dl.device_id')
      .where({ 'dl.tenant_id': tenantId })
      .select(
        ...columns('dl.'),
        'dl.license_key_enc',
        'd.label AS device_name',
      )
      .orderBy('dl.software_name');
    return Promise.all(rows.map(async (r: any) => ({
      ...(await rowToLicense(r)),
      deviceName: r.device_name ?? null,
    })));
  },

  async create(deviceId: number, tenantId: number, data: Partial<DeviceLicense>): Promise<DeviceLicense> {
    return db.transaction(async (trx) => {
      const id = await vault.allocateId('device_licenses', { trx });
      const [row] = await trx('device_licenses').insert({
        id,
        device_id: deviceId,
        tenant_id: tenantId,
        software_name: data.softwareName,
        license_key_enc: data.licenseKey
          ? await vault.seal(keyAt(id, tenantId), data.licenseKey, { trx, requestTenantId: tenantId })
          : null,
        license_type: data.licenseType || null,
        seats: data.seats ?? null,
        expiry_date: data.expiryDate || null,
        vendor: data.vendor || null,
        notes: data.notes || null,
      }).returning([...columns(), 'license_key_enc']);
      return rowToLicense(row);
    });
  },

  async update(id: number, tenantId: number, data: Partial<DeviceLicense>): Promise<DeviceLicense | null> {
    return db.transaction(async (trx) => {
      const cur = await trx('device_licenses').where({ id, tenant_id: tenantId }).forUpdate().first('id', 'tenant_id') as
        { id: number; tenant_id: number } | undefined;
      if (!cur) return null;
      const updates: Record<string, any> = { updated_at: new Date() };
      if (data.softwareName !== undefined) updates.software_name = data.softwareName;
      if (data.licenseKey !== undefined) {
        updates.license_key_enc = data.licenseKey
          ? await vault.seal(keyAt(cur.id, cur.tenant_id), data.licenseKey, { trx, requestTenantId: tenantId })
          : null;
        updates.license_key = null;   // inherited clear column, emptied by the vault's backfill
      }
      if (data.licenseType !== undefined) updates.license_type = data.licenseType;
      if (data.seats !== undefined) updates.seats = data.seats;
      if (data.expiryDate !== undefined) updates.expiry_date = data.expiryDate;
      if (data.vendor !== undefined) updates.vendor = data.vendor;
      if (data.notes !== undefined) updates.notes = data.notes;

      const [row] = await trx('device_licenses')
        .where({ id, tenant_id: tenantId })
        .update(updates)
        .returning([...columns(), 'license_key_enc']);
      return row ? rowToLicense(row) : null;
    });
  },

  async delete(id: number, tenantId: number): Promise<boolean> {
    const count = await db('device_licenses')
      .where({ id, tenant_id: tenantId })
      .delete();
    return count > 0;
  },
};
