import { db } from '../db';
import type { HardwareInventory, SoftwareEntry } from '@obliance/shared';

class InventoryService {
  async getHardware(deviceId: number): Promise<HardwareInventory | null> {
    const row = await db('device_inventory_hardware')
      .where({ device_id: deviceId })
      .orderBy('scanned_at', 'desc')
      .first();
    if (!row) return null;
    return {
      id: row.id, deviceId: row.device_id,
      cpu: row.cpu || {}, memory: row.memory || {},
      disks: row.disks || [], networkInterfaces: row.network_interfaces || [],
      gpu: row.gpu || [], motherboard: row.motherboard || {},
      bios: row.bios || {},
      os: row.os || undefined,
      battery: row.battery || undefined,
      bitlocker: row.bitlocker || [],
      printers: row.printers || [],
      comPorts: row.com_ports || [],
      raw: row.raw || {},
      scannedAt: row.scanned_at,
    };
  }

  async getSoftware(deviceId: number, search?: string): Promise<SoftwareEntry[]> {
    let q = db('device_inventory_software')
      .where({ device_id: deviceId })
      .orderBy('scanned_at', 'desc');

    if (search) q = q.whereILike('name', `%${search}%`);

    const rows = await q;
    return rows.map((r: any) => ({
      id: r.id, deviceId: r.device_id, name: r.name, version: r.version,
      publisher: r.publisher, installDate: r.install_date,
      installLocation: r.install_location, source: r.source,
      packageId: r.package_id, scannedAt: r.scanned_at,
    }));
  }
}

export const inventoryService = new InventoryService();
