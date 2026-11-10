import { z } from 'zod';
import { registerAuditActions } from '../audit';
import { registerJob } from '../jobs';
import { registerApprovalRequestType } from '../services/approval.service';
import { registerDeviceListFilter } from '../services/deviceListFilters';
import { registerRestrictableActions } from '../services/restriction.service';
import { SITES_APPLY, SITES_RESTRICTABLE_ACTIONS, SITE_WRITE_APPROVAL, executeSiteWrite } from './guard';

// =============================================================================
// The hooks of the sites into the core's registries (lot P1-SITE): their audit actions, the filter of the device list
// (?siteId=<uuid> the devices of a site, ?siteId=none those of no site), the restrictable action sites.apply (floor
// 'sensitive', as the import of per-device values) and its approval request site_write (sites/guard.ts), and the hourly
// purge of the batches (sites.batches-purge). Called once by modules/sites.ts, before the jobs start.
// =============================================================================

declare module '../services/deviceListFilters' {
  interface DeviceListFilters {
    /** A site (uuid), or 'none': the devices of no site (lot P1-SITE). */
    siteId?: string;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let registered = false;

export function registerSites(): void {
  if (registered) return;
  registered = true;
  // 'standard' after the fact: the values of a site are customer data, the entries name their keys, never the values.
  registerAuditActions([
    { name: 'site.created', criticality: 'standard', label: 'Site created' },
    { name: 'site.updated', criticality: 'standard', label: 'Site changed' },
    { name: 'site.archived', criticality: 'standard', label: 'Site archived' },
    { name: 'site.restored', criticality: 'standard', label: 'Site restored' },
    { name: 'site.imported', criticality: 'standard', label: 'Sites imported' },
    { name: 'device.site_changed', criticality: 'standard', label: 'Site of a device changed' },
  ]);
  // A change of what the templates of a site's devices read: a second factor at least; a second person beyond the
  // publication thresholds or at 'restricted'.
  registerRestrictableActions(SITES_RESTRICTABLE_ACTIONS, {}, { [SITES_APPLY]: { level: 'sensitive' } });
  registerApprovalRequestType(SITE_WRITE_APPROVAL, executeSiteWrite, { expiryMinutes: 240 });
  // The batches done with (expired or consumed) go within the hour: the values of the sites they carry with them.
  registerJob({
    name: 'sites.batches-purge',
    scope: 'platform',
    description: 'Purge the batches of site writes expired or consumed (MCP batches, console imports held for approval)',
    payload: z.object({}).strict(),
    schedule: { cron: '23 * * * *' },
    pollSeconds: 60,
    timeoutSeconds: 300,
    handler: async (ctx) => (await import('./batches')).purgeBatchesJob(ctx),
  });
  registerDeviceListFilter({
    key: 'siteId',
    query: z.preprocess((v) => (v === undefined || v === '' ? undefined : String(v).trim().toLowerCase()),
      z.string().refine((v) => v === 'none' || UUID_RE.test(v), 'Invalid site').optional()),
    apply: (q, v) => {
      if (v === 'none') q.whereNull('devices.site_id');
      else q.where('devices.site_id', v);
    },
  });
}
