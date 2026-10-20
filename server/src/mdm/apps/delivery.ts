import type { Knex } from 'knex';
import { appArtifactKey } from '@obligarth/shared';
import { db } from '../../db';
import { requestDdmRecompute } from '../../apple/ddm/engine';
import { lockDeviceRows, reasonsOf, rollupConfigState, type ArtifactRow } from '../policies/artifacts';
import { AWAITING_INVENTORY, LICENSE_PENDING, requestManagedAppList } from '../apple/reconcile';
import { requestArtifactReconcile, requestComplianceEvaluation } from '../apple/requests';

// =============================================================================
// The delivery of the apps (docs: modele-donnees-mdm §8.3, §10.3; lot C4):
//   markLicenseReady  the licence of an app is associated for a device: its
//                     artifact leaves license_pending (and 'not_applicable'
//                     license_unavailable) and is delivered (the bus for the
//                     command method, the DDM set for the declaration)
//   licenseTargetsOf  the devices an app goes to, with the licence each needs
//                     (device: serial number; user: Managed Apple Account)
//   applyManagedApps  what a ManagedApplicationList shows (the hook of the
//                     ingestor): an app acknowledged is 'applied' once managed
//                     (Managed), in 'error' on Failed or UserRejected, or still
//                     prompting after 24 hours; an app applied that the list no
//                     longer shows is delivered again (drift_absent)
// For the declaration app.managed, the status of the declaration is the state
// (onDeclarationStatus of the policies provider).
// =============================================================================

/** Licence reasons the gate writes on an app's artifact. */
export const LICENSE_REASONS = [LICENSE_PENDING, 'license_unavailable'] as const;
const PROMPTING_TIMEOUT_MS = 24 * 3600_000;
const FAILED_STATUSES = new Set(['Failed', 'UserRejected', 'ManagementRejected']);

const isLicenseHeld = (r: Pick<ArtifactRow, 'state' | 'state_reasons'>): boolean => {
  const reasons = reasonsOf(r);
  return reasons.some((x) => (LICENSE_REASONS as readonly string[]).includes(x));
};

/** The artifact keys an app identifier goes to (the command and the declaration). */
export const appKeysOf = (identifier: string): string[] => [`app:${identifier}`, appArtifactKey(identifier, true)];

/**
 * markLicenseReady(trx, tenantId, deviceId, identifier): the licence of the app is associated for the device; its
 * artifact is delivered. Locks the device's row (the order of every writer of device_artifacts).
 */
export async function markLicenseReady(trx: Knex.Transaction, tenantId: number, deviceId: number, identifier: string): Promise<void> {
  const keys = appKeysOf(identifier);
  const rows = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('artifact_key', keys).whereNotNull('desired_hash')
    .select('artifact_key', 'state', 'state_reasons') as Array<Pick<ArtifactRow, 'artifact_key' | 'state' | 'state_reasons'>>;
  const held = rows.filter(isLicenseHeld);
  if (held.length === 0) return;
  await lockDeviceRows(trx, tenantId, [deviceId]);
  await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('artifact_key', held.map((r) => r.artifact_key))
    .update({ state: 'pending', state_reasons: '[]', state_at: new Date() });
  await rollupConfigState(trx, [deviceId]);
  if (held.some((r) => r.artifact_key.startsWith('ddm:'))) await requestDdmRecompute(trx, tenantId, { deviceIds: [deviceId] });
  if (held.some((r) => r.artifact_key.startsWith('app:'))) await requestArtifactReconcile(trx, tenantId, [deviceId]);
}

/** licenseTargetsOf(tenantId, appId): the devices the app goes to (a desired artifact of it), with their licence. */
export async function licenseTargetsOf(tenantId: number, appId: number, q: Knex | Knex.Transaction = db): Promise<Array<{ deviceId: number;
  kind: 'device' | 'user'; serialNumber?: string; managedAppleAccount?: string }>> {
  const app = await q('apps').where({ tenant_id: tenantId, id: appId }).first('identifier') as { identifier: string } | undefined;
  if (!app) return [];
  const rows = await q('device_artifacts as x').join('devices as d', function on() { this.on('d.id', 'x.device_id').andOn('d.tenant_id', 'x.tenant_id'); })
    .leftJoin('end_users as u', function on() { this.on('u.id', 'd.end_user_id').andOn('u.tenant_id', 'd.tenant_id'); })
    .where({ 'x.tenant_id': tenantId }).whereIn('x.artifact_key', appKeysOf(app.identifier)).whereNotNull('x.desired_hash')
    .distinct('d.id', 'd.ownership', 'd.serial_number', 'u.managed_apple_account') as
    Array<{ id: number; ownership: string; serial_number: string | null; managed_apple_account: string | null }>;
  return rows.map((r) => (r.ownership === 'personal'
    ? { deviceId: Number(r.id), kind: 'user' as const, ...(r.managed_apple_account ? { managedAppleAccount: r.managed_apple_account } : {}) }
    : { deviceId: Number(r.id), kind: 'device' as const, ...(r.serial_number ? { serialNumber: r.serial_number } : {}) }));
}

/** The hook of the ingestor of ManagedApplicationList (section 8.3, step 3). */
export async function applyManagedApps(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<void> {
  const any = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, channel: 'app' }).whereNotNull('desired_hash')
    .whereIn('state', ['delivering', 'applied']).first('artifact_key');
  if (!any) return;
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const rows = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, channel: 'app' }).whereNotNull('desired_hash')
    .whereIn('state', ['delivering', 'applied']).forUpdate().select('*') as ArtifactRow[];
  if (rows.length === 0) return;
  const identifiers = rows.map((r) => r.artifact_key.slice('app:'.length));
  const apps = new Map((await trx('device_apps').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('identifier', identifiers)
    .select('identifier', 'managed', 'management_status') as Array<{ identifier: string; managed: boolean; management_status: string | null }>)
    .map((a) => [a.identifier, a]));
  const now = new Date();
  let changed = false;
  let again = false;
  for (const row of rows) {
    const a = apps.get(row.artifact_key.slice('app:'.length));
    const awaiting = row.state === 'delivering' && reasonsOf(row).includes(AWAITING_INVENTORY);
    const set = async (u: Record<string, unknown>): Promise<void> => {
      await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: row.artifact_key }).update({ ...u, state_at: now });
      changed = true;
    };
    if (a && a.managed && a.management_status === 'Managed') {
      if (row.state !== 'applied') await set({ state: 'applied', state_reasons: '[]' });
    } else if (a && a.management_status && FAILED_STATUSES.has(a.management_status)) {
      if (row.state !== 'error' || reasonsOf(row).join('|') !== `app:${a.management_status}`) await set({ state: 'error', state_reasons: JSON.stringify([`app:${a.management_status}`]) });
    } else if (awaiting && a?.management_status && /^Prompting/.test(a.management_status)
      && now.getTime() - new Date(row.delivered_at ?? row.state_at).getTime() > PROMPTING_TIMEOUT_MS) {
      await set({ state: 'error', state_reasons: JSON.stringify([`app:${a.management_status}`]) });
    } else if (!a && row.state === 'applied') {
      // Applied, absent now: removed by the user or the device; delivered again.
      await set({ state: 'pending', state_reasons: JSON.stringify(['drift_absent']), desired_at: now });
      again = true;
    }
  }
  if (!changed) return;
  await rollupConfigState(trx, [deviceId]);
  await requestComplianceEvaluation(trx, tenantId, [deviceId]);
  if (again) await requestArtifactReconcile(trx, tenantId, [deviceId]);
}

export { requestManagedAppList };
