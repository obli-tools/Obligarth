// Junction of the Android module with the common code (lot AN-A2; android-amapi §3.4, §15.2): the hooks the lots
// AN-C1b to AN-F2 left for the junction, plugged once by registerAndroidModule, without I/O.
//   - part 3b applied (migration android_junction): the core reasons missing_in_provider and presumed_gone are
//     written as they are (setCoreReasonsWidened);
//   - the public base of the device surface (https://mdm.<domain>, APPLE_MDM_PUBLIC_BASE of lot C) for the links of
//     the BYOD invitations and the sign-in URL;
//   - mdmStaleAfterDays of the tenant (setting of the MDM data model) for the presumed exits of the reconciliation.
// Left to their defaults on purpose: the key resolver of the surfaces (the registry of lot C, appleTenants), the
// notice of a personal device (the generated notice of USR-01 since P0-13 T5, installed by registerPrivacyModule, not
// here), the mail channel (the rules of lot C),
// the quota of the project and the limit of a tenant (no platform setting yet: nothing refused, nothing alerted).
import { SETTINGS_KEYS } from '@obligarth/shared';
import { config } from '../config';
import { db } from '../db';
import { setCoreReasonsWidened } from './operations/exit';
import { setStaleDaysSource } from './operations/reconcile';
import { setByodSurfaceBase } from './routes/byod.routes';
import { setSigninSurfaceBase } from './signin/config';

/** mdmStaleAfterDays of a tenant (1 to 90 days, as the common evaluator reads it); null: the module's default. */
export async function tenantStaleDays(tenantId: number): Promise<number | null> {
  const row = await db('settings').where({ tenant_id: tenantId, scope: 'global', key: SETTINGS_KEYS.MDM_STALE_AFTER_DAYS })
    .whereNull('scope_id').first('value') as { value: unknown } | undefined;
  const n = typeof row?.value === 'number' ? row.value : typeof row?.value === 'string' ? Number(row.value) : NaN;
  return Number.isInteger(n) && n >= 1 && n <= 90 ? n : null;
}

let plugged = false;

export function plugAndroidJunction(): void {
  if (plugged) return;
  plugged = true;
  setCoreReasonsWidened(true);
  const surfaceBase = (): string | null => config.apple.mdmPublicBase ?? null;
  setByodSurfaceBase(surfaceBase);
  setSigninSurfaceBase(surfaceBase);
  setStaleDaysSource((tenantId) => tenantStaleDays(tenantId));
}
