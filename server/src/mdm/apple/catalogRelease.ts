import { createHash } from 'node:crypto';
import { canonicalJson } from '../../audit/canonical';
import { asNone } from '../../db/context';
import { forEachTenant } from '../../db/tenantContext';
import { appConfigService } from '../../services/appConfig.service';
import { logger } from '../../utils/logger';
import { requestTenantResolution } from '../policies/triggers';
import { appleCatalog } from './catalog';
import { COMPILER_VERSION } from './compile';
import { APPLE_OVERLAY, MVP_TYPES } from './overlay';

// =============================================================================
// A new catalog, overlay or compiler resolves every tenant again (docs:
// modele-donnees-mdm §7.3; review of lot B5b, MDM-B5b-C10). What the
// resolution stores (the availability of each key, the artifacts and their
// bodies) was computed with the catalog of the server that ran it: a new
// version of the server that ships another release of the Apple schema,
// another overlay, or another form of the compiled bodies, would otherwise
// leave it as it was until the next change of each tenant. A boot task
// compares the fingerprint of the three with the one kept in app_config
// (mdm_apple_catalog_release) and, when it differs, requests the resolution
// of every tenant that has something to resolve, then stores the new one.
// The published versions do not change: each keeps the release it was
// validated with (schema_release).
// =============================================================================

const KEY = 'mdm_apple_catalog_release';
const ACTOR = { type: 'job' as const, name: 'mdm.catalog-release' };

/** The fingerprint of what the resolution and the compilation depend on, apart from the policies themselves. */
export function catalogFingerprint(): string {
  return createHash('sha256').update(canonicalJson({
    commit: appleCatalog().release.commit, overlay: APPLE_OVERLAY, mvp: [...MVP_TYPES].sort(), compiler: COMPILER_VERSION,
  })).digest('hex');
}

/** The boot task (after jobs.start(): it may enqueue). Returns the number of tenants whose resolution was requested. */
export async function resolveOnCatalogChange(): Promise<number> {
  const current = catalogFingerprint();
  // Platform settings are a catalog: read in any context, written in the identity context by their service.
  const stored = await asNone(ACTOR, () => appConfigService.get(KEY));
  if (stored === current) return 0;
  let requested = 0;
  const { failed } = await forEachTenant(ACTOR, async (tenantId) => {
    if (await requestTenantResolution(null, tenantId)) requested++;
  });
  // Kept only when every tenant was asked: a failure is tried again at the next start.
  if (failed === 0) {
    await asNone(ACTOR, () => appConfigService.set(KEY, current));
  }
  logger.info({ requested, failed, first: stored === null }, 'Apple catalog, overlay or compiler changed: policies resolved again');
  return requested;
}
