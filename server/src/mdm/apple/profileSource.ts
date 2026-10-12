import type { Knex } from 'knex';
import type { ProfileSource, ResolvedProfile } from '../../apple/commands/sensitive';
import { AppError } from '../../middleware/errorHandler';
import { vault } from '../../vault';
import { hashOf, loadRenderContext, storedArtifactOf } from './artifacts';
import { appleCatalog } from './catalog';
import { secretRefsOf } from './compile';
import { RAW_SECRET_PURPOSE, profilePlist, renderedHash } from './render';
import { RenderError } from './variables';

// =============================================================================
// The profile source 'policy' of the command bus (docs: modele-donnees-mdm
// §7.9, §7.10; integration-apple-edge §8.8): an InstallProfile whose
// profileRef is '<artifact key>@<desired hash>' is resolved here, per device,
// when the command is written. The artifact must still be the version the
// device wants (a reference to a version no longer desired is refused:
// staleProfileRef, nothing is sent); its variables are rendered for the
// device, its secrets read from the tenant's vault at this very moment and
// written nowhere: the bus encrypts the PayloadContent for the device's
// identity certificate when the profile carries one (containsSecrets), so
// that neither the base nor apple-edge sees a secret in clear.
// A secret is read only when it is a secret of the policies of the tenant
// (purpose policy.*), under the kind of key it was stored for: the typed JSON
// of a raw profile is never taken for a password, nor the reverse.
// Reads only, in the caller's transaction (the tenant's context); no network.
// =============================================================================

export const POLICY_PROFILE_SOURCE = 'policy';

/** '<artifact key>@<hash>': the reference of a version of a profile artifact. */
export const profileRefOf = (artifactKey: string, hash: string): string => `${artifactKey}@${hash}`;

export function parseProfileRef(ref: string): { artifactKey: string; hash: string } | null {
  const m = /^(profile:tools\.obli\.obligarth\.(?:p|raw)\.[A-Za-z0-9._-]{1,140})@([0-9a-f]{64})$/.exec(String(ref));
  return m ? { artifactKey: m[1], hash: m[2] } : null;
}

const refused = (code: string, message: string, status = 422, details?: Record<string, unknown>): never => {
  throw new AppError(status, message, code, details);
};

/** The secrets a profile refers to, read from the tenant's vault (the caller zeroes them once the profile is built). */
async function readSecrets(trx: Knex.Transaction, tenantId: number, ids: string[], raw: boolean): Promise<Map<string, Buffer>> {
  const out = new Map<string, Buffer>();
  if (ids.length === 0) return out;
  const rows = await trx('tenant_secrets').where({ tenant_id: tenantId }).whereIn('id', ids).select('id', 'purpose') as Array<{ id: string; purpose: string }>;
  const purposes = new Map(rows.map((r) => [String(r.id), String(r.purpose)]));
  try {
    for (const id of ids) {
      const purpose = purposes.get(id);
      // Unknown, of another tenant (row level security), or kept for something else than this kind of profile.
      if (!purpose || !purpose.startsWith('policy.') || (purpose === RAW_SECRET_PURPOSE) !== raw) throw new RenderError('secret_unavailable');
      out.set(id, await vault.readTenantSecret(tenantId, id, { trx }));
    }
  } catch (err) {
    // The caller never sees the secrets read before the one that failed: zeroed here.
    for (const b of out.values()) b.fill(0);
    throw err;
  }
  return out;
}

export const policyProfileSource: ProfileSource<Knex.Transaction> = {
  kind: POLICY_PROFILE_SOURCE,
  async resolve(trx, tenantId, ref, device): Promise<ResolvedProfile> {
    const parsed = parseProfileRef(ref);
    if (!parsed) refused('invalidParams', 'Not a reference to a profile of a policy');
    const { artifactKey, hash } = parsed!;
    const wanted = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: device.deviceId, artifact_key: artifactKey })
      .first('desired_hash') as { desired_hash: string | null } | undefined;
    if (!wanted || hashOf(wanted.desired_hash) !== hash) refused('staleProfileRef', 'This version of the profile is no longer the one the device wants', 409);
    const row = await trx('mdm_artifacts').where({ tenant_id: tenantId, hash })
      .first('channel', 'artifact_type', 'identifier', 'body', 'encrypt') as
      { channel: string; artifact_type: string; identifier: string; body: unknown; encrypt: boolean } | undefined;
    if (!row || row.channel !== 'profile' || `profile:${row.identifier}` !== artifactKey) refused('staleProfileRef', 'Unknown profile artifact', 409);
    const artifact = storedArtifactOf(row!);
    const render = await loadRenderContext(trx, tenantId, device.deviceId);
    if (!render) refused('staleProfileRef', 'The device is no longer under management', 409);
    const secrets = new Map<string, Buffer>();
    try {
      const rendered = renderedHash(artifact, render!.vars);
      const raw = artifact.artifactType === 'raw.profile';
      for (const [id, value] of await readSecrets(trx, tenantId, [...secretRefsOf(artifact.body)].sort(), raw)) secrets.set(id, value);
      const profile = profilePlist(artifact, render!.vars, rendered, secrets, appleCatalog());
      return { profile, containsSecrets: artifact.encrypt || secrets.size > 0 };
    } catch (err) {
      // Key and variable names only: never a value.
      if (err instanceof RenderError) refused('profileRenderFailed', 'The profile cannot be rendered for this device', 422, { reason: err.code });
      throw err;
    } finally {
      for (const b of secrets.values()) b.fill(0);
    }
  },
};
