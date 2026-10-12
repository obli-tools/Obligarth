import type { Knex } from 'knex';
import type { DeclarationProvider, DeclarationSpec } from '../../apple/ddm/engine';
import type { DeclarationStatus } from '../../apple/ddm/report';
import {
  REMOVED, hashOf, isCompileError, loadRenderContext, lockDeviceRows, reasonsOf, rollupConfigState, storedArtifactOf, type ArtifactRow,
} from './artifacts';
import { declarationPayload } from './render';
import { requestComplianceEvaluation } from './requests';
import { RenderError, type VariableValues } from './variables';

// =============================================================================
// The declaration provider of the policies (docs: modele-donnees-mdm §7.10;
// integration-apple-edge §9.2): the 'ddm' artifacts a device wants become its
// configurations, under identifiers obg.cfg.pol-…, with one simple activation
// (obg.act.pol-standard) that cites them all, sorted. Nothing without a
// configuration. Pure reads in the engine's transaction, no network: the
// artifacts of the device, their bodies, and the facts of the device only when
// a body holds a variable. An artifact in error at its compilation, or whose
// variable has no value any more, is not served (the next resolution finds it
// not applicable).
// The engine sets aside a declaration type the device did not announce, and
// prunes the activation accordingly.
//
// The status the device reports for its declarations (management.declarations)
// is the state of these artifacts (onDeclarationStatus, a hook of the status
// channel, in the transaction of the report): active and valid under the
// server-token of the desired version: applied; invalid: error, with the
// device's reason codes; a declaration withdrawn from the set and absent from
// the report: removed.
// =============================================================================

export const POLICIES_PROVIDER = 'policies';
export const POLICIES_ACTIVATION = 'obg.act.pol-standard';
const SIMPLE_ACTIVATION = 'com.apple.activation.simple';

interface DesiredRow {
  artifact_key: string;
  state: ArtifactRow['state'];
  state_reasons: unknown;
  channel: string;
  artifact_type: string;
  identifier: string;
  body: unknown;
  has_variables: boolean;
  encrypt: boolean;
}

/** The 'ddm' artifacts a device wants, with their bodies (device_artifacts and mdm_artifacts). */
export async function desiredDdmArtifacts(trx: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<DesiredRow[]> {
  const rows = await trx('device_artifacts as x')
    .join('mdm_artifacts as m', function joinBody() { this.on('m.tenant_id', '=', 'x.tenant_id').andOn('m.hash', '=', 'x.desired_hash'); })
    .where({ 'x.tenant_id': tenantId, 'x.device_id': deviceId, 'x.channel': 'ddm' }).whereNotNull('x.desired_hash')
    .orderBy('x.artifact_key')
    .select('x.artifact_key', 'x.state', 'x.state_reasons', 'm.channel', 'm.artifact_type', 'm.identifier', 'm.body', 'm.has_variables', 'm.encrypt') as DesiredRow[];
  return rows.filter((r) => r.channel === 'ddm' && !isCompileError(r));
}

export const policiesDeclarationProvider: DeclarationProvider = {
  name: POLICIES_PROVIDER,
  owns: /^obg\.(cfg|act)\.pol-/,
  async declarationsFor(trx, ctx): Promise<DeclarationSpec[]> {
    const rows = await desiredDdmArtifacts(trx, ctx.tenantId, ctx.deviceId);
    if (rows.length === 0) return [];
    let vars: VariableValues = {};
    if (rows.some((r) => r.has_variables)) {
      const render = await loadRenderContext(trx, ctx.tenantId, ctx.deviceId);
      if (!render) return [];
      vars = render.vars;
    }
    const configurations: DeclarationSpec[] = [];
    for (const r of rows) {
      const a = storedArtifactOf(r);
      try {
        configurations.push({ family: 'configuration', identifier: a.identifier, type: a.artifactType, payload: declarationPayload(a, vars) });
      } catch (err) {
        // A variable lost its value since the resolution, or a value has no JSON form: not served.
        if (!(err instanceof RenderError)) throw err;
      }
    }
    if (configurations.length === 0) return [];
    return [...configurations, {
      family: 'activation', identifier: POLICIES_ACTIVATION, type: SIMPLE_ACTIVATION,
      payload: { StandardConfigurations: configurations.map((c) => c.identifier).sort() },
    }];
  },
};

/** The reason codes of a declaration status: the device's codes (bounded, of a plain alphabet), never its texts. */
export function reasonCodes(reasons: unknown[] | null): string[] {
  const out: string[] = [];
  for (const r of reasons ?? []) {
    const code = r && typeof r === 'object' && !Array.isArray(r) ? (r as Record<string, unknown>).code : null;
    if (typeof code === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/.test(code) && !out.includes(code)) out.push(code);
    if (out.length >= 10) break;
  }
  return out.length ? out : ['Error.Unknown'];
}

/**
 * onDeclarationStatus(trx, tenantId, deviceId, statuses): the state of the 'ddm' artifacts of the device from its
 * report (section 7.10). The status channel holds the device's row; the artifacts' rows are locked here.
 */
export async function onDeclarationStatus(trx: Knex.Transaction, tenantId: number, deviceId: number, statuses: DeclarationStatus[]): Promise<void> {
  const any = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, channel: 'ddm' }).first('artifact_key');
  if (!any) return;
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const rows = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, channel: 'ddm' })
    .orderBy('artifact_key').forUpdate().select('*') as ArtifactRow[];
  const reported = new Map(statuses.filter((s) => s.family === 'configuration').map((s) => [s.identifier, s]));
  const now = new Date();
  let changed = false;
  const set = async (row: ArtifactRow, update: Record<string, unknown>): Promise<void> => {
    await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: row.artifact_key }).update({ ...update, state_at: now });
    changed = true;
  };
  for (const row of rows) {
    const identifier = row.artifact_key.slice('ddm:'.length);
    const s = reported.get(identifier);
    if (row.desired_hash === null) {
      // Withdrawn from the set: gone once the device no longer reports it.
      if (row.state === 'removing' && !s) await set(row, { ...REMOVED });
      continue;
    }
    if (isCompileError(row)) continue;
    const rendered = hashOf(row.rendered_hash);
    if (!s) {
      // Reported applied before, absent now: the device no longer holds it.
      if (row.state === 'applied') await set(row, { state: 'pending', state_reasons: JSON.stringify(['not_reported']) });
      continue;
    }
    // A status under another server-token is that of the version the device still holds: the desired one is pending.
    const current = rendered !== null && s.serverToken === rendered;
    if (!current) {
      if (row.state === 'applied') await set(row, { state: 'pending', state_reasons: '[]' });
      continue;
    }
    if (s.valid === 'valid' && s.active === true) {
      if (row.state !== 'applied' || hashOf(row.delivered_hash) !== rendered) {
        await set(row, { state: 'applied', state_reasons: '[]', delivered_hash: rendered, delivered_at: now });
      }
    } else if (s.valid === 'invalid') {
      const codes = reasonCodes(s.reasons);
      if (row.state !== 'error' || codes.join('|') !== reasonsOf(row).join('|')) {
        await set(row, { state: 'error', state_reasons: JSON.stringify(codes) });
      }
    }
    // valid 'unknown', or valid but not active yet: unchanged.
  }
  if (!changed) return;
  await rollupConfigState(trx, [deviceId]);
  await requestComplianceEvaluation(trx, tenantId, [deviceId]);
}
