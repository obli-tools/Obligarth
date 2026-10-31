import type { Knex } from 'knex';
import { LEGACY_AGENT_POLICY_ARTIFACT_KEY, agentReportStateOf, isAgentPolicyWarning } from '@obligarth/shared';
import { requestComplianceEvaluation } from '../mdm/apple/requests';
import { isCompileError, lockDeviceRows, REMOVED, rollupConfigState, type ArtifactRow } from '../mdm/policies/artifacts';
import type { PolicyReport } from './schemas';

// =============================================================================
// The compliance report of an agent policy (lot PONT-POL §8.4), carried by a
// poll of an agent 1.3.0 or later and checked apart from the poll body (a
// refused report never costs the poll): the device's last report kept in
// legacy_agent_policy_reports (codes and short details, never a secret), then
// the state of its artifact agent:policy when the report is about the desired
// version — applied (Knox items pending their licence and a held-back wipe
// threshold tolerated), delivering (only pending items: downloads, permission,
// order), error (the codes of the failing items) — or removed when the agent
// holds no policy any more and none is desired. A refusal of the policy itself
// (a format the agent does not read, items it cannot parse) puts the artifact
// in error whatever the hash. A changed artifact recomputes the aggregate
// state of the device and asks for its compliance (an artifact in error makes a
// bridge device non-compliant: mdm/compliance/evaluate.ts).
// =============================================================================

const clip = (s: string | undefined, n: number): string | undefined =>
  (s === undefined ? undefined : s.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n));

const sameList = (a: string[], b: string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** The artifact's state and reasons a report about the desired version gives (null: leave it). */
export function artifactStateOf(report: PolicyReport, withheld: boolean): { state: 'applied' | 'delivering' | 'error'; reasons: string[] } {
  // A warning (a network added by the user, AGENT_POLICY_WARNING_CODES) is said in the reasons of an applied policy.
  const items = report.items.filter((i) => !isAgentPolicyWarning(i));
  const failing = items.filter((i) => i.state === 'error' || i.state === 'non_compliant');
  if (failing.length) {
    const reasons = [...new Set(failing.map((i) => `agent:${i.code}`))].slice(0, 10);
    return { state: 'error', reasons };
  }
  const pending = items.filter((i) => i.state === 'pending' && i.code !== 'wipe_withheld');
  if (pending.length) return { state: 'delivering', reasons: [] };
  const reasons: string[] = [];
  if (items.some((i) => i.state === 'pending_licence')) reasons.push('agent:knox_pending');
  if (report.items.some(isAgentPolicyWarning)) reasons.push('agent:wifi_user_network');
  if (withheld || report.items.some((i) => i.code === 'wipe_withheld')) reasons.push('deliver:wipe_withheld');
  return { state: 'applied', reasons };
}

/** The bound of legacy_agent_policy_reports_items_check (octet_length(items::text)), and the bytes the jsonb text form
 *  adds to JSON.stringify per item at most (", " and ": " separators). */
const ITEMS_TEXT_BYTES = 98_304;
const JSONB_TEXT_EXTRA_PER_ITEM = 12;

const itemsTextBytes = (items: unknown[]): number => Buffer.byteLength(JSON.stringify(items), 'utf8') + items.length * JSONB_TEXT_EXTRA_PER_ITEM;

/**
 * Records a valid report of a device (in the poll's transaction, tenant context). `clockOffsetSeconds`: the server time
 * minus the agent's, to set appliedAt on the server's clock. Returns whether the artifact changed, or null when the
 * report is too large for its table even without its details (A3: the poll answers 'rejected', never a 5xx): the zod
 * schema bounds characters, the table bytes (non-ASCII SSIDs and escaped quotes take 2 to 4 bytes each).
 */
export async function recordPolicyReport(trx: Knex.Transaction, tenantId: number, deviceId: number, report: PolicyReport,
  clockOffsetSeconds: number): Promise<boolean | null> {
  const counts = { compliant: 0, non_compliant: 0, pending: 0, pending_licence: 0, unsupported: 0, errors: 0 };
  for (const i of report.items) {
    if (i.state === 'error') counts.errors++;
    else counts[i.state]++;
  }
  let items: Array<{ key: string; state: string; code: string; detail?: string }> = [...report.items].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((i) => ({ key: i.key.slice(0, 160), state: i.state, code: i.code, ...(i.detail !== undefined ? { detail: clip(i.detail, 160) } : {}) }));
  if (itemsTextBytes(items) > ITEMS_TEXT_BYTES) items = items.map(({ detail: _detail, ...rest }) => rest);
  if (itemsTextBytes(items) > ITEMS_TEXT_BYTES) return null;
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const appliedAt = new Date((report.appliedAt + clockOffsetSeconds) * 1000);
  const now = new Date();
  await trx('legacy_agent_policy_reports').insert({
    // The fleet column reads this state: a warning (a network added by the user) leaves the policy applied.
    tenant_id: tenantId, device_id: deviceId, policy_hash: report.hash,
    state: report.state === 'none' ? 'none' : agentReportStateOf(report.items.filter((i) => !isAgentPolicyWarning(i)), true), knox_state: report.knoxState,
    items: JSON.stringify(items), ...counts, applied_at: Number.isFinite(appliedAt.getTime()) ? appliedAt : null, received_at: now,
  }).onConflict(['tenant_id', 'device_id']).merge();

  const row = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: LEGACY_AGENT_POLICY_ARTIFACT_KEY })
    .forUpdate().first() as ArtifactRow | undefined;
  if (!row) return false;
  const where = { tenant_id: tenantId, device_id: deviceId, artifact_key: LEGACY_AGENT_POLICY_ARTIFACT_KEY };
  const desired = row.desired_hash ? String(row.desired_hash).trim() : null;
  const reasonsBefore = (() => { try { const r = typeof row.state_reasons === 'string' ? JSON.parse(row.state_reasons) : row.state_reasons; return Array.isArray(r) ? r.map(String) : []; } catch { return []; } })();
  let changed = false;

  const refusal = report.items.find((i) => i.key === LEGACY_AGENT_POLICY_ARTIFACT_KEY && (i.code === 'policy_version_unsupported' || i.code === 'invalid_item'));
  if (refusal && desired !== null && !isCompileError(row)) {
    const reasons = [refusal.code === 'policy_version_unsupported' ? 'agent:policy_version_unsupported' : 'agent:invalid_items'];
    if (row.state !== 'error' || !sameList(reasonsBefore, reasons)) {
      await trx('device_artifacts').where(where).update({ state: 'error', state_reasons: JSON.stringify(reasons), state_at: now });
      changed = true;
    }
  } else if (desired !== null && report.hash === desired && !isCompileError(row)) {
    const withheld = reasonsBefore.includes('deliver:wipe_withheld');
    const next = artifactStateOf(report, withheld);
    if (row.state !== next.state || !sameList(reasonsBefore, next.reasons) || (row.delivered_hash ?? '').trim() !== desired) {
      await trx('device_artifacts').where(where).update({
        state: next.state, state_reasons: JSON.stringify(next.reasons), state_at: now, delivered_hash: desired,
        ...((row.delivered_hash ?? '').trim() !== desired ? { delivered_at: now } : {}),
      });
      changed = true;
    }
  } else if (desired === null && row.state === 'removing' && report.hash === null) {
    await trx('device_artifacts').where(where).update({ ...REMOVED, state_at: now });
    changed = true;
  }
  if (changed) {
    await rollupConfigState(trx, [deviceId]);
    await requestComplianceEvaluation(trx, tenantId, [deviceId]);
  }
  return changed;
}
