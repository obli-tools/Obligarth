import { pbkdf2, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import type { Knex } from 'knex';
import {
  AGENT_WIPE_KEY, LEGACY_AGENT_POLICY_ARTIFACT_KEY, LEGACY_AGENT_POLICY_LIMITS as L, LEGACY_AGENT_POLICY_REPORT_SECONDS,
  type JsonValue,
} from '@obligarth/shared';
import { logger } from '../utils/logger';
import { vault } from '../vault';
import { isCompileError, lockDeviceRows, reasonsOf, rollupConfigState, type ArtifactRow } from '../mdm/policies/artifacts';
import { readStoredPem } from './files';

// =============================================================================
// The delivery of a device's agent policy (lot PONT-POL §8.1, §8.2): the
// compiled body of its artifact agent:policy rendered for one signed answer of
// the poll — the Wi-Fi secrets read from the vault (the tenant's only), the CA
// files inlined from the store, the kiosk PIN replaced by its PBKDF2 hash (the
// clear PIN never leaves the server), the keys the freeze holds back left out
// (a raised wipe threshold, B3). A secret the vault cannot open drops its item
// (`undeliverable`) and marks the answer degraded: its configuration version
// differs, so the agent asks again at its next poll; the artifact is not
// marked delivered meanwhile (deliver:vault_unavailable). A secret that no
// longer exists (or a missing CA file) only drops its item: a lasting state,
// reported by the agent (error/undeliverable), not retried at every poll. The
// result is used for one answer, never logged; only the PIN records are kept
// (10 minutes, per desired hash), never a clear secret.
// =============================================================================

type Obj = Record<string, JsonValue>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The vault failures of the last minute, by secret id (never a value): a degraded poll does not knock again at once. */
const failedReads = new Map<string, number>();

/** A secret of a policy: its value; or `missing` (no such secret of the tenant: a lasting state, the item undeliverable
 *  without a degraded answer, so no retry at every poll); or `failed` (a vault failure: the answer degraded, retried). */
type SecretRead = { value: string } | { missing: true } | { failed: true };

const secretIdOf = (ref: unknown): string | null => {
  const id = isObj(ref) && typeof ref.$secret === 'string' ? ref.$secret.toLowerCase() : null;
  return id && UUID_RE.test(id) ? id : null;
};

async function readSecret(trx: Knex.Transaction, tenantId: number, ref: unknown): Promise<SecretRead> {
  const id = secretIdOf(ref);
  if (!id) return { missing: true };
  const failedAt = failedReads.get(`${tenantId}:${id}`);
  if (failedAt && Date.now() - failedAt < 60_000) return { failed: true };
  // The secret is the tenant's (§4.5): another tenant's id is never read.
  const own = await trx('tenant_secrets').where({ tenant_id: tenantId, id }).first('id');
  if (!own) return { missing: true };
  try {
    const buf = await vault.readTenantSecret(tenantId, id, { trx });
    const value = buf.toString('utf8');
    buf.fill(0);
    failedReads.delete(`${tenantId}:${id}`);
    return { value };
  } catch (err) {
    failedReads.set(`${tenantId}:${id}`, Date.now());
    if (failedReads.size > 10_000) failedReads.delete(failedReads.keys().next().value as string);
    logger.error({ tenantId, code: (err as { code?: unknown })?.code }, 'legacy agent: a secret of a policy cannot be opened');
    return { failed: true };
  }
}

const pbkdf2Async = promisify(pbkdf2);

type PinRecord = { alg: 'pbkdf2-sha256'; iterations: number; salt: string; hash: string };

/** The PBKDF2-HMAC-SHA256 record of a kiosk PIN (§8.2): the agent verifies a typed PIN against it. Off the event loop
 *  (the thread pool of libuv): 20,000 iterations per full configuration would otherwise stall every tenant's requests. */
export async function pinRecord(pin: string): Promise<PinRecord> {
  const salt = randomBytes(16);
  const pinBuf = Buffer.from(pin, 'utf8');
  try {
    const hash = await pbkdf2Async(pinBuf, salt, L.pinIterations, 32, 'sha256');
    return { alg: 'pbkdf2-sha256', iterations: L.pinIterations, salt: salt.toString('base64'), hash: hash.toString('base64') };
  } finally {
    pinBuf.fill(0);
  }
}

/** The PIN records already computed, per tenant, secret id and desired hash (a stable salt per hash is enough: the
 *  record is what the agent stores anyway), 10 minutes: a publish touching many kiosk devices, or a degraded answer
 *  rebuilt at every poll, neither hashes nor reads the vault again. Never the clear PIN. */
const pinRecords = new Map<string, { at: number; record: PinRecord }>();
const PIN_RECORD_TTL_MS = 600_000;

async function kioskPinRecord(trx: Knex.Transaction, tenantId: number, desiredHash: string, ref: unknown): Promise<PinRecord | 'missing' | 'failed'> {
  const id = secretIdOf(ref);
  const k = id ? `${tenantId}:${id}:${desiredHash}` : null;
  const hit = k ? pinRecords.get(k) : undefined;
  if (hit && Date.now() - hit.at < PIN_RECORD_TTL_MS) return hit.record;
  const r = await readSecret(trx, tenantId, ref);
  if ('missing' in r) return 'missing';
  if ('failed' in r) return 'failed';
  const record = await pinRecord(r.value);
  if (k) {
    pinRecords.set(k, { at: Date.now(), record });
    if (pinRecords.size > 20_000) pinRecords.delete(pinRecords.keys().next().value as string);
  }
  return record;
}

export interface RenderedPolicy { policy: Obj; degraded: boolean; withheld: string[] }

/**
 * The policy delivered to the agent from the compiled body (a copy: the body is never changed): hash and report period
 * added, secrets opened, CA files inlined, the PIN hashed, `withhold` applied.
 */
export async function renderAgentPolicy(trx: Knex.Transaction, tenantId: number, deviceId: number, desiredHash: string, body: unknown,
  o: { withhold: string[] }): Promise<RenderedPolicy> {
  const src = (isObj(body) ? JSON.parse(JSON.stringify(body)) : {}) as Obj;
  const undeliverable: string[] = [];
  let degraded = false;
  const policy: Obj = { ...src, hash: desiredHash, reportSeconds: LEGACY_AGENT_POLICY_REPORT_SECONDS };
  const wifi: Obj[] = [];
  for (const w of (Array.isArray(src.wifi) ? src.wifi : []) as Obj[]) {
    const out: Obj = { ...w };
    // ok, or why not: 'failed' (a vault failure: degraded, retried) or 'missing' (lasting: undeliverable only).
    let failure: 'failed' | 'missing' | null = null;
    if (w.psk !== undefined) {
      const v = await readSecret(trx, tenantId, w.psk);
      if ('value' in v) out.psk = v.value; else failure = 'failed' in v ? 'failed' : 'missing';
    }
    if (!failure && isObj(w.eap)) {
      const eap: Obj = { ...w.eap };
      const pw = await readSecret(trx, tenantId, eap.password);
      if ('value' in pw) eap.password = pw.value; else failure = 'failed' in pw ? 'failed' : 'missing';
      if (!failure && isObj(eap.caFile)) {
        const pem = await readStoredPem(tenantId, String(eap.caFile.sha256), Number(eap.caFile.size));
        if (pem === null) failure = 'missing'; else { eap.caPem = pem; delete eap.caFile; }
      }
      out.eap = eap;
    }
    if (!failure) wifi.push(out);
    else { undeliverable.push(String(w.key)); if (failure === 'failed') degraded = true; }
  }
  policy.wifi = wifi;
  if (isObj(src.kiosk)) {
    const pin = await kioskPinRecord(trx, tenantId, desiredHash, src.kiosk.exitPin);
    if (pin === 'failed' || pin === 'missing') {
      policy.kiosk = null;
      undeliverable.push(String(src.kiosk.key));
      if (pin === 'failed') degraded = true;
    } else policy.kiosk = { ...src.kiosk, exitPin: pin };
  }
  const withheld: string[] = [];
  if (o.withhold.length && Array.isArray(src.dpm)) {
    policy.dpm = (src.dpm as Obj[]).filter((d) => {
      if (o.withhold.includes(String(d.key))) { withheld.push(String(d.key)); return false; }
      return true;
    });
  }
  policy.undeliverable = undeliverable.sort();
  policy.withheld = withheld;
  logger.debug({ tenantId, deviceId, keys: Object.keys((src.keys as Obj) ?? {}).length, undeliverable: undeliverable.length }, 'legacy agent: policy rendered');
  return { policy, degraded, withheld };
}

/** The wipe threshold of a compiled body (0 when absent). */
function wipeOf(body: unknown): number {
  const list = isObj(body) && Array.isArray(body.dpm) ? body.dpm as Obj[] : [];
  const v = list.find((d) => d.key === AGENT_WIPE_KEY)?.value;
  return typeof v === 'number' ? v : 0;
}

/**
 * What the freeze holds back from this delivery (B3): the wipe threshold when it is added or raised against what the
 * device last held (the body of its last report's hash, else of the delivered hash). When that reference is the very
 * body being delivered, it was (or may have been) delivered held back already: the device holds the threshold only if
 * its report of this hash says it is applied (compliant); otherwise it stays held back, which the agent reads as "keep
 * what you have" (§10.2), so a configuration rebuilt during the freeze never lets it through.
 */
export async function frozenWithhold(trx: Knex.Transaction, tenantId: number, deviceId: number, body: unknown,
  row: Pick<ArtifactRow, 'delivered_hash' | 'desired_hash'>): Promise<string[]> {
  const now = wipeOf(body);
  if (now <= 0) return [];
  const report = await trx('legacy_agent_policy_reports').where({ tenant_id: tenantId, device_id: deviceId }).first('policy_hash', 'items') as
    { policy_hash: string | null; items: unknown } | undefined;
  const reportHash = report?.policy_hash ? String(report.policy_hash).trim() : null;
  const ref = reportHash ?? (row.delivered_hash ? String(row.delivered_hash).trim() : null);
  const desired = row.desired_hash ? String(row.desired_hash).trim() : null;
  if (ref !== null && ref === desired) {
    if (reportHash !== desired) return [AGENT_WIPE_KEY];
    const items = (typeof report!.items === 'string' ? JSON.parse(report!.items) : report!.items) as unknown;
    const applied = Array.isArray(items) && items.some((i) => isObj(i) && i.key === AGENT_WIPE_KEY && i.state === 'compliant');
    return applied ? [] : [AGENT_WIPE_KEY];
  }
  let before = 0;
  if (ref) {
    const prev = await trx('mdm_artifacts').where({ tenant_id: tenantId, hash: ref }).first('body') as { body: unknown } | undefined;
    before = prev ? wipeOf(typeof prev.body === 'string' ? JSON.parse(prev.body) : prev.body) : 0;
  }
  return now > before ? [AGENT_WIPE_KEY] : [];
}

/** The state of the device's artifact agent:policy (null when none is desired). */
export async function policyArtifactRow(q: Knex | Knex.Transaction, tenantId: number, deviceId: number): Promise<ArtifactRow | null> {
  const r = await q('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: LEGACY_AGENT_POLICY_ARTIFACT_KEY })
    .first() as ArtifactRow | undefined;
  return r ?? null;
}

const VAULT_UNAVAILABLE = 'deliver:vault_unavailable';

/**
 * The policy delivered in full (the answer carried it under its hash): the artifact is 'delivering' (§8.1) when it was
 * pending, or in error for a reason of the delivery (deliver:*) or for another hash. An error the agent reported about
 * this very hash (agent:* reasons) stays: a configuration rebuilt for another cause (freeze, Knox key, settings,
 * policy.reapply) does not hide it, and the agent's next report about this hash sets the state again.
 */
export async function markPolicyDelivered(trx: Knex.Transaction, tenantId: number, deviceId: number, hash: string): Promise<boolean> {
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const where = { tenant_id: tenantId, device_id: deviceId, artifact_key: LEGACY_AGENT_POLICY_ARTIFACT_KEY };
  const row = await trx('device_artifacts').where(where).forUpdate().first() as ArtifactRow | undefined;
  if (!row || (row.desired_hash ?? '').trim() !== hash || isCompileError(row)) return false;
  const reasons = reasonsOf(row);
  const sameHash = (row.delivered_hash ?? '').trim() === hash;
  if (row.state === 'delivering' && reasons.includes(VAULT_UNAVAILABLE)) {
    // The degraded answers are over: their reason goes.
    await trx('device_artifacts').where(where).update({ state_reasons: JSON.stringify(reasons.filter((r) => r !== VAULT_UNAVAILABLE)), state_at: new Date() });
    await rollupConfigState(trx, [deviceId]);
    return true;
  }
  const deliveryError = row.state === 'error' && (!sameHash || reasons.every((r) => r.startsWith('deliver:')));
  if (row.state !== 'pending' && !deliveryError) return false;
  await trx('device_artifacts').where(where)
    .update({ state: 'delivering', delivered_hash: hash, delivered_at: new Date(), state_reasons: '[]', state_at: new Date() });
  await rollupConfigState(trx, [deviceId]);
  return true;
}

/** A degraded answer (a secret of the policy the vault could not open): the reason added to the artifact's, once; the
 *  reasons the agent reported stay. */
export async function markPolicyUndeliverable(trx: Knex.Transaction, tenantId: number, deviceId: number): Promise<boolean> {
  const row = await policyArtifactRow(trx, tenantId, deviceId);
  if (!row || row.desired_hash === null || isCompileError(row)) return false;
  const reasons = reasonsOf(row);
  if (reasons.includes(VAULT_UNAVAILABLE)) return false;
  await lockDeviceRows(trx, tenantId, [deviceId]);
  const n = await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: LEGACY_AGENT_POLICY_ARTIFACT_KEY })
    .whereNotNull('desired_hash')
    .update({ state_reasons: JSON.stringify([...reasons.slice(0, 9), VAULT_UNAVAILABLE]), state_at: new Date() });
  if (n > 0) await rollupConfigState(trx, [deviceId]);
  return n > 0;
}
