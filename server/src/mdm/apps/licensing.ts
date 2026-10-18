import type { Knex } from 'knex';
import { requestDdmRecompute } from '../../apple/ddm/engine';
import { requestAssets, requestUsers, type VppOperationView } from '../../apple/integrations/vpp.service';
import { lockDeviceRows, reasonsOf, rollupConfigState } from '../apple/artifacts';
import { LICENSE_PENDING } from '../apple/reconcile';
import { requestArtifactReconcile } from '../apple/requests';
import { LICENSE_REASONS } from './delivery';
import { clientUserIdOf, licenseOfBody, type LicenseKind } from './licenseRules';

// =============================================================================
// The licences of the apps (docs: modele-donnees-mdm §8.3 step 1; integration
// §11.3, I17; APP-01, APP-02 at the MVP): the decision of associating a
// licence, which the specification of the applications will refine. At the
// MVP every app of the catalog is licensed by Apps and Books ('vpp'):
//   device licence (serial number)  corporate and corporate_personal devices;
//   user licence (clientUserId)     personal devices: the end user's Managed
//                                   Apple Account, created at Apple first
//                                   (users_create), clientUserId 'obg-<uuid>'
//                                   of the end user (never a name);
// The gate (registered with the writer of the artifacts) looks at each app
// artifact a device wants, not yet delivered:
//   licence associated              ready: delivered (markLicenseReady's work)
//   association in progress         'pending' with license_pending
//   a licence available             association asked of Apps and Books (an
//                                   operation in the same transaction), then
//                                   license_pending
//   none                            'not_applicable' with license_unavailable
// The end of an operation (onOperationFinal), a synchronisation of a token
// (new licences) and the end of a user's creation run the gate again for the
// devices concerned. A licence goes back to the pool when the app leaves the
// device (RemoveApplication acknowledged) and when the device leaves
// management (devices.unenroll-cleanup); the hourly synchronisation gives back
// what a lost job left on a device no longer managed.
// =============================================================================

export const LICENSING_REF = 'job:mdm.apps-licensing';
/** An association that failed is asked again this long after, at the earliest. */
const FAILED_RETRY_MS = 3600_000;
const APP_KEY_LIKE = ["app:%", "ddm:obg.cfg.pol-app.managed.%"];

type Decision = 'ready' | 'pending' | 'unavailable';

interface GateRow { device_id: number; artifact_key: string; state: string; state_reasons: unknown; body: unknown }

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});

export { clientUserIdOf, licenseOfBody };

/**
 * The licence gate of the apps (section 8.3, step 1), in the caller's transaction, for the devices given. Locks their
 * rows (the order of every writer of device_artifacts).
 */
export async function licenseGate(trx: Knex.Transaction, tenantId: number, deviceIds: number[]): Promise<void> {
  const ids = [...new Set(deviceIds)].filter((n) => Number.isSafeInteger(n) && n > 0);
  if (ids.length === 0) return;
  const rows = await trx('device_artifacts as x')
    .join('mdm_artifacts as m', function on() { this.on('m.tenant_id', 'x.tenant_id').andOn('m.hash', 'x.desired_hash'); })
    .where({ 'x.tenant_id': tenantId }).whereIn('x.device_id', ids).whereNotNull('x.desired_hash')
    // 'not_applicable' for want of a licence only (a refusal of the bus — ownership, supervision — is not the gate's).
    .where((w) => w.where('x.state', 'pending').orWhere((v) => v.where('x.state', 'not_applicable').whereRaw("jsonb_exists(x.state_reasons, 'license_unavailable')")))
    .where((w) => { for (const l of APP_KEY_LIKE) w.orWhere('x.artifact_key', 'like', l); })
    .select('x.device_id', 'x.artifact_key', 'x.state', 'x.state_reasons', 'm.body') as GateRow[];
  if (rows.length === 0) return;
  await lockDeviceRows(trx, tenantId, [...new Set(rows.map((r) => Number(r.device_id)))]);
  const devices = new Map((await trx('devices as d')
    .leftJoin('end_users as u', function on() { this.on('u.id', 'd.end_user_id').andOn('u.tenant_id', 'd.tenant_id'); })
    .where({ 'd.tenant_id': tenantId }).whereIn('d.id', [...new Set(rows.map((r) => Number(r.device_id)))])
    .select('d.id', 'd.serial_number', 'd.ownership', 'u.uuid as user_uuid', 'u.managed_apple_account', 'u.status as user_status') as
    Array<{ id: number; serial_number: string | null; ownership: string; user_uuid: string | null; managed_apple_account: string | null; user_status: string | null }>)
    .map((d) => [Number(d.id), d]));

  // What each row needs.
  interface Need { row: GateRow; storeId: string | null; kind: LicenseKind; serial: string | null; cuid: string | null; maa: string | null }
  const needs: Need[] = rows.map((row) => {
    const l = licenseOfBody(row.artifact_key, row.body);
    const d = devices.get(Number(row.device_id));
    const serial = l.kind === 'device' && d?.serial_number && /^[A-Za-z0-9-]{1,64}$/.test(d.serial_number) ? d.serial_number : null;
    const userOk = l.kind === 'user' && d?.user_uuid && d.managed_apple_account && d.user_status !== 'departed';
    return { row, storeId: l.storeId, kind: l.kind, serial, cuid: userOk ? clientUserIdOf(d!.user_uuid!) : null, maa: userOk ? d!.managed_apple_account : null };
  });
  const storeIds = [...new Set(needs.map((n) => n.storeId).filter((s): s is string => !!s))];
  const serials = [...new Set(needs.map((n) => n.serial).filter((s): s is string => !!s))];
  const cuids = [...new Set(needs.map((n) => n.cuid).filter((s): s is string => !!s))];

  const assignments = storeIds.length && (serials.length || cuids.length) ? await trx('vpp_assignments as v')
    .join('tenant_apple_vpp_tokens as t', function on() { this.on('t.id', 'v.vpp_token_id').andOn('t.tenant_id', 'v.tenant_id'); })
    .where({ 'v.tenant_id': tenantId }).whereNot('t.state', 'removed').whereIn('v.adam_id', storeIds)
    .where((w) => { if (serials.length) w.orWhereIn('v.serial_number', serials); if (cuids.length) w.orWhereIn('v.client_user_id', cuids); })
    .select('v.adam_id', 'v.serial_number', 'v.client_user_id', 'v.state', 'v.updated_at', 'v.vpp_token_id') as
    Array<{ adam_id: string; serial_number: string | null; client_user_id: string | null; state: string; updated_at: Date; vpp_token_id: string }> : [];
  const assignmentOf = new Map<string, { state: string; updatedAt: number }>();
  const rank: Record<string, number> = { associated: 3, associating: 2, disassociating: 1, failed: 0 };
  for (const a of assignments) {
    const k = `${a.adam_id}|${a.serial_number ?? ''}|${a.client_user_id ?? ''}`;
    const cur = assignmentOf.get(k);
    if (!cur || (rank[a.state] ?? 0) > (rank[cur.state] ?? 0)) assignmentOf.set(k, { state: a.state, updatedAt: new Date(a.updated_at).getTime() });
  }
  // The licences available, per active token (minus the associations in progress).
  const assets = storeIds.length ? await trx('vpp_assets as a')
    .join('tenant_apple_vpp_tokens as t', function on() { this.on('t.id', 'a.vpp_token_id').andOn('t.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 't.state': 'active' }).whereIn('a.adam_id', storeIds)
    .select('a.vpp_token_id', 'a.adam_id', 'a.pricing_param', 'a.device_assignable', 'a.available_count') as
    Array<{ vpp_token_id: string; adam_id: string; pricing_param: string; device_assignable: boolean; available_count: number }> : [];
  const inFlight = storeIds.length ? new Map((await trx('vpp_assignments').where({ tenant_id: tenantId, state: 'associating' }).whereIn('adam_id', storeIds)
    .groupBy('vpp_token_id', 'adam_id').select('vpp_token_id', 'adam_id').count({ n: '*' }) as Array<{ vpp_token_id: string; adam_id: string; n: string | number }>)
    .map((x) => [`${x.vpp_token_id}|${x.adam_id}`, Number(x.n)])) : new Map<string, number>();
  const remaining = new Map(assets.map((a) => [`${a.vpp_token_id}|${a.adam_id}|${a.pricing_param}`,
    Number(a.available_count) - (inFlight.get(`${a.vpp_token_id}|${a.adam_id}`) ?? 0)]));
  const pick = (storeId: string, kind: LicenseKind): { tokenId: string; pricingParam: string } | null => {
    let best: { tokenId: string; pricingParam: string; left: number } | null = null;
    for (const a of assets) {
      if (a.adam_id !== storeId || (kind === 'device' && !a.device_assignable)) continue;
      const left = remaining.get(`${a.vpp_token_id}|${a.adam_id}|${a.pricing_param}`) ?? 0;
      if (left > 0 && (!best || left > best.left)) best = { tokenId: a.vpp_token_id, pricingParam: a.pricing_param, left };
    }
    if (!best) return null;
    remaining.set(`${best.tokenId}|${storeId}|${best.pricingParam}`, best.left - 1);
    return best;
  };
  // The users created at Apple (personal devices), per token.
  const createdUsers = new Set<string>();
  const creatingUsers = new Set<string>();
  if (cuids.length) {
    const ops = await trx('vpp_operations').where({ tenant_id: tenantId, kind: 'users_create' }).whereIn('state', ['requested', 'pending', 'complete'])
      .select('vpp_token_id', 'state', 'request') as Array<{ vpp_token_id: string; state: string; request: unknown }>;
    for (const op of ops) {
      const users = obj(op.request).users;
      for (const u of Array.isArray(users) ? users : []) {
        const cu = obj(u).clientUserId;
        if (typeof cu !== 'string') continue;
        (op.state === 'complete' ? createdUsers : creatingUsers).add(`${op.vpp_token_id}|${cu}`);
      }
    }
  }

  const associate = new Map<string, { tokenId: string; adamId: string; pricingParam: string; serials: Set<string>; cuids: Set<string>; deviceOfSerial: Map<string, number> }>();
  const createUsers = new Map<string, Map<string, string>>();
  const decide = (n: Need): Decision => {
    if (!n.storeId || (n.kind === 'device' ? !n.serial : !n.cuid)) return 'unavailable';
    const a = assignmentOf.get(`${n.storeId}|${n.serial ?? ''}|${n.cuid ?? ''}`);
    if (a?.state === 'associated') return 'ready';
    if (a?.state === 'associating') return 'pending';
    if (a?.state === 'failed' && Date.now() - a.updatedAt < FAILED_RETRY_MS) return 'unavailable';
    const p = pick(n.storeId, n.kind);
    if (!p) return 'unavailable';
    if (n.kind === 'user') {
      const k = `${p.tokenId}|${n.cuid}`;
      if (!createdUsers.has(k)) {
        if (!creatingUsers.has(k)) {
          const m = createUsers.get(p.tokenId) ?? new Map<string, string>();
          m.set(n.cuid!, n.maa!);
          createUsers.set(p.tokenId, m);
          creatingUsers.add(k);
        }
        return 'pending';
      }
    }
    const key = `${p.tokenId}|${n.storeId}|${p.pricingParam}`;
    const g = associate.get(key) ?? { tokenId: p.tokenId, adamId: n.storeId, pricingParam: p.pricingParam, serials: new Set(), cuids: new Set(), deviceOfSerial: new Map() };
    if (n.serial) { g.serials.add(n.serial); g.deviceOfSerial.set(n.serial, Number(n.row.device_id)); }
    if (n.cuid) g.cuids.add(n.cuid);
    associate.set(key, g);
    // The same target of the same app counted once.
    assignmentOf.set(`${n.storeId}|${n.serial ?? ''}|${n.cuid ?? ''}`, { state: 'associating', updatedAt: Date.now() });
    return 'pending';
  };

  const now = new Date();
  const changed = new Set<number>();
  const readyCommand = new Set<number>();
  const readyDdm = new Set<number>();
  for (const n of needs) {
    const d = decide(n);
    const reasons = reasonsOf({ state_reasons: n.row.state_reasons });
    const deviceId = Number(n.row.device_id);
    const set = async (state: string, why: string[]): Promise<void> => {
      await trx('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId, artifact_key: n.row.artifact_key })
        .update({ state, state_reasons: JSON.stringify(why), state_at: now });
      changed.add(deviceId);
    };
    if (d === 'ready') {
      if (n.row.state !== 'pending' || reasons.some((x) => (LICENSE_REASONS as readonly string[]).includes(x))) {
        await set('pending', reasons.filter((x) => !(LICENSE_REASONS as readonly string[]).includes(x)));
        (n.row.artifact_key.startsWith('ddm:') ? readyDdm : readyCommand).add(deviceId);
      }
    } else if (d === 'pending') {
      if (n.row.state !== 'pending' || reasons.join('|') !== LICENSE_PENDING) await set('pending', [LICENSE_PENDING]);
    } else if (n.row.state !== 'not_applicable' || reasons.join('|') !== 'license_unavailable') {
      await set('not_applicable', ['license_unavailable']);
    }
  }
  for (const g of associate.values()) {
    await requestAssets(trx, tenantId, g.tokenId, 'associate', {
      assets: [{ adamId: g.adamId, pricingParam: g.pricingParam }], serialNumbers: [...g.serials], clientUserIds: [...g.cuids],
      requestedByRef: LICENSING_REF, deviceOfSerial: g.deviceOfSerial,
    });
  }
  for (const [tokenId, users] of createUsers) {
    await requestUsers(trx, tenantId, tokenId, 'users_create', [...users].map(([clientUserId, managedAppleId]) => ({ clientUserId, managedAppleId })), LICENSING_REF);
  }
  if (changed.size) await rollupConfigState(trx, [...changed]);
  if (readyDdm.size) await requestDdmRecompute(trx, tenantId, { deviceIds: [...readyDdm] });
  if (readyCommand.size) await requestArtifactReconcile(trx, tenantId, [...readyCommand]);
}

/** The devices an operation was about: by serial number, and those of the end users of its clientUserIds. */
async function devicesOfOperation(trx: Knex.Transaction, tenantId: number, op: VppOperationView): Promise<number[]> {
  const req = op.request;
  const serials = (Array.isArray(req.serialNumbers) ? req.serialNumbers : []).filter((s): s is string => typeof s === 'string');
  const cuids = [
    ...(Array.isArray(req.clientUserIds) ? req.clientUserIds : []),
    ...(Array.isArray(req.users) ? (req.users as unknown[]).map((u) => obj(u).clientUserId) : []),
  ].filter((s): s is string => typeof s === 'string' && s.startsWith('obg-'));
  const out = new Set<number>();
  for (let i = 0; i < serials.length; i += 500) {
    for (const id of await trx('devices').where({ tenant_id: tenantId }).whereIn('serial_number', serials.slice(i, i + 500)).whereNot('enrollment_state', 'unenrolled').pluck('id')) out.add(Number(id));
  }
  const uuids = cuids.map((c) => c.slice(4)).filter((u) => /^[0-9a-f-]{36}$/.test(u));
  if (uuids.length) {
    for (const id of await trx('devices as d').join('end_users as u', function on() { this.on('u.id', 'd.end_user_id').andOn('u.tenant_id', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId }).whereIn('u.uuid', uuids).whereNot('d.enrollment_state', 'unenrolled').pluck('d.id')) out.add(Number(id));
  }
  return [...out].sort((a, b) => a - b).slice(0, 5000);
}

/** The end of an operation of Apps and Books: the gate again for its devices (an association, a user created). */
export async function onLicenseOperationFinal(trx: Knex.Transaction, tenantId: number, op: VppOperationView): Promise<void> {
  if (op.kind !== 'associate' && op.kind !== 'users_create') return;
  const devices = await devicesOfOperation(trx, tenantId, op);
  for (let i = 0; i < devices.length; i += 200) await licenseGate(trx, tenantId, devices.slice(i, i + 200));
}

/** A content token synchronised: the gate again for the apps that wait for a licence; the device licences of devices
 *  no longer managed given back. */
export async function onLicenseTokenSynced(trx: Knex.Transaction, tenantId: number, tokenId: string): Promise<void> {
  const waiting = await trx('device_artifacts').where({ tenant_id: tenantId }).whereNotNull('desired_hash').whereIn('state', ['pending', 'not_applicable'])
    .where((w) => { for (const l of APP_KEY_LIKE) w.orWhere('artifact_key', 'like', l); })
    .whereRaw("(jsonb_exists(state_reasons, 'license_pending') OR jsonb_exists(state_reasons, 'license_unavailable'))")
    .distinct('device_id').orderBy('device_id').limit(500) as Array<{ device_id: number }>;
  if (waiting.length) await licenseGate(trx, tenantId, waiting.map((w) => Number(w.device_id)));
  const token = await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: tokenId }).first('state') as { state: string } | undefined;
  if (token?.state !== 'active') return;
  const orphans = await trx('vpp_assignments as v').join('devices as d', function on() { this.on('d.id', 'v.device_id').andOn('d.tenant_id', 'v.tenant_id'); })
    .where({ 'v.tenant_id': tenantId, 'v.vpp_token_id': tokenId, 'v.state': 'associated', 'd.enrollment_state': 'unenrolled' }).whereNotNull('v.serial_number')
    .limit(1000).select('v.adam_id', 'v.pricing_param', 'v.serial_number') as Array<{ adam_id: string; pricing_param: string; serial_number: string }>;
  await disassociate(trx, tenantId, tokenId, orphans);
  await disassociate(trx, tenantId, tokenId, await unusedLicenses(trx, tenantId, tokenId));
}

/**
 * The device licences of the token the gate associated (an association of LICENSING_REF) for an app the device no
 * longer wants (no desired artifact of it) and does not hold (no managed app of that identifier in its inventory): an
 * app withdrawn before its delivery, a declaration withdrawn. A licence assigned otherwise (in Apple Business) is
 * never touched. Bounded per pass.
 */
export async function unusedLicenses(trx: Knex.Transaction, tenantId: number, tokenId: string): Promise<Array<{ adam_id: string; pricing_param: string; serial_number: string }>> {
  const rows = await trx.raw(`
    SELECT v.adam_id, v.pricing_param, v.serial_number
      FROM obligarth.vpp_assignments v
      JOIN obligarth.devices d ON d.tenant_id = v.tenant_id AND d.id = v.device_id
     WHERE v.tenant_id = ? AND v.vpp_token_id = ? AND v.state = 'associated' AND v.serial_number IS NOT NULL
       AND d.enrollment_state <> 'unenrolled'
       AND EXISTS (SELECT 1 FROM obligarth.vpp_operations o
                    WHERE o.tenant_id = v.tenant_id AND o.vpp_token_id = v.vpp_token_id AND o.kind = 'associate' AND o.state = 'complete'
                      AND o.requested_by_ref = ? AND jsonb_exists(o.request->'serialNumbers', v.serial_number)
                      AND o.request->'assets' @> jsonb_build_array(jsonb_build_object('adamId', v.adam_id)))
       AND NOT EXISTS (SELECT 1 FROM obligarth.apps a
                        JOIN obligarth.device_artifacts x ON x.tenant_id = a.tenant_id AND x.device_id = v.device_id AND x.desired_hash IS NOT NULL
                         AND x.artifact_key IN ('app:' || a.identifier, 'ddm:obg.cfg.pol-app.managed.' || substr(encode(sha256(convert_to(a.identifier, 'UTF8')), 'hex'), 1, 12))
                        WHERE a.tenant_id = v.tenant_id AND a.store_id = v.adam_id)
       AND NOT EXISTS (SELECT 1 FROM obligarth.apps a
                        JOIN obligarth.device_apps p ON p.tenant_id = a.tenant_id AND p.device_id = v.device_id AND p.identifier = a.identifier AND p.managed
                        WHERE a.tenant_id = v.tenant_id AND a.store_id = v.adam_id)
     ORDER BY v.id
     LIMIT 500`, [tenantId, tokenId, LICENSING_REF]);
  return rows.rows as Array<{ adam_id: string; pricing_param: string; serial_number: string }>;
}

async function disassociate(trx: Knex.Transaction, tenantId: number, tokenId: string,
  rows: Array<{ adam_id: string; pricing_param: string; serial_number: string }>): Promise<void> {
  const by = new Map<string, { adamId: string; pricingParam: string; serials: string[] }>();
  for (const r of rows) {
    const k = `${r.adam_id}|${r.pricing_param}`;
    const g = by.get(k) ?? { adamId: r.adam_id, pricingParam: r.pricing_param, serials: [] };
    g.serials.push(r.serial_number);
    by.set(k, g);
  }
  for (const g of by.values()) {
    await requestAssets(trx, tenantId, tokenId, 'disassociate', {
      assets: [{ adamId: g.adamId, pricingParam: g.pricingParam }], serialNumbers: g.serials, requestedByRef: LICENSING_REF,
    });
  }
}

/** The device licences of a device given back (all its apps, or the one of `identifier`), on every active token. User
 *  licences stay: the end user may hold the app on another device. */
export async function releaseDeviceLicenses(trx: Knex.Transaction, tenantId: number, deviceId: number, identifier?: string): Promise<number> {
  const d = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).first('serial_number') as { serial_number: string | null } | undefined;
  let adamIds: string[] | null = null;
  if (identifier) {
    adamIds = (await trx('apps').where({ tenant_id: tenantId, platform_family: 'apple', identifier }).whereNotNull('store_id').pluck('store_id') as string[]).map(String);
    if (adamIds.length === 0) return 0;
  }
  const q = trx('vpp_assignments as v').join('tenant_apple_vpp_tokens as t', function on() { this.on('t.id', 'v.vpp_token_id').andOn('t.tenant_id', 'v.tenant_id'); })
    .where({ 'v.tenant_id': tenantId, 'v.state': 'associated', 't.state': 'active' }).whereNotNull('v.serial_number')
    .where((w) => { w.where('v.device_id', deviceId); if (d?.serial_number) w.orWhere('v.serial_number', d.serial_number); });
  if (adamIds) q.whereIn('v.adam_id', adamIds);
  const rows = await q.select('v.vpp_token_id', 'v.adam_id', 'v.pricing_param', 'v.serial_number') as
    Array<{ vpp_token_id: string; adam_id: string; pricing_param: string; serial_number: string }>;
  const byToken = new Map<string, typeof rows>();
  for (const r of rows) byToken.set(r.vpp_token_id, [...(byToken.get(r.vpp_token_id) ?? []), r]);
  for (const [tokenId, list] of byToken) await disassociate(trx, tenantId, tokenId, list);
  return rows.length;
}
