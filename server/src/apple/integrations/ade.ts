import type { Knex } from 'knex';
import type { AdeServerState, AdeServerView } from '@obligarth/shared';
import { db } from '../../db';
import type { DbActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { vault } from '../../vault';
import { edgeActorOf } from '../actors';
import { resolveInTx } from '../alerts/service';
import { rethrowForConsole } from '../edge/appError';
import { isAppleEdgeError } from '../edge/errors';
import { appleEdge } from '../edge/instance';
import type { EdgeAdeToken } from '../edge/wire';
import { sendAdeProfilesSyncInTx } from '../enrollment/adeProfiles';
import { realtime } from '../realtime';
import { appleTenants } from '../tenants/registry';
import { recordDeadline, retireDeadline } from './deadlines';

// =============================================================================
// The ADE servers of a tenant (docs: integration-apple-edge §11.2, INT-02),
// mirrored in tenant_apple_ade_tokens (the token and its key live in
// apple-edge, the mirror holds the public certificate only):
//   add          vault.requireEscrow() (coffre-secrets V14), createAdeToken at
//                apple-edge (out of any transaction), mirror 'awaiting_token'
//   public key   obligarth-ade-<label>.pem, to upload into Apple Business
//   token        the .p7m of Apple Business (64 KiB), uploadAdeToken; the
//                mirror follows the answer (active, name, expiry), the ADE
//                profiles are defined on it (enrollment.ade-profiles-sync); a
//                renewal is the same upload on the same server
//   sync         syncAdeToken, once a minute and per server (routes)
//   byod         declareAccountDrivenEnrollment: the account-driven discovery
//   delete       a second approver (floor apple.ade_token_delete), refused
//                while devices enrolled from the server are still managed;
//                mirror 'removed', its devices of Apple Business removed
// The hourly integrations.ade-reconcile compares the mirror with apple-edge's
// list. Serial numbers stay in apple_ade_devices, never in a log.
// =============================================================================

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ADE_STATES: readonly AdeServerState[] = ['awaiting_token', 'active', 'terms_not_signed', 'expired', 'error', 'removed'];

interface MirrorRow {
  id: string;
  label: string;
  state: AdeServerState;
  state_at: Date;
  server_name: string | null;
  not_after: Date | null;
  apple_account_hint: string | null;
  last_sync_at: Date | null;
  last_fetch_at: Date | null;
  consecutive_errors: number;
  last_error_code: string | null;
  byod_discovery: boolean;
  byod_discovery_at: Date | null;
  created_at: Date;
  public_certificate_pem: string;
}

const COLS = ['id', 'label', 'state', 'state_at', 'server_name', 'not_after', 'apple_account_hint', 'last_sync_at', 'last_fetch_at',
  'consecutive_errors', 'last_error_code', 'byod_discovery', 'byod_discovery_at', 'created_at', 'public_certificate_pem'];
const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);

export function serverId(raw: unknown): string {
  const id = String(raw ?? '').toLowerCase();
  if (!UUID_RE.test(id)) throw new AppError(404, 'Not found', 'adeServerNotFound');
  return id;
}

async function mirrorOf(q: Knex | Knex.Transaction, tenantId: number, id: string, lock = false): Promise<MirrorRow> {
  let qb = q('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id }).whereNot('state', 'removed');
  if (lock) qb = qb.forUpdate();
  const r = await qb.first(COLS) as MirrorRow | undefined;
  if (!r) throw new AppError(404, 'Not found', 'adeServerNotFound');
  return r;
}

/** Devices enrolled from a server and still managed (a deletion is refused while there are some). */
export async function enrolledDevicesOf(q: Knex | Knex.Transaction, tenantId: number, id: string): Promise<number> {
  const r = await q('apple_ade_devices as a').join('devices as d', function on() { this.on('d.id', 'a.device_id').andOn('d.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.ade_token_id': id }).whereNull('a.removed_at').whereNot('d.enrollment_state', 'unenrolled')
    .count({ n: '*' }).first() as { n: string | number } | undefined;
  return Number(r?.n ?? 0);
}

async function views(q: Knex | Knex.Transaction, tenantId: number, rows: MirrorRow[]): Promise<AdeServerView[]> {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id);
  const counts = await q('apple_ade_devices').where({ tenant_id: tenantId }).whereIn('ade_token_id', ids).whereNull('removed_at')
    .groupBy('ade_token_id').select('ade_token_id').count({ n: '*' }) as Array<{ ade_token_id: string; n: string | number }>;
  const enrolled = await q('apple_ade_devices as a').join('devices as d', function on() { this.on('d.id', 'a.device_id').andOn('d.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId }).whereIn('a.ade_token_id', ids).whereNull('a.removed_at').whereNot('d.enrollment_state', 'unenrolled')
    .groupBy('a.ade_token_id').select('a.ade_token_id').count({ n: '*' }) as Array<{ ade_token_id: string; n: string | number }>;
  const by = (list: Array<{ ade_token_id: string; n: string | number }>) => new Map(list.map((x) => [String(x.ade_token_id), Number(x.n)]));
  const c = by(counts);
  const e = by(enrolled);
  return rows.map((r) => ({
    id: r.id, label: r.label, state: r.state, stateAt: iso(r.state_at)!, serverName: r.server_name, notAfter: iso(r.not_after),
    appleAccountHint: r.apple_account_hint, lastSyncAt: iso(r.last_sync_at ?? r.last_fetch_at), consecutiveErrors: Number(r.consecutive_errors ?? 0),
    lastErrorCode: r.last_error_code, byodDiscovery: r.byod_discovery === true, byodDiscoveryAt: iso(r.byod_discovery_at), createdAt: iso(r.created_at)!,
    devices: c.get(r.id) ?? 0, enrolledDevices: e.get(r.id) ?? 0,
  }));
}

export async function listAdeServers(q: Knex | Knex.Transaction, tenantId: number): Promise<AdeServerView[]> {
  const rows = await q('tenant_apple_ade_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').orderBy('created_at').select(COLS) as MirrorRow[];
  return views(q, tenantId, rows);
}

export async function getAdeServer(q: Knex | Knex.Transaction, tenantId: number, id: string): Promise<AdeServerView> {
  return (await views(q, tenantId, [await mirrorOf(q, tenantId, id)]))[0];
}

/** « Ajouter un serveur ». */
export async function createAdeServer(tenantId: number, userId: number, input: { label: string; appleAccountHint?: string | null }, actor: DbActor):
  Promise<AdeServerView> {
  await vault.requireEscrow();
  const key = await appleTenants.keyOf(tenantId);
  let tok: EdgeAdeToken;
  try {
    tok = await appleEdge.createAdeToken(key, { actor: edgeActorOf(actor) });
  } catch (err) {
    if (isAppleEdgeError(err) && String(err.code) === 'too_many_ade_tokens') {
      throw new AppError(409, 'This tenant has reached the number of ADE servers the device service allows', 'adeServerLimit');
    }
    rethrowForConsole(err);
  }
  const id = String(tok.id).toLowerCase();
  if (!UUID_RE.test(id)) throw new AppError(502, 'The device service gave an answer that cannot be read', 'appleEdgeProtocol');
  try {
    await db('tenant_apple_ade_tokens').insert({
      id, tenant_id: tenantId, label: input.label, state: 'awaiting_token', state_at: new Date(), public_certificate_pem: tok.certificate_pem,
      apple_account_hint: input.appleAccountHint?.trim() || null, created_by: userId,
    });
  } catch (err) {
    // The token at apple-edge would stay without a mirror: removed (best effort; the reconciliation mirrors it otherwise).
    await appleEdge.deleteAdeToken(key, id, { actor: edgeActorOf(actor) }).catch(() => undefined);
    throw err;
  }
  realtime.integrationChanged(tenantId, 'ade');
  return getAdeServer(db, tenantId, id);
}

/** The public certificate to upload into Apple Business. */
export async function adeServerPublicKey(q: Knex, tenantId: number, id: string): Promise<{ filename: string; pem: string }> {
  const m = await mirrorOf(q, tenantId, id);
  const slug = m.label.normalize('NFKD').replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase().slice(0, 40) || 'server';
  return { filename: `obligarth-ade-${slug}.pem`, pem: m.public_certificate_pem };
}

/** The mirror as apple-edge describes the token, at `at` (its answer, or the reconciliation); monotone by state_at. */
async function applyEdgeToken(trx: Knex.Transaction, tenantId: number, m: MirrorRow, t: EdgeAdeToken, at: Date, o: { activated?: boolean } = {}): Promise<boolean> {
  const state = ADE_STATES.includes(t.state as AdeServerState) ? t.state as AdeServerState : null;
  const notAfter = t.not_after ? new Date(t.not_after) : null;
  const patch: Record<string, unknown> = {
    server_name: t.server_name ? t.server_name.slice(0, 200) : m.server_name, server_uuid: t.server_uuid ? t.server_uuid.slice(0, 64) : null,
    updated_at: new Date(),
  };
  if (notAfter && !Number.isNaN(notAfter.getTime())) patch.not_after = notAfter;
  if (t.last_sync_at) patch.last_sync_at = trx.raw('GREATEST(last_sync_at, ?::timestamptz)', [t.last_sync_at]);
  if (t.last_fetch_at) patch.last_fetch_at = trx.raw('GREATEST(last_fetch_at, ?::timestamptz)', [t.last_fetch_at]);
  let changed = false;
  if (state && state !== m.state && new Date(m.state_at).getTime() < at.getTime()) {
    Object.assign(patch, { state, state_at: at });
    if (state === 'active') Object.assign(patch, { consecutive_errors: 0, last_error_code: null });
    changed = true;
  }
  await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id }).update(patch);
  const label = (t.server_name || m.server_name || m.label || 'ADE').slice(0, 200);
  if (notAfter && !Number.isNaN(notAfter.getTime())) await recordDeadline(trx, tenantId, { kind: 'ade_token', subjectRef: m.id, label, notAfter });
  if (changed && state === 'active') {
    for (const kind of ['ade.token_error', 'ade.terms_not_signed', 'ade.token_expired'] as const) await resolveInTx(trx, tenantId, kind, m.id);
  }
  // A token (re)activated: the ADE profiles of the tenant are defined on this server (§10.6).
  if (o.activated || (changed && state === 'active')) await sendAdeProfilesSyncInTx(trx, tenantId);
  return changed;
}

/** « Importer le jeton » / « Renouveler ». */
export async function uploadAdeServerToken(tenantId: number, id: string, p7m: Buffer, actor: DbActor): Promise<AdeServerView> {
  await mirrorOf(db, tenantId, id);
  const key = await appleTenants.keyOf(tenantId);
  let tok: EdgeAdeToken;
  try {
    tok = await appleEdge.uploadAdeToken(key, id, p7m, { actor: edgeActorOf(actor) });
  } catch (err) {
    if (isAppleEdgeError(err)) {
      switch (String(err.code)) {
        case 'invalid_token_file': throw new AppError(422, 'This file is not a server token of Apple Business for this server (download it again after uploading this server\'s public key)', 'adeTokenFileInvalid');
        case 'ade_token_expired': throw new AppError(422, 'This server token is expired: download a new one from Apple Business', 'adeTokenFileExpired');
        case 'ade_token_rejected': throw new AppError(422, 'Apple refused this server token', 'adeTokenRejected');
        case 'ade_token_removed': throw new AppError(404, 'Not found', 'adeServerNotFound');
        default: break;
      }
    }
    rethrowForConsole(err);
  }
  await db.transaction(async (trx) => {
    const m = await mirrorOf(trx, tenantId, id, true);
    await applyEdgeToken(trx, tenantId, m, tok, new Date(), { activated: tok.state === 'active' });
  });
  realtime.integrationChanged(tenantId, 'ade', 'deadlines');
  return getAdeServer(db, tenantId, id);
}

/** « Synchroniser maintenant » (the route limits it to once a minute and per server). */
export async function syncAdeServer(tenantId: number, id: string, actor: DbActor): Promise<void> {
  const m = await mirrorOf(db, tenantId, id);
  if (m.state === 'awaiting_token') throw new AppError(409, 'Import the server token first', 'adeTokenNotActive');
  const key = await appleTenants.keyOf(tenantId);
  try {
    await appleEdge.syncAdeToken(key, id, { actor: edgeActorOf(actor) });
  } catch (err) {
    rethrowForConsole(err);
  }
}

/** « Activer l'enrôlement par compte » (the discovery of the account-driven enrollment at Apple). */
export async function declareAdeServerByod(tenantId: number, id: string, actor: DbActor): Promise<AdeServerView> {
  const m = await mirrorOf(db, tenantId, id);
  if (m.state !== 'active') throw new AppError(409, 'The ADE server is not active', 'adeTokenNotActive');
  const key = await appleTenants.keyOf(tenantId);
  try {
    await appleEdge.declareAccountDrivenEnrollment(key, id, { actor: edgeActorOf(actor) });
  } catch (err) {
    rethrowForConsole(err);
  }
  await db('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id }).update({ byod_discovery: true, byod_discovery_at: new Date(), updated_at: new Date() });
  realtime.integrationChanged(tenantId, 'ade');
  return getAdeServer(db, tenantId, id);
}

/** The checks of a deletion, before a second approver is asked (and again by the executor). */
export async function checkAdeServerDeletable(q: Knex | Knex.Transaction, tenantId: number, id: string): Promise<{ label: string }> {
  const m = await mirrorOf(q, tenantId, id);
  const n = await enrolledDevicesOf(q, tenantId, id);
  if (n > 0) {
    throw new AppError(409, `${n} device(s) enrolled from this server are still managed: unenroll them first`, 'adeServerHasDevices', { devices: n });
  }
  return { label: m.server_name || m.label };
}

/** The approved deletion (executor): apple-edge first, then the mirror and its devices. */
export async function deleteAdeServer(tenantId: number, id: string, actor: DbActor): Promise<void> {
  await checkAdeServerDeletable(db, tenantId, id);
  const key = await appleTenants.keyOf(tenantId);
  try {
    await appleEdge.deleteAdeToken(key, id, { actor: edgeActorOf(actor) });
  } catch (err) {
    if (!(isAppleEdgeError(err) && (String(err.code) === 'not_found' || String(err.code) === 'ade_token_removed'))) rethrowForConsole(err);
  }
  await db.transaction(async (trx) => {
    const now = new Date();
    await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id })
      .update({ state: 'removed', state_at: now, removed_at: now, byod_discovery: false, updated_at: now });
    await trx('apple_ade_devices').where({ tenant_id: tenantId, ade_token_id: id }).whereNull('removed_at').update({ removed_at: now, updated_at: now });
    await retireDeadline(trx, tenantId, 'ade_token', id);
    for (const kind of ['ade.token_error', 'ade.terms_not_signed', 'ade.token_expired', 'ade.assignment_failed'] as const) await resolveInTx(trx, tenantId, kind, id);
  });
  realtime.integrationChanged(tenantId, 'ade', 'deadlines');
}

/**
 * integrations.ade-reconcile, for one tenant (its context, no transaction around the call to apple-edge): the
 * mirror follows apple-edge's list (state, name, expiry, last synchronisation); a mirror row apple-edge no longer
 * knows is removed; a token apple-edge holds without a mirror (a restore of the brain) is mirrored.
 */
export async function reconcileAdeServers(tenantId: number, key: string, actor: DbActor): Promise<{ updated: number; added: number; removed: number }> {
  // A mirror created while the list is read is not in it: only the rows older than the call can be missing.
  const listedAt = new Date();
  const list = await appleEdge.listAdeTokens(key, { actor: edgeActorOf(actor) });
  const at = new Date();
  const out = { updated: 0, added: 0, removed: 0 };
  await db.transaction(async (trx) => {
    const rows = await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').forUpdate().select(COLS) as MirrorRow[];
    const byId = new Map(rows.map((r) => [r.id, r]));
    const seen = new Set<string>();
    for (const t of list) {
      const id = String(t.id).toLowerCase();
      if (!UUID_RE.test(id)) continue;
      if (t.state === 'removed') continue;
      seen.add(id);
      const m = byId.get(id);
      if (m) {
        if (await applyEdgeToken(trx, tenantId, m, t, at)) out.updated += 1;
        continue;
      }
      const exists = await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id }).first('id');
      if (exists) continue;                                            // removed here, still at apple-edge: the deletion goes on
      await trx('tenant_apple_ade_tokens').insert({
        id, tenant_id: tenantId, label: (t.server_name || 'ADE').slice(0, 100), state: ADE_STATES.includes(t.state as AdeServerState) ? t.state : 'error',
        state_at: at, public_certificate_pem: t.certificate_pem, server_name: t.server_name?.slice(0, 200) ?? null,
        server_uuid: t.server_uuid?.slice(0, 64) ?? null, not_after: t.not_after ? new Date(t.not_after) : null,
      });
      if (t.not_after) await recordDeadline(trx, tenantId, { kind: 'ade_token', subjectRef: id, label: (t.server_name || 'ADE').slice(0, 200), notAfter: new Date(t.not_after) });
      out.added += 1;
    }
    for (const m of rows) {
      if (seen.has(m.id) || new Date(m.created_at).getTime() >= listedAt.getTime()) continue;
      await trx('tenant_apple_ade_tokens').where({ tenant_id: tenantId, id: m.id })
        .update({ state: 'removed', state_at: at, removed_at: at, byod_discovery: false, updated_at: at });
      await trx('apple_ade_devices').where({ tenant_id: tenantId, ade_token_id: m.id }).whereNull('removed_at').update({ removed_at: at, updated_at: at });
      await retireDeadline(trx, tenantId, 'ade_token', m.id);
      out.removed += 1;
    }
  });
  if (out.updated + out.added + out.removed > 0) realtime.integrationChanged(tenantId, 'ade', 'deadlines');
  return out;
}
