import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import type { VppAssetView, VppOperationKind, VppOperationListItem, VppOperationState, VppTokenState, VppTokenView } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import type { DbActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { vault } from '../../vault';
import { raiseCountedInTx, raiseInTx, resolveInTx } from '../alerts/service';
import { realtime } from '../realtime';
import { recordDeadline, retireDeadline } from './deadlines';
import { instanceId } from './push';
import {
  cachedLimits, isVppApiError, logVppFailure, vppClient, type VppAssetRow, type VppAssignmentRow, type VppClientConfig, type VppEvent,
  type VppTokenCalls,
} from './vpp.client';
import { bearerMatches, decodeTokenFile, mdmInfoIsOurs, platformsOfAsset, VppTokenFileError, type VppTokenFile } from './vppRules';

// =============================================================================
// Apps and Books (docs: integration-apple-edge §11.3, INT-03; I17; S-17,
// S-18; decision of the owners of 15/10: a token used by another MDM may be
// taken over under guard, hourly synchronisation). The brain holds the
// connection: the content token sealed in its vault, mdmInfo, the
// notifications of Apple, the mirror of the licences and the asynchronous
// operations. Choosing when to associate a licence belongs to the delivery of
// the apps (mdm/apps/licensing.ts), which uses the interface `vpp` below.
//   import      vault.requireEscrow(); the .vpptoken file (16 KiB, base64 of
//               {token, expDate, orgName}: the file's content is the sToken);
//               sealed (AAD of its row); one live token per sToken in the
//               instance (unique index: vppTokenAlreadyUsed, never where);
//               then, out of any transaction, client/config: mdmInfo absent
//               or ours → ours written with the notification URL and secret;
//               another MDM's → 'foreign_mdm' (alert), taken over only by an
//               explicit, guarded request (apple.vpp_token_takeover)
//   notify      POST /t/<key>/vpp/<ref>/notify (vpp.routes.public.ts): the
//               reference's token in the key's tenant, the bearer compared in
//               constant time with the hash of the secret, the body kept in
//               vpp_notifications_inbox (deduplicated), vpp.notification sent
//               in the same transaction; a notification only hastens: an
//               operation ends on what the event status says (S-17)
//   operations  vpp_operations: requested in the caller's transaction (split
//               by the limits of service/config), submitted by
//               vpp.operation-submit (eventId kept), confirmed by
//               vpp.event-status 5 minutes after the submission then every 30
//               seconds at most, or at once after a notification of the same
//               eventId; still pending after 10 minutes: submitted again once,
//               then failed (alert vpp.operation_failed); every end calls the
//               onOperationFinal hooks in its transaction
//   sync        vpp.sync-token (vpp.jobs.ts): mdmInfo checked (changed →
//               foreign_mdm), assets by pages, assignments since the last
//               versionId, mirrors; finished operations and processed
//               notifications older than 30 days purged
// The sToken is opened from the vault for a call and never logged, returned,
// nor written anywhere but its sealed column.
// =============================================================================

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const NOTIFICATION_TYPES = ['ASSET_MANAGEMENT', 'ASSET_COUNT', 'USER_MANAGEMENT', 'USER_ASSOCIATED'] as const;
/** Wrong secrets a token may receive in an hour before the alert. */
const AUTH_FAIL_THRESHOLD = 10;
/** The first look at the status of an operation, after its submission. */
export const FIRST_POLL_SECONDS = 300;
/** Then every so often, at most. */
export const NEXT_POLL_SECONDS = 30;
/** Still pending this long after its (last) submission: submitted again once, then failed. */
export const REPLAY_AFTER_MS = 10 * 60_000;
/** Finished operations and processed notifications are kept this long. */
export const PURGE_AFTER_DAYS = 30;
const SECRET_COL = { table: 'tenant_apple_vpp_tokens', column: 's_token_enc' } as const;

export interface VppAssetRef { adamId: string; pricingParam: 'STDQ' | 'PLUS' | string }
export interface VppOperationView {
  id: string; tokenId: string; kind: VppOperationKind; state: VppOperationState;
  request: Record<string, unknown>; resultSummary: Record<string, unknown> | null; requestedByRef: string | null;
}
export type OperationFinalHook = (trx: Knex.Transaction, tenantId: number, op: VppOperationView) => Promise<void>;
export type TokenSyncedHook = (trx: Knex.Transaction, tenantId: number, tokenId: string) => Promise<void>;

interface TokenRow {
  id: string;
  tenant_id: number;
  label: string;
  org_name: string | null;
  location_name: string | null;
  location_uid: string | null;
  s_token_enc: string;
  s_token_sha256: string;
  exp_date: Date;
  state: VppTokenState;
  state_at: Date;
  mdm_info_id: string;
  notification_ref: string;
  notification_secret_hash: string;
  test_notification_at: Date | null;
  last_notification_at: Date | null;
  assets_version_id: string | null;
  assignments_version_id: string | null;
  last_sync_at: Date | null;
  consecutive_errors: number;
  last_error_code: string | null;
  apple_account_hint: string | null;
  created_at: Date;
  removed_at: Date | null;
}

interface OperationRow {
  id: string;
  tenant_id: number;
  vpp_token_id: string;
  event_id: string | null;
  kind: VppOperationKind;
  state: VppOperationState;
  request: unknown;
  result_summary: unknown;
  requested_by_ref: string | null;
  status_polls: number;
  created_at: Date;
  updated_at: Date;
  completed_at: Date | null;
}

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);
const sha256Hex = (s: string | Buffer): string => createHash('sha256').update(s).digest('hex');
const parse = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  if (typeof v !== 'string') return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};
/** The marker of a token whose notification configuration still has to reach Apple (the secret lived in memory). */
const CONFIG_PENDING = 'client_config_pending';

export function vppTokenId(raw: unknown): string {
  const id = String(raw ?? '').toLowerCase();
  if (!UUID_RE.test(id)) throw new AppError(404, 'Not found', 'vppTokenNotFound');
  return id;
}

// ── Hooks ──────────────────────────────────────────────────────────────────────

const finalHooks: OperationFinalHook[] = [];
const syncedHooks: TokenSyncedHook[] = [];
/** The delivery of the apps chains on the end of an operation (associate → install). */
export function onOperationFinal(fn: OperationFinalHook): void { if (!finalHooks.includes(fn)) finalHooks.push(fn); }
/** The delivery of the apps looks again at the licences it waits for once a token was synchronised. */
export function onTokenSynced(fn: TokenSyncedHook): void { if (!syncedHooks.includes(fn)) syncedHooks.push(fn); }

// ── Job senders (bound by vpp.jobs.ts: no import cycle) ─────────────────────────

export interface VppSenders {
  submit(trx: Knex.Transaction, tenantId: number, operationId: string, attempt: number): Promise<void>;
  eventStatus(trx: Knex.Transaction | null, tenantId: number, operationId: string, delaySeconds: number): Promise<void>;
  syncToken(trx: Knex.Transaction | null, tenantId: number, vppId: string, full: boolean): Promise<void>;
  notification(trx: Knex.Transaction, tenantId: number, inboxId: string): Promise<void>;
}
let senders: VppSenders | null = null;
export function bindVppSenders(s: VppSenders): void { senders = s; }
function send(): VppSenders {
  if (!senders) throw new Error('apps and books: the jobs are not registered');
  return senders;
}

// ── The token file ─────────────────────────────────────────────────────────────

export type { VppTokenFile };

/** Decodes a .vpptoken file (vppRules.ts) for the console: 422 vppTokenFileInvalid or vppTokenExpired, 413. */
export function decodeVppTokenFile(bytes: Buffer, now = new Date()): VppTokenFile {
  try {
    return decodeTokenFile(bytes, now);
  } catch (err) {
    if (err instanceof VppTokenFileError) throw new AppError(err.code === 'fileTooLarge' ? 413 : 422, err.message, err.code);
    throw err;
  }
}

// ── Rows and views ─────────────────────────────────────────────────────────────

async function tokenRow(q: Knex | Knex.Transaction, tenantId: number, id: string, o: { lock?: boolean; removed?: boolean } = {}): Promise<TokenRow> {
  let qb = q('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id });
  if (!o.removed) qb = qb.whereNot('state', 'removed');
  if (o.lock) qb = qb.forUpdate();
  const r = await qb.first() as TokenRow | undefined;
  if (!r) throw new AppError(404, 'Not found', 'vppTokenNotFound');
  return r;
}

const locator = (r: { id: string; tenant_id: number }) => ({ ...SECRET_COL, pk: r.id, tenantId: Number(r.tenant_id) });

/** The calls of a token: its sToken opened from the vault for them. */
async function callsOf(r: TokenRow): Promise<VppTokenCalls> {
  const sToken = await vault.openString(locator(r), r.s_token_enc, { requestTenantId: Number(r.tenant_id) });
  return vppClient(r.id, sToken);
}

async function views(q: Knex | Knex.Transaction, tenantId: number, rows: TokenRow[]): Promise<VppTokenView[]> {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id);
  const assets = await q('vpp_assets').where({ tenant_id: tenantId }).whereIn('vpp_token_id', ids).groupBy('vpp_token_id')
    .select('vpp_token_id').count({ n: '*' }) as Array<{ vpp_token_id: string; n: string | number }>;
  const pending = await q('vpp_operations').where({ tenant_id: tenantId }).whereIn('vpp_token_id', ids).whereIn('state', ['requested', 'pending'])
    .groupBy('vpp_token_id').select('vpp_token_id').count({ n: '*' }) as Array<{ vpp_token_id: string; n: string | number }>;
  const by = (l: Array<{ vpp_token_id: string; n: string | number }>) => new Map(l.map((x) => [String(x.vpp_token_id), Number(x.n)]));
  const a = by(assets);
  const p = by(pending);
  return rows.map((r) => ({
    id: r.id, label: r.label, state: r.state, stateAt: iso(r.state_at)!, orgName: r.org_name, locationName: r.location_name,
    expDate: iso(r.exp_date)!, lastSyncAt: iso(r.last_sync_at), testNotificationAt: iso(r.test_notification_at),
    lastNotificationAt: iso(r.last_notification_at), consecutiveErrors: Number(r.consecutive_errors ?? 0), lastErrorCode: r.last_error_code,
    appleAccountHint: r.apple_account_hint, createdAt: iso(r.created_at)!, assets: a.get(r.id) ?? 0, pendingOperations: p.get(r.id) ?? 0,
  }));
}

export async function listVppTokens(q: Knex | Knex.Transaction, tenantId: number): Promise<VppTokenView[]> {
  const rows = await q('tenant_apple_vpp_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').orderBy('created_at').select() as TokenRow[];
  return views(q, tenantId, rows);
}

export async function getVppToken(q: Knex | Knex.Transaction, tenantId: number, id: string): Promise<VppTokenView> {
  return (await views(q, tenantId, [await tokenRow(q, tenantId, id)]))[0];
}

export async function listVppAssets(q: Knex | Knex.Transaction, tenantId: number, tokenId?: string): Promise<VppAssetView[]> {
  let qb = q('vpp_assets as a').join('tenant_apple_vpp_tokens as t', function on() { this.on('t.id', 'a.vpp_token_id').andOn('t.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId }).whereNot('t.state', 'removed');
  if (tokenId) qb = qb.where({ 'a.vpp_token_id': tokenId });
  const rows = await qb.orderBy(['a.adam_id', 'a.pricing_param']).limit(5000).select('a.*') as Array<Record<string, any>>;
  const adamIds = [...new Set(rows.map((r) => String(r.adam_id)))];
  const apps = adamIds.length
    ? await q('apps').where({ tenant_id: tenantId, platform_family: 'apple' }).whereNull('archived_at').whereIn('store_id', adamIds).select('id', 'store_id') as Array<{ id: number; store_id: string }>
    : [];
  const appOf = new Map(apps.map((x) => [String(x.store_id), Number(x.id)]));
  return rows.map((r) => ({
    id: Number(r.id), tokenId: String(r.vpp_token_id), adamId: String(r.adam_id), pricingParam: String(r.pricing_param), productType: String(r.product_type),
    deviceAssignable: r.device_assignable === true, revocable: r.revocable === true,
    supportedPlatforms: parse<string[]>(r.supported_platforms, []), totalCount: Number(r.total_count), assignedCount: Number(r.assigned_count),
    availableCount: Number(r.available_count), retiredCount: Number(r.retired_count), updatedAt: iso(r.updated_at)!, appId: appOf.get(String(r.adam_id)) ?? null,
  }));
}

export async function listVppOperations(q: Knex | Knex.Transaction, tenantId: number, o: { state?: string; limit?: number } = {}): Promise<VppOperationListItem[]> {
  let qb = q('vpp_operations').where({ tenant_id: tenantId });
  if (o.state) qb = qb.where({ state: o.state });
  const rows = await qb.orderBy('created_at', 'desc').limit(Math.min(Math.max(o.limit ?? 100, 1), 500)).select() as OperationRow[];
  return rows.map((r) => {
    const req = parse<Record<string, unknown>>(r.request, {});
    const sum = parse<Record<string, unknown> | null>(r.result_summary, null);
    const len = (v: unknown): number => (Array.isArray(v) ? v.length : 0);
    return {
      id: r.id, tokenId: r.vpp_token_id, kind: r.kind, state: r.state, assets: len(req.assets), serialNumbers: len(req.serialNumbers),
      clientUserIds: len(req.clientUserIds) + len(req.users), eventId: r.event_id, requestedByRef: r.requested_by_ref,
      createdAt: iso(r.created_at)!, completedAt: iso(r.completed_at), failures: Number(sum?.failures ?? 0),
    };
  });
}

// ── client/config (mdmInfo, notifications) ───────────────────────────────────────

/** Where Apple sends the notifications of a token. */
export function notificationUrlOf(key: string, ref: string): string {
  const base = config.apple.mdmPublicBase;
  if (!base) throw new AppError(503, 'The public address of the device service is not configured', 'appleIntegrationDisabled');
  return `${base.replace(/\/+$/, '')}/t/${key}/vpp/${ref}/notify`;
}

const newSecret = (): { secret: string; hash: string } => {
  const secret = randomBytes(32).toString('base64url');
  return { secret, hash: sha256Hex(secret) };
};

export { mdmInfoIsOurs };

/**
 * The claim of a location of Apple Business by the tenant (decision of the owners of 19/10/2026, INT-INTC-R9 B):
 * obligarth.vpp_location_claim, instance-wide, in the tenant's context. True when the location is free, already
 * this tenant's or taken over (`takeover`: the caller holds the guard of the takeover); false when another tenant
 * of this instance holds it (never which one). An unknown location (no uId) claims nothing.
 */
export async function claimLocation(q: Knex | Knex.Transaction, tokenId: string, uid: string | null | undefined, takeover: boolean): Promise<boolean> {
  if (!uid) return true;
  const res = await q.raw('SELECT obligarth.vpp_location_claim(?::uuid, ?, ?) AS ok', [tokenId, uid, takeover]) as { rows: Array<{ ok: boolean }> };
  return res.rows[0]?.ok === true;
}

/** The token is another MDM's, or its location another tenant's of this instance: 'foreign_mdm', alert. */
async function markForeign(tenantId: number, id: string, label: string, location?: { name: string | null; uid: string | null }): Promise<void> {
  let moved = 0;
  await db.transaction(async (trx) => {
    moved = await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).whereNot('state', 'removed').update({
      state: 'foreign_mdm', state_at: new Date(), ...(location ? { location_name: location.name, location_uid: location.uid } : {}), updated_at: new Date(),
    });
    await raiseInTx(trx, tenantId, 'vpp.foreign_mdm', { discriminant: id, params: { label }, navigateTo: '/integrations' });
  });
  if (moved) realtime.integrationChanged(tenantId, 'vpp');
}

type ConfigureOutcome = 'configured' | 'foreign';

/**
 * client/config of a token: mdmInfo absent or ours (or `takeover`) → mdmInfo, notification types, URL and a secret
 * written at Apple, then the secret's hash, the location and the expiry in the row; another MDM's → 'foreign_mdm'.
 * `secret`: the one drawn at the import (its hash is in the row already); otherwise a new one is drawn.
 */
async function configureClient(tenantId: number, id: string, o: { takeover?: boolean; secret?: string; actor: DbActor }): Promise<ConfigureOutcome> {
  const r = await tokenRow(db, tenantId, id);
  const calls = await callsOf(r);
  const current = await calls.getClientConfig();
  const t = await db('tenants').where({ id: tenantId }).first('uuid') as { uuid: string } | undefined;
  // Another MDM's, or another tenant's of this instance (its metadata, or its claim of the location whether Apple
  // echoes the metadata or not: INT-INTC-R9): a takeover only, under its guard. The claim comes before anything is
  // written at Apple.
  const location = { name: current.locationName ?? r.location_name, uid: current.uId ?? r.location_uid };
  if ((!o.takeover && !mdmInfoIsOurs(current, r.mdm_info_id, t?.uuid ?? null)) || !(await claimLocation(db, id, location.uid, o.takeover === true))) {
    await markForeign(tenantId, id, r.label, location);
    return 'foreign';
  }
  const key = (await db('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined)?.mdm_key;
  if (!key) throw new AppError(409, 'The tenant is not provisioned at the device service yet', 'tenantNotProvisioned');
  const s = o.secret ? { secret: o.secret, hash: r.notification_secret_hash } : newSecret();
  const after = await calls.setClientConfig({
    mdmInfo: { id: r.mdm_info_id, name: 'Obligarth', metadata: String(t?.uuid ?? '') },
    notificationTypes: [...NOTIFICATION_TYPES],
    notificationUrl: notificationUrlOf(key, r.notification_ref),
    notificationAuthToken: s.secret,
  });
  const expiry = after.tokenExpiry ?? current.tokenExpiry;
  await db.transaction(async (trx) => {
    const row = await tokenRow(trx, tenantId, id, { lock: true });
    await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).update({
      notification_secret_hash: s.hash, state: 'active', state_at: row.state === 'active' ? row.state_at : new Date(),
      location_name: after.locationName ?? current.locationName ?? row.location_name, location_uid: after.uId ?? current.uId ?? row.location_uid,
      ...(expiry ? { exp_date: expiry } : {}), last_error_code: null, consecutive_errors: 0, updated_at: new Date(),
    });
    if (expiry) await recordDeadline(trx, tenantId, { kind: 'vpp_token', subjectRef: id, label: row.label, notAfter: expiry, source: 'brain' });
    for (const k of ['vpp.foreign_mdm', 'vpp.token_invalid'] as const) await resolveInTx(trx, tenantId, k, id);
  });
  realtime.integrationChanged(tenantId, 'vpp');
  return 'configured';
}

/** A token Apple refused: 'invalid', critical alert. */
export async function markTokenInvalid(tenantId: number, id: string, code: string): Promise<void> {
  await db.transaction(async (trx) => {
    const n = await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).whereNotIn('state', ['removed', 'invalid'])
      .update({ state: 'invalid', state_at: new Date(), last_error_code: code.slice(0, 64), updated_at: new Date() });
    const r = await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).first('label') as { label: string } | undefined;
    if (n) await raiseInTx(trx, tenantId, 'vpp.token_invalid', { discriminant: id, params: { label: r?.label ?? '' }, navigateTo: '/integrations' });
  });
  realtime.integrationChanged(tenantId, 'vpp');
}

/** An error of a call: the code in the row (token refused: invalid). */
async function recordCallError(tenantId: number, id: string, err: unknown): Promise<void> {
  if (isVppApiError(err) && err.kind === 'token_rejected') { await markTokenInvalid(tenantId, id, err.code); return; }
  const code = isVppApiError(err) ? err.code : String((err as { code?: unknown })?.code ?? 'error').slice(0, 64);
  await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).update({
    consecutive_errors: db.raw('consecutive_errors + 1'), last_error_code: code, updated_at: new Date(),
  });
}

/** The answer of the console to a failed call of Apps and Books. */
function rethrowVpp(err: unknown): never {
  if (isVppApiError(err)) {
    if (err.kind === 'token_rejected') throw new AppError(422, 'Apple refused this content token', 'vppTokenRejected');
    if (err.kind === 'rate_limited') throw new AppError(429, 'Apps and Books asks to wait: try again in a few minutes', 'vppRateLimited');
    throw new AppError(502, 'Apps and Books could not be reached or refused the request', 'vppUnavailable', { code: err.code });
  }
  throw err;
}

// ── Import, takeover, replacement, removal ─────────────────────────────────────

export interface ImportOutcome { view: VppTokenView; outcome: 'active' | 'foreign_mdm' | 'pending' }

/** « Importer un jeton de contenu » (§11.3, steps 1 to 4). */
export async function importVppToken(tenantId: number, userId: number, input: { label: string; appleAccountHint?: string | null }, file: VppTokenFile,
  actor: DbActor): Promise<ImportOutcome> {
  await vault.requireEscrow();
  const id = randomUUID();
  const s = newSecret();
  const mdmInfoId = `obligarth:${await instanceId(db)}`;
  try {
    await db.transaction(async (trx) => {
      const sealed = await vault.seal({ ...SECRET_COL, pk: id, tenantId }, file.sToken, { trx, requestTenantId: tenantId });
      await trx('tenant_apple_vpp_tokens').insert({
        id, tenant_id: tenantId, label: input.label, org_name: file.orgName, s_token_enc: sealed, s_token_sha256: sha256Hex(file.sToken),
        exp_date: file.expDate, state: 'active', state_at: new Date(), mdm_info_id: mdmInfoId, notification_ref: randomBytes(16).toString('base64url'),
        notification_secret_hash: s.hash, last_error_code: CONFIG_PENDING, apple_account_hint: input.appleAccountHint?.trim() || null, created_by: userId,
      });
      await recordDeadline(trx, tenantId, { kind: 'vpp_token', subjectRef: id, label: input.label, notAfter: file.expDate, source: 'brain' });
    });
  } catch (err) {
    const e = err as { code?: string; constraint?: string };
    // The same content token is live in this tenant or another one: never say where (S-18).
    if (e.code === '23505' && String(e.constraint ?? '').includes('tenant_apple_vpp_tokens_live')) {
      throw new AppError(409, 'This content token is already connected', 'vppTokenAlreadyUsed');
    }
    throw err;
  }
  let outcome: ImportOutcome['outcome'] = 'pending';
  try {
    outcome = (await configureClient(tenantId, id, { secret: s.secret, actor })) === 'foreign' ? 'foreign_mdm' : 'active';
  } catch (err) {
    if (isVppApiError(err) && err.kind === 'token_rejected') {
      // Never usable: nothing is kept of it.
      await db.transaction(async (trx) => {
        await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).del();
        await retireDeadline(trx, tenantId, 'vpp_token', id);
      });
      rethrowVpp(err);
    }
    // Kept: the configuration is done again, with a new secret, by the next synchronisation.
    logVppFailure('client/config at the import', id, err);
    await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).update({
      consecutive_errors: 1, last_error_code: CONFIG_PENDING, updated_at: new Date(),
    });
  }
  if (outcome !== 'foreign_mdm') await send().syncToken(null, tenantId, id, true);
  realtime.integrationChanged(tenantId, 'vpp');
  return { view: await getVppToken(db, tenantId, id), outcome };
}

/** A token used by another MDM, before its takeover is asked: the facts the console warns with. */
export async function checkTakeover(q: Knex | Knex.Transaction, tenantId: number, id: string): Promise<{ label: string; locationName: string | null }> {
  const r = await tokenRow(q, tenantId, id);
  if (r.state !== 'foreign_mdm') throw new AppError(409, 'This content token is not used by another MDM', 'vppTokenNotForeign');
  return { label: r.label, locationName: r.location_name };
}

/** « Reprendre le jeton » (decision of 15/10): mdmInfo overwritten; the guard is the caller's (route or approval). */
export async function takeOverVppToken(tenantId: number, id: string, actor: DbActor): Promise<VppTokenView> {
  await checkTakeover(db, tenantId, id);
  try {
    await configureClient(tenantId, id, { takeover: true, actor });
  } catch (err) {
    await recordCallError(tenantId, id, err);
    rethrowVpp(err);
  }
  await send().syncToken(null, tenantId, id, true);
  return getVppToken(db, tenantId, id);
}

/** « Remplacer le jeton » (the yearly renewal): a new file of the same location; a new notification secret. */
export async function replaceVppToken(tenantId: number, id: string, file: VppTokenFile, actor: DbActor): Promise<VppTokenView> {
  const r = await tokenRow(db, tenantId, id);
  let probe: VppClientConfig;
  try {
    probe = await vppClient(id, file.sToken).getClientConfig();
  } catch (err) { rethrowVpp(err); }
  if (r.location_uid && probe!.uId && probe!.uId !== r.location_uid) {
    throw new AppError(422, 'This content token belongs to another location of Apple Business', 'vppTokenOtherLocation');
  }
  try {
    await db.transaction(async (trx) => {
      await tokenRow(trx, tenantId, id, { lock: true });
      const sealed = await vault.seal(locator(r), file.sToken, { trx, requestTenantId: tenantId });
      await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).update({
        s_token_enc: sealed, s_token_sha256: sha256Hex(file.sToken), exp_date: file.expDate, org_name: file.orgName ?? r.org_name,
        state: r.state === 'foreign_mdm' ? 'foreign_mdm' : 'active', state_at: new Date(), last_error_code: CONFIG_PENDING, updated_at: new Date(),
      });
      await recordDeadline(trx, tenantId, { kind: 'vpp_token', subjectRef: id, label: r.label, notAfter: file.expDate, source: 'brain' });
    });
  } catch (err) {
    const e = err as { code?: string; constraint?: string };
    if (e.code === '23505' && String(e.constraint ?? '').includes('tenant_apple_vpp_tokens_live')) {
      throw new AppError(409, 'This content token is already connected', 'vppTokenAlreadyUsed');
    }
    throw err;
  }
  if (r.state !== 'foreign_mdm') {
    try { await configureClient(tenantId, id, { actor }); } catch (err) { await recordCallError(tenantId, id, err); rethrowVpp(err); }
    await send().syncToken(null, tenantId, id, true);
  }
  return getVppToken(db, tenantId, id);
}

/** « Supprimer » : the row 'removed' (its licences are no longer managed here), its operations abandoned. */
export async function removeVppToken(tenantId: number, id: string): Promise<{ label: string }> {
  const out = await db.transaction(async (trx) => {
    const r = await tokenRow(trx, tenantId, id, { lock: true });
    const now = new Date();
    await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).update({ state: 'removed', state_at: now, removed_at: now, updated_at: now });
    await trx('vpp_operations').where({ tenant_id: tenantId, vpp_token_id: id }).whereIn('state', ['requested', 'pending'])
      .update({ state: 'abandoned', completed_at: now, updated_at: now, result_summary: JSON.stringify({ reason: 'token_removed' }) });
    await trx('vpp_assignments').where({ tenant_id: tenantId, vpp_token_id: id }).whereIn('state', ['associating', 'disassociating'])
      .update({ state: 'failed', pending_operation_id: null, updated_at: now });
    await retireDeadline(trx, tenantId, 'vpp_token', id);
    // Its location is free again for the instance (INT-INTC-R9).
    await trx.raw('SELECT obligarth.vpp_location_release(?::uuid)', [id]);
    for (const k of ['vpp.foreign_mdm', 'vpp.token_invalid', 'vpp.notification_auth_failed'] as const) await resolveInTx(trx, tenantId, k, id);
    for (const fn of syncedHooks) await fn(trx, tenantId, id);
    return { label: r.label };
  });
  realtime.integrationChanged(tenantId, 'vpp');
  return out;
}

// ── Notifications ──────────────────────────────────────────────────────────────

/** Wrong secrets per token in the current hour (this process). */
const authFailures = new Map<string, { hour: number; count: number }>();

/**
 * A notification of Apple for the token of `ref` in the tenant (the caller is in its context). The status to answer:
 * 404 (no such live token), 401 (wrong secret), 400 (no type), 200.
 */
export async function receiveNotification(tenantId: number, ref: string, authorization: string | undefined, body: unknown): Promise<number> {
  if (!/^[A-Za-z0-9_-]{16,32}$/.test(ref)) return 404;
  const r = await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, notification_ref: ref }).whereNot('state', 'removed')
    .first('id', 'label', 'notification_secret_hash') as { id: string; label: string; notification_secret_hash: string } | undefined;
  if (!r) return 404;
  if (!bearerMatches(authorization, r.notification_secret_hash)) {
    const hour = Math.floor(Date.now() / 3_600_000);
    const c = authFailures.get(r.id);
    const count = c && c.hour === hour ? c.count + 1 : 1;
    authFailures.set(r.id, { hour, count });
    if (count > AUTH_FAIL_THRESHOLD) {
      await db.transaction((trx) => raiseInTx(trx, tenantId, 'vpp.notification_auth_failed', {
        discriminant: r.id, params: { count, label: r.label }, navigateTo: '/integrations',
      })).catch((err) => logger.warn({ code: (err as { code?: unknown })?.code ?? null }, 'apps and books: alert not raised'));
    }
    return 401;
  }
  const doc = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
  const type = typeof doc?.notificationType === 'string' && /^[A-Z_]{1,32}$/.test(doc.notificationType) ? doc.notificationType : null;
  if (!doc || !type) return 400;
  const now = new Date();
  if (type === 'TEST_NOTIFICATION') {
    await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: r.id }).update({ test_notification_at: now, last_notification_at: now });
    return 200;
  }
  const notificationId = typeof doc.notificationId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(doc.notificationId) ? doc.notificationId : null;
  await db.transaction(async (trx) => {
    const inboxId = randomUUID();
    const ins = (await trx.raw(`
      INSERT INTO obligarth.vpp_notifications_inbox (id, tenant_id, vpp_token_id, notification_type, notification_id, payload)
      VALUES (?, ?, ?, ?, ?, ?::jsonb)
      ON CONFLICT (vpp_token_id, notification_id) WHERE notification_id IS NOT NULL DO NOTHING
      RETURNING id`, [inboxId, tenantId, r.id, type, notificationId, JSON.stringify(doc)])).rows as Array<{ id: string }>;
    await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: r.id }).update({ last_notification_at: now });
    if (ins.length) await send().notification(trx, tenantId, inboxId);
  });
  return 200;
}

/** vpp.notification: what a notification hastens (never what ends an operation). */
export async function processNotification(tenantId: number, inboxId: string): Promise<{ type: string | null; outcome: string }> {
  const row = await db('vpp_notifications_inbox').where({ tenant_id: tenantId, id: inboxId }).first() as
    { id: string; vpp_token_id: string; notification_type: string; payload: unknown; processed_at: Date | null } | undefined;
  if (!row) return { type: null, outcome: 'gone' };
  if (row.processed_at) return { type: row.notification_type, outcome: 'already' };
  const doc = parse<Record<string, unknown>>(row.payload, {});
  const n = doc.notification && typeof doc.notification === 'object' ? doc.notification as Record<string, unknown> : {};
  let outcome = 'recorded';
  await db.transaction(async (trx) => {
    if (row.notification_type === 'ASSET_MANAGEMENT' || row.notification_type === 'USER_MANAGEMENT') {
      const eventId = typeof n.eventId === 'string' ? n.eventId.slice(0, 64) : null;
      const op = eventId ? await trx('vpp_operations').where({ tenant_id: tenantId, vpp_token_id: row.vpp_token_id, event_id: eventId })
        .first('id', 'state') as { id: string; state: string } | undefined : undefined;
      if (op && op.state === 'pending') {
        await send().eventStatus(trx, tenantId, op.id, 0);
        outcome = 'status_requested';
      } else outcome = op ? 'operation_not_pending' : 'operation_unknown';
    } else if (row.notification_type === 'ASSET_COUNT' || row.notification_type === 'USER_ASSOCIATED') {
      await send().syncToken(trx, tenantId, row.vpp_token_id, false);
      outcome = 'sync_requested';
    }
    await trx('vpp_notifications_inbox').where({ tenant_id: tenantId, id: inboxId })
      .update({ processed_at: new Date(), attempts: trx.raw('attempts + 1') });
  });
  return { type: row.notification_type, outcome };
}

// ── Operations ─────────────────────────────────────────────────────────────────

const chunk = <T>(list: T[], n: number): T[][] => {
  if (list.length === 0) return [[]];
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += Math.max(1, n)) out.push(list.slice(i, i + Math.max(1, n)));
  return out;
};

async function liveToken(trx: Knex.Transaction, tenantId: number, tokenId: string): Promise<TokenRow> {
  const r = await tokenRow(trx, tenantId, tokenId);
  if (r.state !== 'active') throw new AppError(409, 'This content token is not active', 'vppTokenNotActive', { state: r.state });
  return r;
}

const opView = (r: OperationRow): VppOperationView => ({
  id: r.id, tokenId: r.vpp_token_id, kind: r.kind, state: r.state, request: parse<Record<string, unknown>>(r.request, {}),
  resultSummary: parse<Record<string, unknown> | null>(r.result_summary, null), requestedByRef: r.requested_by_ref,
});

/**
 * Records the operation(s) in trx (split by the limits of service/config) and enqueues vpp.operation-submit.
 * associate: the targets' rows of vpp_assignments become 'associating' (device_id from `deviceOfSerial`);
 * disassociate, revoke: 'disassociating'.
 */
export async function requestAssets(trx: Knex.Transaction, tenantId: number, tokenId: string, kind: 'associate' | 'disassociate' | 'revoke',
  req: { assets: VppAssetRef[]; serialNumbers?: string[]; clientUserIds?: string[]; requestedByRef: string; deviceOfSerial?: Map<string, number> }): Promise<string[]> {
  await liveToken(trx, tenantId, tokenId);
  const serials = [...new Set(req.serialNumbers ?? [])].filter((s) => /^[A-Za-z0-9-]{1,64}$/.test(s));
  const users = [...new Set(req.clientUserIds ?? [])].filter((s) => /^[A-Za-z0-9_.:@-]{1,64}$/.test(s));
  const assets = req.assets.filter((a) => /^[0-9]{1,20}$/.test(a.adamId)).map((a) => ({ adamId: a.adamId, pricingParam: a.pricingParam || 'STDQ' }));
  if ((kind !== 'revoke' && assets.length === 0) || serials.length + users.length === 0) return [];
  const l = cachedLimits();
  const ids: string[] = [];
  const now = new Date();
  for (const a of kind === 'revoke' ? [assets] : chunk(assets, l.maxAssets)) {
    for (const s of chunk(serials, l.maxSerialNumbers)) {
      for (const u of chunk(users, l.maxClientUserIds)) {
        if (s.length + u.length === 0) continue;
        const id = randomUUID();
        await trx('vpp_operations').insert({
          id, tenant_id: tenantId, vpp_token_id: tokenId, kind, state: 'requested',
          request: JSON.stringify({ assets: a, ...(s.length ? { serialNumbers: s } : {}), ...(u.length ? { clientUserIds: u } : {}) }),
          requested_by_ref: req.requestedByRef.slice(0, 100),
        });
        if (kind === 'associate') {
          const rows = a.flatMap((x) => [
            ...s.map((sn) => ({ adam_id: x.adamId, pricing_param: x.pricingParam, serial_number: sn, client_user_id: null, device_id: req.deviceOfSerial?.get(sn) ?? null })),
            ...u.map((cu) => ({ adam_id: x.adamId, pricing_param: x.pricingParam, serial_number: null, client_user_id: cu, device_id: null })),
          ]);
          for (const r of rows) {
            await trx.raw(`
              INSERT INTO obligarth.vpp_assignments AS v (tenant_id, vpp_token_id, adam_id, pricing_param, serial_number, client_user_id, device_id,
                                                         state, pending_operation_id, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, 'associating', ?, ?)
              ON CONFLICT (tenant_id, vpp_token_id, adam_id, pricing_param, (coalesce(serial_number, '')), (coalesce(client_user_id, '')))
              DO UPDATE SET state = CASE WHEN v.state = 'associated' THEN v.state ELSE 'associating' END,
                            pending_operation_id = CASE WHEN v.state = 'associated' THEN v.pending_operation_id ELSE EXCLUDED.pending_operation_id END,
                            device_id = COALESCE(EXCLUDED.device_id, v.device_id), updated_at = EXCLUDED.updated_at`,
            [tenantId, tokenId, r.adam_id, r.pricing_param, r.serial_number, r.client_user_id, r.device_id, id, now]);
          }
        } else {
          const q = trx('vpp_assignments').where({ tenant_id: tenantId, vpp_token_id: tokenId })
            .where((w) => { if (s.length) w.orWhereIn('serial_number', s); if (u.length) w.orWhereIn('client_user_id', u); });
          if (kind === 'disassociate') q.whereIn(['adam_id', 'pricing_param'], a.map((x) => [x.adamId, x.pricingParam]));
          await q.update({ state: 'disassociating', pending_operation_id: id, updated_at: now });
        }
        await send().submit(trx, tenantId, id, 1);
        ids.push(id);
      }
    }
  }
  return ids;
}

/** The users of Apps and Books (a user licence of a personal device): users_create, users_update, users_retire. */
export async function requestUsers(trx: Knex.Transaction, tenantId: number, tokenId: string, kind: 'users_create' | 'users_update' | 'users_retire',
  users: Array<{ clientUserId: string; managedAppleId?: string }>, requestedByRef: string): Promise<string[]> {
  await liveToken(trx, tenantId, tokenId);
  const clean = users.filter((u) => /^[A-Za-z0-9_.:@-]{1,64}$/.test(u.clientUserId))
    .map((u) => ({ clientUserId: u.clientUserId, ...(u.managedAppleId ? { managedAppleId: u.managedAppleId.slice(0, 320) } : {}) }));
  const ids: string[] = [];
  for (const part of chunk(clean, cachedLimits().maxUsers)) {
    if (part.length === 0) continue;
    const id = randomUUID();
    await trx('vpp_operations').insert({
      id, tenant_id: tenantId, vpp_token_id: tokenId, kind, state: 'requested', request: JSON.stringify({ users: part }), requested_by_ref: requestedByRef.slice(0, 100),
    });
    await send().submit(trx, tenantId, id, 1);
    ids.push(id);
  }
  return ids;
}

async function operationRow(q: Knex | Knex.Transaction, tenantId: number, id: string, lock = false): Promise<OperationRow | null> {
  let qb = q('vpp_operations').where({ tenant_id: tenantId, id });
  if (lock) qb = qb.forUpdate();
  return (await qb.first() as OperationRow | undefined) ?? null;
}

export type SubmitOutcome = 'submitted' | 'not_requested' | 'failed' | 'token_inactive';

/** vpp.operation-submit: the call of Apple, its eventId kept, the first look at the status scheduled. Throws a
 *  retryable error on a rate limit or an outage (the job's retries). */
export async function submitOperation(tenantId: number, id: string): Promise<SubmitOutcome> {
  const op = await operationRow(db, tenantId, id);
  if (!op || op.state !== 'requested') return 'not_requested';
  const token = await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: op.vpp_token_id }).first() as TokenRow | undefined;
  if (!token || token.state !== 'active') {
    await finishOperation(tenantId, id, { state: 'abandoned', code: `token_${token?.state ?? 'gone'}` });
    return 'token_inactive';
  }
  const req = parse<Record<string, any>>(op.request, {});
  const calls = await callsOf(token);
  let eventId: string;
  let expiry: Date | null;
  try {
    const r = op.kind === 'associate' || op.kind === 'disassociate' || op.kind === 'revoke'
      ? await calls.assetsOperation(op.kind, { assets: req.assets ?? [], serialNumbers: req.serialNumbers, clientUserIds: req.clientUserIds })
      : await calls.usersOperation(op.kind, req.users ?? []);
    eventId = r.eventId;
    expiry = r.tokenExpiry;
  } catch (err) {
    if (isVppApiError(err) && (err.kind === 'rate_limited' || err.kind === 'unavailable' || err.kind === 'network')) throw err;
    if (isVppApiError(err) && err.kind === 'token_rejected') await markTokenInvalid(tenantId, token.id, err.code);
    await finishOperation(tenantId, id, { state: 'failed', code: isVppApiError(err) ? err.code : 'error' });
    return 'failed';
  }
  await db.transaction(async (trx) => {
    const cur = await operationRow(trx, tenantId, id, true);
    if (!cur || cur.state !== 'requested') return;
    await trx('vpp_operations').where({ tenant_id: tenantId, id }).update({ event_id: eventId, state: 'pending', status_polls: 0, updated_at: new Date() });
    if (expiry) await moveExpiry(trx, tenantId, token, expiry);
    await send().eventStatus(trx, tenantId, id, FIRST_POLL_SECONDS);
  });
  return 'submitted';
}

async function moveExpiry(trx: Knex.Transaction, tenantId: number, token: Pick<TokenRow, 'id' | 'label' | 'exp_date'>, expiry: Date): Promise<void> {
  if (new Date(token.exp_date).getTime() === expiry.getTime()) return;
  await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: token.id }).update({ exp_date: expiry, updated_at: new Date() });
  await recordDeadline(trx, tenantId, { kind: 'vpp_token', subjectRef: token.id, label: token.label, notAfter: expiry, source: 'brain' });
}

export type StatusOutcome = 'complete' | 'failed' | 'pending' | 'replayed' | 'not_pending';

/** vpp.event-status: the status of an operation's event at Apple (S-17: what ends an operation). */
export async function checkOperationStatus(tenantId: number, id: string, now = new Date()): Promise<StatusOutcome> {
  const op = await operationRow(db, tenantId, id);
  if (!op || op.state !== 'pending' || !op.event_id) return 'not_pending';
  const token = await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: op.vpp_token_id }).first() as TokenRow | undefined;
  if (!token || token.state === 'removed') {
    await finishOperation(tenantId, id, { state: 'abandoned', code: 'token_removed' });
    return 'failed';
  }
  let ev: VppEvent;
  try {
    ev = await (await callsOf(token)).status(op.event_id);
  } catch (err) {
    if (isVppApiError(err) && err.kind === 'token_rejected') {
      await markTokenInvalid(tenantId, token.id, err.code);
      await finishOperation(tenantId, id, { state: 'failed', code: err.code });
      return 'failed';
    }
    throw err;
  }
  if (ev.tokenExpiry) await db.transaction((trx) => moveExpiry(trx, tenantId, token, ev.tokenExpiry!));
  if (ev.status === 'COMPLETE') {
    await finishOperation(tenantId, id, { state: 'complete', event: ev });
    return 'complete';
  }
  if (ev.status === 'FAILED') {
    await finishOperation(tenantId, id, { state: 'failed', event: ev, code: 'event_failed' });
    return 'failed';
  }
  const summary = parse<Record<string, unknown>>(op.result_summary, {});
  const age = now.getTime() - new Date(op.updated_at).getTime();
  if (age < REPLAY_AFTER_MS) {
    await db.transaction(async (trx) => {
      await trx('vpp_operations').where({ tenant_id: tenantId, id, state: 'pending' }).update({ status_polls: trx.raw('status_polls + 1') });
      await send().eventStatus(trx, tenantId, id, NEXT_POLL_SECONDS);
    });
    return 'pending';
  }
  if (summary.replayed !== true) {
    // Still pending after 10 minutes: submitted again, once (06 §4.9).
    await db.transaction(async (trx) => {
      const n = await trx('vpp_operations').where({ tenant_id: tenantId, id, state: 'pending' }).update({
        state: 'requested', event_id: null, status_polls: 0, updated_at: now,
        result_summary: JSON.stringify({ replayed: true, previousEventId: op.event_id }),
      });
      if (n) await send().submit(trx, tenantId, id, 2);
    });
    return 'replayed';
  }
  await finishOperation(tenantId, id, { state: 'failed', code: 'timeout' });
  return 'failed';
}

/** The end of an operation, in one transaction: its row, the mirror of the assignments, the alert, the hooks. */
export async function finishOperation(tenantId: number, id: string, o: { state: 'complete' | 'failed' | 'abandoned'; event?: VppEvent; code?: string }): Promise<void> {
  await db.transaction(async (trx) => {
    const op = await operationRow(trx, tenantId, id, true);
    if (!op || op.state === 'complete' || op.state === 'failed' || op.state === 'abandoned') return;
    const before = parse<Record<string, unknown>>(op.result_summary, {});
    const failures = o.event?.failures ?? [];
    const codes = [...new Set(failures.map((f) => f.errorNumber).filter((n): n is number => n !== null))].slice(0, 10);
    const summary = {
      ...(before.replayed ? { replayed: true } : {}), failures: failures.length, ...(codes.length ? { errorNumbers: codes } : {}),
      ...(o.code ? { code: o.code.slice(0, 64) } : {}),
      ...(o.event?.numCompleted !== null && o.event?.numCompleted !== undefined ? { numCompleted: o.event.numCompleted } : {}),
      ...(o.event?.numRequested !== null && o.event?.numRequested !== undefined ? { numRequested: o.event.numRequested } : {}),
    };
    const now = new Date();
    await trx('vpp_operations').where({ tenant_id: tenantId, id }).update({ state: o.state, completed_at: now, updated_at: now, result_summary: JSON.stringify(summary) });
    // The mirror of the assignments the operation was about.
    const failed = new Set(failures.map((f) => `${f.adamId ?? '*'}|${f.serialNumber ?? ''}|${f.clientUserId ?? ''}`));
    const isFailed = (r: { adam_id: string; serial_number: string | null; client_user_id: string | null }): boolean =>
      failed.has(`${r.adam_id}|${r.serial_number ?? ''}|${r.client_user_id ?? ''}`) || failed.has(`*|${r.serial_number ?? ''}|${r.client_user_id ?? ''}`);
    const rows = await trx('vpp_assignments').where({ tenant_id: tenantId, pending_operation_id: id }).forUpdate()
      .select('id', 'adam_id', 'serial_number', 'client_user_id', 'state') as Array<{ id: number; adam_id: string; serial_number: string | null; client_user_id: string | null; state: string }>;
    for (const r of rows) {
      const ok = o.state === 'complete' && !isFailed(r);
      if (op.kind === 'associate') {
        await trx('vpp_assignments').where({ tenant_id: tenantId, id: r.id }).update({ state: ok ? 'associated' : 'failed', pending_operation_id: null, updated_at: now });
      } else if (ok) {
        await trx('vpp_assignments').where({ tenant_id: tenantId, id: r.id }).del();
      } else {
        await trx('vpp_assignments').where({ tenant_id: tenantId, id: r.id }).update({ state: 'associated', pending_operation_id: null, updated_at: now });
      }
    }
    if (o.state === 'failed' || failures.length > 0) {
      await raiseCountedInTx(trx, tenantId, 'vpp.operation_failed', { at: now, eventId: id }, { discriminant: op.vpp_token_id, navigateTo: '/integrations' });
    }
    const view = opView({ ...op, state: o.state, result_summary: summary });
    for (const fn of finalHooks) await fn(trx, tenantId, view);
  });
  realtime.integrationChanged(tenantId, 'vpp');
}

// ── Synchronisation ────────────────────────────────────────────────────────────

export { platformsOfAsset };

export interface SyncOutcome { outcome: 'synced' | 'foreign_mdm' | 'skipped' | 'invalid'; assets: number; assignments: number; changed: boolean }

const MAX_PAGES = 500;

/** vpp.sync-token (§11.3, synchronisation). `full`: every assignment listed (those Apple no longer lists leave the
 *  mirror), else those since the last versionId. Errors other than a refusal of the token are thrown (retries). */
export async function syncToken(tenantId: number, id: string, o: { full: boolean; actor: DbActor }): Promise<SyncOutcome> {
  const skip: SyncOutcome = { outcome: 'skipped', assets: 0, assignments: 0, changed: false };
  let r = await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).first() as TokenRow | undefined;
  if (!r || r.state === 'removed' || r.state === 'invalid') return skip;
  if (new Date(r.exp_date).getTime() <= Date.now()) {
    if (r.state !== 'expired') {
      await db('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id }).update({ state: 'expired', state_at: new Date(), updated_at: new Date() });
      realtime.integrationChanged(tenantId, 'vpp');
    }
    return skip;
  }
  try {
    if (r.last_error_code === CONFIG_PENDING && r.state !== 'foreign_mdm') {
      await configureClient(tenantId, id, { actor: o.actor });
      r = await tokenRow(db, tenantId, id);
    }
    const calls = await callsOf(r);
    const cfg = await calls.getClientConfig();
    const tenantUuid = (await db('tenants').where({ id: tenantId }).first('uuid') as { uuid: string } | undefined)?.uuid ?? null;
    if (!mdmInfoIsOurs(cfg, r.mdm_info_id, tenantUuid)) {
      if (r.state !== 'foreign_mdm') await markForeign(tenantId, id, r.label);
      return { ...skip, outcome: 'foreign_mdm' };
    }
    if (r.state === 'foreign_mdm') return { ...skip, outcome: 'foreign_mdm' };
    // A location another tenant of this instance claimed (taken over by it, or configured first), whether Apple echoes
    // the metadata or not (INT-INTC-R9): 'foreign_mdm' here too.
    if (!(await claimLocation(db, id, cfg.uId ?? r.location_uid, false))) {
      await markForeign(tenantId, id, r.label);
      return { ...skip, outcome: 'foreign_mdm' };
    }
    if (!cfg.mdmInfo?.id) {
      // Our configuration was cleared (by an administrator at Apple): written again, with a new secret.
      await configureClient(tenantId, id, { actor: o.actor });
    }
    const assets: VppAssetRow[] = [];
    for (let page = 0, n = 0; n < MAX_PAGES; n++) {
      const p = await calls.assets(page);
      assets.push(...p.items);
      if (p.nextPageIndex === null || p.nextPageIndex <= page) break;
      page = p.nextPageIndex;
    }
    const full = o.full || !r.assignments_version_id;
    const assignments: VppAssignmentRow[] = [];
    let versionId: string | null = r.assignments_version_id;
    for (let page = 0, n = 0; n < MAX_PAGES; n++) {
      const p = await calls.assignments(page, full ? null : r.assignments_version_id);
      assignments.push(...p.items);
      if (p.versionId) versionId = p.versionId;
      if (p.nextPageIndex === null || p.nextPageIndex <= page) break;
      page = p.nextPageIndex;
    }
    const changed = await db.transaction((trx) => writeMirror(trx, tenantId, r!, { cfg, assets, assignments, full, versionId }));
    realtime.integrationChanged(tenantId, 'vpp');
    return { outcome: 'synced', assets: assets.length, assignments: assignments.length, changed };
  } catch (err) {
    await recordCallError(tenantId, id, err);
    if (isVppApiError(err) && err.kind === 'token_rejected') return { ...skip, outcome: 'invalid' };
    throw err;
  }
}

async function writeMirror(trx: Knex.Transaction, tenantId: number, r: TokenRow, s: { cfg: VppClientConfig; assets: VppAssetRow[];
  assignments: VppAssignmentRow[]; full: boolean; versionId: string | null }): Promise<boolean> {
  const now = new Date();
  const row = await tokenRow(trx, tenantId, r.id, { lock: true });
  if (row.state !== 'active') return false;
  let changed = false;
  // Assets: upsert, those Apple no longer lists deleted.
  const before = new Map((await trx('vpp_assets').where({ tenant_id: tenantId, vpp_token_id: r.id }).select('adam_id', 'pricing_param', 'available_count') as
    Array<{ adam_id: string; pricing_param: string; available_count: number }>).map((x) => [`${x.adam_id}|${x.pricing_param}`, Number(x.available_count)]));
  const seen = new Set<string>();
  for (const a of s.assets) {
    const k = `${a.adamId}|${a.pricingParam}`;
    if (seen.has(k)) continue;
    seen.add(k);
    if (before.get(k) !== a.availableCount) changed = true;
    await trx('vpp_assets').insert({
      tenant_id: tenantId, vpp_token_id: r.id, adam_id: a.adamId, pricing_param: a.pricingParam, product_type: a.productType,
      device_assignable: a.deviceAssignable, revocable: a.revocable, supported_platforms: JSON.stringify(a.supportedPlatforms),
      total_count: a.totalCount, assigned_count: a.assignedCount, available_count: a.availableCount, retired_count: a.retiredCount, updated_at: now,
    }).onConflict(['tenant_id', 'vpp_token_id', 'adam_id', 'pricing_param']).merge([
      'product_type', 'device_assignable', 'revocable', 'supported_platforms', 'total_count', 'assigned_count', 'available_count', 'retired_count', 'updated_at',
    ]);
  }
  const gone = [...before.keys()].filter((k) => !seen.has(k));
  if (gone.length) {
    changed = true;
    await trx('vpp_assets').where({ tenant_id: tenantId, vpp_token_id: r.id }).whereIn(['adam_id', 'pricing_param'], gone.map((k) => k.split('|'))).del();
  }
  // Assignments: what Apple lists is associated (an operation in progress keeps its row's state).
  const serials = [...new Set(s.assignments.map((a) => a.serialNumber).filter((x): x is string => !!x))];
  const deviceOf = new Map<string, number>();
  for (let i = 0; i < serials.length; i += 500) {
    const rows = await trx('devices').where({ tenant_id: tenantId }).whereIn('serial_number', serials.slice(i, i + 500)).whereNot('enrollment_state', 'unenrolled')
      .select('id', 'serial_number') as Array<{ id: number; serial_number: string }>;
    for (const d of rows) deviceOf.set(d.serial_number, Number(d.id));
  }
  const listed = new Set<string>();
  for (const a of s.assignments) {
    listed.add(`${a.adamId}|${a.pricingParam}|${a.serialNumber ?? ''}|${a.clientUserId ?? ''}`);
    await trx.raw(`
      INSERT INTO obligarth.vpp_assignments AS v (tenant_id, vpp_token_id, adam_id, pricing_param, serial_number, client_user_id, device_id, state, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'associated', ?)
      ON CONFLICT (tenant_id, vpp_token_id, adam_id, pricing_param, (coalesce(serial_number, '')), (coalesce(client_user_id, '')))
      DO UPDATE SET state = CASE WHEN v.state IN ('associating', 'disassociating') THEN v.state ELSE 'associated' END,
                    device_id = COALESCE(EXCLUDED.device_id, v.device_id), updated_at = EXCLUDED.updated_at`,
    [tenantId, r.id, a.adamId, a.pricingParam, a.serialNumber, a.clientUserId, a.serialNumber ? deviceOf.get(a.serialNumber) ?? null : null, now]);
  }
  if (s.full) {
    const mine = await trx('vpp_assignments').where({ tenant_id: tenantId, vpp_token_id: r.id, state: 'associated' })
      .select('id', 'adam_id', 'pricing_param', 'serial_number', 'client_user_id') as Array<{ id: number; adam_id: string; pricing_param: string; serial_number: string | null; client_user_id: string | null }>;
    const drop = mine.filter((m) => !listed.has(`${m.adam_id}|${m.pricing_param}|${m.serial_number ?? ''}|${m.client_user_id ?? ''}`)).map((m) => m.id);
    for (let i = 0; i < drop.length; i += 500) await trx('vpp_assignments').where({ tenant_id: tenantId }).whereIn('id', drop.slice(i, i + 500)).del();
    if (drop.length) changed = true;
  }
  // Metadata of the catalog the assets carry: the platforms.
  const byAdam = new Map<string, string[]>();
  for (const a of s.assets) byAdam.set(a.adamId, platformsOfAsset(a.supportedPlatforms));
  if (byAdam.size) {
    const apps = await trx('apps').where({ tenant_id: tenantId, platform_family: 'apple' }).whereNull('archived_at').whereIn('store_id', [...byAdam.keys()])
      .select('id', 'store_id', 'supported_platforms') as Array<{ id: number; store_id: string; supported_platforms: string[] | null }>;
    for (const app of apps) {
      const p = byAdam.get(String(app.store_id)) ?? [];
      if (p.length === 0) continue;
      const cur = [...(app.supported_platforms ?? [])].sort();
      if (cur.join(',') !== p.join(',')) {
        await trx('apps').where({ tenant_id: tenantId, id: app.id }).update({ supported_platforms: trx.raw('?::varchar[]', [p]), metadata_refreshed_at: now, updated_at: now });
      } else {
        await trx('apps').where({ tenant_id: tenantId, id: app.id }).update({ metadata_refreshed_at: now });
      }
    }
  }
  await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId, id: r.id }).update({
    location_name: s.cfg.locationName ?? row.location_name, location_uid: s.cfg.uId ?? row.location_uid,
    assignments_version_id: s.versionId, last_sync_at: now, consecutive_errors: 0,
    last_error_code: row.last_error_code === CONFIG_PENDING ? CONFIG_PENDING : null, updated_at: now,
  });
  if (s.cfg.tokenExpiry) await moveExpiry(trx, tenantId, row, s.cfg.tokenExpiry);
  // Purges (30 days), and the operations whose status was never looked at again (a lost job).
  const old = new Date(now.getTime() - PURGE_AFTER_DAYS * 86_400_000);
  await trx('vpp_operations').where({ tenant_id: tenantId, vpp_token_id: r.id }).whereIn('state', ['complete', 'failed', 'abandoned']).where('completed_at', '<', old).del();
  await trx('vpp_notifications_inbox').where({ tenant_id: tenantId, vpp_token_id: r.id }).whereNotNull('processed_at').where('processed_at', '<', old).del();
  const stale = await trx('vpp_operations').where({ tenant_id: tenantId, vpp_token_id: r.id, state: 'pending' })
    .where('updated_at', '<', new Date(now.getTime() - FIRST_POLL_SECONDS * 1000)).limit(200).pluck('id') as string[];
  for (const op of stale) await send().eventStatus(trx, tenantId, String(op), 0);
  for (const fn of syncedHooks) await fn(trx, tenantId, r.id);
  return changed;
}

/** « Synchroniser maintenant ». */
export async function requestVppSync(tenantId: number, id: string): Promise<void> {
  const r = await tokenRow(db, tenantId, id);
  if (r.state === 'invalid' || r.state === 'expired') throw new AppError(409, 'This content token is not usable: import a new one', 'vppTokenNotActive', { state: r.state });
  await send().syncToken(null, tenantId, id, true);
}

/** The live tokens of the tenant (the jobs' fan-out). */
export async function liveTokenIds(q: Knex | Knex.Transaction, tenantId: number): Promise<string[]> {
  return (await q('tenant_apple_vpp_tokens').where({ tenant_id: tenantId }).whereIn('state', ['active', 'foreign_mdm', 'expired']).pluck('id') as string[]).map(String);
}

// ── The interface of the delivery of the apps (§11.3) ───────────────────────────

export interface VppService {
  tokens(trx: Knex.Transaction, tenantId: number): Promise<Array<{ id: string; label: string; state: string; locationName: string | null; expDate: string }>>;
  requestAssets: typeof requestAssets;
  requestUsers: typeof requestUsers;
  onOperationFinal(fn: OperationFinalHook): void;
}

export const vpp: VppService = {
  async tokens(trx, tenantId) {
    const rows = await trx('tenant_apple_vpp_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').orderBy('created_at')
      .select('id', 'label', 'state', 'location_name', 'exp_date') as Array<{ id: string; label: string; state: string; location_name: string | null; exp_date: Date }>;
    return rows.map((r) => ({ id: r.id, label: r.label, state: r.state, locationName: r.location_name, expDate: iso(r.exp_date)! }));
  },
  requestAssets,
  requestUsers,
  onOperationFinal,
};
