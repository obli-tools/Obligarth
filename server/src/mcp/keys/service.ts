import type { Knex } from 'knex';
import {
  MASTER_TENANT_ID, MCP_KEY_BOUNDS, MCP_SCOPES, isMcpScope, type AccessKeyCreateBody, type AccessKeyView, type McpKeyRevokeReason,
  type McpPerimeterMode, type McpScope, type TenantOversightKeyView,
} from '@obligarth/shared';
import { audit, type AuditEntryInput, type AuditWriteContext } from '../../audit';
import { db } from '../../db';
import { asIdentity, asNone, asTenant, userActor } from '../../db/context';
import { AppError } from '../../middleware/errorHandler';
import { getIO } from '../../socket';
import { permissionService } from '../../services/permission.service';
import { tenantService } from '../../services/tenant.service';
import { logger } from '../../utils/logger';
import { SocketEvents } from '@obligarth/shared';
import { appendQuiet, systemCtx } from '../audit';
import type { McpKeyInfo, McpTarget } from '../caller';
import { inetText, parseCidr, pgTextArray, sameNetwork } from '../ipUtil';
import { invalidatePolicy } from '../ipPolicy';
import { effectiveTenants, targetsOf } from '../perimeter';
import { MCP_ACTOR, mcpSettings, tenantForcesIp, tenantIpPolicies } from '../settings';
import { newToken } from './secret';

// =============================================================================
// Personal access keys (docs: specs mcp-server §1.1, §6.1): creation within
// the owner's rights, listing, revocation (never a deletion), exclusion of a
// tenant by a tenant manager, the lookup of the authentication (identity
// context, actor i:mcp) and the last use. A key is bound to its owner's
// credential_version at creation: a password change, a TOTP change, an
// activation change or an Obligate link change revokes it at its next use, or
// at the next minute step (revokeStaleKeys) whichever comes first.
// =============================================================================

export const KEY_COLUMNS = [
  'id', 'public_id', 'kind', 'user_id', 'credential_version', 'name', 'secret_sha256', 'scopes', 'tenant_mode', 'group_mode', 'device_mode',
  'created_at', 'expires_at', 'created_ip', 'last_used_at', 'last_used_ip', 'revoked_at', 'revoked_by', 'revoke_reason',
];
const ipAllowCol = () => db.raw('ip_allow::text[] AS ip_allow');

export type KeyRow = Record<string, any>;

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);

export function keyInfoOf(r: KeyRow): McpKeyInfo {
  return {
    rowId: String(r.id), publicId: String(r.public_id), name: String(r.name),
    scopes: (Array.isArray(r.scopes) ? r.scopes : pgTextArray(r.scopes)).filter(isMcpScope),
    tenantMode: r.tenant_mode, groupMode: r.group_mode, deviceMode: r.device_mode, ipAllow: pgTextArray(r.ip_allow),
    expiresAt: new Date(r.expires_at), credentialVersion: Number(r.credential_version),
  };
}

/** The account has a factor that can approve an authorization: exactly checkSecondFactor's rule (§3.2 step 5). */
export function hasStepUpFactor(u: { totp_enabled?: unknown; totp_secret_enc?: unknown; foreign_source?: unknown; foreign_id?: unknown }): boolean {
  return !!(u.totp_enabled && u.totp_secret_enc) || (u.foreign_source === 'obligate' && !!u.foreign_id);
}

// ── Authentication lookup ───────────────────────────────────────────────────

/** The key of a public id and its perimeter rows (identity context). */
export async function lookupForAuth(publicId: string): Promise<{ row: KeyRow; targets: McpTarget[] } | null> {
  return asIdentity(MCP_ACTOR, async () => {
    const row = await db('access_keys').where({ public_id: publicId }).first([...KEY_COLUMNS, ipAllowCol()]) as KeyRow | undefined;
    if (!row) return null;
    const t = await db('access_key_targets').where({ key_id: row.id }).select('kind', 'tenant_id', 'ref_id') as Array<{ kind: string; tenant_id: number; ref_id: number | null }>;
    return { row, targets: targetsOf(t) };
  });
}

// ── Last use and new network (§3.2 step 8) ──────────────────────────────────

const lastTouch = new Map<string, number>();
/** The networks each key was seen from (one address per /24 or /48, newest last), seeded from its stored addresses. */
const keyNetworks = new Map<string, string[]>();
const NETWORKS_PER_KEY = 8;

/**
 * Last use of a key, fire and forget: the row is written at most once a minute per key, but the network of EVERY
 * request is compared (in memory) with the networks the key was seen from: a new one is written at once and told to
 * the owner, so that a stolen key used next to the owner's agent is never hidden behind the per-minute throttle.
 */
export function touchLastUsed(key: { rowId: string; publicId: string; name: string }, userId: number, ip: string): void {
  const now = Date.now();
  const due = (lastTouch.get(key.rowId) ?? 0) <= now - 60_000;
  const nets = keyNetworks.get(key.rowId);
  // Known in memory: decided now (two requests of a new network never both notify).
  let isNew = false;
  if (ip && nets && !nets.some((n) => sameNetwork(ip, n))) {
    isNew = true;
    nets.push(ip);
    if (nets.length > NETWORKS_PER_KEY) nets.shift();
  }
  if (!due && !isNew && nets) return;
  if (due) {
    if (lastTouch.size > 50_000) lastTouch.clear();
    lastTouch.set(key.rowId, now);
  }
  void (async () => {
    const prev = await asIdentity(MCP_ACTOR, async () => {
      const [r] = await db('access_keys').where({ id: key.rowId }).select('last_used_ip', 'created_ip') as Array<{ last_used_ip: string | null; created_ip: string | null }>;
      await db('access_keys').where({ id: key.rowId }).update({ last_used_at: new Date(), last_used_ip: ip || null });
      return r;
    });
    if (!ip || !prev) return;
    if (!nets) {
      // First request of this key since the start: the memory is seeded from the stored addresses.
      const last = inetText(prev.last_used_ip);
      const created = inetText(prev.created_ip);
      const seed = [last, created].filter((x): x is string => !!x);
      if (keyNetworks.size > 50_000) keyNetworks.clear();
      const list = keyNetworks.get(key.rowId) ?? seed;
      const known = list.length === 0 || list.some((n) => sameNetwork(ip, n));
      if (!list.some((n) => sameNetwork(ip, n))) list.push(ip);
      if (list.length > NETWORKS_PER_KEY) list.shift();
      keyNetworks.set(key.rowId, list);
      if (known) return;
    } else if (!isNew) {
      return;
    }
    const at = new Date().toISOString();
    logger.warn({ keyId: key.publicId, ip, userId }, 'mcp: access key used from a new network');
    try { getIO().to(`user:${userId}`).emit(SocketEvents.MCP_KEY_NEW_NETWORK, { keyId: key.publicId, name: key.name, ip, at }); } catch { /* no socket */ }
    await appendQuiet({
      tenantId: MASTER_TENANT_ID, action: 'mcp.key.new_network', target: { type: 'access_key', id: key.publicId },
      details: { publicId: key.publicId, ip, userId },
    }, systemCtx({ ip }));
  })().catch((err) => logger.warn({ err, keyId: key.publicId }, 'mcp: last use of a key not recorded'));
}

// ── Creation (§6.1) ─────────────────────────────────────────────────────────

export interface CreateInput {
  userId: number;
  isPlatformAdmin: boolean;
  body: AccessKeyCreateBody;
  createdIp: string | null;
  sessionTenantId: number;
  auditCtx: AuditWriteContext;
}

/** The tenants the user may put in a key: accessible now and holding mcp.access_keys (a platform admin: every tenant). */
export async function creatableTenants(userId: number, isPlatformAdmin: boolean): Promise<Array<{ id: number; name: string }>> {
  return asNone(userActor(userId), async () => {
    const list = isPlatformAdmin ? (await tenantService.getAll()).map((t) => ({ id: Number(t.id), name: t.name }))
      : (await tenantService.getTenantsForUser(userId)).map((t) => ({ id: Number(t.id), name: t.name }));
    if (isPlatformAdmin) return list;
    const out: Array<{ id: number; name: string }> = [];
    for (const t of list) if (await permissionService.userHasTenantCapability(userId, t.id, 'mcp.access_keys')) out.push(t);
    return out;
  });
}

/** The scopes the user may offer to a key in tenant T (§1.3): the tenant need, and a team row with the device capability. */
export async function offerableScopes(userId: number, isPlatformAdmin: boolean, tenantId: number): Promise<McpScope[]> {
  return asTenant(tenantId, userActor(userId), async () => {
    const out: McpScope[] = [];
    for (const [scope, def] of Object.entries(MCP_SCOPES) as Array<[McpScope, (typeof MCP_SCOPES)[McpScope]]>) {
      if (!isPlatformAdmin) {
        if (def.tenantNeed !== 'membership' && !(await permissionService.userHasTenantCapability(userId, tenantId, def.tenantNeed))) continue;
        const cap = 'deviceCapability' in def ? def.deviceCapability : undefined;
        if (cap && !(await permissionService.userHoldsDeviceCapabilityAnywhere(userId, tenantId, cap))) continue;
      }
      out.push(scope);
    }
    return out;
  });
}

const unprocessable = (message: string, code: string, details?: Record<string, unknown>): AppError => new AppError(422, message, code, details);

/** The IP allow-list of a creation, normalised, with the minimum prefixes (422 ipPrefixTooWide). */
export function normaliseIpAllow(list: readonly string[], minV4: number, minV6: number): string[] {
  const out = new Set<string>();
  for (const raw of list) {
    const c = parseCidr(raw);
    if (!c) throw unprocessable(`Invalid address or network: ${String(raw).slice(0, 64)}`, 'invalidIpAllow');
    if ((c.family === 4 && c.prefix < minV4) || (c.family === 6 && c.prefix < minV6)) {
      throw unprocessable(`Network too wide: ${c.text} (at least /${c.family === 4 ? minV4 : minV6})`, 'ipPrefixTooWide', { minPrefixV4: minV4, minPrefixV6: minV6 });
    }
    out.add(c.text);
  }
  if (out.size > MCP_KEY_BOUNDS.ipAllowMax) throw unprocessable(`At most ${MCP_KEY_BOUNDS.ipAllowMax} entries`, 'invalidIpAllow');
  return [...out];
}

/** Checks a creation within the owner's rights, then writes the key and its perimeter in one transaction. */
export async function createKey(input: CreateInput): Promise<{ row: KeyRow; token: string; targets: McpTarget[] }> {
  const { userId: U, isPlatformAdmin, body } = input;
  const settings = await mcpSettings(true);
  const policies = await tenantIpPolicies(true);

  // The owner has a factor that can later approve the key's authorizations (an e-mail OTP does not count).
  const user = await asNone(userActor(U), () => db('users').where({ id: U })
    .first('id', 'is_active', 'totp_enabled', 'totp_secret_enc', 'foreign_source', 'foreign_id')) as Record<string, any> | undefined;
  if (!user || user.is_active !== true) throw new AppError(401, 'Authentication required');
  if (!hasStepUpFactor(user)) {
    throw new AppError(403, 'Set up a second factor (TOTP) on your profile before creating an access key', 'twoFactorSetupRequired');
  }

  // Tenants: each listed one accessible and holding mcp.access_keys; 'all': at least one.
  const creatable = await creatableTenants(U, isPlatformAdmin);
  const creatableIds = new Set(creatable.map((t) => t.id));
  let perimeterTenants: number[];
  if (body.tenants.mode === 'list') {
    const ids = [...new Set((body.tenants.ids ?? []).map(Number))];
    if (ids.length === 0) throw unprocessable('Choose at least one tenant', 'invalidPerimeter');
    for (const id of ids) {
      if (!creatableIds.has(id)) throw new AppError(403, 'A tenant of the key is not one you may give it', 'tenantNotAllowed', { tenantId: id });
    }
    perimeterTenants = ids;
  } else {
    if (creatable.length === 0) throw new AppError(403, 'Capability mcp.access_keys held in no tenant', 'capabilityMissing');
    perimeterTenants = [...creatableIds];
  }

  // Scopes: each one offerable in at least one tenant of the perimeter.
  const scopes = [...new Set(body.scopes)];
  if (scopes.some((s) => !isMcpScope(s))) throw unprocessable('Unknown scope', 'scopeUnknown');
  const offered = new Set<McpScope>();
  for (const t of perimeterTenants) for (const s of await offerableScopes(U, isPlatformAdmin, t)) offered.add(s);
  for (const s of scopes) if (!offered.has(s)) throw unprocessable(`Scope not held: ${s}`, 'scopeNotHeld', { scope: s });

  // Groups and devices: in a tenant of the perimeter, visible to the owner now.
  const inPerimeter = new Set(perimeterTenants);
  const groups = body.groups.mode === 'list' ? (body.groups.items ?? []) : [];
  const devices = body.devices.mode === 'list' ? (body.devices.items ?? []) : [];
  if (body.groups.mode === 'list' && groups.length === 0) throw unprocessable('Choose at least one group', 'invalidPerimeter');
  if (body.devices.mode === 'list' && devices.length === 0) throw unprocessable('Choose at least one device', 'invalidPerimeter');
  for (const g of groups) {
    if (!inPerimeter.has(Number(g.tenantId))) throw new AppError(404, 'Group not found');
    const ok = await asTenant(Number(g.tenantId), userActor(U), async () => {
      const row = await db('device_groups').where({ tenant_id: g.tenantId, id: g.groupId }).first('id');
      return !!row && (isPlatformAdmin || permissionService.canReadGroup(U, Number(g.groupId), false));
    });
    if (!ok) throw new AppError(404, 'Group not found');
  }
  for (const d of devices) {
    if (!inPerimeter.has(Number(d.tenantId))) throw new AppError(404, 'Device not found');
    const ok = await asTenant(Number(d.tenantId), userActor(U), async () => {
      const row = await db('devices').where({ tenant_id: d.tenantId, id: d.deviceId }).first('id');
      return !!row && (isPlatformAdmin || permissionService.canReadDevice(U, Number(d.deviceId), false));
    });
    if (!ok) throw new AppError(404, 'Device not found');
  }

  // IP allow-list: minimum prefixes; required when a tenant of the perimeter forces it.
  const ipAllow = normaliseIpAllow(body.ipAllow ?? [], settings.minPrefixV4, settings.minPrefixV6);
  if (ipAllow.length === 0 && perimeterTenants.some((t) => tenantForcesIp(t, settings, policies))) {
    throw unprocessable('An IP allow-list is required by your administrator', 'ipAllowListRequired');
  }
  const days = Number(body.expiresInDays);
  if (!Number.isInteger(days) || days < 1 || days > MCP_KEY_BOUNDS.expiryDaysMax) throw unprocessable('Expiry: 1 to 365 days', 'invalidExpiry');

  const { publicId, token, sha256 } = newToken();
  const targets: McpTarget[] = [
    ...(body.tenants.mode === 'list' ? perimeterTenants.map((t) => ({ kind: 'tenant' as const, tenantId: t, refId: null })) : []),
    ...groups.map((g) => ({ kind: 'group' as const, tenantId: Number(g.tenantId), refId: Number(g.groupId) })),
    ...devices.map((d) => ({ kind: 'device' as const, tenantId: Number(d.tenantId), refId: Number(d.deviceId) })),
  ];
  const uniqueTargets = [...new Map(targets.map((t) => [`${t.kind}|${t.tenantId}|${t.refId ?? 0}`, t])).values()];

  const row = await asNone(userActor(U), () => db.transaction(async (trx) => {
    await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`access_keys:${U}`]);
    const active = await trx('access_keys').where({ user_id: U }).whereNull('revoked_at').where('expires_at', '>', trx.fn.now())
      .count<{ n: string }[]>('id as n').first();
    if (Number(active?.n ?? 0) >= MCP_KEY_BOUNDS.activeKeysPerUser) {
      throw unprocessable(`At most ${MCP_KEY_BOUNDS.activeKeysPerUser} active keys`, 'tooManyKeys');
    }
    const cv = await trx('users').where({ id: U }).first('credential_version') as { credential_version: number } | undefined;
    if (!cv) throw new AppError(401, 'Authentication required');
    const [k] = await trx('access_keys').insert({
      public_id: publicId, kind: 'key', user_id: U, credential_version: Number(cv.credential_version), name: body.name.trim(),
      secret_sha256: sha256, scopes, tenant_mode: body.tenants.mode, group_mode: body.groups.mode, device_mode: body.devices.mode,
      ip_allow: trx.raw('?::cidr[]', [ipAllow]), expires_at: trx.raw("now() + make_interval(days => ?)", [days]),
      created_ip: input.createdIp || null,
    }).returning([...KEY_COLUMNS]) as KeyRow[];
    k.ip_allow = ipAllow;
    if (uniqueTargets.length > 0) {
      await trx('access_key_targets').insert(uniqueTargets.map((t) => ({
        key_id: k.id, user_id: U, kind: t.kind, tenant_id: t.tenantId, ref_id: t.refId,
      })));
    }
    // Critical (P1): in the transaction of the key, in the session tenant's chain, each listed tenant's, and the master
    // tenant's for 'all'; the IPs only in the master and the session tenant entries.
    const chains = new Set<number>([input.sessionTenantId, ...(body.tenants.mode === 'list' ? perimeterTenants : [MASTER_TENANT_ID])]);
    const base = {
      publicId, name: body.name.trim(), scopes, tenants: { mode: body.tenants.mode, ids: body.tenants.mode === 'list' ? perimeterTenants : undefined },
      groups: { mode: body.groups.mode, count: groups.length }, devices: { mode: body.devices.mode, count: devices.length },
      expiresAt: iso(k.expires_at),
    };
    const entries: AuditEntryInput[] = [...chains].map((t) => ({
      tenantId: t, action: 'mcp.key.created', target: { type: 'access_key', id: publicId },
      details: { ...base, ...(t === MASTER_TENANT_ID || t === input.sessionTenantId ? { ipAllow } : {}) },
    }));
    await audit.appendManyInTx(trx, entries, input.auditCtx);
    return k;
  }));
  invalidatePolicy();
  return { row, token, targets: uniqueTargets };
}

// ── Views ───────────────────────────────────────────────────────────────────

export function keyState(r: KeyRow): AccessKeyView['state'] {
  if (r.revoked_at) return 'revoked';
  return new Date(r.expires_at).getTime() <= Date.now() ? 'expired' : 'active';
}

/** The owner's view of a key: names resolved only where the owner can still read them. */
export async function keyView(r: KeyRow, targets: McpTarget[], userId: number, isPlatformAdmin: boolean): Promise<AccessKeyView> {
  const info = keyInfoOf(r);
  const eff = keyState(r) === 'active'
    ? await effectiveTenants({ userId, isPlatformAdmin, key: info, targets }).catch(() => ({ tenants: [], outside: [] }))
    : { tenants: [], outside: [] };
  const readable = await asNone(userActor(userId), async () => {
    const list = isPlatformAdmin ? await tenantService.getAll() : await tenantService.getTenantsForUser(userId);
    return new Map(list.map((t) => [Number(t.id), t.name]));
  });
  const groupNames = new Map<string, string>();
  const deviceNames = new Map<string, string>();
  const byTenant = new Map<number, McpTarget[]>();
  for (const t of targets) if (t.kind === 'group' || t.kind === 'device') {
    if (!byTenant.has(t.tenantId)) byTenant.set(t.tenantId, []);
    byTenant.get(t.tenantId)!.push(t);
  }
  for (const [tenantId, list] of byTenant) {
    if (!readable.has(tenantId)) continue;
    await asTenant(tenantId, userActor(userId), async () => {
      const gids = list.filter((t) => t.kind === 'group').map((t) => Number(t.refId));
      const dids = list.filter((t) => t.kind === 'device').map((t) => Number(t.refId));
      if (gids.length) {
        for (const g of await db('device_groups').where({ tenant_id: tenantId }).whereIn('id', gids).select('id', 'name') as Array<{ id: number; name: string }>) {
          if (isPlatformAdmin || await permissionService.canReadGroup(userId, Number(g.id), false)) groupNames.set(`${tenantId}|${g.id}`, g.name);
        }
      }
      if (dids.length) {
        for (const d of await db('devices').where({ tenant_id: tenantId }).whereIn('id', dids).select('id', 'label') as Array<{ id: number; label: string | null }>) {
          if (isPlatformAdmin || await permissionService.canReadDevice(userId, Number(d.id), false)) deviceNames.set(`${tenantId}|${d.id}`, d.label ?? '');
        }
      }
    });
  }
  const mode = (m: unknown): McpPerimeterMode => (m === 'list' ? 'list' : 'all');
  return {
    id: info.publicId, name: info.name, scopes: info.scopes,
    tenants: { mode: mode(r.tenant_mode), items: targets.filter((t) => t.kind === 'tenant').map((t) => ({ tenantId: t.tenantId, name: readable.get(t.tenantId) ?? null })) },
    groups: { mode: mode(r.group_mode), items: targets.filter((t) => t.kind === 'group').map((t) => ({ tenantId: t.tenantId, groupId: Number(t.refId), name: groupNames.get(`${t.tenantId}|${t.refId}`) ?? null })) },
    devices: { mode: mode(r.device_mode), items: targets.filter((t) => t.kind === 'device').map((t) => ({ tenantId: t.tenantId, deviceId: Number(t.refId), name: deviceNames.get(`${t.tenantId}|${t.refId}`) ?? null })) },
    excludedTenants: targets.filter((t) => t.kind === 'tenant_excluded').map((t) => t.tenantId),
    ipAllow: info.ipAllow, createdAt: iso(r.created_at) as string, expiresAt: iso(r.expires_at) as string,
    lastUsedAt: iso(r.last_used_at), lastUsedIp: inetText(r.last_used_ip), revokedAt: iso(r.revoked_at),
    revokeReason: (r.revoke_reason ?? null) as McpKeyRevokeReason | null, state: keyState(r),
    effectiveNow: { tenants: eff.tenants.map((t) => t.id) },
  };
}

/** The keys of a user, newest first, with their perimeter rows. `asOwner`: read as the owner (identity_self). */
export async function keysOfUser(userId: number, asOwner = true): Promise<Array<{ row: KeyRow; targets: McpTarget[] }>> {
  const run = <T>(fn: () => Promise<T>) => (asOwner ? asNone(userActor(userId), fn) : asIdentity(MCP_ACTOR, fn));
  return run(async () => {
    const rows = await db('access_keys').where({ user_id: userId }).orderBy('created_at', 'desc').limit(200)
      .select([...KEY_COLUMNS, ipAllowCol()]) as KeyRow[];
    const ids = rows.map((r) => r.id);
    const t = ids.length === 0 ? [] : await db('access_key_targets').whereIn('key_id', ids).select('key_id', 'kind', 'tenant_id', 'ref_id') as Array<Record<string, any>>;
    return rows.map((row) => ({ row, targets: targetsOf(t.filter((x) => String(x.key_id) === String(row.id)) as Array<{ kind: string; tenant_id: number; ref_id: number | null }>) }));
  });
}

// ── Revocation (§1.1) ───────────────────────────────────────────────────────

/** Who or what caused a cancellation: journaled on each cancelled authorization (never the owner unless he acted). */
export interface CancelCause {
  /** The audit context of the person who acted (an administrator, a tenant manager, the owner); none: the system. */
  ctx?: AuditWriteContext;
  by?: number | null;
  /** 'user', 'admin', 'tenant_excluded', 'credentials_changed', 'expired', … */
  trigger: string;
}

/** Hook of the authorizations service: cancels the pending authorizations and the filed approvals of a key. */
type CancelHook = (key: { rowId: string; userId: number; publicId: string; name: string }, reason: string, tenantId?: number, cause?: CancelCause) => Promise<void>;
let cancelHook: CancelHook | null = null;
export function setAuthorizationCancelHook(fn: CancelHook): void { cancelHook = fn; }

/**
 * The lock of a user's authorizations (transaction scoped): taken by the creation of an authorization (its caps and the
 * liveness of its key) and by the revocation of a key, so that a request already authenticated when its key is
 * revoked can never file a row after the revocation's cancellation sweep.
 */
export async function lockUserAuthorizations(trx: Knex.Transaction, userId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`mcp_auth:${Number(userId)}`]);
}

/**
 * Revokes a key (never deletes it): revoked_at, by, reason; its pending authorizations and filed approvals are
 * cancelled; audited (protective) in the master chain and its listed tenants'; the IP policy is recomputed.
 * False when it was already revoked or does not exist.
 */
export async function revokeKey(rowId: string, reason: McpKeyRevokeReason, by: number | null, ctx?: AuditWriteContext): Promise<boolean> {
  const row = await asIdentity(MCP_ACTOR, () => db.transaction(async (trx) => {
    const owner = await trx('access_keys').where({ id: rowId }).whereNull('revoked_at').first('user_id') as { user_id: number } | undefined;
    if (!owner) return null;
    await lockUserAuthorizations(trx, Number(owner.user_id));
    const [r] = await trx('access_keys').where({ id: rowId }).whereNull('revoked_at')
      .update({ revoked_at: new Date(), revoked_by: by, revoke_reason: reason })
      .returning(['id', 'user_id', 'public_id', 'name']) as KeyRow[];
    if (!r) return null;
    const t = await trx('access_key_targets').where({ key_id: rowId, kind: 'tenant' }).pluck('tenant_id') as number[];
    return { id: r.id, user_id: r.user_id, public_id: r.public_id, name: r.name, tenants: t.map(Number) } as KeyRow & { tenants: number[] };
  }));
  if (!row) return false;
  const key = { rowId: String(row.id), userId: Number(row.user_id), publicId: String(row.public_id), name: String(row.name) };
  try {
    await cancelHook?.(key, `key revoked (${reason})`, undefined, { ctx, by, trigger: reason });
  } catch (err) {
    logger.error({ err, keyId: key.publicId }, 'mcp: authorizations of a revoked key not all cancelled (the minute step retries)');
  }
  const auditCtx = ctx ?? systemCtx();
  for (const t of new Set<number>([MASTER_TENANT_ID, ...row.tenants])) {
    await asTenant(t, MCP_ACTOR, () => audit.append({
      tenantId: t, action: 'mcp.key.revoked', target: { type: 'access_key', id: key.publicId },
      details: { publicId: key.publicId, reason, ownerId: key.userId, ...(by !== null ? { by } : {}) },
    }, auditCtx)).catch((err) => logger.warn({ err }, 'mcp: revocation not audited'));
  }
  invalidatePolicy();
  return true;
}

/** Every active key of a user (sessions killed for these reasons, or a credential change seen at a call). */
export async function revokeAllOfUser(userId: number, reason: McpKeyRevokeReason): Promise<number> {
  const ids = await asIdentity(MCP_ACTOR, () => db('access_keys').where({ user_id: userId }).whereNull('revoked_at').pluck('id')) as string[];
  let n = 0;
  for (const id of ids) if (await revokeKey(String(id), reason, null)) n++;
  return n;
}

// ── Liveness of a key (the approvals it filed, the minute step) ────────────

export interface KeyWithOwner {
  row: KeyRow;
  targets: McpTarget[];
  owner: { id: number; role: string; isActive: boolean; credentialVersion: number } | null;
}

/** Keys by row id, with their perimeter rows and their owner (identity context). */
export async function keysWithOwners(ids: string[]): Promise<Map<string, KeyWithOwner>> {
  const unique = [...new Set(ids.map(String))];
  const out = new Map<string, KeyWithOwner>();
  if (unique.length === 0) return out;
  return asIdentity(MCP_ACTOR, async () => {
    const rows = await db('access_keys').whereIn('id', unique).select([...KEY_COLUMNS, ipAllowCol()]) as KeyRow[];
    const owners = rows.length === 0 ? [] : await db('users').whereIn('id', [...new Set(rows.map((r) => Number(r.user_id)))])
      .select('id', 'role', 'is_active', 'credential_version') as Array<{ id: number; role: string; is_active: boolean; credential_version: number }>;
    const t = rows.length === 0 ? [] : await db('access_key_targets').whereIn('key_id', rows.map((r) => r.id))
      .select('key_id', 'kind', 'tenant_id', 'ref_id') as Array<Record<string, any>>;
    for (const r of rows) {
      const o = owners.find((u) => Number(u.id) === Number(r.user_id));
      out.set(String(r.id), {
        row: r,
        targets: targetsOf(t.filter((x) => String(x.key_id) === String(r.id)) as Array<{ kind: string; tenant_id: number; ref_id: number | null }>),
        owner: o ? { id: Number(o.id), role: String(o.role), isActive: o.is_active === true, credentialVersion: Number(o.credential_version) } : null,
      });
    }
    return out;
  });
}

/** Why a key can no longer act (revoked, expired, owner gone or disabled, credentials changed), or null when alive. */
export function keyDeadReason(k: KeyWithOwner | undefined): string | null {
  if (!k) return 'key_missing';
  if (k.row.revoked_at) return `revoked_${String(k.row.revoke_reason ?? 'unknown')}`;
  if (new Date(k.row.expires_at).getTime() <= Date.now()) return 'expired';
  if (!k.owner) return 'owner_removed';
  if (!k.owner.isActive) return 'user_disabled';
  if (k.owner.credentialVersion !== Number(k.row.credential_version)) return 'credentials_changed';
  return null;
}

/**
 * The minute step: active keys whose owner changed his credentials (password, TOTP, …), was disabled or removed are
 * revoked now rather than at their next use, so that their pending authorizations and filed approvals are cancelled
 * and the console shows them revoked. At most `max` keys per run.
 */
export async function revokeStaleKeys(max = 100): Promise<number> {
  const rows = await asIdentity(MCP_ACTOR, () => db('access_keys as k').leftJoin('users as u', 'u.id', 'k.user_id')
    .whereNull('k.revoked_at').where('k.expires_at', '>', new Date())
    .where((w) => w.whereNull('u.id').orWhere('u.is_active', false).orWhereRaw('u.credential_version <> k.credential_version'))
    .limit(max).select('k.id', db.raw('u.id AS owner_id'), 'u.is_active')) as Array<{ id: string; owner_id: number | null; is_active: boolean | null }>;
  let n = 0;
  for (const r of rows) {
    const reason: McpKeyRevokeReason = r.owner_id === null ? 'owner_removed' : r.is_active !== true ? 'user_disabled' : 'credentials_changed';
    try { if (await revokeKey(String(r.id), reason, null)) n++; } catch (err) { logger.warn({ err }, 'mcp: stale key not revoked'); }
  }
  return n;
}

// ── Tenant oversight (decision D6, revised) ─────────────────────────────────

/**
 * The active keys whose EFFECTIVE perimeter covers tenant T (identity context): listed tenant, or 'all' with the owner
 * able to reach T now; the owner holds mcp.access_keys there; T not excluded. Never the IPs.
 */
export async function keysCoveringTenant(tenantId: number): Promise<Array<{ row: KeyRow; targets: McpTarget[]; owner: { id: number; username: string; isPlatformAdmin: boolean } }>> {
  return asIdentity(MCP_ACTOR, async () => {
    const rows = await db('access_keys as k').join('users as u', 'u.id', 'k.user_id')
      .whereNull('k.revoked_at').where('k.expires_at', '>', new Date()).where('u.is_active', true)
      .whereRaw('u.credential_version = k.credential_version')
      .where((w) => w.where((x) => x.where('k.tenant_mode', 'list').whereExists(db('access_key_targets as t').whereRaw('t.key_id = k.id')
        .where({ 't.kind': 'tenant', 't.tenant_id': tenantId })))
        .orWhere((x) => x.where('k.tenant_mode', 'all').where((y) => y.where('u.role', 'admin')
          .orWhereExists(db('user_tenants as ut').whereRaw('ut.user_id = k.user_id').where('ut.tenant_id', tenantId)))))
      .whereNotExists(db('access_key_targets as e').whereRaw('e.key_id = k.id').where({ 'e.kind': 'tenant_excluded', 'e.tenant_id': tenantId }))
      .select([...KEY_COLUMNS.map((c) => `k.${c}`), db.raw('k.ip_allow::text[] AS ip_allow'), 'u.username', db.raw('u.role AS user_role')])
      .orderBy('k.created_at', 'desc').limit(500) as KeyRow[];
    const out: Array<{ row: KeyRow; targets: McpTarget[]; owner: { id: number; username: string; isPlatformAdmin: boolean } }> = [];
    for (const r of rows) {
      const isAdmin = r.user_role === 'admin';
      if (!isAdmin && !(await permissionService.userHasTenantCapability(Number(r.user_id), tenantId, 'mcp.access_keys'))) continue;
      const t = await db('access_key_targets').where({ key_id: r.id }).select('kind', 'tenant_id', 'ref_id') as Array<{ kind: string; tenant_id: number; ref_id: number | null }>;
      out.push({ row: r, targets: targetsOf(t), owner: { id: Number(r.user_id), username: String(r.username), isPlatformAdmin: isAdmin } });
    }
    return out;
  });
}

export function oversightView(k: { row: KeyRow; owner: { id: number; username: string } }): TenantOversightKeyView {
  const info = keyInfoOf(k.row);
  return {
    id: info.publicId, name: info.name, owner: { userId: k.owner.id, username: k.owner.username }, scopes: info.scopes,
    expiresAt: iso(k.row.expires_at) as string, lastUsedAt: iso(k.row.last_used_at),
  };
}

/**
 * A tenant manager excludes tenant T from a key (identity context: he is not its owner): narrowing only, the key
 * keeps working in its other tenants; its pending authorizations and filed approvals of T are cancelled.
 */
export async function excludeTenant(publicId: string, tenantId: number, byUserId: number, ctx: AuditWriteContext): Promise<boolean> {
  const covering = await keysCoveringTenant(tenantId);
  const k = covering.find((x) => String(x.row.public_id) === publicId);
  if (!k) return false;
  await asIdentity(MCP_ACTOR, () => db('access_key_targets').insert({
    key_id: k.row.id, user_id: k.owner.id, kind: 'tenant_excluded', tenant_id: tenantId, ref_id: null, created_by: byUserId,
  }).onConflict(db.raw('(key_id, kind, tenant_id, COALESCE(ref_id, 0))')).ignore());
  try {
    await cancelHook?.({ rowId: String(k.row.id), userId: k.owner.id, publicId, name: String(k.row.name) }, 'tenant excluded from the key', tenantId,
      { ctx, by: byUserId, trigger: 'tenant_excluded' });
  } catch (err) {
    logger.error({ err, keyId: publicId }, 'mcp: authorizations of an excluded tenant not all cancelled');
  }
  for (const t of [tenantId, MASTER_TENANT_ID]) {
    await asTenant(t, MCP_ACTOR, () => audit.append({
      tenantId: t, action: 'mcp.key.tenant_excluded', target: { type: 'access_key', id: publicId },
      details: { publicId, tenantId, by: byUserId },
    }, ctx)).catch((err) => logger.warn({ err }, 'mcp: exclusion not audited'));
  }
  invalidatePolicy();
  return true;
}

/** Revocation by the owner (DELETE /api/access-keys/:publicId): 404 when the key is not his. */
export async function revokeOwnKey(userId: number, publicId: string, ctx: AuditWriteContext): Promise<boolean> {
  const row = await asNone(userActor(userId), () => db('access_keys').where({ user_id: userId, public_id: publicId }).first('id', 'revoked_at')) as KeyRow | undefined;
  if (!row) throw new AppError(404, 'Access key not found');
  if (row.revoked_at) return false;
  return revokeKey(String(row.id), 'user', userId, ctx);
}

/** Kept for the type of a transaction parameter in callers. */
export type Trx = Knex.Transaction;
