import { isMasterTenant } from '@obliance/shared';
import { db } from '../db';
import { permissionService } from './permission.service';
import type { RestrictionLevel } from './restriction.service';

/**
 * File explorer gate — who may send an explorer command to which device, and
 * the tenant's action restrictions on those commands.
 *
 * Used by the socket.io FILE_EXPLORER_CMD channel (socket.ts: the web's
 * FileExplorerTab and the Oblireach Desktop explorer) and by the REST step-up
 * route POST /api/files/:deviceId/files/step-up (file.routes.ts).
 *
 * Authorization is PER DEVICE, not the tenant frozen at the socket handshake
 * (the Desktop's multi-server socket, a tenant switch, the master god view):
 *   - platform admins: any device (they may switch to any tenant anyway:
 *     POST /api/tenant/switch);
 *   - everyone else: member of the device's tenant, the device visible to one
 *     of their teams, and the capability 'files' on it.
 *
 * Restrictions (the tenant's matrix, keys `command.<type>`): the DEVICE's
 * tenant, and also the master tenant's when the session is on it and the
 * device is not (a master admin's god view is held to both matrices, like the
 * REST routes: restrictionService.enforce deviceTenantId). Any other tenant
 * the session happens to be on is not consulted: the level of an explorer
 * command never depends on where an unrelated earlier request (the Desktop's
 * multi-server mode switches the session per request) left the session.
 *   - 'none'       -> the command goes;
 *   - 'sensitive'  -> a step-up grant of THIS session for this device and this
 *                    action is required. It is obtained with the same verifier
 *                    as every sensitive action (checkSecondFactor: TOTP,
 *                    Obligate code, phone key, trusted IP) on the REST route
 *                    above, which the clients call when the socket answers
 *                    `step_up_required`, then they resend the command;
 *   - 'restricted' -> refused: an approval cannot run an interactive explorer
 *                    operation (its result would never reach the explorer).
 *
 * Grants live in memory (lost at a restart: the client is simply asked again).
 *   - Browsing (`command.list_directory`, the explorer's entry gate and the
 *     only explorer key restricted by default): one code when the explorer
 *     opens (default restrictions of modules/rmm.ts, migration 067), then 15 min of inactivity,
 *     2 h at most.
 *   - Any other explorer action marked sensitive by an admin (upload, delete,
 *     rename...) is a double gate: one confirmation = ONE operation (a
 *     multi-file operation declares its size, at most EXPLORER_OP_MAX_USES),
 *     used within 2 min of the proof (the REST step-up's code-reuse window,
 *     STEPUP_REUSE_STEPS), never extended.
 *   - A grant obtained through the "trusted IP" shortcut holds only from that
 *     address, and only while it is still trusted (a revocation ends it).
 *   - A grant belongs to the session: a session that ends (sign-out, a phone
 *     key revoked: its bound sessions are deleted) takes its grants with it.
 */

/** The only agent command types the FILE_EXPLORER_CMD channel may carry. */
export const FILE_EXPLORER_COMMANDS: ReadonlySet<string> = new Set([
  'list_directory', 'create_directory', 'rename_file', 'delete_file', 'download_file', 'upload_file',
]);

export type ExplorerFailureCode =
  | 'invalid'           // malformed request, command type outside the list
  | 'session'           // the session ended, or the account was disabled
  | 'not_found'         // unknown device, or one the user may not see (no existence leak)
  | 'forbidden'         // visible device, capability 'files' missing
  | 'restricted'        // the tenant restricts this action (approval): never interactive
  | 'step_up_required'  // sensitive: POST /api/files/:id/files/step-up, then resend
  | 'error';            // server error

export interface ExplorerFailure {
  error: string;
  code: ExplorerFailureCode;
  /** The restriction key (`command.<type>`) of a 'restricted' / 'step_up_required' answer. */
  action?: string;
}

export interface ExplorerDevice {
  id: number;
  tenant_id: number;
  hostname: string | null;
}

export const EXPLORER_RESTRICTED_TEXT =
  'This file operation is restricted by your tenant (approval required): an approval cannot run an interactive file operation. Ask an administrator.';
export const EXPLORER_STEP_UP_TEXT = 'Two-factor confirmation required for this file operation';

/** A device id as the clients send it (a number; a digit string is tolerated). */
export function parseDeviceId(raw: unknown): number | null {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && /^[1-9][0-9]{0,9}$/.test(raw) ? Number(raw) : NaN;
  return Number.isSafeInteger(n) && n > 0 && n <= 2147483647 ? n : null;
}

/**
 * The device, when this user may use the file explorer on it. `isAdmin` must
 * be the LIVE role (users.role), not one frozen at a socket handshake.
 */
export async function explorerDeviceAccess(
  userId: number,
  isAdmin: boolean,
  deviceId: number,
): Promise<{ ok: true; device: ExplorerDevice } | { ok: false; failure: ExplorerFailure }> {
  const notFound = { ok: false as const, failure: { error: 'Device not found', code: 'not_found' as const } };
  const device = await db('devices').where({ id: deviceId }).first('id', 'tenant_id', 'hostname') as ExplorerDevice | undefined;
  if (!device) return notFound;
  if (isAdmin) return { ok: true, device };
  const member = await db('user_tenants').where({ user_id: userId, tenant_id: device.tenant_id }).first('user_id');
  if (!member) return notFound;
  if (!(await permissionService.canReadDevice(userId, deviceId, false))) return notFound;
  if (!(await permissionService.canUseCapability(userId, deviceId, false, 'files'))) {
    return { ok: false, failure: { error: 'File explorer not permitted for your team', code: 'forbidden' } };
  }
  return { ok: true, device };
}

/**
 * The restriction level of `command.<commandType>` for this device: the
 * device's tenant, plus the master tenant when the session is on it and the
 * device is not (god view: the strictest of both).
 */
export async function explorerRestrictionLevel(
  commandType: string,
  deviceId: number,
  deviceTenantId: number,
  sessionTenantId?: number | null,
): Promise<RestrictionLevel> {
  const { restrictionService } = await import('./restriction.service');
  const actionKey = `command.${commandType}`;
  const rank: Record<RestrictionLevel, number> = { none: 0, sensitive: 1, restricted: 2 };
  const tenants = [deviceTenantId];
  const s = Number(sessionTenantId);
  if (Number.isInteger(s) && s > 0 && s !== deviceTenantId && isMasterTenant(s)) tenants.push(s);
  let best: RestrictionLevel = 'none';
  for (const tenantId of tenants) {
    const level = await restrictionService.getLevelFor({ tenantId, actionKey, deviceIds: [deviceId] });
    if (rank[level] > rank[best]) best = level;
  }
  return best;
}

// ── Step-up grants (memory) ─────────────────────────────────────────────────

export const EXPLORER_BROWSE_ACTION = 'command.list_directory';
export const EXPLORER_BROWSE_IDLE_MS = 15 * 60 * 1000;
export const EXPLORER_BROWSE_MAX_MS = 2 * 60 * 60 * 1000;
/** Other explorer actions: the grant's lifetime from the proof (not sliding). */
export const EXPLORER_OP_TTL_MS = 2 * 60 * 1000;
/** Other explorer actions: operations one confirmation may cover (a batch). */
export const EXPLORER_OP_MAX_USES = 100;
const MAX_GRANTS = 20_000;

interface Grant {
  createdAt: number;
  lastUsed: number;
  /** Operations left (other actions); null = browsing (unlimited, sliding). */
  uses: number | null;
  /** The trusted address a trusted-IP grant is bound to; null otherwise. */
  ip: string | null;
}
const grants = new Map<string, Grant>();

function isBrowse(actionKey: string): boolean {
  return actionKey === EXPLORER_BROWSE_ACTION;
}

function grantKey(sessionHash: string, userId: number, deviceId: number, actionKey: string): string {
  return `${sessionHash}|${userId}|${deviceId}|${actionKey}`;
}

function expired(g: Grant, now: number): boolean {
  if (g.uses === null) return now - g.createdAt > EXPLORER_BROWSE_MAX_MS || now - g.lastUsed > EXPLORER_BROWSE_IDLE_MS;
  return g.uses <= 0 || now - g.createdAt > EXPLORER_OP_TTL_MS;
}

function sweep(now: number): void {
  for (const [k, g] of grants) {
    if (expired(g, now)) grants.delete(k);
  }
}

/**
 * Records a successful step-up of this session for (device, action).
 *  - `uses`: operations the confirmation covers (other actions only: a
 *    multi-file operation), 1 by default, at most EXPLORER_OP_MAX_USES;
 *  - `via` / `ip`: how the proof was given (checkSecondFactor); a trusted-IP
 *    grant is bound to that address.
 * Returns the grant's window in seconds (what the client may show).
 */
export function grantExplorerStepUp(
  sessionHash: string, userId: number, deviceId: number, actionKey: string,
  opts: { uses?: number; via?: string; ip?: string | null } = {},
): number {
  const now = Date.now();
  if (grants.size >= MAX_GRANTS) sweep(now);
  if (grants.size >= MAX_GRANTS) grants.clear();
  const browse = isBrowse(actionKey);
  const n = Math.floor(Number(opts.uses));
  const uses = browse ? null : Math.min(EXPLORER_OP_MAX_USES, Number.isFinite(n) && n >= 1 ? n : 1);
  const ip = opts.via === 'trusted_ip' ? (opts.ip || '') : null;
  grants.set(grantKey(sessionHash, userId, deviceId, actionKey), { createdAt: now, lastUsed: now, uses, ip });
  return Math.round((browse ? EXPLORER_BROWSE_IDLE_MS : EXPLORER_OP_TTL_MS) / 1000);
}

/**
 * True while this session holds a live grant for (device, action), from this
 * address: the browsing window slides, another action's grant loses one use.
 * A trusted-IP grant also needs the socket's address to be that one, still
 * trusted (tfaTrustService: a revoked trust ends it at once).
 */
export async function useExplorerStepUp(
  sessionHash: string | null, userId: number, deviceId: number, actionKey: string,
  socketIp?: string | null,
): Promise<boolean> {
  if (!sessionHash) return false;
  const k = grantKey(sessionHash, userId, deviceId, actionKey);
  const g = grants.get(k);
  if (!g) return false;
  if (expired(g, Date.now())) { grants.delete(k); return false; }
  if (g.ip !== null) {
    if (!g.ip || !socketIp || socketIp !== g.ip) return false;
    const { tfaTrustService } = await import('./tfaTrust.service');
    if (!(await tfaTrustService.isTrusted(userId, g.ip))) {
      if (grants.get(k) === g) grants.delete(k);
      return false;
    }
    // Re-read after the await: a concurrent use may have spent the last one.
    if (grants.get(k) !== g || expired(g, Date.now())) return false;
  }
  g.lastUsed = Date.now();
  if (g.uses !== null) {
    g.uses -= 1;
    if (g.uses <= 0) grants.delete(k);
  }
  return true;
}

/** Forgets every grant of a user (e.g. their trusted IPs were revoked). */
export function clearExplorerStepUpsOfUser(userId: number): void {
  const mark = `|${userId}|`;
  for (const k of grants.keys()) {
    const first = k.indexOf('|');
    if (first >= 0 && k.startsWith(mark, first)) grants.delete(k);
  }
}

/** Test hook: forgets every grant. */
export function _resetExplorerStepUps(): void {
  grants.clear();
}

// ── One explorer command ────────────────────────────────────────────────────

/**
 * Everything FILE_EXPLORER_CMD decides for one command, the live session
 * already checked by the caller: command type, device, the user's live state,
 * access, restriction level and step-up grant.
 */
export async function authorizeExplorerCommand(ctx: {
  userId: number;
  /** sha256 of the express session id (the socket's session), null when unknown. */
  sessionHash: string | null;
  /** The socket's client address (a trusted-IP grant holds only from it). */
  clientIp?: string | null;
  /** The live session's current tenant. */
  sessionTenantId: number | null;
  deviceId: unknown;
  commandType: unknown;
}): Promise<{ ok: true; device: ExplorerDevice; isAdmin: boolean } | { ok: false; failure: ExplorerFailure }> {
  if (typeof ctx.commandType !== 'string' || !FILE_EXPLORER_COMMANDS.has(ctx.commandType)) {
    return { ok: false, failure: { error: 'Command not allowed on the file explorer channel', code: 'invalid' } };
  }
  const deviceId = parseDeviceId(ctx.deviceId);
  if (deviceId === null) return { ok: false, failure: { error: 'Invalid request', code: 'invalid' } };

  const user = await db('users').where({ id: ctx.userId }).first('is_active', 'role') as { is_active: boolean; role: string } | undefined;
  if (!user || user.is_active === false) return { ok: false, failure: { error: 'Session expired', code: 'session' } };
  const isAdmin = user.role === 'admin';

  const access = await explorerDeviceAccess(ctx.userId, isAdmin, deviceId);
  if (!access.ok) return access;

  const actionKey = `command.${ctx.commandType}`;
  const level = await explorerRestrictionLevel(ctx.commandType, deviceId, access.device.tenant_id, ctx.sessionTenantId);
  if (level === 'restricted') {
    return { ok: false, failure: { error: EXPLORER_RESTRICTED_TEXT, code: 'restricted', action: actionKey } };
  }
  if (level === 'sensitive' && !(await useExplorerStepUp(ctx.sessionHash, ctx.userId, deviceId, actionKey, ctx.clientIp))) {
    return { ok: false, failure: { error: EXPLORER_STEP_UP_TEXT, code: 'step_up_required', action: actionKey } };
  }
  return { ok: true, device: access.device, isAdmin };
}
