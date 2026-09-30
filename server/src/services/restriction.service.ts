import { db } from '../db';
import type { Request, Response } from 'express';
import { AppError } from '../middleware/errorHandler';
import { approvalService, type ApprovalRequestType } from './approval.service';

// ── Restriction model ───────────────────────────────────────────────────────
//
// Per-tenant JSONB map, each entry is either:
//
//   // Shorthand (applies to every device):
//   "device.delete": "restricted"
//
//   // Full form with scope:
//   "device.transfer_tenant": {
//     "level": "sensitive",
//     "scope": { "mode": "exclude", "deviceIds": [42], "groupIds": [7] }
//   }
//
// Scope modes:
//   - "all"      (default) — the restriction applies to every device.
//   - "include"  — applies ONLY to the listed devices / groups (+ descendants).
//   - "exclude"  — applies to every device EXCEPT the listed ones / their groups.
//
// Enforcement:
//   - For single-device actions, we evaluate scope against that device.
//   - For batch actions, if ANY device in the batch falls in scope, the whole
//     batch is gated (keeps the UX obvious: "some of these need approval").

export type RestrictionLevel = 'none' | 'restricted' | 'sensitive';
export type ScopeMode = 'all' | 'include' | 'exclude';

export interface RestrictionScope {
  mode: ScopeMode;
  deviceIds?: number[];
  groupIds?: number[];
}

export interface RestrictionEntry {
  level: RestrictionLevel;
  scope: RestrictionScope;
}

export type RestrictionMap = Record<string, RestrictionEntry>;

// ── Catalog of the restrictable actions ─────────────────────────────────────
// The UI renders this list plus any extra keys that exist in the tenant's
// map (forward-compat). A module lists its own actions
// (registerRestrictableActions; modules/devices.ts for the device registry):
// the matrix shows the modules' actions first, in registration order, then
// the core's tenant-configuration actions.

export interface RestrictableAction {
  key: string;
  label: string;
  category: string;
}

type DefaultLevel = 'restricted' | 'sensitive';

// Tenant config surfaces — editing these pages changes who can do what.
// Defaults live in CORE_DEFAULT_RESTRICTIONS below; we don't auto-seed the
// management ones so fresh installs without TOTP don't lock admins out.
const CORE_RESTRICTABLE_ACTIONS: readonly RestrictableAction[] = [
  { key: 'tenant.manage_restrictions',   label: 'Edit the Restrictions matrix', category: 'Tenant config' },
  { key: 'tenant.manage_users',          label: 'Create / edit / delete users', category: 'Tenant config' },
  { key: 'tenant.manage_teams',          label: 'Create / edit / delete teams', category: 'Tenant config' },
  { key: 'tenant.manage_permissions',    label: 'Edit team permissions / members', category: 'Tenant config' },
  { key: 'tenant.manage_settings',       label: 'Edit tenant settings',       category: 'Tenant config' },
  { key: 'tenant.manage_profile',        label: 'Edit own profile (local users)', category: 'Tenant config' },
  { key: 'audit.clear',                  label: 'Clear the audit log',        category: 'Tenant config' },
];

/**
 * Recommended default levels for fresh tenants (and tenants that never
 * customised anything); the migrations seed the same. Keys listed as 'none'
 * are omitted from the stored map so the UI shows them blank and the admin
 * can opt in later.
 */
const CORE_DEFAULT_RESTRICTIONS: Readonly<Record<string, DefaultLevel>> = {
  // Clearing the audit log deletes accountability — always require a
  // second admin to approve. Doesn't need TOTP.
  'audit.clear':                  'restricted',
  // Tenant-config management (users/teams/permissions/settings/profile/
  // restrictions-config) is intentionally NOT defaulted — admins opt in from
  // the matrix once they have TOTP deployed across privileged accounts,
  // otherwise a fresh install could softlock itself.
};

const moduleActions: RestrictableAction[] = [];
const moduleDefaults: Record<string, DefaultLevel> = {};

/** A module's restrictable actions and their recommended default levels. */
export function registerRestrictableActions(actions: readonly RestrictableAction[], defaults: Readonly<Record<string, DefaultLevel>> = {}): void {
  for (const a of actions) {
    if (!isActionKey(a.key)) throw new Error(`Invalid restrictable action key: ${a.key}`);
    if (moduleActions.some((m) => m.key === a.key) || CORE_RESTRICTABLE_ACTIONS.some((c) => c.key === a.key)) {
      throw new Error(`Restrictable action '${a.key}' registered twice`);
    }
    moduleActions.push({ key: a.key, label: a.label, category: a.category });
  }
  Object.assign(moduleDefaults, defaults);
}

/** The matrix catalog: the modules' actions, then the core's. */
export function restrictableActions(): RestrictableAction[] {
  return [...moduleActions, ...CORE_RESTRICTABLE_ACTIONS];
}

/** Recommended default levels: the modules', then the core's. */
export function defaultRestrictions(): Record<string, DefaultLevel> {
  return { ...moduleDefaults, ...CORE_DEFAULT_RESTRICTIONS };
}

function normalizeEntry(raw: any): RestrictionEntry | null {
  if (raw === 'restricted' || raw === 'sensitive') {
    return { level: raw, scope: { mode: 'all' } };
  }
  if (raw && typeof raw === 'object' && (raw.level === 'restricted' || raw.level === 'sensitive')) {
    const scope: RestrictionScope = {
      mode: raw.scope?.mode === 'include' || raw.scope?.mode === 'exclude' ? raw.scope.mode : 'all',
      deviceIds: Array.isArray(raw.scope?.deviceIds) ? raw.scope.deviceIds.map(Number).filter(Number.isFinite) : undefined,
      groupIds:  Array.isArray(raw.scope?.groupIds)  ? raw.scope.groupIds.map(Number).filter(Number.isFinite)  : undefined,
    };
    return { level: raw.level, scope };
  }
  return null;
}

/**
 * Decide whether a restriction with `scope` applies to a given device.
 * Resolves group membership via the device_group_closure so sub-groups of
 * a scoped parent are matched too.
 */
async function scopeAppliesToDevice(scope: RestrictionScope, deviceId: number, tenantId: number): Promise<boolean> {
  if (scope.mode === 'all') return true;
  const dev = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id', 'group_id');
  if (!dev) return scope.mode === 'include' ? false : true;

  const deviceMatches = (scope.deviceIds ?? []).includes(dev.id);
  let groupMatches = false;
  if (scope.groupIds?.length && dev.group_id != null) {
    // Device matches scope.groupIds if its group_id is one of them, or is a
    // descendant (closure table: ancestor_id → descendant_id).
    const row = await db('device_group_closure')
      .whereIn('ancestor_id', scope.groupIds)
      .andWhere('descendant_id', dev.group_id)
      .first('descendant_id');
    groupMatches = !!row;
  }

  const inScope = deviceMatches || groupMatches;
  return scope.mode === 'include' ? inScope : !inScope;
}

/** An action key of the matrix ('device.delete', 'audit.clear'…):
 *  forward-compatible, but never an arbitrary field name. */
export function isActionKey(key: string): boolean {
  return /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/.test(key) && key.length <= 100;
}

/**
 * The matrix as it will be stored: action keys only, entries normalised,
 * 'none' dropped (what setMap keeps). 400 when `raw` is not an object — an
 * absent map used to clear the whole matrix.
 */
export function sanitizeMap(raw: unknown): RestrictionMap {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new AppError(400, 'map must be an object of action keys');
  }
  const out: RestrictionMap = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!isActionKey(k)) continue;
    const norm = normalizeEntry(v);
    if (norm) out[k] = norm;
  }
  return out;
}

/** Entry changes from `before` to `after` (null = none), keys sorted. */
export function diffMaps(before: RestrictionMap, after: RestrictionMap): Array<{ key: string; from: RestrictionEntry | null; to: RestrictionEntry | null }> {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const out: Array<{ key: string; from: RestrictionEntry | null; to: RestrictionEntry | null }> = [];
  for (const key of keys) {
    const from = before[key] ?? null;
    const to = after[key] ?? null;
    if (JSON.stringify(from) !== JSON.stringify(to)) out.push({ key, from, to });
  }
  return out;
}

export const restrictionService = {
  async getMap(tenantId: number): Promise<RestrictionMap> {
    const row = await db('tenants').where({ id: tenantId }).first('action_restrictions');
    if (!row) return {};
    const raw = typeof row.action_restrictions === 'string'
      ? JSON.parse(row.action_restrictions || '{}')
      : (row.action_restrictions || {});
    const out: RestrictionMap = {};
    for (const [k, v] of Object.entries(raw)) {
      const norm = normalizeEntry(v);
      if (norm) out[k] = norm;
    }
    return out;
  },

  async setMap(tenantId: number, next: RestrictionMap): Promise<void> {
    const clean: RestrictionMap = {};
    for (const [k, v] of Object.entries(next)) {
      const norm = normalizeEntry(v);
      if (norm) clean[k] = norm;
    }
    await db('tenants').where({ id: tenantId }).update({
      action_restrictions: JSON.stringify(clean),
      updated_at: new Date(),
    });
  },

  /**
   * Returns the effective level after scope evaluation. "none" when the
   * action is unrestricted OR when scope excludes the target devices.
   */
  async getLevelFor(params: {
    tenantId: number;
    actionKey: string;
    deviceIds?: number[];  // empty / undefined → treat as "applies to all"
  }): Promise<RestrictionLevel> {
    const map = await this.getMap(params.tenantId);
    const entry = map[params.actionKey];
    if (!entry) return 'none';

    if (entry.scope.mode === 'all' || !params.deviceIds?.length) return entry.level;

    // For batch ops, gate as soon as one device is in scope.
    for (const id of params.deviceIds) {
      if (await scopeAppliesToDevice(entry.scope, id, params.tenantId)) {
        return entry.level;
      }
    }
    return 'none';
  },

  /**
   * Strictest level of `actionKey` over several tenants ('restricted' >
   * 'sensitive' > 'none'), with the tenant it comes from. For actions on
   * USER-GLOBAL data (own profile, own password): the level must not depend
   * on which of the user's tenants the session currently has selected.
   */
  async getStrictestLevel(tenantIds: number[], actionKey: string): Promise<{ level: RestrictionLevel; tenantId: number | null }> {
    const rank: Record<RestrictionLevel, number> = { none: 0, sensitive: 1, restricted: 2 };
    let best: { level: RestrictionLevel; tenantId: number | null } = { level: 'none', tenantId: null };
    for (const tenantId of [...new Set(tenantIds.filter((t) => Number.isInteger(t) && t > 0))]) {
      const level = await this.getLevelFor({ tenantId, actionKey });
      if (rank[level] > rank[best.level]) best = { level, tenantId };
    }
    return best;
  },

  /**
   * Main enforcement entry point — call from route handlers. Writes a 202
   * (pending approval) or 401/403 response when the action must be blocked
   * or gated; returns { ok: true } when the handler can proceed.
   */
  async enforce(params: {
    req: Request;
    actionKey: string;
    deviceIds?: number[];
    approvalRequestType?: ApprovalRequestType;
    approvalDescription?: string;
    approvalPayload?: Record<string, unknown>;
    /** Executor-only data of the approval (bcrypt hash, image): never
     *  returned by the API, wiped when the request is resolved. */
    approvalSealed?: Record<string, unknown>;
    /** The action carries a secret an approval must never keep. Set by the
     *  ROUTE from fields the server knows to be secret (approvalSecrets.ts),
     *  never from the names of the caller's fields: at the 'restricted' level
     *  a fresh step-up — no trusted-IP shortcut — is asked instead of an
     *  approval. Any secret-NAMED key the caller slipped into
     *  `approvalPayload` does not change the level: approvalService.create
     *  drops it and the approval is filed as usual. */
    carriesSecret?: boolean;
    /** User-global action: the level is the strictest over these tenants
     *  (the approval, if any, is filed in the tenant that imposes it). */
    levelTenantIds?: number[];
    /** With levelTenantIds: file the approval in the REQUEST's tenant even
     *  when another tenant imposes the level — for an action whose scope is
     *  the approval's tenant (e.g. a master-tenant action over every tenant:
     *  the level is the strictest of every tenant it touches, the approval
     *  stays in the master tenant so that it still executes on every
     *  tenant). */
    approvalInRequestTenant?: boolean;
    /** The target device's tenant, when it may differ from the request's
     *  (a master-tenant admin's god view): the level is the strictest of
     *  the request's matrix and the device's, each with its own device
     *  scope — the god view never skips the device tenant's restriction.
     *  An approval, if any, is filed in the request's tenant. */
    deviceTenantId?: number;
  }): Promise<
    | { ok: true }
    | { ok: false; status: number; body: any; headers?: Record<string, string> }
    | { ok: false; approval: any; status: 202 }
  > {
    const { req, actionKey } = params;
    const tenantId = (req as any).tenantId as number;
    const userId = (req.session as any).userId as number;
    if (!tenantId) throw new Error('restrictionService.enforce called without req.tenantId');

    let level: RestrictionLevel;
    let approvalTenantId = tenantId;
    if (params.levelTenantIds?.length) {
      const strictest = await this.getStrictestLevel([tenantId, ...params.levelTenantIds], actionKey);
      level = strictest.level;
      if (strictest.tenantId && !params.approvalInRequestTenant) approvalTenantId = strictest.tenantId;
    } else {
      level = await this.getLevelFor({ tenantId, actionKey, deviceIds: params.deviceIds });
      const other = Number(params.deviceTenantId);
      if (Number.isInteger(other) && other > 0 && other !== tenantId && level !== 'restricted') {
        const rank: Record<RestrictionLevel, number> = { none: 0, sensitive: 1, restricted: 2 };
        const deviceLevel = await this.getLevelFor({ tenantId: other, actionKey, deviceIds: params.deviceIds });
        if (rank[deviceLevel] > rank[level]) level = deviceLevel;
      }
    }
    if (level === 'none') return { ok: true };

    if (level === 'sensitive') {
      // One verifier for every step-up (services/deviceKey/stepUpProof.ts):
      // trusted-IP shortcut, TOTP (anti-replay, caps) or Obligate TOTP for
      // SSO accounts. Proofs come from req.stepUpProof (P5), never req.body.
      const { checkSecondFactor } = await import('./deviceKey/stepUpProof');
      const outcome = await checkSecondFactor(req, {
        actionKey,
        deviceIds: params.deviceIds,
        allowTrustedIp: true,
        allowDevice: true,
      });
      if (outcome.ok) return { ok: true };
      return { ok: false, status: outcome.status, body: outcome.body, headers: outcome.headers };
    }

    if (level === 'restricted') {
      if (!params.approvalRequestType) {
        return {
          ok: false, status: 403,
          body: { error: 'This action is restricted but no approval path is configured.' },
        };
      }
      // A secret (password, key) never sits in an approval
      // (services/approvalSecrets.ts): such an action asks a FRESH
      // step-up here instead of a second administrator — the rule P1 applied
      // to the admin password reset. Always a code / the phone: a trusted IP
      // never replaces the second person. Only the route's explicit flag
      // counts (a caller-chosen field name must not skip the second person).
      if (params.carriesSecret === true) {
        const { checkSecondFactor } = await import('./deviceKey/stepUpProof');
        const outcome = await checkSecondFactor(req, {
          actionKey,
          deviceIds: params.deviceIds,
          allowTrustedIp: false,
          allowDevice: true,
        });
        if (outcome.ok) return { ok: true };
        return { ok: false, status: outcome.status, body: outcome.body, headers: outcome.headers };
      }
      const approval = await approvalService.create({
        tenantId: approvalTenantId,
        userId,
        requestType: params.approvalRequestType,
        description: params.approvalDescription ?? actionKey,
        payload: (params.approvalPayload ?? {}) as any,
        sealed: params.approvalSealed,
      });
      return { ok: false, status: 202, approval };
    }

    return { ok: true };
  },
};

/**
 * Convenience wrapper — call this from a route handler. If it returns
 * `false` the response has already been written, so the handler must
 * return immediately.
 */
export async function applyRestriction(
  res: Response,
  args: Parameters<typeof restrictionService.enforce>[0],
): Promise<boolean> {
  const outcome = await restrictionService.enforce(args);
  if (outcome.ok) return true;
  if ((outcome as any).approval) {
    res.status(202).json({ data: { approvalId: (outcome as any).approval.id, status: 'pending_approval' } });
  } else {
    for (const [k, v] of Object.entries(((outcome as any).headers ?? {}) as Record<string, string>)) res.setHeader(k, v);
    res.status((outcome as any).status).json((outcome as any).body);
  }
  return false;
}
