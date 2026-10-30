// =============================================================================
// MCP server: personal access keys of AI agents (docs: specs mcp-server v1)
// =============================================================================
//
// A key acts AS its owner (an Obligarth account, local or signed in through
// Obligate), never more: the owner's current rights are re-checked on every
// call, intersected with the key's scopes and perimeters (tenants, groups,
// devices). Sensitive actions are never run by the key: they become an
// authorization the owner approves in the console with a second factor.

import type { DeviceCapability, TenantCapability } from './capabilities';

/** The prefix of a key: obg_<publicId>_<secret>. */
export const MCP_KEY_PREFIX = 'obg_';

/** Parse rule of a key (the server re-checks it): 12 lowercase characters of public id, 43 of base64url secret. */
export const MCP_KEY_RE = /^obg_([a-z0-9]{12})_([A-Za-z0-9_-]{43})$/;

/** Bounds of a key. */
export const MCP_KEY_BOUNDS = {
  expiryDaysDefault: 90,
  expiryDaysMax: 365,
  activeKeysPerUser: 20,
  ipAllowMax: 32,
  nameMax: 80,
} as const;

/** What a scope needs in the tenant of the call: membership only, or a tenant capability. */
export type McpScopeTenantNeed = 'membership' | TenantCapability;

export interface McpScopeDef {
  /** Read or act: the creation form groups them. */
  kind: 'read' | 'act';
  /** Tenant need, checked per tenant at call time (a platform administrator passes). */
  tenantNeed: McpScopeTenantNeed;
  /** Device capability the write tools of the scope need on each target (with write access), if any. */
  deviceCapability?: DeviceCapability;
  /** English label (the client translates accessKeys.scopes.<key>). */
  label: string;
}

/** The scopes a key may carry, chosen at creation within the owner's rights. */
export const MCP_SCOPES = {
  'devices.read': { kind: 'read', tenantNeed: 'membership', label: 'Read devices, groups and the inventory' },
  'devices.identifiers': { kind: 'read', tenantNeed: 'devices.manage', label: 'Read device identifiers (IMEI, serial numbers)' },
  'commands.read': { kind: 'read', tenantNeed: 'membership', label: 'Read the command queues and results' },
  'alerts.read': { kind: 'read', tenantNeed: 'membership', label: 'Read the live alerts' },
  'apps.read': { kind: 'read', tenantNeed: 'membership', label: 'Read the app catalog, packages and agent versions' },
  'audit.read': { kind: 'read', tenantNeed: 'audit.read', label: "Read the tenant's audit log" },
  'commands.inventory': { kind: 'act', tenantNeed: 'membership', deviceCapability: 'mdm:inventory', label: 'Refresh the inventory' },
  'commands.message': { kind: 'act', tenantNeed: 'membership', deviceCapability: 'mdm:lock', label: 'Show a message on devices' },
  'commands.restart': { kind: 'act', tenantNeed: 'membership', deviceCapability: 'mdm:restart', label: 'Restart devices' },
  'commands.apps': { kind: 'act', tenantNeed: 'membership', deviceCapability: 'mdm:apps', label: 'Install, remove and pull apps, update the agent' },
  'commands.cancel': { kind: 'act', tenantNeed: 'membership', label: 'Cancel pending commands' },
  'groups.move': { kind: 'act', tenantNeed: 'devices.manage', label: 'Move devices between groups (always approved by you)' },
} as const satisfies Record<string, McpScopeDef>;

export type McpScope = keyof typeof MCP_SCOPES;
export const MCP_SCOPE_KEYS = Object.keys(MCP_SCOPES) as McpScope[];

export function isMcpScope(v: unknown): v is McpScope {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(MCP_SCOPES, v);
}

export type McpPerimeterMode = 'all' | 'list';
export type McpIpMode = 'strict' | 'rate' | 'closed';
export type McpKeyState = 'active' | 'expired' | 'revoked';
export type McpKeyRevokeReason = 'user' | 'admin' | 'user_disabled' | 'credentials_changed' | 'sessions_killed' | 'owner_removed';

/** Body of POST /api/access-keys. */
export interface AccessKeyCreateBody {
  name: string;
  expiresInDays: number;
  scopes: McpScope[];
  tenants: { mode: McpPerimeterMode; ids?: number[] };
  groups: { mode: McpPerimeterMode; items?: Array<{ tenantId: number; groupId: number }> };
  devices: { mode: McpPerimeterMode; items?: Array<{ tenantId: number; deviceId: number }> };
  ipAllow: string[];
}

/** A key as its owner sees it (never the secret nor its hash). */
export interface AccessKeyView {
  id: string;
  name: string;
  scopes: McpScope[];
  tenants: { mode: McpPerimeterMode; items: Array<{ tenantId: number; name: string | null }> };
  groups: { mode: McpPerimeterMode; items: Array<{ tenantId: number; groupId: number; name: string | null }> };
  devices: { mode: McpPerimeterMode; items: Array<{ tenantId: number; deviceId: number; name: string | null }> };
  excludedTenants: number[];
  ipAllow: string[];
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  revokedAt: string | null;
  revokeReason: McpKeyRevokeReason | null;
  state: McpKeyState;
  effectiveNow: { tenants: number[] };
}

/** The answer of the creation: the token is shown ONCE. */
export interface AccessKeyCreated {
  key: AccessKeyView;
  token: string;
}

/** GET /api/access-keys/options. */
export interface AccessKeyOptions {
  tenants: Array<{ tenantId: number; name: string; scopes: McpScope[]; forceIpAllowList: boolean }>;
  minPrefixV4: number;
  minPrefixV6: number;
  maxExpiryDays: number;
  ipMode: McpIpMode;
  hasStepUpFactor: boolean;
}

/** A key as a tenant manager sees it (oversight of the keys reaching his tenant): no IP, no last address. */
export interface TenantOversightKeyView {
  id: string;
  name: string;
  owner: { userId: number; username: string | null };
  scopes: McpScope[];
  expiresAt: string;
  lastUsedAt: string | null;
}

export type McpAuthorizationState = 'pending' | 'executing' | 'executed' | 'failed' | 'denied' | 'expired' | 'cancelled' | 'filed' | 'interrupted';
export type McpAuthorizationLevel = 'sensitive' | 'restricted' | 'always_human';

/** An action an AI agent asked through a key, waiting for (or decided by) the key's human. */
export interface McpAuthorizationView {
  id: string;
  tenantId: number;
  tool: string;
  actionKey: string;
  level: McpAuthorizationLevel;
  /** Built by the server, never by the agent. */
  summary: string;
  state: McpAuthorizationState;
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  stepUpVia: string | null;
  outcome: Record<string, unknown> | null;
  errorCode: string | null;
  key: { id: string; name: string };
  agentIp: string | null;
}

/** The detail of an authorization (GET /api/mcp-authorizations/:id). */
export interface McpAuthorizationDetail extends McpAuthorizationView {
  devices: Array<{ id: number; name: string | null }>;
  /** The validated parameters, the agent's free text left out. */
  params: Record<string, unknown>;
  /** Text written by the AI agent (reason, message, package name): data to show as plain text, never markup. */
  agentText: Record<string, string>;
  /** A move of devices: the preview the human approves, and what the approval echoes. */
  preview?: { impact: unknown; devicesToken: string | null; impactDigest: string };
}

/** Socket MCP_AUTHORIZATION_CHANGED (room user:<id>). */
export interface McpAuthorizationChanged {
  id: string;
  tenantId: number;
  state: McpAuthorizationState;
  summary: string;
  expiresAt: string;
}

/** Socket MCP_KEY_NEW_NETWORK (room user:<id>). */
export interface McpKeyNewNetwork {
  keyId: string;
  name: string;
  ip: string;
  at: string;
}

/** Settings of the instance (GET/PUT /api/admin/mcp/settings). */
export interface McpSettingsView {
  forceIpAllowList: boolean;
  minPrefixV4: number;
  minPrefixV6: number;
  failureThreshold: number;
  failureWindowSeconds: number;
  blockSeconds: number;
  knownIpDays: number;
  maxNewBlocksPerMinute: number;
  prefixBlockThreshold: number;
  keyRequestsPerMinute: number;
  authorizationMinutes: number;
  maxPendingPerKey: number;
  maxPendingPerUser: number;
  maxCreatedPerKeyHour: number;
  obliguardEnabled: boolean;
  obliguardUrl: string | null;
  neverBlock: string[];
  /** Read only: the IP mode computed from the active keys. */
  mode: McpIpMode;
  activeKeys: number;
  openKeys: number;
}

export type McpTenantIpPolicy = 'inherit' | 'force' | 'exempt';

export type McpBlockSource = 'mcp_strict' | 'mcp_failures' | 'mcp_prefix' | 'manual';
export type McpObliguardStatus = 'pending' | 'sent' | 'failed' | 'disabled' | 'withdrawn' | 'skipped';

/** A local block of /mcp (an address, or an IPv6 /64). */
export interface McpBlockView {
  id: number;
  ip: string;
  source: McpBlockSource;
  reason: string;
  firstSeenAt: string;
  lastSeenAt: string;
  hitCount: number;
  /** null: permanent. */
  blockedUntil: string | null;
  active: boolean;
  unblockedAt: string | null;
  obliguardStatus: McpObliguardStatus;
  obliguardError: string | null;
}
