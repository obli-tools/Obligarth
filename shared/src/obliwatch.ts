// =============================================================================
// Obliwatch integration (brief GTH-01..09): the shapes shared by the server and the console. Obliwatch reads
// Obligarth through /api/integrations/obliwatch/v1 with an app token of Obligate (sub app:obliwatch, aud obligarth,
// ost = the tenant's slug), only for a tenant that consented. Nothing here carries a hardware identifier.
// =============================================================================

/** Version of the read API, answered by GET /ping. */
export const OBLIWATCH_API_VERSION = 1;

/** Base path of the read API (mounted only when OBLIWATCH_INTEGRATION=on). */
export const OBLIWATCH_API_BASE = '/api/integrations/obliwatch/v1';

/** The format Obliwatch requires for `ost` (its verifier refuses any other slug). */
export const OBLIWATCH_SLUG_RE = /^[a-z0-9-]{1,64}$/;

/** The consent flags of a tenant: each one off until a manager of the tenant turns it on. */
export interface ObliwatchConsentFlags {
  /** Obliwatch may read this tenant (devices, coverage, access keys). */
  read: boolean;
  /** Obligarth pushes the D-MOB-* signals of this tenant to Obliwatch. */
  push: boolean;
  /** Obliwatch analysts may ask actions (each one approved in Obligarth with a second factor). */
  actions: boolean;
  /** The nominative view of the AI apps (aggregates otherwise). */
  nominativeAiApps: boolean;
}

/** GET/PUT /api/integrations/obliwatch/consent (console, current tenant). */
export interface ObliwatchConsentView extends ObliwatchConsentFlags {
  tenantId: number;
  slug: string;
  /** False when the slug does not fit OBLIWATCH_SLUG_RE: nothing can be turned on (422 slugIncompatible). */
  slugCompatible: boolean;
  changedAt: string | null;
  changedBy: { userId: number; username: string | null } | null;
}

export type ObliwatchConsentBody = ObliwatchConsentFlags;

/** GET /ping. Served without consent, for the diagnostic of the link. */
export interface ObliwatchPingResponse {
  ok: true;
  tenant: string;
  consent: { read: boolean; push: boolean; actions: boolean };
  apiVersion: number;
}

export type ObliwatchKeyState = 'active' | 'expired' | 'revoked';

/** One MCP access key reaching the tenant of `ost` (GTH-07). Never the hash of the secret. */
export interface ObliwatchAccessKeyItem {
  id: string;
  name: string;
  /** userId is null for a platform administrator's key (shown by username only). */
  owner: { userId: number | null; username: string; platformAdmin: boolean };
  scopes: string[];
  /** Reduced to the tenant of `ost`: no identifier of another tenant, a count of the devices. */
  perimeter: {
    tenantMode: 'all' | 'list';
    groupMode: 'all' | 'list';
    deviceMode: 'all' | 'list';
    groups: number[];
    devicesCount: number;
    /** Always false: a key the tenant excluded no longer reaches it and is not listed. */
    excluded: false;
  };
  ipAllow: string[];
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokeReason: string | null;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  state: ObliwatchKeyState;
}

/** GET /access-keys?limit=1..200&cursor=. */
export interface ObliwatchAccessKeysResponse {
  items: ObliwatchAccessKeyItem[];
  nextCursor: string | null;
}

/** The body of every refusal of the read API. */
export interface ObliwatchErrorResponse {
  error: string;
  message: string;
}

// ── Devices (GTH-03) and their coverage (GTH-09), lot L2 ──────────────────────────────────────────────────────────

/** What Obligarth can see of the integrity of a device. 'unknown': an AMAPI device without a posture reported yet
 *  (never presented as healthy; a value beyond the brief's three, announced to Obliwatch, owner decision Q-L2b). */
export type ObliwatchIntegrityCoverage = 'covered' | 'unknown' | 'not_covered_apple' | 'not_covered_legacy';

/** What Obligarth collects of the apps of a device: all of them, the managed ones only (privacy profile of the
 *  ownership), or nothing yet. */
export type ObliwatchAppsCoverage = 'full' | 'managed_only' | 'none';

export interface ObliwatchCoverage {
  integrity: ObliwatchIntegrityCoverage;
  apps: ObliwatchAppsCoverage;
  /** Always false: no security log is ingested (GTH-08). */
  securityLogs: boolean;
}

/**
 * One device of the tenant of `ost` (GET /devices, GET /devices/:uuid). A strict whitelist: never a serial number,
 * IMEI, UDID, phone number, MAC address, IP, location, Android id nor the internal id; the uuid is the join key.
 */
export interface ObliwatchDeviceView {
  uuid: string;
  platform: string;
  ownership: 'corporate' | 'corporate_personal' | 'personal';
  managementMode: string;
  /** null on Android (no supervision there). */
  supervised: boolean | null;
  enrollmentState: string;
  /** The device's name, for a corporate-owned device only (corporate, corporate_personal); null on a personal one
   *  (owner decision Q-L2c), and null when it holds the serial number. */
  hostname: string | null;
  osVersion: string | null;
  /** YYYY-MM-DD: AMAPI or bridge agent; null on Apple. */
  securityPatchLevel: string | null;
  complianceState: string;
  /** The codes only, never their detail. */
  complianceCodes: string[];
  /** AMAPI only (Play Integrity), else null. */
  integrityPosture: string | null;
  integrityRisks: string[] | null;
  lostModeState: string;
  lastCheckinAt: string | null;
  /** The end user's address until end_users.upn exists (lot L4). */
  primaryUpn: string | null;
  primaryUpnSource: 'email' | 'none';
  coverage: ObliwatchCoverage;
  /** The change marker (devices.signal_updated_at): the order of GET /devices and the bound of updatedSince. */
  updatedAt: string;
}

/** GET /devices?updatedSince=&limit=1..500&cursor=. */
export interface ObliwatchDevicesResponse {
  items: ObliwatchDeviceView[];
  nextCursor: string | null;
}

export interface ObliwatchDeviceAppItem {
  identifier: string;
  version: string | null;
  shortVersion: string | null;
  managed: boolean;
}

/** GET /devices/:uuid/apps: the managed apps only unless the privacy profile collects them all; nothing personal. */
export interface ObliwatchDeviceAppsResponse {
  items: ObliwatchDeviceAppItem[];
  coverage: ObliwatchAppsCoverage;
  collectedAt: string | null;
}
