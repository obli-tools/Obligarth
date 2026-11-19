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
  /** Obliwatch analysts may ask actions on one device (lot L5, owner decision Q-L5a: a valid request is executed at
   *  once, without a second factor nor an approver; erase and removal always refused, capped, journaled). */
  actions: boolean;
  /** The nominative view of the AI apps (aggregates otherwise). On by default for a tenant that consents to be read
   *  (decision AR-55/AR-57): turned on with the read access unless turned off explicitly; revocable. */
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
  /** The state of the push of the signals (lot L3); null when it cannot be read. */
  pushStatus: ObliwatchPushStatus | null;
}

/** PUT body. nominativeAiApps may be left out (kept, or turned on with the read access: see ObliwatchConsentFlags). */
export type ObliwatchConsentBody = Omit<ObliwatchConsentFlags, 'nominativeAiApps'> & { nominativeAiApps?: boolean };

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

/** The Apple managed device attestation of a device (GTH-08, added in lot L5): 'verified' (the last attestation, at most
 *  30 days old, chains to Apple's Enterprise Attestation root and matches the device), 'failed' (D-MOB-ATTEST-FAILED is
 *  active), 'not_collected' (an Apple device not attested: no push consent, an OS without the query, nothing yet: never
 *  read as healthy), 'not_applicable' (Android, bridge agent). */
export type ObliwatchAttestationCoverage = 'verified' | 'failed' | 'not_collected' | 'not_applicable';

export interface ObliwatchCoverage {
  integrity: ObliwatchIntegrityCoverage;
  apps: ObliwatchAppsCoverage;
  /** True only when the security logs of the device are actually collected (GTH-08, SEC-13): an AMAPI company-owned
   *  fully managed device of a tenant with the push consent, whose security logs reached Obligarth within 7 days. False
   *  means NOT COLLECTED (never "nothing to report"). */
  securityLogs: boolean;
  /** Added in lot L5 (GTH-08): see ObliwatchAttestationCoverage. */
  attestation: ObliwatchAttestationCoverage;
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
  /** The end user's UPN (end_users.upn), else their e-mail address (lot L4: the same rule as user.upn of the push). */
  primaryUpn: string | null;
  /** Where primaryUpn comes from: 'upn' (end_users.upn), 'email' (the e-mail address, no UPN entered), 'none'. */
  primaryUpnSource: ObliwatchUpnSource;
  /** The end user's object id in Entra ID (end_users.entra_object_id), null when not entered (lot L4). */
  entraObjectId: string | null;
  /** The version of Microsoft Authenticator (com.azure.authenticator on Android, com.microsoft.azureauthenticator on
   *  Apple) found in the inventory; null when absent or unknown (lot L4, GTH-06). */
  authenticatorVersion: string | null;
  /** True when Obligarth can tell: the app was found, or every app of the device is collected (apps coverage 'full'
   *  on a corporate device) and it is not there. False: unknown, NEVER to be read as absent. */
  authenticatorKnown: boolean;
  coverage: ObliwatchCoverage;
  /** The change marker (devices.signal_updated_at): the order of GET /devices and the bound of updatedSince. */
  updatedAt: string;
}

export type ObliwatchUpnSource = 'upn' | 'email' | 'none';

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
  /** Lot L4 (GTH-06): true when the bundles of the AI catalog are left out of `items` (managed or not), because the
   *  nominative view of the AI apps is not open for the tenant (consent nominativeAiApps AND Obliwatch's attestation);
   *  set whether or not such an app is on the device. The aggregates stay in GET /apps/ai-summary. */
  aiAppsWithheld: boolean;
  /** Lot L4: true when only the managed apps are listed (apps coverage not 'full', or the work side only of a personal
   *  device, a work profile or a User Enrollment: a personal app is never listed). */
  managedOnly: boolean;
}

// ── Push of the D-MOB-* signals (GTH-01), lot L3 ──────────────────────────────────────────────────────────────────

/** The rules Obligarth computes and pushes to Obliwatch (POST /api/ingest/v1/alerts, source 'mobile'). */
export const OBLIWATCH_RULE_IDS = [
  'D-MOB-INT-COMPROMISED', 'D-MOB-INT-ATRISK', 'D-MOB-MGMT-REMOVED', 'D-MOB-ID-MISMATCH', 'D-MOB-OS-OUTDATED',
  'D-MOB-NONCOMPLIANT', 'D-MOB-STALE', 'D-MOB-LOST-EXIT',
  // Lot L5 (GTH-08): Apple managed device attestation, and the aggregated detections of the AMAPI security logs (SEC-13).
  'D-MOB-ATTEST-FAILED',
  'D-MOB-SEC-USER-CA', 'D-MOB-SEC-ADB', 'D-MOB-SEC-UNLOCK-BURST', 'D-MOB-SEC-KEY-INTEGRITY', 'D-MOB-SEC-LOGGING-STOPPED',
] as const;
export type ObliwatchRuleId = (typeof OBLIWATCH_RULE_IDS)[number];

/** The state of the push of a tenant, shown in the consent card (counts and dates only). */
export interface ObliwatchPushStatus {
  /** Transitions waiting to be sent (retried with a backoff, for 72 hours at most). */
  pending: number;
  /** Transitions given up after 72 hours (or refused by Obliwatch as invalid): the dead letters. */
  dead: number;
  /** The last transition Obliwatch accepted. */
  lastSentAt: string | null;
  /** The last failure of a send (a short text, never a token), while transitions are still pending. */
  lastError: string | null;
}

/** POST /api/integrations/obliwatch/push/retry-dead: the dead letters put back in the queue. */
export interface ObliwatchPushRetryResponse {
  requeued: number;
}

// ── AI apps (GTH-06), lot L4 ──────────────────────────────────────────────────────────────────────────────────────

/** The bundle identifiers of Microsoft Authenticator, per platform family (GTH-06, DeviceView.authenticatorVersion). */
export const AUTHENTICATOR_BUNDLES = { android: 'com.azure.authenticator', ios: 'com.microsoft.azureauthenticator' } as const;

/** The platforms of the AI catalog of Obliwatch ('ios': every Apple device, the bundle ids are shared). */
export type ObliwatchCatalogPlatform = 'android' | 'ios';

/** Bundles of the AI catalog kept at most (GET {obliwatch}/api/external/v1/catalogues/ai-domains, section bundles). */
export const OBLIWATCH_AI_CATALOG_MAX = 5000;

/** A bundle identifier (Android package, Apple bundle id): letters, digits, '_' and '-', in two dotted parts or more. */
export const OBLIWATCH_BUNDLE_ID_RE = /^[A-Za-z0-9_-]{1,100}(\.[A-Za-z0-9_-]{1,100}){1,20}$/;

/** 'ok': a catalog fetched in the last 3 days; 'stale': an older one (still used); 'unavailable': none ever fetched. */
export type ObliwatchCatalogStatus = 'ok' | 'stale' | 'unavailable';

export interface ObliwatchAiSummaryItem {
  bundleId: string;
  platform: ObliwatchCatalogPlatform;
  /** Devices of the tenant where the app was seen (see the rules of GET /apps/ai-summary). */
  devices: number;
  /** ?nominative=1 only (tenant consent nominativeAiApps AND attestation signalled by producer-config): the uuids of
   *  those devices, sorted; never a name. */
  deviceUuids?: string[];
}

/**
 * GET /apps/ai-summary[?nominative=1]: the AI apps of the catalog seen on the devices of the tenant (enrolled, not
 * unenrolled). An app counts on a device when the device's apps coverage is 'full' on a corporate device, or when it
 * is a MANAGED app; a personal app of a personal or work-profile device is never counted. `coverage`: the devices per
 * apps coverage, so that a zero is read with what Obligarth can see.
 */
export interface ObliwatchAiSummaryResponse {
  catalogVersion: string | null;
  catalogStatus: ObliwatchCatalogStatus;
  catalogFetchedAt: string | null;
  nominative: boolean;
  items: ObliwatchAiSummaryItem[];
  coverage: { full: number; managed_only: number; none: number };
}

// ── Action requests (GTH-04) and their results (GTH-05), lot L5 ─────────────────────────────────────────────────────

/** The actions Obliwatch may ask, one device per request. Anything else (erase, removal from management, passcode
 *  clearing, password reset, a list of targets) is refused: 422 actionNotAllowed. */
export const OBLIWATCH_ACTIONS = ['lost_mode_enable', 'lost_mode_disable', 'device_location', 'play_sound', 'device_lock'] as const;
export type ObliwatchAction = (typeof OBLIWATCH_ACTIONS)[number];

/**
 * The states of a request. Owner decision Q-L5a (Obliwatch has the "god mode"): no human approval, a valid request is
 * executed at once; the machine is accepted → executing → done | failed | refused | expired | cancelled.
 * 'awaiting_approval' and 'approved' belong to the brief's enumeration and are NEVER used (kept so that a consumer
 * written against the brief still parses the type).
 *   accepted   recorded, the execution not started yet (a guarded action scheduled; a tenant frozen meanwhile keeps it
 *              here until it expires)
 *   executing  the command is written for the device and waits for its answer
 *   done       the device acknowledged the command
 *   failed     the device answered an error, or the execution failed
 *   refused    refused at execution (rights, device no longer eligible, the device service refused the command)
 *   expired    no answer within 24 hours of the request (its open commands withdrawn), or the command expired
 *   cancelled  cancelled before its execution (POST …/cancel), or the command was cancelled
 */
export const OBLIWATCH_ACTION_STATES = ['accepted', 'awaiting_approval', 'approved', 'executing', 'done', 'failed', 'refused', 'expired', 'cancelled'] as const;
export type ObliwatchActionState = (typeof OBLIWATCH_ACTION_STATES)[number];

/** The final states (a request that reached one never changes again). */
export const OBLIWATCH_ACTION_FINAL_STATES: readonly ObliwatchActionState[] = ['done', 'failed', 'refused', 'expired', 'cancelled'];

/** The refusal codes of POST /action-requests (422 {error, code, reason, message}). */
export type ObliwatchActionRefusal =
  | 'actionNotAllowed' | 'notSupported' | 'supervisionRequired' | 'ownershipForbidden' | 'lostModeRequired' | 'lostModeCooldown'
  | 'notEnrolled' | 'locationDisabled';

/** POST /action-requests (user token of the analyst, consent 'actions'). params: lost_mode_enable {message, phone}
 *  required (footnote optional, Apple); device_lock {message?, phone?} (Apple only, ignored elsewhere); the others {}. */
export interface ObliwatchActionRequestBody {
  deviceUuid: string;
  action: ObliwatchAction;
  params?: Record<string, unknown>;
  /** 10 to 500 characters. */
  reason: string;
  /** Obliwatch's reference of the incident (1 to 200 characters), e.g. obliwatch:INC-42@example. */
  incidentRef: string;
  /** Idempotency: Obliwatch's own uuid of the request, which becomes the requestId; the same uuid again answers the
   *  request already recorded (202), a different payload under it 409 idempotency_conflict. */
  requestUuid?: string;
  /** The analyst as Obliwatch names them (display only, recorded in the journal next to the local account). */
  requestedBy?: string;
}

/** 202 of POST /action-requests. approvalUrl is always null (no approval, Q-L5a). */
export interface ObliwatchActionRequestAccepted {
  requestId: string;
  state: ObliwatchActionState;
  expiresAt: string;
  approvalRequired: false;
  approvalUrl: null;
}

/** The result of a request, never a coordinate: for device_location, whether a position was obtained and its accuracy
 *  bucket only. `code`: why a request failed, was refused or expired (absent otherwise). */
export interface ObliwatchActionResult {
  action: ObliwatchAction;
  code?: string;
  locationObtained?: boolean;
  accuracyBucket?: '<100m' | '100m-1km' | '>1km';
}

/** GET /action-requests/:id (app or user token). */
export interface ObliwatchActionRequestView {
  requestId: string;
  deviceUuid: string;
  action: ObliwatchAction;
  state: ObliwatchActionState;
  /** Increments on each transition (the seq of the results pushed). */
  seq: number;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  result: ObliwatchActionResult | null;
}

/** One item of POST {obliwatch}/api/ingest/v1/action-results {results: [...]} (GTH-05), one per transition. */
export interface ObliwatchActionResultItem {
  uuid: string;
  status: ObliwatchActionState;
  at: string;
  seq: number;
  result: ObliwatchActionResult;
}
