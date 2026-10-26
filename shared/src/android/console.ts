// =============================================================================
// Views of the Android console (lot AN-C2, android-amapi §12): the Android side of a device's record, its menu of
// commands, the tokens of a profile, the devices awaiting approval, the catalog the policy editor generates its forms
// from, the dead letters of the inbox (platform). Identifiers, states and codes only: never a token value, a Google
// credential nor the payload of a notification outside its audited detail. Exported by the index of shared.
// =============================================================================
import type { AndroidMode } from './availability';

/** GET /api/android/devices/:id: the Android facet of a device record (minimised inventory of section 8.2). */
export interface AndroidDeviceView {
  deviceId: number;
  /** enterprises/{e}/devices/{d}: the last segment only (the enterprise is the tenant's). */
  amapiId: string;
  mode: AndroidMode | null;
  managementMode: 'DEVICE_OWNER' | 'PROFILE_OWNER';
  ownership: 'COMPANY_OWNED' | 'PERSONALLY_OWNED';
  apiLevel: number | null;
  securityPatchLevel: string | null;
  state: string | null;
  appliedState: string | null;
  approvalState: 'none' | 'pending' | 'approved' | 'rejected';
  policy: {
    name: string | null;
    pushedVersion: string | null;
    appliedVersion: string | null;
    state: 'pending' | 'delivering' | 'applied' | 'error';
    reasons: string[];
    pushedAt: string | null;
    lastSyncAt: string | null;
    compliant: boolean | null;
  };
  posture: { devicePosture: string | null; risks: string[] } | null;
  nonCompliance: Array<{ settingName?: string; nonComplianceReason?: string; packageName?: string; specificNonComplianceReason?: string }>;
  software: { androidVersion: string | null; androidBuildNumber: string | null; deviceKernelVersion: string | null } | null;
  /** hardwareInfo, as filtered at the ingestion: absent when not collected. */
  hardware?: { brand: string | null; manufacturer: string | null };
  /** networkInfo, as filtered at the ingestion: absent when not collected. */
  network?: { operatorName: string | null };
  lastStatusReportAt: string | null;
  enrolledAt: string;
  releasedAt: string | null;
  releaseReason: string | null;
}

/** One entry of GET /api/android/devices/:id/actions (section 11.2, §22.8). */
export interface AndroidDeviceAction {
  /** An AMAPI command type, or 'DISABLE' / 'ENABLE' (mdm.android_disable, devices.patch state), or 'LOCATE' (P0-13 T7:
   *  never a command, never available; its reason says whether the device sends positions in lost mode). */
  type: string;
  /** The guarded action (guard engine) or the restriction key of the command. */
  actionKey: string;
  guarded: boolean;
  available: boolean;
  /** capabilityMissing, frozen, or a prerequisite (ownership, mode, api_level_unknown, api_level_too_low, not_enrolled);
   *  for LOCATE: ownership (personal device), locationDisabledByPrivacy (privacy profile), automatic (sent by the
   *  device). */
  unavailable: string | null;
}

/** GET /api/android/enrollment-tokens: a token of the tenant, never its value. */
export interface AndroidEnrollmentTokenView {
  id: string;
  profileId: string;
  kind: 'qr' | 'byod_link' | 'zero_touch' | 'kme' | 'signin';
  state: 'creating' | 'active' | 'used' | 'expired' | 'revoked' | 'failed';
  oneTime: boolean;
  expiresAt: string;
  uses: number;
  maxUses: number | null;
  requiresApproval: boolean;
  endUserId: number | null;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

/** The payload of a token as the console shows it once (creation) or again (reveal, audited). */
export type AndroidTokenPayloadView =
  | { form: 'qr'; qrCode: string; value: string; qrDataUrl?: string }
  | { form: 'link'; url: string }
  | { form: 'kme'; json: string }
  | { form: 'zero_touch'; dpcExtras: string }
  | { form: 'signin'; url: string };

export interface AndroidCreatedTokenView {
  id: string;
  kind: AndroidEnrollmentTokenView['kind'];
  expiresAt: string;
  requiresApproval: boolean;
  payload: AndroidTokenPayloadView;
}

/** GET /api/android/devices/pending-approval: a device held DISABLED until approved (AN17). */
export interface AndroidPendingDeviceView {
  deviceId: number;
  displayName: string | null;
  model: string | null;
  ownership: 'COMPANY_OWNED' | 'PERSONALLY_OWNED';
  tokenId: string | null;
  profileId: string | null;
  enrolledAt: string;
}

/** GET /api/android/onboarding: the Android part of the onboarding assistant of a tenant. */
export interface AndroidOnboardingView {
  steps: Array<{ key: string; done: boolean }>;
}

// ── Catalog of the policy editor (generated forms) ────────────────────────────

/** A node of the form catalog: the AMAPI schema resolved one level at a time ($ref names a schema of `schemas`). */
export interface AndroidFormNode {
  type?: 'string' | 'integer' | 'number' | 'boolean' | 'object' | 'array' | 'any';
  $ref?: string;
  format?: string;
  enum?: string[];
  deprecatedValues?: string[];
  deprecated?: boolean;
  items?: AndroidFormNode;
  properties?: Record<string, AndroidFormNode>;
  additionalProperties?: AndroidFormNode;
}

/** The groups of intention the editor shows the top-level fields in. */
export const ANDROID_FORM_GROUPS = [
  'security', 'password', 'apps', 'network', 'restrictions', 'device', 'updates', 'kiosk', 'personal', 'compliance', 'other',
] as const;
export type AndroidFormGroup = typeof ANDROID_FORM_GROUPS[number];

export interface AndroidFormField {
  name: string;
  group: AndroidFormGroup;
  node: AndroidFormNode;
  /** Deprecated: refused at the write; its replacement (null: none, the field has no effect). */
  deprecated: boolean;
  replacement: string | null;
  /** Modes where the field has an effect (absent: every mode) and minimum API level. */
  modes?: AndroidMode[];
  minApi?: number;
  /** Can wipe a device or give its recovery away (published at the restricted level, held under a freeze). */
  wipeCapable: boolean;
  /** Holds a secret slot (a value in clear is refused there): the editor sends a vault reference. */
  secretSlots: boolean;
}

/** GET /api/android/policy-catalog */
export interface AndroidFormCatalogView {
  release: { revision: string; sourceSha256: string };
  fields: AndroidFormField[];
  /** The schemas named by $ref. */
  schemas: Record<string, AndroidFormNode>;
  limits: { requiredForSetupApps: number; minimumVersionCodeApps: number };
}

// ── Dead letters of the inbox (platform administrators, section 7.2) ──────────

/** GET /api/admin/android/inbox/dead (never the payload). */
export interface AndroidDeadLetterView {
  id: string;
  tenantId: number;
  eventType: string;
  messageId: string;
  resourceName: string | null;
  publishedAt: string;
  occurredAt: string;
  attempts: number;
  lastError: string | null;
  receivedAt: string;
  payloadBytes: number;
}

/** GET /api/admin/android/inbox/dead/:id (audited android.inbox_dead_letter_viewed). */
export interface AndroidDeadLetterDetail extends AndroidDeadLetterView {
  payload: unknown;
}

/** Current version of the publisher's terms accepted in the linking assistant (AN35): the server refuses another one. */
export const ANDROID_PUBLISHER_TERMS_VERSION = '2026-10';
