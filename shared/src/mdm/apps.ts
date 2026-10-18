// The catalog of apps and Apps and Books as the console sees them (docs: modele-donnees-mdm §8;
// integration-apple-edge §11.3; lot C4): the apps of a tenant, the options of an app assignment, the content
// tokens of Apps and Books, their licences (assets) and the asynchronous operations. No secret ever: a content
// token is sealed in the brain's vault and never leaves it.

import type { JsonValue } from './policyContent';

/** Kinds of an Apple app of the catalog at the MVP ('enterprise' comes in v1 with the signed URL store). */
export const APPLE_APP_KINDS_MVP = ['app_store', 'custom'] as const;
export type AppleAppKindMvp = typeof APPLE_APP_KINDS_MVP[number];

/** The options of an app assignment (section 8.2), validated by the server (AppleAppOptionsSchema). */
export interface AppleAppOptions {
  /** 'required': installed and kept. 'available' (self-service catalog) is v1. */
  install: 'required';
  /** Attributes.Removable (iOS 14+); false keeps the user from deleting the app. Forced to true on a personal device. */
  removable: boolean;
  /** ManagementFlags bit 1: the app goes away with the MDM profile. */
  removeOnUnenroll: boolean;
  /** ManagementFlags bit 4: no backup of the app's data. */
  preventBackup: boolean;
  /** ChangeManagementState 'Managed': take over an app the user installed (never in User Enrollment). */
  takeOver: boolean;
  /** Managed app configuration (APP-03): plist-compatible values, variables allowed, no secret at the MVP. */
  config?: Record<string, JsonValue>;
}

export const APPLE_APP_OPTION_DEFAULTS: Readonly<AppleAppOptions> = Object.freeze({
  install: 'required', removable: false, removeOnUnenroll: true, preventBackup: false, takeOver: false,
});

/** An app of the catalog. */
export interface AppCatalogEntry {
  id: number;
  uuid: string;
  tenantId: number;
  platformFamily: 'apple' | 'android';
  kind: string;
  identifier: string;
  storeId: string | null;
  name: string;
  publisher: string | null;
  iconUrl: string | null;
  supportedPlatforms: string[];
  minimumOsVersion: string | null;
  licenseMode: 'vpp' | 'none';
  metadataRefreshedAt: string | null;
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
  /** Assignments of the app in the tenant. */
  assignments: number;
  /** Licences of the tenant for the app (every live content token): total, assigned, available. */
  licenses: { total: number; assigned: number; available: number } | null;
}

/** The page of an app: the catalog entry and what the inventory shows (section 8.4). */
export interface AppDetail extends AppCatalogEntry {
  installs: {
    installed: number;
    managed: number;
    failed: number;
    versions: Array<{ version: string; devices: number }>;
  };
  /** The delivery of the app to the devices it is assigned to, by state of their artifact. */
  delivery: Record<string, number>;
}

/** States of a content token (tenant_apple_vpp_tokens.state). */
export const VPP_TOKEN_STATES = ['active', 'foreign_mdm', 'expired', 'invalid', 'removed'] as const;
export type VppTokenState = typeof VPP_TOKEN_STATES[number];

export interface VppTokenView {
  id: string;
  label: string;
  state: VppTokenState;
  stateAt: string;
  orgName: string | null;
  locationName: string | null;
  expDate: string;
  lastSyncAt: string | null;
  testNotificationAt: string | null;
  lastNotificationAt: string | null;
  consecutiveErrors: number;
  lastErrorCode: string | null;
  appleAccountHint: string | null;
  createdAt: string;
  /** Licences mirrored for the token. */
  assets: number;
  /** Operations not finished yet. */
  pendingOperations: number;
}

/** A licence of a content token (vpp_assets). */
export interface VppAssetView {
  id: number;
  tokenId: string;
  adamId: string;
  pricingParam: string;
  productType: string;
  deviceAssignable: boolean;
  revocable: boolean;
  supportedPlatforms: string[];
  totalCount: number;
  assignedCount: number;
  availableCount: number;
  retiredCount: number;
  updatedAt: string;
  /** The app of the catalog with this App Store id, when there is one. */
  appId: number | null;
}

export const VPP_OPERATION_KINDS = ['associate', 'disassociate', 'revoke', 'users_create', 'users_update', 'users_retire'] as const;
export type VppOperationKind = typeof VPP_OPERATION_KINDS[number];
export const VPP_OPERATION_STATES = ['requested', 'pending', 'complete', 'failed', 'abandoned'] as const;
export type VppOperationState = typeof VPP_OPERATION_STATES[number];

/** An asynchronous operation, as the console lists it (counts only: never a serial number nor a user). */
export interface VppOperationListItem {
  id: string;
  tokenId: string;
  kind: VppOperationKind;
  state: VppOperationState;
  assets: number;
  serialNumbers: number;
  clientUserIds: number;
  eventId: string | null;
  requestedByRef: string | null;
  createdAt: string;
  completedAt: string | null;
  failures: number;
}

/** Bounds of the Apps and Books files and fields (§11.3). */
export const VPP_LIMITS = Object.freeze({
  /** A .vpptoken file. */
  tokenFileBytes: 16 * 1024,
  label: 100,
  /** A notification body. */
  notificationBytes: 1024 * 1024,
});
