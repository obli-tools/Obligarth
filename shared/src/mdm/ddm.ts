// DDM state of a device as the console sees it (docs: integration-apple-edge §9.9): the declaration set the
// engine serves, what the device reported of each declaration, the synchronisation tokens, and the status items
// of the status channel. Identifiers, types, tokens and states only: never the payload of a declaration.

export const DDM_DECLARATION_FAMILIES = ['activation', 'asset', 'configuration', 'management'] as const;
export type DdmDeclarationFamily = typeof DDM_DECLARATION_FAMILIES[number];

/** What the device reported of a declaration (management.declarations). */
export interface DdmDeclarationStatusView {
  active: boolean | null;
  valid: 'valid' | 'invalid' | 'unknown' | null;
  /** The ServerToken the device holds. */
  serverToken: string | null;
  /** The device holds the version of the declaration the engine serves now. */
  current: boolean;
  /** The device's reasons (codes, descriptions), when it gave some. */
  reasons: unknown[] | null;
  observedAt: string;
}

/** A declaration of the set served to the device. */
export interface DdmDeclarationView {
  family: DdmDeclarationFamily;
  identifier: string;
  type: string;
  serverToken: string;
  /** null until the device reported it. */
  status: DdmDeclarationStatusView | null;
}

/** A declaration the device reports and the set no longer holds (being removed, or not the engine's). */
export interface DdmReportedDeclarationView {
  family: DdmDeclarationFamily;
  identifier: string;
  status: DdmDeclarationStatusView;
}

export interface DeviceDeclarationsView {
  ddmEnabled: boolean;
  ddmEnabledAt: string | null;
  /** The device reported its client capabilities (before that, its set is empty). */
  capabilitiesKnown: boolean;
  /** null: no set computed yet. */
  declarationsToken: string | null;
  computedAt: string | null;
  /** The token the last DeclarativeManagement command announced. */
  sentToken: string | null;
  /** A DeclarativeManagement command is waiting for the device. */
  syncOpen: boolean;
  /** The token of the last declaration-items the device fetched. */
  fetchedToken: string | null;
  fetchedAt: string | null;
  declarations: DdmDeclarationView[];
  reportedOnly: DdmReportedDeclarationView[];
}

/** A status item of the device (last value). */
export interface DeviceStatusItemView {
  item: string;
  value: unknown;
  error: unknown | null;
  observedAt: string;
  /** apple.status.<item> (the console falls back on the item's name). */
  i18nKey: string;
}

export interface DeviceStatusHistoryEntry {
  item: string;
  value: unknown;
  observedAt: string;
}

/** POST /api/apple/devices/:id/ddm-sync. */
export interface DdmSyncRequestOutcome {
  /** false: a synchronisation of this device was already requested within the minute. */
  requested: boolean;
}
