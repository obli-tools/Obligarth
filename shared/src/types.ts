// =============================================================================
// Obligarth MDM — Shared Types
// =============================================================================

import type { DeviceCapability, TenantCapability } from './capabilities';

// ─── USERS ────────────────────────────────────────────────────────────────────

export interface User {
  id: number;
  username: string;
  displayName: string | null;
  role: 'admin' | 'user';
  isActive: boolean;
  email: string | null;
  preferredLanguage: string;
  enrollmentVersion: number;
  preferences: UserPreferences;
  totpEnabled: boolean;
  emailOtpEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  // SSO
  foreignSource: string | null;
  foreignId: number | null;
  foreignSourceUrl: string | null;
  hasPassword: boolean;
  avatar: string | null;
}

export interface UserWithPassword extends User {
  passwordHash: string;
  totpSecret: string | null;
}

/**
 * Web theme ids. `obli-dim` is the mid-dark (Nord Polar Night) companion of
 * `obli-daylight`: it changes neutrals only, Obli Operator's raspberry accent
 * stays (client/src/index.css).
 */
export type AppTheme = 'obli-operator' | 'modern' | 'neon' | 'obli-daylight' | 'obli-dim';

export interface UserPreferences {
  toastEnabled?: boolean;
  toastPosition?: 'top-center' | 'bottom-right';
  multiTenantNotifications?: boolean;
  sidebarFloating?: boolean;
  theme?: 'dark' | 'light';
  preferredTheme?: AppTheme;
  /** Anonymous mode — masks hostnames, IPs, usernames in the UI (for demos/screenshots). */
  anonymousMode?: boolean;
}

// ─── TENANTS ─────────────────────────────────────────────────────────────────

export interface Tenant {
  id: number;
  name: string;
  slug: string;
  /** When true, destructive batch/uninstall actions require a 2nd admin approval. */
  twoStepApproval?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface TenantWithRole extends Tenant {
  role: 'admin' | 'member';
}

export interface TenantMembership {
  userId: number;
  tenantId: number;
  role: 'admin' | 'member';
}

// ─── DEVICE GROUPS ───────────────────────────────────────────────────────────

export interface DeviceGroup {
  id: number;
  tenantId: number;
  /** Optional resolved tenant display name. Surfaced in master/god-view
   *  responses so the sidebar can render tenant headers above each
   *  child tenant's group sub-tree. Undefined / null when the row was
   *  fetched inside a single-tenant context (the column is implicit). */
  tenantName?: string | null;
  parentId: number | null;
  name: string;
  slug: string;
  description: string | null;
  sortOrder: number;
  groupNotifications: boolean;
  /** When true, devices in this group (and sub-groups, via inheritance) are
   *  expected to be permanently powered on. A device going offline is then
   *  treated as a CRITICAL fault: immediate channel notification + a
   *  'critical'-severity bell alert (vs the benign 'info' used for ordinary
   *  workstations). Default false. */
  alwaysOn: boolean;
  groupConfig: DeviceGroupConfig;
  /** Lot D.2 — per-group metric thresholds. Empty object means "use system
   *  default". Each metric key may set a `warn` and/or `crit` percentage. */
  thresholds: MetricThresholds;
  /** Whether metric-threshold-driven status flips and notifications fire
   *  for devices in this group, unless the device overrides individually.
   *  `null` = use system default (true). */
  metricAlertsEnabled: boolean | null;
  uuid: string;
  createdAt: string;
  updatedAt: string;
}

export interface DeviceGroupTreeNode extends DeviceGroup {
  children: DeviceGroupTreeNode[];
  deviceCount?: number;
  onlineCount?: number;
  offlineCount?: number;
  warningCount?: number;
  criticalCount?: number;
  /** Total device count (alias/aggregate): the devices under management (MDM). */
  total?: number;
  /** MDM counters of the group and its subtree (modele-donnees-mdm §11.3): enrolled, non compliant, in
   *  configuration error, without contact for mdmStaleAfterDays days. The online / offline / warning /
   *  critical counters of the removed agent stay at 0 until the console moves to these (lot B6). */
  enrolledCount?: number;
  nonCompliantCount?: number;
  configErrorCount?: number;
  staleCount?: number;
  /** Optional kind discriminator for mixed-type trees */
  kind?: string;
}

// ─── DEVICES ─────────────────────────────────────────────────────────────────
// The registry views (DeviceSummary, DeviceDetail, MdmFleetSummary…) are in ./mdm/devices.ts; the device type
// of the removed agent left with the console of the model (lot B6).


// ─── GROUP FIELDS OF THE REMOVED RMM ─────────────────────────────────────────
//
// What the removed agent and supervision kept on a group (agent settings,
// metric thresholds). DeviceGroup still declares these fields, mapped from
// their columns; nothing writes them any more. What the agent reported on a
// device (hardware and software inventory, metrics, roles) left with its
// device type (lot B6).

/** Lot D.2 — Pair of warn/crit percentages applied to a single metric.
 *  Either field may be undefined (inherited from the layer above).
 *
 *  `notify` is the per-metric ALERTS switch, tri-state per layer:
 *    - undefined = inherit from the layer above (default: alerts on),
 *    - true      = alerts on (re-enables what a parent layer muted),
 *    - false     = muted: the metric still drives the device status but
 *                  never sends a notification.
 *  Note: warn=0 / crit=0 keeps its historical meaning ("always critical"). */
export interface MetricThreshold { warn?: number; crit?: number; notify?: boolean }

/** Lot D.2 — Map of metric kind → threshold pair. Stored verbatim in JSONB
 *  on both `device_groups.thresholds` and `devices.thresholds_override`.
 *
 *  `diskByMount` lets admins set per-mount-point overrides — e.g. tighter
 *  thresholds on `/var` or `D:` than the default disk slot. Mounts not
 *  listed fall back to the generic `disk` threshold, then to the system
 *  default. cpu / ram stay generic; the breakdown isn't useful enough to
 *  carry the same UX cost as disk. */
export type MetricThresholds = Partial<{
  disk: MetricThreshold;
  cpu: MetricThreshold;
  ram: MetricThreshold;
  diskByMount: Record<string, MetricThreshold>;
}>;

export interface DeviceGroupConfig {
  pushIntervalSeconds?: number;
  scanIntervalSeconds?: number;
  maxMissedPushes?: number;
  autoApprove?: boolean;
}


// ─── LICENSES ────────────────────────────────────────────────────────────────

export interface DeviceLicense {
  id: number;
  deviceId: number;
  tenantId: number;
  softwareName: string;
  licenseKey: string | null;
  licenseType: 'per_device' | 'per_user' | 'volume' | 'subscription' | 'other' | null;
  seats: number | null;
  expiryDate: string | null;
  vendor: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
}


// ─── SOFTWARE REPOSITORY ─────────────────────────────────────────────────────

export interface SoftwareRepoPackage {
  id: number;
  uuid: string;
  tenantId: number;
  filename: string;
  displayName: string | null;
  fileSize: number;
  fileHash: string;
  mimeType: string | null;
  platform: 'windows' | 'linux' | 'macos';
  uploadedBy: number | null;
  createdAt: string;
}

/**
 * Per-tenant software-repository settings + live usage. Returned by
 * GET /api/software-repo/settings. `quotaBytes: null` means unlimited.
 * The plaintext access key is NEVER returned here — only `keyPrefix`
 * (for display) and `hasKey`. The full key is surfaced exactly once,
 * in the response of POST /api/software-repo/access-key.
 */
export interface SoftwareRepoSettings {
  enabled: boolean;
  quotaBytes: number | null;
  usedBytes: number;
  packageCount: number;
  hasKey: boolean;
  keyPrefix: string | null;
}

// ─── NOTIFICATIONS ───────────────────────────────────────────────────────────

export type NotificationChannelType =
  | 'telegram' | 'discord' | 'slack' | 'teams'
  | 'smtp' | 'webhook' | 'gotify' | 'ntfy' | 'pushover' | 'freemobile';

export type OverrideMode = 'merge' | 'replace' | 'exclude';

export interface NotificationChannel {
  id: number;
  tenantId: number;
  name: string;
  type: NotificationChannelType;
  /** The public settings of the channel: never a secret field (write-only,
   *  sealed by the server's vault). When the caller doesn't own this
   *  channel (master fan-out into a child tenant), any other key that
   *  looks secret is replaced by the literal string `__REDACTED__` as well;
   *  the UI uses `readOnly` below to switch the editor into read-only mode. */
  config: Record<string, any>;
  /** Names of the secret fields that hold a value (sealed, never returned):
   *  the form shows them as "set" and sends a new value only to replace one
   *  (coffre-secrets V8). Empty for a channel the caller does not own. */
  secretFieldsSet: string[];
  uuid: string;
  createdAt: string;
  updatedAt: string;
  /** True when the caller's tenant is NOT the channel owner — i.e.
   *  this is a master-fan-out channel surfaced to a child tenant.
   *  The client treats it as visible-but-unmodifiable. Server-side
   *  edit / delete / binding endpoints already enforce the same rule
   *  (see assertChannelOwnedByCaller). */
  readOnly?: boolean;
}

export interface NotificationBinding {
  id: number;
  tenantId: number;
  channelId: number;
  scope: 'global' | 'group' | 'device';
  scopeId: number | null;
  overrideMode: OverrideMode;
}

// ─── SETTINGS ────────────────────────────────────────────────────────────────

export type SettingScope = 'global' | 'group' | 'device';

export interface SettingValue {
  id: number;
  tenantId: number;
  scope: SettingScope;
  scopeId: number | null;
  key: string;
  value: any;
  createdAt: string;
  updatedAt: string;
}

// ─── MAINTENANCE ─────────────────────────────────────────────────────────────

export type MaintenanceScope = 'global' | 'group' | 'device';
export type MaintenanceScheduleType = 'one_time' | 'recurring';

export interface MaintenanceRecurrenceRule {
  frequency?: 'daily' | 'weekly';
  daysOfWeek?: number[];
  time?: string;
  duration?: number; // minutes
}

export interface MaintenanceWindow {
  id: number;
  tenantId: number;
  name: string;
  scopeType: MaintenanceScope;
  scopeId: number | null;
  scheduleType: MaintenanceScheduleType;
  startsAt: string;
  endsAt: string;
  /** @deprecated Use startsAt instead */
  startAt?: string;
  /** @deprecated Use endsAt instead */
  endAt?: string;
  recurrenceRule: MaintenanceRecurrenceRule;
  timezone: string;
  notificationChannels: number[];
  lastDedupKey: string | null;
  createdBy: number | null;
  createdAt: string;
  updatedAt: string;
  // Additional fields returned by the API for effective/resolved windows
  startTime?: string | null;
  endTime?: string | null;
  recurrenceType?: MaintenanceRecurrenceType | null;
  daysOfWeek?: number[] | null;
  notifyChannelIds?: number[];
  active?: boolean;
  isActiveNow?: boolean;
  isDisabledHere?: boolean;
  /** Source of this window when fetching effective windows: 'local' | 'global' | 'group' */
  source?: 'local' | 'global' | 'group';
  sourceName?: string;
  /** Display name of the scope target */
  scopeName?: string;
  canEdit?: boolean;
  canDelete?: boolean;
  canDisable?: boolean;
  canEnable?: boolean;
}

// ─── TEAMS & RBAC ────────────────────────────────────────────────────────────

export interface UserTeam {
  id: number;
  tenantId: number;
  name: string;
  canCreate: boolean;
  uuid: string;
  createdAt: string;
  updatedAt: string;
  /** Optional: tenant name (populated when fetching all teams as platform admin) */
  tenantName?: string;
  /** Optional: team description */
  description?: string | null;
}

export interface TeamMembership {
  teamId: number;
  userId: number;
}

export interface TeamPermission {
  id: number;
  tenantId: number;
  teamId: number;
  /** 'group' / 'device' = scoped to a specific row.
   *  'ungrouped' = catch-all for devices with group_id IS NULL whose
   *  enrolling API key has no default_group_id (orphan devices).
   *  scope_id is 0 by convention for 'ungrouped' since there's no
   *  matching row to point at. */
  scope: 'group' | 'device' | 'ungrouped';
  scopeId: number;
  level: 'ro' | 'rw';
  /** Device capabilities on the devices of the row (capabilities.ts). */
  capabilities: DeviceCapability[];
}

// ─── SMTP ────────────────────────────────────────────────────────────────────

export interface SmtpServer {
  id: number;
  tenantId: number | null;
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string | null;
  fromAddress: string | null;
  createdAt: string;
  updatedAt: string;
}

// ─── LIVE ALERTS ─────────────────────────────────────────────────────────────

export type AlertSeverity = 'info' | 'warning' | 'critical' | 'down' | 'up';

/**
 * A live alert (web bell, mobile "À traiter"). Only ACTIVE alerts reach the
 * clients: once the incident behind an alert recovers (device back online,
 * metrics back under threshold, disk health good again…) or escalates to a
 * new row, the server resolves it — it disappears from every list and a
 * `NOTIFICATION_RESOLVED` socket event (`LiveAlertsResolvedEvent`) tells
 * open clients to drop it. No "back to normal" alert is created any more.
 */
export interface LiveAlert {
  id: number;
  tenantId: number;
  severity: AlertSeverity;
  title: string;
  message: string | null;
  navigateTo: string | null;
  stableKey: string | null;
  readAt: string | null;
  createdAt: string;
  /** Optional: tenant name (populated for cross-tenant alerts) */
  tenantName?: string;
  /** Catalogue kind of an alert of a module (Apple integration: integration-apple-edge §12.1); null for the
   *  core's own alerts. */
  kind?: string | null;
  /** Translatable text (I11): the console renders `${i18nKey}.title` and `.message` with i18nParams, the
   *  English title and message being the fallback. */
  i18nKey?: string | null;
  /** Scalar parameters of the text; never personal data. */
  i18nParams?: Record<string, string | number | boolean> | null;
}

/** Payload of the `NOTIFICATION_RESOLVED` socket event. */
export interface LiveAlertsResolvedEvent {
  /** Ids of the live alerts that were just resolved (hidden). */
  ids: number[];
}

// ─── REPORTS ─────────────────────────────────────────────────────────────────

export type ReportType = 'fleet' | 'software' | 'custom';
export type ReportFormat = 'json' | 'csv' | 'pdf' | 'excel' | 'html';
export type ReportStatus = 'generating' | 'ready' | 'error';
export type ReportSection = 'hardware' | 'software' | 'network' | 'inventory_detail';

export interface Report {
  id: number;
  tenantId: number;
  name: string;
  description: string | null;
  type: ReportType;
  format: ReportFormat;
  scopeType: 'tenant' | 'group' | 'device';
  scopeId: number | null;
  sections: ReportSection[];
  filters: Record<string, any>;
  scheduleCron: string | null;
  timezone: string;
  isEnabled: boolean;
  lastGeneratedAt: string | null;
  createdBy: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface ReportOutput {
  id: number;
  reportId: number;
  tenantId: number;
  status: ReportStatus;
  filePath: string | null;
  fileSizeBytes: number | null;
  rowCount: number | null;
  errorMessage: string | null;
  expiresAt: string | null;
  generatedAt: string | null;
  createdAt: string;
}

// ─── API RESPONSE ────────────────────────────────────────────────────────────

export interface ApiResponse<T = unknown> {
  data?: T;
  error?: string;
  message?: string;
}

// ─── USER REQUEST TYPES ──────────────────────────────────────────────────────

export interface CreateUserRequest {
  username: string;
  password: string;
  displayName?: string | null;
  email?: string | null;
  role?: 'admin' | 'user';
  preferredLanguage?: string;
}

export interface UpdateUserRequest {
  username?: string;
  displayName?: string | null;
  email?: string | null;
  role?: 'admin' | 'user';
  preferredLanguage?: string;
  isActive?: boolean;
}

// ─── TEAM REQUEST TYPES ──────────────────────────────────────────────────────

export interface CreateTeamRequest {
  name: string;
  description?: string | null;
  canCreate?: boolean;
}

export interface UpdateTeamRequest {
  name?: string;
  description?: string | null;
  canCreate?: boolean;
}

export interface SetTeamMembersRequest {
  memberIds: number[];
}

export interface SetTeamPermissionsRequest {
  permissions: Array<{
    scope: 'group' | 'device' | 'ungrouped';
    scopeId: number;
    level: 'ro' | 'rw';
    capabilities?: DeviceCapability[];
  }>;
}

// ─── NOTIFICATION CHANNEL REQUEST TYPES ─────────────────────────────────────

export interface CreateNotificationChannelRequest {
  name: string;
  type: NotificationChannelType;
  config: Record<string, any>;
}

export interface UpdateNotificationChannelRequest {
  name?: string;
  /** Secret fields: absent or '' keeps the stored value, a string replaces
   *  it, null clears it (an optional field only). */
  config?: Record<string, any>;
}

// ─── APP CONFIG ──────────────────────────────────────────────────────────────

export interface AppConfigData {
  allow_2fa: string;
  force_2fa: string;
  otp_smtp_server_id: string | null;
  inventory_retention_days: string;
  app_name: string;
  default_language: string;
  // Obligate SSO gateway
  obligate_url?: string | null;
  obligate_enabled?: string;
  // Device-bound 2FA platform settings ('true' / 'false', default 'true') —
  // docs/mobile/device-bound-2fa.md §9 [D15].
  device_keys_enabled?: string;
  device_keys_login?: string;
  device_keys_require_attestation?: string;
  device_keys_strict_session?: string;
}

export interface ObligateConfig {
  url: string | null;
  apiKeySet: boolean;
  enabled: boolean;
  /** A distinct secret Obligate must present on its calls to this server
   *  (else the API key is expected). Never returned in clear. */
  inboundSecretSet?: boolean;
  inboundSecretFromEnv?: boolean;
}

// ─── VAULT ───────────────────────────────────────────────────────────────────
// State and operations of the server's vault of secrets (docs: coffre-secrets
// §11.1), shown to the platform administrators. Identifiers, fingerprints and
// counts only: never a key nor a secret.

export interface VaultStatus {
  provider: 'file' | 'transit';
  /** First 16 hex characters of SHA-256 of the KEK: a fingerprint, not a secret. */
  kekId: string;
  /** apple-edge's, once it exposes it (coffre-secrets §8.4-1). */
  edgeKekId: string | null;
  instanceDek: { id: string; version: number; createdAt: string } | null;
  tenantKeys: { active: number; retired: number; destroyed: number; scheduled: number; tenantsWithoutKey: number };
  backfill: { complete: boolean; remaining: Record<string, number>; lastRunAt: string | null };
  escrow: { confirmedAt: string | null; lastTestAt: string | null; coversCurrentKek: boolean };
  lastKekRotationAt: string | null;
  operations: { running: number; failed: number };
}

export type VaultOperationKind =
  | 'backfill' | 'dek_rotation' | 'kek_rotation' | 'verify'
  | 'escrow_confirmation' | 'escrow_test' | 'escrow_retirement' | 'kek_loss_recovery';

export type VaultOperationState =
  | 'pending_approval' | 'authorized' | 'running' | 'done' | 'failed' | 'expired' | 'cancelled';

export interface VaultOperation {
  id: string;
  kind: VaultOperationKind;
  state: VaultOperationState;
  tenantId: number | null;
  approvalId: number | null;
  requestedBy: number | null;
  reason: string | null;
  params: Record<string, unknown>;
  progress: Record<string, unknown>;
  authorizedUntil: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  createdAt: string;
}


// ─── AUTH & USERS ─────────────────────────────────────────────────────────────

export interface LoginRequest {
  username: string;
  password: string;
  totpCode?: string;
  emailOtp?: string;
}

export type UserRole = 'admin' | 'user';

export type PermissionLevel = 'ro' | 'rw';

export interface UserPermissions {
  canCreate: boolean;
  teams: number[];
  permissions: Record<string, PermissionLevel>;
  /** Tenant capabilities of the user's role in the active tenant (the
   *  permission set's, capabilities.ts). Used by the client to gate the
   *  pages that are not device-scoped (e.g. Supervision: 'supervision:read').
   *  Always empty for platform admins — they bypass. */
  tenantCapabilities: TenantCapability[];
}

export interface UserTenantAssignment {
  tenantId: number;
  tenantName: string;
  tenantSlug: string;
  isMember: boolean;
  /** 'admin' (tenant administrator) or a permission set slug ('user' by
   *  default). 'member' is the pre-091 name of 'user' and is never returned. */
  role: string;
}

// ─── MAINTENANCE ──────────────────────────────────────────────────────────────

export type MaintenanceRecurrenceType = 'daily' | 'weekly';

export type MaintenanceScopeType = 'global' | 'group' | 'device';

export interface CreateMaintenanceWindowRequest {
  name: string;
  scopeType: MaintenanceScopeType;
  scopeId?: number | null;
  scheduleType: string;
  startAt?: string | null;
  endAt?: string | null;
  /** New canonical field name for one-time start (replaces startAt) */
  startsAt?: string;
  /** New canonical field name for one-time end (replaces endAt) */
  endsAt?: string;
  startTime?: string | null;
  endTime?: string | null;
  recurrenceType?: string | null;
  /** New canonical field name for recurring rule (replaces recurrenceType) */
  recurrenceRule?: MaintenanceRecurrenceRule | null;
  daysOfWeek?: number[] | null;
  timezone?: string;
  notifyChannelIds?: number[];
  /** New canonical field name for notification channels (replaces notifyChannelIds) */
  notificationChannels?: number[];
  active?: boolean;
}

export interface UpdateMaintenanceWindowRequest extends Partial<CreateMaintenanceWindowRequest> {}

// ─── NOTIFICATION PLUGINS ─────────────────────────────────────────────────────

export type NotificationConfigFieldType = 'text' | 'password' | 'number' | 'boolean' | 'select' | 'textarea' | 'url' | 'smtp_server_select' | 'email_list';

export interface NotificationConfigField {
  key: string;
  label: string;
  type: NotificationConfigFieldType;
  /** A secret field (token, webhook URL…): sealed by the server, never
   *  returned (write-only). Every 'password' field is secret. */
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
  helpText?: string;
  options?: { value: string; label: string }[];
  default?: string | number | boolean;
}

export interface NotificationPluginMeta {
  type: string;
  name: string;
  description: string;
  configFields: NotificationConfigField[];
}

// ─── AUTOMATION NOTIFICATION BINDINGS ────────────────────────────────────────
//
// The channels an automation notifies, and how (the client's
// NotificationChannelBindings picker). The RMM automations that sent them
// are removed.

/**
 * - 'per_device': dispatch immediately for each device the automation acts
 *   on. One message per device, regardless of success/failure.
 * - 'summary':    wait until every fanned-out device has finished and
 *   send a single recap (OK: N / Failed: M).
 *
 * Legacy `'on_error'` is accepted for read so older bindings still
 * dispatch; it's treated as `per_device` but filters to failure-only
 * messages. New rows should write 'per_device' or 'summary'.
 */
export type AutomationNotificationMode = 'per_device' | 'summary' | 'on_error';

export interface AutomationNotificationBinding {
  channelId: number;
  mode: AutomationNotificationMode;
}
