// =============================================================================
// Android bridge agent, channel 'legacy_agent' (docs: agent-pont-android §4,
// §5, §7): the vocabulary of the frozen contract between the agent and the
// server, and the views of the console. No import: the client and the unit
// tests load it as is.
// =============================================================================

/** Command types of v0 (§5.1). agent.retire is v1 (§15.4). */
export const LEGACY_AGENT_COMMAND_TYPES = [
  'inventory.refresh', 'device.message', 'device.lock', 'device.wipe', 'device.reboot',
  'app.install', 'app.uninstall', 'agent.update',
] as const;
export type LegacyAgentCommandType = typeof LEGACY_AGENT_COMMAND_TYPES[number];

/** The types the guard engine alone enqueues (§5.2, I24). */
export const LEGACY_AGENT_GUARDED_TYPES = ['device.wipe', 'device.lock'] as const;

/** The types a console request enqueues directly (each behind its restriction, §5.4). */
export const LEGACY_AGENT_CONSOLE_TYPES = [
  'inventory.refresh', 'device.message', 'device.reboot', 'app.install', 'app.uninstall', 'agent.update',
] as const;
export type LegacyAgentConsoleType = typeof LEGACY_AGENT_CONSOLE_TYPES[number];

/** States of a row of legacy_agent_commands (§3.2): a state never goes back (rank). */
export const LEGACY_AGENT_COMMAND_STATES = ['pending', 'sent', 'acknowledged', 'error', 'rejected', 'expired', 'cancelled'] as const;
export type LegacyAgentCommandState = typeof LEGACY_AGENT_COMMAND_STATES[number];

/** Result codes of the agent (§5.3). */
export const LEGACY_AGENT_RESULT_CODES = [
  'done', 'wipe_started', 'reboot_started', 'lock_done', 'installed', 'uninstalled', 'update_installed', 'message_shown',
  'admin_inactive', 'knox_required', 'knox_error', 'download_failed', 'hash_mismatch', 'signer_mismatch', 'package_mismatch',
  'version_not_higher', 'install_failed', 'user_declined', 'user_timeout', 'forbidden_package', 'unsupported',
  'expired_on_device', 'bad_params', 'internal',
] as const;
export type LegacyAgentResultCode = typeof LEGACY_AGENT_RESULT_CODES[number];

/** Events an interrogation carries (§4.5). */
export const LEGACY_AGENT_EVENT_TYPES = [
  'boot', 'admin_enabled', 'admin_disabled', 'admin_disable_requested', 'knox_license', 'config_imported', 'update_installed',
  'clock_corrected',
] as const;
export type LegacyAgentEventType = typeof LEGACY_AGENT_EVENT_TYPES[number];

/** Error codes of the agent surface (§4.8). */
export const LEGACY_AGENT_ERROR_CODES = [
  'badRequest', 'badKey', 'badSignature', 'unknownAgent', 'clockSkew', 'tokenInvalid', 'agentRevoked', 'notFound', 'seqReplay',
  'tooLarge', 'unsupportedMediaType', 'agentTooOld', 'rateLimited', 'unavailable',
] as const;
export type LegacyAgentErrorCode = typeof LEGACY_AGENT_ERROR_CODES[number];

export const LEGACY_AGENT_KNOX_STATES = ['absent', 'present', 'licensed', 'license_error'] as const;
export type LegacyAgentKnoxState = typeof LEGACY_AGENT_KNOX_STATES[number];

export const LEGACY_AGENT_KEY_STORAGES = ['hardware', 'software', 'unknown'] as const;
export type LegacyAgentKeyStorage = typeof LEGACY_AGENT_KEY_STORAGES[number];

/** Package name of the agent (§4.4): an app.install / app.uninstall of it is refused. */
export const LEGACY_AGENT_PACKAGE = 'tools.obli.obligarth.agent';

/** Prefix of an enrollment token: OLE1.<publicId 22>.<secret 43> (§4.4). */
export const LEGACY_AGENT_TOKEN_RE = /^OLE1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

/** Bounds of a token (§3.2, §7). */
export const LEGACY_AGENT_TOKEN_BOUNDS = { maxUsesMax: 2000, maxUsesDefault: 50, daysMax: 30, daysDefault: 7 } as const;

/** Poll interval bounds and default, seconds (PB10). */
export const LEGACY_AGENT_POLL_BOUNDS = { min: 60, max: 3600, default: 300 } as const;

// ── Views of the console ─────────────────────────────────────────────────────

export interface LegacyAgentDeviceView {
  deviceId: number;
  deviceUuid: string;
  agentId: string;
  name: string | null;
  model: string | null;
  modelName: string | null;
  osVersion: string | null;
  apiLevel: number | null;
  securityPatch: string | null;
  serialNumber: string | null;
  agentVersionCode: number;
  agentVersionName: string;
  adminActive: boolean;
  knoxState: LegacyAgentKnoxState;
  keyStorage: LegacyAgentKeyStorage;
  identityConflict: boolean;
  enrollmentState: string;
  lastPollAt: string | null;
  lastInventoryAt: string | null;
  batteryLevel: number | null;
  unknownSources: boolean | null;
  revokedAt: string | null;
  revokeReason: string | null;
  enrolledAt: string;
  groupId: number | null;
}

export interface LegacyAgentDeviceDetail extends LegacyAgentDeviceView {
  androidId: string | null;
  claimedSerial: string | null;
  samsungSerial: string | null;
  imeis: string[];
  hints: Record<string, unknown> | null;
  knoxInfo: Record<string, unknown> | null;
  pollSeconds: number | null;
  clockOffsetSeconds: number | null;
  status: Array<{ item: string; value: unknown; observedAt: string }>;
  apps: Array<{ packageName: string; label: string | null; versionName: string | null; versionCode: string | null; managed: boolean }>;
}

export interface LegacyAgentCommandView {
  id: string;
  batchId: string;
  deviceId: number;
  type: LegacyAgentCommandType;
  params: Record<string, unknown>;
  origin: string;
  state: LegacyAgentCommandState;
  holdReason: string | null;
  deliveryCount: number;
  createdAt: string;
  notBefore: string | null;
  expiresAt: string;
  deliveredAt: string | null;
  completedAt: string | null;
  resultCode: string | null;
  resultDetail: Record<string, unknown> | null;
  requestedBy: number | null;
  reason: string | null;
  guardActionUuid: string | null;
}

export interface LegacyAgentTokenView {
  id: string;
  publicId: string;
  label: string;
  groupId: number | null;
  maxUses: number;
  uses: number;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  state: 'active' | 'expired' | 'revoked' | 'used_up';
}

/** The creation answer: the token's value, the encoded configuration and the MobiControl script, shown once. */
export interface LegacyAgentTokenCreated extends LegacyAgentTokenView {
  token: string;
  config: string;
  configJson: string;
  script: string;
}

export interface LegacyAgentPackageView {
  id: string;
  packageName: string;
  versionCode: string;
  versionName: string | null;
  sha256: string;
  sizeBytes: number;
  signerSha256: string | null;
  label: string | null;
  createdAt: string;
}

export interface LegacyAgentReleaseView {
  id: string;
  versionCode: number;
  versionName: string;
  sha256: string;
  sizeBytes: number;
  signerSha256: string;
  notes: string | null;
  createdAt: string;
  withdrawnAt: string | null;
}

export interface LegacyAgentServerKeyView {
  keyId: string;
  spki: string;
  spkiSha256: string;
  createdAt: string | null;
  exportedAt: string | null;
  missing: boolean;
}

export interface LegacyAgentInstanceSettings {
  pollSeconds: number;
  minVersionCode: number;
  inventorySeconds: number;
  signers: string[];
  publicBase: string | null;
}
