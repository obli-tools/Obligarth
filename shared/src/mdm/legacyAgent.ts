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

/** MobiControl lines of the device administrator (lot ADM, seen on a real device on 27/10): the Lockdown of
 *  MobiControl keeps the ACTIVATE button of the Android screen from activating the administrator. `_adminmode on`
 *  suspends the Lockdown (the phone is out of it until `_adminmode off`; the launcher of the client and the profile
 *  stay intact), `_adminmode off` restores it and is sent on its own, once the console shows the administrator
 *  active. */
export const LEGACY_AGENT_MOBICONTROL_ADMIN_MODE_ON = '_adminmode on';
export const LEGACY_AGENT_MOBICONTROL_ADMIN_MODE_OFF = '_adminmode off';

/** The enrollment script of a token (§4.9): the Lockdown suspended, then the configuration on both lines. An app
 *  never launched is in the stopped state and may miss the broadcast, whereas the activity started by the last line
 *  always runs and imports it too (SetupActivity.importFromIntent). A second import of the same configuration is
 *  idempotent, and refused once enrolled. base64url ([A-Za-z0-9_-]) needs no escaping in an intent URI nor between
 *  the double quotes. */
export function legacyAgentEnrollmentScript(encodedConfig: string): string {
  const pkg = LEGACY_AGENT_PACKAGE;
  const extra = `S.config=${encodedConfig}`;
  return [
    LEGACY_AGENT_MOBICONTROL_ADMIN_MODE_ON,
    `sendintent -b "intent:#Intent;action=${pkg}.action.CONFIGURE;package=${pkg};${extra};end"`,
    `sendintent -a "intent:#Intent;action=${pkg}.action.ACTIVATE_ADMIN;package=${pkg};${extra};end"`,
  ].join('\n');
}

/** The activation script of a device already enrolled whose administrator is off: the Lockdown suspended, then the
 *  agent's screen (its launcher activity), whose ACTIVATE button now works. No token, no configuration. */
export const LEGACY_AGENT_ACTIVATE_SCRIPT = [
  LEGACY_AGENT_MOBICONTROL_ADMIN_MODE_ON,
  `sendintent -a "intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;component=${LEGACY_AGENT_PACKAGE}/.SetupActivity;end"`,
].join('\n');

/** The return script: the Lockdown restored, sent on its own once the administrator is active. */
export const LEGACY_AGENT_ADMIN_OFF_SCRIPT = LEGACY_AGENT_MOBICONTROL_ADMIN_MODE_OFF;

/** Prefix of an enrollment token: OLE1.<publicId 22>.<secret 43> (§4.4). */
export const LEGACY_AGENT_TOKEN_RE = /^OLE1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

/** Bounds of a token (§3.2, §7). */
export const LEGACY_AGENT_TOKEN_BOUNDS = { maxUsesMax: 2000, maxUsesDefault: 50, daysMax: 30, daysDefault: 7 } as const;

/** Poll interval bounds and default, seconds (PB10). */
export const LEGACY_AGENT_POLL_BOUNDS = { min: 60, max: 3600, default: 300 } as const;

/** Automatic update of the fleet to the latest version of the agent (lot AGENT-RU): devices per hour, instance-wide. */
export const LEGACY_AGENT_AUTO_UPDATE_BOUNDS = { min: 1, max: 5000, default: 500 } as const;

/** Where a version of the agent comes from: uploaded by a platform administrator, or embedded in the server image. */
export const LEGACY_AGENT_RELEASE_ORIGINS = ['upload', 'bundled'] as const;
export type LegacyAgentReleaseOrigin = typeof LEGACY_AGENT_RELEASE_ORIGINS[number];

/** Why the version embedded in the server image was not registered (lot AGENT-RU). */
export const LEGACY_AGENT_BUNDLE_REFUSALS = ['manifestInvalid', 'apkMissing', 'apkTooLarge', 'signerNotAdmitted', 'sha256Mismatch', 'notAnApk',
  'signerMismatch', 'versionConflict'] as const;
export type LegacyAgentBundleRefusal = typeof LEGACY_AGENT_BUNDLE_REFUSALS[number];

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
  apps: Array<{ packageName: string; label: string | null; versionName: string | null; versionCode: string | null; managed: boolean; system?: boolean }>;
}

/** One entry of GET /api/legacy-agent/devices/:id/actions: the menu of a bridge agent's device. */
export interface LegacyAgentDeviceAction {
  type: 'device.lock' | 'device.wipe' | 'device.message' | 'device.reboot' | 'inventory.refresh';
  /** The guarded action (legacy_agent.device_lock, legacy_agent.erase_device) or the restriction key of the type. */
  actionKey: string;
  guarded: boolean;
  available: boolean;
  /** capabilityMissing; revoked (the agent's key withdrawn); notEnrolled; adminInactive (the device administrator is
   *  off: lock and erase fail on the device); knoxRequired (reboot needs a licensed Knox); frozen. */
  unavailable: 'capabilityMissing' | 'revoked' | 'notEnrolled' | 'adminInactive' | 'knoxRequired' | 'frozen' | null;
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

/** The creation answer: the token's value, the encoded configuration and the MobiControl script, shown once; with
 *  the two scripts that hold no secret (lot ADM): the activation of a device already enrolled, and the return
 *  (`_adminmode off`) sent on its own once the administrator is active. */
export interface LegacyAgentTokenCreated extends LegacyAgentTokenView {
  token: string;
  config: string;
  configJson: string;
  script: string;
  activateScript: string;
  adminOffScript: string;
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
  origin: LegacyAgentReleaseOrigin;
  /** Version of the server image that first brought a bundled release; null for an upload. */
  bundledIn: string | null;
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
  /** Automatic update of the enrolled agents to the latest version not withdrawn (lot AGENT-RU). */
  autoUpdate: boolean;
  autoUpdatePerHour: number;
  /** The version embedded in this server's image, as its start found it; null before the start task ran. */
  bundle: LegacyAgentBundleStatus | null;
}

/**
 * The version of the agent embedded in the server image (/app/server/agent-release), as the start task of this
 * server found it: absent; registered now; present already; withdrawn (never brought back); refused (reason);
 * storeError (the copy to the store of the APKs failed: full or read-only volume, rights); error (the database
 * failed). A failure is tried again at the next start.
 */
export interface LegacyAgentBundleStatus {
  state: 'absent' | 'registered' | 'present' | 'withdrawn' | 'refused' | 'storeError' | 'error';
  reason: LegacyAgentBundleRefusal | null;
  versionCode: number | null;
  versionName: string | null;
  imageVersion: string;
  checkedAt: string;
}
