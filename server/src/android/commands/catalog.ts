// Catalogue of the Android commands (section 11.2, AN14): AMAPI type, Obligarth action, modes and ownerships allowed,
// minimum API level, duration, guard. Pure: no import, erasable TypeScript only (unit tests under node --test). The
// prerequisites are checked by the bus as for Apple (§8.3 of the integration): record enrolled, channel amapi,
// ownership and mode allowed, API level known and sufficient (api_level_unknown, api_level_too_low rather than the
// API_LEVEL failure of Google). The ownership personal forbids WIPE outside the removal from management, the lost
// mode, RESET_PASSWORD and REBOOT (EX-A7). newPassword is never part of a command body built here: it is sealed apart
// (secret_enc) and joined to the body by the submission only, in memory.

export type AndroidCommandType =
  | 'LOCK' | 'RESET_PASSWORD' | 'REBOOT' | 'START_LOST_MODE' | 'STOP_LOST_MODE' | 'WIPE' | 'RELINQUISH_OWNERSHIP' | 'CLEAR_APP_DATA';

export type AndroidDeviceMode = 'fully_managed' | 'dedicated' | 'work_profile_corporate' | 'work_profile_personal';
export type AndroidDeviceOwnership = 'corporate' | 'corporate_personal' | 'personal';

export interface AndroidCommandSpec {
  type: AndroidCommandType;
  /** The Obligarth action (restriction key) that requests it. */
  action: string;
  /** Seconds: the AMAPI default (10 minutes) is never relied on. */
  durationSeconds: number;
  modes: readonly AndroidDeviceMode[];
  /** Ownerships refused (EX-A7). WIPE of a personal device is the removal from management only (profileWipe). */
  refuseOwnership: readonly AndroidDeviceOwnership[];
  /** Minimum API level per mode (absent: none). */
  minApi?: Partial<Record<AndroidDeviceMode, number>>;
  /** Only through the guard engine (origin 'guard'): 409 guardedActionRequired from any other path. */
  guarded: boolean;
  /** Refused for a tenant frozen, held in the instance (AN15: the gateway refuses them too). */
  destructive: boolean;
  /** Cancellable while the device did not acknowledge (cancelOperation). */
  cancellable: boolean;
}

const ALL_MODES: readonly AndroidDeviceMode[] = ['fully_managed', 'dedicated', 'work_profile_corporate', 'work_profile_personal'];
const HOUR = 3600;
const DAY = 86_400;

export const ANDROID_COMMANDS: Readonly<Record<AndroidCommandType, AndroidCommandSpec>> = Object.freeze({
  LOCK: { type: 'LOCK', action: 'mdm.device_lock', durationSeconds: DAY, modes: ALL_MODES, refuseOwnership: [], guarded: true, destructive: true, cancellable: true },
  RESET_PASSWORD: {
    type: 'RESET_PASSWORD', action: 'mdm.reset_password', durationSeconds: DAY, modes: ['fully_managed', 'dedicated', 'work_profile_corporate'],
    refuseOwnership: ['personal'], guarded: true, destructive: true, cancellable: true,
  },
  REBOOT: {
    type: 'REBOOT', action: 'mdm.reboot', durationSeconds: HOUR, modes: ['fully_managed', 'dedicated'], refuseOwnership: ['personal'],
    minApi: { fully_managed: 24, dedicated: 24 }, guarded: false, destructive: false, cancellable: true,
  },
  START_LOST_MODE: {
    type: 'START_LOST_MODE', action: 'mdm.lost_mode_enable', durationSeconds: DAY, modes: ['fully_managed', 'work_profile_corporate'],
    refuseOwnership: ['personal'], minApi: { fully_managed: 30, work_profile_corporate: 33 }, guarded: true, destructive: true, cancellable: true,
  },
  STOP_LOST_MODE: {
    type: 'STOP_LOST_MODE', action: 'mdm.lost_mode_disable', durationSeconds: DAY, modes: ['fully_managed', 'work_profile_corporate'],
    refuseOwnership: ['personal'], minApi: { fully_managed: 30, work_profile_corporate: 33 }, guarded: false, destructive: false, cancellable: true,
  },
  WIPE: { type: 'WIPE', action: 'mdm.erase_device', durationSeconds: 7 * DAY, modes: ALL_MODES, refuseOwnership: [], guarded: true, destructive: true, cancellable: true },
  RELINQUISH_OWNERSHIP: {
    type: 'RELINQUISH_OWNERSHIP', action: 'mdm.relinquish_ownership', durationSeconds: 7 * DAY, modes: ['work_profile_corporate'],
    refuseOwnership: ['personal', 'corporate'], minApi: { work_profile_corporate: 26 }, guarded: true, destructive: true, cancellable: true,
  },
  CLEAR_APP_DATA: {
    type: 'CLEAR_APP_DATA', action: 'mdm.clear_app_data', durationSeconds: DAY, modes: ALL_MODES, refuseOwnership: [],
    minApi: { fully_managed: 28, dedicated: 28, work_profile_corporate: 28, work_profile_personal: 28 }, guarded: false, destructive: false, cancellable: true,
  },
});

export const ANDROID_COMMAND_TYPES = Object.keys(ANDROID_COMMANDS) as AndroidCommandType[];
export const isAndroidCommandType = (t: unknown): t is AndroidCommandType => typeof t === 'string' && Object.hasOwn(ANDROID_COMMANDS, t);

/** Command types the gateway's freeze lock refuses (AN15): the same list, kept in one place for the bus and the tests. */
export const DESTRUCTIVE_COMMAND_TYPES: readonly AndroidCommandType[] = ANDROID_COMMAND_TYPES.filter((t) => ANDROID_COMMANDS[t].destructive);

// ── Prerequisites ─────────────────────────────────────────────────────────────

export type AndroidCommandRefusal =
  | 'not_found' | 'not_amapi' | 'not_enrolled' | 'ownership' | 'mode' | 'api_level_unknown' | 'api_level_too_low';

export interface AndroidCommandTarget {
  managementChannel: string;
  enrollmentState: string;
  /** android_devices.released_at is set: no longer under management. */
  released: boolean;
  ownership: string;
  mode: string;
  apiLevel: number | null;
}

/**
 * The prerequisites of a command for one device; null: the device takes it. `profileWipe`: WIPE of a personal device
 * as the removal from management (the profile only), the only WIPE a personal device takes.
 */
export function refusalOf(type: AndroidCommandType, d: AndroidCommandTarget | undefined, o: { profileWipe?: boolean } = {}): AndroidCommandRefusal | null {
  const spec = ANDROID_COMMANDS[type];
  if (!d) return 'not_found';
  if (d.managementChannel !== 'amapi') return 'not_amapi';
  if (d.enrollmentState !== 'enrolled' || d.released) return 'not_enrolled';
  if ((spec.refuseOwnership as readonly string[]).includes(d.ownership)) return 'ownership';
  if (type === 'WIPE' && d.ownership === 'personal' && !o.profileWipe) return 'ownership';
  if (!(spec.modes as readonly string[]).includes(d.mode)) return 'mode';
  const min = spec.minApi?.[d.mode as AndroidDeviceMode];
  if (min !== undefined) {
    if (d.apiLevel === null || !Number.isInteger(d.apiLevel)) return 'api_level_unknown';
    if (d.apiLevel < min) return 'api_level_too_low';
  }
  return null;
}

// ── Parameters and body ───────────────────────────────────────────────────────

export class AndroidCommandParamError extends Error {
  readonly code: string;
  constructor(code: string, message = code) {
    super(message);
    this.name = 'AndroidCommandParamError';
    this.code = code;
  }
}

const RESET_FLAGS = new Set(['REQUIRE_ENTRY', 'DO_NOT_ASK_CREDENTIALS_ON_BOOT', 'LOCK_NOW']);
const WIPE_FLAGS = new Set(['PRESERVE_RESET_PROTECTION_DATA', 'WIPE_EXTERNAL_STORAGE', 'WIPE_ESIMS']);
const PACKAGE_RE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$/;
const PHONE_RE = /^\+?[0-9 ().-]{3,30}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown, max: number, code: string): string | undefined => {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') throw new AndroidCommandParamError(code);
  const t = v.trim().replace(/[\u0000-\u001f\u007f]/g, ' ');
  if (!t || t.length > max) throw new AndroidCommandParamError(code);
  return t;
};
const only = (p: Record<string, unknown>, keys: string[]): void => {
  for (const k of Object.keys(p)) if (!keys.includes(k)) throw new AndroidCommandParamError('unknown_param', `unknown parameter ${k.slice(0, 40)}`);
};

/** Parameters of a command once validated (never a secret). */
export type AndroidCommandParams = Record<string, unknown>;

/**
 * Validates the operator's parameters of a type (strict: an unknown key is refused) and returns their normalised
 * form. newPassword is never accepted here (it is sealed apart). START_LOST_MODE needs a message, a phone number, an
 * e-mail or an address: the organisation alone never suffices (AMAPI-R11).
 */
export function validateParams(type: AndroidCommandType, raw: unknown): AndroidCommandParams {
  const p = raw === undefined || raw === null ? {} : raw;
  if (!isObj(p)) throw new AndroidCommandParamError('invalid_params');
  if ('newPassword' in p) throw new AndroidCommandParamError('secret_in_params', 'newPassword is sealed apart, never a parameter');
  switch (type) {
    case 'LOCK': case 'REBOOT': case 'STOP_LOST_MODE': case 'RELINQUISH_OWNERSHIP':
      only(p, []);
      return {};
    case 'RESET_PASSWORD': {
      only(p, ['flags']);
      if (p.flags === undefined) return {};
      if (!Array.isArray(p.flags) || p.flags.length > 3 || p.flags.some((f) => typeof f !== 'string' || !RESET_FLAGS.has(f))) {
        throw new AndroidCommandParamError('invalid_flags');
      }
      return { flags: [...new Set(p.flags as string[])] };
    }
    case 'START_LOST_MODE': {
      only(p, ['message', 'phoneNumber', 'email', 'streetAddress', 'organization']);
      const out = {
        message: text(p.message, 200, 'invalid_message'),
        phoneNumber: text(p.phoneNumber, 30, 'invalid_phone'),
        email: text(p.email, 254, 'invalid_email'),
        streetAddress: text(p.streetAddress, 300, 'invalid_address'),
        organization: text(p.organization, 100, 'invalid_organization'),
      };
      if (out.phoneNumber !== undefined && !PHONE_RE.test(out.phoneNumber)) throw new AndroidCommandParamError('invalid_phone');
      if (out.email !== undefined && !EMAIL_RE.test(out.email)) throw new AndroidCommandParamError('invalid_email');
      if (out.message === undefined && out.phoneNumber === undefined && out.email === undefined && out.streetAddress === undefined) {
        throw new AndroidCommandParamError('lost_mode_contact_required', 'a message, a phone number, an e-mail or an address is required');
      }
      return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined));
    }
    case 'WIPE': {
      only(p, ['wipeDataFlags', 'wipeReason']);
      const out: AndroidCommandParams = {};
      if (p.wipeDataFlags !== undefined) {
        if (!Array.isArray(p.wipeDataFlags) || p.wipeDataFlags.length > 3 || p.wipeDataFlags.some((f) => typeof f !== 'string' || !WIPE_FLAGS.has(f))) {
          throw new AndroidCommandParamError('invalid_wipe_flags');
        }
        out.wipeDataFlags = [...new Set(p.wipeDataFlags as string[])];
      }
      const reason = text(p.wipeReason, 200, 'invalid_wipe_reason');
      if (reason !== undefined) out.wipeReason = reason;
      return out;
    }
    case 'CLEAR_APP_DATA': {
      only(p, ['packageNames']);
      if (!Array.isArray(p.packageNames) || p.packageNames.length < 1 || p.packageNames.length > 50
        || p.packageNames.some((n) => typeof n !== 'string' || n.length > 255 || !PACKAGE_RE.test(n))) {
        throw new AndroidCommandParamError('invalid_packages');
      }
      return { packageNames: [...new Set(p.packageNames as string[])] };
    }
    default:
      throw new AndroidCommandParamError('unknown_type');
  }
}

/**
 * A new password for RESET_PASSWORD (sealed apart): 4 to 64 characters, printable; a numeric code of 6 digits at
 * least (Android 14). An empty password is refused: RESET_PASSWORD without newPassword clears the password, which
 * is expressed by leaving the field out.
 */
export function checkNewPassword(v: unknown): string {
  if (typeof v !== 'string' || v.length < 4 || v.length > 64 || /[\u0000-\u001f\u007f]/.test(v)) throw new AndroidCommandParamError('invalid_password');
  if (/^[0-9]+$/.test(v) && v.length < 6) throw new AndroidCommandParamError('password_too_short', 'a numeric code needs 6 digits at least');
  return v;
}

const msg = (s: string): { defaultMessage: string } => ({ defaultMessage: s });

/**
 * The AMAPI Command body of a type, WITHOUT any secret (stored as amapi_command). `durationSeconds`: what remains of
 * the command's life at the submission (the default of the type at the creation).
 */
export function commandBody(type: AndroidCommandType, params: AndroidCommandParams, durationSeconds = ANDROID_COMMANDS[type].durationSeconds): Record<string, unknown> {
  const duration = `${Math.max(60, Math.floor(durationSeconds))}s`;
  const body: Record<string, unknown> = { type, duration };
  if (type === 'RESET_PASSWORD' && Array.isArray(params.flags) && params.flags.length) body.resetPasswordFlags = params.flags;
  if (type === 'START_LOST_MODE') {
    body.startLostModeParams = {
      ...(params.message ? { lostMessage: msg(String(params.message)) } : {}),
      ...(params.phoneNumber ? { lostPhoneNumber: msg(String(params.phoneNumber)) } : {}),
      ...(params.email ? { lostEmailAddress: String(params.email) } : {}),
      ...(params.streetAddress ? { lostStreetAddress: msg(String(params.streetAddress)) } : {}),
      ...(params.organization ? { lostOrganization: msg(String(params.organization)) } : {}),
    };
  }
  if (type === 'STOP_LOST_MODE') body.stopLostModeParams = {};
  if (type === 'WIPE' && (params.wipeDataFlags || params.wipeReason)) {
    body.wipeParams = {
      ...(Array.isArray(params.wipeDataFlags) && params.wipeDataFlags.length ? { wipeDataFlags: params.wipeDataFlags } : {}),
      ...(params.wipeReason ? { wipeReason: msg(String(params.wipeReason)) } : {}),
    };
  }
  if (type === 'CLEAR_APP_DATA') body.clearAppsDataParams = { packageNames: params.packageNames };
  return body;
}

/** A command body with its duration replaced (submission: what remains of the command's life). */
export function withDuration(body: Record<string, unknown>, remainingSeconds: number): Record<string, unknown> {
  return { ...body, duration: `${Math.max(60, Math.floor(remainingSeconds))}s` };
}

// ── States (section 11.3) ─────────────────────────────────────────────────────

export type AndroidTargetState = 'pending' | 'sent' | 'acknowledged' | 'error' | 'cancelled' | 'expired' | 'rejected';
export const FINAL_STATES: ReadonlySet<AndroidTargetState> = new Set(['acknowledged', 'error', 'cancelled', 'expired', 'rejected']);

const COMMAND_ERROR_CODES = new Set(['UNKNOWN', 'API_LEVEL', 'MANAGEMENT_MODE', 'INVALID_VALUE', 'UNSUPPORTED']);
/** google.rpc.Code CANCELLED and DEADLINE_EXCEEDED. */
const RPC_CANCELLED = 1;
const RPC_DEADLINE_EXCEEDED = 4;

export interface OperationFacts {
  done?: boolean;
  error?: { code?: number } | null;
  metadata?: { type?: string; errorCode?: string } | null;
}

/**
 * The final state an operation gives to a target 'sent' (section 11.3), or null while it runs: done without error →
 * acknowledged; cancelled after our cancelOperation → cancelled; deadline exceeded → expired [NV: exact form of an
 * expired operation, to observe at AN-J]; any other error → error (the CommandErrorCode of the metadata, else UNKNOWN).
 */
export function finalStateOf(op: OperationFacts | null | undefined, o: { cancelRequested: boolean }):
  { state: 'acknowledged' | 'error' | 'cancelled' | 'expired'; errorCode: string | null } | null {
  if (!op || op.done !== true) return null;
  const code = op.error && typeof op.error.code === 'number' ? op.error.code : null;
  const errorCode = typeof op.metadata?.errorCode === 'string' && COMMAND_ERROR_CODES.has(op.metadata.errorCode) ? op.metadata.errorCode : null;
  if (!op.error && !errorCode) return { state: 'acknowledged', errorCode: null };
  if (code === RPC_CANCELLED && o.cancelRequested) return { state: 'cancelled', errorCode: null };
  if (code === RPC_DEADLINE_EXCEEDED) return { state: 'expired', errorCode: null };
  return { state: 'error', errorCode: errorCode ?? 'UNKNOWN' };
}

/**
 * When to poll an operation 'sent' next (section 11.3: every 5 minutes for the operations sent more than 2 minutes
 * ago, then at 15 min, 1 h, 6 h, then every 6 hours until the expiry): offsets from the delivery.
 */
const POLL_OFFSETS_MIN = [2, 7, 12, 15, 60, 360];
export function nextPollAt(deliveredAt: Date, pollCount: number): Date {
  const minutes = pollCount < POLL_OFFSETS_MIN.length ? POLL_OFFSETS_MIN[pollCount] : 360 + (pollCount - POLL_OFFSETS_MIN.length + 1) * 360;
  return new Date(deliveredAt.getTime() + minutes * 60_000);
}

/**
 * AN50 recovery: among the operations of the device (listed without a filter), those that may be the command whose
 * submission was interrupted: same type, created since the mark minus 5 seconds. Only type, device and time are
 * compared (no fingerprint of a body that carries a secret, §22.9).
 */
export function adoptableOperations<T extends { name: string; metadata?: { type?: string; createTime?: string } | null }>(
  ops: readonly T[], type: AndroidCommandType, markedAt: Date): T[] {
  const from = markedAt.getTime() - 5_000;
  return ops.filter((op) => {
    if (op.metadata?.type !== type) return false;
    const t = Date.parse(String(op.metadata?.createTime ?? ''));
    return Number.isFinite(t) && t >= from;
  });
}
