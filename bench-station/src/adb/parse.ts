/**
 * Obligarth bench station — pure readers of what adb and the device print (lot BANC §5.1, §6).
 *
 * No process, no file: every function takes the text a command printed and returns facts. The harness
 * (testing/parse.verify.ts) feeds them outputs of Android 7, 9 and 15. Nothing here keeps a name or an address of an
 * account: only types, counts and the package that carries each type.
 */

export const AGENT_PACKAGE = 'tools.obli.obligarth.agent';
export const AGENT_ADMIN = `${AGENT_PACKAGE}/.AgentAdminReceiver`;
export const AGENT_ADMIN_FULL = `${AGENT_PACKAGE}/${AGENT_PACKAGE}.AgentAdminReceiver`;
export const BENCH_AUTHORITY = `${AGENT_PACKAGE}.bench`;

// ── adb devices -l ──────────────────────────────────────────────────────────

export type AdbDeviceState = 'device' | 'unauthorized' | 'offline' | 'no permissions' | 'authorizing' | 'connecting'
  | 'recovery' | 'sideload' | 'bootloader' | 'unknown';

export interface AdbDevice {
  serial: string;
  state: AdbDeviceState;
  usb: string | null;
  product: string | null;
  model: string | null;
  device: string | null;
  transportId: number | null;
}

const KNOWN_STATES: AdbDeviceState[] = ['device', 'unauthorized', 'offline', 'authorizing', 'connecting', 'recovery', 'sideload', 'bootloader'];

/** `adb devices -l`: `<serial> <state> usb:… product:… model:… device:… transport_id:N`. */
export function parseDevicesL(out: string): AdbDevice[] {
  const list: AdbDevice[] = [];
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('List of devices') || line.startsWith('*')) continue;
    const m = /^(\S+)\s+(no permissions|\S+)(.*)$/.exec(line);
    if (!m) continue;
    const kv: Record<string, string> = {};
    for (const part of m[3].trim().split(/\s+/)) {
      const i = part.indexOf(':');
      if (i > 0) kv[part.slice(0, i)] = part.slice(i + 1);
    }
    const state = (KNOWN_STATES as string[]).includes(m[2]) ? (m[2] as AdbDeviceState) : m[2] === 'no permissions' ? 'no permissions' : 'unknown';
    const tid = kv.transport_id ? Number.parseInt(kv.transport_id, 10) : NaN;
    list.push({
      serial: m[1], state, usb: kv.usb ?? null, product: kv.product ?? null, model: kv.model ?? null, device: kv.device ?? null,
      transportId: Number.isFinite(tid) ? tid : null,
    });
  }
  return list;
}

// ── getprop ─────────────────────────────────────────────────────────────────

/** `getprop` without argument: `[key]: [value]` per line. */
export function parseGetprop(out: string): Record<string, string> {
  const props: Record<string, string> = {};
  for (const line of out.split(/\r?\n/)) {
    const m = /^\[([^\]]+)\]:\s*\[(.*)\]\s*$/.exec(line.trim());
    if (m) props[m[1]] = m[2];
  }
  return props;
}

export interface DeviceIdentity {
  model: string;
  manufacturer: string;
  sdkInt: number;
  osRelease: string | null;
  securityPatch: string | null;
  oneUi: string | null;
  /** ro.serialno (or ro.boot.serialno): the serial ADB shows, Build.SERIAL. */
  adbSerial: string | null;
  /** ril.serialnumber (Samsung, the serial of the label); null when empty or unreadable. */
  hwSerial: string | null;
}

const SERIAL_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const clean = (v: string | undefined, max: number): string | null => {
  const s = (v ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s ? s.slice(0, max) : null;
};
const serialOf = (v: string | undefined): string | null => {
  const s = clean(v, 64);
  if (!s || s.toLowerCase() === 'unknown' || /^0+$/.test(s)) return null;
  return SERIAL_RE.test(s) ? s : null;
};

export function identityOf(props: Record<string, string>): DeviceIdentity {
  const sdk = Number.parseInt(props['ro.build.version.sdk'] ?? '', 10);
  return {
    model: clean(props['ro.product.model'], 64) ?? 'unknown',
    manufacturer: clean(props['ro.product.manufacturer'], 64) ?? 'unknown',
    sdkInt: Number.isFinite(sdk) ? sdk : 0,
    osRelease: clean(props['ro.build.version.release'], 32),
    securityPatch: clean(props['ro.build.version.security_patch'], 32),
    oneUi: clean(props['ro.build.version.oneui'], 32),
    adbSerial: serialOf(props['ro.serialno']) ?? serialOf(props['ro.boot.serialno']),
    hwSerial: serialOf(props['ril.serialnumber']),
  };
}

// ── pm, dumpsys ─────────────────────────────────────────────────────────────

/** `pm list users`: the ids of the `UserInfo{<id>:…}` lines. */
export function parseUsers(out: string): number[] {
  const ids: number[] = [];
  for (const m of out.matchAll(/UserInfo\{(\d+):/g)) ids.push(Number(m[1]));
  return [...new Set(ids)];
}

export interface AccountsReading {
  count: number;
  /** The types (com.google, com.whatsapp…), never a name. */
  types: string[];
  /** The package that carries each type, read from the authenticators. */
  owners: Record<string, string>;
  /** Every account counted was read with a valid type (none left out of `types`): only then may the station hide the
   *  accounts for a while (an account it cannot see the type of keeps the owner blocked). */
  complete: boolean;
}

const ACCOUNT_TYPE_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** `dumpsys account`: `Accounts: N` (one per user), `Account {name=…, type=…}`, `AuthenticatorDescription {type=…},
 *  ComponentInfo{<pkg>/…}`. The names are never kept. */
export function parseAccounts(out: string): AccountsReading {
  let count = 0;
  let sawHeader = false;
  for (const m of out.matchAll(/^\s*Accounts:\s*(\d+)/gm)) { count += Number(m[1]); sawHeader = true; }
  const types = new Set<string>();
  let listed = 0;
  let rejected = 0;
  for (const m of out.matchAll(/Account \{name=[^}]*?,\s*type=([^}\s,]+)\}/g)) {
    listed++;
    if (ACCOUNT_TYPE_RE.test(m[1])) types.add(m[1]); else rejected++;
  }
  if (!sawHeader) count = listed;
  const owners: Record<string, string> = {};
  for (const m of out.matchAll(/AuthenticatorDescription \{type=([^}]+)\},\s*ComponentInfo\{([A-Za-z0-9_.]+)\//g)) {
    if (ACCOUNT_TYPE_RE.test(m[1]) && types.has(m[1])) owners[m[1]] = m[2];
  }
  return { count, types: [...types].sort(), owners, complete: rejected === 0 && listed === count };
}

// ── accounts hidden for a while (owner decision of 28/11/2026) ──────────────

/**
 * The packages the station never disables, whatever account they carry: the agent, the framework, Settings, the
 * system UI, the shell, the phone, the launchers, the package installers, the content providers, the keyboards. An
 * account carried by one of them keeps the owner blocked, as before.
 */
export function isProtectedPackage(pkg: string): boolean {
  if (pkg === AGENT_PACKAGE || pkg === 'android') return true;
  if (/^com\.android\.(settings|systemui|shell|phone|providers\..+|server\..+)$/.test(pkg)) return true;
  return /launcher|packageinstaller|\.home$|inputmethod|keyboard|honeyboard|systemui|settings/i.test(pkg);
}

/** `pm disable-user --user 0 <pkg>` / `pm enable <pkg>`: `Package <pkg> new state: disabled-user|enabled`. Read only
 *  from that sentence, for that package (a refusal prints an exception: SecurityException, protected package…). */
export function parsePmNewState(out: string, pkg: string): 'disabled' | 'enabled' | null {
  for (const line of out.split(/\r?\n/)) {
    const m = /^Package (\S+) new state:\s*(disabled-user|disabled|enabled|default)\s*$/.exec(line.trim());
    if (m && m[1] === pkg) return m[2] === 'enabled' || m[2] === 'default' ? 'enabled' : 'disabled';
  }
  return null;
}

const PACKAGE_NAME_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;

/** The marker the station leaves on the device while packages are disabled (`cat` of it): package names, blank
 *  separated; any other word is ignored, and so is a package the station never disables. */
export function parseHiddenMarker(out: string): string[] {
  if (/No such file|not found|Permission denied/i.test(out)) return [];
  return [...new Set(out.split(/\s+/).filter((w) => w.length <= 255 && PACKAGE_NAME_RE.test(w) && !isProtectedPackage(w)))].sort();
}

export interface PolicyReading {
  /** The package of the device owner, or null. */
  deviceOwner: string | null;
  /** How many profile owners (work profile, secure folder…). */
  profileOwners: number;
  /** Active administrators, as `package/class` (class possibly relative). */
  activeAdmins: string[];
}

const COMPONENT_RE = /([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\/([A-Za-z0-9_.$]+)/;

/** `cmd device_policy list-owners` (Android 12+): `User  0: admin=<pkg>/<cls>,DeviceOwner` or `no owners`. */
export function parseListOwners(out: string): Pick<PolicyReading, 'deviceOwner' | 'profileOwners'> & { understood: boolean } {
  let deviceOwner: string | null = null;
  let profileOwners = 0;
  let understood = /no owners/i.test(out) || /\d+ owners?:/i.test(out);
  for (const m of out.matchAll(/admin=([^,\s]+)((?:,[A-Za-z]+)*)/g)) {
    understood = true;
    const comp = COMPONENT_RE.exec(m[1]);
    const flags = m[2];
    if (/DeviceOwner/.test(flags) && comp) deviceOwner = comp[1];
    else if (/ProfileOwner/.test(flags)) profileOwners++;
  }
  return { deviceOwner, profileOwners, understood };
}

/** `dumpsys device_policy`: the « Device Owner: » and « Profile Owner (User N): » sections, and the components listed
 *  under « Enabled Device Admins (User N…): ». Formats of Android 7 to 15. */
export function parseDumpsysDevicePolicy(out: string): PolicyReading {
  const lines = out.split(/\r?\n/);
  let deviceOwner: string | null = null;
  let profileOwners = 0;
  const admins: string[] = [];
  let section: 'owner' | 'profile' | 'admins' | null = null;
  let sectionIndent = -1;
  for (const raw of lines) {
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (!line) continue;
    if (/^Device Owner:?/i.test(line)) { section = 'owner'; sectionIndent = indent; continue; }
    if (/^Profile Owner/i.test(line)) { section = 'profile'; sectionIndent = indent; profileOwners++; continue; }
    if (/^Enabled Device Admins/i.test(line)) { section = 'admins'; sectionIndent = indent; continue; }
    if (section !== null && indent <= sectionIndent) section = null;
    if (section === 'owner' && deviceOwner === null) {
      const pkg = /^package=([A-Za-z0-9_.]+)/.exec(line) ?? /admin=ComponentInfo\{([A-Za-z0-9_.]+)\//.exec(line);
      if (pkg) deviceOwner = pkg[1];
    }
    if (section === 'admins') {
      const m = /^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\/[A-Za-z0-9_.$]+):?$/.exec(line);
      if (m) admins.push(m[1]);
    }
  }
  return { deviceOwner, profileOwners, activeAdmins: [...new Set(admins)] };
}

/** Is `component` (`pkg/.Cls` or `pkg/pkg.Cls`) the agent's administrator? */
export function isAgentAdmin(component: string): boolean {
  return component === AGENT_ADMIN || component === AGENT_ADMIN_FULL;
}

// ── dpm ─────────────────────────────────────────────────────────────────────

export type DpmOwnerVerdict =
  | { ok: true }
  | { ok: false; code: 'accounts' | 'extra_users' | 'foreign_owner' | 'owner_failed'; message: string };

/** The output of `dpm set-device-owner`. Success only on the exact sentence (the caller reads the owners back too). */
export function parseSetDeviceOwner(out: string): DpmOwnerVerdict {
  if (/Success: Device owner set/i.test(out)) return { ok: true };
  const message = out.replace(/\s+/g, ' ').trim().slice(0, 300);
  if (/already some accounts|accounts on the device/i.test(out)) return { ok: false, code: 'accounts', message };
  if (/several users|already (?:several|multiple) users|users on the device/i.test(out)) return { ok: false, code: 'extra_users', message };
  if (/device owner is already set|already has a device owner|already provisioned/i.test(out)) return { ok: false, code: 'foreign_owner', message };
  return { ok: false, code: 'owner_failed', message };
}

/** `dpm set-active-admin`: `Success: Active admin set to component …`. */
export function parseSetActiveAdmin(out: string): boolean {
  return /Success: Active admin set/i.test(out);
}

// ── install, package ────────────────────────────────────────────────────────

export type InstallVerdict =
  | { ok: true }
  | { ok: false; code: 'agent_foreign_signer' | 'agent_downgrade' | 'install_failed' | 'install_restricted' | 'play_protect'; reason: string };

/** `adb install -r`: `Success`, or `Failure [INSTALL_FAILED_…]` / `adb: failed to install …: Failure [INSTALL_…: …]`. */
export function parseInstall(out: string): InstallVerdict {
  const reasonM = /(INSTALL_[A-Z_]+)/.exec(out);
  if (/^\s*Success\s*$/m.test(out) && !reasonM) return { ok: true };
  const reason = reasonM ? reasonM[1] : 'unknown';
  switch (reason) {
    case 'INSTALL_FAILED_UPDATE_INCOMPATIBLE':
    case 'INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES':
      return { ok: false, code: 'agent_foreign_signer', reason };
    case 'INSTALL_FAILED_VERSION_DOWNGRADE':
      return { ok: false, code: 'agent_downgrade', reason };
    case 'INSTALL_FAILED_VERIFICATION_FAILURE':
    case 'INSTALL_FAILED_VERIFICATION_TIMEOUT':
      return { ok: false, code: 'play_protect', reason };
    case 'INSTALL_FAILED_USER_RESTRICTED':
      return { ok: false, code: 'install_restricted', reason };
    default:
      return { ok: false, code: 'install_failed', reason };
  }
}

/** `pm list packages --show-versioncode <pkg>` (Android 9+): `package:<pkg> versionCode:N`; exact package only. */
export function parsePmVersion(out: string, pkg = AGENT_PACKAGE): number | null {
  for (const line of out.split(/\r?\n/)) {
    const m = /^package:(\S+)\s+versionCode:(\d+)/.exec(line.trim());
    if (m && m[1] === pkg) return Number(m[2]);
  }
  return null;
}

/** `dumpsys package <pkg>` (any version), filtered here: the first `versionCode=N` of the « Packages: » section. */
export function parseDumpsysVersion(out: string): number | null {
  if (/Unable to find package/i.test(out)) return null;
  const at = out.indexOf('Packages:');
  const m = /versionCode=(\d+)/.exec(at >= 0 ? out.slice(at) : out);
  return m ? Number(m[1]) : null;
}

/** `pm path <pkg>`: the `base.apk` line (`package:/data/app/…/base.apk`), else the first one. */
export function parsePmPath(out: string): string | null {
  const paths = out.split(/\r?\n/).map((l) => /^package:(\/\S+\.apk)\s*$/.exec(l.trim())?.[1]).filter((p): p is string => !!p);
  return paths.find((p) => p.endsWith('/base.apk')) ?? paths[0] ?? null;
}

// ── the bench channel of the agent ─────────────────────────────────────────

export interface BenchAnswer {
  ok: boolean | null;
  code: string | null;
  phase: string | null;
  role: string | null;
  last: string | null;
  knox: string | null;
  versionCode: number | null;
  [k: string]: unknown;
}

/** `content call …`: `Result: Bundle[{ok=true, code=configured, phase=CONFIGURED, …}]`. null when the bundle was not
 *  printed (`Bundle[mParcelledData…]`, an exception, no provider): the caller falls back to the logcat line. */
export function parseContentCall(out: string): BenchAnswer | null {
  const m = /Result:\s*Bundle\[\{(.*)\}\]/s.exec(out);
  if (!m) return null;
  const kv: Record<string, string> = {};
  for (const part of m[1].split(/,\s*/)) {
    const i = part.indexOf('=');
    if (i > 0) kv[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  const bool = (v: string | undefined): boolean | null => (v === 'true' ? true : v === 'false' ? false : null);
  const str = (v: string | undefined): string | null => (v && v !== 'null' && /^[A-Za-z0-9_]{1,48}$/.test(v) ? v : null);
  const vc = kv.versionCode ? Number.parseInt(kv.versionCode, 10) : NaN;
  const extra: Record<string, unknown> = {};
  for (const k of ['ownerCleared', 'adminActive']) if (k in kv) extra[k] = bool(kv[k]);
  if ('windowSeconds' in kv) extra.windowSeconds = Number.parseInt(kv.windowSeconds, 10);
  return {
    ok: bool(kv.ok), code: str(kv.code), phase: str(kv.phase), role: str(kv.role), last: str(kv.last), knox: str(kv.knox),
    versionCode: Number.isFinite(vc) ? vc : null, ...extra,
  };
}

/** The last `phase=<…> role=<…> last=<code>` line of `logcat -d -s ObligarthBench:I` (agent 1.4.0, §7.4). */
export function parseBenchLogLine(out: string): { phase: string; role: string; last: string } | null {
  let found: { phase: string; role: string; last: string } | null = null;
  for (const m of out.matchAll(/phase=([A-Z_]+) role=([A-Z_]+) last=([a-z0-9_]+)/g)) found = { phase: m[1], role: m[2], last: m[3] };
  return found;
}

/** `settings get …`: the value, `null` printed as such is null. */
export function parseSetting(out: string): string | null {
  const v = out.trim().split(/\r?\n/).pop()?.trim() ?? '';
  return v === '' || v === 'null' ? null : v;
}

/** An adb error that says the device is no longer there (unplugged, offline, its authorization withdrawn). */
export function deviceGoneMessage(stderr: string): boolean {
  return /device '[^']*' not found|no devices\/emulators found|device offline|device unauthorized|device still authorizing|error: closed/i.test(stderr);
}
