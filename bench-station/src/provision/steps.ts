import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BENCH_ERROR_CODES, BENCH_OWNER_MIN_VERSION_CODE, BENCH_STEP_IDS, benchRolePlan,
  type BenchStepId,
} from '../../../shared/src/mdm/bench';
import {
  AGENT_ADMIN, AGENT_PACKAGE, BENCH_AUTHORITY, identityOf, isAgentAdmin, parseAccounts, parseBenchLogLine, parseContentCall,
  parseDumpsysDevicePolicy, parseDumpsysVersion, parseGetprop, parseInstall, parseListOwners, parsePmPath, parsePmVersion,
  parseSetActiveAdmin, parseSetDeviceOwner, parseSetting, parseUsers,
  type AccountsReading, type BenchAnswer, type DeviceIdentity, type PolicyReading,
} from '../adb/parse';
import { type AdbDevice } from '../adb/parse';
import { AdbListError, DeviceGoneError, type AdbResult, type AdbRunner } from '../adb/runner';
import { BenchApiError, type BenchApi, type BenchTarget, type PlanAnswer, type ProvisioningState, type StepEntry } from '../benchApi';
import { redact } from '../redact';
import { ensureServedApk, signerOfApk, type ServedAgent } from './apk';

/**
 * Obligarth bench station — the provisioning sequence of ONE device (lot BANC §6), driven by an AdbRunner and a
 * BenchApi, both injected (the harness runs it against a fake adb and a fake platform).
 *
 *   detect → identify → agent_check → preflight → [plan] → install → role → prepare → configure → wait_enroll →
 *   verify → finalize
 *
 * Every step is idempotent and checks its precondition again before acting; a step whose effect has gone (an agent
 * uninstalled meanwhile, the owner lost) is played again. The card's state lives in memory AND can be derived from the
 * device and the server: a run that starts again (same serial, or the station relaunched) identifies the device, asks
 * the server for its open provisioning (409 `open_provisioning` gives its id) and resumes at the first step not done.
 *
 * ┌─ THE RULES THAT MATTER ──────────────────────────────────────────────────┐
 * │ - the station's approval is read live (`requireApproved`, GET /me) before │
 * │   every step that ACTS on the device;                                     │
 * │ - the configuration (the enrollment token) is fetched just before        │
 * │   `configure`, written on the standard input of `adb shell -T`, then      │
 * │   dropped: never an argument on the PC, never in a log, the history or a  │
 * │   step sent to the server;                                                │
 * │ - the agent's signer is the PINNED one, on the served APK and on the     │
 * │   package installed on the device (pulled base.apk), before any           │
 * │   `set-device-owner`; another signer stops, nothing is ever uninstalled;  │
 * │ - after `dpm set-device-owner`, the REAL state is read back, whatever the │
 * │   version: a failure may have removed the administrator (§6.5);          │
 * │ - the steps sent to the server carry codes, counts and account TYPES     │
 * │   only (BenchStepDetail): the raw outputs stay in the card.               │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export type StepStatus = 'pending' | 'running' | 'ok' | 'warn' | 'failed' | 'skipped';
export type CardTone = 'idle' | 'wait' | 'act' | 'hold' | 'ok' | 'warn' | 'bad';
export type Choice = 'recheck' | 'continue_admin' | 'confirm_admin' | 'retry' | 'reissue';

export interface Prompt {
  /** An i18n code: `bench.prompt.<code>` (the page translates). */
  code: string;
  params?: Record<string, string | number>;
  choices: Choice[];
  /** Beep and flash: the technician must act. */
  attention: boolean;
}

export interface RunOptions {
  target?: BenchTarget;
  deviceName?: string | null;
  /** Lot BANC-T §9: the site of the card (null: none). */
  site?: { id: string; code: string; name: string } | null;
  /** Lot BANC-T Q3: the exception D3 decided on the bench. */
  allowLegacyOwner?: boolean;
  choice?: Choice;
}

export interface ProvisionTiming {
  enrollMs: number;
  pollMs: number;
  verifyMs: number;
  stateEvery: number;
}

export const DEFAULT_TIMING: ProvisionTiming = { enrollMs: 180_000, pollMs: 3_000, verifyMs: 180_000, stateEvery: 2 };

export interface ProvisionDeps {
  runner: AdbRunner;
  api: BenchApi;
  /** The agent's pinned signer (pins.ts); null refuses every APK. */
  pin: string | null;
  apkCacheDir: string;
  /** GET /me, live: throws GateError when the station is not approved. */
  requireApproved: () => Promise<void>;
  /** Another adb holds the USB device (§5.5)? Consulted on `offline`. */
  adbConflict?: () => Promise<boolean>;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  timing?: Partial<ProvisionTiming>;
  onChange?: () => void;
  /** A finished provisioning (history). */
  onFinished?: (run: ProvisionRun) => void;
}

/** The station is not approved (or no longer): nothing more is done on any device. */
export class GateError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'GateError'; }
}

class Hold extends Error {
  constructor(readonly prompt: Prompt) { super(prompt.code); }
}

class Fail extends Error {
  constructor(readonly code: string, readonly params: Record<string, string | number> = {}) { super(code); }
}

const PKG = AGENT_PACKAGE;
const RUNTIME_PERMISSIONS = [
  'android.permission.READ_PHONE_STATE', 'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.ACCESS_COARSE_LOCATION',
];
const ACCOUNT_TYPE_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const SERVER_ERROR_CODES = new Set<string>(BENCH_ERROR_CODES);
const CONFIG_RE = /^[A-Za-z0-9_-]{16,16384}={0,2}$/;
/** The settling of the administrator's state after dpm (§6.5): a reading every 300 ms, 5 s at most, 1.5 s at least. */
const SETTLE_STEP_MS = 300;
const SETTLE_READS = 16;
const SETTLE_MIN_READS = 5;

/** A local code turned into one the server accepts for a result (BENCH_ERROR_CODES), `internal` otherwise. */
export function serverErrorCode(code: string): string {
  if (SERVER_ERROR_CODES.has(code)) return code;
  switch (code) {
    case 'play_protect': case 'apk_unavailable': return 'install_failed';
    case 'accounts': case 'extra_users': case 'foreign_owner': case 'profile_owner': return 'owner_blocked';
    case 'not_verified': return 'owner_failed';
    default: return 'internal';
  }
}

export interface Preflight {
  users: number[];
  accounts: AccountsReading;
  policy: PolicyReading;
  agentAdminActive: boolean;
  setupComplete: boolean | null;
}

export interface AgentInstalled {
  versionCode: number;
  signerSha256: string | null;
  adminActive: boolean;
  phase: string | null;
}

/** One device on the bench: its state, its steps, what it waits for. */
export class ProvisionRun {
  readonly steps: Record<BenchStepId, { status: StepStatus; code: string | null }>;
  tone: CardTone = 'idle';
  busy = false;
  prompt: Prompt | null = null;
  /** A non-blocking sentence for the technician (`bench.hint.<code>`). */
  hint: string | null = null;
  outcome: 'open' | 'completed' | 'failed' | 'abandoned' = 'open';
  errorCode: string | null = null;
  errorParams: Record<string, string | number> = {};
  target: BenchTarget | null = null;
  deviceName: string | null = null;
  /** Lot BANC-T §9: the site chosen on the card (null: none, the target's group). */
  site: { id: string; code: string; name: string } | null = null;
  /** Lot BANC-T Q3: the exception D3 decided on the bench (in an open session; the server audits each use). */
  allowLegacyOwner = false;
  identity: DeviceIdentity | null = null;
  served: ServedAgent | null = null;
  agent: AgentInstalled | null = null;
  preflight: Preflight | null = null;
  plan: PlanAnswer | null = null;
  /** The role this run aims at now (the plan's, or the administrator after the technician's choice). */
  roleChosen: 'device_owner' | 'device_admin' | null = null;
  /** The owner was set by THIS run (« Rendre l'appareil » may then give the device back, whatever the card's state). */
  ownerSetHere = false;
  /** THIS run launched `dpm set-device-owner` (kept before the reading back: a device unplugged in between and found
   *  owner at the replay was set here). */
  private ownerAttempted = false;
  serverState: ProvisioningState | null = null;
  /** ADB switched off at the end, confirmed only when the agent reports adbEnabled=false (§6.7). */
  adbCut: 'none' | 'pending_agent' = 'none';
  /** Raw outputs, redacted, kept in memory for the « export » (§5.7). Never sent. */
  readonly raw: string[] = [];
  private queue: StepEntry[] = [];
  /** The journal being sent: one sending at a time (the timer of the page and a run may ask together). */
  private flushing: Promise<void> | null = null;
  private confirmations = 0;
  private readonly t: ProvisionTiming;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;

  constructor(readonly serial: string, private readonly d: ProvisionDeps) {
    this.steps = Object.fromEntries(BENCH_STEP_IDS.map((s) => [s, { status: 'pending' as StepStatus, code: null }])) as ProvisionRun['steps'];
    this.t = { ...DEFAULT_TIMING, ...(d.timing ?? {}) };
    this.sleep = d.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = d.now ?? Date.now;
  }

  get provisioningId(): string | null { return this.plan?.provisioningId ?? null; }
  /** The steps waiting to reach the server (they are sent again when it answers). */
  get pendingSteps(): number { return this.queue.length; }

  // ── adb, through the card ──────────────────────────────────────────────

  private note(args: string[], r: AdbResult): void {
    const line = `$ adb ${args.join(' ')}\n${r.stdout}${r.stderr ? `\n[stderr] ${r.stderr}` : ''}\n[exit ${r.code}${r.timedOut ? ', timeout' : ''}]`;
    this.raw.push(redact(line).slice(0, 8_000));
    if (this.raw.length > 400) this.raw.splice(0, this.raw.length - 400);
  }

  private async sh(argv: string[], timeoutMs?: number): Promise<AdbResult> {
    const r = await this.d.runner.shell(this.serial, argv, { timeoutMs });
    this.note(['shell', ...argv], r);
    return r;
  }

  /** A script on the standard input of `adb shell -T` (it may carry a secret: its echo is redacted, never logged as
   *  such). */
  private async script(lines: string[], label: string, timeoutMs = 60_000): Promise<AdbResult> {
    const r = await this.d.runner.shell(this.serial, [], { stdin: lines.join('\n'), timeoutMs });
    this.note(['shell', '-T', `<${label}>`], r);
    return r;
  }

  private async benchCall(method: 'state' | 'poll' | 'prepare_owner' | 'release'): Promise<BenchAnswer | null> {
    const r = await this.sh(['content', 'call', '--uri', `content://${BENCH_AUTHORITY}`, '--method', method]);
    const parsed = parseContentCall(r.stdout);
    if (parsed) return parsed;
    // The bundle was not printed (older `content`): the diagnostic line of the agent (§7.4).
    const log = await this.sh(['logcat', '-d', '-s', 'ObligarthBench:I']);
    const line = parseBenchLogLine(log.stdout);
    return line ? { ok: null, code: null, phase: line.phase, role: line.role, last: line.last, knox: null, versionCode: null } : null;
  }

  // ── the journal ────────────────────────────────────────────────────────

  private mark(step: BenchStepId, status: StepStatus, code: string | null = null, detail?: StepEntry['detail']): void {
    this.steps[step] = { status, code };
    if (status !== 'pending' && step !== 'detect') {
      const entry: StepEntry = { step, status: status as StepEntry['status'], at: this.d.api.nowIso(), ...(code ? { code } : {}), ...(detail ? { detail } : {}) };
      const last = this.queue[this.queue.length - 1];
      // « Revérifier », Play Protect again…: one entry with its attempt, not a pile (§6.8).
      if (last && last.step === entry.step && last.status === entry.status && last.code === entry.code) {
        last.at = entry.at;
        last.detail = { ...(entry.detail ?? {}), attempt: Math.min(1000, (last.detail?.attempt ?? 1) + 1) };
      } else {
        this.queue.push(entry);
      }
    }
    this.d.onChange?.();
  }

  /** Sends the journal in order; stops at the first failure (sent again later), never blocks the sequence. One sending
   *  at a time: a second call gets the one under way (an entry is never sent twice nor dropped unsent). */
  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    const p = this.flushQueue().finally(() => { if (this.flushing === p) this.flushing = null; });
    this.flushing = p;
    return p;
  }

  private async flushQueue(): Promise<void> {
    const id = this.provisioningId;
    if (!id) return;
    while (this.queue.length > 0) {
      try {
        await this.d.api.step(id, this.queue[0]);
        this.queue.shift();
      } catch (err) {
        // A refused entry (400) is dropped: it would block the queue forever.
        if (err instanceof BenchApiError && err.status === 400) { this.queue.shift(); continue; }
        return;
      }
    }
  }

  private done(step: BenchStepId): boolean {
    const s = this.steps[step].status;
    return s === 'ok' || s === 'warn' || s === 'skipped';
  }

  // ── the run ────────────────────────────────────────────────────────────

  /** Runs (or resumes) the sequence until it ends, holds for the technician, or fails. Never throws for a device or
   *  platform reason: the card says it. */
  async run(opts: RunOptions = {}): Promise<void> {
    if (this.busy) throw new Error('busy');
    if (this.outcome !== 'open') return;
    this.busy = true;
    this.tone = 'act';
    this.prompt = null;
    this.hint = null;
    if (!this.plan) {
      if (opts.target) this.target = opts.target;
      if (opts.deviceName !== undefined) this.deviceName = opts.deviceName ? opts.deviceName.trim().slice(0, 100) || null : null;
      if (opts.site !== undefined) this.site = opts.site;
      if (opts.allowLegacyOwner !== undefined) this.allowLegacyOwner = opts.allowLegacyOwner;
    }
    this.d.onChange?.();
    try {
      await this.sequence(opts.choice ?? null);
    } catch (err) {
      await this.settle(err);
    } finally {
      for (const s of BENCH_STEP_IDS) if (this.steps[s].status === 'running') this.steps[s] = { status: 'pending', code: null };
      this.busy = false;
      await this.flush().catch(() => undefined);
      this.d.onChange?.();
    }
  }

  private async settle(err: unknown): Promise<void> {
    if (err instanceof Hold) {
      this.prompt = err.prompt;
      this.tone = 'hold';
      return;
    }
    if (err instanceof DeviceGoneError) {
      this.prompt = { code: 'device_gone', choices: ['retry'], attention: true };
      this.tone = 'hold';
      return;
    }
    if (err instanceof GateError) {
      this.prompt = { code: 'station_refused', params: { reason: err.code }, choices: ['retry'], attention: true };
      this.tone = 'hold';
      return;
    }
    if (err instanceof BenchApiError) {
      if (err.code === 'station_refused') {
        this.prompt = { code: 'station_refused', params: { reason: String(err.details?.stationCode ?? '') }, choices: ['retry'], attention: true };
        this.tone = 'hold';
        return;
      }
      // The token quota of the station (§3.5): its own sentence, never « server unreachable ».
      if (err.code === 'rate_limited' || err.status === 429) {
        this.prompt = { code: 'rate_limited', choices: ['retry'], attention: true };
        this.tone = 'hold';
        return;
      }
      if (err.code === 'server_unreachable' || err.code === 'redirected' || err.status >= 500) {
        this.prompt = { code: err.code === 'redirected' ? 'redirected' : 'server_unreachable', choices: ['retry'], attention: true };
        this.tone = 'hold';
        return;
      }
      await this.fail(err.code);
      return;
    }
    if (err instanceof Fail) {
      await this.fail(err.code, err.params);
      return;
    }
    await this.fail('internal', { detail: err instanceof Error ? redact(err.message).slice(0, 120) : 'error' });
  }

  private async fail(code: string, params: Record<string, string | number> = {}): Promise<void> {
    this.outcome = 'failed';
    this.errorCode = code;
    this.errorParams = params;
    this.tone = 'bad';
    this.prompt = null;
    const id = this.provisioningId;
    if (id && !['completed', 'failed', 'abandoned', 'expired'].includes(this.serverState?.state ?? '')) {
      await this.flush().catch(() => undefined);
      try { await this.d.api.result(id, { outcome: 'failed', errorCode: serverErrorCode(code) }); } catch { /* the server expires it */ }
    }
    this.d.onFinished?.(this);
  }

  /** « Abandonner » (an open provisioning closed as abandoned) or « Rendre l'appareil » (any state): `release` gives
   *  back a device whose owner this run set and whose agent is not enrolled (agent 1.4.0, the shell-only bench channel;
   *  the agent refuses it once enrolled). */
  async abandon(release = false): Promise<{ released: boolean | null }> {
    if (this.busy) throw new Error('busy');
    let released: boolean | null = null;
    if (release && this.ownerSetHere && (this.served?.versionCode ?? 0) >= BENCH_OWNER_MIN_VERSION_CODE) {
      try {
        await this.d.requireApproved();
        const a = await this.benchCall('release');
        released = a?.ok === true;
      } catch {
        released = false;
      }
    }
    const id = this.provisioningId;
    if (id && this.outcome === 'open') {
      await this.flush().catch(() => undefined);
      try { await this.d.api.result(id, { outcome: 'abandoned' }); } catch { /* expires by itself */ }
    }
    if (this.outcome === 'open') {
      this.outcome = 'abandoned';
      this.tone = 'warn';
      this.prompt = null;
      this.d.onFinished?.(this);
    }
    this.d.onChange?.();
    return { released };
  }

  private async sequence(choice: Choice | null): Promise<void> {
    if (!this.target) throw new Hold({ code: 'choose_target', choices: [], attention: false });
    await this.d.requireApproved();
    if (choice === 'continue_admin' || choice === 'confirm_admin') this.chooseAdmin(choice);
    // « Revérifier »: the technician changed their mind (an account removed…): the owner again, unless the fallback was
    // confirmed for good (twice on Android 15+).
    if (choice === 'recheck') this.resetFallback();
    if (choice === 'reissue') {
      this.steps.configure = { status: 'pending', code: null };
      this.steps.wait_enroll = { status: 'pending', code: null };
    }
    await this.detect();
    await this.identify();
    await this.agentCheck();
    if (!this.done('preflight') || choice === 'recheck' || !this.preflight) await this.readPreflight();
    if (!this.plan) await this.planProvisioning();
    await this.flush();
    this.ownerDecision();
    // The journal goes to the server after every step (what could not be sent is sent at the next one).
    await this.install();
    await this.flush();
    await this.role();
    await this.flush();
    if (!this.done('prepare')) { await this.prepare(); await this.flush(); }
    if (!this.done('configure')) { await this.configure(); await this.flush(); }
    if (this.plan!.kind === 'new' && !this.done('wait_enroll')) await this.waitEnroll();
    else if (this.plan!.kind === 'convert') this.mark('wait_enroll', 'skipped', 'convert');
    await this.flush();
    if (!this.done('verify')) await this.verify();
    await this.finalize();
  }

  // ── detect, identify ───────────────────────────────────────────────────

  /** `adb devices`, read twice before a conclusion: a failed reading (adb restarting, a time-out under load) is never
   *  « unplugged »: it holds on `adb_server`. */
  private async listDevices(): Promise<AdbDevice[]> {
    try {
      return await this.d.runner.devices();
    } catch (err) {
      if (!(err instanceof AdbListError)) throw err;
      await this.sleep(1_000);
      try {
        return await this.d.runner.devices();
      } catch (again) {
        if (!(again instanceof AdbListError)) throw again;
        this.mark('detect', 'failed', 'adb_server');
        throw new Hold({ code: 'adb_server', choices: ['retry'], attention: true });
      }
    }
  }

  private async detect(): Promise<void> {
    this.mark('detect', 'running');
    let dev = (await this.listDevices()).find((x) => x.serial === this.serial);
    // Absent once: read again a second later before concluding « unplugged ».
    if (!dev) {
      await this.sleep(1_000);
      dev = (await this.listDevices()).find((x) => x.serial === this.serial);
    }
    if (!dev) throw new DeviceGoneError(this.serial, 'absent');
    if (dev.state === 'unauthorized' || dev.state === 'authorizing') {
      this.mark('detect', 'failed', 'device_unauthorized');
      throw new Hold({ code: 'device_unauthorized', choices: ['retry'], attention: true });
    }
    if (dev.state !== 'device') {
      const conflict = this.d.adbConflict ? await this.d.adbConflict().catch(() => false) : false;
      const code = conflict ? 'adb_conflict' : 'device_offline';
      this.mark('detect', 'failed', code);
      throw new Hold({ code, choices: ['retry'], attention: true });
    }
    this.mark('detect', 'ok');
  }

  private async identify(): Promise<void> {
    this.mark('identify', 'running');
    const props = parseGetprop((await this.sh(['getprop'])).stdout);
    const id = identityOf(props);
    if (!id.adbSerial) id.adbSerial = /^[A-Za-z0-9._:-]{1,64}$/.test(this.serial) ? this.serial : null;
    if (!id.adbSerial) throw new Fail('internal', { detail: 'serial' });
    // The same serial as the card, or this is another device on the same plug.
    if (this.identity && this.identity.adbSerial !== id.adbSerial) throw new Fail('device_gone');
    this.identity = id;
    if (id.sdkInt < 24) {
      this.mark('identify', 'failed', 'unsupported_sdk', { sdk: id.sdkInt });
      throw new Fail('unsupported_sdk', { sdk: id.sdkInt });
    }
    const setup = parseSetting((await this.sh(['settings', 'get', 'secure', 'user_setup_complete'])).stdout);
    const warn = setup !== '1' ? 'setup_incomplete' : !/samsung/i.test(id.manufacturer) ? 'not_samsung' : null;
    this.mark('identify', warn ? 'warn' : 'ok', warn, { sdk: id.sdkInt });
    this.setupComplete = setup === null ? null : setup === '1';
  }

  private setupComplete: boolean | null = null;

  // ── agent_check ────────────────────────────────────────────────────────

  private async installedVersion(): Promise<number | null> {
    if ((this.identity?.sdkInt ?? 0) >= 28) {
      const v = parsePmVersion((await this.sh(['pm', 'list', 'packages', '--show-versioncode', PKG])).stdout);
      if (v !== null) return v;
      const listed = await this.sh(['pm', 'list', 'packages', PKG]);
      if (!new RegExp(`^package:${PKG.replace(/\./g, '\\.')}\\s*$`, 'm').test(listed.stdout)) return null;
    }
    return parseDumpsysVersion((await this.sh(['dumpsys', 'package', PKG])).stdout);
  }

  /** The signer of the package INSTALLED on the device: `pm path`, `adb pull` of base.apk, read here (§6.3). */
  private async installedSigner(): Promise<string | null> {
    const path = parsePmPath((await this.sh(['pm', 'path', PKG])).stdout);
    if (!path) return null;
    const dir = mkdtempSync(join(tmpdir(), 'obligarth-bench-apk-'));
    try {
      const local = join(dir, 'base.apk');
      const r = await this.d.runner.pull(this.serial, path, local);
      this.note(['pull', path, '<tmp>'], r);
      if (r.code !== 0) return null;
      return await signerOfApk(local);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  private async agentCheck(): Promise<void> {
    this.mark('agent_check', 'running');
    if (!this.served) {
      try {
        this.served = await this.d.api.agent();
      } catch (err) {
        if (err instanceof BenchApiError && err.code === 'apk_unavailable') {
          this.mark('agent_check', 'failed', 'apk_unavailable');
          throw new Fail('apk_unavailable');
        }
        throw err;
      }
    }
    const version = await this.installedVersion();
    if (version === null) {
      this.agent = null;
      this.mark('agent_check', 'ok', 'agent_absent');
      return;
    }
    if (version > this.served.versionCode) {
      this.mark('agent_check', 'failed', 'agent_downgrade', { versionCode: version });
      throw new Fail('agent_downgrade', { installed: version, served: this.served.versionCode });
    }
    const signer = await this.installedSigner();
    if (signer === null || signer !== this.d.pin) {
      this.mark('agent_check', 'failed', 'agent_foreign_signer', { versionCode: version });
      throw new Fail('agent_foreign_signer');
    }
    let phase: string | null = null;
    if (version >= BENCH_OWNER_MIN_VERSION_CODE) phase = (await this.benchCall('state'))?.phase ?? null;
    const policy = await this.readPolicy();
    this.agent = { versionCode: version, signerSha256: signer, adminActive: policy.agentAdminActive, phase };
    this.mark('agent_check', 'ok', 'agent_present', { versionCode: version });
  }

  // ── preflight ──────────────────────────────────────────────────────────

  private async readPolicy(): Promise<PolicyReading & { agentAdminActive: boolean }> {
    const reading = parseDumpsysDevicePolicy((await this.sh(['dumpsys', 'device_policy'])).stdout);
    if ((this.identity?.sdkInt ?? 0) >= 31) {
      const lo = parseListOwners((await this.sh(['cmd', 'device_policy', 'list-owners'])).stdout);
      if (lo.understood) { reading.deviceOwner = lo.deviceOwner; reading.profileOwners = lo.profileOwners; }
    }
    return { ...reading, agentAdminActive: reading.activeAdmins.some(isAgentAdmin) };
  }

  private async readPreflight(): Promise<void> {
    this.mark('preflight', 'running');
    const users = parseUsers((await this.sh(['pm', 'list', 'users'])).stdout);
    const accounts = parseAccounts((await this.sh(['dumpsys', 'account'])).stdout);
    const policy = await this.readPolicy();
    this.preflight = { users, accounts, policy, agentAdminActive: policy.agentAdminActive, setupComplete: this.setupComplete };
    if (this.agent) this.agent.adminActive = policy.agentAdminActive;
    const blockers = this.blockers();
    this.mark('preflight', blockers.length ? 'warn' : 'ok', blockers.length ? 'owner_blocked' : (policy.deviceOwner === PKG ? 'owner_already' : 'owner_possible'), {
      counts: { users: users.length || 1, accounts: accounts.count, profile_owners: policy.profileOwners },
      accountTypes: accounts.types.filter((t) => ACCOUNT_TYPE_RE.test(t)).slice(0, 16),
    });
  }

  /** What keeps the agent from becoming the owner now (AOSP preconditions, §6.3); none when it already is. */
  blockers(): string[] {
    const p = this.preflight;
    if (!p) return [];
    if (p.policy.deviceOwner === PKG) return [];
    const b: string[] = [];
    if (p.accounts.count > 0) b.push('accounts');
    if (p.users.length > 1) b.push('extra_users');
    if (p.policy.deviceOwner && p.policy.deviceOwner !== PKG) b.push('foreign_owner');
    if (p.policy.profileOwners > 0) b.push('profile_owner');
    return b;
  }

  // ── plan ───────────────────────────────────────────────────────────────

  private async planProvisioning(): Promise<void> {
    const id = this.identity!;
    const p = this.preflight!;
    const t = this.target!;
    try {
      this.plan = await this.d.api.plan({
        tenantId: t.tenantId, groupId: t.groupId,
        ...(this.site ? { siteId: this.site.id } : {}),
        ...(this.allowLegacyOwner ? { allowLegacyOwner: true } : {}),
        device: { adbSerial: id.adbSerial!, hwSerial: id.hwSerial, model: id.model, manufacturer: id.manufacturer, sdkInt: id.sdkInt, osRelease: id.osRelease, oneUi: id.oneUi },
        agentInstalled: this.agent ? { versionCode: this.agent.versionCode, signerSha256: this.agent.signerSha256, adminActive: this.agent.adminActive, phase: this.agent.phase } : null,
        deviceName: this.deviceName,
        preflight: {
          users: p.users.length || 1, accounts: p.accounts.count, accountTypes: p.accounts.types.filter((x) => /^[A-Za-z0-9._-]{1,64}$/.test(x)).slice(0, 32),
          deviceOwner: p.policy.deviceOwner, profileOwners: p.policy.profileOwners, agentAdminActive: p.agentAdminActive, setupComplete: p.setupComplete,
        },
      });
    } catch (err) {
      if (err instanceof BenchApiError && err.code === 'open_provisioning' && typeof err.details?.provisioningId === 'string') {
        await this.resumeOpen(String(err.details.provisioningId));
        return;
      }
      // Lot BANC-T §9: the name taken meanwhile in the site (another card, the console), the site no longer the target's:
      // nothing was planned, the card goes back to the choice (the page reads the site again).
      if (err instanceof BenchApiError && err.code === 'name_taken') {
        const suggested = typeof err.details?.suggestedName === 'string' ? err.details.suggestedName.slice(0, 100) : '';
        throw new Hold({ code: 'name_taken', params: { name: this.deviceName ?? '', suggestedName: suggested }, choices: [], attention: true });
      }
      if (err instanceof BenchApiError && err.code === 'site_refused') {
        throw new Hold({ code: 'site_refused', choices: [], attention: true });
      }
      // The exception D3 asked without an open session (closed meanwhile).
      if (err instanceof BenchApiError && err.code === 'no_session') {
        throw new Hold({ code: 'no_session', choices: ['retry'], attention: true });
      }
      if (err instanceof BenchApiError && ['target_refused', 'device_outside_target', 'agent_already_enrolled', 'agent_too_old'].includes(err.code)) {
        throw new Fail(err.code);
      }
      throw err;
    }
    if (this.plan.deviceName) this.deviceName = this.plan.deviceName;
    if (this.plan.warnings.includes('name_taken') || this.plan.warnings.includes('identity_conflict')) this.hint = this.plan.warnings[0];
    this.roleChosen = this.plan.roleTarget;
    if (this.plan.kind === 'convert') this.serverState = await this.d.api.provisioning(this.plan.provisioningId);
  }

  /** The open provisioning of this station for this serial: same role rule as the server (benchRolePlan, shared). It is
   *  resumed AS IT WAS PLANNED (lot BANC-T): its name, its site and its exception D3 replace those of the new card,
   *  which the card then shows (hint resumed_earlier when they differ); an older server gives none of them. */
  private async resumeOpen(id: string): Promise<void> {
    const st = await this.d.api.provisioning(id);
    this.serverState = st;
    const t = this.target!;
    let differs = false;
    if (st.deviceName !== undefined) {
      differs ||= (st.deviceName ?? null) !== (this.deviceName ?? null);
      this.deviceName = st.deviceName ?? null;
    }
    if (st.site !== undefined) {
      differs ||= (st.site?.id ?? null) !== (this.site?.id ?? null);
      this.site = st.site ?? null;
    }
    if (st.legacyOwnerBench !== undefined) this.allowLegacyOwner = st.legacyOwnerBench;
    const rp = benchRolePlan(t.rolePolicy, this.identity!.sdkInt, this.served?.versionCode ?? 0, t.allowLegacyOwner || this.allowLegacyOwner);
    // The server's role target when it gives it (the plan's), the local rule otherwise.
    const roleTarget = st.roleTarget ?? rp.target;
    differs ||= st.roleTarget !== undefined && st.roleTarget !== rp.target;
    this.plan = {
      provisioningId: id, kind: st.kind, roleTarget, fallbackAllowed: rp.fallbackAllowed,
      fallbackConfirm: rp.fallbackConfirm, deviceName: this.deviceName, warnings: [],
    };
    this.roleChosen = this.roleChosen ?? roleTarget;
    this.hint = differs ? 'resumed_earlier' : 'resumed';
    if (st.state === 'enrolled') {
      if (st.kind === 'new') { this.steps.configure = { status: 'ok', code: 'resumed' }; this.steps.wait_enroll = { status: 'ok', code: 'resumed' }; }
    }
  }

  // ── the role decision ──────────────────────────────────────────────────

  private chooseAdmin(choice: Choice): void {
    if (!this.plan || !this.plan.fallbackAllowed) return;
    if (choice === 'confirm_admin') this.confirmations = 2;
    else this.confirmations = Math.max(this.confirmations, 1);
    if (!this.plan.fallbackConfirm || this.confirmations >= 2) {
      this.roleChosen = 'device_admin';
      this.steps.role = { status: 'pending', code: null };
    }
  }

  /** Back to the plan's role after « Revérifier »: a fallback confirmed only once (Android 15+) is forgotten, and so is
   *  one without a second confirmation; only a fallback confirmed twice stays. */
  private resetFallback(): void {
    if (!this.plan) return;
    if (!this.plan.fallbackConfirm || this.confirmations < 2) {
      this.confirmations = 0;
      this.roleChosen = this.plan.roleTarget;
    }
    if (this.roleChosen === 'device_owner' && !this.done('role')) this.steps.role = { status: 'pending', code: null };
  }

  private ownerDecision(): void {
    if (this.roleChosen !== 'device_owner') return;
    const plan = this.plan!;
    // « Continuer en administrateur » on Android 15+: a second confirmation (Knox is restricted to an administrator).
    if (plan.fallbackAllowed && this.confirmations === 1 && plan.fallbackConfirm) {
      throw new Hold({ code: 'confirm_admin_sdk35', choices: ['confirm_admin', 'recheck'], attention: true });
    }
    const b = this.blockers();
    if (b.length === 0) return;
    throw new Hold({
      code: 'owner_blocked',
      params: { blockers: b.join(','), types: this.preflight!.accounts.types.join(', '), owners: Object.entries(this.preflight!.accounts.owners).map(([k, v]) => `${k}=${v}`).join(', ') },
      choices: plan.fallbackAllowed ? ['recheck', 'continue_admin'] : ['recheck'],
      attention: true,
    });
  }

  // ── install ────────────────────────────────────────────────────────────

  private async install(): Promise<void> {
    const served = this.served!;
    const current = await this.installedVersion();
    if (current !== null && current >= served.versionCode) {
      if (current > served.versionCode) throw new Fail('agent_downgrade');
      this.mark('install', 'skipped', 'up_to_date', { versionCode: current });
      return;
    }
    await this.d.requireApproved();
    this.mark('install', 'running');
    const apk = await ensureServedApk(this.d.apkCacheDir, served, this.d.pin, (dest) => this.d.api.downloadApk(served.sha256, dest));
    if (!apk.ok) {
      this.mark('install', 'failed', 'apk_mismatch');
      throw new Fail('apk_mismatch', { reason: apk.reason });
    }
    const r = await this.d.runner.install(this.serial, apk.file, ['-r']);
    this.note(['install', '-r', '<agent.apk>'], r);
    const v = r.timedOut ? { ok: false as const, code: 'play_protect' as const, reason: 'timeout' } : parseInstall(`${r.stdout}\n${r.stderr}`);
    if (v.ok) {
      this.mark('install', 'ok', 'installed', { versionCode: served.versionCode });
      this.agent = { versionCode: served.versionCode, signerSha256: this.d.pin, adminActive: this.agent?.adminActive ?? false, phase: this.agent?.phase ?? null };
      return;
    }
    if (v.code === 'play_protect') {
      this.mark('install', 'warn', 'play_protect');
      throw new Hold({ code: 'play_protect', choices: ['retry'], attention: true });
    }
    if (v.code === 'install_restricted') {
      this.mark('install', 'failed', 'install_restricted');
      throw new Hold({ code: 'install_restricted', choices: ['retry'], attention: true });
    }
    this.mark('install', 'failed', v.code);
    throw new Fail(v.code, { reason: v.reason });
  }

  // ── role ───────────────────────────────────────────────────────────────

  private async agentKnoxLicensed(): Promise<boolean> {
    const vc = this.agent?.versionCode ?? 0;
    if (vc < BENCH_OWNER_MIN_VERSION_CODE) return false;
    return (await this.benchCall('state'))?.knox === 'licensed';
  }

  /**
   * The state of the administrator once settled: DPMS removes an administrator asynchronously (it stays listed until
   * its DEVICE_ADMIN_DISABLED broadcast is done), so a reading right after `dpm` may still show it. Read every 300 ms
   * for 5 s at most, until two consecutive readings agree after 1.5 s at least (counted in readings, not by the clock).
   */
  private async settledPolicy(): Promise<PolicyReading & { agentAdminActive: boolean }> {
    let prev = await this.readPolicy();
    for (let i = 1; i <= SETTLE_READS; i++) {
      await this.sleep(SETTLE_STEP_MS);
      const cur = await this.readPolicy();
      if (i >= SETTLE_MIN_READS && cur.agentAdminActive === prev.agentAdminActive && cur.deviceOwner === prev.deviceOwner) return cur;
      prev = cur;
    }
    return prev;
  }

  private async setActiveAdmin(): Promise<boolean> {
    for (let attempt = 0; ; attempt++) {
      const r = await this.sh(['dpm', 'set-active-admin', '--user', '0', AGENT_ADMIN]);
      // « Trying to set an admin which is being removed »: the removal of a failed set-device-owner is not over yet.
      if (/being removed/i.test(`${r.stdout}\n${r.stderr}`) && attempt < 5) { await this.settledPolicy(); continue; }
      const policy = await this.settledPolicy();
      // The output says it; the reading back decides.
      if (!parseSetActiveAdmin(r.stdout) && !policy.agentAdminActive) return false;
      return policy.agentAdminActive;
    }
  }

  private async role(): Promise<void> {
    // Right before the role: the signer of what is REALLY installed, again (§6.4).
    const signer = await this.installedSigner();
    if (signer === null || signer !== this.d.pin) {
      this.mark('role', 'failed', 'agent_foreign_signer');
      throw new Fail('agent_foreign_signer');
    }
    const policy = await this.readPolicy();
    if (this.roleChosen === 'device_admin') {
      if (policy.agentAdminActive) { this.mark('role', 'ok', 'admin_already'); return; }
      await this.d.requireApproved();
      this.mark('role', 'running');
      if (!(await this.setActiveAdmin())) {
        this.mark('role', 'failed', 'admin_failed');
        throw new Fail('admin_failed');
      }
      this.mark('role', 'ok', 'admin_set');
      return;
    }
    if (policy.deviceOwner === PKG) {
      // Set by this run before an interruption (unplugged between dpm and the reading back): still this run's owner.
      if (this.ownerAttempted) this.ownerSetHere = true;
      this.mark('role', 'ok', 'owner_already');
      return;
    }
    // The preconditions, once more, right before (§6.3: the technician may have added an account meanwhile).
    await this.readPreflight();
    this.ownerDecision();
    await this.d.requireApproved();
    this.mark('role', 'running');
    const wasAdmin = policy.agentAdminActive;
    const knox = wasAdmin ? await this.agentKnoxLicensed() : false;
    if (wasAdmin && (this.agent?.versionCode ?? 0) >= BENCH_OWNER_MIN_VERSION_CODE) {
      // The Knox lock of the administrator (setAdminRemovable(false), every agent 1.3.0 under licence) can break the
      // administrator's removal dpm does: lifted first, by the agent, for 30 minutes.
      const prep = await this.prepareOwner();
      if (prep?.ok !== true) {
        this.mark('role', 'failed', 'owner_failed', { code: 'prepare_owner' });
        throw new Fail('owner_failed', { detail: 'prepare_owner' });
      }
    }
    this.ownerAttempted = true;
    const out = await this.sh(['dpm', 'set-device-owner', AGENT_ADMIN], 60_000);
    const verdict = parseSetDeviceOwner(`${out.stdout}\n${out.stderr}`);
    // The reading back decides (§6.5): an owner set whose output was lost (time-out, another wording) is a success; a
    // failure is read once the administrator's state has settled (its removal by DPMS is asynchronous).
    let after = await this.readPolicy();
    if (after.deviceOwner !== PKG) after = await this.settledPolicy();
    if (after.deviceOwner === PKG) {
      this.ownerSetHere = true;
      this.mark('role', 'ok', 'owner_set');
      return;
    }
    // Failed: read the REAL state back; restore the administrator only when it was there or the fallback is the plan.
    const code = verdict.ok ? 'owner_failed' : verdict.code;
    if (!after.agentAdminActive && wasAdmin) {
      if (!(await this.setActiveAdmin())) {
        this.mark('role', 'failed', 'admin_lost');
        throw new Fail('admin_lost');
      }
      if (knox) {
        await this.benchCall('poll');
        this.mark('role', 'warn', 'knox_reactivation');
        if (this.plan?.kind === 'convert') await this.waitKnoxLicensed();
      }
    }
    this.mark('role', 'failed', code);
    if (this.plan?.fallbackAllowed) {
      throw new Hold({ code: code === 'owner_failed' ? 'owner_failed' : 'owner_blocked', params: { blockers: code }, choices: ['recheck', 'continue_admin'], attention: true });
    }
    throw new Fail(code === 'owner_failed' ? 'owner_failed' : 'owner_blocked', { blockers: code });
  }

  /**
   * prepare_owner. An agent already enrolled (kind convert) lifts its lock only while the server allows it (an open
   * conversion of this device, told at its poll): on `not_authorized`, a poll is asked and the call made again, for
   * 60 s at most.
   */
  private async prepareOwner(): Promise<BenchAnswer | null> {
    let prep = await this.benchCall('prepare_owner');
    // 12 tries 5 s apart (60 s), counted in tries: the poll of the agent runs at most every 10 s.
    for (let i = 0; i < 12 && prep?.code === 'not_authorized' && this.plan?.kind === 'convert'; i++) {
      await this.benchCall('poll');
      await this.sleep(Math.max(this.t.pollMs, 5_000));
      prep = await this.benchCall('prepare_owner');
    }
    return prep;
  }

  private async waitKnoxLicensed(): Promise<void> {
    const deadline = this.now() + this.t.verifyMs;
    while (this.now() < deadline) {
      const st = await this.d.api.provisioning(this.plan!.provisioningId).catch(() => null);
      if (st?.agent?.knoxState === 'licensed') { this.mark('role', 'warn', 'knox_reactivated'); return; }
      await this.sleep(this.t.pollMs);
    }
  }

  // ── prepare ────────────────────────────────────────────────────────────

  private async prepare(): Promise<void> {
    await this.d.requireApproved();
    this.mark('prepare', 'running');
    const sdk = this.identity!.sdkInt;
    const cmds: string[][] = [['dumpsys', 'deviceidle', 'whitelist', `+${PKG}`]];
    if (sdk >= 28) cmds.push(['cmd', 'appops', 'set', PKG, 'RUN_ANY_IN_BACKGROUND', 'allow']);
    for (const p of RUNTIME_PERMISSIONS) cmds.push(['pm', 'grant', PKG, p]);
    if (sdk >= 33) cmds.push(['pm', 'grant', PKG, 'android.permission.POST_NOTIFICATIONS']);
    if (this.roleChosen === 'device_admin') {
      cmds.push(['appops', 'set', PKG, 'SYSTEM_ALERT_WINDOW', 'allow']);
      if (sdk <= 25) cmds.push(['settings', 'put', 'secure', 'install_non_market_apps', '1']);
      else cmds.push(['appops', 'set', PKG, 'REQUEST_INSTALL_PACKAGES', 'allow']);
    }
    let failed = 0;
    for (const c of cmds) {
      const r = await this.sh(c);
      if (r.code !== 0 || /Exception|Error|Unknown/i.test(r.stdout + r.stderr)) failed++;
    }
    this.mark('prepare', failed ? 'warn' : 'ok', failed ? 'partial' : null, { counts: { commands: cmds.length, failed } });
  }

  // ── configure (the secret) ─────────────────────────────────────────────

  private async configure(): Promise<void> {
    const plan = this.plan!;
    await this.d.requireApproved();
    this.mark('configure', 'running');
    if (plan.kind === 'convert') {
      // Already enrolled: no token. A cycle, so that the agent reports deviceOwner=true (§6.5).
      await this.benchCall('poll');
      this.mark('configure', 'ok', 'convert_poll');
      return;
    }
    let config: string;
    try {
      config = (await this.d.api.token(plan.provisioningId)).config;
    } catch (err) {
      if (err instanceof BenchApiError && err.code === 'no_session') {
        this.mark('configure', 'failed', 'no_session');
        throw new Hold({ code: 'no_session', choices: ['retry'], attention: true });
      }
      if (err instanceof BenchApiError && err.code === 'bad_state') {
        this.serverState = await this.d.api.provisioning(plan.provisioningId);
        if (this.serverState.state === 'enrolled') { this.mark('configure', 'ok', 'resumed'); this.mark('wait_enroll', 'ok', 'resumed'); return; }
      }
      throw err;
    }
    if (!CONFIG_RE.test(config)) { config = ''; throw new Fail('configure_failed', { detail: 'config' }); }
    const legacy = (this.agent?.versionCode ?? this.served!.versionCode) < BENCH_OWNER_MIN_VERSION_CODE;
    const line = legacy
      ? `am start -n ${PKG}/.SetupActivity -a ${PKG}.action.ACTIVATE_ADMIN --es config '${config}'`
      : `content call --uri content://${BENCH_AUTHORITY} --method import --arg '${config}'`;
    let r: AdbResult;
    try {
      r = await this.script(['input keyevent KEYCODE_WAKEUP', line], 'configure');
    } finally {
      config = '';
    }
    if ((this.identity?.sdkInt ?? 0) >= 34) this.hint = 'old_android_dialog';
    if (legacy) {
      if (r.code !== 0 || /Error|Exception/.test(r.stdout + r.stderr)) { this.mark('configure', 'failed', 'configure_failed'); throw new Fail('configure_failed'); }
      this.mark('configure', 'ok', 'activity_started');
      return;
    }
    const ans = parseContentCall(r.stdout) ?? (await this.benchCall('state'));
    if (ans?.ok === true || (ans?.ok === null && ans.phase === 'CONFIGURED')) { this.mark('configure', 'ok', 'configured'); return; }
    const code = ans?.code ?? null;
    if (code === 'already_enrolled' || ans?.phase === 'ENROLLED') { this.mark('configure', 'failed', 'agent_already_enrolled'); throw new Fail('agent_already_enrolled'); }
    this.mark('configure', 'failed', 'configure_failed', code ? { code: code.toLowerCase().slice(0, 48) } : undefined);
    throw new Fail('configure_failed', { detail: code ?? 'unknown' });
  }

  // ── wait_enroll, verify, finalize ──────────────────────────────────────

  private async waitEnroll(): Promise<void> {
    const id = this.plan!.provisioningId;
    this.mark('wait_enroll', 'running');
    this.tone = 'wait';
    const deadline = this.now() + this.t.enrollMs;
    let n = 0;
    let enrolledOnDevice = 0;
    const modern = (this.agent?.versionCode ?? 0) >= BENCH_OWNER_MIN_VERSION_CODE;
    while (this.now() < deadline) {
      const st = await this.d.api.provisioning(id);
      this.serverState = st;
      if (st.state === 'enrolled' || st.state === 'completed') { this.mark('wait_enroll', 'ok'); this.tone = 'act'; return; }
      if (st.state === 'failed') {
        const c = st.errorCode === 'identity_mismatch' ? 'identity_mismatch' : (st.errorCode ?? 'enroll_timeout');
        this.mark('wait_enroll', 'failed', c);
        throw new Fail(c);
      }
      if (st.state === 'abandoned' || st.state === 'expired') { this.mark('wait_enroll', 'failed', 'enroll_timeout'); throw new Fail('enroll_timeout'); }
      if (modern && ++n % this.t.stateEvery === 0) {
        const a = await this.benchCall('state');
        if (a?.phase === 'TOKEN_REJECTED') {
          this.mark('wait_enroll', 'failed', 'token_rejected');
          throw new Hold({ code: 'token_rejected', choices: ['reissue'], attention: true });
        }
        if (a?.phase === 'ENROLLED') {
          if (++enrolledOnDevice >= 3) { this.mark('wait_enroll', 'failed', 'agent_already_enrolled'); throw new Fail('agent_already_enrolled'); }
        } else {
          enrolledOnDevice = 0;
        }
        if (a?.last && ['network_error', 'clock', 'link_lost'].includes(a.last)) this.hint = a.last;
      }
      await this.sleep(this.t.pollMs);
    }
    this.mark('wait_enroll', 'failed', 'enroll_timeout');
    throw new Hold({ code: 'enroll_timeout', choices: ['reissue'], attention: true });
  }

  private async verify(): Promise<void> {
    this.mark('verify', 'running');
    const id = this.plan!.provisioningId;
    const owner = this.roleChosen === 'device_owner';
    const modern = (this.agent?.versionCode ?? 0) >= BENCH_OWNER_MIN_VERSION_CODE;
    const policy = await this.readPolicy();
    if (owner && policy.deviceOwner !== PKG) { this.mark('verify', 'failed', 'owner_failed'); throw new Fail('owner_failed'); }
    if (!owner && !policy.agentAdminActive) { this.mark('verify', 'failed', 'admin_lost'); throw new Fail('admin_lost'); }
    const deadline = this.now() + this.t.verifyMs;
    let n = 0;
    for (;;) {
      const st = await this.d.api.provisioning(id);
      this.serverState = st;
      const reported = !!st.agent && (!owner || !modern || st.agent.deviceOwner === true);
      if (reported) break;
      if (this.now() >= deadline) { this.mark('verify', 'failed', 'owner_failed'); throw new Fail('owner_failed', { detail: 'not_reported' }); }
      if (modern && ++n % 5 === 0) await this.benchCall('poll');
      await this.sleep(this.t.pollMs);
    }
    const st = this.serverState!;
    if (st.identityState === 'mismatch') { this.mark('verify', 'failed', 'identity_mismatch'); throw new Fail('identity_mismatch'); }
    const warn = owner && !modern ? 'owner_unconfirmed' : st.identityState === 'unconfirmed' ? 'identity_unconfirmed' : null;
    this.mark('verify', warn ? 'warn' : 'ok', warn ?? (owner ? 'owner_confirmed' : 'admin_confirmed'));
  }

  private async finalize(): Promise<void> {
    const id = this.plan!.provisioningId;
    await this.d.requireApproved();
    this.mark('finalize', 'running');
    await this.flush();
    const deadline = this.now() + this.t.verifyMs;
    for (;;) {
      try {
        await this.d.api.result(id, { outcome: 'completed', roleDeclared: this.roleChosen! });
        break;
      } catch (err) {
        if (err instanceof BenchApiError && err.code === 'not_verified' && this.now() < deadline) {
          await this.benchCall('poll');
          await this.sleep(this.t.pollMs);
          continue;
        }
        if (err instanceof BenchApiError && err.code === 'not_verified') { this.mark('finalize', 'failed', 'owner_failed'); throw new Fail('owner_failed'); }
        throw err;
      }
    }
    this.serverState = { ...(this.serverState as ProvisioningState), state: 'completed' };
    this.mark('finalize', 'ok', this.target!.disableDevOptions ? 'adb_cut' : 'adb_kept');
    await this.flush();
    this.outcome = 'completed';
    this.tone = 'ok';
    if (this.target!.disableDevOptions) {
      // ONE script: the second of two calls would die with ADB. The device then leaves adb: expected. The cut is
      // acquired only when the agent reports adbEnabled=false.
      this.adbCut = 'pending_agent';
      try {
        await this.script(['settings put global development_settings_enabled 0', 'settings put global adb_enabled 0'], 'finalize');
      } catch (err) {
        if (!(err instanceof DeviceGoneError)) throw err;
      }
    }
    this.d.onFinished?.(this);
  }
}
