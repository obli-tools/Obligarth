import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { redact } from '../redact';
import { parseDevicesL, deviceGoneMessage, type AdbDevice } from './parse';

/**
 * Obligarth bench station — every call to adb goes through an AdbRunner (lot BANC §5.6).
 *
 * ┌─ NO SHELL ON THE PC, NO PIPE ON THE DEVICE ──────────────────────────────┐
 * │ `spawn` with `shell:false` and an argument array: nothing is ever parsed  │
 * │ by cmd.exe. On the device, a command is ONE string quoted by `shellQuote` │
 * │ (refusing any control character), never a pipe or a filter: the whole    │
 * │ output comes back and is filtered here.                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A SECRET NEVER TRAVELS AS AN ARGUMENT ON THE PC ────────────────────────┐
 * │ A call that carries a configuration (the enrollment token) passes        │
 * │ `stdin`: the runner starts `adb -s X shell -T` (no PTY, so no echo of    │
 * │ the script), writes the script on its standard input, then `exit`, and   │
 * │ redacts stdout and stderr. The documented exception is on the DEVICE:    │
 * │ there the configuration is an argument of `content` for the length of   │
 * │ the call, readable by shell and root only (hidepid, Android 7+).         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The binary is injectable as `[exe, ...prefix]`: since Node 18.20.2 / 20.12.2 (CVE-2024-27980) a `.cmd` no longer
 * starts with `shell:false`, so the harness's fake adb is a `.mjs` started as `[process.execPath, 'fake-adb.mjs']`.
 *
 * The adb server runs on the station's OWN port (5137 by default, `[adb] port=` of the .ini), so it never shares the
 * server of another tool on 5037 — which does not isolate USB (WinUSB opens a device for one process only: see
 * conflict.ts). The adb process gets its own home (`adb-home`): ANDROID_USER_HOME (the `.android` folder itself),
 * ANDROID_SDK_HOME, USERPROFILE and HOME (its parent). MEASURED on platform-tools 37.0.1 for Windows: adb reads none of
 * them for its key, which stays in the Windows profile (`SHGetFolderPath(CSIDL_PROFILE)`); platformTools.ts checks
 * where the key really is and the page says so (keyLocation).
 */

export interface AdbResult { code: number; stdout: string; stderr: string; timedOut: boolean }

export interface ShellOptions { timeoutMs?: number; stdin?: string }

export interface AdbRunner {
  devices(): Promise<AdbDevice[]>;
  shell(serial: string, argv: string[], opts?: ShellOptions): Promise<AdbResult>;
  install(serial: string, apkPath: string, flags: string[]): Promise<AdbResult>;
  pull(serial: string, remote: string, local: string): Promise<AdbResult>;
  track(onChange: (list: AdbDevice[]) => void): () => void;
  startServer(): Promise<AdbResult>;
  killServer(): Promise<AdbResult>;
  /** `kill-server` on another port (the conflict of §5.5: `adb -P 5037 kill-server`). */
  killServerOn(port: number): Promise<AdbResult>;
}

/** `adb devices -l` failed (non-zero exit, time-out, a server restarting): NOT a list without devices. */
export class AdbListError extends Error {
  constructor(readonly reason: string) { super(`adb devices failed: ${reason}`); this.name = 'AdbListError'; }
}

/** The device is no longer reachable (unplugged, offline, authorization withdrawn): the card holds. */
export class DeviceGoneError extends Error {
  constructor(readonly serial: string, detail: string) {
    super(`device ${serial} gone: ${detail.slice(0, 120)}`);
    this.name = 'DeviceGoneError';
  }
}

export const DEFAULT_TIMEOUT_MS = 30_000;
export const INSTALL_TIMEOUT_MS = 180_000;
export const OUTPUT_LIMIT = 1024 * 1024;
export const DEFAULT_ADB_PORT = 5137;

const SAFE_ARG = /^[A-Za-z0-9_@%+=:,./-]+$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

/** Quote an argv for the device's shell (one string). Refuses any control character: a newline would start a second
 *  command. */
export function shellQuote(argv: string[]): string {
  return argv.map((a) => {
    if (typeof a !== 'string') throw new TypeError('shellQuote: not a string');
    if (CONTROL.test(a)) throw new Error('shellQuote: control character refused');
    if (a === '') return "''";
    return SAFE_ARG.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`;
  }).join(' ');
}

/** The environment of the adb process only. */
export function adbEnvironment(base: NodeJS.ProcessEnv, port: number, adbHome: string): NodeJS.ProcessEnv {
  return {
    ...base,
    ANDROID_ADB_SERVER_PORT: String(port),
    ANDROID_USER_HOME: join(adbHome, '.android'),
    ANDROID_SDK_HOME: adbHome,
    USERPROFILE: adbHome,
    HOME: adbHome,
    // Never a serial chosen by the environment: every call names its device.
    ANDROID_SERIAL: '',
  };
}

export interface ProcessAdbRunnerOptions {
  /** `[exe, ...prefix]`: adb.exe, or `[process.execPath, 'fake-adb.mjs']`. */
  command: string[];
  port?: number;
  adbHome: string;
  env?: NodeJS.ProcessEnv;
  /** Called with every finished call, its output redacted: the card's raw journal. */
  onCall?: (entry: { args: string[]; result: AdbResult }) => void;
}

export class ProcessAdbRunner implements AdbRunner {
  readonly port: number;
  private readonly command: string[];
  private readonly env: NodeJS.ProcessEnv;

  constructor(private readonly opts: ProcessAdbRunnerOptions) {
    if (opts.command.length === 0) throw new Error('ProcessAdbRunner: no command');
    this.command = opts.command;
    this.port = opts.port ?? DEFAULT_ADB_PORT;
    try { mkdirSync(join(opts.adbHome, '.android'), { recursive: true }); } catch { /* adb creates what it needs */ }
    this.env = adbEnvironment(opts.env ?? process.env, this.port, opts.adbHome);
  }

  /** One adb call. `-P <port>` always first, so no call can reach another server by mistake. */
  run(args: string[], o: { timeoutMs?: number; stdin?: string; secret?: boolean } = {}): Promise<AdbResult> {
    const [exe, ...prefix] = this.command;
    const full = [...prefix, '-P', String(this.port), ...args];
    const timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    return new Promise((resolve) => {
      let child: ChildProcess;
      let stdout = '';
      let stderr = '';
      let size = 0;
      let timedOut = false;
      const done = (code: number): void => {
        clearTimeout(timer);
        const result: AdbResult = {
          code,
          stdout: o.secret ? redact(stdout) : stdout,
          stderr: o.secret ? redact(stderr) : stderr,
          timedOut,
        };
        this.opts.onCall?.({ args: args.map((a) => redact(a)), result: { ...result, stdout: redact(result.stdout), stderr: redact(result.stderr) } });
        resolve(result);
      };
      try {
        child = spawn(exe, full, { shell: false, windowsHide: true, env: this.env, stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (err) {
        resolve({ code: -1, stdout: '', stderr: err instanceof Error ? err.message : String(err), timedOut: false });
        return;
      }
      const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
      const take = (which: 'out' | 'err') => (chunk: Buffer): void => {
        if (size >= OUTPUT_LIMIT) return;
        const text = chunk.toString('utf8');
        size += chunk.length;
        if (which === 'out') stdout += text; else stderr += text;
        if (size >= OUTPUT_LIMIT) {
          if (which === 'out') stdout = stdout.slice(0, OUTPUT_LIMIT); else stderr = stderr.slice(0, OUTPUT_LIMIT);
        }
      };
      child.stdout?.on('data', take('out'));
      child.stderr?.on('data', take('err'));
      child.once('error', (err) => { stderr += err.message; done(-1); });
      child.once('close', (code) => done(code ?? -1));
      if (o.stdin !== undefined) {
        child.stdin?.end(o.stdin.endsWith('\n') ? o.stdin : `${o.stdin}\n`);
      } else {
        child.stdin?.end();
      }
    });
  }

  private checkGone(serial: string, r: AdbResult): AdbResult {
    if (r.code !== 0 && deviceGoneMessage(r.stderr)) throw new DeviceGoneError(serial, r.stderr);
    return r;
  }

  /** The devices adb sees; throws AdbListError when the reading failed (a failure is never « no device »). */
  async devices(): Promise<AdbDevice[]> {
    const r = await this.run(['devices', '-l'], { timeoutMs: 10_000 });
    if (r.code !== 0 || r.timedOut) throw new AdbListError(r.timedOut ? 'timeout' : `exit ${r.code}`);
    return parseDevicesL(r.stdout);
  }

  async shell(serial: string, argv: string[], opts: ShellOptions = {}): Promise<AdbResult> {
    if (opts.stdin !== undefined) {
      // The script, then `exit`: the shell ends when the script does, never waits on a closed pipe.
      const script = `${opts.stdin.replace(/\n+$/, '')}\nexit\n`;
      const r = await this.run(['-s', serial, 'shell', '-T'], { timeoutMs: opts.timeoutMs, stdin: script, secret: true });
      return this.checkGone(serial, r);
    }
    const r = await this.run(['-s', serial, 'shell', shellQuote(argv)], { timeoutMs: opts.timeoutMs });
    return this.checkGone(serial, r);
  }

  async install(serial: string, apkPath: string, flags: string[]): Promise<AdbResult> {
    for (const f of flags) if (!['-r', '-g'].includes(f)) throw new Error(`install flag refused: ${f}`);
    const r = await this.run(['-s', serial, 'install', ...flags, apkPath], { timeoutMs: INSTALL_TIMEOUT_MS });
    return this.checkGone(serial, r);
  }

  async pull(serial: string, remote: string, local: string): Promise<AdbResult> {
    if (CONTROL.test(remote) || !remote.startsWith('/')) throw new Error('pull: remote path refused');
    const r = await this.run(['-s', serial, 'pull', remote, local], { timeoutMs: 120_000 });
    return this.checkGone(serial, r);
  }

  startServer(): Promise<AdbResult> { return this.run(['start-server'], { timeoutMs: 20_000 }); }
  killServer(): Promise<AdbResult> { return this.run(['kill-server'], { timeoutMs: 10_000 }); }

  killServerOn(port: number): Promise<AdbResult> {
    const [exe, ...prefix] = this.command;
    return new Promise((resolve) => {
      const child = spawn(exe, [...prefix, '-P', String(port), 'kill-server'], { shell: false, windowsHide: true, env: { ...this.env, ANDROID_ADB_SERVER_PORT: String(port) }, stdio: 'ignore' });
      const t = setTimeout(() => child.kill(), 10_000);
      child.once('error', () => { clearTimeout(t); resolve({ code: -1, stdout: '', stderr: 'spawn failed', timedOut: false }); });
      child.once('close', (code) => { clearTimeout(t); resolve({ code: code ?? -1, stdout: '', stderr: '', timedOut: false }); });
    });
  }

  /**
   * `adb track-devices` as a trigger, `devices -l` as the reading (the long format of track-devices varies between
   * versions), and a reading every 2 s whenever the tracking process is not running (§5.4).
   */
  track(onChange: (list: AdbDevice[]) => void): () => void {
    let stopped = false;
    let child: ChildProcess | null = null;
    let last = '';
    let reading = false;
    // An event that comes during a reading is never lost: the reading goes again once it ends.
    let again = false;
    const read = async (): Promise<void> => {
      if (stopped) return;
      if (reading) { again = true; return; }
      reading = true;
      try {
        do {
          again = false;
          let list: AdbDevice[];
          // A failed reading is ignored (the next event or the reading of safety reads again): never « all unplugged ».
          try { list = await this.devices(); } catch { continue; }
          const key = JSON.stringify(list);
          if (key !== last) { last = key; onChange(list); }
        } while (again && !stopped);
      } finally {
        reading = false;
      }
    };
    const startTracker = (): void => {
      if (stopped) return;
      const [exe, ...prefix] = this.command;
      try {
        child = spawn(exe, [...prefix, '-P', String(this.port), 'track-devices'], { shell: false, windowsHide: true, env: this.env, stdio: ['ignore', 'pipe', 'ignore'] });
        child.stdout?.on('data', () => { void read(); });
        child.once('error', () => { child = null; });
        child.once('close', () => { child = null; });
      } catch {
        child = null;
      }
    };
    startTracker();
    void read();
    const poll = setInterval(() => {
      if (!child) { void read(); startTracker(); }
    }, 2_000);
    // A reading every 10 s anyway: a tracker that says nothing is not proof that nothing changed.
    const safety = setInterval(() => { void read(); }, 10_000);
    return () => {
      stopped = true;
      clearInterval(poll);
      clearInterval(safety);
      try { child?.kill(); } catch { /* gone */ }
    };
  }
}
