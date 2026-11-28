import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, openSync, closeSync, readFileSync, writeFileSync, unlinkSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { uiProfileDir } from './paths';
import { logError } from './native';

/**
 * Obligarth bench station — the desktop half: the window and one instance per user (lot BANC §5.2), ported from the
 * bench of Obliwan.
 *
 * The page is served by a loopback HTTP server (127.0.0.1, port 0, a per-run token) and opens in Microsoft Edge's APP
 * mode (`--app=<url>`, a profile of its own in %LOCALAPPDATA%\Obligarth\bench-ui): a window with no address bar, its
 * own taskbar entry, and a process whose exit is the window closing.
 *
 * NO BROWSER FALLBACK (decision of the suite, kept from Obliwan): Edge is tried three times, 1.5 s apart, re-found each
 * time, every failure written to bench-error.log; after the third the answer is `none` and the caller says so in a
 * message box and stops. Nothing here may ever spawn `cmd start`, `open` or `xdg-open`.
 *
 * The process ends with the window: the page holds an EventSource open and posts a heartbeat every 5 s (WindowWatch);
 * it ends ~15 s after the last sign of life, or 2 s after Edge exits with no stream open — never during an operation on
 * a device (gui.ts reopens the window instead).
 */

const APP_PATHS = [
  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe',
  'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe',
  'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe',
];

function registryDefault(key: string): string | null {
  try {
    const out = execFileSync('reg', ['query', key, '/ve'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], timeout: 5_000 });
    const m = /REG_(?:EXPAND_)?SZ\s+(.+?)\s*$/m.exec(out);
    if (!m) return null;
    return m[1].replace(/^"|"$/g, '').replace(/%([^%]+)%/g, (_, name: string) => process.env[name] ?? `%${name}%`);
  } catch {
    return null;
  }
}

/** msedge.exe: the registry's App Paths first, then the standard folders. */
export function findEdge(env: NodeJS.ProcessEnv = process.env): string | null {
  if (process.platform !== 'win32') return null;
  for (const key of APP_PATHS) {
    const p = registryDefault(key);
    if (p && /msedge\.exe$/i.test(p) && existsSync(p)) return p;
  }
  const roots = [env['ProgramFiles(x86)'], env.ProgramFiles, env.ProgramW6432, env.LOCALAPPDATA]
    .filter((r): r is string => typeof r === 'string' && r.trim() !== '');
  for (const root of roots) {
    const p = join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe');
    if (existsSync(p)) return p;
  }
  return null;
}

export type WindowMode = 'edge-app' | 'none';

export interface OpenedWindow {
  mode: WindowMode;
  child: ChildProcess | null;
  /** `edge-app`: the msedge.exe used. `none`: a code and its cause, for the log and the message box. */
  detail: string | null;
}

export const EDGE_ATTEMPTS = 3;
export const EDGE_RETRY_MS = 1_500;

/** The Edge command line: an app window on a profile of its own. */
export function edgeArguments(url: string, userDataDir: string): string[] {
  return [
    `--app=${url}`,
    `--user-data-dir=${userDataDir}`,
    '--window-size=1200,880',
    '--no-first-run',
    '--no-default-browser-check',
    // The page beeps when a card needs the technician, possibly before anybody clicked in the window.
    '--autoplay-policy=no-user-gesture-required',
  ];
}

type Spawned = { ok: true } | { ok: false; code: string };

function spawned(child: ChildProcess): Promise<Spawned> {
  return new Promise((resolve) => {
    child.once('spawn', () => resolve({ ok: true }));
    child.once('error', (err: NodeJS.ErrnoException) => resolve({ ok: false, code: err?.code ?? err?.message ?? 'unknown' }));
  });
}

export interface OpenWindowOptions {
  attempts?: number;
  retryMs?: number;
  sleep?: (ms: number) => Promise<void>;
  /** Injected by the harness (it records the arguments instead of starting Edge). */
  spawnEdge?: (exe: string, args: string[]) => ChildProcess;
  findEdge?: (env: NodeJS.ProcessEnv) => string | null;
}

/** Open the UI in Edge's app mode, up to EDGE_ATTEMPTS times; never the default browser. NOT `windowsHide` for Edge
 *  (SW_HIDE would hide its first window). */
export async function openAppWindow(url: string, env: NodeJS.ProcessEnv = process.env, opts: OpenWindowOptions = {}): Promise<OpenedWindow> {
  const attempts = Math.max(1, opts.attempts ?? EDGE_ATTEMPTS);
  const retryMs = opts.retryMs ?? EDGE_RETRY_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const find = opts.findEdge ?? findEdge;
  const start = opts.spawnEdge ?? ((exe: string, args: string[]) => spawn(exe, args, { stdio: 'ignore', detached: false }));
  const profile = uiProfileDir(env);
  let cause = 'unknown';
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1) await sleep(retryMs);
    const edge = find(env);
    if (!edge) {
      cause = 'edge_not_found';
    } else {
      try { mkdirSync(profile, { recursive: true }); } catch { /* Edge creates it */ }
      try {
        const child = start(edge, edgeArguments(url, profile));
        const r = await spawned(child);
        if (r.ok) return { mode: 'edge-app', child, detail: edge };
        cause = `edge_failed (${r.code})`;
      } catch (err) {
        cause = `edge_failed (${(err as NodeJS.ErrnoException)?.code ?? (err instanceof Error ? err.message : String(err))})`;
      }
    }
    // Never the URL: it carries the per-run token.
    logError(`application window, attempt ${attempt}/${attempts}: ${cause}${edge ? ` [${edge}]` : ''}`, env);
  }
  return { mode: 'none', child: null, detail: `${cause} (${attempts} attempts)` };
}

// ── When to exit ────────────────────────────────────────────────────────────

export interface WindowWatchOptions {
  idleMs?: number;
  startupGraceMs?: number;
  handoffMs?: number;
  now?: () => number;
}

export type WatchVerdict = 'alive' | 'window-closed' | 'never-opened';

/** Pure bookkeeping; the caller ticks it and acts on the verdict. */
export class WindowWatch {
  private streams = 0;
  private lastSign: number;
  private connected = false;
  private readonly idleMs: number;
  private readonly startupGraceMs: number;
  private readonly handoffMs: number;
  private readonly now: () => number;

  constructor(opts: WindowWatchOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.idleMs = opts.idleMs ?? 15_000;
    this.startupGraceMs = opts.startupGraceMs ?? 120_000;
    this.handoffMs = opts.handoffMs ?? 10_000;
    this.lastSign = this.now();
  }

  streamOpened(): void { this.streams++; this.connected = true; this.lastSign = this.now(); }
  streamClosed(): void { this.streams = Math.max(0, this.streams - 1); this.lastSign = this.now(); }
  heartbeat(): void { this.connected = true; this.lastSign = this.now(); }
  reopened(): void { this.lastSign = this.now(); }

  /** The Edge child exited after `ranMs`: a quick exit is a hand-off to a running Edge, not a close. */
  edgeExited(ranMs: number): void {
    if (ranMs < this.handoffMs || this.streams > 0) return;
    this.lastSign = Math.min(this.lastSign, this.now() - this.idleMs + 2_000);
  }

  verdict(): WatchVerdict {
    if (this.streams > 0) return 'alive';
    const t = this.now();
    if (!this.connected) return t - this.lastSign > this.startupGraceMs ? 'never-opened' : 'alive';
    return t - this.lastSign > this.idleMs ? 'window-closed' : 'alive';
  }
}

// ── One instance per user ───────────────────────────────────────────────────

export interface InstanceLock { pid: number; port: number | null; token: string | null; startedAt: string }

function readLock(path: string): InstanceLock | null {
  try {
    const v = JSON.parse(readFileSync(path, 'utf8')) as Partial<InstanceLock>;
    if (typeof v.pid !== 'number' || !Number.isInteger(v.pid)) return null;
    return {
      pid: v.pid,
      port: typeof v.port === 'number' && Number.isInteger(v.port) && v.port > 0 && v.port < 65536 ? v.port : null,
      token: typeof v.token === 'string' && /^[0-9a-f]{32,128}$/.test(v.token) ? v.token : null,
      startedAt: typeof v.startedAt === 'string' ? v.startedAt : '',
    };
  } catch {
    return null;
  }
}

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (err) { return (err as NodeJS.ErrnoException).code === 'EPERM'; }
}

export type InstanceClaim =
  | { owner: true; publish(port: number, token: string): void; release(): void }
  | { owner: false; running: InstanceLock & { port: number; token: string } };

/**
 * Become THE instance, or find the one that is. The lock (`bench.lock`) is created exclusively (`wx`); a lock left by
 * a dead process, or whose server does not answer `probe` with its own token, is stale and replaced.
 */
export async function claimInstance(
  path: string,
  probe: (lock: InstanceLock & { port: number; token: string }) => Promise<boolean>,
  opts: { waitMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<InstanceClaim> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deadline = Date.now() + (opts.waitMs ?? 6_000);
  mkdirSync(dirname(path), { recursive: true });
  for (;;) {
    try {
      const fd = openSync(path, 'wx');
      const mine: InstanceLock = { pid: process.pid, port: null, token: null, startedAt: new Date().toISOString() };
      writeFileSync(fd, JSON.stringify(mine));
      closeSync(fd);
      return {
        owner: true,
        publish(port: number, token: string) {
          writeFileSync(path, JSON.stringify({ ...mine, port, token }), { encoding: 'utf8', mode: 0o600 });
        },
        release() {
          try {
            const now = readLock(path);
            if (now && now.pid === process.pid) unlinkSync(path);
          } catch { /* already gone */ }
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
    const lock = readLock(path);
    if (lock && lock.port !== null && lock.token !== null) {
      const running = { ...lock, port: lock.port, token: lock.token };
      if (await probe(running)) return { owner: false, running };
    }
    let fresh = false;
    try { fresh = lock === null && Date.now() - statSync(path).mtimeMs < 2_000; } catch { /* gone meanwhile */ }
    const starting = fresh || (lock !== null && lock.port === null && lock.pid !== process.pid && pidAlive(lock.pid));
    if (starting && Date.now() < deadline) { await sleep(250); continue; }
    try { unlinkSync(path); } catch (err) { if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err; }
    if (Date.now() > deadline + 5_000) throw new Error(`cannot take the lock ${path}`);
  }
}
