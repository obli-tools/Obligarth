import { loadBenchConfig } from './config';
import { defaultProtector } from './dpapi';
import { createBenchApp, type BenchAppHooks } from './gui';
import { t } from './i18n';
import { showMessageBox } from './native';
import { lockFile, stationFile } from './paths';
import { StationStore } from './station';
import { claimInstance, openAppWindow, type InstanceLock } from './window';

/**
 * Obligarth bench station — the process: one instance, one window, adb started on its own port and stopped with the
 * application, gone when the window is — never during an operation on a device (the window comes back instead, once
 * per operation). Ported from Obliwan's runGui.
 */

const TITLE = 'Obligarth Bench';

async function probeInstance(lock: InstanceLock & { port: number; token: string }): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${lock.port}/api/instance`, { headers: { 'x-bench-token': lock.token }, signal: AbortSignal.timeout(1_500) });
    const body = (await res.json()) as { app?: unknown };
    return res.ok && body.app === 'obligarth-bench';
  } catch {
    return false;
  }
}

export async function runGui(): Promise<void> {
  const claim = await claimInstance(lockFile(), probeInstance);
  if (!claim.owner) {
    let ok = false;
    try {
      const res = await fetch(`http://127.0.0.1:${claim.running.port}/api/window`, {
        method: 'POST', headers: { 'x-bench-token': claim.running.token }, signal: AbortSignal.timeout(5_000),
      });
      ok = res.ok;
    } catch {
      ok = false;
    }
    if (!ok) await showMessageBox(TITLE, t('bench.main.alreadyRunning') || 'The station is already open but does not answer.');
    process.exitCode = ok ? 0 : 1;
    return;
  }
  process.on('exit', () => claim.release());

  const protector = defaultProtector();
  const store = new StationStore(stationFile(), protector);
  const config = loadBenchConfig({ lastAnsweredUrl: await store.lastAnsweredUrl() });
  const hooks: BenchAppHooks = {};
  const app = createBenchApp({ hooks, protector, stationStore: store, config });
  try {
    await app.listen();
  } catch (err) {
    claim.release();
    await showMessageBox(TITLE, t('bench.main.serverFailed', { detail: err instanceof Error ? err.message : String(err) }) || 'The local server could not start.');
    process.exit(1);
  }
  claim.publish(Number(new URL(app.url()).port), app.token);
  void app.startAdb();

  let opening = false;
  let leaving = false;
  let watchTimer: NodeJS.Timeout | null = null;
  const leave = async (code: number, message: string | null): Promise<void> => {
    if (leaving) return;
    leaving = true;
    if (watchTimer) clearInterval(watchTimer);
    claim.release();
    await app.close().catch(() => undefined);
    if (message) await showMessageBox(TITLE, message, 'info');
    process.exitCode = code;
    setTimeout(() => process.exit(code), 5_000).unref();
  };
  const open = async (): Promise<void> => {
    if (opening) return;
    opening = true;
    try {
      const w = await openAppWindow(app.url());
      app.setWindow(w.mode, w.detail);
      if (w.child) {
        const started = Date.now();
        w.child.once('exit', () => app.watch.edgeExited(Date.now() - started));
      }
      if (w.mode === 'none') {
        await showMessageBox(TITLE, t('bench.main.windowFailed', { detail: w.detail ?? '' }) || 'The window could not open.');
        if (app.busy() === null) void leave(1, null);
      }
    } finally {
      opening = false;
    }
  };
  hooks.reopen = () => void open();
  hooks.exit = () => void leave(0, null);
  process.on('SIGINT', () => void leave(0, null));
  process.on('SIGTERM', () => void leave(0, null));

  await open();
  if (leaving) return;
  let reopenedFor: string | null = null;
  watchTimer = setInterval(() => {
    const v = app.watch.verdict();
    if (v === 'alive') return;
    const op = app.busy();
    if (op) {
      // Never leave in the middle of an operation on a device: the window comes back once for it.
      if (reopenedFor !== op.serial) { reopenedFor = op.serial; app.watch.reopened(); void open(); }
      return;
    }
    if (v === 'window-closed') void leave(0, null);
    else if (v === 'never-opened') void leave(1, t('bench.main.neverOpened') || 'The window never showed.');
  }, 1_000);
}
