import { argv, exit } from 'node:process';
import { writeFileSync } from 'node:fs';
import { t } from './i18n';
import { logError, showMessageBox } from './native';

/**
 * Obligarth bench station — the entry point of a WINDOWS GUI application (lot BANC §5.1, ported from Obliwan).
 *
 * build.mjs patches the executable's PE header to the GUI subsystem: no console, so every failure ends in a native
 * message box and a line in %LOCALAPPDATA%\Obligarth\bench-error.log. Two switches, neither opens a window:
 *   --version            the version on stdout (seen through a pipe);
 *   --self-test <file>   writes to stdout and stderr (which must not crash without a console), then "ok <version>"
 *                        into <file>. build.mjs runs both on the patched copy before anything is signed.
 */

declare const __BENCH_VERSION__: string | undefined;
const VERSION = typeof __BENCH_VERSION__ === 'string' ? __BENCH_VERSION__ : '0.0.0';
const TITLE = 'Obligarth Bench';

let failing = false;
function fatal(what: string, err: unknown): void {
  if (failing) return;
  failing = true;
  const detail = err instanceof Error ? err.message : String(err);
  const log = logError(`${what}: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  void showMessageBox(TITLE, `${what}\n\n${detail}\n\nObligarth Bench v${VERSION}.${log ? `\n${t('bench.main.logAt', { path: log }) || log}` : ''}`)
    .then(() => exit(1));
}

process.on('uncaughtException', (err: unknown) => fatal(t('bench.main.crashed') || 'The application stopped unexpectedly.', err));
process.on('unhandledRejection', (reason: unknown) => fatal(t('bench.main.unhandled') || 'An operation failed without being handled.', reason));

async function start(): Promise<void> {
  if (argv.includes('--version')) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  const selfTest = argv.indexOf('--self-test');
  if (selfTest >= 0) {
    const target = argv[selfTest + 1];
    console.log('self-test: stdout');
    console.error('self-test: stderr');
    process.stdout.write('self-test: write\n');
    if (target) writeFileSync(target, `ok ${VERSION}\n`, 'utf8');
    return;
  }
  const { runGui } = await import('./run');
  await runGui();
}

start().catch((err: unknown) => fatal(t('bench.main.startFailed') || 'The application could not start.', err));
