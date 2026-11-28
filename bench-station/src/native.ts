import { spawn, type ChildProcess } from 'node:child_process';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { powershellExe } from './dpapi';
import { errorLogFile } from './paths';
import { redact } from './redact';

/**
 * Obligarth bench station — what a GUI-subsystem process without a console needs from Windows (lot BANC §5.1, ported
 * from the bench of Obliwan): the error log, a native message box, a flashing taskbar entry. The texts travel in
 * environment variables, never on a command line; PowerShell runs hidden.
 */

/** Appends to %LOCALAPPDATA%\Obligarth\bench-error.log, redacted (§5.7). Never throws. */
export function logError(text: string, env: NodeJS.ProcessEnv = process.env): string | null {
  try {
    const path = errorLogFile(env);
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `[${new Date().toISOString()}] ${redact(text)}\n`, 'utf8');
    return path;
  } catch {
    return null;
  }
}

/** A message box owned by an invisible top-most form; resolves when closed. Off Windows: stderr. */
export function showMessageBox(title: string, text: string, kind: 'error' | 'info' = 'error'): Promise<void> {
  if (process.platform !== 'win32') {
    try { process.stderr.write(`\n${title}\n${text}\n`); } catch { /* nowhere */ }
    return Promise.resolve();
  }
  const icon = kind === 'error' ? 'Error' : 'Information';
  const script =
    'Add-Type -AssemblyName System.Windows.Forms; '
    + '$f = New-Object System.Windows.Forms.Form; $f.TopMost = $true; $f.ShowInTaskbar = $false; '
    + '[void][System.Windows.Forms.MessageBox]::Show($f, $env:OBLIGARTH_BENCH_MSG, $env:OBLIGARTH_BENCH_TITLE, '
    + `[System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::${icon}); $f.Dispose()`;
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
        windowsHide: true, stdio: 'ignore',
        env: { ...process.env, OBLIGARTH_BENCH_MSG: redact(text).slice(0, 4000), OBLIGARTH_BENCH_TITLE: title.slice(0, 200) },
      });
    } catch {
      resolve();
      return;
    }
    child.once('error', () => resolve());
    child.once('exit', () => resolve());
  });
}

export const FLASH_SCRIPT =
  '$t = Add-Type -Name FlashW -Namespace ObligarthBench -PassThru -MemberDefinition @"\n'
  + '[StructLayout(LayoutKind.Sequential)] public struct FLASHWINFO { public uint cbSize; public System.IntPtr hwnd; public uint dwFlags; public uint uCount; public uint dwTimeout; }\n'
  + '[DllImport("user32.dll")] public static extern bool FlashWindowEx(ref FLASHWINFO pwfi);\n'
  + '"@\n'
  + 'Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like (\'*\' + $env:OBLIGARTH_BENCH_TITLE + \'*\') } | ForEach-Object {\n'
  + '  $i = New-Object ObligarthBench.FlashW+FLASHWINFO\n'
  + '  $i.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($i); $i.hwnd = $_.MainWindowHandle; $i.dwFlags = 15; $i.uCount = 0; $i.dwTimeout = 0\n'
  + '  [void][ObligarthBench.FlashW]::FlashWindowEx([ref]$i)\n'
  + '}\n';

/** Flash the application window (a card needs the technician). Best effort, never waits. */
export function flashWindow(titlePart: string): void {
  if (process.platform !== 'win32') return;
  try {
    const encoded = Buffer.from(FLASH_SCRIPT, 'utf16le').toString('base64');
    const child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
      windowsHide: true, stdio: 'ignore', env: { ...process.env, OBLIGARTH_BENCH_TITLE: titlePart.slice(0, 200) },
    });
    child.once('error', () => undefined);
    child.unref();
  } catch {
    /* nothing to flash with */
  }
}

/** One hidden PowerShell command, its stdout (asynchronous: the event loop serves the page meanwhile). */
export function powershellOut(command: string, timeoutMs = 30_000, env: NodeJS.ProcessEnv = process.env): Promise<string> {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(`[Console]::OutputEncoding = [Text.Encoding]::UTF8
${command}`, 'utf16le').toString('base64');
    const child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env,
    });
    let out = '';
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.on('data', (c: Buffer) => { out += c.toString('utf8'); });
    child.once('error', (e) => { clearTimeout(timer); reject(e); });
    child.once('close', (code) => { clearTimeout(timer); if (code === 0) resolve(out); else reject(new Error(`powershell exit ${code}`)); });
  });
}
