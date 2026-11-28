import { spawn } from 'node:child_process';
import { join } from 'node:path';

/**
 * Obligarth bench station — DPAPI protection (CurrentUser) of the station token and of the history (lot BANC §4,
 * §5.7).
 *
 * A Node SEA has no native module, so the protection runs in a HIDDEN PowerShell child
 * (`[Security.Cryptography.ProtectedData]`, scope CurrentUser, an entropy of its own): the data goes in base64 on its
 * STANDARD INPUT, never as an argument nor in the environment, and comes back on its standard output. The script is
 * passed with -EncodedCommand (no quoting by anyone). Data protected so is readable only by the same Windows user on
 * the same computer.
 *
 * `Protector` is an interface so that the harness can run off Windows (`PlainTestProtector`, never in a build).
 */
export interface Protector {
  readonly kind: string;
  protect(plain: Buffer): Promise<Buffer>;
  unprotect(blob: Buffer): Promise<Buffer>;
}

const SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -AssemblyName System.Security',
  '$in = [Console]::In.ReadToEnd().Trim()',
  '$bytes = [Convert]::FromBase64String($in)',
  "$entropy = [Text.Encoding]::UTF8.GetBytes('Obligarth.Bench.v1')",
  '$scope = [Security.Cryptography.DataProtectionScope]::CurrentUser',
  "if ($env:OBLIGARTH_DPAPI_MODE -eq 'protect') { $out = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, $scope) }",
  "elseif ($env:OBLIGARTH_DPAPI_MODE -eq 'unprotect') { $out = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, $scope) }",
  'else { exit 3 }',
  '[Console]::Out.Write([Convert]::ToBase64String($out))',
].join('\n');

export function powershellExe(env: NodeJS.ProcessEnv = process.env): string {
  const root = (env.SystemRoot ?? env.windir ?? 'C:\\Windows').trim();
  return join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

function run(mode: 'protect' | 'unprotect', data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(SCRIPT, 'utf16le').toString('base64');
    const child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
      windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, OBLIGARTH_DPAPI_MODE: mode },
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill(), 30_000);
    child.stdout.on('data', (c: Buffer) => { out += c.toString('ascii'); });
    child.stderr.on('data', (c: Buffer) => { err += c.toString('utf8'); });
    child.once('error', (e) => { clearTimeout(timer); reject(e); });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) { reject(new Error(`DPAPI ${mode} failed (${code}): ${err.replace(/\s+/g, ' ').slice(0, 160)}`)); return; }
      try {
        resolve(Buffer.from(out.trim(), 'base64'));
      } catch (e) {
        reject(e);
      }
    });
    child.stdin.end(`${data.toString('base64')}\n`);
  });
}

export const dpapiProtector: Protector = {
  kind: 'dpapi-user',
  protect: (plain) => run('protect', plain),
  unprotect: (blob) => run('unprotect', blob),
};

/** For the harness only: no protection at all, and says so in the file. */
export const plainTestProtector: Protector = {
  kind: 'plain-test',
  protect: async (plain) => Buffer.from(plain),
  unprotect: async (blob) => Buffer.from(blob),
};

/** The protector of this platform: DPAPI on Windows, nothing elsewhere (development off Windows only). */
export function defaultProtector(): Protector {
  return process.platform === 'win32' ? dpapiProtector : plainTestProtector;
}

/** The envelope written to disk. */
export interface ProtectedFile { version: 1; protection: string; data: string }

export async function sealJson(p: Protector, value: unknown): Promise<string> {
  const blob = await p.protect(Buffer.from(JSON.stringify(value), 'utf8'));
  const env: ProtectedFile = { version: 1, protection: p.kind, data: blob.toString('base64') };
  return `${JSON.stringify(env)}\n`;
}

/** Throws when the file is not an envelope of this protector or cannot be opened (another user, another PC). */
export async function openJson(p: Protector, text: string): Promise<unknown> {
  const env = JSON.parse(text) as Partial<ProtectedFile>;
  if (env?.version !== 1 || typeof env.data !== 'string' || env.protection !== p.kind) throw new Error('not a protected file of this station');
  const plain = await p.unprotect(Buffer.from(env.data, 'base64'));
  return JSON.parse(plain.toString('utf8'));
}
