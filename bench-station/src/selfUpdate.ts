import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { powershellOut } from './native';
import { codeSigningAdmitted, CODE_SIGNING_PINS } from './pins';

/**
 * Obligarth bench station — its own update (lot BANC §5.8), ported from the bench of Obliwan (itself from Obliance's
 * agent): `GET /api/bench/version` at start, every 20 minutes and on a change of URL (8 s, never an exception); the
 * file name is a CONSTANT (`obligarth-bench.msi`, never one the server names); the download (300 s) goes into a fresh
 * `mkdtemp` directory with `wx`; Content-Length, then SHA-256 (no hash: refused).
 *
 * ┌─ THE SIGNATURE IS THE ANCHOR, AND IT IS PINNED ──────────────────────────┐
 * │ A compromised server serves a malicious MSI and its matching hash just  │
 * │ as easily: the hash proves the download, the signature proves WHO built  │
 * │ it. The MSI must be Authenticode `Valid` AND signed by a certificate     │
 * │ whose issuer and SHA-256 are in pins.ts (current + next) — Obliwan       │
 * │ compared the subject with the running exe's; here the certificate is    │
 * │ pinned, and the running exe must ITSELF be validly signed by a pinned    │
 * │ certificate (an unsigned exe is a development build: no update).        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The installer starts ONLY on the technician's click (« Mettre à jour »), never by itself, and never while a card is
 * acting (gui.ts): `msiexec /i … /qb+ /norestart /l*v <log> [OBLIGARTHURL=…]`, detached; the station closes 1.5 s
 * later.
 */
export const BENCH_MSI = 'obligarth-bench.msi';

export interface UpdateCheck {
  available: string | null;
  current: string;
  sha256: string | null;
  file: typeof BENCH_MSI;
}

export function isNewer(candidate: string, current: string): boolean {
  const parse = (v: string) => v.trim().split('.').map((n) => Number.parseInt(n, 10) || 0);
  const a = parse(candidate);
  const b = parse(current);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return false;
}

export async function checkForUpdate(baseUrl: string | null, current: string, fetchImpl: typeof fetch = fetch): Promise<UpdateCheck> {
  const none: UpdateCheck = { available: null, current, sha256: null, file: BENCH_MSI };
  if (!baseUrl) return none;
  try {
    const res = await fetchImpl(`${baseUrl.replace(/\/+$/, '')}/api/bench/version`, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
    if (!res.ok) return none;
    const body = (await res.json()) as { data?: { version?: string; available?: boolean; sha256?: string | null; file?: string } };
    const d = body.data;
    if (!d?.version || d.available !== true) return none;
    if (d.file !== undefined && d.file !== BENCH_MSI) return none;
    const sha = typeof d.sha256 === 'string' && /^[0-9a-f]{64}$/.test(d.sha256) ? d.sha256 : null;
    return { available: isNewer(d.version, current) ? d.version : null, current, sha256: sha, file: BENCH_MSI };
  } catch {
    return none;
  }
}

export interface SignatureReading { status: string; issuer: string; sha256: string }

/** Get-AuthenticodeSignature of a file: status, issuer, SHA-256 of the signing certificate. The path travels in an
 *  environment variable, never in the script. */
export async function readSignature(file: string): Promise<SignatureReading | null> {
  try {
    const out = await powershellOut(
      "$s = Get-AuthenticodeSignature -LiteralPath $env:OBLIGARTH_SIG_FILE; "
      + "$c = $s.SignerCertificate; if ($c -eq $null) { '' + $s.Status + '||'; exit 0 }; "
      + "'' + $s.Status + '|' + $c.Issuer + '|' + $c.GetCertHashString('SHA256')",
      30_000,
      { ...process.env, OBLIGARTH_SIG_FILE: file },
    );
    const [status, issuer, sha256] = out.trim().split('|');
    return { status: status ?? '', issuer: issuer ?? '', sha256: (sha256 ?? '').toUpperCase() };
  } catch {
    return null;
  }
}

export type SignatureVerdict = { ok: true } | { ok: false; reason: 'running_unsigned' | 'invalid' | 'not_pinned' | 'unreadable' };

/** The rule, pure (tested): the running exe validly signed by a pinned certificate, the MSI too. */
export function judgeSignatures(running: SignatureReading | null, msi: SignatureReading | null, pins = CODE_SIGNING_PINS): SignatureVerdict {
  if (!running || running.status !== 'Valid' || !codeSigningAdmitted(running.issuer, running.sha256, pins)) return { ok: false, reason: 'running_unsigned' };
  if (!msi) return { ok: false, reason: 'unreadable' };
  if (msi.status !== 'Valid') return { ok: false, reason: 'invalid' };
  if (!codeSigningAdmitted(msi.issuer, msi.sha256, pins)) return { ok: false, reason: 'not_pinned' };
  return { ok: true };
}

export function msiexecArguments(msi: string, logPath: string, installerUrl: string | null): string[] {
  const url = installerUrl && /^https?:\/\/[^\s"]+$/i.test(installerUrl) ? installerUrl : null;
  return ['/i', msi, '/qb+', '/norestart', '/l*v', logPath, ...(url ? [`OBLIGARTHURL=${url}`] : [])];
}

export function launchInstaller(args: string[], command = 'msiexec'): Promise<{ launched: true } | { launched: false; reason: string }> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, { detached: true, stdio: 'ignore' });
    } catch (err) {
      resolve({ launched: false, reason: err instanceof Error ? err.message : String(err) });
      return;
    }
    child.once('error', (err) => resolve({ launched: false, reason: err.message }));
    child.once('spawn', () => { child.unref(); resolve({ launched: true }); });
  });
}

export type ApplyResult = { launched: true; code: 'update_started'; logPath: string } | { launched: false; code: string };

export interface ApplyDeps {
  fetchImpl?: typeof fetch;
  readSignature?: (file: string) => Promise<SignatureReading | null>;
  launch?: (args: string[]) => Promise<{ launched: true } | { launched: false; reason: string }>;
}

/** Download, verify (length, SHA-256, pinned signature), hand to msiexec. Codes for the page: `update.<code>`. */
export async function applyUpdate(baseUrl: string, check: UpdateCheck, exePath: string, opts: { installerUrl?: string | null } & ApplyDeps = {}): Promise<ApplyResult> {
  if (check.file !== BENCH_MSI) return { launched: false, code: 'refused_file' };
  const f = opts.fetchImpl ?? fetch;
  let bytes: Buffer;
  let headerHash: string | null;
  try {
    const res = await f(`${baseUrl.replace(/\/+$/, '')}/api/bench/download/${BENCH_MSI}`, { redirect: 'manual', signal: AbortSignal.timeout(300_000) });
    if (!res.ok) return { launched: false, code: 'download_refused' };
    headerHash = res.headers.get('x-content-sha256');
    const declared = Number(res.headers.get('content-length') ?? '0');
    bytes = Buffer.from(await res.arrayBuffer());
    if (declared > 0 && bytes.length !== declared) return { launched: false, code: 'truncated' };
  } catch {
    return { launched: false, code: 'download_failed' };
  }
  const expected = (check.sha256 ?? headerHash ?? '').toLowerCase();
  if (!expected) return { launched: false, code: 'no_hash' };
  if (createHash('sha256').update(bytes).digest('hex') !== expected) return { launched: false, code: 'hash_mismatch' };
  let dir: string;
  let msi: string;
  try {
    dir = mkdtempSync(join(tmpdir(), 'obligarth-bench-update-'));
    msi = join(dir, BENCH_MSI);
    writeFileSync(msi, bytes, { flag: 'wx' });
  } catch {
    return { launched: false, code: 'stage_failed' };
  }
  const read = opts.readSignature ?? readSignature;
  const verdict = judgeSignatures(await read(exePath), await read(msi));
  if (!verdict.ok) {
    rmSync(dir, { recursive: true, force: true });
    return { launched: false, code: `signature_${verdict.reason}` };
  }
  const logPath = join(dir, 'install.log');
  const started = await (opts.launch ?? launchInstaller)(msiexecArguments(msi, logPath, opts.installerUrl ?? null));
  if (!started.launched) {
    rmSync(dir, { recursive: true, force: true });
    return { launched: false, code: 'msiexec_failed' };
  }
  return { launched: true, code: 'update_started', logPath };
}

declare const __BENCH_VERSION__: string | undefined;

export function currentVersion(): string {
  return typeof __BENCH_VERSION__ === 'string' ? __BENCH_VERSION__ : '0.0.0';
}
