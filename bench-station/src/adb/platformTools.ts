import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { zipEntries, zipRead } from '../zip';

/**
 * Obligarth bench station — adb without redistributing it (lot BANC §5.5, D12).
 *
 * The station ships no adb (licence of the Android SDK, §3.4 of its terms). On the first launch the page shows the
 * summary and link of the licence; on acceptance the station downloads the VERSIONED archive of platform-tools from
 * Google, checks its size and SHA-256 (pinned below), and takes THREE files out of it (adb.exe, AdbWinApi.dll,
 * AdbWinUsbApi.dll — measured: adb 37.0.1 runs with these three alone) into
 * %LOCALAPPDATA%\Obligarth\platform-tools-<ver>\. Each file's SHA-256 is pinned too, and checked again at every
 * launch. A technician with no access to dl.google.com gives a zip by hand: same checks.
 *
 * VALUES MEASURED on 30/10/2026 on the official archive (repository2-3.xml: platform-tools 37.0.1, Windows archive,
 * size 8044989, SHA-1 e03e78b1d80b396f1c3358e31251cb31740e1110 — equal to the downloaded file's), never invented.
 * A new version of platform-tools is a new release of the station with new values.
 */
export const PLATFORM_TOOLS = {
  version: '37.0.1',
  url: 'https://dl.google.com/android/repository/platform-tools_r37.0.1-win.zip',
  size: 8044989,
  sha256: '45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99',
  files: {
    'adb.exe': 'b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f',
    'AdbWinApi.dll': 'c1d653030b4bde65d3e07e4d0b0979e17be56df1436cdd15528630f27808050d',
    'AdbWinUsbApi.dll': '0710e894d9b40f71a670c13c694079d564c92c1279da382cfe4850983aaebe1b',
  } as Record<string, string>,
  licenseUrl: 'https://developer.android.com/studio/terms',
} as const;

export type PlatformToolsSpec = { version: string; url: string; size: number; sha256: string; files: Record<string, string> };

const sha256 = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

export type ToolsCheck = { ok: true; adb: string } | { ok: false; code: 'adb_missing'; reason: string };

/** The installed copy: every file present and equal to its pinned hash. */
export function checkInstalled(dir: string, spec: PlatformToolsSpec = PLATFORM_TOOLS): ToolsCheck {
  for (const [name, hash] of Object.entries(spec.files)) {
    const p = join(dir, name);
    if (!existsSync(p)) return { ok: false, code: 'adb_missing', reason: `absent:${name}` };
    if (sha256(readFileSync(p)) !== hash) return { ok: false, code: 'adb_missing', reason: `hash:${name}` };
  }
  return { ok: true, adb: join(dir, 'adb.exe') };
}

/** Checks an archive and installs its three files (a temporary folder, then a rename). */
export function installFromArchive(zip: Buffer, dir: string, spec: PlatformToolsSpec = PLATFORM_TOOLS): ToolsCheck {
  if (zip.length !== spec.size) return { ok: false, code: 'adb_missing', reason: 'size' };
  if (sha256(zip) !== spec.sha256) return { ok: false, code: 'adb_missing', reason: 'sha256' };
  const entries = zipEntries(zip);
  const tmp = `${dir}.${process.pid}.part`;
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  try {
    for (const [name, hash] of Object.entries(spec.files)) {
      const e = entries.find((x) => x.name === `platform-tools/${name}`);
      if (!e) return { ok: false, code: 'adb_missing', reason: `missing:${name}` };
      const data = zipRead(zip, e);
      if (sha256(data) !== hash) return { ok: false, code: 'adb_missing', reason: `hash:${name}` };
      writeFileSync(join(tmp, name), data, { flag: 'wx' });
    }
    writeFileSync(join(tmp, 'hashes.json'), `${JSON.stringify({ version: spec.version, files: spec.files }, null, 2)}\n`);
    rmSync(dir, { recursive: true, force: true });
    renameSync(tmp, dir);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  return checkInstalled(dir, spec);
}

/** The proxy for an https URL: HTTPS_PROXY / https_proxy (NO_PROXY honoured for the host). */
export function proxyFor(target: URL, env: NodeJS.ProcessEnv = process.env): URL | null {
  const raw = env.HTTPS_PROXY ?? env.https_proxy ?? '';
  if (!raw.trim()) return null;
  const no = (env.NO_PROXY ?? env.no_proxy ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const host = target.hostname.toLowerCase();
  if (no.some((n) => n === '*' || host === n.replace(/^\./, '') || host.endsWith(n.startsWith('.') ? n : `.${n}`))) return null;
  try {
    const u = new URL(raw.includes('://') ? raw : `http://${raw}`);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u : null;
  } catch {
    return null;
  }
}

/** GET an https URL into memory (bounded), through HTTPS_PROXY when set (CONNECT), following at most 3 https
 *  redirects (the hash is pinned: where the bytes come from does not decide whether they are used). */
export function download(url: string, maxBytes: number, env: NodeJS.ProcessEnv = process.env, redirects = 3): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== 'https:') { reject(new Error('https only')); return; }
    const onResponse = (res: import('node:http').IncomingMessage): void => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400 && res.headers.location && redirects > 0) {
        res.resume();
        download(new URL(res.headers.location, url).toString(), maxBytes, env, redirects - 1).then(resolve, reject);
        return;
      }
      if (status !== 200) { res.resume(); reject(new Error(`HTTP ${status}`)); return; }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (size > maxBytes) { res.destroy(new Error('too large')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    };
    const proxy = proxyFor(target, env);
    const timeout = 300_000;
    if (!proxy) {
      const req = httpsRequest(target, { method: 'GET', timeout }, onResponse);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.end();
      return;
    }
    const auth = proxy.username ? { 'proxy-authorization': `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString('base64')}` } : {};
    const connectReq = httpRequest({
      host: proxy.hostname, port: Number(proxy.port || 80), method: 'CONNECT', path: `${target.hostname}:${target.port || 443}`,
      headers: { host: `${target.hostname}:${target.port || 443}`, ...auth }, timeout,
    });
    connectReq.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); reject(new Error(`proxy ${res.statusCode}`)); return; }
      const tls = tlsConnect({ socket, servername: target.hostname });
      const req = httpsRequest(target, { method: 'GET', createConnection: () => tls, timeout }, onResponse);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.end();
    });
    connectReq.on('timeout', () => connectReq.destroy(new Error('timeout')));
    connectReq.on('error', reject);
    connectReq.end();
  });
}

/** Download and install (after the technician accepted the licence). */
export async function downloadAndInstall(dir: string, spec: PlatformToolsSpec = PLATFORM_TOOLS, fetchArchive: (url: string) => Promise<Buffer> = (u) => download(u, spec.size + 1024)): Promise<ToolsCheck> {
  let zip: Buffer;
  try {
    zip = await fetchArchive(spec.url);
  } catch (err) {
    return { ok: false, code: 'adb_missing', reason: `download:${err instanceof Error ? err.message.slice(0, 60) : 'error'}` };
  }
  return installFromArchive(zip, dir, spec);
}

export type KeyLocation = 'station' | 'profile' | 'none';

/**
 * Where adb keeps its key (§5.5, hypothesis H5). The station's own home is tried first (`adb-home\.android\adbkey`);
 * MEASURED on 30/10/2026 with adb 37.0.1 for Windows: adb reads none of ANDROID_USER_HOME, ANDROID_SDK_HOME,
 * USERPROFILE or HOME and keeps its key in the Windows profile (`%USERPROFILE%\.android`, from the user's token). The
 * page then says so: the key is the user's, shared with any other adb of this Windows account, and a renewal of the
 * station cannot regenerate it without touching the other tools — the technician is told instead.
 */
export function keyLocation(adbHome: string, profile: string = homedir()): KeyLocation {
  if (existsSync(join(adbHome, '.android', 'adbkey'))) return 'station';
  if (existsSync(join(profile, '.android', 'adbkey'))) return 'profile';
  return 'none';
}

/** The renewal of a station regenerates ITS key (§3.3 step 4): the station's own folder only, never the profile's. */
export function forgetStationKey(adbHome: string): void {
  rmSync(join(adbHome, '.android'), { recursive: true, force: true });
  mkdirSync(join(adbHome, '.android'), { recursive: true });
}
