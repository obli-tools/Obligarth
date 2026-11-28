import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execPath } from 'node:process';
import { DEFAULT_ADB_PORT } from './adb/runner';

/**
 * Obligarth bench station — its settings (lot BANC §5.1, §5.5).
 *
 * The MSI writes `obligarth-bench.ini` beside the executable, once, at install (`OBLIGARTHURL`):
 *   [server] url=https://obligarth.example.test
 *   [adb]    port=5137            (optional)
 * Precedence of the URL:
 *   1. the .ini (the installer's, the administrator's: it is never changed from the page);
 *   2. the last URL whose platform ANSWERED for this user's station (bench-station.json);
 *   3. nothing: the page asks for it, with no invented default.
 * `OBLIGARTH_URL` is read ONLY by a development build (`build.mjs --dev`, `__BENCH_DEV__`), between 1 and 2; a
 * production build ignores it (§5.10 crit. 6): an environment variable must not be able to point an installed station
 * at a server of somebody's choosing.
 * Nothing here is a secret: the .ini holds a URL and a port.
 */

declare const __BENCH_DEV__: boolean | undefined;

/** True only in a development build (or when the sources run under tsx for the harness). */
export function isDevBuild(): boolean {
  return typeof __BENCH_DEV__ === 'boolean' ? __BENCH_DEV__ : true;
}

export type UrlSource = 'installer' | 'environment' | 'station' | 'typed' | null;

export interface BenchConfig {
  baseUrl: string | null;
  source: UrlSource;
  adbPort: number;
}

export function iniPath(exe: string = execPath): string {
  return join(dirname(exe), 'obligarth-bench.ini');
}

/** A tiny INI reader: `[section]` and `key = value`, keys as `section.key`. Absent or unreadable: empty. */
export function readIni(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  let text: string;
  try { text = readFileSync(path, 'utf8'); } catch { return out; }
  let section = '';
  for (const rawLine of text.replace(/^﻿/, '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('#')) continue;
    const s = /^\[([^\]]+)\]$/.exec(line);
    if (s) { section = s[1].trim().toLowerCase(); continue; }
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    out[`${section}.${line.slice(0, eq).trim().toLowerCase()}`] = line.slice(eq + 1).trim();
  }
  return out;
}

/** A loopback host (localhost, 127.0.0.0/8, ::1): the only one a production build reaches over plain http. */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '::1' || /^127(\.\d{1,3}){3}$/.test(h);
}

/** The protocol of a station URL: https; plain http only in a development build or toward a loopback address, so that
 *  the station's token and the enrollment configurations never travel in clear on a network. */
export function protocolAllowed(u: URL, dev: boolean = isDevBuild()): boolean {
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && (dev || isLoopbackHost(u.hostname));
}

/** `https://host[:port][/path]`, no trailing slash, no credentials, no query; empty is absent. Plain http only as
 *  protocolAllowed admits it (the .ini, a typed URL and the last URL that answered alike). */
export function normaliseBenchUrl(value: string | undefined | null, dev: boolean = isDevBuild()): string | null {
  const v = (value ?? '').trim().replace(/\/+$/, '');
  if (!v) return null;
  let u: URL;
  try { u = new URL(v); } catch { return null; }
  if (!protocolAllowed(u, dev)) return null;
  if (u.username || u.password || u.search || u.hash) return null;
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

export function adbPortOf(ini: Record<string, string>): number {
  const p = Number.parseInt(ini['adb.port'] ?? '', 10);
  return Number.isInteger(p) && p > 1024 && p < 65536 && p !== 5037 ? p : DEFAULT_ADB_PORT;
}

export function loadBenchConfig(opts: { lastAnsweredUrl?: string | null; ini?: Record<string, string>; env?: NodeJS.ProcessEnv; dev?: boolean } = {}): BenchConfig {
  const ini = opts.ini ?? readIni(iniPath());
  const env = opts.env ?? process.env;
  const dev = opts.dev ?? isDevBuild();
  const adbPort = adbPortOf(ini);
  const fromIni = normaliseBenchUrl(ini['server.url'], dev);
  if (fromIni) return { baseUrl: fromIni, source: 'installer', adbPort };
  if (dev) {
    const fromEnv = normaliseBenchUrl(env.OBLIGARTH_URL, dev);
    if (fromEnv) return { baseUrl: fromEnv, source: 'environment', adbPort };
  }
  const fromStation = normaliseBenchUrl(opts.lastAnsweredUrl ?? null, dev);
  if (fromStation) return { baseUrl: fromStation, source: 'station', adbPort };
  return { baseUrl: null, source: null, adbPort };
}
