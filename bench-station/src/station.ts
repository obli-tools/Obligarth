import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { hostname, userInfo } from 'node:os';
import { dirname } from 'node:path';
import { ServerClock } from './clock';
import { protocolAllowed } from './config';
import { openJson, sealJson, type Protector } from './dpapi';

/**
 * Obligarth bench station — this workstation's credential towards the platform (lot BANC §4).
 *
 * The contract, read off server/src/bench/api.routes.ts and guard.ts (T1):
 *   POST /api/bench/stations/register  {name, hostname, token, stationVersion}  public, 20/h per address;
 *        201 created / 200 known: {stationId (uuid), status, verificationCode}; 429 `too_many_pending`.
 *   GET  /api/bench/stations/me        Authorization: Bench <token>
 *        200 {stationId, status: pending|approved|suspended, name, verificationCode}; `session` (a server of before
 *        28/11/2026, or the marker a newer one keeps for the stations 1.0.3) is ignored: no bench session any more.
 *        401 unknown token (⇒ register); 403 `station_revoked`, `station_ip_refused`, `station_refused`.
 *   `x-bench-version: <version>` on every call (the server keeps the station's version).
 *
 * ┌─ THE TOKEN ──────────────────────────────────────────────────────────────┐
 * │ randomBytes(32) hex, drawn HERE and written to disk BEFORE it is          │
 * │ registered (a registration whose answer is lost leaves a token this      │
 * │ station still holds). Filed by normalised URL: a token is never sent to  │
 * │ another instance than the one it was registered at. The file is          │
 * │ %LOCALAPPDATA%\Obligarth\bench-station.json — not %APPDATA%, which may   │
 * │ roam — and its content is protected by DPAPI (CurrentUser): another      │
 * │ account, or the same file copied to another PC, cannot read it. An       │
 * │ unreadable file is set aside (`.illisible-<ts>`), never overwritten.     │
 * │ It is the station's only durable secret: once the station is approved   │
 * │ (in the console, with a second factor), it enrolls within its targets   │
 * │ by itself (28/11/2026: no bench session); suspend or revoke it to stop. │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * No request carrying the token FOLLOWS a redirect (`redirect: 'manual'`): a 3xx is its own answer (`redirected`).
 */

const STATION_TIMEOUT_MS = 10_000;
const ME_PATH = '/api/bench/stations/me';
const REGISTER_PATH = '/api/bench/stations/register';

export const STATION_POLL_PENDING_MS = 5_000;
export const STATION_POLL_APPROVED_MS = 60_000;
export const STATION_POLL_UNREACHABLE_MS = 15_000;

export function stationUrlKey(baseUrl: string): string {
  const u = new URL(baseUrl.trim());
  if (!protocolAllowed(u)) throw new Error('not an https URL (plain http: development build or loopback only)');
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

interface StationRecord {
  url: string;
  token: string;
  name: string;
  hostname: string;
  createdAt: string;
  answeredAt?: string;
}

const TOKEN_RE = /^[0-9a-f]{64,256}$/;

function isRecord(v: unknown): v is StationRecord {
  const r = v as Partial<StationRecord> | null;
  return !!r && typeof r.url === 'string' && typeof r.token === 'string' && TOKEN_RE.test(r.token)
    && typeof r.name === 'string' && typeof r.hostname === 'string' && typeof r.createdAt === 'string';
}

export class StationFileError extends Error {
  constructor(message: string) { super(message); this.name = 'StationFileError'; }
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;

/** "BANC-01 (technicien)": the machine and the Windows account (the file is per user), at most 100 characters. */
export function defaultStationName(): { name: string; hostname: string } {
  const host = hostname().replace(CONTROL, '').trim();
  let user = '';
  try { user = userInfo().username.replace(CONTROL, '').trim(); } catch { /* a service context */ }
  const name = (host && user ? `${host} (${user})` : host || user || 'Bench station').slice(0, 100);
  return { name, hostname: host.slice(0, 255) };
}

/** The station file, DPAPI-protected, cached by (size, mtime): one PowerShell per change, not per request. */
export class StationStore {
  private cache: { key: string; stations: StationRecord[] } | null = null;

  constructor(readonly file: string, private readonly protector: Protector) {}

  private fileKey(): string | null {
    try { const s = statSync(this.file); return `${s.size}|${s.mtimeMs}`; } catch { return null; }
  }

  async read(): Promise<StationRecord[]> {
    const key = this.fileKey();
    if (key === null) return [];
    if (this.cache && this.cache.key === key) return this.cache.stations;
    let text: string;
    try {
      text = readFileSync(this.file, 'utf8');
    } catch (err) {
      throw new StationFileError(`station file unreadable: ${(err as Error).message}`);
    }
    let stations: StationRecord[];
    try {
      const v = await openJson(this.protector, text) as { stations?: unknown };
      stations = Array.isArray(v?.stations) ? v.stations.filter(isRecord) : [];
    } catch {
      const aside = `${this.file}.illisible-${Date.now()}`;
      try { renameSync(this.file, aside); } catch (err) {
        throw new StationFileError(`station file unreadable and could not be set aside: ${(err as Error).message}`);
      }
      this.cache = null;
      return [];
    }
    this.cache = { key, stations };
    return stations;
  }

  async write(stations: StationRecord[]): Promise<void> {
    try {
      mkdirSync(dirname(this.file), { recursive: true });
      const sealed = await sealJson(this.protector, { version: 1, stations });
      const tmp = `${this.file}.${process.pid}.tmp`;
      writeFileSync(tmp, sealed, { encoding: 'utf8', mode: 0o600 });
      renameSync(tmp, this.file);
      const key = this.fileKey();
      this.cache = key ? { key, stations } : null;
    } catch (err) {
      throw new StationFileError(`station file could not be written: ${(err as Error).message}`);
    }
  }

  /** The URL whose platform answered most recently, or null (never throws). */
  async lastAnsweredUrl(): Promise<string | null> {
    try {
      const answered = (await this.read()).filter((s) => typeof s.answeredAt === 'string');
      if (answered.length === 0) return null;
      return answered.reduce((a, b) => (Date.parse(b.answeredAt!) > Date.parse(a.answeredAt!) ? b : a)).url;
    } catch {
      return null;
    }
  }
}

export type StationStatus =
  | { state: 'pending' | 'approved' | 'suspended'; stationId: string; name: string; verificationCode: string | null }
  | { state: 'revoked'; code: string }
  /** Network, DNS, timeout: nothing is known. */
  | { state: 'unreachable'; code: 'server_unreachable'; detail: string }
  /** A 3xx, not followed. */
  | { state: 'redirected'; code: 'redirected'; status: number; location: string | null; suggestedUrl: string | null }
  /** The station file could not be read or written: nothing was sent. */
  | { state: 'localError'; code: 'internal'; detail: string }
  /** An answer outside the contract, or a refusal (403 station_ip_refused, 429…). */
  | { state: 'refused'; code: string; status: number };

export function redirectedStatus(res: Response, requested: string, apiPath: string): StationStatus | null {
  if (res.status < 300 || res.status > 399) return null;
  const raw = res.headers.get('location');
  let location: string | null = null;
  let suggestedUrl: string | null = null;
  if (raw) {
    try {
      const u = new URL(raw, requested);
      location = u.toString();
      if ((u.protocol === 'http:' || u.protocol === 'https:') && u.pathname.endsWith(apiPath)) {
        suggestedUrl = `${u.protocol}//${u.host}${u.pathname.slice(0, -apiPath.length).replace(/\/+$/, '')}`;
      }
    } catch {
      location = raw.slice(0, 300);
    }
  }
  return { state: 'redirected', code: 'redirected', status: res.status, location, suggestedUrl };
}

interface Answer { status: number; data: Record<string, unknown> | null; code: string | null }

async function readAnswer(res: Response): Promise<Answer> {
  const text = await res.text();
  let body: { data?: unknown; code?: unknown } | null = null;
  try { body = JSON.parse(text) as { data?: unknown; code?: unknown }; } catch { body = null; }
  const data = body && typeof body.data === 'object' && body.data !== null ? (body.data as Record<string, unknown>) : null;
  const code = body && typeof body.code === 'string' && /^[a-z_]{1,48}$/.test(body.code) ? body.code : null;
  return { status: res.status, data, code };
}

function unreachable(err: unknown): StationStatus {
  const e = err as Error & { cause?: { code?: string } };
  const detail = e?.name === 'TimeoutError' ? 'timeout' : e?.cause?.code ?? e?.name ?? 'error';
  return { state: 'unreachable', code: 'server_unreachable', detail: String(detail).slice(0, 60) };
}

function knownStation(data: Record<string, unknown> | null): StationStatus | null {
  if (!data) return null;
  const { stationId, status, name, verificationCode } = data;
  if (typeof stationId !== 'string' || !/^[0-9a-f-]{36}$/i.test(stationId)) return null;
  if (status !== 'pending' && status !== 'approved' && status !== 'suspended') return null;
  return {
    state: status, stationId, name: typeof name === 'string' ? name : '',
    verificationCode: typeof verificationCode === 'string' && /^[0-9A-F]{4}-[0-9A-F]{4}$/.test(verificationCode) ? verificationCode : null,
  };
}

export interface BenchStationOptions {
  store: StationStore;
  version: string;
  clock?: ServerClock;
  fetchImpl?: typeof fetch;
  /** Called when the station draws a new token (renewal): the adb key is regenerated (§3.3 step 4). */
  onRenew?: () => Promise<void> | void;
}

/** This workstation, as known to ONE instance. */
export class BenchStation {
  readonly baseUrl: string;
  private readonly f: typeof fetch;
  readonly clock: ServerClock;

  private constructor(baseUrl: string, private readonly o: BenchStationOptions) {
    this.baseUrl = baseUrl;
    this.f = o.fetchImpl ?? fetch;
    this.clock = o.clock ?? new ServerClock();
  }

  static forUrl(baseUrl: string, o: BenchStationOptions): BenchStation {
    return new BenchStation(stationUrlKey(baseUrl), o);
  }

  private async record(): Promise<StationRecord> {
    const all = await this.o.store.read();
    const existing = all.find((s) => s.url === this.baseUrl);
    if (existing) return existing;
    const { name, hostname: host } = defaultStationName();
    const fresh: StationRecord = { url: this.baseUrl, token: randomBytes(32).toString('hex'), name, hostname: host, createdAt: new Date().toISOString() };
    await this.o.store.write([...all, fresh]);
    return fresh;
  }

  /** `{ authorization, x-bench-version }` for THIS station's URL only. */
  async authHeaders(): Promise<Record<string, string>> {
    const rec = await this.record();
    return { authorization: `Bench ${rec.token}`, 'x-bench-version': this.o.version };
  }

  private async me(rec: StationRecord): Promise<StationStatus | 'unknown'> {
    const url = `${this.baseUrl}${ME_PATH}`;
    let answer: Answer;
    try {
      const res = await this.f(url, {
        headers: { authorization: `Bench ${rec.token}`, 'x-bench-version': this.o.version, 'cache-control': 'no-store' },
        redirect: 'manual',
        signal: AbortSignal.timeout(STATION_TIMEOUT_MS),
      });
      this.clock.observe(res.headers.get('date'));
      const moved = redirectedStatus(res, url, ME_PATH);
      if (moved) { await res.text().catch(() => ''); return moved; }
      answer = await readAnswer(res);
    } catch (err) {
      return unreachable(err);
    }
    if (answer.status === 401) return 'unknown';
    if (answer.status === 403) {
      if (answer.code === 'station_revoked') return { state: 'revoked', code: 'station_revoked' };
      return { state: 'refused', code: answer.code ?? 'station_refused', status: 403 };
    }
    const known = answer.status === 200 ? knownStation(answer.data) : null;
    if (known) return known;
    return { state: 'refused', code: answer.code ?? 'internal', status: answer.status };
  }

  private async register(rec: StationRecord): Promise<StationStatus | null> {
    const url = `${this.baseUrl}${REGISTER_PATH}`;
    let answer: Answer;
    try {
      const res = await this.f(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-bench-version': this.o.version },
        body: JSON.stringify({ name: rec.name, hostname: rec.hostname, token: rec.token, stationVersion: this.o.version }),
        redirect: 'manual',
        signal: AbortSignal.timeout(STATION_TIMEOUT_MS),
      });
      this.clock.observe(res.headers.get('date'));
      const moved = redirectedStatus(res, url, REGISTER_PATH);
      if (moved) { await res.text().catch(() => ''); return moved; }
      answer = await readAnswer(res);
    } catch (err) {
      return unreachable(err);
    }
    if (answer.status === 200 || answer.status === 201) {
      if (answer.data?.status === 'revoked') return { state: 'revoked', code: 'station_revoked' };
      return null;
    }
    return { state: 'refused', code: answer.code ?? 'station_refused', status: answer.status };
  }

  /** Where this workstation stands; registers when needed. Never throws. */
  async status(): Promise<StationStatus> {
    let rec: StationRecord;
    try {
      rec = await this.record();
    } catch (err) {
      return { state: 'localError', code: 'internal', detail: err instanceof Error ? err.message.slice(0, 200) : 'error' };
    }
    const first = await this.me(rec);
    let answer: StationStatus;
    if (first !== 'unknown') {
      answer = first;
    } else {
      const registered = await this.register(rec);
      if (registered) answer = registered;
      else {
        const second = await this.me(rec);
        answer = second !== 'unknown' ? second : { state: 'refused', code: 'station_refused', status: 401 };
      }
    }
    if (['pending', 'approved', 'suspended', 'revoked'].includes(answer.state)) await this.markAnswered(rec);
    return answer;
  }

  private async markAnswered(rec: StationRecord): Promise<void> {
    if (rec.answeredAt) return;
    try {
      const at = new Date().toISOString();
      const all = await this.o.store.read();
      await this.o.store.write(all.map((s) => (s.url === rec.url && s.token === rec.token ? { ...s, answeredAt: at } : s)));
    } catch { /* asked again next launch */ }
  }

  /** After a revocation only: a new token, a new pending station, a new adb key. */
  async renew(): Promise<StationStatus> {
    const current = await this.status();
    if (current.state !== 'revoked') return current;
    try {
      const all = await this.o.store.read();
      await this.o.store.write(all.filter((s) => s.url !== this.baseUrl));
    } catch (err) {
      return { state: 'localError', code: 'internal', detail: err instanceof Error ? err.message.slice(0, 200) : 'error' };
    }
    try { await this.o.onRenew?.(); } catch { /* the key is checked again at the next start */ }
    return this.status();
  }
}
