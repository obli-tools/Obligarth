import { randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { execPath } from 'node:process';
import {
  judgeConflict, readEnvironment, readSamsungDriver, readSamsungUsb, stopProcesses, usbUnseenByAdb, type ConflictVerdict, type EnvironmentReading,
} from './adb/conflict';
import { type AdbDevice } from './adb/parse';
import { checkInstalled, downloadAndInstall, forgetStationKey, installFromArchive, keyLocation, PLATFORM_TOOLS, type KeyLocation } from './adb/platformTools';
import { AdbListError, ProcessAdbRunner, type AdbRunner } from './adb/runner';
import { sameBenchName } from '../../shared/src/mdm/bench';
import { BenchApiError, HttpBenchApi, type BenchApi, type BenchTarget } from './benchApi';
import { ServerClock } from './clock';
import { isDevBuild, loadBenchConfig, normaliseBenchUrl, type BenchConfig, type UrlSource } from './config';
import { defaultProtector, type Protector } from './dpapi';
import { HistoryStore, type HistoryEntry } from './history';
import { flashWindow, logError } from './native';
import { adbHomeDir, apkCacheDir, historyFile, localDataDir, platformToolsDir, stationFile } from './paths';
import { agentSignerPin } from './pins';
import { GateError, ProvisionRun, type Choice, type ProvisionTiming } from './provision/steps';
import { anonymise, truncateSerial } from './redact';
import { applyUpdate, checkForUpdate, currentVersion, type UpdateCheck } from './selfUpdate';
import { SlotBoard, MAX_CARDS } from './slots';
import { BenchStation, StationStore, STATION_POLL_APPROVED_MS, STATION_POLL_PENDING_MS, STATION_POLL_UNREACHABLE_MS, type StationStatus } from './station';
import { renderPage } from './ui';
import { WindowWatch, type WindowMode } from './window';

/**
 * Obligarth bench station — the local application (lot BANC §5.2, §5.3): a loopback HTTP server (127.0.0.1, port 0)
 * that serves the page and drives the cards, ported from the bench of Obliwan.
 *
 * ┌─ LOCAL SECURITY ─────────────────────────────────────────────────────────┐
 * │ A token per run (randomBytes(24)) on EVERY request, the page included    │
 * │ (`?t=` or `x-bench-token`, timingSafeEqual); no-store, nosniff, DENY,    │
 * │ no-referrer, a strict CSP; bodies of 64 KiB at most. The page never sees │
 * │ the station token nor a configuration: the status, the name, the code.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE GATE ───────────────────────────────────────────────────────────────┐
 * │ GET /me every 5 s while pending, 60 s approved, 15 s unreachable, and    │
 * │ LIVE right before any action on a device (`requireApprovedLive`): a      │
 * │ station revoked or suspended in the console stops at the next step.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Texts: the server side answers CODES and parameters; the page translates them (catalogs en/fr built into the page,
 * `t('ns.key') || 'Fallback'`).
 */

const BODY_LIMIT = 64 * 1024;
const OUTCOMES_KEPT = 16;
const OP_ID = /^[A-Za-z0-9_-]{8,64}$/;
const SITE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const TITLE_PART = 'Obligarth Bench';

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, readonly extra: Record<string, unknown> = {}) { super(code); }
}

/** A refusal of the platform for the page: its own code when the server named one about the request (404, 409, 422),
 *  otherwise 502 (unreachable, redirected, a 5xx). */
function relayed(err: unknown): HttpError {
  if (err instanceof BenchApiError && [404, 409, 422].includes(err.status)) {
    return new HttpError(err.status, err.code, typeof err.details?.suggestedName === 'string' ? { suggestedName: err.details.suggestedName } : {});
  }
  return new HttpError(502, (err as { code?: string })?.code ?? 'server_unreachable');
}

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

export const PAGE_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function tokenMatches(supplied: unknown, token: string): boolean {
  if (typeof supplied !== 'string' || supplied.length !== token.length) return false;
  return timingSafeEqual(Buffer.from(supplied), Buffer.from(token));
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > BODY_LIMIT) throw new HttpError(413, 'too_large');
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    throw new HttpError(400, 'bad_request');
  }
}

export type Phase = 'need-url' | 'checking' | StationStatus['state'];
export type AdbStatus = 'missing' | 'downloading' | 'ready' | 'error';

interface Card {
  run: ProvisionRun;
  device: AdbDevice | null;
  present: boolean;
  createdAt: number;
  /** The technician's choices before the plan. */
  tenantId: number | null;
  groupId: number | null;
  deviceName: string | null;
  /** Lot BANC-T §9: the site chosen (checked against the station's targets when chosen), the exception D3. */
  site: { id: string; code: string; name: string } | null;
  allowLegacyOwner: boolean;
  attentionSeen: string | null;
  /** The device left (or the card holds on device_gone): the first reading in state `device` resumes it (§5.4). */
  awaitingDevice: boolean;
}

interface Outcome { op: string; serial: string; kind: string; pending: boolean; status: number; body: unknown; delivered: boolean }

export interface BenchAppHooks { reopen?: () => void; exit?: () => void }

export interface BenchAppDeps {
  config?: BenchConfig;
  protector?: Protector;
  env?: NodeJS.ProcessEnv;
  stationStore?: StationStore;
  history?: HistoryStore;
  /** The adb of the harness (a fake). Absent: platform-tools, checked. */
  runner?: AdbRunner;
  readEnvironment?: () => Promise<EnvironmentReading>;
  readSamsungDriver?: () => Promise<boolean | null>;
  /** The Samsung phones Windows sees on USB (§6.1: Auto Blocker suspected when adb does not list them). */
  readSamsungUsb?: () => Promise<string[] | null>;
  fetchImpl?: typeof fetch;
  pin?: string | null;
  watch?: WindowWatch;
  hooks?: BenchAppHooks;
  timing?: Partial<ProvisionTiming>;
  sleep?: (ms: number) => Promise<void>;
  /** Background pollers (gate, update, devices); the harness drives them by hand. */
  background?: boolean;
  exePath?: string;
}

export interface BenchApp {
  readonly server: Server;
  readonly token: string;
  readonly watch: WindowWatch;
  listen(): Promise<number>;
  url(): string;
  setWindow(mode: WindowMode, detail: string | null): void;
  busy(): { serial: string } | null;
  /** Reads the gate now (the harness). */
  refresh(): Promise<void>;
  /** Starts adb (platform-tools or the injected runner) and the tracking. */
  startAdb(): Promise<void>;
  /** Feeds a device list (the harness; production: the tracker). */
  devicesChanged(list: AdbDevice[]): void;
  close(): Promise<void>;
}

export function createBenchApp(deps: BenchAppDeps = {}): BenchApp {
  const env = deps.env ?? process.env;
  const protector = deps.protector ?? defaultProtector();
  const store = deps.stationStore ?? new StationStore(stationFile(env), protector);
  const history = deps.history ?? new HistoryStore(historyFile(env), protector);
  const token = randomBytes(24).toString('hex');
  const watch = deps.watch ?? new WindowWatch();
  const hooks = deps.hooks ?? {};
  const version = currentVersion();
  const pin = deps.pin !== undefined ? deps.pin : agentSignerPin();
  const exe = deps.exePath ?? execPath;
  const background = deps.background ?? true;
  const clock = new ServerClock();
  let cfg: BenchConfig = deps.config ?? loadBenchConfig();
  let typedUrl: string | null = null;

  // ── the gate ────────────────────────────────────────────────────────────
  let urlSource: UrlSource = cfg.source;
  let station: BenchStation | null = null;
  let status: StationStatus | null = null;
  let checking = false;
  let api: BenchApi | null = null;

  const makeStation = (url: string | null): void => {
    station = url ? BenchStation.forUrl(url, {
      store, version, clock, fetchImpl: deps.fetchImpl,
      onRenew: () => { forgetStationKey(adbHomeDir(env)); },
    }) : null;
    api = station ? new HttpBenchApi({ baseUrl: station.baseUrl, headers: () => station!.authHeaders(), clock, fetchImpl: deps.fetchImpl }) : null;
    status = null;
  };
  makeStation(cfg.baseUrl);

  const phase = (): Phase => {
    if (!station) return 'need-url';
    if (!status) return 'checking';
    return status.state;
  };

  let refreshing: Promise<void> | null = null;
  const refresh = (mode: 'fresh' | 'renew' = 'fresh'): Promise<void> => {
    if (refreshing && mode === 'fresh') return refreshing;
    const st = station;
    if (!st) return Promise.resolve();
    checking = true;
    refreshing = (async () => {
      try {
        const next = mode === 'renew' ? await st.renew() : await st.status();
        if (station === st) status = next;
      } finally {
        checking = false;
        refreshing = null;
        changed();
      }
    })();
    return refreshing;
  };

  /** GET /me now; throws GateError unless approved. Before any action on a device. */
  const requireApprovedLive = async (): Promise<void> => {
    await refresh('fresh');
    const s = status as StationStatus | null;
    if (!s || s.state !== 'approved') {
      const code = !s ? 'station_refused' : s.state === 'pending' ? 'station_pending' : s.state === 'suspended' ? 'station_suspended'
        : s.state === 'revoked' ? 'station_revoked' : 'code' in s ? s.code : 'station_refused';
      throw new GateError(code);
    }
  };

  const urlEditable = (): boolean => cfg.source !== 'installer' && cfg.source !== 'environment' && phase() !== 'approved' && phase() !== 'revoked';

  // ── adb ─────────────────────────────────────────────────────────────────
  let runner: AdbRunner | null = deps.runner ?? null;
  let adbStatus: AdbStatus = runner ? 'ready' : 'missing';
  let adbReason: string | null = null;
  let keyLoc: KeyLocation = 'none';
  let conflict: ConflictVerdict | null = null;
  let smartSwitch = false;
  let samsungDriver: boolean | null = null;
  /** Samsung phones on USB that adb does not list (§6.1): truncated serials, for the banner. */
  let usbUnseen: string[] = [];
  let usbReading = false;
  const readUsb = async (): Promise<void> => {
    if (usbReading || adbStatus !== 'ready' || (!background && !deps.readSamsungUsb)) return;
    usbReading = true;
    try {
      const usb = await (deps.readSamsungUsb ?? readSamsungUsb)().catch(() => null);
      const next = usbUnseenByAdb(usb, devices.map((d) => d.serial)).map((s) => truncateSerial(s) ?? s);
      // The driver only matters for a phone Windows sees and adb does not: Windows drives the phones itself (WinUSB).
      const driver = next.length === 0 ? true : await (deps.readSamsungDriver ?? readSamsungDriver)().catch(() => null);
      let moved = false;
      if (driver !== samsungDriver) { samsungDriver = driver; moved = true; }
      if (JSON.stringify(next) !== JSON.stringify(usbUnseen)) { usbUnseen = next; moved = true; }
      if (moved) changed();
    } finally {
      usbReading = false;
    }
  };
  let stopTracking: (() => void) | null = null;
  const toolsDir = platformToolsDir(PLATFORM_TOOLS.version, env);
  const adbHome = adbHomeDir(env);
  let ownAdb: string | null = null;

  const readEnv = deps.readEnvironment ?? readEnvironment;
  const checkConflict = async (): Promise<boolean> => {
    const r = await readEnv();
    smartSwitch = r.smartSwitch;
    conflict = judgeConflict(r, ownAdb, cfg.adbPort);
    changed();
    return conflict.conflict;
  };

  const startAdb = async (): Promise<void> => {
    if (!runner) {
      // The development build may name a fake adb (`OBLIGARTH_BENCH_ADB`, a .mjs started by node); never production.
      const fake = isDevBuild() ? (env.OBLIGARTH_BENCH_ADB ?? '').trim() : '';
      if (fake) {
        runner = new ProcessAdbRunner({ command: [process.execPath, fake], port: cfg.adbPort, adbHome, env });
      } else {
        const check = checkInstalled(toolsDir);
        if (!check.ok) { adbStatus = 'missing'; adbReason = check.reason; changed(); return; }
        ownAdb = check.adb;
        runner = new ProcessAdbRunner({ command: [check.adb], port: cfg.adbPort, adbHome, env });
      }
    }
    const started = await runner.startServer();
    if (started.code !== 0) { adbStatus = 'error'; adbReason = 'adb_server'; changed(); return; }
    adbStatus = 'ready';
    adbReason = null;
    keyLoc = keyLocation(adbHome);
    void checkConflict().catch(() => false);
    if (background && !stopTracking) stopTracking = runner.track((list) => devicesChanged(list));
    changed();
  };

  /** Reinstalls nothing: starts the adb server again (after adb_server: a port held, a server stuck). */
  const retryAdb = async (): Promise<void> => {
    if (runner) await runner.killServerOn(cfg.adbPort).catch(() => undefined);
    await startAdb();
  };

  // ── cards ───────────────────────────────────────────────────────────────
  const board = new SlotBoard<Card>(MAX_CARDS);
  let refusedSerials: string[] = [];
  let devices: AdbDevice[] = [];

  const finished = (run: ProvisionRun): void => {
    const c = board.get(run.serial);
    const t = run.target;
    const entry: HistoryEntry = {
      at: new Date().toISOString(),
      station: status && 'name' in status ? status.name : null,
      tenant: t?.tenantName ?? null,
      group: t?.groupPath ?? null,
      site: run.site ? `${run.site.code} — ${run.site.name}` : null,
      serial: truncateSerial(run.identity?.adbSerial ?? run.serial),
      model: run.identity?.model ?? c?.device?.model ?? null,
      android: run.identity?.osRelease ?? null,
      roleTarget: run.plan?.roleTarget ?? null,
      roleObtained: run.outcome === 'completed' ? run.roleChosen : null,
      outcome: run.outcome === 'completed' ? 'completed' : run.outcome === 'abandoned' ? 'abandoned' : 'failed',
      errorCode: run.errorCode,
      provisioningId: run.provisioningId,
      deviceUuid: run.serverState?.deviceUuid ?? null,
    };
    void history.append(entry);
  };

  const newCard = (serial: string, device: AdbDevice | null): Card => ({
    run: new ProvisionRun(serial, {
      runner: runner!, api: apiProxy, pin, apkCacheDir: apkCacheDir(env), requireApproved: requireApprovedLive,
      adbConflict: () => checkConflict(), timing: deps.timing, sleep: deps.sleep, onChange: () => changed(), onFinished: finished,
    }),
    device, present: true, createdAt: Date.now(), tenantId: null, groupId: null, deviceName: null, site: null, allowLegacyOwner: false, attentionSeen: null, awaitingDevice: false,
  });

  /** The api of the current station, resolved at each call (the URL may change between two steps). */
  const apiProxy: BenchApi = {
    targets: () => need().targets(),
    tenants: () => need().tenants(),
    sites: (t, s) => need().sites(t, s),
    siteDevices: (s, g) => need().siteDevices(s, g),
    agent: () => need().agent(),
    downloadApk: (s, d) => need().downloadApk(s, d),
    plan: (b) => need().plan(b),
    provisioning: (id) => need().provisioning(id),
    token: (id) => need().token(id),
    step: (id, e) => need().step(id, e),
    result: (id, b) => need().result(id, b),
    nowIso: () => clock.iso(),
  };
  function need(): BenchApi {
    if (!api) throw new GateError('station_refused');
    return api;
  }

  function devicesChanged(list: AdbDevice[]): void {
    devices = list;
    refusedSerials = [];
    const seen = new Set(list.map((d) => d.serial));
    for (const d of list) {
      const card = board.get(d.serial);
      if (card) {
        if (!card.present || card.run.prompt?.code === 'device_gone') card.awaitingDevice = true;
        card.device = d;
        card.present = true;
        // The same serial plugged back: the card that held for it resumes at the first reading in state `device` (it
        // usually goes through offline, authorizing or unauthorized first) (§5.4).
        if (card.awaitingDevice && d.state === 'device' && card.run.prompt?.code === 'device_gone' && !card.run.busy && runner) {
          card.awaitingDevice = false;
          void startRun(card, 'retry');
        }
        continue;
      }
      if (!runner) continue;
      const claim = board.claim(d.serial, () => newCard(d.serial, d));
      if (!claim.ok) refusedSerials.push(d.serial);
    }
    for (const c of board.values()) if (!seen.has(c.run.serial)) { c.present = false; c.awaitingDevice = true; }
    void readUsb();
    if (list.some((d) => d.state === 'offline' || d.state === 'no permissions')) void checkConflict().catch(() => false);
    changed();
  }

  const cardFor = (serial: string): Card => {
    const c = board.get(serial);
    if (!c) throw new HttpError(404, 'card_unknown');
    return c;
  };

  const cardView = (c: Card) => {
    const r = c.run;
    return {
      serial: r.serial,
      present: c.present,
      state: c.device?.state ?? null,
      model: r.identity?.model ?? c.device?.model?.replace(/_/g, ' ') ?? null,
      manufacturer: r.identity?.manufacturer ?? null,
      android: r.identity?.osRelease ?? null,
      sdk: r.identity?.sdkInt ?? null,
      oneUi: r.identity?.oneUi ?? null,
      hwSerial: r.identity?.hwSerial ?? null,
      tenantId: r.target?.tenantId ?? c.tenantId,
      groupId: r.target?.groupId ?? c.groupId,
      targetLabel: r.target ? `${r.target.tenantName} › ${r.target.groupPath}` : null,
      site: r.site ?? c.site,
      allowLegacyOwner: r.plan ? r.allowLegacyOwner : c.allowLegacyOwner,
      deviceName: r.deviceName ?? c.deviceName,
      kind: r.plan?.kind ?? null,
      roleTarget: r.plan?.roleTarget ?? null,
      roleChosen: r.roleChosen,
      agentVersion: r.agent?.versionCode ?? null,
      servedVersion: r.served?.versionName ?? null,
      steps: Object.entries(r.steps).map(([id, s]) => ({ id, status: s.status, code: s.code })),
      tone: r.tone,
      busy: r.busy,
      prompt: r.prompt,
      hint: r.hint,
      outcome: r.outcome,
      errorCode: r.errorCode,
      errorParams: r.errorParams,
      blockers: r.blockers(),
      provisioningId: r.provisioningId,
      identityState: r.serverState?.identityState ?? null,
      adbCut: r.adbCut,
      pendingSteps: r.pendingSteps,
      ownerSetHere: r.ownerSetHere,
    };
  };

  const outcomes: Outcome[] = [];
  const startRun = (card: Card, choice: Choice | undefined, op?: string): Promise<void> => {
    const rec: Outcome = { op: op ?? randomBytes(9).toString('base64url'), serial: card.run.serial, kind: 'run', pending: true, status: 0, body: null, delivered: false };
    outcomes.push(rec);
    if (outcomes.length > OUTCOMES_KEPT) outcomes.splice(0, outcomes.length - OUTCOMES_KEPT);
    return card.run.run({ choice }).then(() => {
      rec.pending = false;
      rec.status = 200;
      rec.body = { card: cardView(card) };
      if (card.run.prompt?.attention && card.attentionSeen !== card.run.prompt.code) {
        card.attentionSeen = card.run.prompt.code;
        flashWindow(TITLE_PART);
      }
      changed();
    }, (err: unknown) => {
      rec.pending = false;
      rec.status = 500;
      rec.body = { code: 'internal' };
      logError(`card run: ${err instanceof Error ? err.stack ?? err.message : String(err)}`, env);
    });
  };

  const busyCards = (): Card[] => board.values().filter((c) => c.run.busy);

  // ── update ──────────────────────────────────────────────────────────────
  let update: UpdateCheck | null = null;
  const checkUpdate = async (): Promise<void> => {
    update = await checkForUpdate(station?.baseUrl ?? null, version, deps.fetchImpl ?? fetch);
    changed();
  };

  // ── events ──────────────────────────────────────────────────────────────
  const streams = new Set<ServerResponse>();
  let pendingEvent: NodeJS.Timeout | null = null;
  function changed(): void {
    if (pendingEvent) return;
    pendingEvent = setTimeout(() => {
      pendingEvent = null;
      for (const s of streams) { try { s.write('event: change\ndata: {}\n\n'); } catch { /* closed */ } }
    }, 150);
    pendingEvent.unref?.();
  }

  let windowMode: WindowMode = 'none';
  let windowDetail: string | null = null;

  const stateView = () => {
    const s = status as StationStatus | null;
    return {
      app: 'obligarth-bench',
      version,
      dev: isDevBuild(),
      phase: phase(),
      checking,
      url: station?.baseUrl ?? null,
      urlSource: typedUrl && station?.baseUrl === typedUrl ? 'typed' : urlSource,
      urlEditable: urlEditable(),
      station: s && 'stationId' in s ? { stationId: s.stationId, name: s.name, verificationCode: s.verificationCode, session: s.session, status: s.state } : null,
      refusal: s && 'code' in s ? { code: s.code, ...('status' in s ? { status: s.status } : {}), ...('suggestedUrl' in s ? { suggestedUrl: s.suggestedUrl, location: s.location } : {}) } : null,
      clockOffsetMs: clock.offset(),
      adb: {
        status: adbStatus, reason: adbReason, version: PLATFORM_TOOLS.version, licenseUrl: PLATFORM_TOOLS.licenseUrl, port: cfg.adbPort,
        keyLocation: keyLoc, conflict, smartSwitch, samsungDriver, dataDir: localDataDir(env), usbUnseen,
      },
      pinPresent: pin !== null,
      update: update ? { available: update.available, current: update.current } : null,
      cards: board.size,
      maxCards: MAX_CARDS,
      refusedSerials,
      window: { mode: windowMode, detail: windowDetail },
    };
  };

  const requireApprovedRoute = async (): Promise<void> => {
    try {
      await requireApprovedLive();
    } catch (err) {
      if (err instanceof GateError) throw new HttpError(403, 'not_approved', { gate: err.code });
      throw err;
    }
  };

  // ── routes ──────────────────────────────────────────────────────────────
  async function route(req: IncomingMessage, res: ServerResponse, path: string, url: URL): Promise<void> {
    const method = req.method ?? 'GET';
    if (method === 'GET' && path === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': PAGE_CSP, ...SECURITY_HEADERS });
      res.end(renderPage(version));
      return;
    }
    if (method === 'GET' && path === '/api/instance') { json(res, 200, { app: 'obligarth-bench', pid: process.pid, version }); return; }
    if (method === 'POST' && path === '/api/window') { watch.reopened(); hooks.reopen?.(); json(res, 200, { ok: true }); return; }
    if (method === 'POST' && path === '/api/heartbeat') { watch.heartbeat(); res.writeHead(204, SECURITY_HEADERS); res.end(); return; }
    if (method === 'GET' && path === '/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', connection: 'keep-alive', ...SECURITY_HEADERS });
      res.write(': open\n\n');
      watch.streamOpened();
      streams.add(res);
      const ping = setInterval(() => res.write(': ping\n\n'), 10_000);
      req.on('close', () => { clearInterval(ping); streams.delete(res); watch.streamClosed(); });
      return;
    }
    if (method === 'GET' && path === '/api/state') {
      if (url.searchParams.get('refresh') === '1') await refresh('fresh');
      json(res, 200, stateView());
      return;
    }
    if (method === 'POST' && path === '/api/url') {
      const body = await readJsonBody(req);
      if (!urlEditable()) throw new HttpError(phase() === 'approved' ? 409 : 403, 'url_locked');
      const given = normaliseBenchUrl(typeof body.url === 'string' ? body.url : '');
      if (!given) throw new HttpError(400, 'url_invalid');
      if (busyCards().length) throw new HttpError(409, 'busy');
      typedUrl = given;
      urlSource = 'typed';
      cfg = { ...cfg, baseUrl: given, source: 'typed' };
      makeStation(given);
      await refresh('fresh');
      void checkUpdate();
      json(res, 200, stateView());
      return;
    }
    if (method === 'POST' && path === '/api/station/renew') {
      await readJsonBody(req);
      if (phase() !== 'revoked') throw new HttpError(409, 'not_revoked');
      await refresh('renew');
      json(res, 200, stateView());
      return;
    }
    if (method === 'POST' && path === '/api/adb/retry') {
      await readJsonBody(req);
      if (adbStatus === 'ready') throw new HttpError(409, 'adb_ready');
      if (adbStatus === 'downloading') throw new HttpError(409, 'busy');
      await retryAdb();
      json(res, 200, stateView());
      return;
    }
    if (method === 'POST' && path === '/api/adb/install') {
      const body = await readJsonBody(req);
      if (body.accept !== true) throw new HttpError(400, 'license_not_accepted');
      // A working adb is never reinstalled (its runner is the cards' and the tracker's); a busy card never loses it.
      if (adbStatus === 'ready') throw new HttpError(409, 'adb_ready');
      if (adbStatus === 'downloading' || busyCards().length) throw new HttpError(409, 'busy');
      // A server of ours still running from the folder would hold its files (EBUSY): stopped first, tracker included.
      if (runner) await runner.killServerOn(cfg.adbPort).catch(() => undefined);
      stopTracking?.();
      stopTracking = null;
      adbStatus = 'downloading';
      changed();
      const zipPath = typeof body.zipPath === 'string' ? body.zipPath.trim().replace(/^"|"$/g, '') : '';
      let check;
      try {
        check = zipPath
          ? installFromArchive(readFileSync(zipPath), toolsDir)
          : await downloadAndInstall(toolsDir);
      } catch (err) {
        check = { ok: false as const, code: 'adb_missing' as const, reason: err instanceof Error ? err.message.slice(0, 60) : 'error' };
      }
      if (!check.ok) { adbStatus = 'missing'; adbReason = check.reason; changed(); json(res, 422, { code: 'adb_missing', reason: check.reason }); return; }
      runner = null;
      await startAdb();
      json(res, 200, stateView());
      return;
    }
    if (method === 'POST' && path === '/api/adb/stop-conflicts') {
      const body = await readJsonBody(req);
      if (body.confirm !== true) throw new HttpError(400, 'confirmation_required');
      if (busyCards().length) throw new HttpError(409, 'busy');
      const r = await readEnv();
      const v = judgeConflict(r, ownAdb, cfg.adbPort);
      if (runner) await runner.killServerOn(5037).catch(() => undefined);
      await stopProcesses([...v.foreign.map((f) => f.pid), ...r.listener5037]);
      await checkConflict();
      json(res, 200, stateView());
      return;
    }
    if (method === 'GET' && path === '/api/targets') {
      await requireApprovedRoute();
      try {
        json(res, 200, { targets: await need().targets() });
      } catch (err) {
        throw new HttpError(502, (err as { code?: string }).code ?? 'server_unreachable');
      }
      return;
    }
    // Lot BANC-T §9: the choice of a card, tenant → site → names of the site (the server bounds them to the targets).
    if (method === 'GET' && path === '/api/tenants') {
      await requireApprovedRoute();
      json(res, 200, { tenants: await need().tenants().catch((err: unknown) => { throw relayed(err); }) });
      return;
    }
    const ts = /^\/api\/tenants\/([1-9][0-9]{0,9})\/sites$/.exec(path);
    if (method === 'GET' && ts) {
      await requireApprovedRoute();
      const search = (url.searchParams.get('search') ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 100) || null;
      json(res, 200, { sites: await need().sites(Number(ts[1]), search).catch((err: unknown) => { throw relayed(err); }) });
      return;
    }
    const sd = /^\/api\/sites\/([0-9a-fA-F-]{36})\/devices$/.exec(path);
    if (method === 'GET' && sd) {
      if (!SITE_ID.test(sd[1])) throw new HttpError(400, 'bad_request');
      const rawGroup = url.searchParams.get('groupId');
      const groupId = rawGroup !== null && /^[1-9][0-9]{0,9}$/.test(rawGroup) ? Number(rawGroup) : null;
      if (rawGroup !== null && groupId === null) throw new HttpError(400, 'bad_request');
      await requireApprovedRoute();
      json(res, 200, await need().siteDevices(sd[1].toLowerCase(), groupId).catch((err: unknown) => { throw relayed(err); }));
      return;
    }
    if (method === 'GET' && path === '/api/cards') {
      json(res, 200, { cards: board.values().sort((a, b) => a.createdAt - b.createdAt).map(cardView), devices: devices.length, now: Date.now() });
      return;
    }
    if (method === 'POST' && path === '/api/cards') {
      await readJsonBody(req);
      if (runner) {
        try {
          devicesChanged(await runner.devices());
        } catch (err) {
          // A failed reading is not « every device unplugged »: the cards stay as they are.
          if (!(err instanceof AdbListError)) throw err;
        }
      }
      json(res, 200, { cards: board.values().map(cardView) });
      return;
    }
    const m = /^\/api\/cards\/([A-Za-z0-9._:-]{1,64})\/(plan|run|abandon|close|export)$/.exec(path);
    if (m && method === 'POST') {
      const card = cardFor(m[1]);
      const body = await readJsonBody(req);
      switch (m[2]) {
        case 'plan': {
          if (card.run.plan) throw new HttpError(409, 'already_planned');
          const tenantId = Number(body.tenantId);
          const groupId = Number(body.groupId);
          if (!Number.isInteger(tenantId) || tenantId <= 0 || !Number.isInteger(groupId) || groupId <= 0) throw new HttpError(400, 'target_required');
          const deviceName = typeof body.deviceName === 'string' ? body.deviceName.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 100) || null : null;
          const siteId = typeof body.siteId === 'string' && body.siteId ? body.siteId.toLowerCase() : null;
          if (siteId !== null && !SITE_ID.test(siteId)) throw new HttpError(400, 'bad_request');
          if (body.allowLegacyOwner !== undefined && typeof body.allowLegacyOwner !== 'boolean') throw new HttpError(400, 'bad_request');
          const allowLegacyOwner = body.allowLegacyOwner === true;
          let site: Card['site'] = null;
          if (siteId) {
            // The site read again now: one of this target's, and the name not already used in it (§9: a duplicate is
            // refused before anything is prepared; the server checks it again under its lock).
            await requireApprovedRoute();
            const info = await need().siteDevices(siteId, groupId).catch((err: unknown) => { throw relayed(err); });
            if (info.site.tenantId !== tenantId || !info.site.targetGroupIds.includes(groupId)) throw new HttpError(422, 'site_refused');
            if (deviceName && info.devices.some((d) => sameBenchName(d.label, deviceName))) {
              throw new HttpError(409, 'name_taken', { suggestedName: info.suggestedName });
            }
            site = { id: info.site.id, code: info.site.code, name: info.site.name };
          }
          // Q3: the exception D3 is decided on the bench in an open session only (its second factor covers it).
          if (allowLegacyOwner) {
            const s = status as StationStatus | null;
            if (!s || !('session' in s) || !s.session) throw new HttpError(409, 'no_session');
          }
          card.tenantId = tenantId;
          card.groupId = groupId;
          card.deviceName = deviceName;
          card.site = site;
          card.allowLegacyOwner = allowLegacyOwner;
          json(res, 200, { card: cardView(card) });
          return;
        }
        case 'run': {
          if (card.run.busy) throw new HttpError(409, 'busy');
          if (!card.present) throw new HttpError(409, 'device_gone');
          await requireApprovedRoute();
          let target: BenchTarget | undefined;
          if (!card.run.plan) {
            if (card.tenantId === null || card.groupId === null) throw new HttpError(400, 'target_required');
            const all = await need().targets().catch((err: { code?: string }) => { throw new HttpError(502, err.code ?? 'server_unreachable'); });
            target = all.find((t) => t.tenantId === card.tenantId && t.groupId === card.groupId);
            if (!target) throw new HttpError(422, 'target_refused');
          }
          const choices: Choice[] = ['recheck', 'continue_admin', 'confirm_admin', 'retry', 'reissue'];
          const choice = typeof body.choice === 'string' && (choices as string[]).includes(body.choice) ? (body.choice as Choice) : undefined;
          if (choice && card.run.prompt && !card.run.prompt.choices.includes(choice) && choice !== 'retry') throw new HttpError(409, 'choice_not_offered');
          const op = typeof req.headers['x-bench-op'] === 'string' && OP_ID.test(req.headers['x-bench-op']) ? req.headers['x-bench-op'] : undefined;
          if (target) {
            card.run.target = target;
            card.run.deviceName = card.deviceName;
            card.run.site = card.site;
            card.run.allowLegacyOwner = card.allowLegacyOwner;
          }
          const p = startRun(card, choice, op);
          const rec = outcomes[outcomes.length - 1];
          const quick = await Promise.race([p.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), req.headers['x-bench-async'] === '1' ? 5_000 : 0))]);
          json(res, quick ? 200 : 202, { op: rec.op, card: cardView(card) });
          return;
        }
        case 'abandon': {
          if (card.run.busy) throw new HttpError(409, 'busy');
          const r = await card.run.abandon(body.release === true);
          json(res, 200, { card: cardView(card), released: r.released });
          return;
        }
        case 'close': {
          if (card.run.busy) throw new HttpError(409, 'busy');
          if (card.run.outcome === 'open' && card.run.provisioningId) throw new HttpError(409, 'abandon_first');
          board.release(card.run.serial);
          // A device still plugged in gets a fresh card at once (the tracker reports changes only).
          devicesChanged(devices);
          json(res, 200, { ok: true });
          return;
        }
        case 'export': {
          const r = card.run;
          const text = anonymise(r.raw.join('\n\n'), [r.serial, r.identity?.adbSerial, r.identity?.hwSerial]);
          const dir = join(localDataDir(env), 'exports');
          mkdirSync(dir, { recursive: true });
          const file = join(dir, `bench-raw-${new Date().toISOString().replace(/[:.]/g, '-')}-${truncateSerial(r.serial)?.slice(1) ?? 'x'}.txt`);
          writeFileSync(file, text, { encoding: 'utf8', flag: 'wx' });
          json(res, 200, { path: file });
          return;
        }
      }
    }
    if (method === 'GET' && path === '/api/outcome') {
      const op = url.searchParams.get('op');
      const rec = op !== null ? outcomes.find((o) => o.op === op) ?? null : [...outcomes].reverse().find((o) => o.pending || !o.delivered) ?? null;
      if (op !== null && !rec) throw new HttpError(404, 'op_unknown');
      if (rec && !rec.pending) rec.delivered = true;
      json(res, 200, { outcome: rec ? { op: rec.op, serial: rec.serial, kind: rec.kind, pending: rec.pending, status: rec.status, body: rec.body } : null });
      return;
    }
    if (method === 'GET' && path === '/api/history/today') {
      json(res, 200, { history: await history.today() });
      return;
    }
    if (method === 'POST' && path === '/api/update/apply') {
      await readJsonBody(req);
      if (busyCards().length || board.values().some((c) => c.run.tone === 'act' || c.run.tone === 'wait')) throw new HttpError(409, 'busy');
      if (!update?.available || !station) throw new HttpError(409, 'no_update');
      const r = await applyUpdate(station.baseUrl, update, exe, { installerUrl: cfg.source === 'installer' ? cfg.baseUrl : null, fetchImpl: deps.fetchImpl });
      json(res, r.launched ? 200 : 502, r);
      if (r.launched) setTimeout(() => hooks.exit?.(), 1_500).unref();
      return;
    }
    json(res, 404, { code: 'not_found' });
  }

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const supplied = url.searchParams.get('t') ?? req.headers['x-bench-token'];
    if (!tokenMatches(supplied, token)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
      res.end('Forbidden');
      return;
    }
    route(req, res, url.pathname, url).catch((err: unknown) => {
      if (res.headersSent) { res.end(); return; }
      if (err instanceof HttpError) { json(res, err.status, { code: err.code, ...err.extra }); return; }
      logError(`request ${req.method} ${url.pathname}: ${err instanceof Error ? err.stack ?? err.message : String(err)}`, env);
      json(res, 500, { code: 'internal' });
    });
  });

  // ── background ──────────────────────────────────────────────────────────
  let gateTimer: NodeJS.Timeout | null = null;
  let updateTimer: NodeJS.Timeout | null = null;
  let flushTimer: NodeJS.Timeout | null = null;
  let usbTimer: NodeJS.Timeout | null = null;
  const scheduleGate = (): void => {
    if (!background) return;
    const p = phase();
    const delay = p === 'approved' ? STATION_POLL_APPROVED_MS : p === 'pending' || p === 'checking' ? STATION_POLL_PENDING_MS : STATION_POLL_UNREACHABLE_MS;
    gateTimer = setTimeout(() => { void refresh('fresh').finally(scheduleGate); }, delay);
    gateTimer.unref?.();
  };
  if (background) {
    void refresh('fresh').finally(scheduleGate);
    setTimeout(() => void checkUpdate(), 2_000).unref?.();
    updateTimer = setInterval(() => void checkUpdate(), 20 * 60_000);
    updateTimer.unref?.();
    // Steps the server did not receive (it was unreachable) are sent again when it answers (§6.8).
    flushTimer = setInterval(() => {
      for (const c of board.values()) if (!c.run.busy && c.run.pendingSteps > 0) void c.run.flush().then(changed);
    }, 30_000);
    flushTimer.unref?.();
    // §6.1: a Samsung phone on USB that adb does not list (Auto Blocker, USB debugging blocked by a policy).
    usbTimer = setInterval(() => void readUsb(), 15_000);
    usbTimer.unref?.();
  }

  let port = 0;
  return {
    server,
    token,
    watch,
    async listen() {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;
      return port;
    },
    url() { return `http://127.0.0.1:${port}/?t=${token}`; },
    setWindow(mode, detail) { windowMode = mode; windowDetail = detail; },
    busy() { const c = busyCards()[0]; return c ? { serial: c.run.serial } : null; },
    refresh: () => refresh('fresh'),
    startAdb,
    devicesChanged,
    async close() {
      if (gateTimer) clearTimeout(gateTimer);
      if (updateTimer) clearInterval(updateTimer);
      if (flushTimer) clearInterval(flushTimer);
      if (usbTimer) clearInterval(usbTimer);
      stopTracking?.();
      for (const s of streams) { try { s.end(); } catch { /* closed */ } }
      if (runner && background) await runner.killServer().catch(() => undefined);
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
