import { db } from '../db';
import { getDistFileInfo, parseStoredObliReachStatus } from './oblireachAutoInstall.service';

// ── ObliReach self-update: one owner at a time ──────────────────────────────
//
// The server answers an outdated ObliReach with an `update` command (its own
// self-update, WS heartbeat every 30 s or HTTP push). It used to do so on
// EVERY heartbeat: each one started another msiexec on the agent side, racing
// the previous one and the Obliance agent's verified install (oblireach
// manager, agent 4.5.81+). Now:
//   - at most one automatic `update` per device and target version every
//     OR_UPDATE_THROTTLE_MS (an update that failed is retried then; the
//     Obliance agent's manager takes over after its own 5 min grace);
//   - none while an update / install is known to be in flight: the Obliance
//     agent reports it is installing ObliReach or waiting for a running
//     installer (devices.oblireach_status, fresh), or an install_oblireach
//     command is on its way. Looked at again after OR_UPDATE_RECHECK_MS.
// Older Obliance agents (no manager) still rely on this self-update: it stays,
// throttled — never removed.

/** One automatic `update` per device and target version per window. */
export const OR_UPDATE_THROTTLE_MS = 10 * 60_000;
/** Skipped because something is in flight: look again after this. */
export const OR_UPDATE_RECHECK_MS = 60_000;
/** The Obliance agent's report counts only while it keeps pushing. */
const AGENT_REPORT_FRESH_MS = 10 * 60_000;
/** An 'installing' report older than this is a leftover (agent stopped mid-install). */
const INSTALLING_MAX_AGE_MS = 20 * 60_000;
/** An install_oblireach command still pending / sent / running, created within this window. */
const INSTALL_CMD_WINDOW_MS = 15 * 60_000;
/**
 * An `update` sent to an ObliReach that does not report its self-update
 * state (builds before the guard): treated as in progress this long (its
 * download + msiexec) — the manual button does not send a second one on top
 * (those builds reuse one fixed temp file: overlapping runs corrupt it).
 */
export const OR_UPDATE_SENT_INFLIGHT_MS = 5 * 60_000;

interface GateEntry { target: string; nextAt: number; sentAt?: number }

/** `${tenantId}:${deviceUuid}` → next time an automatic update may go out. */
const gate = new Map<string, GateEntry>();

const keyOf = (deviceUuid: string, tenantId: number) => `${Number(tenantId)}:${deviceUuid}`;

/** Tests only. */
export function __resetOrUpdateGateForTests(): void { gate.clear(); }

/** Drop the entries whose window is over (called by the hub's keepalive sweep). */
export function pruneOrUpdateGate(now = Date.now()): void {
  for (const [k, e] of gate) if (e.nextAt <= now) gate.delete(k);
}

/** A manual update went out: the automatic one waits a full window. */
export function noteOrUpdateSent(deviceUuid: string, tenantId: number, target: string, now = Date.now()): void {
  gate.set(keyOf(deviceUuid, tenantId), { target, nextAt: now + OR_UPDATE_THROTTLE_MS, sentAt: now });
}

/**
 * When an `update` for `target` went out to this ObliReach within
 * OR_UPDATE_SENT_INFLIGHT_MS (automatic or manual), else null.
 */
export function lastOrUpdateSentAt(deviceUuid: string, tenantId: number, target: string, now = Date.now()): number | null {
  const e = gate.get(keyOf(deviceUuid, tenantId));
  if (!e || e.target !== target || e.sentAt === undefined) return null;
  return now - e.sentAt < OR_UPDATE_SENT_INFLIGHT_MS ? e.sentAt : null;
}

/** The claimed automatic `update` could not be sent (channel closed): the next heartbeat may try again. */
export function releaseAutoUpdate(deviceUuid: string, tenantId: number, target: string): void {
  const k = keyOf(deviceUuid, tenantId);
  if (gate.get(k)?.target === target) gate.delete(k);
}

/**
 * Why an ObliReach update must not be started now (null = nothing in flight):
 *   'manager_installing'         the Obliance agent is installing ObliReach
 *   'manager_busy_msi'           it waits for a running installer (often
 *                                ObliReach's own msiexec)
 *   'manager_busy_agent_update'  the Obliance agent is updating itself
 *   'install_command'            an install_oblireach command is on its way
 */
export async function obliReachUpdateInFlight(deviceUuid: string, tenantId: number, now = Date.now()): Promise<string | null> {
  const dev = await db('devices')
    .where({ uuid: deviceUuid, tenant_id: tenantId })
    .first('id', 'oblireach_status', 'last_seen_at');
  if (!dev) return null;
  const st = parseStoredObliReachStatus(dev.oblireach_status);
  const seen = dev.last_seen_at ? new Date(dev.last_seen_at).getTime() : 0;
  if (st && Number.isFinite(seen) && now - seen < AGENT_REPORT_FRESH_MS) {
    const since = Date.parse(st.since);
    if (st.state === 'installing' && (!Number.isFinite(since) || now - since < INSTALLING_MAX_AGE_MS)) {
      return 'manager_installing';
    }
    if (st.state === 'pending' && (st.reason === 'busy_msi' || st.reason === 'busy_agent_update')) {
      return `manager_${st.reason}`;
    }
  }
  const cmd = await db('command_queue')
    .where({ device_id: dev.id, type: 'install_oblireach' })
    .whereIn('status', ['pending', 'sent', 'ack_running'])
    .where('created_at', '>', new Date(now - INSTALL_CMD_WINDOW_MS))
    .first('id');
  return cmd ? 'install_command' : null;
}

export type OrAutoUpdateClaim =
  | { send: true }
  | { send: false; reason: 'throttled' | string };

/**
 * May the server send an automatic `update` (target version `target`) to this
 * ObliReach now? Records the decision: a claim that answers send:true blocks
 * the next ones for OR_UPDATE_THROTTLE_MS; one skipped because something is in
 * flight is looked at again after OR_UPDATE_RECHECK_MS. Concurrent heartbeats
 * (WS + HTTP) never both get send:true.
 */
export async function claimAutoUpdate(deviceUuid: string, tenantId: number, target: string, now = Date.now()): Promise<OrAutoUpdateClaim> {
  const key = keyOf(deviceUuid, tenantId);
  const cur = gate.get(key);
  if (cur && cur.target === target && now < cur.nextAt) return { send: false, reason: 'throttled' };
  // Provisional: a concurrent heartbeat waits while the database is read.
  gate.set(key, { target, nextAt: now + OR_UPDATE_RECHECK_MS });
  let inFlight: string | null = null;
  try {
    inFlight = await obliReachUpdateInFlight(deviceUuid, tenantId, now);
  } catch {
    inFlight = null; // database hiccup: the throttle alone still applies
  }
  if (inFlight) return { send: false, reason: inFlight };
  gate.set(key, { target, nextAt: now + OR_UPDATE_THROTTLE_MS, sentAt: now });
  return { send: true };
}

// ── ObliReach's own report of its self-update (heartbeat `selfUpdate`) ──────

/** Self-update state an ObliReach agent (guarded builds) reports in its heartbeat. */
export interface ObliReachSelfUpdate {
  inProgress: boolean;
  target: string | null;
  since: string | null;
  /** installed | failed | busy | not_restarted | unsupported */
  lastOutcome: string | null;
  lastResult: string | null;
  lastResultAt: string | null;
  lastError: string | null;
  failures: number;
  /** Automatic attempts not before (a manual request only waits for its 2-min gap). */
  nextAttemptAt: string | null;
}

const SU_OUTCOMES = new Set(['installed', 'failed', 'busy', 'not_restarted', 'unsupported']);
const SU_VERSION_RE = /^v?\d+(\.\d+){1,3}$/;

function suText(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return s ? s.slice(0, max) : null;
}

function suTime(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 40) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/** Validated copy of a heartbeat's `selfUpdate` block (agent input: never trusted as is); null when absent / not an object. */
export function sanitizeObliReachSelfUpdate(raw: unknown): ObliReachSelfUpdate | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const target = suText(r.target, 32);
  const outcome = suText(r.lastOutcome, 20);
  const failures = Number(r.failures);
  return {
    inProgress: r.inProgress === true,
    target: target && SU_VERSION_RE.test(target) ? target : null,
    since: suTime(r.since),
    lastOutcome: outcome && SU_OUTCOMES.has(outcome) ? outcome : null,
    lastResult: suText(r.lastResult, 400),
    lastResultAt: suTime(r.lastResultAt),
    lastError: suText(r.lastError, 400),
    failures: Number.isInteger(failures) && failures > 0 ? Math.min(failures, 1000) : 0,
    nextAttemptAt: suTime(r.nextAttemptAt),
  };
}

/** Server download name of the ObliReach build for the OS / arch an ObliReach agent reports. */
export function obliReachUpdateFile(agentOS?: string | null, agentArch?: string | null): string {
  if (agentOS === 'windows') return 'oblireach-agent.msi';
  if (agentOS === 'darwin') return agentArch === 'arm64' ? 'oblireach-agent-darwin-arm64' : 'oblireach-agent-darwin-amd64';
  return 'oblireach-agent-linux-amd64';
}

/**
 * The `update` command for an ObliReach agent. sha256 + size of the file are
 * added when known (an agent that checks them refuses a corrupt download;
 * older agents ignore them).
 */
export async function buildObliReachUpdateCommand(
  idPrefix: string,
  agentOS: string | null | undefined,
  agentArch: string | null | undefined,
  version: string,
  now = Date.now(),
): Promise<{ type: 'update'; id: string; payload: Record<string, unknown> }> {
  const file = obliReachUpdateFile(agentOS, agentArch);
  let info: { sha256: string; size: number } | null = null;
  try { info = await getDistFileInfo(file); } catch { info = null; }
  return {
    type: 'update',
    id: `${idPrefix}_${now}`,
    payload: {
      version,
      url: `/api/agent/download/${file}`,
      ...(info ? { sha256: info.sha256, size: info.size } : {}),
    },
  };
}
