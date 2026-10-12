import { MASTER_TENANT_ID } from '@obligarth/shared';
import { config } from '../../config';
import type { DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { vault } from '../../vault';
import { raiseAlert, resolveAlert } from '../alerts/service';
import { appleMetrics } from '../metrics';
import { describeIncompatibility, versionCompatible } from './compat';
import { isAppleEdgeError } from './errors';
import { allowDevVersion, appleEdge, edgeRuntime, noteEdgeVersion } from './instance';
import { serverVersion } from './version';

// =============================================================================
// Health of apple-edge as the brain sees it (docs: integration-apple-edge
// §5.5, I15; coffre-secrets §8.4-1):
//   - at start (start task apple.edge-check, 5 s at most): GET /status. A
//     version out of the matrix, or apple-edge's KEK equal to the brain's
//     (kek_id), refuses the start (fatal log, exit code 1). apple-edge
//     unreachable (or refusing the token): normal start, integration noted
//     unavailable, alerts by the probe;
//   - the probe apple-edge.health (every minute, no retry): GET /status in
//     3 s; state in memory; at the 3rd failure in a row, edge.unreachable
//     (resolved at the first success); a version that became incompatible:
//     edge.incompatible, and the client refuses every call but the probe; a
//     refused token: edge.auth_failed; the same KEK: edge.kek_shared.
// APPLE_EDGE_MODE=off: no call at all.
// =============================================================================

export interface EdgeHealthState {
  up: boolean | null;
  version: string | null;
  compatible: boolean | null;
  kekId: string | null;
  signingIdentity: { sha256: string; notAfter: string } | null;
  lastOkAt: string | null;
  consecutiveFailures: number;
  checkedAt: string | null;
}

const state: EdgeHealthState = {
  up: null, version: null, compatible: null, kekId: null, signingIdentity: null, lastOkAt: null, consecutiveFailures: 0, checkedAt: null,
};

/** The platform alerts of the probe this process raised; unknown (null) until the first probe, which
 *  resolves them all (an alert raised before a restart). */
let raised: Set<string> | null = null;

/** Raises `kind` when `active`, resolves it otherwise (only when raised: no write when nothing changes). */
async function settle(actor: DbActor, kind: 'edge.unreachable' | 'edge.incompatible' | 'edge.auth_failed' | 'edge.kek_shared',
  active: boolean, params?: Record<string, string>): Promise<void> {
  if (active) {
    await raiseAlert(actor, MASTER_TENANT_ID, kind, params ? { params } : {});
    raised?.add(kind);
  } else if (raised === null || raised.has(kind)) {
    await resolveAlert(actor, MASTER_TENANT_ID, kind);
    raised?.delete(kind);
  }
}

/** Unreachable this many probes in a row: alert. */
const UNREACHABLE_ALERT_AFTER = 3;
const START_BUDGET_MS = 5_000;

export function edgeHealth(): EdgeHealthState {
  return { ...state, compatible: edgeRuntime.compatible, version: edgeRuntime.version ?? state.version };
}

/** apple-edge's kek_id, for the vault's state (coffre-secrets §8.4-1). */
export function edgeKekId(): string | null {
  return state.kekId;
}

function brainKekId(): string | null {
  try {
    return vault.isReady() ? vault.kekId() : null;
  } catch {
    return null;
  }
}

export type EdgeStartOutcome = 'off' | 'ok' | 'unreachable' | 'unauthorized' | 'incompatible' | 'kek_shared';

/** The start check (§5.5). `exit`: what a refusal does (process.exit(1) in the server). */
export async function checkEdgeAtStart(o: { exit?: (code: number) => void } = {}): Promise<EdgeStartOutcome> {
  if (config.apple.mode !== 'on') return 'off';
  const exit = o.exit ?? ((code: number) => process.exit(code));
  const actor = 'job:apple.edge-check';
  let outcome: EdgeStartOutcome;
  try {
    const budget = AbortSignal.timeout(START_BUDGET_MS);
    const { status, version } = await appleEdge.status({ actor, requestId: 'boot-edge-check', timeoutMs: 3_000, signal: budget });
    noteEdgeVersion(version);
    state.up = true;
    state.version = version;
    state.kekId = typeof status.kek_id === 'string' ? status.kek_id : null;
    state.signingIdentity = status.signing_identity ? { sha256: status.signing_identity.sha256, notAfter: status.signing_identity.not_after } : null;
    state.lastOkAt = new Date().toISOString();
    state.consecutiveFailures = 0;
    appleMetrics.probe(true, version);
    const verdict = versionCompatible(version, serverVersion(), { allowDev: allowDevVersion() });
    if (!verdict.ok) {
      logger.fatal(describeIncompatibility(version, serverVersion(), verdict.reason));
      logger.fatal('apple-edge version out of the compatibility matrix: refusing to start.');
      exit(1);
      return 'incompatible';
    }
    const ours = brainKekId();
    if (state.kekId && ours && state.kekId === ours) {
      logger.fatal({ kekId: ours }, 'apple-edge uses the same key encryption key as the brain (same kek_id): give each service its own KEK (secrets edge_kek and server_kek).');
      logger.fatal('Shared key encryption key: refusing to start.');
      exit(1);
      return 'kek_shared';
    }
    outcome = 'ok';
    logger.info({ edgeVersion: version, brainVersion: serverVersion() }, 'apple-edge reachable and compatible');
  } catch (err) {
    state.up = false;
    state.consecutiveFailures += 1;
    appleMetrics.probe(false, null);
    if (isAppleEdgeError(err) && err.status === 401) {
      outcome = 'unauthorized';
      logger.error('apple-edge refuses the token of the brain at start: integration unavailable (degraded start)');
    } else {
      outcome = 'unreachable';
      logger.warn({ code: isAppleEdgeError(err) ? err.code : 'error' }, 'apple-edge unreachable at start: integration unavailable (degraded start), probed every minute');
    }
  }
  state.checkedAt = new Date().toISOString();
  return outcome;
}

const recoveryHooks: Array<() => Promise<void>> = [];

/** Called when a probe answers after one that did not: apple-edge is back (the command queue submits again what it
 *  held meanwhile, integration §8.6). Registered before anything starts; a hook never fails the probe. */
export function onEdgeRecovered(fn: () => Promise<void>): void {
  recoveryHooks.push(fn);
}

/** The probe of apple-edge.health. Never throws. */
export async function probeEdge(actor: DbActor, requestId: string): Promise<{ up: boolean; compatible: boolean | null }> {
  state.checkedAt = new Date().toISOString();
  try {
    const { status, version } = await appleEdge.status({ actor: `job:${actor.type === 'job' ? actor.name : 'apple-edge.health'}`, requestId, timeoutMs: 3_000 });
    noteEdgeVersion(version);
    const wasDown = state.consecutiveFailures >= UNREACHABLE_ALERT_AFTER;
    const back = state.up === false;
    state.up = true;
    state.version = version;
    state.kekId = typeof status.kek_id === 'string' ? status.kek_id : null;
    state.signingIdentity = status.signing_identity ? { sha256: status.signing_identity.sha256, notAfter: status.signing_identity.not_after } : null;
    state.lastOkAt = new Date().toISOString();
    state.consecutiveFailures = 0;
    appleMetrics.probe(true, version);
    if (wasDown) logger.info('apple-edge reachable again');
    edgeRuntime.unauthorized = false;
    const verdict = versionCompatible(version, serverVersion(), { allowDev: allowDevVersion() });
    const ours = brainKekId();
    await settle(actor, 'edge.unreachable', false);
    await settle(actor, 'edge.auth_failed', false);
    await settle(actor, 'edge.incompatible', !verdict.ok, { version: /^[0-9A-Za-z.+-]{1,64}$/.test(version) ? version : 'unreadable' });
    await settle(actor, 'edge.kek_shared', !!(state.kekId && ours && state.kekId === ours));
    if (raised === null) raised = new Set([...(!verdict.ok ? ['edge.incompatible'] : []), ...(state.kekId && ours && state.kekId === ours ? ['edge.kek_shared'] : [])]);
    if (back && verdict.ok) {
      for (const hook of recoveryHooks) {
        await hook().catch((e) => { logger.warn({ code: (e as { code?: unknown })?.code }, 'apple-edge recovery hook failed'); });
      }
    }
    return { up: true, compatible: verdict.ok };
  } catch (err) {
    state.up = false;
    state.consecutiveFailures += 1;
    appleMetrics.probe(false, null);
    if (isAppleEdgeError(err) && err.status === 401) {
      await settle(actor, 'edge.auth_failed', true);
    } else if (state.consecutiveFailures >= UNREACHABLE_ALERT_AFTER) {
      if (state.consecutiveFailures === UNREACHABLE_ALERT_AFTER) logger.error('apple-edge unreachable for 3 probes in a row');
      await settle(actor, 'edge.unreachable', true);
    }
    return { up: false, compatible: edgeRuntime.compatible };
  }
}

/** Tests. */
export function resetEdgeHealthForTests(): void {
  raised = null;
  Object.assign(state, { up: null, version: null, compatible: null, kekId: null, signingIdentity: null, lastOkAt: null, consecutiveFailures: 0, checkedAt: null });
}
