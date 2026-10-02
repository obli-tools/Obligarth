import { config } from '../../config';
import { logger } from '../../utils/logger';
import { appleMetrics } from '../metrics';
import { createAppleEdgeClient, type AppleEdgeClient } from './client';
import { versionCompatible } from './compat';
import type { AppleEdgeError } from './errors';
import { readApiTokenFile } from './secrets';
import { serverVersion } from './version';

// =============================================================================
// The client of this process (docs: integration-apple-edge §5.3: "singleton
// built from config at first use"): APPLE_EDGE_URL, the token of
// APPLE_EDGE_API_TOKEN_FILE (read once), APPLE_EDGE_TIMEOUT_MS, refused calls
// with APPLE_EDGE_MODE=off; the version of every answer checked against the
// matrix (a version that became incompatible refuses every call but the
// probe: edge/health.ts raises its alert); failures logged by code, never
// with a value; a 401 reported to the probe (alert edge.auth_failed).
// =============================================================================

/** What the answers of apple-edge told this process (read by edge/health.ts and the gate of the client). */
export const edgeRuntime = {
  /** Last X-Apple-Edge-Version seen. */
  version: null as string | null,
  /** null: not known yet (no answer since the start); false: out of the matrix. */
  compatible: null as boolean | null,
  /** A 401 since the last successful probe. */
  unauthorized: false,
};

let token: string | null = null;

/** Accept the version 'dev' (laboratory). */
export function allowDevVersion(): boolean {
  return config.apple.allowDevVersion || process.env.NODE_ENV === 'development';
}

/** Records the version of an answer; re-evaluates the matrix when it changes. */
export function noteEdgeVersion(version: string): void {
  if (version === edgeRuntime.version && edgeRuntime.compatible !== null) return;
  edgeRuntime.version = version;
  const verdict = versionCompatible(version, serverVersion(), { allowDev: allowDevVersion() });
  const was = edgeRuntime.compatible;
  edgeRuntime.compatible = verdict.ok;
  if (!verdict.ok && was !== false) logger.error({ edgeVersion: /^[0-9A-Za-z.+-]{1,64}$/.test(version) ? version : 'unreadable', reason: verdict.reason }, 'apple-edge: version out of the compatibility matrix: calls refused');
}

function onFailure(e: AppleEdgeError, call: { method: string; route: string }): void {
  const fields = { route: call.route, status: e.status, code: e.code };
  if (e.status === 401) {
    edgeRuntime.unauthorized = true;
    logger.error(fields, 'apple-edge refused the token of the brain (check apple_edge_api_token on both sides)');
  } else if (e.code === 'invalid_request' || e.code === 'protocol') {
    logger.error(fields, 'apple-edge call refused or unreadable (programming defect)');
  } else if (e.code === 'disabled' || e.code === 'incompatible') {
    logger.debug(fields, 'apple-edge call refused by the client');
  } else if (e.retryable) {
    logger.warn(fields, 'apple-edge call failed');
  } else {
    logger.info(fields, 'apple-edge refused the call');
  }
}

let client: AppleEdgeClient | null = null;

function instance(): AppleEdgeClient {
  if (client) return client;
  client = createAppleEdgeClient({
    baseUrl: config.apple.edgeUrl,
    token: () => {
      if (token === null) token = readApiTokenFile(config.apple.apiTokenFile);
      return token;
    },
    timeoutMs: config.apple.timeoutMs,
    enabled: () => config.apple.mode === 'on',
    compatible: () => edgeRuntime.compatible !== false,
    onVersion: noteEdgeVersion,
    onFailure,
    onCall: (c) => appleMetrics.call(c.route, c.status),
  });
  appleMetrics.setCircuitSource(() => client?.circuitOpen() ?? false);
  return client;
}

/** The process's client, built at first use (a Proxy: every method of AppleEdgeClient). */
export const appleEdge: AppleEdgeClient = new Proxy({} as AppleEdgeClient, {
  get(_target, prop) {
    const c = instance() as unknown as Record<PropertyKey, unknown>;
    const v = c[prop];
    return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(c) : v;
  },
});

/** Tests: forget the client and what it learnt (another configuration, another apple-edge). */
export function resetAppleEdgeForTests(): void {
  client = null;
  token = null;
  edgeRuntime.version = null;
  edgeRuntime.compatible = null;
  edgeRuntime.unauthorized = false;
}
