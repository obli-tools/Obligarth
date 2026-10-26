import { readFileSync, statSync } from 'node:fs';

// =============================================================================
// Settings of the observability (P0-13 T8, decision D11): the metrics are served on an internal listener of their
// own, never published by docker-compose nor relayed by nginx or the edge proxy; a bearer token is optional.
//   METRICS_PORT        port of the internal listener (1 to 65535, 9464 by default), or "off": no listener
//   METRICS_HOST        interface it listens on (0.0.0.0 by default: the container's networks; the port is
//                       published by no service)
//   METRICS_TOKEN_FILE  file holding the bearer token (32 to 512 printable characters); empty: no token asked
// Read once at start (config.ts), refused at start when invalid (startupConfigErrors).
// =============================================================================

export interface OpsConfig {
  metrics: {
    /** null: no listener (METRICS_PORT=off). */
    port: number | null;
    host: string;
    tokenFile: string;
  };
}

export const DEFAULT_METRICS_PORT = 9464;
const MIN_TOKEN_LENGTH = 32;
const MAX_TOKEN_FILE_BYTES = 4096;

export function readOpsConfig(env: NodeJS.ProcessEnv, appPort?: number): { config: OpsConfig; errors: string[] } {
  const errors: string[] = [];
  const rawPort = (env.METRICS_PORT ?? '').trim();
  let port: number | null = DEFAULT_METRICS_PORT;
  if (rawPort === 'off') port = null;
  else if (rawPort !== '') {
    port = /^[0-9]{1,5}$/.test(rawPort) ? parseInt(rawPort, 10) : NaN;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push('METRICS_PORT must be a port from 1 to 65535 (9464 by default), or "off" for no metrics listener.');
      port = null;
    } else if (appPort !== undefined && port === appPort) {
      errors.push('METRICS_PORT must differ from PORT: the metrics are served on an internal listener of their own.');
      port = null;
    }
  }
  const host = (env.METRICS_HOST ?? '').trim() || '0.0.0.0';
  if (!/^[0-9A-Za-z.:_-]{1,253}$/.test(host)) errors.push('METRICS_HOST must be an address or a host name (0.0.0.0 by default).');
  const tokenFile = (env.METRICS_TOKEN_FILE ?? '').trim();
  return { config: { metrics: { port, host, tokenFile } }, errors };
}

/** The bearer token of the metrics (METRICS_TOKEN_FILE), or null when none is set. Throws with a message that never
 *  carries the token. */
export function readMetricsToken(file: string): string | null {
  if (!file) return null;
  let text: string;
  try {
    if (statSync(file).size > MAX_TOKEN_FILE_BYTES) throw new Error('too large');
    text = readFileSync(file, 'utf8');
  } catch {
    throw new Error(`METRICS_TOKEN_FILE ${file}: unreadable (or larger than ${MAX_TOKEN_FILE_BYTES} bytes)`);
  }
  const token = text.trim();
  if (token.length < MIN_TOKEN_LENGTH || token.length > 512) {
    throw new Error(`METRICS_TOKEN_FILE ${file}: the token must hold ${MIN_TOKEN_LENGTH} to 512 characters (32 random bytes in base64url)`);
  }
  if (/[\s\0-\x1f\x7f]/.test(token)) throw new Error(`METRICS_TOKEN_FILE ${file}: the token holds spaces or control characters`);
  return token;
}

/** The checks that read files (start-up): the token file, when set. */
export function opsStartupErrors(c: OpsConfig): string[] {
  if (c.metrics.port === null || !c.metrics.tokenFile) return [];
  try {
    readMetricsToken(c.metrics.tokenFile);
    return [];
  } catch (err) {
    return [(err as Error).message];
  }
}
