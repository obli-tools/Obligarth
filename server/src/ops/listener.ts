import { createHash, timingSafeEqual } from 'node:crypto';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { PROMETHEUS_CONTENT_TYPE } from './metrics';

// =============================================================================
// Internal listener of the metrics (P0-13 T8, decision D11): GET /metrics on METRICS_PORT, a plain node:http server
// of its own, outside the Express app (no session, no cookie, no CORS, no limiter of the API, no route of the
// console). Never published by docker-compose, never relayed by nginx nor by the edge proxy: reachable from the
// Docker networks of the server only. With a token (METRICS_TOKEN_FILE), `Authorization: Bearer <token>` is
// required, compared in constant time; a refusal answers 401 without detail. Concurrent scrapes share one
// rendering. Nothing else is served (404), no other method (405).
// =============================================================================

export interface MetricsHandlerOptions {
  /** The bearer token; null: none asked. */
  token: string | null;
  /** Renders the scrape (metricsRegistry.render). */
  render: () => Promise<string>;
  /** A rendering failure (logged by the caller; never the token). */
  onError?: (err: unknown) => void;
}

const digest = (s: string): Buffer => createHash('sha256').update(s, 'utf8').digest();

/** Is the Authorization header the bearer `token`? (constant time on the digests) */
export function bearerMatches(header: string | string[] | undefined, token: string): boolean {
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== 'string' || value.length > 1024) return false;
  const m = /^Bearer[ ]+(\S+)\s*$/i.exec(value);
  const given = m ? m[1] : '';
  // Both sides digested: same length whatever the input, no early exit on a prefix.
  return timingSafeEqual(digest(given), digest(token)) && m !== null;
}

function send(res: ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(body);
}

/** The request handler of the listener (tests use it directly). */
export function createMetricsHandler(opts: MetricsHandlerOptions): (req: IncomingMessage, res: ServerResponse) => void {
  let inflight: Promise<string> | null = null;
  const scrape = (): Promise<string> => {
    if (!inflight) inflight = opts.render().finally(() => { inflight = null; });
    return inflight;
  };
  return (req, res) => {
    const url = req.url ?? '/';
    const q = url.indexOf('?');
    const path = q === -1 ? url : url.slice(0, q);
    if (path !== '/metrics') { send(res, 404, 'Not found\n'); return; }
    if (req.method !== 'GET' && req.method !== 'HEAD') { send(res, 405, 'Method not allowed\n', { Allow: 'GET, HEAD' }); return; }
    if (opts.token !== null && !bearerMatches(req.headers.authorization, opts.token)) {
      send(res, 401, 'Unauthorized\n', { 'WWW-Authenticate': 'Bearer realm="metrics"' });
      return;
    }
    scrape().then(
      (text) => {
        res.writeHead(200, { 'Content-Type': PROMETHEUS_CONTENT_TYPE, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
        res.end(req.method === 'HEAD' ? undefined : text);
      },
      (err) => {
        opts.onError?.(err);
        if (!res.headersSent) send(res, 500, 'Metrics unavailable\n');
        else res.end();
      },
    );
  };
}

export interface MetricsListener {
  address(): AddressInfo | null;
  close(): Promise<void>;
}

/** Starts the listener on host:port; rejects when it cannot listen (port taken, address unknown). */
export function startMetricsListener(o: MetricsHandlerOptions & { port: number; host: string }): Promise<MetricsListener> {
  const server = http.createServer(createMetricsHandler(o));
  // A scrape is small and quick: short timeouts, few headers.
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => { reject(err); };
    server.once('error', onError);
    server.listen(o.port, o.host, () => {
      server.off('error', onError);
      resolve({
        address: () => {
          const a = server.address();
          return a && typeof a === 'object' ? a : null;
        },
        close: () => new Promise<void>((done) => {
          server.closeAllConnections?.();
          server.close(() => done());
        }),
      });
    });
  });
}
