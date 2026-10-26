import type { NextFunction, Request, Response } from 'express';
import { family, type MetricFamily } from './metrics';

// =============================================================================
// HTTP metrics of the server (P0-13 T8): obligarth_http_requests_total{route, status} and
// obligarth_http_errors_total{kind}. The route label is the PATTERN of the Express route that answered
// (`/api/devices/:id`), never the path itself: a path carries ids, serial numbers, the key of a tenant
// (/t/<key>/…). Its prefix comes from the mounts, whose only parametric ones are the device surfaces /t/:key and
// /a/:key (app.ts): they are rewritten; any other segment of a mount that does not look like a fixed name becomes
// `:param`. A request no route answered (404, refused by a middleware, static file) is counted under its surface
// (`/api/*`, `/t/:key/*`, …) or `other`. Cost on the request path: one listener and one Map increment at the end
// of the response; no I/O. Self-contained apart from Express' types (unit tests).
// =============================================================================

/** Distinct (route, status) pairs kept; past it, `route="other"` (a route table is bounded, this is a guard). */
export const MAX_HTTP_SERIES = 1_500;
const STATIC_SEGMENT_RE = /^[a-z][a-z0-9-]{0,40}$/;
const PARAMETRIC_MOUNTS: ReadonlyArray<string> = ['t', 'a'];
const SURFACES: ReadonlyArray<[RegExp, string]> = [
  [/^\/api(\/|$)/, '/api/*'],
  [/^\/t\/[^/]+(\/|$)/, '/t/:key/*'],
  [/^\/a\/[^/]+(\/|$)/, '/a/:key/*'],
  [/^\/agent\/v1(\/|$)/, '/agent/v1/*'],
  [/^\/auth(\/|$)/, '/auth/*'],
  [/^\/internal(\/|$)/, '/internal/*'],
  [/^\/health(\/|$)/, '/health*'],
];

const requests = new Map<string, number>();
const errors = new Map<string, number>();

/** The path of a URL, without its query string. */
function pathOf(url: string): string {
  const i = url.search(/[?#]/);
  return i === -1 ? url : url.slice(0, i);
}

/** The surface of a path no route answered. */
export function surfaceOf(path: string): string {
  for (const [re, label] of SURFACES) if (re.test(path)) return label;
  return 'other';
}

/** Segments of a route pattern, or null when it is not a plain one (regexp, wildcard, optional parameter). */
function patternSegments(pattern: unknown): string[] | null {
  if (typeof pattern !== 'string' || !pattern.startsWith('/')) return null;
  if (/[*?()[\]+]/.test(pattern)) return null;
  return pattern === '/' ? [] : pattern.slice(1).split('/');
}

/**
 * The route label of a request: the mount prefix, read from the path and rewritten (parametric mounts, anything
 * that does not look like a fixed name), followed by the pattern of the route that answered. `routePath` is
 * req.route.path (undefined: no route answered).
 */
export function routeLabel(originalUrl: string, routePath: unknown): string {
  const path = pathOf(originalUrl || '/');
  const segs = patternSegments(routePath);
  if (segs === null) {
    // The SPA fallback of app.ts ('*'), a regexp route, or nothing matched.
    if (routePath === '*') return '*';
    return surfaceOf(path);
  }
  const actual = path === '/' ? [] : path.replace(/\/+$/, '').slice(1).split('/');
  // A trailing slash or a strict-routing difference: the route's segments are the last ones of the path.
  const prefixLen = actual.length - segs.length;
  if (prefixLen < 0) return surfaceOf(path);
  const prefix = actual.slice(0, prefixLen).map((s, i, all) => {
    if (i === 1 && PARAMETRIC_MOUNTS.includes(all[0])) return ':key';
    return STATIC_SEGMENT_RE.test(s) ? s : ':param';
  });
  const label = `/${[...prefix, ...segs].join('/')}`;
  return label.length > 200 ? surfaceOf(path) : label;
}

export const httpMetrics = {
  /** One answered request. */
  request(route: string, status: number): void {
    const s = Number.isInteger(status) && status >= 100 && status <= 599 ? status : 0;
    let k = `${route}|${s}`;
    if (!requests.has(k) && requests.size >= MAX_HTTP_SERIES) k = `other|${s}`;
    requests.set(k, (requests.get(k) ?? 0) + 1);
  },
  /** One error answered by the error handler (middleware/errorHandler.ts), by kind. */
  error(kind: 'app' | 'db_context_denied' | 'rls_denied' | 'cross_tenant_reference' | 'vault' | 'db_context' | 'unhandled'): void {
    errors.set(kind, (errors.get(kind) ?? 0) + 1);
  },
  families(): MetricFamily[] {
    return [
      family('obligarth_http_requests_total', 'HTTP requests answered, by route pattern and status', 'counter',
        [...requests].map(([k, value]) => {
          const i = k.lastIndexOf('|');
          return { labels: { route: k.slice(0, i), status: k.slice(i + 1) }, value };
        })),
      family('obligarth_http_errors_total', 'Errors answered by the error handler, by kind', 'counter',
        [...errors].map(([kind, value]) => ({ labels: { kind }, value }))),
    ];
  },
  /** Tests only. */
  reset(): void {
    requests.clear();
    errors.clear();
  },
};

/** The middleware that counts every response (app.ts, first of the chain). */
export function httpMetricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.once('finish', () => {
    httpMetrics.request(routeLabel(req.originalUrl, req.route?.path), res.statusCode);
  });
  next();
}
