// Thin REST client of AMAPI and Pub/Sub (undici): HTTPS only in google mode (the base URLs are frozen), bounded
// timeouts (5 s to connect, 15 s to answer, 30 s for a pull), bounded bodies (8 MiB, 12 MiB for a pull, 2 MiB for
// a request), one retry of idempotent calls only, a circuit breaker (5 transport failures in a row: open 15 s, then
// a trial call), a global backoff on 429 (Retry-After respected, 10 minutes at most). Never logs a body; the
// access token only travels in the Authorization header.
import { Agent, request, type Dispatcher } from 'undici';
import { logger } from '../../utils/logger';
import {
  AndroidAuthError, AndroidError, AndroidRateLimitedError, AndroidRequestError, AndroidResponseTooLargeError, AndroidUnavailableError, googleErrorFor,
  type GoogleScope,
} from '../gateway/errors';
import { androidMetrics } from '../metrics';
import { androidWait } from '../wait';
import type { GoogleTokenProvider } from './token';

export const REQUEST_MAX_BYTES = 2 * 1024 * 1024;
export const RESPONSE_MAX_BYTES = 8 * 1024 * 1024;
const BREAKER_THRESHOLD = 5;

const BREAKER_OPEN_MS = 15_000;
const BACKOFF_MIN_MS = 5_000;
const BACKOFF_MAX_MS = 60_000;

export interface CallOptions {
  op: string;
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  url: string;
  body?: unknown;
  scope: GoogleScope;
  /** GET of a resource: a 404 answers null. */
  read?: boolean;
  /** Safe to send twice (one retry after 250 to 500 ms on a transport failure or a 5xx). */
  idempotent: boolean;
  timeoutMs?: number;
  maxBytes?: number;
  signal?: AbortSignal;
}

export interface BreakerStatus { state: 'closed' | 'open' | 'half_open'; failures: number; openedAt: number | null; backoffUntil: number | null }

/** The transport's state, shared by every call of the process. */
export class GoogleHttp {
  private failures = 0;
  private openedAt: number | null = null;
  private trial = false;
  private backoffUntil = 0;
  private backoffMs = 0;
  private readonly agent: Dispatcher;

  constructor(private readonly tokens: GoogleTokenProvider, private readonly allowHttp: boolean) {
    this.agent = new Agent({ connect: { timeout: 5_000 }, keepAliveTimeout: 30_000 });
  }

  breaker(): BreakerStatus {
    const state = this.openedAt === null ? 'closed' : Date.now() - this.openedAt >= BREAKER_OPEN_MS ? 'half_open' : 'open';
    return { state, failures: this.failures, openedAt: this.openedAt, backoffUntil: this.backoffUntil > Date.now() ? this.backoffUntil : null };
  }

  /** Test hook: back to a closed breaker and no backoff. */
  resetTransport(): void {
    this.failures = 0;
    this.openedAt = null;
    this.trial = false;
    this.backoffUntil = 0;
    this.backoffMs = 0;
  }

  private checkBreaker(): void {
    if (this.backoffUntil > Date.now()) {
      throw new AndroidRateLimitedError(Math.ceil((this.backoffUntil - Date.now()) / 1000));
    }
    if (this.openedAt === null) return;
    if (Date.now() - this.openedAt < BREAKER_OPEN_MS || this.trial) throw new AndroidUnavailableError('circuit open');
    this.trial = true;
  }

  private transportOk(): void {
    this.failures = 0;
    this.openedAt = null;
    this.trial = false;
  }

  private transportFailed(): void {
    this.trial = false;
    this.failures += 1;
    if (this.failures >= BREAKER_THRESHOLD) {
      if (this.openedAt === null) logger.warn({ android: { breaker: 'open' } }, 'android: Google circuit opened');
      this.openedAt = Date.now();
    }
  }

  private rateLimited(retryAfterS: number): void {
    this.backoffMs = Math.min(BACKOFF_MAX_MS, Math.max(BACKOFF_MIN_MS, this.backoffMs * 2 || BACKOFF_MIN_MS));
    this.backoffUntil = Date.now() + Math.max(this.backoffMs, retryAfterS * 1000);
  }

  /** The parsed JSON answer, null for a 404 of a read, or an AndroidError. */
  async call<T>(o: CallOptions): Promise<T | null> {
    if (!this.allowHttp && !o.url.startsWith('https://')) throw new AndroidRequestError('refused: not an https URL');
    let bodyText: string | undefined;
    if (o.body !== undefined) {
      bodyText = JSON.stringify(o.body);
      if (Buffer.byteLength(bodyText) > REQUEST_MAX_BYTES) throw new AndroidRequestError('request body too large');
    }
    let authRetried = false;
    for (let attempt = 1; ; attempt++) {
      this.checkBreaker();
      const started = Date.now();
      let status = 0;
      try {
        const token = await this.tokens.accessToken();
        const res = await request(o.url, {
          dispatcher: this.agent,
          method: o.method,
          headers: {
            authorization: `Bearer ${token}`,
            accept: 'application/json',
            ...(bodyText !== undefined ? { 'content-type': 'application/json; charset=utf-8' } : {}),
          },
          body: bodyText,
          headersTimeout: o.timeoutMs ?? 15_000,
          bodyTimeout: o.timeoutMs ?? 15_000,
          signal: o.signal,
        });
        status = res.statusCode;
        const json = await readBounded(res, o.maxBytes ?? RESPONSE_MAX_BYTES);
        this.transportOk();
        androidMetrics.googleRequest(o.op, status, Date.now() - started);
        if (status >= 200 && status < 300) {
          this.backoffMs = 0;
          return (json ?? {}) as T;
        }
        const header = res.headers['retry-after'];
        const err = googleErrorFor(status, json, { scope: o.scope, read: o.read, retryAfter: Array.isArray(header) ? header[0] : header });
        if (err === null) return null;
        if (err instanceof AndroidRateLimitedError) this.rateLimited(err.retryAfterSeconds);
        if (err instanceof AndroidAuthError && status === 401 && !authRetried) {
          authRetried = true;
          this.tokens.reset();
          continue;
        }
        if (err.kind === 'unavailable' && o.idempotent && attempt === 1) {
          await androidWait(250 + Math.floor(Math.random() * 250));
          continue;
        }
        throw err;
      } catch (err) {
        if (err instanceof AndroidError) throw err;
        if ((err as { name?: string }).name === 'AbortError' || o.signal?.aborted) throw new AndroidUnavailableError('aborted');
        // Transport failure: connection, timeout, oversized body.
        if (status === 0) this.transportFailed();
        androidMetrics.googleRequest(o.op, 0, Date.now() - started);
        if (o.idempotent && attempt === 1 && this.openedAt === null) {
          await androidWait(250 + Math.floor(Math.random() * 250));
          continue;
        }
        throw new AndroidUnavailableError(`transport failure on ${o.op}`);
      }
    }
  }
}

async function readBounded(res: Dispatcher.ResponseData, max: number): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of res.body) {
    size += (c as Buffer).length;
    if (size > max) {
      res.body.destroy();
      throw new AndroidResponseTooLargeError();
    }
    chunks.push(c as Buffer);
  }
  if (size === 0) return null;
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return null;
  }
}

