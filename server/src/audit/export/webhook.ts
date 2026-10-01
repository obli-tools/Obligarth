// JSON webhook of the SIEM export (docs: audit-durci §8.4): POST <url> with
// { instance, deliveryId, sentAt, items } (maxBatch items, maxBatchBytes),
// signed X-Obligarth-Signature: t=<epoch s>,v1=<HMAC-SHA256(secret,
// "<t>.<raw body>") hex>, X-Obligarth-Delivery, an optional bearer token.
// 2xx: delivered. 408, 429, 5xx, timeout, network error: retryable. Any
// other 4xx: the destination is in error.
import { createHmac, randomUUID } from 'node:crypto';
import { Agent, fetch as undiciFetch } from 'undici';
import { assertSiemTarget } from '../../utils/ssrfGuard';

export interface WebhookSettings {
  url: string;
  maxBatch: number;
  maxBatchBytes: number;
  timeoutSeconds: number;
  includeEvent: boolean;
  caPem?: string;
}

export interface WebhookSecrets { hmacSecret: string; bearerToken?: string }

/** The signature header of a body sent at `t` (epoch seconds). The secret is
 *  the base64url text of 32 random bytes; the key is those bytes. */
export function webhookSignature(secret: string, t: number, rawBody: string): string {
  const mac = createHmac('sha256', Buffer.from(secret, 'base64url')).update(`${t}.${rawBody}`, 'utf8').digest('hex');
  return `t=${t},v1=${mac}`;
}

/** The raw body of a delivery. */
export function webhookBody(instance: string, deliveryId: string, items: readonly string[], sentAt = new Date().toISOString()): string {
  return `{"instance":${JSON.stringify(instance)},"deliveryId":${JSON.stringify(deliveryId)},"sentAt":${JSON.stringify(sentAt)},"items":[${items.join(',')}]}`;
}

/** How many of `items` (messages, JSON text) fit one delivery. */
export function batchSize(items: readonly string[], s: Pick<WebhookSettings, 'maxBatch' | 'maxBatchBytes'>): number {
  let bytes = 200;
  let n = 0;
  for (const it of items) {
    const size = Buffer.byteLength(it, 'utf8') + 1;
    if (n >= s.maxBatch || (n > 0 && bytes + size > s.maxBatchBytes)) break;
    bytes += size;
    n++;
  }
  return Math.max(n, items.length ? 1 : 0);
}

export type WebhookResult = { ok: true; status: number } | { ok: false; retryable: boolean; code: string };

const agents = new Map<string, Agent>();

function agentFor(caPem: string | undefined): Agent | undefined {
  if (!caPem) return undefined;
  let a = agents.get(caPem);
  if (!a) {
    a = new Agent({ connect: { ca: caPem } });
    agents.set(caPem, a);
  }
  return a;
}

/** One delivery of `items`. Never throws. */
export async function postWebhook(s: WebhookSettings, secrets: WebhookSecrets, instance: string, items: readonly string[],
  o: { allowLoopback: boolean }): Promise<WebhookResult> {
  let url: URL;
  try {
    url = new URL(s.url);
    if (url.protocol !== 'https:') return { ok: false, retryable: false, code: 'https_only' };
    await assertSiemTarget(url.hostname, { allowLoopback: o.allowLoopback });
  } catch {
    return { ok: false, retryable: true, code: 'target_refused' };
  }
  const deliveryId = randomUUID();
  const body = webhookBody(instance, deliveryId, items);
  const t = Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Obligarth-Signature': webhookSignature(secrets.hmacSecret, t, body),
    'X-Obligarth-Delivery': deliveryId,
  };
  if (secrets.bearerToken) headers.Authorization = `Bearer ${secrets.bearerToken}`;
  try {
    const res = await undiciFetch(url, {
      method: 'POST', headers, body, redirect: 'error',
      signal: AbortSignal.timeout(s.timeoutSeconds * 1000),
      dispatcher: agentFor(s.caPem),
    });
    await res.arrayBuffer().catch(() => undefined);
    if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status };
    const retryable = res.status === 408 || res.status === 429 || res.status >= 500;
    return { ok: false, retryable, code: `http_${res.status}` };
  } catch (err) {
    const name = (err as Error).name === 'TimeoutError' || (err as Error).name === 'AbortError' ? 'timeout' : 'network';
    return { ok: false, retryable: true, code: name };
  }
}
