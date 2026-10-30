import type { Request, Response } from 'express';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ZodError } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import { keyLimiter } from './auth';
import type { McpCaller } from './caller';
import { instructionsFor } from './instructions';
import { toolNamed, toolsForKey } from './tools';

// =============================================================================
// The MCP transport (docs: specs mcp-server §4): stateless JSON-RPC 2.0 over
// Streamable HTTP, JSON responses only (no SSE, no session), modelled on
// Oblimint's services/apiKeys/mcp.ts. Methods: initialize, ping, tools/list,
// tools/call; notifications answer 202 without a body. Batches of 1 to 10
// messages, 4 at a time, answered in order. Errors: invalid arguments and
// refusals (status < 500) are tool results with isError; anything else is a
// fixed "Internal error (request <id>)", logged with its stack, never leaked.
// =============================================================================

export const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'] as const;
const BATCH_MAX = 10;
const BATCH_CONCURRENCY = 4;
const TEXT_MAX = 200_000;

let serverVersion = 'dev';
try {
  serverVersion = (JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf-8')) as { version: string }).version;
} catch { /* dev */ }

interface RpcMessage { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown }
type RpcResponse = { jsonrpc: '2.0'; id: string | number | null; result?: unknown; error?: { code: number; message: string; data?: unknown } };

const rpcError = (id: RpcResponse['id'], code: number, message: string, data?: unknown): RpcResponse =>
  ({ jsonrpc: '2.0', id, error: { code, message, ...(data !== undefined ? { data } : {}) } });

/** The id of a message; null for anything that is not an object (a null batch element included: never throws). */
const idOf = (m: unknown): RpcResponse['id'] => {
  if (!m || typeof m !== 'object') return null;
  const id = (m as RpcMessage).id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
};
const isNotification = (m: RpcMessage): boolean => !!m && typeof m === 'object' && !('id' in m);

/** Halves an array until `fits` says the payload fits (one element at least). */
function shorten(list: unknown[], fits: (l: unknown[]) => boolean): unknown[] {
  let l = list;
  while (l.length > 1 && !fits(l)) l = l.slice(0, Math.floor(l.length / 2));
  return l;
}

/**
 * The text and structured content of a payload, capped: the page of a list is shortened, its nextOffset following the
 * items actually sent (from its offset, the last page included); another payload has its largest inner arrays
 * shortened (marked in `truncatedFields`); only what still does not fit becomes { truncated: true }.
 */
function toolResult(payload: unknown, protocol: string, isError = false): Record<string, unknown> {
  let value = payload;
  let text = JSON.stringify(value ?? null);
  const fits = (v: unknown): boolean => JSON.stringify(v).length <= TEXT_MAX;
  if (text.length > TEXT_MAX && value && typeof value === 'object' && Array.isArray((value as { items?: unknown }).items)) {
    const v = value as { items: unknown[]; offset?: unknown; nextOffset?: unknown };
    const items = shorten(v.items, (l) => fits({ ...v, items: l }));
    const dropped = v.items.length - items.length;
    const nextOffset = typeof v.offset === 'number' ? v.offset + items.length
      : typeof v.nextOffset === 'number' ? v.nextOffset - dropped : null;
    value = { ...v, items, truncated: true, nextOffset, ...(nextOffset === null ? { omitted: dropped } : {}) };
    text = JSON.stringify(value);
  } else if (text.length > TEXT_MAX && value && typeof value === 'object' && !Array.isArray(value)) {
    // whoami, a record with its apps, a configuration: the largest arrays first, one level deep.
    const v = { ...(value as Record<string, unknown>) };
    const shortened: string[] = [];
    const arrays = (o: Record<string, unknown>, path: string): Array<{ o: Record<string, unknown>; k: string; path: string; size: number }> =>
      Object.entries(o).filter(([, x]) => Array.isArray(x)).map(([k, x]) => ({ o, k, path: path + k, size: JSON.stringify(x).length }));
    const candidates = [...arrays(v, '')];
    for (const [k, x] of Object.entries(v)) {
      if (x && typeof x === 'object' && !Array.isArray(x)) { const inner = { ...(x as Record<string, unknown>) }; v[k] = inner; candidates.push(...arrays(inner, `${k}.`)); }
    }
    for (const c of candidates.sort((a, b) => b.size - a.size)) {
      if (fits(v)) break;
      const list = c.o[c.k] as unknown[];
      const others = JSON.stringify(v).length - c.size;
      const next = shorten(list, (l) => others + JSON.stringify(l).length <= TEXT_MAX);
      if (next.length < list.length) { c.o[c.k] = next; shortened.push(`${c.path} (${next.length} of ${list.length})`); }
    }
    value = { ...v, truncated: true, truncatedFields: shortened };
    text = JSON.stringify(value);
  }
  if (text.length > TEXT_MAX) { value = { truncated: true }; text = JSON.stringify(value); }
  return {
    content: [{ type: 'text', text }],
    ...(protocol === '2025-06-18' && value && typeof value === 'object' && !Array.isArray(value) ? { structuredContent: value } : {}),
    ...(isError ? { isError: true } : {}),
  };
}

async function callTool(caller: McpCaller, params: unknown, protocol: string): Promise<{ ok: true; result: unknown } | { ok: false; code: number; message: string }> {
  const p = (params ?? {}) as { name?: unknown; arguments?: unknown };
  const tool = typeof p.name === 'string' ? toolNamed(p.name) : undefined;
  if (!tool || (tool.scope !== null && !caller.key.scopes.includes(tool.scope))) {
    return { ok: false, code: -32602, message: `Unknown tool: ${typeof p.name === 'string' ? p.name.slice(0, 64) : ''}` };
  }
  const parsed = tool.args.safeParse(p.arguments ?? {});
  if (!parsed.success) {
    const issue = (parsed.error as ZodError).issues[0];
    return { ok: true, result: toolResult({ error: `Invalid arguments: ${issue ? `${issue.path.join('.') || '(root)'}: ${issue.message}` : 'invalid'}` }, protocol, true) };
  }
  try {
    const out = await tool.run(caller, parsed.data);
    return { ok: true, result: toolResult(out, protocol) };
  } catch (err) {
    const e = err as AppError & { status?: number };
    const status = err instanceof AppError ? e.statusCode : Number(e?.status);
    if (Number.isInteger(status) && status >= 400 && status < 500) {
      const message = err instanceof Error ? err.message : 'Refused';
      return { ok: true, result: toolResult({ error: { code: (err as AppError).code ?? (status === 404 ? 'notFound' : 'refused'), message, details: (err as AppError).details ?? null } }, protocol, true) };
    }
    logger.error({ err, tool: tool.name, requestId: caller.requestId, userId: caller.userId }, 'mcp: tool failed');
    return { ok: true, result: toolResult({ error: { code: 'internal', message: `Internal error (request ${caller.requestId})` } }, protocol, true) };
  }
}

async function handleOne(caller: McpCaller, m: RpcMessage, protocol: { value: string }): Promise<RpcResponse | null> {
  if (!m || typeof m !== 'object' || Array.isArray(m)) return rpcError(null, -32600, 'Invalid Request');
  const id = idOf(m);
  if (m.jsonrpc !== '2.0' || typeof m.method !== 'string') return rpcError(id, -32600, 'Invalid Request');
  if (isNotification(m)) return null;
  switch (m.method) {
    case 'initialize': {
      const asked = (m.params as { protocolVersion?: unknown } | undefined)?.protocolVersion;
      const version = typeof asked === 'string' && (PROTOCOL_VERSIONS as readonly string[]).includes(asked) ? asked : PROTOCOL_VERSIONS[0];
      protocol.value = version;
      return {
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: version, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'obligarth', version: serverVersion },
          instructions: await instructionsFor(caller),
        },
      };
    }
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };
    case 'tools/list':
      return {
        jsonrpc: '2.0', id,
        result: {
          tools: toolsForKey(caller.key.scopes).map((t) => ({
            name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations,
          })),
        },
      };
    case 'tools/call': {
      const r = await callTool(caller, m.params, protocol.value);
      return r.ok ? { jsonrpc: '2.0', id, result: r.result } : rpcError(id, r.code, r.message);
    }
    default:
      return rpcError(id, -32601, 'Method not found');
  }
}

async function inPool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i]); }
  }));
  return out;
}

/** POST /mcp, once authenticated: one message or a batch. */
export async function handleRpc(req: Request, res: Response): Promise<void> {
  const caller = req.mcp!;
  const header = req.get('MCP-Protocol-Version');
  if (header !== undefined && !(PROTOCOL_VERSIONS as readonly string[]).includes(header)) {
    res.status(400).json(rpcError(null, -32600, 'Unsupported MCP-Protocol-Version'));
    return;
  }
  const protocol = { value: header ?? PROTOCOL_VERSIONS[0] };
  const body = req.body as unknown;
  const batch = Array.isArray(body);
  const messages = (batch ? body : [body]) as RpcMessage[];
  if (messages.length === 0 || messages.length > BATCH_MAX) { res.status(400).json(rpcError(null, -32600, 'Invalid Request')); return; }

  // Each message counts towards the key's rate (a batch of 5 tools/call counts 5), decided before anything runs.
  const limiter = await keyLimiter();
  for (let i = 0; i < messages.length; i++) {
    const wait = limiter.take(`key:${caller.key.rowId}`);
    if (wait > 0) {
      res.status(429).setHeader('Retry-After', String(wait));
      res.json(rpcError(null, -32029, 'Too many requests'));
      return;
    }
  }

  // The id is taken before the message runs, and the per-message handler cannot throw: one bad element never loses
  // the answers (and the writes) of the others.
  const answers = await inPool(messages, BATCH_CONCURRENCY, (m) => {
    const id = idOf(m);
    return handleOne(caller, m, protocol).catch((err) => {
      try { logger.error({ err, requestId: caller.requestId }, 'mcp: message failed'); } catch { /* never */ }
      return rpcError(id, -32603, `Internal error (request ${caller.requestId})`);
    });
  });
  const replies = answers.filter((a): a is RpcResponse => a !== null);
  if (replies.length === 0) { res.status(202).end(); return; }
  res.status(200).json(batch ? replies : replies[0]);
}
