import type { z } from 'zod';
import type { McpScope } from '@obligarth/shared';
import type { McpCaller } from '../caller';

// =============================================================================
// The tools of the MCP server (docs: specs mcp-server §4, §5): a registry of
// definitions { name, title, description, scope, inputSchema (JSON Schema,
// written by hand next to the zod schema), args (zod, strict), annotations,
// run(caller, args) }. tools/list shows only the tools whose scope the key
// carries (whoami, list_tenants and the authorization tools always); the
// rights of the human are checked per tenant inside each tool.
// =============================================================================

export interface ToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: false;
}

export interface ToolDef<A = any> {
  name: string;
  title: string;
  description: string;
  /** null: no scope (whoami, list_tenants, the authorization tools). */
  scope: McpScope | null;
  inputSchema: Record<string, unknown>;
  args: z.ZodType<A, z.ZodTypeDef, unknown>;
  annotations: ToolAnnotations;
  run(caller: McpCaller, args: A): Promise<unknown>;
}

const registry = new Map<string, ToolDef>();

export function registerTool<A>(def: ToolDef<A>): void {
  if (!/^[a-z_]{1,64}$/.test(def.name)) throw new Error(`invalid MCP tool name ${def.name}`);
  if (registry.has(def.name)) throw new Error(`MCP tool ${def.name} registered twice`);
  registry.set(def.name, def as ToolDef);
}

export function toolNamed(name: string): ToolDef | undefined {
  return registry.get(name);
}

export function allTools(): ToolDef[] {
  return [...registry.values()];
}

/** The tools a key may list: its scopes, and the tools without a scope. */
export function toolsForKey(scopes: readonly McpScope[]): ToolDef[] {
  return allTools().filter((t) => t.scope === null || scopes.includes(t.scope));
}

// ── JSON Schema helpers (hand-written, as Oblimint) ─────────────────────────

export const js = {
  obj: (properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> =>
    ({ type: 'object', properties, required, additionalProperties: false }),
  int: (description: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({ type: 'integer', description, ...extra }),
  str: (description: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({ type: 'string', description, ...extra }),
  bool: (description: string): Record<string, unknown> => ({ type: 'boolean', description }),
  enumOf: (values: readonly string[], description: string): Record<string, unknown> => ({ type: 'string', enum: [...values], description }),
  ids: (description: string, max = 50): Record<string, unknown> => ({ type: 'array', items: { type: 'integer', minimum: 1 }, minItems: 1, maxItems: max, description }),
  tenant: { type: 'integer', minimum: 1, description: 'The tenant to act in (see whoami / list_tenants). Required on every call.' } as Record<string, unknown>,
  limit: { type: 'integer', minimum: 1, maximum: 200, description: 'Page size (default 50, max 200).' } as Record<string, unknown>,
  offset: { type: 'integer', minimum: 0, maximum: 100000, description: 'Offset of the page (default 0).' } as Record<string, unknown>,
};

export const READ: Omit<ToolAnnotations, 'title'> = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

/**
 * A page of a list: { items, offset, total?, nextOffset }. `offset` lets the transport give the right nextOffset when it
 * shortens a page too large to send (the last page included).
 */
export function page<T>(items: T[], offset: number, limit: number, total?: number): { items: T[]; offset: number; total?: number; nextOffset: number | null } {
  const more = total !== undefined ? offset + items.length < total : items.length === limit;
  return { items, offset, ...(total !== undefined ? { total } : {}), nextOffset: more ? offset + items.length : null };
}
