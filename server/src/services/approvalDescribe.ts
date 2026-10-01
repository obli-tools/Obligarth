import { db } from '../db';
import { isSecretKey } from './approvalSecrets';
import { userLabels } from './userLabels.service';

// ── What a two-step approval will execute, in words ────────────────────────
//
// The second administrator approves the `description` of a request (the web
// page also shows its payload). Since approved requests are EXECUTED, the
// description must say what will run, built on the server from the very
// payload the executor reads — never a bare label ("Update user X") behind
// which the requester could put anything. English, like every server text of
// the approvals; values shortened, secret-named fields masked.

const MAX_LIST = 8;

/** A value, short and readable ("text", 12, yes / no, [a, b], {…}). */
export function short(v: unknown, max = 80): string {
  let s: string;
  if (v === null || v === undefined) s = 'none';
  else if (typeof v === 'boolean') s = v ? 'yes' : 'no';
  else if (typeof v === 'number') s = String(v);
  else if (typeof v === 'string') s = `"${v}"`;
  else if (Array.isArray(v)) s = `[${v.map((x) => short(x, 40)).join(', ')}]`;
  else {
    try { s = JSON.stringify(maskSecrets(v)); } catch { s = '{…}'; }
  }
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Deep copy with the secret-named fields shown as ••• (display only). */
export function maskSecrets(v: unknown, depth = 0): unknown {
  if (depth > 8) return '…';
  if (Array.isArray(v)) return v.map((x) => maskSecrets(x, depth + 1));
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      o[k] = isSecretKey(k) && x !== null && x !== undefined && x !== '' && typeof x !== 'boolean' ? '•••' : maskSecrets(x, depth + 1);
    }
    return o;
  }
  return v;
}

/** "a → b" for a changed field, null when unchanged. */
export function change(label: string, before: unknown, after: unknown): string | null {
  if (JSON.stringify(before ?? null) === JSON.stringify(after ?? null)) return null;
  return `${label}: ${short(before)} → ${short(after)}`;
}

/** "k=v, k2=v2" of an object's fields (secret-named masked). */
export function fields(obj: unknown, max = 300): string {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return short(obj, max);
  const parts = Object.entries(maskSecrets(obj) as Record<string, unknown>).map(([k, v]) => `${k}=${short(v, 60)}`);
  const s = parts.join(', ');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function capList(names: string[]): string {
  if (names.length <= MAX_LIST) return names.join(', ');
  return `${names.slice(0, MAX_LIST).join(', ')} (+${names.length - MAX_LIST} more)`;
}

function ids(raw: unknown): number[] {
  return Array.isArray(raw) ? [...new Set(raw.map(Number).filter((n) => Number.isInteger(n) && n > 0))] : [];
}

/** Hostnames of the devices of `tenantId` among `rawIds` ("pc-1, pc-2 (+3 more)"). */
export async function deviceList(tenantId: number, rawIds: unknown): Promise<string> {
  const list = ids(rawIds);
  if (!list.length) return 'no device';
  const rows = await db('devices').where({ tenant_id: tenantId }).whereIn('id', list)
    .select('id', 'hostname', 'display_name') as Array<{ id: number; hostname: string | null; display_name: string | null }>;
  const byId = new Map(rows.map((r) => [Number(r.id), r.display_name || r.hostname || `#${r.id}`]));
  const names = list.map((id) => byId.get(id) ?? `#${id} (not in this tenant)`);
  return `${list.length} device${list.length > 1 ? 's' : ''}: ${capList(names)}`;
}

export async function tenantLabel(id: unknown): Promise<string> {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return `tenant ${short(id)}`;
  const row = await db('tenants').where({ id: n }).first('name') as { name: string } | undefined;
  return row ? `tenant "${row.name}" (#${n})` : `tenant #${n} (unknown)`;
}

export async function groupLabel(tenantId: number, id: unknown): Promise<string> {
  if (id === null || id === undefined) return 'no group (ungrouped)';
  const n = Number(id);
  const row = Number.isInteger(n) ? await db('device_groups').where({ id: n, tenant_id: tenantId }).first('name') as { name: string } | undefined : undefined;
  return row ? `group "${row.name}" (#${n})` : `group #${short(id)}`;
}

/** Usernames (obligarth.user_labels: the accounts the caller may name). */
export async function userList(rawIds: unknown): Promise<string> {
  const list = ids(rawIds);
  if (!list.length) return 'nobody';
  const labels = await userLabels(list);
  return capList(list.map((id) => labels.get(id)?.username ?? `#${id}`));
}

/** One line per restriction entry ("sensitive", "restricted (include: …)"). */
function entryText(e: unknown): string {
  if (!e) return 'none';
  const x = e as { level?: string; scope?: { mode?: string; deviceIds?: unknown[]; groupIds?: unknown[] } };
  const level = x.level ?? 'none';
  const mode = x.scope?.mode;
  if (!mode || mode === 'all') return level;
  const parts: string[] = [];
  if (x.scope?.deviceIds?.length) parts.push(`devices ${x.scope.deviceIds.join(', ')}`);
  if (x.scope?.groupIds?.length) parts.push(`groups ${x.scope.groupIds.join(', ')}`);
  return `${level} (${mode}: ${parts.join('; ') || 'nothing'})`;
}

export function describeRestrictionChanges(changes: Array<{ key: string; from: unknown; to: unknown }>): string {
  const lines = changes.map((c) => `${c.key}: ${entryText(c.from)} → ${entryText(c.to)}`);
  return `Edit the action restrictions matrix (${changes.length} change${changes.length > 1 ? 's' : ''}) — ${lines.join('; ')}`;
}

/** Team permission rows ("group "Servers" (#5): rw [monitor]"). */
export async function permissionList(tenantId: number, perms: unknown): Promise<string> {
  if (!Array.isArray(perms) || !perms.length) return 'none (every permission removed)';
  const out: string[] = [];
  for (const p of perms as Array<{ scope?: string; scopeId?: number; level?: string; capabilities?: string[] }>) {
    let target: string;
    if (p.scope === 'group') target = await groupLabel(tenantId, p.scopeId);
    else if (p.scope === 'device') target = (await deviceList(tenantId, [p.scopeId])).replace(/^1 device: /, 'device ');
    else target = 'ungrouped devices';
    out.push(`${target}: ${p.level ?? '?'}${p.capabilities?.length ? ` [${p.capabilities.join(', ')}]` : ''}`);
  }
  return capList(out);
}
