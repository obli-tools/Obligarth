// The body of an audit entry (docs: audit-durci §3.1, §3.5, §3.6): built once,
// serialised in canonical form, hashed and stored as is. The other fields are
// typed; only `details` is free, and redacted here. No database import (unit
// tests, offline tool).
import { createHash, randomUUID } from 'node:crypto';
import type { AuditCriticality } from '@obligarth/shared';
import { isSecretKey, hasValue } from '../services/approvalSecrets';
import { canonicalJson } from './canonical';
import { ACTION_RE } from './catalog';
import { AuditBodyError } from './bodyError';
import type { AuditActor, AuditEntryInput, AuditOrigin, AuditWriteContext } from './types';

/** Size limits (the database refuses a body over 32 KiB). */
export const MAX_BODY_BYTES = 32_768;
export const MAX_DETAILS_BYTES = 8_192;
/** Device ids per entry, and per entry that also carries serial numbers. */
export const MAX_TARGETS = 1_000;
export const MAX_TARGETS_WITH_SERIALS = 500;

const ACTOR_REF_RE = /^[ujiea]:[A-Za-z0-9._:-]{1,64}$/;
const ACTOR_TYPES = new Set(['user', 'job', 'integration', 'enrollment', 'anonymous']);
const SIDES = new Set(['msp', 'client', 'system', 'unknown']);
const OUTCOMES = new Set(['success', 'failure', 'denied', 'requested', 'scheduled', 'cancelled']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SESSION_RE = /^[0-9a-f]{64}$/;
const STEP_UP = new Set(['totp', 'obligate_totp', 'device_key', 'password', 'trusted_ip']);

// ── Redaction of `details` (§3.5) ───────────────────────────────────────────

/** Secret-looking names for the journal, beyond the approvals' rule. */
const EXTRA_SECRET_RE = /(pin|passcode|unlock|bootstrap|privatekey|p12|pkcs|recovery|bypass)/i;
/** A sealed value of the vault (coffre R3). */
const SEALED_RE = /^v1:[0-9a-f]{8}-[0-9a-f]{4}-/;
const MAX_STRING = 1_000;
const MAX_ARRAY = 200;
const MAX_DEPTH = 6;

function isJournalSecretKey(key: string): boolean {
  if (isSecretKey(key)) return true;
  if (key.includes('.')) return false;
  const n = key.toLowerCase().replace(/[_\-\s]/g, '');
  if (/(id|ids)$/.test(n)) return false;
  return EXTRA_SECRET_RE.test(n);
}

function redactValue(v: unknown, path: string[], removed: string[], depth: number): unknown {
  if (depth > MAX_DEPTH) return '[depth]';
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'string') {
    if (SEALED_RE.test(v)) return '[sealed]';
    return v.length > MAX_STRING ? `${v.slice(0, MAX_STRING)}…` : v;
  }
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  if (Buffer.isBuffer(v)) return `[${v.length} bytes]`;
  if (Array.isArray(v)) {
    const kept = v.slice(0, MAX_ARRAY).map((x, i) => redactValue(x, [...path, String(i)], removed, depth + 1));
    if (v.length > MAX_ARRAY) kept.push({ _truncated: v.length - MAX_ARRAY });
    return kept;
  }
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    // A reference to a tenant secret is opaque: kept as is.
    if (Object.keys(o).length === 1 && typeof o.$secret === 'string' && UUID_RE.test(o.$secret)) return { $secret: o.$secret };
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(o)) {
      if (x === undefined || typeof x === 'function') continue;
      if (isJournalSecretKey(k) && hasValue(x)) { removed.push([...path, k].join('.')); continue; }
      out[k] = redactValue(x, [...path, k], removed, depth + 1);
    }
    return out;
  }
  return String(v).slice(0, MAX_STRING);
}

/** `details` as it may enter the journal: secret-named keys removed (their
 *  paths listed in _redacted, never their values), sealed values masked,
 *  long strings, long arrays and deep objects cut, 8 KiB at most once
 *  canonical (else a digest of the full canonical form). */
export function redactDetails(details: Record<string, unknown> | undefined | null): Record<string, unknown> | undefined {
  if (details === undefined || details === null) return undefined;
  if (typeof details !== 'object' || Array.isArray(details)) return { value: redactValue(details, [], [], 0) };
  const removed: string[] = [];
  const out = redactValue(details, [], removed, 0) as Record<string, unknown>;
  if (removed.length) out._redacted = removed.slice(0, 50);
  const text = canonicalJson(out);
  if (Buffer.byteLength(text, 'utf8') > MAX_DETAILS_BYTES) {
    return { _truncated: true, sha256: createHash('sha256').update(text).digest('hex') };
  }
  return out;
}

// ── Large target lists (§3.6) ───────────────────────────────────────────────

/** SHA-256 hex of the ids sorted in ascending order and joined by commas. */
export function targetsDigest(deviceIds: readonly number[]): string {
  return createHash('sha256').update([...deviceIds].sort((a, b) => a - b).join(',')).digest('hex');
}

export interface TargetSplit {
  /** `targets` of the main entry. */
  main: Record<string, unknown>;
  /** `targets` of each continuation entry (empty when the list fits). */
  chunks: Array<Record<string, unknown>>;
}

/** The `targets` of an entry and, past 1,000 devices (500 with serials), the
 *  chunks of its continuation entries. */
export function splitTargets(t: NonNullable<AuditEntryInput['targets']>): TargetSplit {
  const ids = (Array.isArray(t.deviceIds) ? t.deviceIds : []).map(Number);
  if (!ids.every((n) => Number.isSafeInteger(n) && n > 0)) throw new AuditBodyError('targets.deviceIds must be positive integers');
  const serials = Array.isArray(t.serials) ? t.serials.map((s) => String(s).slice(0, 64)) : undefined;
  if (serials && serials.length !== ids.length) throw new AuditBodyError('targets.serials must follow targets.deviceIds');
  const selection = t.selection ? {
    ...(Array.isArray(t.selection.groups) ? { groups: t.selection.groups.map(Number).filter((n) => Number.isSafeInteger(n) && n > 0).slice(0, 200) } : {}),
    ...(t.selection.tenant === true ? { tenant: true } : {}),
  } : undefined;
  const limit = serials ? MAX_TARGETS_WITH_SERIALS : MAX_TARGETS;
  if (ids.length <= limit) {
    return {
      main: { count: ids.length, devices: ids, ...(serials ? { serials } : {}), ...(selection ? { selection } : {}) },
      chunks: [],
    };
  }
  const chunks: Array<Record<string, unknown>> = [];
  for (let i = 0; i < ids.length; i += limit) {
    const part = ids.slice(i, i + limit);
    chunks.push({ count: part.length, devices: part, ...(serials ? { serials: serials.slice(i, i + limit) } : {}) });
  }
  return {
    main: { count: ids.length, digest: targetsDigest(ids), chunks: chunks.length, ...(selection ? { selection } : {}) },
    chunks,
  };
}

// ── The body (§3.1) ─────────────────────────────────────────────────────────

const cut = (v: unknown, max: number): string | undefined => {
  if (typeof v !== 'string' || v === '') return undefined;
  return v.length > max ? v.slice(0, max) : v;
};

const posInt = (v: unknown): number | undefined => {
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 && n <= 2_147_483_647 ? n : undefined;
};

function actorOf(a: AuditActor): Record<string, unknown> {
  if (!a || !ACTOR_TYPES.has(a.type)) throw new AuditBodyError('invalid actor type');
  if (typeof a.ref !== 'string' || !ACTOR_REF_RE.test(a.ref) || a.ref[0] !== a.type[0]) throw new AuditBodyError('invalid actor ref');
  if (!SIDES.has(a.side)) throw new AuditBodyError('invalid actor side');
  return {
    type: a.type,
    ref: a.ref,
    side: a.side,
    label: cut(a.label, 100),
    role: cut(a.role, 64),
    homeTenant: posInt(a.homeTenant),
    auth: cut(a.auth, 32),
    stepUp: a.stepUp && STEP_UP.has(a.stepUp) ? a.stepUp : undefined,
    session: typeof a.session === 'string' && SESSION_RE.test(a.session) ? a.session : undefined,
  };
}

function originOf(o: AuditOrigin | undefined): Record<string, unknown> | undefined {
  if (!o) return undefined;
  const out = {
    ip: cut(o.ip, 45),
    ua: cut(o.ua, 300),
    requestId: cut(o.requestId, 64),
    route: cut(o.route, 120),
  };
  return Object.values(out).some((v) => v !== undefined) ? out : undefined;
}

function linksOf(l: AuditEntryInput['links']): Record<string, unknown> | undefined {
  if (!l) return undefined;
  const out: Record<string, string> = {};
  for (const k of ['action', 'intent', 'command', 'grant'] as const) {
    const v = l[k];
    if (typeof v === 'string' && v) {
      const low = v.toLowerCase();
      if (!UUID_RE.test(low)) throw new AuditBodyError(`links.${k} must be a UUID`);
      out[k] = low;
    }
  }
  return Object.keys(out).length ? out : undefined;
}

export interface BuildOptions {
  criticality: AuditCriticality;
  /** Replayed from the spool (§5.5). */
  late?: boolean;
  /** Keep an existing id and instant (a spooled body rebuilt). */
  id?: string;
  ts?: string;
}

export interface BuiltBody {
  text: string;
  uuid: string;
  tenantId: number;
  action: string;
  criticality: AuditCriticality;
  body: Record<string, unknown>;
}

/** The canonical body of one entry (its continuation entries apart). Throws
 *  AuditBodyError on a malformed input. */
export function buildBody(entry: AuditEntryInput, ctx: AuditWriteContext, o: BuildOptions,
  targets?: Record<string, unknown>): BuiltBody {
  const tenant = posInt(entry?.tenantId);
  if (!tenant) throw new AuditBodyError('tenantId must be a positive integer');
  const action = String(entry.action ?? '');
  if (!ACTION_RE.test(action) || action.length > 100) throw new AuditBodyError(`invalid action name ${JSON.stringify(action.slice(0, 120))}`);
  const outcome = entry.outcome ?? 'success';
  if (!OUTCOMES.has(outcome)) throw new AuditBodyError('invalid outcome');
  const id = o.id ?? randomUUID();
  if (!UUID_RE.test(id)) throw new AuditBodyError('invalid id');
  const ts = o.ts ?? new Date().toISOString();
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$/.test(ts)) throw new AuditBodyError('invalid ts');
  let target: Record<string, unknown> | undefined;
  if (entry.target) {
    const type = cut(String(entry.target.type ?? ''), 50);
    const tid = String(entry.target.id ?? '').slice(0, 500);
    if (!type || !/^[a-z][a-z0-9_]*$/.test(type)) throw new AuditBodyError('target needs a type');
    const device = entry.target.device === undefined || entry.target.device === null ? undefined : posInt(entry.target.device);
    if (entry.target.device !== undefined && entry.target.device !== null && device === undefined) throw new AuditBodyError('invalid target.device');
    target = { type, id: tid, device };
  }
  const approvals = Array.isArray(entry.approvalIds) && entry.approvalIds.length
    ? entry.approvalIds.map((n) => {
      const v = posInt(n);
      if (v === undefined) throw new AuditBodyError('approvals must be positive integers');
      return v;
    })
    : undefined;
  const onBehalfOf = entry.onBehalfOf === undefined || entry.onBehalfOf === null ? undefined : posInt(entry.onBehalfOf);
  const body: Record<string, unknown> = {
    v: 1,
    id,
    ts,
    tenant,
    action,
    outcome,
    crit: o.criticality,
    actor: actorOf(ctx.actor),
    onBehalfOf,
    origin: originOf(ctx.origin),
    target,
    targets,
    details: redactDetails(entry.details),
    reason: cut(entry.reason, 500),
    ticket: cut(entry.ticket, 64),
    approvals,
    links: linksOf(entry.links),
    late: o.late ? true : undefined,
  };
  const text = canonicalJson(body);
  if (Buffer.byteLength(text, 'utf8') > MAX_BODY_BYTES) throw new AuditBodyError('body larger than 32 KiB');
  return { text, uuid: id, tenantId: tenant, action, criticality: o.criticality, body };
}

/** The same body as replayed from the spool: `late: true`, same id and
 *  instant (it is not chained yet, so it may still change). */
export function lateText(built: BuiltBody): string {
  return canonicalJson({ ...built.body, late: true });
}

/** The bodies of an entry: the main one, then one continuation entry
 *  (audit.targets) per chunk of a large target list, all with the same
 *  context. */
export function buildEntryGroup(entry: AuditEntryInput, ctx: AuditWriteContext, o: BuildOptions): BuiltBody[] {
  if (!entry.targets) return [buildBody(entry, ctx, o)];
  const split = splitTargets(entry.targets);
  const main = buildBody(entry, ctx, o, split.main);
  if (!split.chunks.length) return [main];
  const out = [main];
  split.chunks.forEach((t, i) => {
    out.push(buildBody({
      tenantId: entry.tenantId,
      action: 'audit.targets',
      outcome: entry.outcome,
      details: { part: i + 1, of: split.chunks.length, of_action: entry.action },
      links: { ...(entry.links ?? {}), action: entry.links?.action ?? main.uuid },
    }, ctx, { criticality: o.criticality, late: o.late }, t));
  });
  return out;
}
