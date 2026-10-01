// Operations on the keys (docs: coffre-secrets §4.1, §6.6, §6.7, §11.1):
// vault_operations, a technical table. Never a secret in a row: kinds,
// states, tenant ids, kek_ids, counts, a reason typed by an administrator.
import crypto from 'node:crypto';
import type { Knex } from 'knex';
import type { VaultOperation, VaultOperationKind, VaultOperationState } from '@obligarth/shared';

export const OPERATION_KINDS: readonly VaultOperationKind[] = [
  'backfill', 'dek_rotation', 'kek_rotation', 'verify',
  'escrow_confirmation', 'escrow_test', 'escrow_retirement', 'kek_loss_recovery',
];

/** Validity of a KEK rotation authorized by its double validation. */
export const KEK_ROTATION_VALIDITY_MS = 24 * 3600_000;

interface OperationRow {
  id: string;
  kind: VaultOperationKind;
  state: VaultOperationState;
  tenant_id: number | null;
  approval_id: number | null;
  requested_by: number | null;
  reason: string | null;
  params: Record<string, unknown> | string | null;
  progress: Record<string, unknown> | string | null;
  authorized_until: Date | null;
  started_at: Date | null;
  finished_at: Date | null;
  error: string | null;
  created_at: Date;
}

const COLUMNS = ['id', 'kind', 'state', 'tenant_id', 'approval_id', 'requested_by', 'reason', 'params', 'progress',
  'authorized_until', 'started_at', 'finished_at', 'error', 'created_at'] as const;

function json(v: unknown): Record<string, unknown> {
  if (v == null) return {};
  if (typeof v === 'string') {
    try { return JSON.parse(v) as Record<string, unknown>; } catch { return {}; }
  }
  return v as Record<string, unknown>;
}

const isoOrNull = (d: Date | string | null | undefined): string | null => (d ? new Date(d).toISOString() : null);

export function rowToOperation(r: OperationRow): VaultOperation {
  return {
    id: r.id,
    kind: r.kind,
    state: r.state,
    tenantId: r.tenant_id ?? null,
    approvalId: r.approval_id ?? null,
    requestedBy: r.requested_by ?? null,
    reason: r.reason ?? null,
    params: json(r.params),
    progress: json(r.progress),
    authorizedUntil: isoOrNull(r.authorized_until),
    startedAt: isoOrNull(r.started_at),
    finishedAt: isoOrNull(r.finished_at),
    error: r.error ?? null,
    createdAt: isoOrNull(r.created_at) ?? '',
  };
}

/** A short error text for an operation row: a fixed code and coordinates,
 *  never a value (errors of the vault carry none). */
export function operationError(err: unknown): string {
  const e = err as { code?: unknown; message?: unknown; name?: unknown } | null;
  const code = typeof e?.code === 'string' ? e.code : 'error';
  const name = typeof e?.name === 'string' ? e.name : 'Error';
  // VaultError messages carry only coordinates; others are reduced to their code.
  const msg = name === 'VaultError' && typeof e?.message === 'string' ? e.message : code;
  return msg.slice(0, 1000);
}

export const vaultOperations = {
  async create(q: Knex | Knex.Transaction, o: {
    id?: string;
    kind: VaultOperationKind;
    state: VaultOperationState;
    tenantId?: number | null;
    approvalId?: number | null;
    requestedBy?: number | null;
    reason?: string | null;
    params?: Record<string, unknown>;
    progress?: Record<string, unknown>;
    authorizedUntil?: Date | null;
    startedAt?: Date | null;
    finishedAt?: Date | null;
  }): Promise<VaultOperation> {
    const [row] = await q('vault_operations').insert({
      id: o.id ?? crypto.randomUUID(),
      kind: o.kind,
      state: o.state,
      tenant_id: o.tenantId ?? null,
      approval_id: o.approvalId ?? null,
      requested_by: o.requestedBy ?? null,
      reason: o.reason ? String(o.reason).slice(0, 2000) : null,
      params: JSON.stringify(o.params ?? {}),
      progress: JSON.stringify(o.progress ?? {}),
      authorized_until: o.authorizedUntil ?? null,
      started_at: o.startedAt ?? null,
      finished_at: o.finishedAt ?? null,
    }).returning(COLUMNS as unknown as string[]) as OperationRow[];
    return rowToOperation(row);
  },

  async get(q: Knex | Knex.Transaction, id: string, opts: { forUpdate?: boolean } = {}): Promise<VaultOperation | null> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(id))) return null;
    const qb = q('vault_operations').where({ id }).first(COLUMNS as unknown as string[]);
    if (opts.forUpdate) qb.forUpdate();
    const row = await qb as OperationRow | undefined;
    return row ? rowToOperation(row) : null;
  },

  async list(q: Knex | Knex.Transaction, o: { kind?: VaultOperationKind; limit?: number } = {}): Promise<VaultOperation[]> {
    const qb = q('vault_operations').select(COLUMNS as unknown as string[]).orderBy('created_at', 'desc').orderBy('id')
      .limit(Math.min(Math.max(o.limit ?? 50, 1), 500));
    if (o.kind) qb.where({ kind: o.kind });
    return (await qb as OperationRow[]).map(rowToOperation);
  },

  async update(q: Knex | Knex.Transaction, id: string, patch: {
    state?: VaultOperationState;
    params?: Record<string, unknown>;
    progress?: Record<string, unknown>;
    startedAt?: Date | null;
    finishedAt?: Date | null;
    error?: string | null;
    authorizedUntil?: Date | null;
  }, opts: { fromStates?: readonly VaultOperationState[] } = {}): Promise<boolean> {
    const set: Record<string, unknown> = {};
    if (patch.state !== undefined) set.state = patch.state;
    if (patch.params !== undefined) set.params = JSON.stringify(patch.params);
    if (patch.progress !== undefined) set.progress = JSON.stringify(patch.progress);
    if (patch.startedAt !== undefined) set.started_at = patch.startedAt;
    if (patch.finishedAt !== undefined) set.finished_at = patch.finishedAt;
    if (patch.error !== undefined) set.error = patch.error === null ? null : String(patch.error).slice(0, 1000);
    if (patch.authorizedUntil !== undefined) set.authorized_until = patch.authorizedUntil;
    const qb = q('vault_operations').where({ id }).update(set);
    if (opts.fromStates?.length) qb.whereIn('state', opts.fromStates as string[]);
    return (await qb) > 0;
  },

  /** An authorized operation past its validity becomes 'expired'. */
  async expireStale(q: Knex | Knex.Transaction): Promise<number> {
    return q('vault_operations').where({ state: 'authorized' }).whereNotNull('authorized_until')
      .where('authorized_until', '<', new Date()).update({ state: 'expired', finished_at: new Date() });
  },
};
