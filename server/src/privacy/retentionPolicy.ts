import type { Knex } from 'knex';
import {
  RETENTION_CATEGORIES, RETENTION_LOWERING_DELAY_DAYS, isRetentionCategory, retentionChanges, retentionValueErrors,
  type RetentionCategory, type RetentionCategoryDto, type RetentionFixedDto, type RetentionPendingRequestDto, type RetentionPolicyDto,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { userActor } from '../db/context';
import {
  ADE_REMOVED_RETENTION_DAYS, ENROLLMENT_SESSION_RETENTION_DAYS, ENROLLMENT_TOKEN_RETENTION_DAYS, INVENTORY_COMMAND_RETENTION_DAYS,
} from '../apple/retention';
import { LIVE_ALERT_RETENTION_DAYS, NOTIFICATION_LOG_RETENTION_DAYS } from '../jobs/core.jobs';
import { ICON_ORPHAN_DAYS } from '../mdm/inventory/retention';
import { refuse, requireTenantCapability, type ApprovalExecution } from '../services/approval.service';
import { privacyMetrics } from './metrics';
import { retentionValues } from './retention';
import { RETENTION_CHANGE_REQUEST_TYPE, RetentionChangePayload } from './requests';

// =============================================================================
// Changes of the retention of a tenant (P0-13 T4, CNF-04; D3: a second person, level 'restricted'; D4: a decrease after
// 7 days, cancellable meanwhile, an increase at once), on the model of the audit log's retention (audit/retention.ts):
//   - the executor of a request privacy_retention_change (registered by privacy/index.ts, examined as the profiles'
//     requests: privacy/approvals.ts privacyReviewerPolicy), as the requester: mdm.privacy.manage read again, the values
//     checked again, the retention unchanged since the request (else refused: file it again), then
//     obligarth.retention_set, which checks the request itself and writes the prepared entry privacy.retention_changed
//     (critical) in the same transaction, then the hooks of a change (onRetentionChanged: the regeneration of the
//     notice, P0-13 T5);
//   - a decrease waiting is cancelled (D4) by a request of the same type asking the value in force (restored, see
//     retentionChanges): a change of the retention as any other, examined by a second person (D3); no other way;
//   - the DTO of GET /api/privacy/retention: the categories (value in force, value set, decrease waiting), the request
//     waiting, the retentions of the platform shown read only (D16), the audit log's retention.
// =============================================================================

/** Days of the backups rotation (BACKUP_RETENTION_DAYS of the platform, conception §10.4; set with P0-13 T9). */
const BACKUP_RETENTION_DAYS_DEFAULT = 35;
/** Days an applied event of the Android inbox is kept (android/maintenance.ts). */
const ANDROID_INBOX_DAYS = 7;

/** The rotation of the backups of the platform, in days (BACKUP_RETENTION_DAYS, 35 by default): shown read only, and
 *  told to the employees by the notice (P0-13 T5). */
export function backupRetentionDays(): number {
  const backups = Number(process.env.BACKUP_RETENTION_DAYS);
  return Number.isInteger(backups) && backups > 0 ? backups : BACKUP_RETENTION_DAYS_DEFAULT;
}

/** The retentions of the platform, not set per tenant (shown read only). */
export function fixedRetentions(): RetentionFixedDto[] {
  return [
    { key: 'enrollment_sessions', value: ENROLLMENT_SESSION_RETENTION_DAYS, unit: 'days' },
    { key: 'enrollment_tokens', value: ENROLLMENT_TOKEN_RETENTION_DAYS, unit: 'days' },
    { key: 'inventory_commands', value: INVENTORY_COMMAND_RETENTION_DAYS, unit: 'days' },
    { key: 'ade_removed_devices', value: ADE_REMOVED_RETENTION_DAYS, unit: 'days' },
    { key: 'app_icons_orphaned', value: ICON_ORPHAN_DAYS, unit: 'days' },
    { key: 'android_inbox', value: ANDROID_INBOX_DAYS, unit: 'days' },
    { key: 'notification_log', value: NOTIFICATION_LOG_RETENTION_DAYS, unit: 'days' },
    { key: 'live_alerts', value: LIVE_ALERT_RETENTION_DAYS, unit: 'days' },
    { key: 'backups', value: backupRetentionDays(), unit: 'days' },
  ];
}

type Q = Knex | Knex.Transaction;
type Values = Partial<Record<RetentionCategory, number>>;

/** The row of the tenant (the defaults when it never set its retention), as in force now: a decrease past its date is
 *  read among the values (obligarth.retention_value; retention_set folds it at the next change). */
export interface RetentionRow {
  values: Values;
  /** The decreases waiting for their date (null: none). */
  pending: Values | null;
  pendingEffectiveAt: Date | null;
  version: number;
  justification: string | null;
  updatedBy: number | null;
  updatedAt: Date | null;
}

const valuesOf = (v: unknown): Values => {
  const o = typeof v === 'string' ? (() => { try { return JSON.parse(v); } catch { return null; } })() : v;
  const out: Values = {};
  if (o && typeof o === 'object' && !Array.isArray(o)) {
    for (const [k, x] of Object.entries(o as Record<string, unknown>)) if (isRetentionCategory(k) && typeof x === 'number') out[k] = x;
  }
  return out;
};

export async function retentionRow(q: Q, tenantId: number): Promise<RetentionRow> {
  const r = await q('tenant_retention_policies').where({ tenant_id: tenantId })
    .first('values', 'pending_values', 'pending_effective_at', 'version', 'justification', 'updated_by', 'updated_at') as
    Record<string, unknown> | undefined;
  if (!r) return { values: {}, pending: null, pendingEffectiveAt: null, version: 0, justification: null, updatedBy: null, updatedAt: null };
  const pending = r.pending_values === null || r.pending_values === undefined ? null : valuesOf(r.pending_values);
  const at = r.pending_effective_at ? new Date(r.pending_effective_at as string) : null;
  const due = pending !== null && at !== null && at.getTime() <= Date.now();
  return {
    values: due ? { ...valuesOf(r.values), ...pending } : valuesOf(r.values),
    pending: due ? null : pending,
    pendingEffectiveAt: due ? null : at,
    version: Number(r.version ?? 0),
    justification: (r.justification as string | null) ?? null,
    updatedBy: r.updated_by === null || r.updated_by === undefined ? null : Number(r.updated_by),
    updatedAt: r.updated_at ? new Date(r.updated_at as string) : null,
  };
}

/** The decreases still waiting for their date (null: none). */
export const pendingActive = (row: RetentionRow, now = new Date()): Values | null =>
  (row.pending && row.pendingEffectiveAt && row.pendingEffectiveAt.getTime() > now.getTime() ? row.pending : null);

/** The lock of the changes of the tenant (the one of obligarth.retention_set: taken again there, in the same
 *  transaction). */
async function lockRetention(trx: Knex.Transaction, tenantId: number): Promise<void> {
  await trx.raw("SELECT pg_advisory_xact_lock(hashtext('obligarth.retention_set'), ?)", [tenantId]);
}

// ── Execution of an approved change ────────────────────────────────────────

/** What else a change of the retention starts, in its transaction (the regeneration of the notice, P0-13 T5: it tells
 *  the durations in force). */
export type RetentionChangedHook = (trx: Knex.Transaction, p: { tenantId: number; lowersOn: string | null }) => Promise<void>;
const changedHooks: Array<{ name: string; run: RetentionChangedHook }> = [];

export function onRetentionChanged(name: string, run: RetentionChangedHook): void {
  if (changedHooks.some((h) => h.name === name)) throw new Error(`retention hook '${name}' registered twice`);
  changedHooks.push({ name, run });
}

/** An approved change of the retention, executed as the requester (in the approval's tenant context). */
export async function executeRetentionChange(x: ApprovalExecution): Promise<void> {
  const parsed = RetentionChangePayload.safeParse(x.payload ?? {});
  if (!parsed.success) refuse('Malformed retention request');
  const p = parsed.data;
  if (!x.approvalId) refuse('A retention is changed from its approval only');
  await requireTenantCapability(x.requesterId, x.tenantId, 'mdm.privacy.manage');
  const errors = retentionValueErrors(p.values);
  if (errors.unknown.length || errors.outOfRange.length || Object.keys(p.values).length === 0) {
    refuse(`retentionOutOfRange: ${[...errors.unknown, ...errors.outOfRange].join(', ')}`);
  }
  const ctx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  await db.transaction(async (trx) => {
    await lockRetention(trx, x.tenantId);
    const row = await retentionRow(trx, x.tenantId);
    if (row.version !== p.baseVersion) {
      refuse(`privacyRetentionChanged: the retention changed since the request (version ${row.version} now); file it again`);
    }
    const inForce = await retentionValues(trx, x.tenantId);
    const changes = retentionChanges(inForce, pendingActive(row), p.values);
    const previous: Values = {};
    for (const k of Object.keys(p.values) as RetentionCategory[]) previous[k] = inForce[k];
    const lowersOn = changes.lowered.length ? new Date(Date.now() + RETENTION_LOWERING_DELAY_DAYS * 86_400_000).toISOString() : null;
    const body = audit.prepare({
      tenantId: x.tenantId, action: 'privacy.retention_changed', target: { type: 'privacy_retention', id: String(x.tenantId) },
      approvalIds: [x.approvalId!], reason: p.justification.slice(0, 500),
      details: {
        values: p.values, previous, raised: changes.raised, lowered: changes.lowered, restored: changes.restored, lowersOn,
        reviewerSide: p.reviewerSide, viaApproval: true,
      },
    }, ctx, { criticality: 'critical' });
    await trx.raw('SELECT policy_version FROM obligarth.retention_set(?::jsonb, ?, ?, ?)',
      [JSON.stringify(p.values), p.justification, x.approvalId!, body.text]);
    for (const h of changedHooks) await h.run(trx, { tenantId: x.tenantId, lowersOn });
  });
  privacyMetrics.change('applied');
}

// ── Reading ──────────────────────────────────────────────────────────────

type PendingRow = { id: number; requested_by: number; created_at: Date; expires_at: Date; payload: unknown };

/** The change of the retention of the tenant waiting for its approval (the latest one; null: none). */
export async function retentionRequestWaiting(q: Q, tenantId: number): Promise<PendingRow | null> {
  const r = await q('pending_approvals').where({ tenant_id: tenantId, request_type: RETENTION_CHANGE_REQUEST_TYPE, status: 'pending' })
    .where('expires_at', '>', new Date()).orderBy('created_at', 'desc')
    .first('id', 'requested_by', 'created_at', 'expires_at', 'payload') as PendingRow | undefined;
  return r ?? null;
}

const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);

/** GET /api/privacy/retention. */
export async function retentionPolicyDto(q: Q, tenantId: number, canManage: boolean): Promise<RetentionPolicyDto> {
  const row = await retentionRow(q, tenantId);
  const inForce = await retentionValues(q, tenantId);
  const waiting = pendingActive(row);
  const categories: RetentionCategoryDto[] = RETENTION_CATEGORIES.map((c) => ({
    key: c.key, default: c.default, min: c.min, max: c.max, unit: c.unit,
    value: inForce[c.key], configured: row.values[c.key] ?? null, pending: waiting?.[c.key] ?? null,
  }));
  const req = await retentionRequestWaiting(q, tenantId);
  const payload = req ? RetentionChangePayload.safeParse(typeof req.payload === 'string' ? JSON.parse(req.payload) : req.payload) : null;
  const request: RetentionPendingRequestDto | null = req && payload?.success ? {
    approvalId: Number(req.id), requestedBy: Number(req.requested_by), requestedAt: iso(req.created_at)!, expiresAt: iso(req.expires_at)!,
    values: payload.data.values,
  } : null;
  const months = Number((await q.raw('SELECT obligarth.audit_retention_months(?) AS m', [tenantId]) as { rows: Array<{ m: number }> }).rows[0]?.m ?? 12);
  const a = await q('audit_retention').where({ tenant_id: tenantId }).first('pending_months', 'pending_effective_at') as
    { pending_months: number | null; pending_effective_at: Date | null } | undefined;
  const auditPending = a?.pending_effective_at && new Date(a.pending_effective_at).getTime() > Date.now();
  return {
    categories,
    pendingEffectiveAt: waiting ? iso(row.pendingEffectiveAt) : null,
    version: row.version,
    justification: row.justification,
    updatedBy: row.updatedBy,
    updatedAt: iso(row.updatedAt),
    request,
    fixed: fixedRetentions(),
    auditLog: {
      months,
      pendingMonths: auditPending ? Number(a!.pending_months) : null,
      pendingEffectiveAt: auditPending ? iso(a!.pending_effective_at) : null,
    },
    canManage,
  };
}
