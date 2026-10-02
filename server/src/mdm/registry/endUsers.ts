import type { Knex } from 'knex';
import type { EndUser, EndUserImportReport } from '@obligarth/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';

// =============================================================================
// End users: the employees of the client (docs: modele-donnees-mdm §4.8,
// PLT-28). No account in Obligate nor in Obligarth. Unique per tenant, case
// insensitive, by e-mail address, Managed Apple Account and external id. A
// departure keeps the device ↔ employee link 90 days (conception §10.4), then
// the retention purges the end user and the links become NULL (composite keys
// ON DELETE SET NULL). Every function runs in the caller's database context
// (the tenant's); writes by a route go through its audit.
// =============================================================================

const EMAIL_RE = /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const EXTERNAL_ID_RE = /^[\x21-\x7e][\x20-\x7e]{0,254}$/;

export interface EndUserInput {
  email?: string | null;
  displayName?: string | null;
  managedAppleAccount?: string | null;
  externalId?: string | null;
}

/** Normalised fields, or the code of the first invalid one. */
export function normaliseEndUser(input: EndUserInput): { ok: true; value: Required<EndUserInput> } | { ok: false; code: string; field: string } {
  const clean = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
  const email = clean(input.email);
  const maa = clean(input.managedAppleAccount);
  const externalId = clean(input.externalId);
  const displayName = clean(input.displayName);
  if (email !== null && (email.length > 320 || !EMAIL_RE.test(email))) return { ok: false, code: 'invalid_email', field: 'email' };
  if (maa !== null && (maa.length > 320 || !EMAIL_RE.test(maa))) return { ok: false, code: 'invalid_managed_apple_account', field: 'managedAppleAccount' };
  if (externalId !== null && !EXTERNAL_ID_RE.test(externalId)) return { ok: false, code: 'invalid_external_id', field: 'externalId' };
  if (displayName !== null && (displayName.length > 200 || /[\u0000-\u001f\u007f]/.test(displayName))) return { ok: false, code: 'invalid_display_name', field: 'displayName' };
  if (email === null && maa === null && externalId === null) return { ok: false, code: 'identity_required', field: 'email' };
  return { ok: true, value: { email, displayName, managedAppleAccount: maa, externalId } };
}

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);

export function rowToEndUser(r: Record<string, any>): EndUser {
  const u: EndUser = {
    id: Number(r.id), uuid: r.uuid, tenantId: Number(r.tenant_id),
    externalId: r.external_id ?? null, email: r.email ?? null, displayName: r.display_name ?? null,
    managedAppleAccount: r.managed_apple_account ?? null, source: r.source, status: r.status,
    departedAt: iso(r.departed_at), createdAt: iso(r.created_at)!, updatedAt: iso(r.updated_at)!,
  };
  if (r.device_count !== undefined) u.deviceCount = Number(r.device_count);
  return u;
}

/** A 409 for a violation of one of the unique indexes (same e-mail, Managed Apple Account or external id). */
function conflictOf(err: unknown): AppError | null {
  const e = err as { code?: string; constraint?: string };
  if (e?.code !== '23505') return null;
  const field = e.constraint === 'end_users_email_uq' ? 'email'
    : e.constraint === 'end_users_maa_uq' ? 'managedAppleAccount'
      : e.constraint === 'end_users_external_uq' ? 'externalId' : null;
  return field ? new AppError(409, 'An end user of this tenant already has this identity', 'endUserExists', { field }) : null;
}

export const endUserService = {
  async list(tenantId: number, q: { status?: 'active' | 'departed'; search?: string; page?: number; pageSize?: number } = {}):
    Promise<{ items: EndUser[]; total: number; page: number; pageSize: number }> {
    const page = Math.max(1, Math.floor(q.page ?? 1));
    const pageSize = Math.min(500, Math.max(1, Math.floor(q.pageSize ?? 100)));
    const base = db('end_users as u').where('u.tenant_id', tenantId);
    if (q.status) base.where('u.status', q.status);
    if (q.search && q.search.trim()) {
      const pat = `%${q.search.trim().replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      base.where(function search() {
        this.whereILike('u.display_name', pat).orWhereILike('u.email', pat).orWhereILike('u.managed_apple_account', pat)
          .orWhereILike('u.external_id', pat);
      });
    }
    const total = Number((await base.clone().count<{ n: string }[]>('u.id as n').first())?.n ?? 0);
    const rows = await base
      .select('u.*', db.raw(`(SELECT count(*) FROM obligarth.devices d
                               WHERE d.tenant_id = u.tenant_id AND d.end_user_id = u.id
                                 AND d.enrollment_state <> 'unenrolled')::int AS device_count`))
      .orderByRaw('lower(COALESCE(u.display_name, u.email, u.managed_apple_account, u.external_id)) asc, u.id asc')
      .limit(pageSize).offset((page - 1) * pageSize);
    return { items: rows.map(rowToEndUser), total, page, pageSize };
  },

  async get(tenantId: number, id: number): Promise<EndUser | null> {
    if (!Number.isSafeInteger(id) || id <= 0) return null;
    const row = await db('end_users').where({ tenant_id: tenantId, id }).first();
    return row ? rowToEndUser(row) : null;
  },

  async create(tenantId: number, input: EndUserInput, opts: { createdBy: number | null; source?: 'manual' | 'csv' | 'directory' | 'enrollment' }): Promise<EndUser> {
    const n = normaliseEndUser(input);
    if (!n.ok) throw new AppError(400, 'Invalid end user', 'invalidRequest', { field: n.field, code: n.code });
    try {
      const [row] = await db('end_users').insert({
        tenant_id: tenantId, email: n.value.email, display_name: n.value.displayName,
        managed_apple_account: n.value.managedAppleAccount, external_id: n.value.externalId,
        source: opts.source ?? 'manual', created_by: opts.createdBy,
      }).returning('*');
      return rowToEndUser(row);
    } catch (err) {
      throw conflictOf(err) ?? err;
    }
  },

  async update(tenantId: number, id: number, input: EndUserInput): Promise<EndUser | null> {
    const current = await db('end_users').where({ tenant_id: tenantId, id }).first() as Record<string, any> | undefined;
    if (!current) return null;
    const merged: EndUserInput = {
      email: input.email !== undefined ? input.email : current.email,
      displayName: input.displayName !== undefined ? input.displayName : current.display_name,
      managedAppleAccount: input.managedAppleAccount !== undefined ? input.managedAppleAccount : current.managed_apple_account,
      externalId: input.externalId !== undefined ? input.externalId : current.external_id,
    };
    const n = normaliseEndUser(merged);
    if (!n.ok) throw new AppError(400, 'Invalid end user', 'invalidRequest', { field: n.field, code: n.code });
    try {
      const [row] = await db('end_users').where({ tenant_id: tenantId, id }).update({
        email: n.value.email, display_name: n.value.displayName, managed_apple_account: n.value.managedAppleAccount,
        external_id: n.value.externalId, updated_at: new Date(),
      }).returning('*');
      return row ? rowToEndUser(row) : null;
    } catch (err) {
      throw conflictOf(err) ?? err;
    }
  },

  /** The employee left: kept (with the device links) until the retention purges them (90 days). */
  async depart(tenantId: number, id: number, at = new Date()): Promise<EndUser | null> {
    const [row] = await db('end_users').where({ tenant_id: tenantId, id }).update({
      status: 'departed', departed_at: db.raw('COALESCE(departed_at, ?::timestamptz)', [at]), updated_at: new Date(),
    }).returning('*');
    return row ? rowToEndUser(row) : null;
  },

  /**
   * CSV import (PLT-28): header row with the columns email, display_name, managed_apple_account, external_id
   * (any order, at least one identity column); a line is matched by external id, then e-mail, then Managed
   * Apple Account (case insensitive) and updated, else created (source 'csv'); a line whose external id
   * differs from that of the end user its address designates, or whose identity belongs to another end user,
   * is refused (identity_conflict); a report line by line. 5 000 lines at most. In one transaction of the
   * tenant: a line refused by the base is reported, the others stay.
   */
  async importCsv(tenantId: number, csv: string, opts: { createdBy: number | null }): Promise<EndUserImportReport> {
    const lines = parseCsv(csv);
    if (lines.length === 0) throw new AppError(400, 'Empty file', 'invalidRequest', { code: 'empty' });
    const header = lines[0].map((h) => h.trim().toLowerCase());
    const col = (name: string) => header.indexOf(name);
    const cols = { email: col('email'), displayName: col('display_name'), maa: col('managed_apple_account'), externalId: col('external_id') };
    if (cols.email < 0 && cols.maa < 0 && cols.externalId < 0) {
      throw new AppError(400, 'The header names no identity column (email, managed_apple_account, external_id)', 'invalidRequest', { code: 'header' });
    }
    if (lines.length - 1 > 5000) throw new AppError(413, 'Too many lines (5000 at most)', 'invalidRequest', { code: 'too_many_lines' });
    const report: EndUserImportReport = { created: 0, updated: 0, unchanged: 0, rejected: 0, lines: [] };
    await db.transaction(async (trx) => {
      for (let i = 1; i < lines.length; i++) {
        const cells = lines[i];
        if (cells.every((c) => !c.trim())) continue;
        const cell = (k: number) => (k >= 0 ? (cells[k] ?? '') : undefined);
        const n = normaliseEndUser({ email: cell(cols.email), displayName: cell(cols.displayName), managedAppleAccount: cell(cols.maa), externalId: cell(cols.externalId) });
        if (!n.ok) { report.rejected++; report.lines.push({ line: i + 1, outcome: 'rejected', code: n.code }); continue; }
        const v = n.value;
        const outcome = await importOne(trx, tenantId, v, opts.createdBy).catch((err) => {
          const c = conflictOf(err);
          if (c) return { outcome: 'rejected' as const, code: 'identity_conflict' };
          throw err;
        });
        if (outcome.outcome === 'rejected') { report.rejected++; report.lines.push({ line: i + 1, outcome: 'rejected', code: outcome.code }); continue; }
        report[outcome.outcome]++;
        report.lines.push({ line: i + 1, outcome: outcome.outcome, id: outcome.id });
      }
    });
    return report;
  },
};

/** One line of an import, under its own savepoint (a refused line leaves the transaction usable). */
async function importOne(trx: Knex.Transaction, tenantId: number, v: Required<EndUserInput>, createdBy: number | null):
  Promise<{ outcome: 'created' | 'updated' | 'unchanged'; id: number } | { outcome: 'rejected'; code: string }> {
  return trx.transaction(async (sp) => {
    let existing: Record<string, any> | undefined;
    if (v.externalId) existing = await sp('end_users').where({ tenant_id: tenantId, external_id: v.externalId }).first();
    const byExternalId = !!existing;
    if (!existing && v.email) existing = await sp('end_users').where('tenant_id', tenantId).whereRaw('lower(email) = lower(?)', [v.email]).first();
    if (!existing && v.managedAppleAccount) {
      existing = await sp('end_users').where('tenant_id', tenantId).whereRaw('lower(managed_apple_account) = lower(?)', [v.managedAppleAccount]).first();
    }
    // The line's external id and the one of the end user its address designates disagree: two identities,
    // never merged silently (an operator decides).
    if (existing && !byExternalId && v.externalId && existing.external_id && existing.external_id !== v.externalId) {
      return { outcome: 'rejected' as const, code: 'identity_conflict' };
    }
    if (!existing) {
      const [row] = await sp('end_users').insert({
        tenant_id: tenantId, email: v.email, display_name: v.displayName, managed_apple_account: v.managedAppleAccount,
        external_id: v.externalId, source: 'csv', created_by: createdBy,
      }).returning('id');
      return { outcome: 'created' as const, id: Number(row.id ?? row) };
    }
    const next = {
      email: v.email ?? existing.email, display_name: v.displayName ?? existing.display_name,
      managed_apple_account: v.managedAppleAccount ?? existing.managed_apple_account, external_id: v.externalId ?? existing.external_id,
    };
    const same = next.email === existing.email && next.display_name === existing.display_name
      && next.managed_apple_account === existing.managed_apple_account && next.external_id === existing.external_id;
    if (same) return { outcome: 'unchanged' as const, id: Number(existing.id) };
    await sp('end_users').where({ tenant_id: tenantId, id: existing.id }).update({ ...next, updated_at: new Date() });
    return { outcome: 'updated' as const, id: Number(existing.id) };
  });
}

/** RFC 4180 subset: comma or semicolon separator (from the header), double quotes, CRLF or LF. */
export function parseCsv(text: string): string[][] {
  const src = text.replace(/^﻿/, '');
  const firstLine = src.split(/\r?\n/, 1)[0] ?? '';
  const sep = (firstLine.match(/;/g)?.length ?? 0) > (firstLine.match(/,/g)?.length ?? 0) ? ';' : ',';
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"') {
        if (src[i + 1] === '"') { cell += '"'; i++; } else quoted = false;
      } else cell += c;
      continue;
    }
    if (c === '"') { quoted = true; continue; }
    if (c === sep) { row.push(cell); cell = ''; continue; }
    if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = '';
      continue;
    }
    cell += c;
  }
  if (cell !== '' || row.length > 0) { row.push(cell); rows.push(row); }
  return rows.filter((r) => !(r.length === 1 && r[0] === ''));
}

/**
 * Assigns (or unassigns, null) the end user of a device of `tenantId` (§10.3): the end user must be one of
 * the tenant's (a composite key refuses another tenant's anyway). Returns false when the device or the end
 * user is not in the tenant.
 */
export async function assignEndUser(trx: Knex.Transaction, tenantId: number, deviceId: number, endUserId: number | null): Promise<boolean> {
  if (endUserId !== null) {
    const u = await trx('end_users').where({ tenant_id: tenantId, id: endUserId }).first('id');
    if (!u) return false;
  }
  const n = await trx('devices').where({ tenant_id: tenantId, id: deviceId }).update({
    end_user_id: endUserId, end_user_assigned_at: endUserId === null ? null : new Date(), updated_at: new Date(),
  });
  if (!n) return false;
  // The open episode follows the device's current end user.
  await trx('device_enrollments').where({ tenant_id: tenantId, device_id: deviceId }).whereNull('ended_at').update({ end_user_id: endUserId });
  return true;
}

/** The end user of a Managed Apple Account (BYOD enrollment, §4.8): found case insensitively, else created
 *  with source 'enrollment'. In the enrollment's transaction. */
export async function endUserForManagedAppleAccount(trx: Knex.Transaction, tenantId: number, account: string): Promise<number> {
  const n = normaliseEndUser({ managedAppleAccount: account });
  if (!n.ok) throw new AppError(400, 'Invalid Managed Apple Account', 'invalidRequest', { code: n.code });
  const found = await trx('end_users').where('tenant_id', tenantId)
    .whereRaw('lower(managed_apple_account) = lower(?)', [n.value.managedAppleAccount]).first('id');
  if (found) return Number(found.id);
  const [row] = await trx('end_users').insert({
    tenant_id: tenantId, managed_apple_account: n.value.managedAppleAccount, source: 'enrollment',
  }).returning('id');
  return Number(row.id ?? row);
}
