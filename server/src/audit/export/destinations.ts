// SIEM destinations (docs: audit-durci §8.1): configured by the platform
// administrators on the master tenant; scope_tenant_id NULL: every chain (the
// MSP's SIEM), set: one tenant's chain (a client's SIEM, connected by the MSP).
// Settings in clear (config), secrets sealed by the vault under the instance
// key (secrets_enc: syslog { clientKeyPem? }, webhook { hmacSecret,
// bearerToken? }), never returned, except the webhook's HMAC secret, drawn by
// the server and shown once at the creation or a rotation. The id is reserved
// before the insertion (coffre R7). Every change writes its critical entry in
// the same transaction (P1), in the master tenant and, for a destination of a
// tenant, in that tenant's chain too.
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { Knex } from 'knex';
import { MASTER_TENANT_ID, type AuditDestinationDto } from '@obligarth/shared';
import { config } from '../../config';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { vault, type SecretLocator } from '../../vault';
import { isVaultError } from '../../vault/errors';
import { registerSecretColumn, secretColumn } from '../../vault/registry';
import { assertSiemTarget } from '../../utils/ssrfGuard';
import type { AuditWriteContext } from '../types';
import { appendManyInTx } from '../writer';

export const SyslogTlsConfig = z.object({
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535).default(6514),
  serverName: z.string().max(253).optional(),
  caPem: z.string().max(20_000).optional(),
  clientCertPem: z.string().max(20_000).optional(),
  hostname: z.string().max(255).optional(),
  maxMessageBytes: z.number().int().min(8192).max(1_048_576).default(65_536),
  includeEvent: z.boolean().default(true),
}).strict();

export const WebhookConfig = z.object({
  url: z.string().url().max(2000).refine((u) => u.startsWith('https://'), 'https only'),
  maxBatch: z.number().int().min(1).max(1000).default(200),
  maxBatchBytes: z.number().int().min(65_536).max(10_485_760).default(1_048_576),
  timeoutSeconds: z.number().int().min(2).max(60).default(10),
  includeEvent: z.boolean().default(true),
  /** Trust anchor of a private SIEM (absent: the system's authorities). */
  caPem: z.string().max(20_000).optional(),
}).strict();

export type DestinationSecrets = { clientKeyPem?: string } | { hmacSecret: string; bearerToken?: string };

export const CreateDestinationInput = z.object({
  name: z.string().trim().min(1).max(100),
  kind: z.enum(['syslog_tls', 'webhook']),
  scopeTenantId: z.number().int().positive().nullable().default(null),
  config: z.record(z.unknown()),
  /** syslog_tls: the client certificate's key; webhook: a bearer token. */
  clientKeyPem: z.string().max(20_000).optional(),
  bearerToken: z.string().max(2_000).optional(),
  enabled: z.boolean().default(true),
  requiredForPurge: z.boolean().default(true),
  includeSeals: z.boolean().default(true),
  startFrom: z.enum(['beginning', 'now']).default('beginning'),
}).strict();

export const UpdateDestinationInput = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  config: z.record(z.unknown()).optional(),
  clientKeyPem: z.string().max(20_000).optional(),
  bearerToken: z.string().max(2_000).nullable().optional(),
  enabled: z.boolean().optional(),
  requiredForPurge: z.boolean().optional(),
  includeSeals: z.boolean().optional(),
}).strict();

export type CreateDestination = z.infer<typeof CreateDestinationInput>;
export type UpdateDestination = z.infer<typeof UpdateDestinationInput>;

const TABLE = 'audit_export_destinations';

/** Declares the sealed column to the vault (rotations, verification). */
export function registerDestinationSecretColumn(): void {
  if (secretColumn(TABLE, 'secrets_enc')) return;
  registerSecretColumn({
    table: TABLE, column: 'secrets_enc', pk: 'id', pkType: 'integer', tenantColumn: null, instanceContext: 'none',
    encoding: 'json', owner: 'audit.export', onLoss: 'null',
  });
}

const locator = (id: number): SecretLocator => ({ table: TABLE, column: 'secrets_enc', pk: id, tenantId: null });

/** The settings of a destination, checked by its kind's schema. */
export function parseConfig(kind: string, raw: unknown): Record<string, unknown> {
  const schema = kind === 'webhook' ? WebhookConfig : SyslogTlsConfig;
  const r = schema.safeParse(raw ?? {});
  if (!r.success) throw new AppError(400, `Invalid destination settings: ${r.error.errors.map((e) => `${e.path.join('.')} ${e.message}`).join('; ')}`, 'invalidDestination');
  return r.data as Record<string, unknown>;
}

/** The network target of the settings must be admitted (§8.1). */
export async function checkTarget(kind: string, cfg: Record<string, unknown>): Promise<void> {
  const host = kind === 'webhook' ? new URL(String(cfg.url)).hostname : String(cfg.host);
  try {
    await assertSiemTarget(host, { allowLoopback: config.audit.siemAllowLoopback });
  } catch (err) {
    throw new AppError(400, (err as Error).message, 'siemTargetRefused');
  }
}

export interface DestinationRow {
  id: number; uuid: string; name: string; kind: 'syslog_tls' | 'webhook'; scope_tenant_id: number | null; config: Record<string, unknown>;
  secrets_enc: string | null; enabled: boolean; required_for_purge: boolean; include_seals: boolean; last_seal_seq: string | number;
  last_success_at: Date | null; last_error_at: Date | null; last_error_code: string | null; created_at: Date; updated_at: Date;
}

/** The secrets of a destination (the exporter's, at the last moment). */
export async function openSecrets(row: Pick<DestinationRow, 'id' | 'secrets_enc'>): Promise<DestinationSecrets> {
  if (!row.secrets_enc) return {};
  return vault.openJson<DestinationSecrets>(locator(row.id), row.secrets_enc);
}

async function secretNames(row: Pick<DestinationRow, 'id' | 'secrets_enc'>): Promise<string[]> {
  try {
    const s = await openSecrets(row) as Record<string, unknown>;
    return Object.keys(s).filter((k) => typeof s[k] === 'string' && s[k] !== '').sort();
  } catch (err) {
    return isVaultError(err) ? ['unreadable'] : [];
  }
}

export async function destinationDto(row: DestinationRow, lagSeconds: number | null = null): Promise<AuditDestinationDto> {
  const cfg = typeof row.config === 'string' ? JSON.parse(row.config) : row.config;
  return {
    id: Number(row.id),
    uuid: row.uuid,
    name: row.name,
    kind: row.kind,
    scopeTenantId: row.scope_tenant_id != null ? Number(row.scope_tenant_id) : null,
    config: cfg ?? {},
    secretsSet: await secretNames(row),
    enabled: row.enabled,
    requiredForPurge: row.required_for_purge,
    includeSeals: row.include_seals,
    lastSealSeq: Number(row.last_seal_seq),
    lastSuccessAt: row.last_success_at ? new Date(row.last_success_at).toISOString() : null,
    lastErrorAt: row.last_error_at ? new Date(row.last_error_at).toISOString() : null,
    lastErrorCode: row.last_error_code,
    lagSeconds,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export async function getDestination(id: number, q: Knex | Knex.Transaction = db): Promise<DestinationRow | undefined> {
  return q(TABLE).where({ id }).first() as Promise<DestinationRow | undefined>;
}

export async function listDestinationRows(): Promise<DestinationRow[]> {
  return db(TABLE).orderBy('id') as Promise<DestinationRow[]>;
}

/** The entries of a destination change: the master tenant, and the scoped
 *  tenant for a destination of a tenant (written in ascending order). */
function changeEntries(action: string, row: { id: number; name: string; kind: string; scope_tenant_id: number | null },
  details: Record<string, unknown>) {
  const base = { action, target: { type: 'destination', id: String(row.id) }, details: { name: row.name, kind: row.kind, ...details } };
  const out = [{ tenantId: MASTER_TENANT_ID, ...base, onBehalfOf: row.scope_tenant_id ?? undefined }];
  if (row.scope_tenant_id && row.scope_tenant_id !== MASTER_TENANT_ID) out.push({ tenantId: row.scope_tenant_id, ...base, onBehalfOf: row.scope_tenant_id });
  return out;
}

/** Cursors at the current heads (startFrom 'now'). */
async function cursorsAtHeads(trx: Knex.Transaction, destinationId: number, scope: number | null): Promise<void> {
  const chains = (await trx.raw('SELECT tenant_id, last_seq FROM obligarth.audit_chains()') as {
    rows: Array<{ tenant_id: number; last_seq: string | number }>;
  }).rows.filter((c) => scope === null || Number(c.tenant_id) === scope);
  for (const c of chains) {
    await trx('audit_export_cursors').insert({ destination_id: destinationId, tenant_id: c.tenant_id, last_seq: Number(c.last_seq), last_sent_at: null })
      .onConflict(['destination_id', 'tenant_id']).merge();
  }
  const lastSeal = await trx('audit_seals').max({ s: 'seal_seq' }).first() as { s: string | number | null } | undefined;
  await trx(TABLE).where({ id: destinationId }).update({ last_seal_seq: Number(lastSeal?.s ?? 0) });
}

/** Creates a destination; the webhook's HMAC secret is returned once. */
export async function createDestination(input: CreateDestination, ctx: AuditWriteContext, userId: number | null): Promise<{ destination: AuditDestinationDto; hmacSecret?: string }> {
  const cfg = parseConfig(input.kind, input.config);
  await checkTarget(input.kind, cfg);
  if (input.scopeTenantId !== null) {
    const exists = await db('tenants').where({ id: input.scopeTenantId }).first('id');
    if (!exists) throw new AppError(404, 'Tenant not found');
  }
  const secrets: Record<string, string> = {};
  let hmacSecret: string | undefined;
  if (input.kind === 'webhook') {
    hmacSecret = randomBytes(32).toString('base64url');
    secrets.hmacSecret = hmacSecret;
    if (input.bearerToken) secrets.bearerToken = input.bearerToken;
  } else if (input.clientKeyPem) {
    secrets.clientKeyPem = input.clientKeyPem;
  }
  const row = await db.transaction(async (trx) => {
    const id = await vault.allocateId(TABLE, { trx });
    const sealed = Object.keys(secrets).length ? await vault.sealJson(locator(id), secrets, { trx }) : null;
    const [r] = await trx(TABLE).insert({
      id, name: input.name, kind: input.kind, scope_tenant_id: input.scopeTenantId, config: JSON.stringify(cfg),
      secrets_enc: sealed, enabled: input.enabled, required_for_purge: input.requiredForPurge, include_seals: input.includeSeals,
      created_by: userId,
    }).returning('*') as DestinationRow[];
    if (input.startFrom === 'now') await cursorsAtHeads(trx, id, input.scopeTenantId);
    await appendManyInTx(trx, changeEntries('audit.destination_created', r, {
      scopeTenantId: input.scopeTenantId, startFrom: input.startFrom, requiredForPurge: input.requiredForPurge, enabled: input.enabled,
      target: input.kind === 'webhook' ? new URL(String(cfg.url)).hostname : `${String(cfg.host)}:${String(cfg.port)}`,
    }), ctx);
    return r;
  });
  return { destination: await destinationDto(await getDestination(row.id) as DestinationRow), hmacSecret };
}

/** Is this patch a "pause of the journal" (RE 2024/2690 3.2.3 (k)): disabling,
 *  or no longer required for the purge? Or does it divert or weaken the
 *  copy: a new target (config: host, port, URL) or the seals no longer sent
 *  (review of lot A6, AUD-A6-R9; integration of lot A)? Such a patch needs
 *  'restricted' (a second administrator), like a deletion. */
export function patchStopsCopy(row: Pick<DestinationRow, 'enabled' | 'required_for_purge' | 'include_seals'>, patch: UpdateDestination): boolean {
  return (patch.enabled === false && row.enabled) || (patch.requiredForPurge === false && row.required_for_purge)
    || patch.config !== undefined || (patch.includeSeals === false && row.include_seals);
}

/** The approval description of such a patch (English, server-built). */
export function stopDescription(row: Pick<DestinationRow, 'name'>, patch: UpdateDestination): string {
  const what = [
    patch.enabled === false ? 'disable' : null,
    patch.requiredForPurge === false ? 'make optional for the purge' : null,
    patch.config !== undefined ? 'change the target of' : null,
    patch.includeSeals === false ? 'stop sending the seals to' : null,
  ].filter(Boolean).join(', ');
  return `${what.charAt(0).toUpperCase()}${what.slice(1)} the SIEM destination "${row.name}"`;
}

export async function updateDestination(id: number, patch: UpdateDestination, ctx: AuditWriteContext): Promise<AuditDestinationDto> {
  const row = await getDestination(id);
  if (!row) throw new AppError(404, 'Destination not found');
  const cfg = patch.config !== undefined ? parseConfig(row.kind, patch.config) : null;
  if (cfg) await checkTarget(row.kind, cfg);
  await db.transaction(async (trx) => {
    const locked = await trx(TABLE).where({ id }).forUpdate().first() as DestinationRow | undefined;
    if (!locked) throw new AppError(404, 'Destination not found');
    const update: Record<string, unknown> = { updated_at: trx.fn.now() };
    const changed: string[] = [];
    if (patch.name !== undefined && patch.name !== locked.name) { update.name = patch.name; changed.push('name'); }
    if (cfg) { update.config = JSON.stringify(cfg); changed.push('config'); }
    if (patch.enabled !== undefined && patch.enabled !== locked.enabled) { update.enabled = patch.enabled; changed.push('enabled'); }
    if (patch.requiredForPurge !== undefined && patch.requiredForPurge !== locked.required_for_purge) { update.required_for_purge = patch.requiredForPurge; changed.push('requiredForPurge'); }
    if (patch.includeSeals !== undefined && patch.includeSeals !== locked.include_seals) { update.include_seals = patch.includeSeals; changed.push('includeSeals'); }
    if (patch.clientKeyPem !== undefined || patch.bearerToken !== undefined) {
      const current = await openSecrets(locked) as Record<string, string>;
      const next = { ...current };
      if (locked.kind === 'syslog_tls' && patch.clientKeyPem !== undefined) next.clientKeyPem = patch.clientKeyPem;
      if (locked.kind === 'webhook' && patch.bearerToken !== undefined) {
        if (patch.bearerToken === null || patch.bearerToken === '') delete next.bearerToken; else next.bearerToken = patch.bearerToken;
      }
      update.secrets_enc = Object.keys(next).length ? await vault.sealJson(locator(id), next, { trx }) : null;
      changed.push('secrets');
    }
    await trx(TABLE).where({ id }).update(update);
    const disabled = patch.enabled === false && locked.enabled;
    await appendManyInTx(trx, changeEntries(disabled ? 'audit.destination_disabled' : 'audit.destination_updated', locked, {
      changed, enabled: patch.enabled ?? locked.enabled, requiredForPurge: patch.requiredForPurge ?? locked.required_for_purge,
    }), ctx);
  });
  return destinationDto(await getDestination(id) as DestinationRow);
}

export async function deleteDestination(id: number, ctx: AuditWriteContext): Promise<void> {
  await db.transaction(async (trx) => {
    const row = await getDestination(id, trx);
    if (!row) throw new AppError(404, 'Destination not found');
    await trx(TABLE).where({ id }).delete();      // cursors cascade
    await appendManyInTx(trx, changeEntries('audit.destination_deleted', row, {}), ctx);
  });
}

/** A new HMAC secret for a webhook, returned once. */
export async function rotateDestinationSecret(id: number, ctx: AuditWriteContext): Promise<string> {
  const hmacSecret = randomBytes(32).toString('base64url');
  await db.transaction(async (trx) => {
    const row = await getDestination(id, trx);
    if (!row) throw new AppError(404, 'Destination not found');
    if (row.kind !== 'webhook') throw new AppError(400, 'Only a webhook has a signing secret', 'notWebhook');
    const current = await openSecrets(row) as Record<string, string>;
    const sealed = await vault.sealJson(locator(id), { ...current, hmacSecret }, { trx });
    await trx(TABLE).where({ id }).update({ secrets_enc: sealed, updated_at: trx.fn.now() });
    await appendManyInTx(trx, changeEntries('audit.destination_updated', row, { changed: ['secretRotated'] }), ctx);
  });
  return hmacSecret;
}
