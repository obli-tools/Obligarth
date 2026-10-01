// Boot backfill of the inherited clear secrets (docs: coffre-secrets §7.2;
// review COF-RC3: one database context per class of table). For every
// registered column that declares a legacy source:
//   1. the legacy column no longer exists (the contract migration ran): nothing
//      to do (an image N still starts after the migration N+1);
//   2. scope by scope (scopes.ts: users in 'identity', the platform SMTP
//      servers in 'identity', then each tenant's rows in its own context), by
//      batches of 200 rows, each batch in its own transaction, under
//      pg_advisory_xact_lock(hashtext('obligarth.vault.backfill')) and, for
//      users, the reseal flag (credential_version unchanged, phone keys kept):
//      the clear value is sealed into the twin column and the clear column
//      emptied (compare-and-set);
//   3. a sealed value already present next to a clear one: the sealed one is
//      kept, the clear one emptied, warning vault.backfill_conflict
//      (coordinates only); notification channels lose every secret field of
//      their plugin from `config`, the ones with a value moving into
//      secrets_enc (merged with a sealed one) and their names into
//      secret_fields; the Obligate settings move into instance_secrets;
//   4. a database or encryption error is fatal (refusal to start); a value
//      that cannot be read (invalid JSON) stays where it is, with a warning
//      vault.backfill_skipped, and is counted as remaining;
//   5. when something moved: an operation 'backfill' (done, counts), the
//      entry vault.backfill_completed (master tenant), and the remaining
//      counts in the vault's state (obligarth_vault_backfill_remaining);
//   6. idempotent: a second boot finds nothing.
import type { Knex } from 'knex';
import { db } from '../db';
import { asIdentity, asNone, type DbActor } from '../db/context';
import { logger } from '../utils/logger';
import { isVaultError } from './errors';
import { masterEntry, writeVaultAudit } from './events';
import { vaultOperations } from './operations';
import { secretColumns, type SecretColumnDef } from './registry';
import { setResealFlag } from './reseal';
import { scopesOf, type RowScope } from './scopes';
import { vault, vaultInternals, type SecretLocator } from './vault';

export interface BackfillCounts { moved: number; conflicts: number; skipped: number }
export type BackfillReport = Record<string, BackfillCounts>;

const BATCH = 200;
const LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext('obligarth.vault.backfill'))";
const BACKFILL_ACTOR: DbActor = { type: 'job', name: 'vault.backfill' };

/** A failure of the backfill: the server refuses to start. */
export class BackfillError extends Error {
  constructor(readonly table: string, readonly column: string, readonly pk: string, readonly code: string) {
    super(`Vault backfill failed on ${table}.${column} (${pk}): ${code}`);
    this.name = 'BackfillError';
  }
}

function codeOf(err: unknown): string {
  if (isVaultError(err)) return err.code;
  const c = (err as { code?: unknown } | null)?.code;
  return typeof c === 'string' && /^[A-Za-z0-9_]{1,32}$/.test(c) ? c : 'error';
}

/** Does the column still exist (the contract migration drops it)? */
async function columnExists(table: string, column: string): Promise<boolean> {
  const res = await asNone(BACKFILL_ACTOR, () => db.raw(
    `SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass(?) AND attname = ? AND attnum > 0 AND NOT attisdropped`,
    [`obligarth.${table}`, column],
  )) as { rows: unknown[] };
  return res.rows.length > 0;
}

function locatorOf(def: SecretColumnDef, row: Record<string, unknown>): SecretLocator {
  return {
    table: def.table, column: def.column, pk: row[def.pk] as string | number,
    tenantId: def.tenantColumn && row[def.tenantColumn] != null ? Number(row[def.tenantColumn]) : null,
  };
}

function hasValue(v: unknown): boolean {
  return v !== null && v !== undefined && !(typeof v === 'string' && v === '');
}

/** One row of a 'column' source. */
async function moveColumn(trx: Knex.Transaction, def: SecretColumnDef, legacyCol: string, encoding: 'text' | 'jsonb',
  row: Record<string, unknown>, c: BackfillCounts): Promise<void> {
  const loc = locatorOf(def, row);
  const clear = row[legacyCol];
  const where = trx(def.table).where(def.pk, row[def.pk] as string | number);
  if (row[def.column] != null) {
    // A sealed value already there: it wins, the clear one goes.
    await where.update({ [legacyCol]: null });
    c.conflicts++;
    logger.warn({ vault: { event: 'vault.backfill_conflict', table: def.table, column: def.column, pk: String(loc.pk), tenantId: loc.tenantId } },
      'vault backfill: a sealed value and a clear one, the sealed one kept');
    return;
  }
  // A jsonb value comes parsed from the driver: sealed as it is.
  const sealed = encoding === 'jsonb'
    ? await vault.sealJson(loc, clear, { trx })
    : await vault.seal(loc, String(clear), { trx });
  const n = await where.clone().modify((qb) => { if (encoding === 'text') qb.where(legacyCol, String(clear)); })
    .update({ [def.column]: sealed, [legacyCol]: null });
  if (n) c.moved++;
}

/** One row of a 'json-fields' source (notification channels). */
async function moveJsonFields(trx: Knex.Transaction, def: SecretColumnDef, legacyCol: string,
  fields: readonly string[], row: Record<string, unknown>, c: BackfillCounts): Promise<'moved' | 'none' | 'skipped'> {
  const loc = locatorOf(def, row);
  const raw = row[legacyCol];
  let cfg: Record<string, unknown>;
  try {
    cfg = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, unknown>;
  } catch {
    cfg = null as unknown as Record<string, unknown>;
  }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return 'skipped';
  const present = fields.filter((f) => Object.prototype.hasOwnProperty.call(cfg, f));
  if (!present.length) return 'none';
  let secrets: Record<string, unknown> = {};
  if (row[def.column] != null) {
    secrets = await vault.openJson<Record<string, unknown>>(loc, String(row[def.column]), { trx });
  }
  let conflict = false;
  for (const f of present) {
    if (hasValue(cfg[f])) {
      if (hasValue(secrets[f])) conflict = true;
      else secrets[f] = cfg[f];
    }
  }
  const publicCfg: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(cfg)) if (!fields.includes(k)) publicCfg[k] = v;
  const names = Object.keys(secrets).filter((k) => hasValue(secrets[k])).sort();
  const sealed = names.length ? await vault.sealJson(loc, Object.fromEntries(names.map((k) => [k, secrets[k]])), { trx }) : null;
  await trx(def.table).where(def.pk, row[def.pk] as string | number).update({
    [legacyCol]: JSON.stringify(publicCfg),
    [def.column]: sealed,
    secret_fields: JSON.stringify(names),
  });
  if (conflict) {
    c.conflicts++;
    logger.warn({ vault: { event: 'vault.backfill_conflict', table: def.table, column: def.column, pk: String(loc.pk), tenantId: loc.tenantId } },
      'vault backfill: a sealed value and a clear one, the sealed one kept');
  }
  c.moved++;
  return 'moved';
}

/** One scope of a column: batches of 200 rows, a pk cursor (a row left in
 *  place is never read twice). */
async function backfillScope(def: SecretColumnDef, scope: RowScope, c: BackfillCounts): Promise<void> {
  const legacy = def.legacy;
  if (!legacy || legacy.kind === 'custom') return;
  const legacyCol = legacy.column;
  let after: string | number | null = null;
  for (;;) {
    const res = await scope.run(() => db.transaction(async (trx) => {
      await trx.raw(LOCK_SQL);
      if (def.resealFlag) await setResealFlag(trx);
      const cols = ['*'];
      let qb = scope.filter(trx(def.table).select(cols));
      if (legacy.kind === 'column') qb = qb.whereNotNull(legacyCol);
      // jsonb_exists_any rather than the ?| operator (a bind placeholder for
      // Knex); the keys never hold a comma.
      else qb = qb.whereRaw("jsonb_exists_any(??, string_to_array(?, ','))", [legacyCol, legacy.candidates().join(',')]);
      if (after !== null) qb = qb.where(def.pk, '>', after);
      const rows = await qb.orderBy(def.pk).limit(BATCH).forUpdate() as Array<Record<string, unknown>>;
      for (const row of rows) {
        try {
          if (legacy.kind === 'column') {
            await moveColumn(trx, def, legacyCol, legacy.encoding, row, c);
          } else {
            const fields = legacy.fieldsOf(row);
            const out = await moveJsonFields(trx, def, legacyCol, fields, row, c);
            if (out === 'skipped' || (out === 'none' && fields.length === 0)) {
              c.skipped++;
              logger.warn({ vault: { event: 'vault.backfill_skipped', table: def.table, column: def.column, pk: String(row[def.pk]) } },
                'vault backfill: a legacy value could not be classified, left in place');
            }
          }
        } catch (err) {
          if (err instanceof SyntaxError) {
            c.skipped++;
            logger.warn({ vault: { event: 'vault.backfill_skipped', table: def.table, column: def.column, pk: String(row[def.pk]) } },
              'vault backfill: a legacy value is not valid JSON, left in place');
            continue;
          }
          throw new BackfillError(def.table, def.column, String(row[def.pk]), codeOf(err));
        }
      }
      return { n: rows.length, last: rows.length ? rows[rows.length - 1][def.pk] as string | number : null };
    }));
    if (res.n < BATCH || res.last === null) break;
    after = res.last;
  }
}

/** The Obligate settings (app_config.obligate_config): apiKey and
 *  inboundSecret into instance_secrets, the JSON rewritten without them;
 *  the identity context (app_config is a catalog written there). */
export async function backfillObligateSettings(): Promise<BackfillCounts> {
  const c: BackfillCounts = { moved: 0, conflicts: 0, skipped: 0 };
  await asIdentity(BACKFILL_ACTOR, () => db.transaction(async (trx) => {
    await trx.raw(LOCK_SQL);
    const row = await trx('app_config').where({ key: 'obligate_config' }).forUpdate().first('value') as { value: string } | undefined;
    if (!row?.value) return;
    let cfg: Record<string, unknown>;
    try {
      cfg = JSON.parse(row.value) as Record<string, unknown>;
    } catch {
      cfg = null as unknown as Record<string, unknown>;
    }
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
      c.skipped++;
      logger.warn({ vault: { event: 'vault.backfill_skipped', table: 'app_config', column: 'value', pk: 'obligate_config' } },
        'vault backfill: obligate_config is not a JSON object, left in place');
      return;
    }
    let changed = false;
    for (const [field, name] of [['apiKey', 'obligate_api_key'], ['inboundSecret', 'obligate_inbound_secret']] as const) {
      if (!(field in cfg)) continue;
      const v = cfg[field];
      if (typeof v === 'string' && v !== '') {
        const existing = await trx('instance_secrets').where({ name }).first('name');
        if (existing) {
          c.conflicts++;
          logger.warn({ vault: { event: 'vault.backfill_conflict', table: 'instance_secrets', column: 'value_enc', pk: name } },
            'vault backfill: a sealed value and a clear one, the sealed one kept');
        } else {
          await vault.setInstanceSecret(name, v, { userId: null }, { trx });
          c.moved++;
        }
      }
      delete cfg[field];
      changed = true;
    }
    if (changed) await trx('app_config').where({ key: 'obligate_config' }).update({ value: JSON.stringify(cfg) });
  }));
  return c;
}

/** Runs the backfill (boot, CLI `vault backfill`). Throws BackfillError (or
 *  a database error): the server refuses to start. */
export async function backfillLegacySecrets(): Promise<BackfillReport> {
  vaultInternals.requireReady();
  const report: BackfillReport = {};
  for (const def of secretColumns()) {
    const legacy = def.legacy;
    if (!legacy) continue;
    const label = legacy.kind === 'custom' ? `${def.table}.${legacy.name}` : `${def.table}.${legacy.column}`;
    if (legacy.kind === 'custom') {
      report[label] = await legacy.run();
      continue;
    }
    if (!(await columnExists(def.table, legacy.column))) continue;   // contracted: nothing left
    const c: BackfillCounts = { moved: 0, conflicts: 0, skipped: 0 };
    for (const scope of await scopesOf(def, BACKFILL_ACTOR)) await backfillScope(def, scope, c);
    report[label] = c;
  }
  const remaining = Object.fromEntries(Object.entries(report).map(([k, v]) => [k, v.skipped]));
  vaultInternals.setBackfillReport(remaining);
  const moved = Object.values(report).reduce((n, v) => n + v.moved, 0);
  if (moved > 0) {
    await asNone(BACKFILL_ACTOR, async () => {
      const op = await vaultOperations.create(db, {
        kind: 'backfill', state: 'done', startedAt: new Date(), finishedAt: new Date(), progress: { report },
      });
      await writeVaultAudit([masterEntry('vault.backfill_completed', { operationId: op.id, report })]);
    });
    logger.info({ report }, 'vault backfill: inherited clear secrets moved into the vault');
  }
  if (Object.values(remaining).some((n) => n > 0)) {
    logger.warn({ remaining }, 'vault backfill: some legacy values were left in place (see vault.backfill_skipped)');
  }
  return report;
}
