// Registry of the secret columns (docs: coffre-secrets §5.5): the list of
// truth of the sealed values. The DEK rotation, the verification, the
// recovery after a KEK loss and the backfill walk it; the vault refuses to
// seal or open for a column that is not registered (not_registered), so that
// no sealed value can escape the rotations.
//
// Also: the names of the instance secrets, and the columns of documents that
// hold {"$secret": "<tenant_secrets.id>"} references (garbage collection of
// tenant_secrets).
//
// No database import, and only what Node's native type stripping runs: the
// unit tests run under `node --test`. A registration error throws at start:
// a defect of the code, never of the data.

/** Where the clear value of an inherited secret still lives (expand/contract,
 *  coffre-secrets §7.2): the boot backfill moves it into the sealed column. */
export type LegacySource =
  | { kind: 'column'; column: string; encoding: 'text' | 'jsonb' }
  /** Secret fields of a JSON column (notification_channels.config): the fields
   *  of a row are given by `fieldsOf` (its plugin's secret fields);
   *  `candidates` lists every key that may be one (the SQL filter). */
  | {
    kind: 'json-fields'; column: string;
    fieldsOf: (row: Record<string, unknown>) => readonly string[];
    candidates: () => readonly string[];
  }
  /** Anything else (the Obligate settings in app_config): its own runner. */
  | { kind: 'custom'; name: string; run: () => Promise<{ moved: number; conflicts: number; skipped: number }> };

export interface SecretColumnDef {
  /** Physical table name, e.g. 'smtp_servers'. */
  table: string;
  /** Sealed column, ends with '_enc'. */
  column: string;
  /** Single primary key column ('id' or 'name'). */
  pk: string;
  /** Form of the primary key: a serial ('integer', decimal in the AAD), a
   *  server-generated UUID (lower case), or a registered instance secret
   *  name. */
  pkType: 'integer' | 'uuid' | 'name';
  /** Column holding tenants.id; null: instance scope (instance DEK). */
  tenantColumn: string | null;
  /** The tenant column may be NULL (a platform row, sealed under the
   *  instance DEK): smtp_servers. */
  tenantNullable?: boolean;
  /** Database context of the rows sealed under the instance DEK (tables
   *  without tenant column): 'identity' for the identity tables (users),
   *  'none' for the vault's own technical tables. The platform rows of a
   *  table with a nullable tenant column are always read and written in
   *  'identity' (class tenant_or_global, rls-tenant §5.1). */
  instanceContext?: 'identity' | 'none';
  encoding: 'utf8' | 'json' | 'binary';
  /** Reports and audit, e.g. 'core.smtp'. */
  owner: string;
  /** Sets obligarth.vault_reseal = 'on' while resealing (users.totp_secret_enc):
   *  a reseal never bumps users.credential_version. */
  resealFlag?: boolean;
  /** Transient values (session): excluded from rotation scans, verification
   *  and the recovery after a KEK loss. */
  transient?: boolean;
  /** Expand/contract: where the clear value still lives. */
  legacy?: LegacySource;
  /** Recovery after a KEK loss (vault recover-lost-kek): the sealed column is
   *  emptied ('null', with `lossPatch` for the other columns that must
   *  follow) or the row deleted ('delete': the column is NOT NULL). */
  onLoss?: 'null' | 'delete';
  lossPatch?: Record<string, unknown>;
}

export interface SecretReferenceHolder {
  table: string;
  column: string;
  tenantColumn: string;
  /** The tenant_secrets ids a stored value refers to. */
  refs: (value: unknown) => readonly string[];
}

const IDENT_RE = /^[a-z_][a-z0-9_]{0,62}$/;
const COLUMN_ENC_RE = /^[a-z_][a-z0-9_]{0,58}_enc$/;
const OWNER_RE = /^[a-z][a-z0-9_.-]{1,63}$/;
const INSTANCE_SECRET_NAME_RE = /^[a-z][a-z0-9_]{1,63}$/;

export class RegistryError extends Error {
  constructor(message: string) {
    super(`vault registry: ${message}`);
    this.name = 'RegistryError';
  }
}

const columns: SecretColumnDef[] = [];
const instanceSecretNames = new Map<string, string>();
const referenceHolders: SecretReferenceHolder[] = [];

function key(table: string, column: string): string {
  return `${table}.${column}`;
}

/** Declares a sealed column. Throws on a bad name, a duplicate, or a
 *  definition the vault could not walk. */
export function registerSecretColumn(def: SecretColumnDef): void {
  if (!def || typeof def !== 'object') throw new RegistryError('a definition object is required');
  const at = `${String(def.table)}.${String(def.column)}`;
  if (!IDENT_RE.test(String(def.table))) throw new RegistryError(`invalid table name in ${at}`);
  if (!COLUMN_ENC_RE.test(String(def.column))) throw new RegistryError(`${at}: a sealed column ends with "_enc"`);
  if (!IDENT_RE.test(String(def.pk))) throw new RegistryError(`${at}: invalid primary key column`);
  if (!['integer', 'uuid', 'name'].includes(def.pkType)) throw new RegistryError(`${at}: pkType must be integer, uuid or name`);
  if (def.tenantColumn !== null && !IDENT_RE.test(String(def.tenantColumn))) throw new RegistryError(`${at}: invalid tenant column`);
  if (def.tenantColumn === null && def.tenantNullable) throw new RegistryError(`${at}: tenantNullable needs a tenant column`);
  if (def.instanceContext !== undefined && !['identity', 'none'].includes(def.instanceContext)) {
    throw new RegistryError(`${at}: instanceContext must be identity or none`);
  }
  if (!['utf8', 'json', 'binary'].includes(def.encoding)) throw new RegistryError(`${at}: encoding must be utf8, json or binary`);
  if (!OWNER_RE.test(String(def.owner))) throw new RegistryError(`${at}: invalid owner`);
  if (def.pkType === 'name' && def.tenantColumn !== null) throw new RegistryError(`${at}: a named secret has no tenant`);
  if (def.onLoss !== undefined && !['null', 'delete'].includes(def.onLoss)) throw new RegistryError(`${at}: onLoss must be null or delete`);
  if (def.lossPatch !== undefined) {
    for (const k of Object.keys(def.lossPatch)) if (!IDENT_RE.test(k)) throw new RegistryError(`${at}: invalid lossPatch column`);
  }
  const legacy = def.legacy;
  if (legacy) {
    if (legacy.kind === 'column' || legacy.kind === 'json-fields') {
      if (!IDENT_RE.test(String(legacy.column)) || legacy.column === def.column) throw new RegistryError(`${at}: invalid legacy column`);
      if (legacy.kind === 'column' && !['text', 'jsonb'].includes(legacy.encoding)) throw new RegistryError(`${at}: invalid legacy encoding`);
      if (legacy.kind === 'json-fields' && (typeof legacy.fieldsOf !== 'function' || typeof legacy.candidates !== 'function')) {
        throw new RegistryError(`${at}: fieldsOf and candidates are required`);
      }
    } else if (legacy.kind === 'custom') {
      if (!IDENT_RE.test(String(legacy.name)) || typeof legacy.run !== 'function') throw new RegistryError(`${at}: invalid custom legacy source`);
    } else {
      throw new RegistryError(`${at}: unknown legacy source`);
    }
  }
  if (columns.some((c) => key(c.table, c.column) === at)) throw new RegistryError(`${at} registered twice`);
  columns.push(Object.freeze({ ...def }));
}

/** Every registered column, in registration order. */
export function secretColumns(): readonly SecretColumnDef[] {
  return columns.slice();
}

/** The definition of a column, or undefined. */
export function secretColumn(table: string, column: string): SecretColumnDef | undefined {
  return columns.find((c) => c.table === table && c.column === column);
}

/** Declares the name of an instance secret (instance_secrets.name). */
export function registerInstanceSecretName(name: string, description: string): void {
  if (!INSTANCE_SECRET_NAME_RE.test(String(name))) throw new RegistryError(`invalid instance secret name ${JSON.stringify(name)}`);
  if (typeof description !== 'string' || !description.trim()) throw new RegistryError(`instance secret ${name}: a description is required`);
  if (instanceSecretNames.has(name)) throw new RegistryError(`instance secret ${name} registered twice`);
  instanceSecretNames.set(name, description.trim());
}

export function isInstanceSecretName(name: unknown): name is string {
  return typeof name === 'string' && instanceSecretNames.has(name);
}

export function instanceSecretNameList(): Array<{ name: string; description: string }> {
  return [...instanceSecretNames].map(([name, description]) => ({ name, description }));
}

/** Declares a column of documents that hold {"$secret": "<id>"} references
 *  (garbage collection of tenant_secrets, coffre-secrets §6.4). */
export function registerSecretReferenceHolder(def: SecretReferenceHolder): void {
  const at = `${String(def?.table)}.${String(def?.column)}`;
  if (!def || !IDENT_RE.test(String(def.table)) || !IDENT_RE.test(String(def.column)) || !IDENT_RE.test(String(def.tenantColumn))) {
    throw new RegistryError(`invalid reference holder ${at}`);
  }
  if (typeof def.refs !== 'function') throw new RegistryError(`reference holder ${at}: refs missing`);
  if (referenceHolders.some((h) => key(h.table, h.column) === at)) throw new RegistryError(`reference holder ${at} registered twice`);
  referenceHolders.push(Object.freeze({ ...def }));
}

export function secretReferenceHolders(): readonly SecretReferenceHolder[] {
  return referenceHolders.slice();
}

/** The {"$secret": "<uuid>"} references found in a document, at any depth. */
export function findSecretRefs(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 32 || value === null || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    for (const v of value) findSecretRefs(v, out, depth + 1);
    return out;
  }
  const o = value as Record<string, unknown>;
  const ref = o.$secret;
  if (typeof ref === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(ref)) out.push(ref);
  for (const v of Object.values(o)) findSecretRefs(v, out, depth + 1);
  return out;
}
