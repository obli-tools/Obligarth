import { db } from '../db';
import nodemailer from 'nodemailer';
import type { SmtpServer } from '@obligarth/shared';
import { vault, type SecretLocator } from '../vault';

// The password of an SMTP server is sealed by the vault (docs: coffre-secrets
// §6.3, §7.3): smtp_servers.password_enc, under the DEK of the row's tenant,
// or the instance DEK for a platform server (tenant_id NULL). The API never
// returns it (it never did); getTransportConfig, right before nodemailer
// uses it, is the only place that opens it. The tenant of the AAD is the
// row's (R1): a platform administrator who changes from the master tenant
// the server of another tenant seals under that tenant's DEK.

interface SmtpServerRow {
  id: number;
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  from_address: string;
  tenant_id: number | null;
  created_at: Date;
  updated_at: Date;
}

/** What a mapper may read (R6): never password_enc (nor the legacy column). */
const PUBLIC_COLUMNS = ['id', 'tenant_id', 'name', 'host', 'port', 'secure', 'username',
  'from_address', 'created_at', 'updated_at'] as const;
const publicColumns = (): string[] => [...PUBLIC_COLUMNS];

const passwordAt = (id: number, tenantId: number | null): SecretLocator =>
  ({ table: 'smtp_servers', column: 'password_enc', pk: id, tenantId });

export interface SmtpTransport {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromAddress: string;
}

function rowToServer(row: SmtpServerRow): SmtpServer {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    host: row.host,
    port: row.port,
    secure: row.secure,
    username: row.username,
    fromAddress: row.from_address,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

export const smtpServerService = {
  async list(tenantId?: number): Promise<SmtpServer[]> {
    const query = db('smtp_servers').select(publicColumns()).orderBy('name');
    if (tenantId !== undefined) {
      query.where({ tenant_id: tenantId });
    } else {
      query.whereNull('tenant_id');
    }
    const rows = await query as unknown as SmtpServerRow[];
    return rows.map(rowToServer);
  },

  /** UNSAFE without tenant scope (public columns only, never the password).
   *  HTTP routes MUST gate on tenant ownership before exposing the row. */
  async getPublicById(id: number): Promise<SmtpServer | null> {
    const row = await db('smtp_servers').where({ id }).first(publicColumns()) as unknown as SmtpServerRow | undefined;
    return row ? rowToServer(row) : null;
  },

  async create(data: {
    name: string;
    host: string;
    port: number;
    secure: boolean;
    username: string;
    password: string;
    fromAddress: string;
    tenantId?: number;
  }): Promise<SmtpServer> {
    return db.transaction(async (trx) => {
      const id = await vault.allocateId('smtp_servers', { trx });
      const tenantId = data.tenantId ?? null;
      const passwordEnc = data.password
        ? await vault.seal(passwordAt(id, tenantId), data.password, { trx })
        : null;
      const [row] = await trx('smtp_servers')
        .insert({
          id,
          name: data.name,
          host: data.host,
          port: data.port,
          secure: data.secure,
          username: data.username,
          password_enc: passwordEnc,
          from_address: data.fromAddress,
          tenant_id: tenantId,
        })
        .returning(publicColumns()) as SmtpServerRow[];
      return rowToServer(row);
    });
  },

  /** A password absent or '' keeps the stored one; any other string replaces
   *  it (sealed under the DEK of the row's tenant). */
  async update(id: number, data: Partial<{
    name: string;
    host: string;
    port: number;
    secure: boolean;
    username: string;
    password: string;
    fromAddress: string;
  }>, opts: { requestTenantId?: number; globalView?: boolean } = {}): Promise<SmtpServer | null> {
    return db.transaction(async (trx) => {
      const cur = await trx('smtp_servers').where({ id }).forUpdate().first('id', 'tenant_id') as
        { id: number; tenant_id: number | null } | undefined;
      if (!cur) return null;
      const update: Record<string, unknown> = { updated_at: new Date() };
      if (data.name !== undefined) update.name = data.name;
      if (data.host !== undefined) update.host = data.host;
      if (data.port !== undefined) update.port = data.port;
      if (data.secure !== undefined) update.secure = data.secure;
      if (data.username !== undefined) update.username = data.username;
      if (data.fromAddress !== undefined) update.from_address = data.fromAddress;
      if (typeof data.password === 'string' && data.password !== '') {
        update.password_enc = await vault.seal(passwordAt(cur.id, cur.tenant_id ?? null), data.password,
          { trx, requestTenantId: opts.requestTenantId, globalView: opts.globalView });
      }
      const [row] = await trx('smtp_servers').where({ id }).update(update).returning(publicColumns()) as SmtpServerRow[];
      return row ? rowToServer(row) : null;
    });
  },

  async delete(id: number): Promise<boolean> {
    const count = await db('smtp_servers').where({ id }).del();
    return count > 0;
  },

  async test(id: number, opts: { requestTenantId?: number; globalView?: boolean } = {}): Promise<void> {
    const server = await this.getTransportConfig(id, opts);
    if (!server) throw new Error('SMTP server not found');

    const transport = nodemailer.createTransport({
      host: server.host,
      port: server.port,
      secure: server.secure,
      auth: { user: server.username, pass: server.password },
    });

    // SECURITY: catch the raw nodemailer error before bubbling it up
    // — its `.message` can include the SMTP password (envelope info,
    // verbose auth-failure output) which would then surface in the
    // admin UI toast. We rewrap with a generic shape that retains
    // the FAILURE category but drops the credentials.
    try {
      await transport.verify();
    } catch (err) {
      const code = (err as { code?: string; responseCode?: number })?.code
        ?? String((err as { responseCode?: number })?.responseCode ?? 'UNKNOWN');
      throw new Error(`SMTP test failed (${code}). Check host / port / TLS / credentials.`);
    }
  },

  /** The transport of a server, password opened: the only place that opens
   *  it, right before nodemailer uses it. Never returned by an API. In a
   *  request, `requestTenantId`: a server of another tenant is refused
   *  (tenant_mismatch), a platform server (no tenant) accepted. */
  async getTransportConfig(id: number, opts: { requestTenantId?: number; globalView?: boolean } = {}): Promise<SmtpTransport | null> {
    const row = await db('smtp_servers').where({ id })
      .first('id', 'tenant_id', 'host', 'port', 'secure', 'username', 'from_address', 'password_enc') as
      (SmtpServerRow & { password_enc: string | null }) | undefined;
    if (!row) return null;
    const password = row.password_enc
      ? await vault.openString(passwordAt(row.id, row.tenant_id ?? null), row.password_enc, { requestTenantId: opts.requestTenantId, globalView: opts.globalView })
      : '';
    return {
      host: row.host,
      port: row.port,
      secure: row.secure,
      username: row.username,
      password,
      fromAddress: row.from_address,
    };
  },
};
