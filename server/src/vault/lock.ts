// Online lock of the vault (docs: coffre-secrets §6.1, §11.2). Every running
// server holds, for its whole life, a SHARED advisory lock on a dedicated
// PostgreSQL connection, outside Knex's pool; the offline commands of the CLI
// (kek-rotate, recover-lost-kek) need it EXCLUSIVE: they refuse to run while
// a server holds it (server_running), and a server refuses to start while
// such a command runs. Advisory locks are per database.
//
// The connection reads no table: it carries no database context. If it
// drops, the lock is taken again on a new connection (with a warning), at
// once, then at the next use of the vault: never with a timer.
import pg from 'pg';
import { VaultError } from './errors';

const LOCK_KEY_SQL = "hashtext('obligarth.vault.online')";
const RETRY_EVERY_MS = 30_000;

function newClient(url: string, name: string): pg.Client {
  return new pg.Client({ connectionString: url, application_name: name, keepAlive: true });
}

export class OnlineLock {
  #client: pg.Client | null = null;
  #url = '';
  #closing = false;
  #lastAttempt = 0;
  #warn: (msg: string, extra?: Record<string, unknown>) => void = () => {};

  held(): boolean {
    return this.#client !== null;
  }

  /** Takes the shared lock; VaultError('server_running') when an offline
   *  command holds it exclusively. */
  async acquireShared(url: string, warn: (msg: string, extra?: Record<string, unknown>) => void): Promise<void> {
    this.#url = url;
    this.#warn = warn;
    this.#closing = false;
    await this.#connect();
  }

  async #connect(): Promise<void> {
    if (!this.#url) throw new VaultError('kek_unavailable', null, 'no database URL for the vault lock');
    const client = newClient(this.#url, 'obligarth-vault-lock');
    this.#lastAttempt = Date.now();
    await client.connect();
    try {
      const res = await client.query(`SELECT pg_try_advisory_lock_shared(${LOCK_KEY_SQL}) AS ok`);
      if (res.rows[0]?.ok !== true) {
        throw new VaultError('server_running', null,
          'an offline vault command (kek-rotate, recover-lost-kek) holds the vault lock: wait for it to finish');
      }
    } catch (err) {
      await client.end().catch(() => undefined);
      throw err;
    }
    client.on('error', () => this.#lost());
    client.on('end', () => this.#lost());
    this.#client = client;
  }

  #lost(): void {
    if (!this.#client || this.#closing) return;
    this.#client = null;
    this.#warn('vault lock connection lost: taking the lock again');
    this.#lastAttempt = 0;   // at once, then at most every 30 s
    void this.ensure();
  }

  /** Cheap check at each use of the vault: takes the lock again in the
   *  background when its connection dropped. */
  check(): void {
    if (!this.#client && !this.#closing && this.#url) void this.ensure();
  }

  /** Takes the lock again if its connection dropped (at most every 30 s). */
  async ensure(): Promise<void> {
    if (this.#client || this.#closing || !this.#url) return;
    if (Date.now() - this.#lastAttempt < RETRY_EVERY_MS && this.#lastAttempt !== 0) return;
    try {
      await this.#connect();
      this.#warn('vault lock taken again');
    } catch (err) {
      this.#warn('vault lock could not be taken again', { code: (err as { code?: string }).code ?? 'error' });
    }
  }

  async release(): Promise<void> {
    this.#closing = true;
    const client = this.#client;
    this.#client = null;
    if (client) await client.end().catch(() => undefined);
  }
}

/** The exclusive lock of an offline CLI command, on its own connection;
 *  null when a server (or another command) holds the lock. The caller ends
 *  the client once done (which releases the lock). */
export async function tryExclusiveOnlineLock(url: string): Promise<pg.Client | null> {
  const client = newClient(url, 'obligarth-vault-cli');
  await client.connect();
  try {
    const res = await client.query(`SELECT pg_try_advisory_lock(${LOCK_KEY_SQL}) AS ok`);
    if (res.rows[0]?.ok === true) return client;
  } catch (err) {
    await client.end().catch(() => undefined);
    throw err;
  }
  await client.end().catch(() => undefined);
  return null;
}
