// The PostgreSQL dialect of Knex (3.3.0, pinned in package.json): the
// base class of the context-aware client (db/contextPgClient.ts), with the
// internal methods it overrides. Knex ships no declaration for this path.
declare module 'knex/lib/dialects/postgres' {
  import type { Knex } from 'knex';

  class ClientPG extends Knex.Client {
    acquireConnection(): Promise<any>;
    releaseConnection(connection: any): Promise<void>;
    _query(connection: any, obj: any): Promise<any>;
    _stream(connection: any, obj: any, stream: any, options: any): Promise<any>;
    queryBuilder(): any;
    raw(...args: any[]): any;
    runner(builder: any): any;
    transaction(container: any, config: any, outerTx: any): any;
  }

  export = ClientPG;
}
