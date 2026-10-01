import knex from 'knex';
import { runtimeConfig } from '../../knexfile';

// Every query of the server goes through this instance: the database context
// of the caller (src/db/context.ts) is set at each lease, and a query issued
// without one fails (DB_CONTEXT_MISSING).
export const db = knex(runtimeConfig);
