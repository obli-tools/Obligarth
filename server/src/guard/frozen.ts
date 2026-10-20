// Is a tenant frozen for the commands of a channel (docs: audit-durci §10.7; android-amapi §11.4, COH-9, lot AN-P)?
// The emergency freeze of the guard engine (tenant_guard_settings.frozen_at) holds for every platform; a channel may
// add a mirror of a freeze set elsewhere (registerFreezeMirror): the freeze held by apple-edge for the Apple channel
// (tenant_apple_edge.commands_frozen), and, by decision PONT-R (agent-pont-android, review PONT-R), for the queue of
// the Android bridge agent too. The channel amapi reads the engine's freeze only (its gateway checks it before every
// destructive call, AN15). Read in the caller's transaction (tenant context).
import type { Knex } from 'knex';
import { db } from '../db';
import { readSettings } from './settings';
import type { ManagementChannel } from './types';

/** A freeze set outside the engine, as the brain mirrors it (true: frozen). */
export type FreezeMirror = (q: Knex | Knex.Transaction, tenantId: number) => Promise<boolean>;

const mirrors = new Map<ManagementChannel, FreezeMirror>();

/** The mirror of a channel (one per channel, registered by its module before anything runs). */
export function registerFreezeMirror(channel: ManagementChannel, fn: FreezeMirror): void {
  if (mirrors.has(channel)) throw new Error(`freeze mirror of ${channel}: registered twice`);
  mirrors.set(channel, fn);
}

/** Frozen for the commands of `channel`: the engine's freeze, or the channel's mirror. `trx` null: read outside a
 *  transaction (the caller's database context). */
export async function tenantFrozen(trx: Knex.Transaction | null, tenantId: number, channel: ManagementChannel): Promise<boolean> {
  if ((await readSettings(tenantId, trx ?? undefined)).frozen_at) return true;
  const mirror = mirrors.get(channel);
  return mirror ? mirror(trx ?? db, tenantId) : false;
}
