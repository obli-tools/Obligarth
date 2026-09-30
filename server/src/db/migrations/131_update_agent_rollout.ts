import type { Knex } from 'knex';
import { logger } from '../../utils/logger';

// Agent updates that wait for offline devices + fleet-wide rollout
// (services/agentUpdateRollout.service.ts).
//
// update_agent is no longer a 5-minute command: it stays queued (no
// expires_at) until the device comes back, and the server hands it to at most
// N agents per minute. Two partial indexes on command_queue:
//
//   command_queue_update_agent_outstanding_uniq  UNIQUE (device_id)
//     WHERE type = 'update_agent' AND status IN ('pending', 'sent')
//     → at most ONE outstanding agent update per device, enforced by the
//       database (INSERT … ON CONFLICT DO NOTHING on every enqueue path, safe
//       under concurrency). Also the access path of the rollout's "head of
//       the queue" read (pending updates only: at most one row per device).
//   command_queue_update_agent_sent_at_idx  (sent_at) WHERE type = 'update_agent'
//     → the rollout throttle counts the updates handed out in the last
//       minute on every delivery attempt; also serves every
//       "type = 'update_agent'" lookup below.
//
// Both indexes cover update_agent rows only (a few per device and release),
// so they stay tiny whatever the size of command_queue. Built CONCURRENTLY
// (no write lock on the table) → this migration runs outside a transaction;
// every step is idempotent, so a run interrupted half-way is simply re-run.
// Cost: each CONCURRENTLY build reads the whole command_queue table twice and
// first waits for the transactions already open in the database (an idle
// "psql" session left in a transaction delays it) — proportional to the size
// of command_queue; every step is logged with its duration.
//
// Existing rows, before the unique index can exist (dates kept honest: the
// change timeline dates a command by COALESCE(finished_at, acked_at, sent_at,
// created_at) — a row closed here must not show up at the deploy time):
//   - pending update_agent rows lose their expires_at (the old 5-minute TTL
//     of POST /api/commands): they now wait for the device — except a
//     scenario's (its node keeps its timeout);
//   - sent rows older than the 30-min delivery deadline (agent restarted into
//     the new version, its ack lost; old bulk / approval paths had no expiry)
//     are closed now, dated at their deadline: 'success' when the device
//     reports the target version, 'timeout' otherwise;
//   - younger sent rows without a deadline get sent_at + 30 min: the command
//     sweeper closes them;
//   - several outstanding rows for one device: the oldest pending one is kept
//     (a sent one when none is pending), the others are closed (duplicate
//     pending → cancelled, duplicate sent → timeout dated at its deadline)
//     with an explanation.
export const config = { transaction: false };

const UNIQ = 'command_queue_update_agent_outstanding_uniq';
const SENT_AT = 'command_queue_update_agent_sent_at_idx';
const DELIVERY_TIMEOUT_MINUTES = 30;
const DEADLINE = `LEAST(now(), COALESCE(sent_at, created_at) + interval '${DELIVERY_TIMEOUT_MINUTES} minutes')`;
// COALESCE: a NULL source must give false, not NULL (NOT NULL is NULL).
const SCENARIO = `(COALESCE(source_type, '') = 'scenario_node' OR starts_with(COALESCE(source_type, ''), 'scenario_step_'))`;

function rowCount(r: any): number {
  return Number(r?.rowCount ?? r?.affectedRows ?? 0);
}

async function step<T>(label: string, fn: () => Promise<T>): Promise<T> {
  const t0 = Date.now();
  logger.info(`migration 131: ${label}…`);
  const out = await fn();
  logger.info(`migration 131: ${label} done in ${Date.now() - t0} ms`);
  return out;
}

async function indexState(knex: Knex, name: string): Promise<'absent' | 'valid' | 'invalid'> {
  const r = await knex.raw(
    `SELECT i.indisvalid AS valid
       FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
      WHERE c.relname = ? AND c.relkind = 'i'`,
    [name],
  );
  const row = (r.rows ?? [])[0] as { valid: boolean } | undefined;
  if (!row) return 'absent';
  return row.valid ? 'valid' : 'invalid';
}

/** CREATE [UNIQUE] INDEX CONCURRENTLY, idempotent: a valid index is kept, an
 *  INVALID one (left by an interrupted concurrent build) is dropped and
 *  rebuilt. `prepare` runs before each build attempt (the duplicate cleanup
 *  for the unique index: a row inserted between the cleanup and the build by
 *  another server instance would fail it once). */
async function ensureIndex(knex: Knex, name: string, createSql: string, prepare?: () => Promise<void>): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    const state = await indexState(knex, name);
    if (state === 'valid') {
      logger.info(`migration 131: index ${name} already valid`);
      return;
    }
    if (state === 'invalid') {
      logger.warn(`migration 131: index ${name} left INVALID by an interrupted build — dropping and rebuilding it`);
      await knex.raw(`DROP INDEX CONCURRENTLY IF EXISTS ${name}`);
    }
    if (prepare) await prepare();
    try {
      await step(`building index ${name} (CONCURRENTLY, attempt ${attempt})`, () => knex.raw(createSql));
    } catch (err) {
      if (attempt >= 2) throw err;
      logger.warn({ err }, `migration 131: building index ${name} failed on attempt ${attempt} — retrying once`);
      continue;
    }
    if ((await indexState(knex, name)) === 'valid') return;
    if (attempt >= 2) throw new Error(`index ${name} could not be built (left invalid)`);
    logger.warn(`migration 131: index ${name} left invalid after attempt ${attempt} — retrying once`);
  }
}

async function cleanOutstanding(knex: Knex): Promise<void> {
  await step('cleaning outstanding update_agent rows', async () => {
    // A pending agent update waits for its device: no TTL (a scenario's keeps
    // its node timeout).
    const ttl = await knex.raw(
      `UPDATE command_queue SET expires_at = NULL, updated_at = now()
        WHERE type = 'update_agent' AND status = 'pending' AND expires_at IS NOT NULL
          AND NOT ${SCENARIO}`,
    );
    // Delivered long ago and never closed: closed now, dated at the deadline.
    const confirmed = await knex.raw(
      `UPDATE command_queue c
          SET status = 'success',
              finished_at = LEAST(now(), COALESCE(c.sent_at, c.created_at) + interval '${DELIVERY_TIMEOUT_MINUTES} minutes'),
              updated_at = now(),
              result = jsonb_build_object('message', 'Agent reports version ' || d.agent_version || ' (closed by migration 131)',
                                          'agentVersion', d.agent_version, 'inferred', true)
         FROM devices d
        WHERE d.id = c.device_id AND c.type = 'update_agent' AND c.status = 'sent'
          AND COALESCE(c.sent_at, c.created_at) < now() - interval '${DELIVERY_TIMEOUT_MINUTES} minutes'
          AND d.agent_version IS NOT NULL AND d.agent_version = c.payload->>'version'`,
    );
    const stale = await knex.raw(
      `UPDATE command_queue
          SET status = 'timeout',
              finished_at = ${DEADLINE},
              updated_at = now(),
              result = jsonb_build_object('message', 'No confirmation from the agent (closed by migration 131)')
        WHERE type = 'update_agent' AND status = 'sent'
          AND COALESCE(sent_at, created_at) < now() - interval '${DELIVERY_TIMEOUT_MINUTES} minutes'`,
    );
    // A recently delivered one gets a deadline (the sweeper closes it).
    const deadline = await knex.raw(
      `UPDATE command_queue
          SET expires_at = COALESCE(sent_at, updated_at, now()) + interval '${DELIVERY_TIMEOUT_MINUTES} minutes',
              updated_at = now()
        WHERE type = 'update_agent' AND status = 'sent' AND expires_at IS NULL`,
    );
    // One outstanding update per device.
    const dup = await knex.raw(
      `WITH ranked AS (
         SELECT id, status,
                row_number() OVER (
                  PARTITION BY device_id
                  ORDER BY (status = 'pending') DESC, created_at ASC, id ASC
                ) AS rn
           FROM command_queue
          WHERE type = 'update_agent' AND status IN ('pending', 'sent')
       )
       UPDATE command_queue q
          SET status = CASE WHEN ranked.status = 'pending' THEN 'cancelled'::command_status ELSE 'timeout'::command_status END,
              finished_at = CASE WHEN ranked.status = 'pending' THEN now()
                                 ELSE LEAST(now(), COALESCE(q.sent_at, q.created_at) + interval '${DELIVERY_TIMEOUT_MINUTES} minutes') END,
              updated_at = now(),
              result = jsonb_build_object(
                'skipped', true,
                'reason', 'duplicate',
                'message', 'Duplicate agent update closed: one outstanding agent update per device'
              )
         FROM ranked
        WHERE q.id = ranked.id AND ranked.rn > 1`,
    );
    logger.info({
      ttlRemoved: rowCount(ttl), closedSuccess: rowCount(confirmed), closedTimeout: rowCount(stale),
      deadlineSet: rowCount(deadline), duplicatesClosed: rowCount(dup),
    }, 'migration 131: update_agent rows cleaned');
  });
}

export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasTable('command_queue'))) return;
  // Built first: the cleanup below (type = 'update_agent') uses it instead of
  // scanning the whole table.
  await ensureIndex(knex, SENT_AT,
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS ${SENT_AT}
       ON command_queue (sent_at) WHERE type = 'update_agent'`);
  await ensureIndex(knex, UNIQ,
    `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ${UNIQ}
       ON command_queue (device_id) WHERE type = 'update_agent' AND status IN ('pending', 'sent')`,
    () => cleanOutstanding(knex));
}

export async function down(knex: Knex): Promise<void> {
  // Rows are left as they are (no TTL back on pending updates): only the
  // indexes go.
  await knex.raw(`DROP INDEX CONCURRENTLY IF EXISTS ${UNIQ}`);
  await knex.raw(`DROP INDEX CONCURRENTLY IF EXISTS ${SENT_AT}`);
}
