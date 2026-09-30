import type { Knex } from 'knex';

// Two-step approvals hardening.
//
//  - `sealed_payload`: data only the executor reads, NEVER returned by the
//    API nor pushed on the socket (a bcrypt hash of the password of a user
//    to create, an avatar image). Wiped as soon as the request leaves the
//    'pending' state (executed, failed, denied, cancelled, expired).
//  - `execution_error`: why an APPROVED request could not be executed (it
//    then stays 'approved'): shown to the reviewers instead of a silent
//    "approved" that did nothing.
//  - `description` becomes text: it now says what an approved request will
//    execute (before → after, device / user lists), longer than 500 chars.
//  - Clean-up of the requests filed before: a password, a token or a secret
//    script parameter never stays in `payload`. A request still pending that
//    carried one is cancelled (it could not run correctly without it).

const SECRET_KEY = /(password|passwd|passphrase|^pwd$|^pass$|secret|token|apikey|privatekey|credential|twofactorcode|^totp|^otp$|assertion)/;

function isSecretKey(key: string): boolean {
  if (key.includes('.')) return false; // map keys ('command.set_privacy_password'), not fields
  const n = key.toLowerCase().replace(/[_\-\s]/g, '');
  if (/(id|ids)$/.test(n)) return false; // identifiers (targetApiKeyId, keyId…)
  return SECRET_KEY.test(n);
}

function hasValue(v: unknown): boolean {
  if (v === null || v === undefined || typeof v === 'boolean') return false;
  if (typeof v === 'string') return v.length > 0;
  if (typeof v === 'number') return true;
  if (Array.isArray(v)) return v.some(hasValue);
  if (typeof v === 'object') return Object.values(v as Record<string, unknown>).some(hasValue);
  return false;
}

/** Deep copy without the secret-named keys; `removed` counts them. */
function scrub(value: unknown, removed: { n: number }): unknown {
  if (Array.isArray(value)) return value.map((v) => scrub(v, removed));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (isSecretKey(k) && hasValue(v)) { removed.n++; continue; }
      out[k] = scrub(v, removed);
    }
    return out;
  }
  return value;
}

export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasTable('pending_approvals'))) return;
  if (!(await knex.schema.hasColumn('pending_approvals', 'sealed_payload'))) {
    await knex.schema.alterTable('pending_approvals', (t) => { t.jsonb('sealed_payload').nullable(); });
  }
  if (!(await knex.schema.hasColumn('pending_approvals', 'execution_error'))) {
    await knex.schema.alterTable('pending_approvals', (t) => { t.string('execution_error', 1000).nullable(); });
  }
  await knex.raw('ALTER TABLE pending_approvals ALTER COLUMN description TYPE text');

  const hasScriptParams = await knex.schema.hasTable('script_parameters');
  const rows = await knex('pending_approvals').select('id', 'status', 'payload') as Array<{ id: number; status: string; payload: unknown }>;
  for (const row of rows) {
    let payload: unknown;
    try { payload = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload; } catch { continue; }
    if (!payload || typeof payload !== 'object') continue;
    const removed = { n: 0 };
    const clean = scrub(payload, removed) as Record<string, any>;
    // Manual script run: values of 'secret' parameters, whatever their name.
    const params = clean.params;
    if (hasScriptParams && clean.action === 'run_script' && params && typeof params === 'object'
      && params.scriptId != null && params.parameterValues && typeof params.parameterValues === 'object') {
      const secretNames = await knex('script_parameters')
        .where({ script_id: Number(params.scriptId), type: 'secret' })
        .pluck('name') as string[];
      for (const name of secretNames) {
        if (Object.prototype.hasOwnProperty.call(params.parameterValues, name) && hasValue(params.parameterValues[name])) {
          delete params.parameterValues[name];
          removed.n++;
        }
      }
    }
    if (removed.n === 0) continue;
    const patch: Record<string, unknown> = { payload: JSON.stringify(clean) };
    if (row.status === 'pending') {
      patch.status = 'cancelled';
      patch.reviewed_at = new Date();
      patch.review_reason = 'Cancelled by a server update: the request carried a secret that approvals no longer keep. Redo the action.';
    }
    await knex('pending_approvals').where({ id: row.id }).update(patch);
  }
}

export async function down(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasTable('pending_approvals'))) return;
  // The scrubbed secrets are not restored (by design).
  await knex.raw('UPDATE pending_approvals SET description = left(description, 500) WHERE length(description) > 500');
  await knex.raw('ALTER TABLE pending_approvals ALTER COLUMN description TYPE varchar(500)');
  if (await knex.schema.hasColumn('pending_approvals', 'execution_error')) {
    await knex.schema.alterTable('pending_approvals', (t) => { t.dropColumn('execution_error'); });
  }
  if (await knex.schema.hasColumn('pending_approvals', 'sealed_payload')) {
    await knex.schema.alterTable('pending_approvals', (t) => { t.dropColumn('sealed_payload'); });
  }
}
