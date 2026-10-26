import type { Knex } from 'knex';

// =============================================================================
// The upserts of device_apps (every ingestor: Apple lists and DDM status, AMAPI reports, the bridge agent) keep
// version_changed_at: now() when an existing row changes its version or its build, else its value. A new row keeps
// NULL (the server does not know when an app it sees for the first time was installed or updated). The CASE reads
// the row before the update (every expression of ON CONFLICT DO UPDATE SET does), so the order of the columns does
// not matter.
// =============================================================================

/** The value of version_changed_at in the merge; `next` are the SQL expressions of the new version and build. */
export function versionChangedMerge(q: Knex | Knex.Transaction,
  next: { version: string; shortVersion: string } = { version: 'excluded.version', shortVersion: 'excluded.short_version' }): Knex.Raw {
  return q.raw(`CASE WHEN device_apps.version IS DISTINCT FROM (${next.version})
    OR device_apps.short_version IS DISTINCT FROM (${next.shortVersion}) THEN now() ELSE device_apps.version_changed_at END`);
}

/** The merge of `columns` from the inserted row (excluded.<column>), with version_changed_at. */
export function appsMerge(q: Knex | Knex.Transaction, columns: readonly string[]): Record<string, Knex.Raw> {
  const merge: Record<string, Knex.Raw> = {};
  for (const c of columns) {
    if (!/^[a-z_]+$/.test(c)) throw new Error(`appsMerge: bad column ${c}`);
    merge[c] = q.raw(`excluded.${c}`);
  }
  merge.version_changed_at = versionChangedMerge(q);
  return merge;
}
