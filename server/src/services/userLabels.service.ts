import { db } from '../db';

// Names of the accounts referenced by tenant rows (audit actors, approval
// requesters and reviewers, authors) through obligarth.user_labels
// (rls-tenant §5.3.3): members of the context's readable tenants, the actor
// itself and the platform administrators (MSP staff who acted for the
// client) — never the accounts of another client. A join on `users` would
// only name the members the row level security lets the caller read.

export interface UserLabel {
  username: string;
  displayName: string | null;
}

/** Labels of these account ids (ids the caller may not name are absent). */
export async function userLabels(ids: ReadonlyArray<unknown>): Promise<Map<number, UserLabel>> {
  const list = [...new Set(ids.map(Number).filter((n) => Number.isSafeInteger(n) && n > 0 && n <= 2147483647))];
  if (list.length === 0) return new Map();
  const res = await db.raw('SELECT id, username, display_name FROM obligarth.user_labels(?::integer[])', [list]) as
    { rows: Array<{ id: number; username: string; display_name: string | null }> };
  return new Map(res.rows.map((r) => [Number(r.id), { username: r.username, displayName: r.display_name }]));
}
