// Weekly check of the enterprises of the project (AN51): enterprises.list (BASIC view) compared with the registry;
// an enterprise whose name never figured in android_enterprises (an interrupted signup, a refused managed Google
// Play Accounts enterprise) raises android.enterprise_orphan. Its adoption by the tenant whose signup was interrupted
// is offered only when its display name carries the marker of that signup and its name never belonged to any tenant
// (RR-3); the adoption itself (restriction android.enterprise_adopt) comes with lot AN-H.
import { createHash } from 'node:crypto';
import type { AmapiEnterpriseBasic } from '@obligarth/shared';
import { db } from '../../db';
import { asNone, type DbActor } from '../../db/context';
import { raiseAndroidPlatformAlert } from '../alerts';
import { androidGateway } from '../gateway';
import type { AndroidGateway } from '../gateway/types';
import { signupMarker } from './signup';

export const MAINTENANCE_ACTOR: DbActor = Object.freeze({ type: 'job', name: 'android.maintenance' }) as DbActor;
const MAX_PAGES = 100;

/** The enterprises of the project that the registry never knew. */
export async function checkProjectEnterprises(gw: AndroidGateway = androidGateway()): Promise<AmapiEnterpriseBasic[]> {
  return asNone(MAINTENANCE_ACTOR, async () => {
    const all: AmapiEnterpriseBasic[] = [];
    let token: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const r = await gw.listProjectEnterprises(token);
      all.push(...r.items);
      token = r.nextPageToken;
      if (!token) break;
    }
    if (!all.length) return [];
    const r = await db.raw('SELECT obligarth.android_enterprise_known(?::text[]) AS k', [all.map((e) => e.name)]) as { rows: Array<{ k: string[] }> };
    const known = new Set(r.rows[0]?.k ?? []);
    const orphans = all.filter((e) => !known.has(e.name));
    for (const o of orphans) {
      const ref = createHash('sha256').update(o.name).digest('hex').slice(0, 12);
      void raiseAndroidPlatformAlert('android.enterprise_orphan', { ref }, ref);
    }
    return orphans;
  });
}

/** Is `orphan` adoptable by a tenant whose interrupted signups are `signupIds` (RR-3)? */
export function adoptableBy(orphan: AmapiEnterpriseBasic, signupIds: readonly string[]): string | null {
  const display = orphan.enterpriseDisplayName ?? '';
  return signupIds.find((id) => display.endsWith(signupMarker(id))) ?? null;
}
