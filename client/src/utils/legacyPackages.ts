import type { LegacyAgentPackageView } from '@obligarth/shared';

// Review F028: a package of the bridge agent sent back by a device (app.pull, the harvest of the migration) is
// installed only once a person confirmed it (POST /api/legacy-agent/packages/:id/confirm); the server refuses an
// app.install of it with 422 packageNotConfirmed. An upload is confirmed when it is created.

/** Not confirmed yet. A server older than F028 sends no confirmedAt: its packages are installable as before. */
export function isUnconfirmedPackage(p: Pick<LegacyAgentPackageView, 'confirmedAt'>): boolean {
  return p.confirmedAt === null;
}

/** The packages an app.install may name first (confirmed), then those set aside until they are confirmed. */
export function splitInstallable<T extends Pick<LegacyAgentPackageView, 'confirmedAt'>>(packages: T[]): { installable: T[]; toConfirm: T[] } {
  const installable: T[] = [];
  const toConfirm: T[] = [];
  for (const p of packages) (isUnconfirmedPackage(p) ? toConfirm : installable).push(p);
  return { installable, toConfirm };
}
