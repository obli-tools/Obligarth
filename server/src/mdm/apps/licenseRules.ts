// =============================================================================
// Pure rules of the licences of the apps (docs: modele-donnees-mdm §8.3 step 1;
// lot C4): what an app artifact's body asks (its App Store id, a device or a
// user licence) and the clientUserId of an end user at Apps and Books. No
// database: the unit tests load this module (apps.test.ts).
// =============================================================================

export type LicenseKind = 'device' | 'user';

const obj = (v: unknown): Record<string, unknown> => {
  const x = typeof v === 'string' ? (() => { try { return JSON.parse(v) as unknown; } catch { return null; } })() : v;
  return x && typeof x === 'object' && !Array.isArray(x) ? x as Record<string, unknown> : {};
};

/** The App Store id and the licence's kind an app artifact's body names (compile.ts, compileApp). */
export function licenseOfBody(key: string, body: unknown): { storeId: string | null; kind: LicenseKind } {
  const b = obj(body);
  if (key.startsWith('app:')) {
    const id = typeof b.iTunesStoreID === 'number' && b.iTunesStoreID > 0 ? String(b.iTunesStoreID) : null;
    return { storeId: id, kind: b.LicenseAssignment === 'user' ? 'user' : 'device' };
  }
  const p = obj(b.Payload);
  const lic = obj(obj(p.InstallBehavior).License);
  const id = typeof p.AppStoreID === 'string' && /^[0-9]{1,20}$/.test(p.AppStoreID) ? p.AppStoreID : null;
  return { storeId: id, kind: lic.Assignment === 'User' ? 'user' : 'device' };
}

/** The clientUserId of an end user at Apps and Books: an internal reference, never a name nor an address. */
export const clientUserIdOf = (endUserUuid: string): string => `obg-${String(endUserUuid).toLowerCase()}`;
