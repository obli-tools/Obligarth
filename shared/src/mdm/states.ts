// =============================================================================
// Separate states of a device (docs: modele-donnees-mdm §4.4): the contact is
// derived from last_checkin_at, never stored; mirror of the SQL helper
// obligarth.version_num (migration mdm_model_expand).
// =============================================================================

export type ContactState = 'never' | 'recent' | 'quiet' | 'stale';

/** 'never' without any contact, 'recent' within 24 h, 'quiet' within the tenant's threshold
 *  (mdmStaleAfterDays), 'stale' beyond. */
export function contactState(lastCheckinAt: string | Date | null | undefined, now: Date, staleAfterDays: number): ContactState {
  if (!lastCheckinAt) return 'never';
  const at = lastCheckinAt instanceof Date ? lastCheckinAt.getTime() : Date.parse(lastCheckinAt);
  if (!Number.isFinite(at)) return 'never';
  const ageMs = now.getTime() - at;
  if (ageMs <= 24 * 3600_000) return 'recent';
  return ageMs <= staleAfterDays * 86_400_000 ? 'quiet' : 'stale';
}

/** Mirror of obligarth.version_num: '17.5.1 (21F90)' → 17005001, '17' → 17000000; null for anything that
 *  is not one to three groups of one to three digits (after cutting at the first other character). */
export function versionNum(version: string | null | undefined): number | null {
  const v = (version ?? '').replace(/[^0-9.][\s\S]*$/, '');
  if (!/^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$/.test(v)) return null;
  const [major, minor = '', patch = ''] = v.split('.');
  return Number(major) * 1_000_000 + Number(minor || '0') * 1_000 + Number(patch || '0');
}
