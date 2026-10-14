import { Glasses, Laptop, MonitorSmartphone, Smartphone, Tablet, Tv } from 'lucide-react';
import type { TFunction } from 'i18next';
import type { EnrollmentMethod, ManagementMode, Ownership, Platform } from '@obligarth/shared';

// One icon per platform of the registry (modele-donnees-mdm §11.3): replaces the icon by OS family of the agent.

export function PlatformIcon({ platform, className = 'w-4 h-4' }: { platform: Platform | string | null | undefined; className?: string }) {
  switch (platform) {
    case 'ios': return <Smartphone className={className} />;
    case 'ipados': return <Tablet className={className} />;
    case 'macos': return <Laptop className={className} />;
    case 'tvos': return <Tv className={className} />;
    case 'visionos': return <Glasses className={className} />;
    case 'android': return <Smartphone className={className} />;
    default: return <MonitorSmartphone className={className} />;
  }
}

const PLATFORM_NAMES: Record<string, string> = {
  ios: 'iOS', ipados: 'iPadOS', macos: 'macOS', tvos: 'tvOS', visionos: 'visionOS', android: 'Android',
};

/** Product names: never translated. */
export const platformLabel = (platform: string | null | undefined): string => (platform ? (PLATFORM_NAMES[platform] ?? platform) : '—');

/** 'iOS 17.5' */
export const osLabel = (platform: string | null | undefined, osVersion: string | null | undefined): string =>
  [platformLabel(platform), osVersion].filter(Boolean).join(' ');

const OWNERSHIP_FALLBACK: Record<Ownership, string> = {
  corporate: 'Corporate', corporate_personal: 'Corporate, personally enabled', personal: 'Personal',
};
export const ownershipLabel = (t: TFunction, o: Ownership | string): string =>
  t(`mdm.ownership.${o}`) || OWNERSHIP_FALLBACK[o as Ownership] || o;

const METHOD_FALLBACK: Record<EnrollmentMethod, string> = {
  ade: 'Automated Device Enrollment', ota: 'Enrollment link', byod_account: 'Account-driven User Enrollment',
  configurator: 'Apple Configurator', account_device: 'Account-driven Device Enrollment', migration: 'Migration',
};
export const enrollmentMethodLabel = (t: TFunction, m: EnrollmentMethod | string): string =>
  t(`mdm.enrollmentMethod.${m}`) || METHOD_FALLBACK[m as EnrollmentMethod] || m;

const MODE_FALLBACK: Record<ManagementMode, string> = {
  device: 'Device', user_enrollment: 'User Enrollment', fully_managed: 'Fully managed', dedicated: 'Dedicated',
  work_profile_corporate: 'Work profile (corporate)', work_profile_personal: 'Work profile (personal)',
};
export const managementModeLabel = (t: TFunction, m: ManagementMode | string): string =>
  t(`mdm.managementMode.${m}`) || MODE_FALLBACK[m as ManagementMode] || m;

/** A short relative age ('5 min', '3 h', '12 d'), for the last contact of a row. */
export function shortAge(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return '—';
  const mins = Math.max(1, Math.floor(ms / 60_000));
  if (mins < 60) return `${mins} min`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours} h`;
  return `${Math.floor(hours / 24)} d`;
}

export const formatDateTime = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleString() : '—');
export const formatDate = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleDateString() : '—');
/** A calendar day (YYYY-MM-DD, a DATE column) in the viewer's format. Read as a local day: new Date('2027-03-01')
 *  is midnight UTC, the day before west of UTC. */
export const formatDay = (ymd: string | null | undefined): string => {
  const m = typeof ymd === 'string' ? /^(\d{4})-(\d{2})-(\d{2})/.exec(ymd) : null;
  return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).toLocaleDateString() : (ymd || '—');
};
/** True when a calendar day (YYYY-MM-DD) is before today, in the viewer's calendar. */
export const dayIsPast = (ymd: string | null | undefined): boolean => {
  if (typeof ymd !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(ymd)) return false;
  const n = new Date();
  const today = `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}-${String(n.getDate()).padStart(2, '0')}`;
  return ymd.slice(0, 10) < today;
};

/** '64 GB' from a number of bytes. */
export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
