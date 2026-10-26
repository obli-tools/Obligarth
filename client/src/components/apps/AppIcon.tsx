import { useEffect, useState } from 'react';

// The icon of an app, shared by the catalog (pages/AppsPage) and the inventory of a device (mdm/DeviceAppsTab): its
// logo when it has one (the catalog's https URL, or the PNG a device of the tenant sent, served by the console's own
// route), else its initials on a colour taken from its identifier, stable from one visit to the next. An icon that
// fails to load falls back to the initials.

export type AppIconSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl';

export interface AppIconSource {
  name: string | null;
  identifier: string;
  iconUrl?: string | null;
}

/** Two letters for a tile: the first letters of the first two words of the name; without a name, the first two
 *  letters of the last segment of the identifier (com.sec.android.app.camera → CA). */
export function initialsOf(name: string | null, identifier = ''): string {
  if (!name || !name.trim()) {
    const last = identifier.split('.').filter(Boolean).pop() ?? '';
    return (last.replace(/[^A-Za-z0-9]/g, '').slice(0, 2) || '?').toUpperCase();
  }
  const words = name.trim().split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2);
  return letters.toUpperCase();
}

export function hueOf(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) % 360;
  return h;
}

const BOX: Record<AppIconSize, string> = {
  xs: 'h-6 w-6 rounded-md text-[9px]',
  sm: 'h-9 w-9 rounded-lg text-xs',
  md: 'h-12 w-12 rounded-xl text-sm',
  lg: 'h-16 w-16 rounded-2xl text-lg',
  xl: 'h-20 w-20 rounded-[1.4rem] text-2xl',
};

export function AppIcon({ app, size }: { app: AppIconSource; size: AppIconSize }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [app.iconUrl]);
  const box = BOX[size];
  if (app.iconUrl && !failed) {
    return <img src={app.iconUrl} alt="" referrerPolicy="no-referrer" loading="lazy" onError={() => setFailed(true)}
      className={`${box} shrink-0 bg-white object-cover shadow-md ring-1 ring-black/5`} />;
  }
  const hue = hueOf(app.identifier || app.name || '');
  return (
    <span aria-hidden className={`${box} inline-flex shrink-0 items-center justify-center font-bold text-white shadow-md`}
      style={{ background: `linear-gradient(135deg, hsl(${hue} 70% 55%), hsl(${(hue + 40) % 360} 65% 42%))` }}>
      {initialsOf(app.name, app.identifier)}
    </span>
  );
}
