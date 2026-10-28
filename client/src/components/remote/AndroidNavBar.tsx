import { useTranslation } from 'react-i18next';
import { Bell, ChevronLeft, Circle, Square, Sun, Volume1, Volume2 } from 'lucide-react';
import type { RemoteNavAction } from '@obligarth/shared';

// =============================================================================
// The navigation bar of the remote viewer (P0-15 §5.2, §5.3): Back, Home, Recents, Notifications, the volume and the
// wake of the screen. No power button, lock nor shutdown in v1: a power dialog then a touch would switch the device
// off outside the guarded actions.
// =============================================================================

const BUTTONS: Array<{ action: RemoteNavAction; icon: JSX.Element; key: string; fallback: string }> = [
  { action: 'back', icon: <ChevronLeft size={18} />, key: 'remote.nav.back', fallback: 'Back' },
  { action: 'home', icon: <Circle size={16} />, key: 'remote.nav.home', fallback: 'Home' },
  { action: 'recents', icon: <Square size={15} />, key: 'remote.nav.recents', fallback: 'Recent apps' },
  { action: 'notifications', icon: <Bell size={16} />, key: 'remote.nav.notifications', fallback: 'Notifications' },
  { action: 'volume_down', icon: <Volume1 size={16} />, key: 'remote.nav.volumeDown', fallback: 'Volume down' },
  { action: 'volume_up', icon: <Volume2 size={16} />, key: 'remote.nav.volumeUp', fallback: 'Volume up' },
  { action: 'wake', icon: <Sun size={16} />, key: 'remote.nav.wake', fallback: 'Wake the screen' },
];

export function AndroidNavBar({ disabled, onNav }: { disabled: boolean; onNav: (action: RemoteNavAction) => void }) {
  const { t } = useTranslation();
  return (
    <div role="toolbar" aria-label={t('remote.nav.label') || 'Navigation of the device'} className="flex flex-wrap items-center justify-center gap-1">
      {BUTTONS.map((b) => {
        const label = t(b.key) || b.fallback;
        return (
          <button
            key={b.action}
            type="button"
            title={label}
            aria-label={label}
            disabled={disabled}
            onClick={() => onNav(b.action)}
            className="flex h-9 w-10 items-center justify-center rounded-lg bg-bg-tertiary text-text-secondary hover:text-text-primary disabled:opacity-40 coarse:h-10 coarse:w-11"
          >
            {b.icon}
          </button>
        );
      })}
    </div>
  );
}
