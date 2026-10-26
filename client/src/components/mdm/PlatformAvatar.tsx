import { clsx } from 'clsx';
import { Apple, Smartphone } from 'lucide-react';
import type { Platform } from '@obligarth/shared';
import { PlatformIcon, platformLabel } from '@/components/mdm/PlatformIcon';

// The platform of a device as a tinted rounded square (device record header, list rows): Apple neutral, Android
// emerald. PlatformIcon (used by many screens) stays as it is.

const SIZES = {
  sm: { box: 'h-7 w-7 rounded-md', icon: 'w-3.5 h-3.5' },
  md: { box: 'h-10 w-10 rounded-lg', icon: 'w-5 h-5' },
  lg: { box: 'h-14 w-14 rounded-xl', icon: 'w-7 h-7' },
} as const;

export function PlatformAvatar({ platform, size = 'md', className }: {
  platform: Platform | string | null | undefined; size?: keyof typeof SIZES; className?: string;
}) {
  const s = SIZES[size];
  const android = platform === 'android';
  const apple = !android && typeof platform === 'string' && ['ios', 'ipados', 'macos', 'tvos', 'visionos'].includes(platform);
  return (
    <span
      role="img"
      aria-label={platformLabel(platform)}
      title={platformLabel(platform)}
      className={clsx(
        'inline-flex shrink-0 items-center justify-center border',
        android ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-400'
          : apple ? 'border-border bg-bg-tertiary text-text-primary'
            : 'border-border bg-bg-tertiary text-text-muted',
        s.box,
        className,
      )}
    >
      {platform === 'ios' ? <Apple className={s.icon} aria-hidden />
        : android ? <Smartphone className={s.icon} aria-hidden />
          : <PlatformIcon platform={platform} className={s.icon} />}
    </span>
  );
}
