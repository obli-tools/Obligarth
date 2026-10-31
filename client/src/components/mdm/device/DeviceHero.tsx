import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { Pencil, ShieldCheck, ShieldOff } from 'lucide-react';
import type { DeviceDetail } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { ActionMenu, type ActionMenuItem } from '@/components/common/ActionMenu';
import { TenantBadge } from '@/components/common/TenantBadge';
import { Tip } from '@/components/common/Tip';
import { useLayoutMode } from '@/hooks/useMediaQuery';
import { DeviceStateBadges } from '@/components/mdm/DeviceStateBadges';
import { LastSeenPill } from '@/components/mdm/LastSeenPill';
import { PlatformAvatar } from '@/components/mdm/PlatformAvatar';
import { osLabel, ownershipLabel } from '@/components/mdm/PlatformIcon';
import { CopyButton } from '@/components/mdm/ui/InfoCard';
import { anonymize } from '@/utils/anonymize';
import { ACTION_ICON, CHANNEL_REASONS, channelOf, type DeviceActions, type UnifiedAction } from './useDeviceActions';

// The header of a device record: who and what it is (platform, name, model, system, serial number, user, ownership,
// group, tenant), its states and last contact, and the quick actions of a lost or stolen device (locate, lock, lost
// mode; the others in the "…" menu, a bottom sheet on a phone). A greyed action says why on hover or tap.

/** One quick action: a button, or the greyed button with its reason in a tip (tap on a touch screen). */
export function QuickActionButton({ action, compact = false, className }: { action: UnifiedAction; compact?: boolean; className?: string }) {
  const Icon = ACTION_ICON[action.key];
  const tipped = !action.available && !!action.reasonLabel;
  const button = (
    <Button
      size="sm"
      variant={action.danger ? 'danger' : 'secondary'}
      disabled={!action.available}
      onClick={action.run}
      className={clsx('gap-1.5', tipped ? 'w-full' : className)}
      aria-label={compact ? action.label : undefined}
    >
      <Icon className="w-4 h-4 shrink-0" aria-hidden />
      {!compact && <span className="truncate">{action.label}</span>}
      {action.pending && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-blue-400 animate-pulse" aria-hidden />}
    </Button>
  );
  if (!tipped) return button;
  // The disabled button is the tip's direct child: its rule [&>*:disabled]:pointer-events-none lets a tap reach the
  // wrapper (a disabled button fires no click), so the reason opens on a touch screen too.
  return <Tip content={action.reasonLabel} className={className}>{button}</Tip>;
}

export function DeviceHero({ device, tenantName, actions, canWrite, onEdit }: {
  device: DeviceDetail;
  tenantName: string;
  actions: DeviceActions;
  canWrite: boolean;
  onEdit: () => void;
}) {
  const { t } = useTranslation();
  const phone = useLayoutMode() === 'phone';
  const managed = device.enrollmentState !== 'unenrolled';
  const a = actions.actions;
  const isApple = actions.channel === 'apple_mdm';
  const lostToggle = device.lostModeState === 'off' ? a.lostOn : a.lostOff;
  // What the channel cannot do at all is left out (the lost device panel says why). Three buttons on a tablet or a
  // desktop (locate, lock, lost mode), two on a phone (lock, lost mode); the rest in the menu, erase last.
  const offered = (x: UnifiedAction) => !x.hidden && !(x.reason && CHANNEL_REASONS.has(x.reason));
  const preferred = (phone ? [a.lock, lostToggle, a.message, a.restart] : [a.locate, a.lock, lostToggle, a.message, a.restart]).filter(offered);
  const primary = preferred.slice(0, phone ? 2 : 3);
  const secondary = [a.locate, a.sound, a.message, a.restart, a.inventory].filter((x) => offered(x) && !primary.includes(x));
  const menuItem = (x: UnifiedAction, more: Partial<ActionMenuItem> = {}): ActionMenuItem => {
    const Icon = ACTION_ICON[x.key];
    return {
      key: x.key, icon: <Icon className="w-4 h-4" />, label: x.label, onClick: x.run, disabled: !x.available, danger: x.danger,
      description: x.available ? (x.pending ? (t('deviceSummary.lost.pending') || 'Waiting for the device') : undefined) : (x.reasonLabel ?? undefined),
      // A greyed action's reason is read in full (it can be long: the mode, the Android version), not truncated.
      wrapDescription: !x.available,
      ...more,
    };
  };
  const items: ActionMenuItem[] = [
    ...secondary.map((x) => menuItem(x)),
    ...(a.erase.hidden ? [] : [menuItem(a.erase, { separator: true })]),
  ];

  const title = anonymize(device.displayName || device.label);
  const model = device.modelName || device.model;
  const endUser = device.endUser ? anonymize(device.endUser.displayName || device.endUser.email || `#${device.endUser.id}`) : null;

  return (
    <section className="rounded-xl border border-border bg-bg-secondary p-4 sm:p-5 min-w-0">
      <div className="flex items-start gap-3 sm:gap-4 min-w-0">
        <PlatformAvatar platform={device.platform} size="lg" className="max-sm:h-12 max-sm:w-12" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
            <h1 className="min-w-0 flex-1 text-xl sm:text-2xl font-semibold text-text-primary break-words">{title}</h1>
            <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
              {channelOf(device) === 'legacy_agent' && (
                // The Android bridge agent (agent-pont-android §7): its panel, actions and queue live on its own page too.
                <Link to={`/legacy-agent?device=${device.id}`} className="text-sm text-accent hover:underline coarse:min-h-10 inline-flex items-center">
                  {t('legacyAgent.openPanel') || 'Android agent panel'}
                </Link>
              )}
              {canWrite && (
                <Button variant="secondary" size="sm" onClick={onEdit}>
                  <Pencil size={14} className="mr-1.5" />{t('common.edit') || 'Edit'}
                </Button>
              )}
            </div>
          </div>

          <p className="mt-1 flex flex-wrap items-center gap-x-1.5 text-sm text-text-secondary">
            {model && <span>{model}</span>}
            {model && <span className="text-text-muted" aria-hidden>·</span>}
            <span>{osLabel(device.platform, device.osVersion)}</span>
            {device.serialNumber && (
              <>
                <span className="text-text-muted" aria-hidden>·</span>
                <span className="group inline-flex items-center gap-0.5 font-mono text-[13px]">
                  {anonymize(device.serialNumber)}
                  <CopyButton value={device.serialNumber} />
                </span>
              </>
            )}
          </p>

          <p className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-sm text-text-muted">
            {device.endUser && endUser ? (
              <Link to={`/devices?endUserId=${device.endUser.id}`} className="text-accent hover:underline">{endUser}</Link>
            ) : <span>{t('deviceSummary.hero.noEndUser') || 'No end user'}</span>}
            <span aria-hidden>·</span>
            <span>{ownershipLabel(t, device.ownership)}</span>
            {device.groupId != null && (
              <>
                <span aria-hidden>·</span>
                <Link to={`/group/${device.groupId}`} className="hover:text-text-primary hover:underline">{anonymize(device.groupName) || `#${device.groupId}`}</Link>
              </>
            )}
            <TenantBadge tenantId={device.tenantId} tenantName={tenantName} />
          </p>

          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <DeviceStateBadges device={device} size="md" all={managed} />
            {isApple && managed && (
              <span className={clsx('inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium whitespace-nowrap',
                device.supervised ? 'border-accent/30 bg-accent/10 text-accent' : 'border-border text-text-muted')}>
                {device.supervised ? <ShieldCheck className="w-3.5 h-3.5" aria-hidden /> : <ShieldOff className="w-3.5 h-3.5" aria-hidden />}
                {device.supervised ? (t('deviceSummary.hero.supervised') || 'Supervised') : (t('deviceSummary.hero.unsupervised') || 'Not supervised')}
              </span>
            )}
            <LastSeenPill lastCheckinAt={device.lastCheckinAt} contactState={device.contactState} className="py-1 text-xs" />
          </div>
        </div>
      </div>

      {managed && canWrite && (
        <div className="mt-4 flex items-center gap-2 border-t border-border pt-3">
          <div className="flex min-w-0 flex-1 flex-wrap gap-2">
            {primary.map((x) => <QuickActionButton key={x.key} action={x} className="max-sm:flex-1" />)}
          </div>
          {items.length > 0 && (
            <ActionMenu
              items={items}
              label={t('deviceSummary.hero.more') || 'More actions'}
              sheetTitle={title}
              triggerVariant="ghost"
            />
          )}
        </div>
      )}
    </section>
  );
}
