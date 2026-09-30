import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, CheckCircle2, MinusCircle, RefreshCw } from 'lucide-react';
import type { ObliReachAutoStatus } from '@obliance/shared';
import type { ObliReachSelfUpdate } from '@/api/remote.api';
import { Tip } from '@/components/common/Tip';
import { cn } from '@/utils/cn';

// ObliReach automatic install / update, as last reported by the Obliance
// agent (devices.oblireach_status, live through DEVICE_UPDATED).
//   "ObliReach: up to date (v1.0.198)" / "installing v1.0.199…" / "failed: <reason>"

type Tone = 'ok' | 'busy' | 'warn' | 'error' | 'muted';

/** Short state text (without the "ObliReach:" prefix) + its tone. */
export function obliReachAutoText(status: ObliReachAutoStatus, t: TFunction): { text: string; tone: Tone } {
  const installed = status.installedVersion;
  const desired = status.desiredVersion;
  switch (status.state) {
    case 'up_to_date': {
      const text = installed
        ? t('oblireachAuto.state.upToDateVersion', { version: installed, defaultValue: 'up to date (v{{version}})' })
        : t('oblireachAuto.state.upToDate', 'up to date');
      // Installed at the right version but the service is down.
      if (status.running === false) {
        return { tone: 'warn', text: t('oblireachAuto.state.upToDateNotRunning', { status: text, defaultValue: '{{status}}, service not running' }) };
      }
      return { tone: 'ok', text };
    }
    case 'installing':
      return {
        tone: 'busy',
        text: desired
          ? t('oblireachAuto.state.installingVersion', { version: desired, defaultValue: 'installing v{{version}}…' })
          : t('oblireachAuto.state.installing', 'installing…'),
      };
    case 'pending':
      switch (status.reason) {
        case 'waiting_self_update': return { tone: 'muted', text: t('oblireachAuto.pending.waitingSelfUpdate', 'waiting for its own update') };
        case 'grace': return { tone: 'muted', text: t('oblireachAuto.pending.grace', 'update pending (grace period)') };
        case 'spread': return { tone: 'muted', text: t('oblireachAuto.pending.spread', 'install scheduled (staggered start)') };
        case 'busy_msi': return { tone: 'muted', text: t('oblireachAuto.pending.busyMsi', 'waiting: another installation is running') };
        case 'busy_agent_update': return { tone: 'muted', text: t('oblireachAuto.pending.busyAgentUpdate', 'waiting: Obliance agent update in progress') };
        case 'hold': return { tone: 'muted', text: t('oblireachAuto.pending.hold', 'update deferred: remote session open') };
        default: return { tone: 'muted', text: t('oblireachAuto.state.pending', 'install scheduled') };
      }
    case 'failed':
      return {
        tone: 'error',
        text: status.error
          ? t('oblireachAuto.state.failedReason', { reason: status.error, defaultValue: 'failed: {{reason}}' })
          : t('oblireachAuto.state.failed', 'failed'),
      };
    case 'privacy_deferred':
      return { tone: 'warn', text: t('oblireachAuto.state.privacyDeferred', 'on hold: privacy mode is on') };
    case 'disabled':
      return { tone: 'muted', text: t('oblireachAuto.state.disabled', 'automatic install off') };
    case 'unsupported':
      return { tone: 'muted', text: t('oblireachAuto.state.unsupported', 'not available for this platform') };
    default:
      return { tone: 'muted', text: status.state };
  }
}

const TONE_CLASS: Record<Tone, string> = {
  ok: 'text-green-400',
  busy: 'text-sky-400',
  warn: 'text-amber-400',
  error: 'text-red-400',
  muted: 'text-text-muted',
};

function ToneIcon({ tone, className }: { tone: Tone; className?: string }) {
  const c = cn('w-3.5 h-3.5 shrink-0', className);
  if (tone === 'ok') return <CheckCircle2 className={c} />;
  if (tone === 'busy') return <RefreshCw className={cn(c, 'animate-spin')} />;
  if (tone === 'error' || tone === 'warn') return <AlertTriangle className={c} />;
  return <MinusCircle className={c} />;
}

function fmt(iso: string | null, futureOnly = false): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || (futureOnly && d.getTime() <= Date.now())) return null;
  return d.toLocaleString();
}

/** Details shown in the tooltip. */
function Details({ status }: { status: ObliReachAutoStatus }) {
  const { t } = useTranslation();
  const rows: string[] = [];
  if (status.installedVersion) rows.push(t('oblireachAuto.detail.installed', { version: status.installedVersion, defaultValue: 'Installed: v{{version}}' }));
  else rows.push(t('oblireachAuto.detail.notInstalled', 'Installed: none'));
  if (status.desiredVersion) rows.push(t('oblireachAuto.detail.target', { version: status.desiredVersion, defaultValue: 'Target: v{{version}}' }));
  if (status.running !== null) rows.push(status.running ? t('oblireachAuto.detail.running', 'Service running') : t('oblireachAuto.detail.notRunning', 'Service not running'));
  if (status.attempts > 0) rows.push(t('oblireachAuto.detail.attempts', { count: status.attempts, defaultValue: 'Failed attempts: {{count}}' }));
  const last = fmt(status.lastAttemptAt);
  if (last) rows.push(t('oblireachAuto.detail.lastAttempt', { time: last, defaultValue: 'Last attempt: {{time}}' }));
  const next = fmt(status.nextAttemptAt, true);
  if (next) rows.push(t('oblireachAuto.detail.nextAttempt', { time: next, defaultValue: 'Next attempt: {{time}}' }));
  const since = fmt(status.since);
  if (since) rows.push(t('oblireachAuto.detail.since', { time: since, defaultValue: 'In this state since: {{time}}' }));
  return (
    <div className="space-y-0.5 text-xs">
      <div className="font-semibold">{t('oblireachAuto.detail.title', 'ObliReach automatic install')}</div>
      {rows.map((r) => <div key={r}>{r}</div>)}
    </div>
  );
}

interface Props {
  status: ObliReachAutoStatus | null | undefined;
  /** Header variant: one short inline item. */
  compact?: boolean;
  className?: string;
}

/** Short time of the next attempt (HH:MM today, date + time otherwise); null when already past. */
function shortTime(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getTime() <= Date.now()) return null;
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
}

/** "ObliReach: <state>" line; renders nothing when the agent never reported. */
export function ObliReachAutoStatusLine({ status, compact, className }: Props) {
  const { t } = useTranslation();
  if (!status) return null;
  const { text, tone } = obliReachAutoText(status, t);
  // Full line: when the next attempt is due (end of a grace period, installer
  // busy retry, failure backoff) — why the update is not there yet, and when.
  const next = !compact && (status.state === 'pending' || status.state === 'failed') ? shortTime(status.nextAttemptAt) : null;
  const line = next
    ? t('oblireachAuto.lineNext', { status: text, time: next, defaultValue: 'ObliReach: {{status}} · next attempt {{time}}' })
    : t('oblireachAuto.line', { status: text, defaultValue: 'ObliReach: {{status}}' });
  return (
    <Tip content={<Details status={status} />} placement="bottom" align="start" className={cn('min-w-0 max-w-full', className)}>
      <span
        className={cn(
          'inline-flex items-center gap-1.5 min-w-0 max-w-full',
          compact ? 'text-xs' : 'text-sm',
          TONE_CLASS[tone],
        )}
      >
        <ToneIcon tone={tone} />
        <span className="truncate">{line}</span>
      </span>
    </Tip>
  );
}

interface SelfUpdateProps {
  selfUpdate: ObliReachSelfUpdate | null | undefined;
  /** ObliReach still runs an older build than the server's (a failure is still relevant). */
  outdated: boolean;
  className?: string;
}

/**
 * ObliReach's OWN self-update, as it reports it in its heartbeat: an attempt
 * in progress or — while it still runs an older build — why the last one did
 * not complete and when it tries again on its own. Nothing otherwise.
 */
export function ObliReachSelfUpdateLine({ selfUpdate, outdated, className }: SelfUpdateProps) {
  const { t } = useTranslation();
  if (!selfUpdate) return null;
  const su = selfUpdate;
  let tone: Tone;
  let text: string;
  if (su.inProgress) {
    tone = 'busy';
    text = su.target
      ? t('oblireachAuto.self.inProgressVersion', { version: su.target, defaultValue: 'ObliReach is updating itself to v{{version}}…' })
      : t('oblireachAuto.self.inProgress', 'ObliReach is updating itself…');
  } else if (outdated && su.lastOutcome && su.lastOutcome !== 'installed' && su.lastOutcome !== 'unsupported') {
    tone = su.lastOutcome === 'busy' ? 'muted' : 'error';
    const reason = su.lastError ?? su.lastResult ?? su.lastOutcome;
    text = t('oblireachAuto.self.lastFailed', { reason, defaultValue: 'ObliReach self-update: {{reason}}' });
    const next = shortTime(su.nextAttemptAt);
    if (next) text = t('oblireachAuto.self.withNext', { text, time: next, defaultValue: '{{text}} · next automatic attempt {{time}}' });
  } else {
    return null;
  }
  const rows: string[] = [];
  if (su.lastResult) rows.push(t('oblireachAuto.self.lastResult', { result: su.lastResult, defaultValue: 'Last result: {{result}}' }));
  const at = fmt(su.lastResultAt);
  if (at) rows.push(t('oblireachAuto.self.lastResultAt', { time: at, defaultValue: 'At: {{time}}' }));
  if (su.failures > 0) rows.push(t('oblireachAuto.detail.attempts', { count: su.failures, defaultValue: 'Failed attempts: {{count}}' }));
  const next = fmt(su.nextAttemptAt, true);
  if (next) rows.push(t('oblireachAuto.self.nextAuto', { time: next, defaultValue: 'Next automatic attempt: {{time}}' }));
  if (!su.inProgress) rows.push(t('oblireachAuto.self.retryHint', 'The update button retries now (at most once every 2 minutes).'));
  return (
    <Tip
      content={(
        <div className="space-y-0.5 text-xs">
          <div className="font-semibold">{t('oblireachAuto.self.title', 'ObliReach self-update')}</div>
          {rows.map((r) => <div key={r}>{r}</div>)}
        </div>
      )}
      placement="bottom"
      align="start"
      className={cn('min-w-0 max-w-full', className)}
    >
      <span className={cn('inline-flex items-center gap-1.5 min-w-0 max-w-full text-sm', TONE_CLASS[tone])}>
        <ToneIcon tone={tone} />
        <span className="truncate">{text}</span>
      </span>
    </Tip>
  );
}
