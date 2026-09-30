import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, Download, MinusCircle, RefreshCw } from 'lucide-react';
import type { ObliReachWebView2Mode, ObliReachWebView2Status } from '@obliance/shared';
import { remoteApi } from '@/api/remote.api';
import { apiErrorMessage } from '@/api/sshBastion.api';
import { Tip } from '@/components/common/Tip';
import { cn } from '@/utils/cn';

// The chat window of ObliReach is a Microsoft Edge WebView2 page. Its runtime,
// as the ObliReach agent (Windows) reports it: ready / missing / installing /
// failed / blocked by a policy / unsupported — with an Install button for
// admins and users with the 'remote' capability (the server checks the device
// rights; the platform setting may disable installs).

type Tone = 'ok' | 'busy' | 'warn' | 'error' | 'muted';

/** The agent ignores a forced attempt within 1 min of the previous one's start
 *  (the server answers 409 too_soon): the button waits as long (+ margin). */
const RETRY_GAP_MS = 63_000;

const TONE_CLASS: Record<Tone, string> = {
  ok: 'text-green-400',
  busy: 'text-sky-400',
  warn: 'text-amber-400',
  error: 'text-red-400',
  muted: 'text-text-muted',
};

function ToneIcon({ tone }: { tone: Tone }) {
  const c = 'w-3.5 h-3.5 shrink-0';
  if (tone === 'ok') return <CheckCircle2 className={c} />;
  if (tone === 'busy') return <RefreshCw className={cn(c, 'animate-spin')} />;
  if (tone === 'error' || tone === 'warn') return <AlertTriangle className={c} />;
  return <MinusCircle className={c} />;
}

/** Why the last install attempt failed, in words. */
export function webview2ReasonText(reason: string | null, t: TFunction): string | null {
  switch (reason) {
    case 'network': return t('oblireachWebView2.reason.network', 'network error (the machine could not reach Microsoft\'s download servers)');
    case 'signature': return t('oblireachWebView2.reason.signature', 'the installer\'s Microsoft signature was refused');
    case 'bootstrapper_missing': return t('oblireachWebView2.reason.bootstrapperMissing', 'the installer is not shipped with this ObliReach version (update ObliReach)');
    case 'timeout': return t('oblireachWebView2.reason.timeout', 'the installation took too long (stopped after 20 minutes)');
    case 'access_denied': return t('oblireachWebView2.reason.accessDenied', 'access denied');
    case 'cancelled': return t('oblireachWebView2.reason.cancelled', 'installation cancelled');
    case 'launch': return t('oblireachWebView2.reason.launch', 'the installer could not start');
    case 'not_detected': return t('oblireachWebView2.reason.notDetected', 'the runtime was not found after the installation');
    case 'installer_failed':
    case 'exit_code': return t('oblireachWebView2.reason.installerError', 'the Microsoft installer reported an error');
    default: return null;
  }
}

function fmt(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

function shortFuture(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getTime() <= Date.now()) return null;
  return d.toDateString() === new Date().toDateString()
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
}

/**
 * State text (without the "Chat component" prefix) + tone. `mode`: the
 * platform setting — the agent's "next automatic attempt" is only real in
 * proactive mode (the server never sends one from heartbeats otherwise).
 */
export function webview2StateText(s: ObliReachWebView2Status, t: TFunction, mode: ObliReachWebView2Mode | null = null): { text: string; tone: Tone } {
  switch (s.state) {
    case 'ok':
      return {
        tone: 'ok',
        text: s.version
          ? t('oblireachWebView2.state.okVersion', { version: s.version, defaultValue: 'ready (WebView2 {{version}})' })
          : t('oblireachWebView2.state.ok', 'ready'),
      };
    case 'installing':
      return { tone: 'busy', text: t('oblireachWebView2.state.installing', 'Microsoft Edge WebView2 Runtime being installed…') };
    case 'failed': {
      const reason = webview2ReasonText(s.reason, t) ?? s.lastError ?? s.reason ?? '';
      let text = reason
        ? t('oblireachWebView2.state.failedReason', { reason, defaultValue: 'missing — installation failed: {{reason}}' })
        : t('oblireachWebView2.state.failed', 'missing — installation failed');
      if (mode === 'proactive') {
        const next = shortFuture(s.nextAttemptAt);
        if (next) text = t('oblireachWebView2.withNext', { text, time: next, defaultValue: '{{text}} · next automatic attempt {{time}}' });
      } else if (mode === 'on_demand') {
        text = t('oblireachWebView2.withOnDemand', { text, defaultValue: '{{text}} · retried when a chat cannot open, or with the button' });
      }
      return { tone: 'error', text };
    }
    case 'blocked':
      return { tone: 'warn', text: t('oblireachWebView2.state.blocked', 'missing — its installation is blocked by a Microsoft Edge Update policy') };
    case 'unsupported':
      return { tone: 'muted', text: t('oblireachWebView2.state.unsupported', 'not supported by this version of Windows (the chat cannot open)') };
    case 'unknown':
      return { tone: 'muted', text: t('oblireachWebView2.state.unknown', 'state unknown (detection failed)') };
    default:
      return {
        tone: 'warn',
        text: s.reason === 'per_user_only'
          ? t('oblireachWebView2.state.perUserOnly', 'missing for the whole machine (installed for a user only) — the chat window cannot open')
          : t('oblireachWebView2.state.missing', 'Microsoft Edge WebView2 Runtime missing — the chat window cannot open'),
      };
  }
}

interface Props {
  deviceUuid: string;
  status: ObliReachWebView2Status | null | undefined;
  /** Platform setting (null: unknown). */
  mode: ObliReachWebView2Mode | null;
  /** Admin, or the 'remote' capability (the server checks the device itself). */
  canInstall: boolean;
  /** Re-read the agent's state after a request. */
  onRequested?: () => void;
  className?: string;
}

/** "Chat component: <state>" line + Install button; renders nothing when the agent does not report it. */
export function ObliReachWebView2Line({ deviceUuid, status, mode, canInstall, onRequested, className }: Props) {
  const { t } = useTranslation();
  const [sending, setSending] = useState(false);
  // Install / Retry within a minute of the previous attempt's start: the
  // agent would ignore it — the button waits (with the reason) instead.
  const lastAttempt = status?.lastAttemptAt ? Date.parse(status.lastAttemptAt) : NaN;
  const retryAt = Number.isFinite(lastAttempt) ? lastAttempt + RETRY_GAP_MS : null;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    setNow(Date.now());
    if (retryAt === null) return undefined;
    const wait = retryAt - Date.now();
    if (wait <= 0 || wait > RETRY_GAP_MS) return undefined;
    const id = window.setTimeout(() => setNow(Date.now()), wait + 50);
    return () => window.clearTimeout(id);
  }, [retryAt]);
  if (!status) return null;
  const { text, tone } = webview2StateText(status, t, mode);
  // (An attempt "in the future" beyond the gap: the agent's clock is ahead —
  // never blocks the button longer than the agent's own 1-min floor.)
  const tooSoon = retryAt !== null && retryAt > now && retryAt - now <= RETRY_GAP_MS;
  const tooSoonText = tooSoon && retryAt !== null
    ? t('oblireachWebView2.detail.tooSoon', {
      time: new Date(retryAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      defaultValue: 'An installation attempt started less than a minute ago: the button is available again at {{time}}.',
    })
    : null;
  const line = t('oblireachWebView2.line', { status: text, defaultValue: 'Chat component: {{status}}' });

  const installable = status.state === 'missing' || status.state === 'failed' || status.state === 'blocked' || status.state === 'unknown';
  const showButton = canInstall && installable && status.installer;
  const disabledByMode = mode === 'disabled';

  const rows: string[] = [];
  rows.push(t('oblireachWebView2.detail.what', 'The chat window shown to the user is a Microsoft Edge WebView2 page: without this Microsoft runtime the chat cannot open on this machine.'));
  if (status.version) rows.push(t('oblireachWebView2.detail.version', { version: status.version, defaultValue: 'Installed version: {{version}}' }));
  if (status.attempts > 0) rows.push(t('oblireachWebView2.detail.attempts', { count: status.attempts, defaultValue: 'Failed attempts: {{count}}' }));
  if (status.lastError && status.state !== 'ok') rows.push(t('oblireachWebView2.detail.lastError', { error: status.lastError, defaultValue: 'Last error: {{error}}' }));
  const last = fmt(status.lastAttemptAt);
  if (last && status.state !== 'ok') rows.push(t('oblireachWebView2.detail.lastAttempt', { time: last, defaultValue: 'Last attempt: {{time}}' }));
  const since = fmt(status.installingSince);
  if (since && status.state === 'installing') rows.push(t('oblireachWebView2.detail.since', { time: since, defaultValue: 'Started: {{time}}' }));
  if (!status.installer && status.state !== 'ok') rows.push(t('oblireachWebView2.detail.noInstaller', 'This ObliReach version cannot install it: update ObliReach first.'));
  if (installable && status.installer) {
    rows.push(mode === 'disabled'
      ? t('oblireachWebView2.detail.modeDisabled', 'Installing WebView2 is disabled in the settings (Settings > ObliReach).')
      : mode === 'on_demand'
        ? t('oblireachWebView2.detail.modeOnDemand', 'Installed on demand: when a chat cannot open, or with the Install button.')
        : t('oblireachWebView2.detail.modeProactive', 'Installed automatically within the hour after the server notices it is missing.'));
  }

  const install = async () => {
    setSending(true);
    try {
      const r = await remoteApi.installObliReachWebView2(deviceUuid);
      if (r.delivered === 'sent') toast.success(t('oblireachWebView2.toast.sent', 'Installation started on this machine: it may take several minutes (about 150 MB downloaded from Microsoft).'));
      else if (r.delivered === 'already_installed') toast.success(t('oblireachWebView2.toast.alreadyInstalled', 'The WebView2 runtime is already installed on this machine.'));
      else toast(t('oblireachWebView2.toast.inProgress', 'An installation is already in progress on this machine.'));
      onRequested?.();
    } catch (err) {
      const e = err as { response?: { status?: number; data?: { error?: string } } };
      const code = e.response?.status === 409 ? e.response.data?.error : undefined;
      const known: Record<string, string> = {
        disabled: t('oblireachWebView2.error.disabled', 'Installing WebView2 is disabled in the settings (Settings > ObliReach).'),
        not_reporting: t('oblireachWebView2.error.notReporting', 'ObliReach is offline on this machine, or too old to install WebView2.'),
        no_installer: t('oblireachWebView2.error.noInstaller', 'This ObliReach version does not ship the installer: update ObliReach first.'),
        unsupported: t('oblireachWebView2.error.unsupported', 'This version of Windows does not support the WebView2 runtime.'),
        too_soon: t('oblireachWebView2.error.tooSoon', 'An installation attempt started less than a minute ago on this machine: try again in a minute.'),
      };
      const msg = code && known[code] ? known[code] : apiErrorMessage(err, t('oblireachWebView2.error.generic', 'The installation could not be requested.'));
      if (msg) toast.error(msg);
    } finally {
      setSending(false);
    }
  };

  const buttonLabel = status.state === 'failed'
    ? t('oblireachWebView2.button.retry', 'Retry the installation')
    : t('oblireachWebView2.button.install', 'Install WebView2');
  const button = showButton ? (
    <button
      type="button"
      onClick={install}
      disabled={sending || disabledByMode || tooSoon}
      className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border border-accent/40 text-accent hover:bg-accent/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors coarse:min-h-10"
    >
      <Download className="w-3.5 h-3.5" />
      {sending ? t('oblireachWebView2.button.sending', 'Sending…') : buttonLabel}
    </button>
  ) : null;

  return (
    <div className={cn('flex flex-wrap items-center gap-2 min-w-0', className)}>
      <Tip
        content={(
          <div className="space-y-0.5 text-xs">
            <div className="font-semibold">{t('oblireachWebView2.detail.title', 'Chat component (Microsoft Edge WebView2 Runtime)')}</div>
            {rows.map((r) => <div key={r}>{r}</div>)}
          </div>
        )}
        placement="bottom"
        align="start"
        className="min-w-0 max-w-full"
      >
        <span className={cn('inline-flex items-center gap-1.5 min-w-0 max-w-full text-sm', TONE_CLASS[tone])}>
          <ToneIcon tone={tone} />
          <span className="truncate">{line}</span>
        </span>
      </Tip>
      {button && (disabledByMode
        ? <Tip content={t('oblireachWebView2.detail.modeDisabled', 'Installing WebView2 is disabled in the settings (Settings > ObliReach).')}>{button}</Tip>
        : tooSoonText
          ? <Tip content={tooSoonText}>{button}</Tip>
          : button)}
    </div>
  );
}
