import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import axios from 'axios';
import type { ObliwatchConsentFlags, ObliwatchConsentView } from '@obligarth/shared';
import { obliwatchApi } from '@/api/obliwatch.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage } from '@/utils/apiError';

// The Obliwatch consent of the tenant (brief GTH-01..09, plan §0 F5), on the Integrations page: what Obliwatch may
// do with this tenant (read, push of the signals, action requests, nominative view of the AI apps), each off until a
// manager turns it on. A change asks a fresh second factor and is journaled. Hidden when the integration is off on
// the instance (404) or the user may not read the tenant's settings (403). Model of /devices: no border, rows that
// light up on hover, pills.

const FLAGS: Array<{ key: keyof ObliwatchConsentFlags; label: string; hint: string }> = [
  { key: 'read', label: 'Obliwatch may read this tenant', hint: 'Devices, their posture and coverage, and the access keys of AI agents. Never a serial number, IMEI, phone number, MAC address or location.' },
  { key: 'push', label: 'Send the mobile security signals', hint: 'Compliance, integrity, management, lost mode, Apple attestation and Android security-log detections (counts only, company-owned fully managed devices, which then show that logging is on), sent to Obliwatch as they happen.' },
  { key: 'actions', label: 'Accept action requests from Obliwatch', hint: 'Lock, lost mode, location or sound on one device: a valid request is executed at once, without a second factor or an approver (erase and removal always refused, capped, journaled).' },
  { key: 'nominativeAiApps', label: 'Nominative view of the AI apps', hint: 'Which device runs which AI app, instead of counts only. On by default with the read access; can be turned off.' },
];

const sameFlags = (a: ObliwatchConsentFlags, b: ObliwatchConsentFlags): boolean => FLAGS.every((f) => a[f.key] === b[f.key]);

export function ObliwatchConsentCard() {
  const { t } = useTranslation();
  const [view, setView] = useState<ObliwatchConsentView | null>(null);
  const [draft, setDraft] = useState<ObliwatchConsentFlags | null>(null);
  const [hidden, setHidden] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    obliwatchApi.consent().then((v) => { setView(v); setDraft({ read: v.read, push: v.push, actions: v.actions, nominativeAiApps: v.nominativeAiApps }); })
      .catch((err) => {
        const status = axios.isAxiosError(err) ? err.response?.status : undefined;
        if (status === 404 || status === 403) setHidden(true);
        else toast.error(apiErrorMessage(err));
      });
  }, []);
  useEffect(() => { load(); }, [load]);

  if (hidden || !view || !draft) return null;
  const dirty = !sameFlags(view, draft);
  const anyOn = FLAGS.some((f) => view[f.key]);

  const save = async () => {
    setBusy(true);
    try {
      const v = await obliwatchApi.setConsent(draft);
      setView(v);
      setDraft({ read: v.read, push: v.push, actions: v.actions, nominativeAiApps: v.nominativeAiApps });
      toast.success(t('obliwatch.consent.saved') || 'Obliwatch consent saved');
    } catch (err) {
      if (isStepUpHandled(err)) return;
      const code = axios.isAxiosError(err) ? (err.response?.data as { code?: string } | undefined)?.code : undefined;
      toast.error(code === 'slugIncompatible'
        ? (t('obliwatch.consent.slugIncompatible', { slug: view.slug }) || `The identifier of this tenant (${view.slug}) does not fit the format Obliwatch requires: lowercase letters, digits and hyphens, 64 at most.`)
        : apiErrorMessage(err), { duration: 8000 });
    } finally {
      setBusy(false);
    }
  };

  // The dead letters of the push (lot L3) sent again: a new window of 72 hours, journaled.
  const retry = async () => {
    setBusy(true);
    try {
      const r = await obliwatchApi.retryDead();
      toast.success(t('obliwatch.push.requeued', { count: r.requeued }) || `${r.requeued} signal(s) queued again`);
      load();
    } catch (err) {
      if (isStepUpHandled(err)) return;
      toast.error(apiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded-xl bg-bg-secondary p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-accent" />
        <h2 className="text-base font-semibold text-text-primary">{t('obliwatch.consent.title') || 'Obliwatch'}</h2>
        <StateBadge tone={anyOn ? 'green' : 'gray'}
          label={anyOn ? (t('obliwatch.consent.stateOn') || 'Consent given') : (t('obliwatch.consent.stateOff') || 'No consent')} />
        <span className="ml-auto flex flex-wrap gap-2">
          {dirty && (
            <Button size="sm" variant="secondary" disabled={busy}
              onClick={() => setDraft({ read: view.read, push: view.push, actions: view.actions, nominativeAiApps: view.nominativeAiApps })}>
              {t('common.cancel') || 'Cancel'}
            </Button>
          )}
          <Button size="sm" disabled={!dirty || busy} onClick={save}>{t('common.save') || 'Save'}</Button>
        </span>
      </div>
      <p className="text-sm text-text-muted">
        {t('obliwatch.consent.subtitle') || 'What the security tool of the suite may do with this tenant. Each change asks a second factor and is journaled.'}
      </p>
      {!view.slugCompatible && (
        <p className="flex items-start gap-2 text-sm text-status-down">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{t('obliwatch.consent.slugIncompatible', { slug: view.slug }) || `The identifier of this tenant (${view.slug}) does not fit the format Obliwatch requires: lowercase letters, digits and hyphens, 64 at most.`}</span>
        </p>
      )}
      <div>
        <div className="px-3 pb-1 text-[10px] uppercase tracking-wide text-text-muted">{t('obliwatch.consent.allowed') || 'Allowed'}</div>
        <ul>
          {FLAGS.map((f) => (
            <li key={f.key} className="flex items-start gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-bg-tertiary">
              <div className="min-w-0 flex-1">
                <div className="text-sm text-text-primary">{t(`obliwatch.consent.${f.key}`) || f.label}</div>
                <div className="text-xs text-text-muted">{t(`obliwatch.consent.${f.key}Hint`) || f.hint}</div>
              </div>
              <ToggleSwitch checked={draft[f.key]} disabled={busy || (!view.slugCompatible && !draft[f.key])}
                ariaLabel={t(`obliwatch.consent.${f.key}`) || f.label}
                onChange={(next) => setDraft({
                  ...draft, [f.key]: next,
                  // The read access turned on brings the nominative view of the AI apps along (decision AR-55/AR-57), unless
                  // it was changed in this draft; the server applies the same rule.
                  ...(f.key === 'read' && next && !view.read && draft.nominativeAiApps === view.nominativeAiApps ? { nominativeAiApps: true } : {}),
                })} />
            </li>
          ))}
        </ul>
      </div>
      {view.pushStatus && (view.push || view.pushStatus.dead > 0 || view.pushStatus.pending > 0) && (
        <div>
          <div className="px-3 pb-1 text-[10px] uppercase tracking-wide text-text-muted">{t('obliwatch.push.status') || 'Signals sent to Obliwatch'}</div>
          <div className="flex flex-wrap items-center gap-2 rounded-lg px-3 py-2.5 transition-colors hover:bg-bg-tertiary">
            <span className="text-sm text-text-primary">
              {view.pushStatus.lastSentAt
                ? (t('obliwatch.push.lastSent', { date: formatDateTime(view.pushStatus.lastSentAt) }) || `Last sent: ${formatDateTime(view.pushStatus.lastSentAt)}`)
                : (t('obliwatch.push.neverSent') || 'Nothing sent yet')}
            </span>
            {view.pushStatus.pending > 0 && (
              <StateBadge tone="gray" label={t('obliwatch.push.pending', { count: view.pushStatus.pending }) || `${view.pushStatus.pending} waiting`} />
            )}
            {view.pushStatus.dead > 0 && (
              <StateBadge tone="red" label={t('obliwatch.push.deadLetters', { count: view.pushStatus.dead }) || `${view.pushStatus.dead} not delivered`} />
            )}
            {view.pushStatus.dead > 0 && (
              <Button size="sm" variant="secondary" className="ml-auto" disabled={busy} onClick={retry}>
                {t('obliwatch.push.retry') || 'Send again'}
              </Button>
            )}
          </div>
          {view.pushStatus.pending > 0 && view.pushStatus.lastError && (
            <p className="px-3 text-xs text-text-muted">
              {t('obliwatch.push.lastError', { error: view.pushStatus.lastError }) || `Last failure: ${view.pushStatus.lastError}`}
            </p>
          )}
        </div>
      )}
      <p className="text-xs text-text-muted">
        {view.changedAt
          ? (t('obliwatch.consent.lastChange', { date: formatDateTime(view.changedAt), user: view.changedBy?.username ?? '—' })
            || `Last change: ${formatDateTime(view.changedAt)} by ${view.changedBy?.username ?? '—'}`)
          : (t('obliwatch.consent.neverChanged') || 'Never changed: everything is off.')}
      </p>
    </section>
  );
}
