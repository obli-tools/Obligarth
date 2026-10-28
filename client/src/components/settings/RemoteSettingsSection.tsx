import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Clock, MonitorSmartphone } from 'lucide-react';
import toast from 'react-hot-toast';
import { REMOTE_LIMITS, type RemoteSettings, type RemoteSettingsDto } from '@obligarth/shared';
import { remoteApi } from '@/api/remote.api';
import { Button } from '@/components/common/Button';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { useAuthStore } from '@/store/authStore';
import { apiErrorMessage } from '@/utils/apiError';

// Settings › Remote assistance (P0-15 §4.1, §4.6, D9, D14, D16): the settings of the tenant's remote assistance
// sessions. Read with Settings or audit.read; a change (Settings) is always an approval request examined by a second
// person, and one of the MSP that touches the client approval of its sessions by a client approver only. Hidden when
// the server refuses the reading.

const KEYS = ['mspSessionsNeedClientApproval', 'maxMinutes', 'waitChannel'] as const;

export function RemoteSettingsSection() {
  const { t } = useTranslation();
  const { isAdmin, permissions } = useAuthStore();
  const canEdit = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('settings');
  const [cfg, setCfg] = useState<RemoteSettingsDto | null>(null);
  const [draft, setDraft] = useState<RemoteSettings | null>(null);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    try {
      const c = await remoteApi.settings();
      setCfg(c);
      setDraft({ mspSessionsNeedClientApproval: c.mspSessionsNeedClientApproval, maxMinutes: c.maxMinutes, waitChannel: c.waitChannel });
    } catch {
      setCfg(null);
    }
  };
  useEffect(() => { load(); }, []);

  if (!cfg || !draft) return null;

  const changes = Object.fromEntries(KEYS.filter((k) => draft[k] !== cfg[k]).map((k) => [k, draft[k]])) as Partial<RemoteSettings>;
  const minutesValid = Number.isInteger(draft.maxMinutes) && draft.maxMinutes >= REMOTE_LIMITS.maxMinutesMin && draft.maxMinutes <= REMOTE_LIMITS.maxMinutesMax;
  const editable = canEdit && !cfg.pending && !saving;

  const submit = async () => {
    setSaving(true);
    try {
      await remoteApi.requestSettings(changes);
      toast.success(t('remote.settings.requested') || 'Change requested: it waits for its approval.');
      await load();
    } catch (err) {
      toast.error(apiErrorMessage(err, t('remote.settings.failed') || 'The change could not be requested.'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <h2 className="mb-2 flex items-center gap-2 text-lg font-semibold text-text-primary">
        <MonitorSmartphone size={18} className="text-accent" />
        {t('remote.settings.title') || 'Remote assistance'}
      </h2>
      <p className="mb-4 text-sm text-text-muted">
        {t('remote.settings.intro') || 'The remote assistance sessions of this tenant. A change is examined by a second person; a change made by the MSP to the client approval of its sessions is examined by a client approver.'}
      </p>
      <div className="divide-y divide-border rounded-lg bg-bg-secondary">
        {cfg.pending && (
          <div className="flex items-start gap-2 p-4 text-xs text-amber-300">
            <Clock size={14} className="mt-0.5 shrink-0" />
            {t('remote.settings.pending', { id: cfg.pending.approvalId }) || `A change waits for its approval (request #${cfg.pending.approvalId}).`}
          </div>
        )}
        <div className="flex items-start justify-between gap-4 p-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-text-primary">{t('remote.settings.mspApproval') || 'Sessions of the MSP approved by the client'}</p>
            <p className="mt-0.5 text-xs text-text-muted">
              {t('remote.settings.mspApprovalDesc') || 'Every session asked by a technician of the MSP waits for the approval of a designated client approver of the tenant.'}
            </p>
          </div>
          <ToggleSwitch
            checked={draft.mspSessionsNeedClientApproval}
            onChange={(v) => setDraft({ ...draft, mspSessionsNeedClientApproval: v })}
            disabled={!editable}
            ariaLabel={t('remote.settings.mspApproval') || 'Sessions of the MSP approved by the client'}
          />
        </div>
        <div className="flex flex-wrap items-start justify-between gap-4 p-4">
          <div className="min-w-0 flex-1">
            <label htmlFor="remote-max-minutes" className="text-sm font-medium text-text-primary">
              {t('remote.settings.maxMinutes') || 'Maximum duration of a session'}
            </label>
            <p className="mt-0.5 text-xs text-text-muted">
              {t('remote.settings.maxMinutesDesc', { min: REMOTE_LIMITS.maxMinutesMin, max: REMOTE_LIMITS.maxMinutesMax })
                || `From ${REMOTE_LIMITS.maxMinutesMin} to ${REMOTE_LIMITS.maxMinutesMax} minutes; the session ends when it is reached.`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              id="remote-max-minutes"
              type="number"
              inputMode="numeric"
              min={REMOTE_LIMITS.maxMinutesMin}
              max={REMOTE_LIMITS.maxMinutesMax}
              step={5}
              value={Number.isFinite(draft.maxMinutes) ? draft.maxMinutes : ''}
              onChange={(e) => setDraft({ ...draft, maxMinutes: e.target.value === '' ? NaN : Number(e.target.value) })}
              disabled={!editable}
              aria-invalid={!minutesValid}
              className="w-24 rounded-md border border-border bg-bg-primary px-2 py-1.5 text-sm text-text-primary disabled:opacity-60"
            />
            <span className="text-xs text-text-muted">{t('remote.settings.minutes') || 'minutes'}</span>
          </div>
        </div>
        <div className="flex items-start justify-between gap-4 p-4">
          <div className="min-w-0">
            <p className="text-sm font-medium text-text-primary">{t('remote.settings.waitChannel') || 'Permanent wake-up of the Android agents'}</p>
            <p className="mt-0.5 text-xs text-text-muted">
              {t('remote.settings.waitChannelDesc') || 'Off by default: an agent keeps a long wait only for 15 minutes after « Ask for help » or after a session. Turning it on costs battery and mobile data on every device: decide after the measures of the pilot.'}
            </p>
          </div>
          <ToggleSwitch
            checked={draft.waitChannel}
            onChange={(v) => setDraft({ ...draft, waitChannel: v })}
            disabled={!editable}
            ariaLabel={t('remote.settings.waitChannel') || 'Permanent wake-up of the Android agents'}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 p-4">
          <p className="text-xs text-text-muted">
            {canEdit
              ? t('remote.settings.approvalNote') || 'The change applies once approved.'
              : t('remote.settings.readOnly') || 'Read only: changing these settings needs the Settings capability.'}
          </p>
          {canEdit && (
            <Button size="sm" onClick={submit} disabled={!editable || Object.keys(changes).length === 0 || !minutesValid}>
              {t('remote.settings.request') || 'Request the change'}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
