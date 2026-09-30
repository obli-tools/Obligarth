import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint, AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import toast from 'react-hot-toast';
import type { AppConfigData, DeviceKeyListResponse, DeviceKeySettingKey, DeviceKeysSsoStatus } from '@obliance/shared';
import { appConfigApi } from '@/api/appConfig.api';
import { deviceKeysApi } from '@/api/deviceKeys.api';
import { isStepUpHandled } from '@/api/client';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { useConfirm } from '@/components/common/ConfirmDialog';

// Settings › "Validation par téléphone" (platform admins) — docs/mobile/
// device-bound-2fa.md §8–§9 [D15]: the four platform switches (on by
// default) and the enrolment origin state (APP_URL / DEVICE_KEY_ORIGINS
// [D17]). Enrolment itself happens in the Android app.

const ROWS: Array<{ key: DeviceKeySettingKey; label: [string, string]; desc: [string, string] }> = [
  {
    key: 'device_keys_enabled',
    label: ['deviceKeys.settings.enabled', 'Fingerprint validation'],
    desc: ['deviceKeys.settings.enabledDesc', 'Phones registered in the Android app validate sensitive actions with the fingerprint instead of a code. Off: no fingerprint anywhere, keys are kept.'],
  },
  {
    key: 'device_keys_login',
    label: ['deviceKeys.settings.login', 'Sign-in with the fingerprint'],
    desc: ['deviceKeys.settings.loginDesc', 'Local accounts sign in to the app with their password and the fingerprint instead of a code.'],
  },
  {
    key: 'device_keys_require_attestation',
    label: ['deviceKeys.settings.requireAttestation', 'Hardware attestation required'],
    desc: ['deviceKeys.settings.requireAttestationDesc', 'A phone must prove (Google key attestation) that its key lives in the secure hardware, on a locked, verified system. Turning this on revokes the phones accepted without it.'],
  },
  {
    key: 'device_keys_strict_session',
    label: ['deviceKeys.settings.strictSession', 'Strict phone session'],
    desc: ['deviceKeys.settings.strictSessionDesc', 'On a registered phone, a code alone is refused (password + code instead). Trusted IPs never apply on a registered phone, whatever this switch says.'],
  },
];

export function DeviceKeysSettingsSection() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [cfg, setCfg] = useState<AppConfigData | null>(null);
  const [info, setInfo] = useState<DeviceKeyListResponse | null>(null);
  const [saving, setSaving] = useState<string | null>(null);

  const load = async () => {
    const [c, i] = await Promise.all([appConfigApi.getConfig().catch(() => null), deviceKeysApi.mine().catch(() => null)]);
    setCfg(c); setInfo(i);
  };
  useEffect(() => { load(); }, []);

  if (!cfg || !info) return null;

  const isOn = (k: DeviceKeySettingKey) => (cfg[k] ?? 'true') === 'true';
  const toggle = async (k: DeviceKeySettingKey) => {
    const next = !isOn(k);
    if (k === 'device_keys_require_attestation' && next && !(await confirm({
      message: t('deviceKeys.settings.confirmRequireAttestation', 'Phones registered without a verified attestation will be revoked now. Continue?'),
      danger: true,
    }))) return;
    setSaving(k);
    try {
      const { pendingApproval } = await appConfigApi.setConfig(k, next);
      await load();
      toast.success(pendingApproval
        ? t('users.sentForApproval', 'Sent for approval to a second administrator')
        : t('common.saved', 'Saved'));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(t('settings.failedUpdate', 'Failed to update settings'));
    } finally { setSaving(null); }
  };

  // DEVICE_KEYS_DISABLED (env) overrides the switch.
  const envOff = isOn('device_keys_enabled') && !info.policy.enabled;
  const origins = info.allowedOrigins;

  return (
    <div>
      <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-text-primary">
        <Fingerprint size={18} className="text-accent" />
        {t('deviceKeys.settings.title', 'Phone validation')}
      </h2>
      <div className="divide-y divide-border rounded-lg bg-bg-secondary">
        {envOff && (
          <div className="flex items-start gap-2 p-4 text-xs text-amber-300">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            {t('deviceKeys.settings.envDisabled', 'Emergency switch DEVICE_KEYS_DISABLED is set on the server: the feature is off whatever the switches below say.')}
          </div>
        )}
        {ROWS.map((row) => (
          <div key={row.key} className={`flex items-start justify-between gap-4 p-4 ${row.key !== 'device_keys_enabled' && !isOn('device_keys_enabled') ? 'opacity-60' : ''}`}>
            <div className="min-w-0">
              <p className="text-sm font-medium text-text-primary">{t(row.label[0], row.label[1])}</p>
              <p className="mt-0.5 text-xs text-text-muted">{t(row.desc[0], row.desc[1])}</p>
            </div>
            <ToggleSwitch
              checked={isOn(row.key)}
              onChange={() => toggle(row.key)}
              disabled={saving !== null}
              ariaLabel={t(row.label[0], row.label[1])}
            />
          </div>
        ))}
        <div className="flex items-start gap-2 p-4 text-xs">
          {origins.length > 0 ? (
            <>
              <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-green-400" />
              <div className="min-w-0 space-y-0.5 text-text-muted">
                {origins.map((o) => (
                  <p key={o} className="break-all">
                    {t('deviceKeys.settings.origin', { origin: o, defaultValue: 'Allowed origin: {{origin}}' })}
                  </p>
                ))}
              </div>
            </>
          ) : (
            <>
              <AlertTriangle size={14} className="mt-0.5 shrink-0 text-red-400" />
              <p className="text-red-400">
                {t('deviceKeys.settings.originMissing', 'Not configured: enrolment is refused. Set APP_URL (or CLIENT_ORIGIN) or DEVICE_KEY_ORIGINS.')}
              </p>
            </>
          )}
        </div>
        {info.ssoStatus && <SsoStatusRow status={info.ssoStatus} />}
      </div>
    </div>
  );
}

// Lot O (phone validation for Obligate accounts): read-only, as the server
// sees it — its switch (DEVICE_KEYS_SSO_ENABLED) and Obligate's capabilities.
const SSO_STATE_TEXT: Record<DeviceKeysSsoStatus['state'], [string, string]> = {
  switch_off: ['deviceKeys.settings.sso.switchOff', 'Off on this server (DEVICE_KEYS_SSO_ENABLED is not set): Obligate accounts validate with their code, as before.'],
  sso_off: ['deviceKeys.settings.sso.ssoOff', 'Obligate sign-in is disabled or not configured.'],
  announced: ['deviceKeys.settings.sso.announced', 'On: Obligate announces the required capabilities, Obligate accounts can register a phone.'],
  withdrawn: ['deviceKeys.settings.sso.withdrawn', 'Closed: Obligate answers without the required capabilities (OAUTH_LOT_O_CAPABILITIES=false). Registered phones fall back to the code.'],
  unreachable: ['deviceKeys.settings.sso.unreachable', 'Obligate cannot be checked right now: phone validation is refused for Obligate accounts, and registered phones cannot validate until it answers. An Obligate older than 0.1.67 also shows here: turn DEVICE_KEYS_SSO_ENABLED off before rolling Obligate back.'],
};

function SsoStatusRow({ status }: { status: DeviceKeysSsoStatus }) {
  const { t } = useTranslation();
  const [key, fallback] = SSO_STATE_TEXT[status.state];
  const tone = status.state === 'announced'
    ? { icon: <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-green-400" />, text: 'text-text-muted' }
    : status.state === 'withdrawn' || status.state === 'unreachable'
      ? { icon: <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-300" />, text: 'text-amber-300' }
      : { icon: <Info size={14} className="mt-0.5 shrink-0 text-text-muted" />, text: 'text-text-muted' };
  return (
    <div className="flex items-start gap-2 p-4 text-xs">
      {tone.icon}
      <div className="min-w-0">
        <p className="font-medium text-text-primary">{t('deviceKeys.settings.sso.title', 'Obligate accounts')}</p>
        <p className={`mt-0.5 ${tone.text}`}>{t(key, fallback)}</p>
      </div>
    </div>
  );
}
