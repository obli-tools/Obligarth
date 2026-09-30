import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint, Info } from 'lucide-react';
import toast from 'react-hot-toast';
import type { DeviceKeyInfo, DeviceKeyListResponse } from '@obligarth/shared';
import { deviceKeysApi } from '@/api/deviceKeys.api';
import { isStepUpHandled } from '@/api/client';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { useAuthStore } from '@/store/authStore';
import { DeviceKeyList } from './DeviceKeyList';

// Profile › "Téléphones de validation" (docs/mobile/device-bound-2fa.md §8):
// the account's phones registered in the Android app for fingerprint
// validation, with Revoke / Revoke all (no step-up: revoking only reduces
// access [D8b]). Hidden on a server without device keys (404), and while the
// feature is off for an account without any phone (nothing to show or do).

/** Window event: the account's trusted IPs changed (a phone revocation
 *  forgets them all, §6.7) — the "Trusted IPs" section reloads. */
export const TRUSTED_IPS_CHANGED_EVENT = 'obli:trusted-ips-changed';

export function DeviceKeysSection({ ssoAccount = false }: { ssoAccount?: boolean }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const [data, setData] = useState<DeviceKeyListResponse | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = async () => {
    try { setData(await deviceKeysApi.mine()); }
    catch { setData(null); }
    finally { setLoaded(true); }
  };
  useEffect(() => { load(); }, []);

  if (!loaded || !data) return null;

  const revoke = async (k: DeviceKeyInfo) => {
    const label = k.label || t('deviceKeys.list.unnamed', 'Android phone');
    if (!(await confirm({
      message: t('deviceKeys.list.revokeConfirm', {
        label,
        defaultValue: 'Revoke {{label}}? This phone will be signed out immediately. Your trusted IPs will also be forgotten: the next sensitive action will ask for a code again.',
      }),
      danger: true,
      confirmLabel: t('deviceKeys.list.revoke', 'Revoke'),
    }))) return;
    setBusyId(k.id);
    try {
      await deviceKeysApi.revokeMine(k.id);
      toast.success(t('deviceKeys.list.revoked', 'Phone revoked'));
      if (k.current) { window.location.href = '/login'; return; }
      window.dispatchEvent(new Event(TRUSTED_IPS_CHANGED_EVENT));
      await load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(t('common.error', 'Error'));
    } finally { setBusyId(null); }
  };

  const revokeAll = async () => {
    if (!(await confirm({
      message: t('deviceKeys.list.revokeAllConfirm', 'Revoke every phone of this account? They will be signed out immediately. Your trusted IPs will also be forgotten: the next sensitive action will ask for a code again.'),
      danger: true,
      confirmLabel: t('deviceKeys.list.revokeAll', 'Revoke all'),
    }))) return;
    setBusyId('*');
    try {
      await deviceKeysApi.revokeAllMine();
      toast.success(t('deviceKeys.list.revokedAll', 'All phones revoked'));
      if (data.boundKeyId) { window.location.href = '/login'; return; }
      window.dispatchEvent(new Event(TRUSTED_IPS_CHANGED_EVENT));
      await load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(t('common.error', 'Error'));
    } finally { setBusyId(null); }
  };

  const { policy, eligibility } = data;
  // Feature off and no phone: nothing to show nor to do on this profile.
  if (!policy.enabled && data.keys.length === 0) return null;
  // Why a phone cannot be added right now (the list itself stays usable).
  // Operator-side problems (no APP_URL) are for the platform administrators
  // only (Settings shows them too); users see what THEY can act on.
  const reason = eligibility?.ok ? null : eligibility?.reason;
  const notice = !policy.enabled
    ? t('deviceKeys.disabledByAdmin', 'Disabled by the administrator of this server.')
    : ssoAccount && !policy.ssoSupported
      ? t('deviceKeys.ssoUnsupported', 'Not available yet for Obligate accounts.')
      : !policy.originConfigured
        ? (isPlatformAdmin ? t('deviceKeys.originUnset', 'This server has no public address configured (APP_URL or CLIENT_ORIGIN). Ask the administrator.') : null)
        : reason === 'no_totp'
          ? t('deviceKeys.list.needTotp', 'To add a phone, first enable an authenticator app (two-factor authentication) on this profile, then use the Android app.')
          : reason === 'enrol_locked'
            ? t('deviceKeys.enrolLocked', 'Too many attempts. Enabling is blocked for 24 hours.')
            : null;
  // The "add from the app" hint only when this account can add one now.
  const canAdd = policy.enabled && policy.originConfigured && !notice && eligibility?.ok !== false;

  return (
    <div id="device-keys" className="mt-8 rounded-xl bg-bg-secondary p-4 sm:p-6 scroll-mt-6">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-text-primary">
            <Fingerprint size={18} className="text-accent" />
            {t('deviceKeys.list.title', 'Validation phones')}
          </h2>
          <p className="mt-0.5 text-xs text-text-muted">
            {t('deviceKeys.list.intro', 'Phones where sensitive actions of this account are validated with the fingerprint instead of a code.')}
          </p>
        </div>
        {data.keys.length > 0 && (
          <button
            type="button"
            onClick={revokeAll}
            disabled={busyId !== null}
            className="rounded border border-red-400/30 px-2.5 py-1 text-xs text-red-400 hover:bg-red-400/10 disabled:opacity-50 coarse:px-3 coarse:py-2"
          >
            {t('deviceKeys.list.revokeAll', 'Revoke all')}
          </button>
        )}
      </div>

      {notice && (
        <div className="mb-3 flex items-start gap-2 rounded-md border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-300">
          <Info size={14} className="mt-0.5 shrink-0" />
          {notice}
        </div>
      )}

      <DeviceKeyList keys={data.keys} onRevoke={revoke} busyId={busyId} />

      {canAdd && (
        <p className="mt-3 text-[11px] text-text-muted">
          {t('deviceKeys.list.addHint', 'Phones are added from the Android app, in Profile and security.')}
        </p>
      )}
    </div>
  );
}
