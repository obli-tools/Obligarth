import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint } from 'lucide-react';
import toast from 'react-hot-toast';
import type { DeviceKeyInfo } from '@obligarth/shared';
import { deviceKeysApi } from '@/api/deviceKeys.api';
import { isStepUpHandled } from '@/api/client';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { DeviceKeyList } from './DeviceKeyList';

// Administration › Users › "Téléphones de validation" of one account
// (docs/mobile/device-bound-2fa.md §6.5, §8): list + Revoke / Revoke all.
// Server side: users.manage + P1 scope + the tenant.manage_users envelope
// (a code may be asked; at the 'restricted' level the revocation waits for a
// second administrator — 202).

export function DeviceKeysAdminDialog({
  user, onClose,
}: {
  user: { id: number; username: string };
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [keys, setKeys] = useState<DeviceKeyInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const shown = user.username.startsWith('og_') ? user.username.slice(3) : user.username;

  const load = async () => {
    try {
      setKeys(await deviceKeysApi.listForUser(user.id));
      setError(null);
    } catch (err) {
      const msg = (err as { response?: { data?: { error?: unknown } } })?.response?.data?.error;
      setError(typeof msg === 'string' ? msg : t('common.error', 'Error'));
      setKeys([]);
    }
  };
  useEffect(() => { load(); }, [user.id]);

  const done = async (pending: boolean, okMsg: string) => {
    toast.success(pending ? t('users.sentForApproval', 'Sent for approval to a second administrator') : okMsg);
    await load();
  };

  const revoke = async (k: DeviceKeyInfo) => {
    const label = k.label || t('deviceKeys.list.unnamed', 'Android phone');
    if (!(await confirm({
      message: t('deviceKeys.list.adminRevokeConfirm', {
        label,
        defaultValue: 'Revoke {{label}}? This phone will be signed out immediately. The trusted IPs of this user will also be forgotten: their next sensitive action will ask for a code again.',
      }),
      danger: true,
      confirmLabel: t('deviceKeys.list.revoke', 'Revoke'),
    }))) return;
    setBusyId(k.id);
    try {
      await done(await deviceKeysApi.revokeForUser(user.id, k.id), t('deviceKeys.list.revoked', 'Phone revoked'));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(t('common.error', 'Error'));
    } finally { setBusyId(null); }
  };

  const revokeAll = async () => {
    if (!(await confirm({
      message: t('deviceKeys.list.adminRevokeAllConfirm', 'Revoke every phone of this account? They will be signed out immediately. The trusted IPs of this user will also be forgotten: their next sensitive action will ask for a code again.'),
      danger: true,
      confirmLabel: t('deviceKeys.list.revokeAll', 'Revoke all'),
    }))) return;
    setBusyId('*');
    try {
      await done(await deviceKeysApi.revokeAllForUser(user.id), t('deviceKeys.list.revokedAll', 'All phones revoked'));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(t('common.error', 'Error'));
    } finally { setBusyId(null); }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={t('deviceKeys.list.adminTitle', { username: shown, defaultValue: 'Validation phones of {{username}}' })}
      icon={<Fingerprint className="h-4 w-4 text-accent" />}
      size="md"
      bodyClassName="py-4 space-y-3"
      footer={
        <>
          {keys && keys.length > 0 && (
            <button
              type="button"
              onClick={revokeAll}
              disabled={busyId !== null}
              className="mr-auto rounded border border-red-400/30 px-2.5 py-1 text-xs text-red-400 hover:bg-red-400/10 disabled:opacity-50 coarse:px-3 coarse:py-2"
            >
              {t('deviceKeys.list.revokeAll', 'Revoke all')}
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded px-3 py-1.5 text-xs text-text-muted hover:text-text-primary coarse:min-h-10 coarse:px-4"
          >
            {t('common.close', 'Close')}
          </button>
        </>
      }
    >
      {error && <p className="text-xs text-red-400">{error}</p>}
      {keys === null
        ? <p className="text-sm italic text-text-muted">{t('common.loading', 'Loading…')}</p>
        : <DeviceKeyList keys={keys} onRevoke={revoke} busyId={busyId} />}
    </Modal>
  );
}
