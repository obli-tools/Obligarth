import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { AgentWifiItem, LegacyAgentFileView } from '@obligarth/shared';
import { isValidSsid } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { ChipChoice, Field, SecretInput, StorePicker, fieldCls } from './ui';

// The dialog of a Wi-Fi network of the bridge agent (lot PONT-POL §11.1): SSID, security (WPA2 personal, or WPA2
// enterprise PEAP/MSCHAPv2 with a CA from the store or pasted), priority, auto-connection, hidden, and the networks it
// is preferred over (Android 7 largely ignores the priority). Secrets are write-only: a stored one shows "Set", typing
// replaces it. The placeholders are fictitious examples only.

export function WifiDialog({ open, item, taken, files, onUploaded, onClose, onSave }: {
  open: boolean; item: AgentWifiItem | null; taken: string[]; files: LegacyAgentFileView[] | null; onUploaded: () => void;
  onClose: () => void; onSave: (w: AgentWifiItem) => void;
}) {
  const { t } = useTranslation();
  const [d, setD] = useState<AgentWifiItem>(() => item ?? empty());
  const [prefer, setPrefer] = useState('');
  useEffect(() => { if (open) { setD(item ?? empty()); setPrefer(''); } }, [open, item]);
  const set = (p: Partial<AgentWifiItem>) => setD((x) => ({ ...x, ...p }));
  const eap = d.eap ?? { identity: '', password: { $secretValue: '' }, phase2: 'mschapv2' as const };
  const setEap = (p: Partial<NonNullable<AgentWifiItem['eap']>>) => set({ eap: { ...eap, ...p } });
  const ssidOk = isValidSsid(d.ssid) && (d.ssid === item?.ssid || !taken.includes(d.ssid));
  const secretOk = d.security === 'wpa2_psk' ? !!d.psk : !!d.eap?.password && !!d.eap.identity;
  const caOk = d.security === 'wpa2_psk' || !!d.eap?.caPem || !!d.eap?.caFile || d.eap?.allowNoCa === true;

  return (
    <Modal open={open} onClose={onClose} size="lg" title={item ? (t('legacyAgentPolicy.wifi.edit') || 'Edit a network') : (t('legacyAgentPolicy.wifi.add') || 'Add a network')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={!ssidOk || !secretOk || !caOk} onClick={() => {
            const out: AgentWifiItem = { ...d };
            if (out.security === 'wpa2_psk') delete out.eap; else { delete out.psk; out.eap = eap; }
            onSave(out);
          }}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="space-y-4">
        <Field label="SSID">
          <input className={fieldCls} value={d.ssid} maxLength={32} placeholder="Corp-Private" onChange={(e) => set({ ssid: e.target.value })} />
        </Field>
        <Field label={t('legacyAgentPolicy.wifi.security') || 'Security'}>
          <ChipChoice value={d.security} onChange={(s) => set({ security: s })}
            options={[{ id: 'wpa2_psk', label: t('legacyAgentPolicy.wifi.psk') || 'WPA2 personal' }, { id: 'wpa2_eap_peap', label: t('legacyAgentPolicy.wifi.peap') || 'WPA2 enterprise (PEAP)' }]} />
        </Field>
        {d.security === 'wpa2_psk' ? (
          <Field label={t('legacyAgentPolicy.wifi.password') || 'Password'} hint={t('legacyAgentPolicy.wifi.pskHint') || '8 to 63 characters, or 64 hexadecimal digits.'}>
            <SecretInput value={d.psk} onChange={(v) => set({ psk: v })} />
          </Field>
        ) : (
          <div className="space-y-3 rounded-lg bg-bg-secondary p-3">
            <Field label={t('legacyAgentPolicy.wifi.identity') || 'Identity'}>
              <input className={fieldCls} value={eap.identity} maxLength={128} placeholder="svc-wifi@example.com" onChange={(e) => setEap({ identity: e.target.value })} />
            </Field>
            <Field label={t('legacyAgentPolicy.wifi.anonymous') || 'Anonymous identity (optional)'}>
              <input className={fieldCls} value={eap.anonymousIdentity ?? ''} maxLength={128} onChange={(e) => setEap({ anonymousIdentity: e.target.value || null })} />
            </Field>
            <Field label={t('legacyAgentPolicy.wifi.password') || 'Password'}>
              <SecretInput value={eap.password} onChange={(v) => setEap({ password: v ?? { $secretValue: '' } })} />
            </Field>
            <Field label={t('legacyAgentPolicy.wifi.ca') || 'CA certificate'}>
              <StorePicker kind="certificate" files={files} value={eap.caFile?.sha256} onUploaded={onUploaded}
                onPick={(f) => setEap({ caFile: { sha256: f.sha256, size: f.sizeBytes, name: f.name }, caPem: null })} />
            </Field>
            <Field label={t('legacyAgentPolicy.wifi.caPem') || 'Or paste the PEM'}>
              <textarea className={`${fieldCls} font-mono text-[11px]`} rows={4} spellCheck={false} value={eap.caPem ?? ''}
                placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => setEap({ caPem: e.target.value || null, ...(e.target.value ? { caFile: null } : {}) })} />
            </Field>
            <Field label={t('legacyAgentPolicy.wifi.domain') || 'Server domain (suffix match, optional)'}>
              <input className={fieldCls} value={eap.domainSuffixMatch ?? ''} maxLength={253} placeholder="radius.example.com" onChange={(e) => setEap({ domainSuffixMatch: e.target.value || null })} />
            </Field>
            <ToggleSwitch checked={eap.allowNoCa === true} onChange={(v) => setEap({ allowNoCa: v || undefined })}
              label={t('legacyAgentPolicy.wifi.noCa') || 'Allow without a CA (not recommended)'}
              description={t('legacyAgentPolicy.wifi.noCaHint') || 'The device would accept any server: only while a device refuses the CA.'} />
          </div>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('legacyAgentPolicy.wifi.priority') || 'Priority (0 to 100)'}>
            <input className={fieldCls} inputMode="numeric" value={String(d.priority ?? 40)} maxLength={3}
              onChange={(e) => { const n = Number(e.target.value.replace(/[^0-9]/g, '')); set({ priority: Math.min(100, Number.isFinite(n) ? n : 0) }); }} />
          </Field>
          <div className="space-y-2 pt-4">
            <ToggleSwitch checked={d.autoConnect !== false} onChange={(v) => set({ autoConnect: v ? undefined : false })} label={t('legacyAgentPolicy.wifi.autoConnect') || 'Connect automatically'} />
            <ToggleSwitch checked={d.hidden === true} onChange={(v) => set({ hidden: v || undefined })} label={t('legacyAgentPolicy.wifi.hidden') || 'Hidden network'} />
          </div>
        </div>
        <Field label={t('legacyAgentPolicy.wifi.preferOver') || 'Prefer over these networks'} hint={t('legacyAgentPolicy.wifi.preferHint') || 'When the device is on one of them and this network is in range, it switches (once every 6 hours at most).'}>
          <div className="space-y-1.5">
            <div className="flex flex-wrap gap-1.5">
              {(d.preferOver ?? []).map((s) => (
                <button key={s} type="button" className="rounded-full bg-bg-tertiary px-2 py-0.5 text-xs text-text-primary hover:text-red-400"
                  onClick={() => set({ preferOver: (d.preferOver ?? []).filter((x) => x !== s) })}>{s} ×</button>
              ))}
            </div>
            <div className="flex gap-2">
              <input className={fieldCls} value={prefer} maxLength={32} placeholder="Corp-Legacy" onChange={(e) => setPrefer(e.target.value)} />
              <Button size="sm" variant="secondary" disabled={!isValidSsid(prefer) || prefer === d.ssid || (d.preferOver ?? []).includes(prefer) || (d.preferOver ?? []).length >= 8}
                onClick={() => { set({ preferOver: [...(d.preferOver ?? []), prefer] }); setPrefer(''); }}>{t('common.add') || 'Add'}</Button>
            </div>
          </div>
        </Field>
      </div>
    </Modal>
  );
}

function empty(): AgentWifiItem {
  return { ssid: '', security: 'wpa2_psk', priority: 40 };
}
