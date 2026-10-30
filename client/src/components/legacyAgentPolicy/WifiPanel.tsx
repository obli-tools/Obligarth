import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pencil, Plus, Trash2, Wifi } from 'lucide-react';
import type { AgentWifiItem, LegacyAgentFileView, PolicyValidationIssue } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS, isValidSsid } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { WifiDialog } from './WifiDialog';
import { IssueList, fieldCls, issuesUnder } from './ui';

// The Wi-Fi networks of the bridge agent's policy (lot PONT-POL §11.1), and the networks to remove, which only a
// licensed Knox can do (a profile another app created cannot be changed by the agent otherwise; D5). The agent never
// turns Wi-Fi on.

export function WifiPanel({ wifi, remove, editable, issues, store, onStoreChanged, onChange }: {
  wifi: AgentWifiItem[]; remove: string[]; editable: boolean; issues: PolicyValidationIssue[]; store: LegacyAgentFileView[] | null;
  onStoreChanged: () => void; onChange: (next: { wifi: AgentWifiItem[]; remove: string[] }) => void;
}) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<{ index: number | null } | null>(null);
  const [toRemove, setToRemove] = useState('');
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="flex items-center">
          <p className="text-xs text-text-muted">{t('legacyAgentPolicy.wifi.intro') || 'Networks added to the devices; their passwords stay in the vault.'}</p>
          {editable && wifi.length < LEGACY_AGENT_POLICY_LIMITS.wifi && (
            <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setEditing({ index: null })}><Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.wifi.add') || 'Add a network'}</Button>
          )}
        </div>
        {wifi.length === 0 ? <p className="text-sm text-text-muted">{t('legacyAgentPolicy.wifi.none') || 'No network.'}</p> : (
          <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
            {wifi.map((w, i) => (
              <li key={`${w.ssid}-${i}`} className="px-3 py-2 text-sm hover:bg-bg-tertiary">
                <div className="flex flex-wrap items-center gap-2">
                  <Wifi className="h-4 w-4 text-text-muted" />
                  <span className="font-medium text-text-primary">{w.ssid}</span>
                  <span className="rounded-full bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
                    {w.security === 'wpa2_psk' ? (t('legacyAgentPolicy.wifi.psk') || 'WPA2 personal') : (t('legacyAgentPolicy.wifi.peap') || 'WPA2 enterprise (PEAP)')}
                  </span>
                  {(w.preferOver ?? []).length > 0 && <span className="text-[11px] text-text-muted">{t('legacyAgentPolicy.wifi.preferOverShort') || 'preferred over'} {(w.preferOver ?? []).join(', ')}</span>}
                  {w.autoConnect === false && <span className="text-[11px] text-text-muted">{t('legacyAgentPolicy.wifi.manual') || 'manual'}</span>}
                  {editable && (
                    <span className="ml-auto flex">
                      <button type="button" className="rounded p-1.5 text-text-muted hover:text-text-primary" aria-label={t('common.edit') || 'Edit'} onClick={() => setEditing({ index: i })}><Pencil className="h-4 w-4" /></button>
                      <button type="button" className="rounded p-1.5 text-text-muted hover:text-red-400" aria-label={t('common.delete') || 'Delete'} onClick={() => onChange({ wifi: wifi.filter((_, j) => j !== i), remove })}><Trash2 className="h-4 w-4" /></button>
                    </span>
                  )}
                </div>
                <IssueList issues={issuesUnder(issues, `wifi[${i}]`)} />
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('legacyAgentPolicy.wifi.removeTitle') || 'Remove these networks'}</h3>
          <span className="rounded-full bg-violet-400/10 px-2 py-0.5 text-[11px] text-violet-400">{t('legacyAgentPolicy.knoxRequired') || 'Knox licence required'}</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {remove.length === 0 && <span className="text-sm text-text-muted">{t('legacyAgentPolicy.wifi.removeNone') || 'None.'}</span>}
          {remove.map((s) => (
            <button key={s} type="button" disabled={!editable} className="rounded-full bg-bg-tertiary px-2 py-0.5 text-xs text-text-primary enabled:hover:text-red-400"
              onClick={() => onChange({ wifi, remove: remove.filter((x) => x !== s) })}>{s}{editable ? ' ×' : ''}</button>
          ))}
        </div>
        {editable && remove.length < LEGACY_AGENT_POLICY_LIMITS.wifiRemove && (
          <div className="flex max-w-md gap-2">
            <input className={fieldCls} value={toRemove} maxLength={32} placeholder="Corp-Legacy" onChange={(e) => setToRemove(e.target.value)} />
            <Button size="sm" variant="secondary" disabled={!isValidSsid(toRemove) || remove.includes(toRemove) || wifi.some((w) => w.ssid === toRemove)}
              onClick={() => { onChange({ wifi, remove: [...remove, toRemove] }); setToRemove(''); }}>{t('common.add') || 'Add'}</Button>
          </div>
        )}
        <IssueList issues={issuesUnder(issues, 'wifiRemove')} />
      </div>

      <WifiDialog open={editing !== null} item={editing?.index != null ? wifi[editing.index] : null} taken={wifi.map((w) => w.ssid)} files={store}
        onUploaded={onStoreChanged} onClose={() => setEditing(null)}
        onSave={(w) => {
          onChange({ wifi: editing?.index != null ? wifi.map((x, j) => (j === editing.index ? w : x)) : [...wifi, w], remove });
          setEditing(null);
        }} />
    </div>
  );
}
