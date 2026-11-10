import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Eye, Package, Pencil, Plus, Trash2 } from 'lucide-react';
import type { AgentAppConfigItem, LegacyAgentDeviceView, PolicyValidationIssue } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS as L, isAgentPackageName, isOwnAgentPackage } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { sitesApi } from '@/api/sites.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { apiErrorMessage } from '@/utils/apiError';
import { Field, IssueList, fieldCls, issuesUnder } from './ui';

// The managed configuration of apps (lot P1-QR §6 ter, agent 1.4.2): one instance per app (agent:appconfig:<id>), its
// package and its entries, each a key and a text template rendered per device by the server (strings only). The owner
// of the device sets it with setApplicationRestrictions; the app reads it through RestrictionsManager. An agent that only
// administers the device reports it non-compliant, an older agent never receives it. A variable without a value on a
// device leaves the whole configuration out of that device, as a file template.

const BASE_VARIABLES = ['device.name', 'device.serial_number', 'device.model', 'device.uuid', 'tenant.name'];
const SITE_VARIABLES = ['site.code', 'site.name', 'site.city'];

export function AppConfigPanel({ items, editable, issues, onChange }: {
  items: AgentAppConfigItem[]; editable: boolean; issues: PolicyValidationIssue[]; onChange: (next: AgentAppConfigItem[]) => void;
}) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<{ index: number | null } | null>(null);
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <p className="text-xs text-text-muted">{t('legacyAgentPolicy.appConfig.intro') || 'Values handed to apps as their managed configuration (the app reads them through RestrictionsManager).'}</p>
        <span className="shrink-0 rounded-full bg-violet-400/10 px-2 py-0.5 text-[11px] text-violet-400">{t('legacyAgentPolicy.appConfig.ownerOnly') || 'Device owner, agent 1.4.2'}</span>
        {editable && items.length < L.appConfigs && (
          <Button size="sm" variant="secondary" className="ml-auto shrink-0" onClick={() => setEditing({ index: null })}>
            <Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.appConfig.add') || 'Configure an app'}
          </Button>
        )}
      </div>
      {items.length === 0 ? <p className="text-sm text-text-muted">{t('legacyAgentPolicy.appConfig.none') || 'No app configured.'}</p> : (
        <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
          {items.map((a, i) => (
            <li key={`${a.id}-${i}`} className="px-3 py-2 text-sm hover:bg-bg-tertiary">
              <div className="flex flex-wrap items-center gap-2">
                <Package className="h-4 w-4 text-text-muted" />
                <span className="font-mono text-text-primary">{a.package}</span>
                <span className="rounded-full bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
                  {t('legacyAgentPolicy.appConfig.entryCount', { count: a.entries.length }) || `${a.entries.length} values`}
                </span>
                <span className="truncate text-[11px] text-text-muted">{a.entries.slice(0, 4).map((e) => e.key).join(', ')}{a.entries.length > 4 ? '…' : ''}</span>
                <span className="ml-auto font-mono text-[11px] text-text-muted">{a.id}</span>
                {editable && (
                  <>
                    <button type="button" className="rounded p-1.5 text-text-muted hover:text-text-primary" aria-label={t('common.edit') || 'Edit'} onClick={() => setEditing({ index: i })}><Pencil className="h-4 w-4" /></button>
                    <button type="button" className="rounded p-1.5 text-text-muted hover:text-red-400" aria-label={t('common.delete') || 'Delete'} onClick={() => onChange(items.filter((_, j) => j !== i))}><Trash2 className="h-4 w-4" /></button>
                  </>
                )}
              </div>
              <IssueList issues={issuesUnder(issues, `appConfigs[${i}]`)} />
            </li>
          ))}
        </ul>
      )}
      <AppConfigDialog open={editing !== null} item={editing?.index != null ? items[editing.index] : null}
        others={items.filter((_, j) => j !== editing?.index)} onClose={() => setEditing(null)}
        onSave={(item) => {
          onChange(editing?.index != null ? items.map((a, j) => (j === editing.index ? item : a)) : [...items, item]);
          setEditing(null);
        }} />
    </div>
  );
}

type Preview = { deviceName: string; entries: Array<{ key: string; text: string; missing: string[] }> };

function AppConfigDialog({ open, item, others, onClose, onSave }: {
  open: boolean; item: AgentAppConfigItem | null; others: AgentAppConfigItem[]; onClose: () => void; onSave: (item: AgentAppConfigItem) => void;
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<AgentAppConfigItem>(() => item ?? emptyAppConfig());
  const [focused, setFocused] = useState(0);
  const [customKeys, setCustomKeys] = useState<string[]>([]);
  const [siteKeys, setSiteKeys] = useState<string[]>([]);
  const [devices, setDevices] = useState<LegacyAgentDeviceView[]>([]);
  const [deviceQuery, setDeviceQuery] = useState('');
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  useEffect(() => { if (open) { setDraft(item ?? emptyAppConfig()); setFocused(0); setPreview(null); setPreviewError(null); } }, [open, item]);
  useEffect(() => {
    if (!open) return;
    legacyAgentApi.customKeys().then(setCustomKeys).catch(() => setCustomKeys([]));
    sitesApi.valueKeys().then(setSiteKeys).catch(() => setSiteKeys([]));
    legacyAgentApi.devices({}).then(setDevices).catch(() => setDevices([]));
  }, [open]);

  const set = (patch: Partial<AgentAppConfigItem>) => setDraft((d) => ({ ...d, ...patch }));
  const setEntry = (i: number, patch: Partial<AgentAppConfigItem['entries'][number]>) =>
    set({ entries: draft.entries.map((e, j) => (j === i ? { ...e, ...patch } : e)) });
  const idOk = L.idRe.test(draft.id) && !others.some((o) => o.id === draft.id);
  const pkgOk = isAgentPackageName(draft.package) && !isOwnAgentPackage(draft.package)
    && !others.some((o) => o.package.toLowerCase() === draft.package.toLowerCase());
  const keyOk = (k: string, i: number) => L.appConfigKeyRe.test(k) && !draft.entries.some((e, j) => j !== i && e.key === k);
  const entriesOk = draft.entries.length > 0 && draft.entries.every((e, i) => keyOk(e.key, i) && e.template.length <= L.appConfigValueChars);
  const shownDevices = useMemo(() => {
    const q = deviceQuery.trim().toLowerCase();
    return devices.filter((d) => !q || (d.name ?? '').toLowerCase().includes(q)).slice(0, 12);
  }, [devices, deviceQuery]);
  const variables = [...BASE_VARIABLES, ...customKeys.map((k) => `device.custom.${k}`), ...SITE_VARIABLES, ...siteKeys.map((k) => `site.${k}`)];

  const insertVariable = (name: string) => {
    const i = Math.min(focused, draft.entries.length - 1);
    if (i < 0) return;
    setEntry(i, { template: `${draft.entries[i].template}{{${name}}}` });
  };
  const runPreview = async (d: LegacyAgentDeviceView) => {
    setPreview(null); setPreviewError(null);
    try {
      const entries = await legacyAgentApi.renderAppConfigPreview(draft.entries.map((e) => ({ key: e.key, template: e.template })), d.deviceId);
      setPreview({ deviceName: d.name ?? d.deviceUuid, entries });
    } catch (err) { setPreviewError(apiErrorMessage(err)); }
  };
  const missing = preview ? [...new Set(preview.entries.flatMap((e) => e.missing))] : [];

  return (
    <Modal open={open} onClose={onClose} size="lg"
      title={item ? (t('legacyAgentPolicy.appConfig.edit') || 'Edit the configuration of an app') : (t('legacyAgentPolicy.appConfig.add') || 'Configure an app')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={!idOk || !pkgOk || !entriesOk} onClick={() => onSave({ ...draft, package: draft.package.trim() })}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('legacyAgentPolicy.files.id') || 'Identifier'} hint={t('legacyAgentPolicy.files.idHint') || 'Lower-case letters, digits, - and _ (the key of the setting).'}>
            <input className={fieldCls} value={draft.id} maxLength={48} placeholder="store-app" onChange={(e) => set({ id: e.target.value.toLowerCase() })} />
          </Field>
          <Field label={t('legacyAgentPolicy.appConfig.package') || 'Package of the app'}
            hint={draft.package && !pkgOk ? <span className="text-red-400">{t('legacyAgentPolicy.appConfig.packageInvalid') || 'A package name (com.example.app), not the agent\'s, configured once.'}</span> : undefined}>
            <input className={`${fieldCls} font-mono`} value={draft.package} maxLength={255} placeholder="com.example.store" spellCheck={false}
              onChange={(e) => set({ package: e.target.value.trim() })} />
          </Field>
        </div>

        <div className="space-y-2">
          <span className="text-xs text-text-muted">{t('legacyAgentPolicy.appConfig.entries') || 'Values (key and template, text only)'}</span>
          {draft.entries.map((e, i) => (
            <div key={i} className={`flex items-start gap-2 rounded-lg p-1.5 ${focused === i ? 'bg-bg-secondary' : ''}`}>
              <input className={`${fieldCls} w-48 shrink-0 font-mono`} value={e.key} maxLength={64} placeholder="storeCode" spellCheck={false}
                aria-label={t('legacyAgentPolicy.appConfig.key') || 'Key'} onFocus={() => setFocused(i)}
                onChange={(ev) => setEntry(i, { key: ev.target.value.trim() })} />
              <textarea className={`${fieldCls} font-mono text-xs`} rows={1} spellCheck={false} value={e.template} maxLength={L.appConfigValueChars}
                placeholder="{{device.custom.storeCode}}" aria-label={t('legacyAgentPolicy.appConfig.template') || 'Template'} onFocus={() => setFocused(i)}
                onChange={(ev) => setEntry(i, { template: ev.target.value })} />
              {e.key && !keyOk(e.key, i) && <AlertTriangle className="mt-2 h-4 w-4 shrink-0 text-red-400" aria-label={t('legacyAgentPolicy.appConfig.keyInvalid') || 'Invalid or repeated key'} />}
              <button type="button" className="rounded p-1.5 text-text-muted hover:bg-bg-tertiary hover:text-red-400" aria-label={t('common.delete') || 'Delete'}
                onClick={() => { set({ entries: draft.entries.filter((_, j) => j !== i) }); setFocused(0); }}><Trash2 className="h-4 w-4" /></button>
            </div>
          ))}
          <p className="text-[11px] text-text-muted">{t('legacyAgentPolicy.appConfig.keyHint') || 'A key starts with a letter: letters, digits, _ and . (64 at most).'}</p>
          {draft.entries.length < L.appConfigEntries && (
            <Button size="sm" variant="ghost" onClick={() => { set({ entries: [...draft.entries, { key: '', template: '' }] }); setFocused(draft.entries.length); }}>
              <Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.appConfig.addEntry') || 'Add a value'}
            </Button>
          )}
          {draft.entries.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              <span className="text-[11px] text-text-muted">{t('legacyAgentPolicy.appConfig.insertInto', { key: draft.entries[Math.min(focused, draft.entries.length - 1)]?.key || '…' }) || 'Insert into the selected value:'}</span>
              {variables.map((v) => (
                <button key={v} type="button" onClick={() => insertVariable(v)} className="rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-[11px] text-text-muted hover:text-text-primary">{v}</button>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-1.5 rounded-lg bg-bg-secondary p-2">
          <span className="flex items-center gap-1 text-xs text-text-muted"><Eye className="h-3.5 w-3.5" />{t('legacyAgentPolicy.files.preview') || 'Preview on a device'}</span>
          <input className={fieldCls} value={deviceQuery} placeholder={t('legacyAgentPolicy.files.searchDevice') || 'Search a device…'} onChange={(e) => setDeviceQuery(e.target.value)} />
          <div className="flex flex-wrap gap-1.5">
            {shownDevices.map((d) => (
              <button key={d.deviceId} type="button" disabled={!entriesOk} onClick={() => void runPreview(d)}
                className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-muted hover:text-text-primary disabled:opacity-50">{d.name ?? d.deviceUuid}</button>
            ))}
          </div>
          {previewError && <p className="text-xs text-red-400">{previewError}</p>}
          {preview && (
            <div className="space-y-1">
              <p className="text-[11px] text-text-muted">{preview.deviceName}</p>
              {missing.length > 0 && (
                <p className="text-xs text-amber-400">
                  {t('legacyAgentPolicy.appConfig.missing') || 'Without a value on this device (the configuration is not sent to it):'} {missing.join(', ')}
                </p>
              )}
              <dl className="divide-y divide-border/50 rounded bg-bg-tertiary">
                {preview.entries.map((e) => (
                  <div key={e.key} className="flex gap-3 px-2 py-1 font-mono text-[11px]">
                    <dt className="w-40 shrink-0 truncate text-text-muted">{e.key}</dt>
                    <dd className="min-w-0 whitespace-pre-wrap break-all text-text-primary">{e.text}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}

function emptyAppConfig(): AgentAppConfigItem {
  return { id: '', package: '', entries: [{ key: '', template: '' }] };
}
