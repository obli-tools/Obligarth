import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Eye, Plus, Trash2 } from 'lucide-react';
import type { AgentFileItem, LegacyAgentDeviceView, LegacyAgentFileView } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS, isAgentFilePath } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { apiErrorMessage } from '@/utils/apiError';
import { ChipChoice, Field, StorePicker, fieldCls } from './ui';

// The dialog of a deposited file (lot PONT-POL §11.1): its id, its target paths (up to 4, the same content deposited to
// each; Download/ and the storage root as presets; another app's data folder only with its toggle), its source (a file
// of the store, or a template rendered per device with {{device.custom.<name>}}), the overwrite and removal behaviour.
// A template is previewed on one device by the server (never logged); the rendered text is shown as plain text.

const BASE_VARIABLES = ['device.name', 'device.serial_number', 'device.model', 'device.uuid', 'tenant.name'];

export function FileDialog({ open, item, taken, files, onUploaded, onClose, onSave }: {
  open: boolean; item: AgentFileItem | null; taken: string[]; files: LegacyAgentFileView[] | null; onUploaded: () => void;
  onClose: () => void; onSave: (item: AgentFileItem) => void;
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<AgentFileItem>(() => item ?? emptyFile());
  const [customKeys, setCustomKeys] = useState<string[]>([]);
  const [devices, setDevices] = useState<LegacyAgentDeviceView[]>([]);
  const [deviceQuery, setDeviceQuery] = useState('');
  const [preview, setPreview] = useState<{ text: string; missing: string[]; jsonValid: boolean | null } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  useEffect(() => { if (open) { setDraft(item ?? emptyFile()); setPreview(null); setPreviewError(null); } }, [open, item]);
  useEffect(() => {
    if (!open) return;
    legacyAgentApi.customKeys().then(setCustomKeys).catch(() => setCustomKeys([]));
    legacyAgentApi.devices({}).then(setDevices).catch(() => setDevices([]));
  }, [open]);

  const set = (patch: Partial<AgentFileItem>) => setDraft((d) => ({ ...d, ...patch }));
  const pathsOk = draft.paths.length > 0 && draft.paths.every((p) => isAgentFilePath(p, { allowAppDataDir: draft.allowAppDataDir === true }));
  const idOk = LEGACY_AGENT_POLICY_LIMITS.idRe.test(draft.id) && (draft.id === item?.id || !taken.includes(draft.id));
  const sourceOk = draft.source.kind === 'store' ? !!draft.source.sha256 : draft.source.text.length > 0;
  const shownDevices = useMemo(() => {
    const q = deviceQuery.trim().toLowerCase();
    return devices.filter((d) => !q || (d.name ?? '').toLowerCase().includes(q)).slice(0, 12);
  }, [devices, deviceQuery]);

  const insertVariable = (name: string) => {
    if (draft.source.kind !== 'template') return;
    set({ source: { ...draft.source, text: `${draft.source.text}{{${name}}}` } });
  };
  const runPreview = async (deviceId: number) => {
    if (draft.source.kind !== 'template') return;
    setPreview(null); setPreviewError(null);
    try { setPreview(await legacyAgentApi.renderPreview(draft.source.text, draft.source.encoding, deviceId)); } catch (err) { setPreviewError(apiErrorMessage(err)); }
  };

  return (
    <Modal open={open} onClose={onClose} size="lg" title={item ? (t('legacyAgentPolicy.files.edit') || 'Edit a file') : (t('legacyAgentPolicy.files.add') || 'Add a file')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={!pathsOk || !idOk || !sourceOk} onClick={() => onSave(draft)}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="space-y-4">
        <Field label={t('legacyAgentPolicy.files.id') || 'Identifier'} hint={t('legacyAgentPolicy.files.idHint') || 'Lower-case letters, digits, - and _ (the key of the setting).'}>
          <input className={fieldCls} value={draft.id} maxLength={48} placeholder="store-conf" onChange={(e) => set({ id: e.target.value.toLowerCase() })} />
        </Field>

        <div className="space-y-1.5">
          <span className="text-xs text-text-muted">{t('legacyAgentPolicy.files.paths') || 'Target paths (relative to the storage, up to 4)'}</span>
          {draft.paths.map((p, i) => (
            <div key={i} className="flex items-center gap-2">
              <input className={`${fieldCls} font-mono`} value={p} maxLength={LEGACY_AGENT_POLICY_LIMITS.pathMax} placeholder="Download/conf_store.json"
                onChange={(e) => set({ paths: draft.paths.map((x, j) => (j === i ? e.target.value : x)) })} />
              {!isAgentFilePath(p, { allowAppDataDir: draft.allowAppDataDir === true }) && p && <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" aria-label="invalid" />}
              {draft.paths.length > 1 && (
                <button type="button" className="rounded p-1.5 text-text-muted hover:bg-bg-tertiary hover:text-red-400" aria-label={t('common.delete') || 'Delete'}
                  onClick={() => set({ paths: draft.paths.filter((_, j) => j !== i) })}><Trash2 className="h-4 w-4" /></button>
              )}
            </div>
          ))}
          {draft.paths.length < LEGACY_AGENT_POLICY_LIMITS.pathsPerFile && (
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="ghost" onClick={() => set({ paths: [...draft.paths, 'Download/'] })}><Plus className="mr-1 h-3.5 w-3.5" />Download/</Button>
              <Button size="sm" variant="ghost" onClick={() => set({ paths: [...draft.paths, ''] })}><Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.files.root') || 'Storage root'}</Button>
            </div>
          )}
          <ToggleSwitch checked={draft.allowAppDataDir === true} onChange={(v) => set({ allowAppDataDir: v || undefined })}
            label={t('legacyAgentPolicy.files.appData') || 'Application data folder'}
            description={t('legacyAgentPolicy.files.appDataHint') || 'Admits Android/data/<package>/files/…: the file is written into another app\'s folder.'} />
        </div>

        <div className="space-y-2">
          <span className="text-xs text-text-muted">{t('legacyAgentPolicy.files.source') || 'Source'}</span>
          <ChipChoice value={draft.source.kind} onChange={(k) => set({ source: k === 'store' ? { kind: 'store', sha256: '', size: 0, name: '' } : { kind: 'template', text: '', encoding: 'json' } })}
            options={[{ id: 'store', label: t('legacyAgentPolicy.files.storeSource') || 'Stored file' }, { id: 'template', label: t('legacyAgentPolicy.files.templateSource') || 'Per-device template' }]} />
          {draft.source.kind === 'store' && (
            <StorePicker kind="file" files={files} value={draft.source.sha256} onUploaded={onUploaded}
              onPick={(f) => set({ source: { kind: 'store', sha256: f.sha256, size: f.sizeBytes, name: f.name } })} />
          )}
          {draft.source.kind === 'template' && (
            <div className="space-y-2">
              <ChipChoice value={draft.source.encoding} onChange={(enc) => set({ source: { ...(draft.source as { kind: 'template'; text: string }), kind: 'template', encoding: enc } })}
                options={[{ id: 'json', label: 'JSON' }, { id: 'text', label: t('legacyAgentPolicy.files.text') || 'Text' }]} />
              <textarea className={`${fieldCls} font-mono text-xs`} rows={8} spellCheck={false} value={draft.source.text}
                maxLength={LEGACY_AGENT_POLICY_LIMITS.templateBytes}
                placeholder={'{\n  "codeMag": "{{device.custom.storeCode}}"\n}'}
                onChange={(e) => set({ source: { ...(draft.source as { kind: 'template'; encoding: 'text' | 'json' }), kind: 'template', text: e.target.value } })} />
              <div className="flex flex-wrap gap-1.5">
                <span className="text-[11px] text-text-muted">{t('legacyAgentPolicy.files.variables') || 'Insert:'}</span>
                {[...BASE_VARIABLES, ...customKeys.map((k) => `device.custom.${k}`)].map((v) => (
                  <button key={v} type="button" onClick={() => insertVariable(v)} className="rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-[11px] text-text-muted hover:text-text-primary">{v}</button>
                ))}
              </div>
              <div className="space-y-1.5 rounded-lg bg-bg-secondary p-2">
                <span className="flex items-center gap-1 text-xs text-text-muted"><Eye className="h-3.5 w-3.5" />{t('legacyAgentPolicy.files.preview') || 'Preview on a device'}</span>
                <input className={fieldCls} value={deviceQuery} placeholder={t('legacyAgentPolicy.files.searchDevice') || 'Search a device…'} onChange={(e) => setDeviceQuery(e.target.value)} />
                <div className="flex flex-wrap gap-1.5">
                  {shownDevices.map((d) => (
                    <button key={d.deviceId} type="button" onClick={() => void runPreview(d.deviceId)} className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-muted hover:text-text-primary">{d.name ?? d.deviceUuid}</button>
                  ))}
                </div>
                {previewError && <p className="text-xs text-red-400">{previewError}</p>}
                {preview && (
                  <div className="space-y-1">
                    {preview.missing.length > 0 && <p className="text-xs text-amber-400">{t('legacyAgentPolicy.files.missing') || 'Without a value on this device:'} {preview.missing.join(', ')}</p>}
                    {preview.jsonValid === false && <p className="text-xs text-red-400">{t('legacyAgentPolicy.files.jsonInvalid') || 'The rendered file is not valid JSON.'}</p>}
                    <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-bg-tertiary p-2 font-mono text-[11px] text-text-primary">{preview.text}</pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('legacyAgentPolicy.files.overwrite') || 'When the file exists'}>
              <ChipChoice value={draft.overwrite ?? 'always'} onChange={(v) => set({ overwrite: v })}
                options={[{ id: 'always', label: t('legacyAgentPolicy.files.always') || 'Overwrite' }, { id: 'if_absent', label: t('legacyAgentPolicy.files.ifAbsent') || 'Keep (once)' }]} />
            </Field>
            <Field label={t('legacyAgentPolicy.files.onRemove') || 'When removed from the policy'}>
              <ChipChoice value={draft.onRemove ?? 'keep'} onChange={(v) => set({ onRemove: v })}
                options={[{ id: 'keep', label: t('legacyAgentPolicy.files.keep') || 'Keep the file' }, { id: 'delete', label: t('legacyAgentPolicy.files.delete') || 'Delete it' }]} />
            </Field>
        </div>
        <ToggleSwitch checked={draft.mediaScan !== false} onChange={(v) => set({ mediaScan: v ? undefined : false })}
          label={t('legacyAgentPolicy.files.mediaScan') || 'Make it visible to the other apps (media scan)'} />
      </div>
    </Modal>
  );
}

function emptyFile(): AgentFileItem {
  return { id: '', paths: ['Download/'], source: { kind: 'template', text: '', encoding: 'json' } };
}
