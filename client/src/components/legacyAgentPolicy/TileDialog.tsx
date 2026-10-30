import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { AgentTile, AgentTileAction, LegacyAgentFileView } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS, isAgentPackageName, isAgentTileUrl, isIntentUriWellFormed, isOwnAgentPackage, isUnsafeIntentUri, normalizeIntentUri } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { ChipChoice, Field, StorePicker, fieldCls } from './ui';

// A tile of the bridge agent's kiosk (lot PONT-POL §11.1): its label, its image (a store image), and what it opens — an
// app by its package, an http(s) URL (optionally in one browser), or an intent URI. An intent that names the agent,
// carries launch flags, a selector, a browser fallback or a file/content scheme is refused here as on the server (B1).

export function TileDialog({ open, tile, taken, files, onUploaded, onClose, onSave }: {
  open: boolean; tile: AgentTile | null; taken: string[]; files: LegacyAgentFileView[] | null; onUploaded: () => void;
  onClose: () => void; onSave: (t: AgentTile) => void;
}) {
  const { t } = useTranslation();
  const [d, setD] = useState<AgentTile>(() => tile ?? empty());
  useEffect(() => { if (open) setD(tile ?? empty()); }, [open, tile]);
  const set = (p: Partial<AgentTile>) => setD((x) => ({ ...x, ...p }));
  const setAction = (a: AgentTileAction) => set({ action: a });
  const a = d.action;
  const actionOk = a.type === 'app' ? isAgentPackageName(a.package) && !isOwnAgentPackage(a.package)
    : a.type === 'url' ? isAgentTileUrl(a.url) && (!a.package || (isAgentPackageName(a.package) && !isOwnAgentPackage(a.package)))
      : isIntentUriWellFormed(a.uri) && !isUnsafeIntentUri(normalizeIntentUri(a.uri) ?? '');
  const idOk = LEGACY_AGENT_POLICY_LIMITS.idRe.test(d.id) && (d.id === tile?.id || !taken.includes(d.id));
  const labelOk = d.label.trim().length > 0 && d.label.length <= LEGACY_AGENT_POLICY_LIMITS.labelMax;
  return (
    <Modal open={open} onClose={onClose} size="md" title={tile ? (t('legacyAgentPolicy.kiosk.editTile') || 'Edit a tile') : (t('legacyAgentPolicy.kiosk.addTile') || 'Add a tile')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={!actionOk || !idOk || !labelOk} onClick={() => onSave(a.type === 'intent' ? { ...d, action: { type: 'intent', uri: normalizeIntentUri(a.uri) ?? a.uri } } : d)}>
            {t('common.save') || 'Save'}
          </Button>
        </>
      )}>
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('legacyAgentPolicy.kiosk.label') || 'Label'}>
            <input className={fieldCls} value={d.label} maxLength={LEGACY_AGENT_POLICY_LIMITS.labelMax} placeholder="Catalogue" onChange={(e) => set({ label: e.target.value })} />
          </Field>
          <Field label={t('legacyAgentPolicy.files.id') || 'Identifier'}>
            <input className={fieldCls} value={d.id} maxLength={48} placeholder="catalog" onChange={(e) => set({ id: e.target.value.toLowerCase() })} />
          </Field>
        </div>
        <Field label={t('legacyAgentPolicy.kiosk.action') || 'Opens'}>
          <ChipChoice value={a.type} onChange={(type) => setAction(type === 'app' ? { type: 'app', package: '' } : type === 'url' ? { type: 'url', url: 'https://' } : { type: 'intent', uri: 'intent:#Intent;end' })}
            options={[{ id: 'app', label: t('legacyAgentPolicy.kiosk.app') || 'An app' }, { id: 'url', label: t('legacyAgentPolicy.kiosk.url') || 'A web address' }, { id: 'intent', label: t('legacyAgentPolicy.kiosk.intent') || 'An intent' }]} />
        </Field>
        {a.type === 'app' && (
          <Field label={t('legacyAgentPolicy.kiosk.package') || 'Package'}>
            <input className={`${fieldCls} font-mono`} value={a.package} placeholder="com.example.catalog" onChange={(e) => setAction({ type: 'app', package: e.target.value.trim() })} />
          </Field>
        )}
        {a.type === 'url' && (
          <>
            <Field label="URL"><input className={`${fieldCls} font-mono`} value={a.url} placeholder="https://www.example.com" onChange={(e) => setAction({ ...a, url: e.target.value.trim() })} /></Field>
            <Field label={t('legacyAgentPolicy.kiosk.browser') || 'Browser package (optional)'}>
              <input className={`${fieldCls} font-mono`} value={a.package ?? ''} placeholder="com.example.browser" onChange={(e) => setAction({ ...a, package: e.target.value.trim() || null })} />
            </Field>
          </>
        )}
        {a.type === 'intent' && (
          <Field label="Intent URI" hint={t('legacyAgentPolicy.kiosk.intentHint') || 'intent:…#Intent;…;end — no launch flags, no selector, never the agent itself.'}>
            <textarea className={`${fieldCls} font-mono text-[11px]`} rows={3} spellCheck={false} value={a.uri} onChange={(e) => setAction({ type: 'intent', uri: e.target.value.trim() })} />
          </Field>
        )}
        <Field label={t('legacyAgentPolicy.kiosk.image') || 'Image (optional: the app icon otherwise)'}>
          <StorePicker kind="image" files={files} value={d.image?.sha256} onUploaded={onUploaded} onPick={(f) => set({ image: { sha256: f.sha256, size: f.sizeBytes, name: f.name } })} />
          {d.image && <button type="button" className="mt-1 text-xs text-text-muted hover:text-red-400" onClick={() => set({ image: null })}>{t('legacyAgentPolicy.kiosk.noImage') || 'No image'}</button>}
        </Field>
        <ToggleSwitch checked={d.launchOnStart === true} onChange={(v) => set({ launchOnStart: v || undefined })} label={t('legacyAgentPolicy.kiosk.launchOnStart') || 'Open after a restart'} />
      </div>
    </Modal>
  );
}

function empty(): AgentTile {
  return { id: '', label: '', action: { type: 'app', package: '' } };
}
