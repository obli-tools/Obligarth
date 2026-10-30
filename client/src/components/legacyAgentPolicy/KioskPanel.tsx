import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowDown, ArrowUp, FileInput, Pencil, Plus, Trash2 } from 'lucide-react';
import type { AgentKiosk, AgentKioskHard, AgentTile, LegacyAgentFileView, PolicyValidationIssue } from '@obligarth/shared';
import { AGENT_KIOSK_BLOCK_KEYS, LEGACY_AGENT_POLICY_LIMITS } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { MobiControlImportDialog, type MobiControlImportResult } from './MobiControlImportDialog';
import { TileDialog } from './TileDialog';
import { ChipChoice, Field, IssueList, SecretInput, StoreImage, StorePicker, fieldCls, issuesUnder } from './ui';

// The soft kiosk of the bridge agent (lot PONT-POL §11.1): the agent becomes the home screen, with tiles; the admin exit
// takes a PIN (8 to 12 digits, stored hashed, never shown); the hard lockdown (system bar, task manager, keys) needs a
// licensed Knox. A live preview of the grid, the images read from the store. The MobiControl kiosk templates import
// into this draft (MobiControlImportDialog); nothing is published by the import.

const HARD: Array<keyof Omit<AgentKioskHard, 'blockKeys'>> = ['hideSystemBar', 'disableStatusBarExpansion', 'disableTaskManager', 'disableSettingsChanges'];

export function KioskPanel({ kiosk, editable, issues, store, onStoreChanged, onChange, onImportSettings }: {
  kiosk: AgentKiosk | null | undefined; editable: boolean; issues: PolicyValidationIssue[]; store: LegacyAgentFileView[] | null;
  onStoreChanged: () => void; onChange: (k: AgentKiosk | null) => void; onImportSettings: (r: MobiControlImportResult) => void;
}) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<{ index: number | null } | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const bySha = new Map((store ?? []).map((f) => [f.sha256, f]));

  if (!kiosk) {
    return (
      <div className="space-y-2">
        <p className="text-sm text-text-muted">{t('legacyAgentPolicy.kiosk.none') || 'No kiosk: the devices keep their launcher.'}</p>
        {editable && (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => onChange({ enabled: true, columns: 3, tiles: [], exitPin: { $secretValue: '' } })}>
              <Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.kiosk.create') || 'Create a kiosk'}
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setImportOpen(true)}><FileInput className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.kiosk.import') || 'Import from MobiControl…'}</Button>
          </div>
        )}
        <MobiControlImportDialog open={importOpen} onClose={() => setImportOpen(false)} hasKiosk={false} onStoreChanged={onStoreChanged}
          onApply={(r) => { if (r.kiosk) onChange(r.kiosk); onImportSettings(r); setImportOpen(false); }} />
      </div>
    );
  }
  const set = (p: Partial<AgentKiosk>) => onChange({ ...kiosk, ...p });
  const setHard = (p: Partial<AgentKioskHard>) => set({ hard: { ...(kiosk.hard ?? {}), ...p } });
  const tiles = kiosk.tiles;
  const move = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= tiles.length) return;
    const next = [...tiles];
    [next[i], next[j]] = [next[j], next[i]];
    set({ tiles: next });
  };
  const cols = kiosk.columns ?? 3;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <ToggleSwitch checked={kiosk.enabled} disabled={!editable} onChange={(v) => set({ enabled: v })} label={t('legacyAgentPolicy.kiosk.enabled') || 'Kiosk enabled'} />
        {editable && (
          <span className="ml-auto flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => setImportOpen(true)}><FileInput className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.kiosk.import') || 'Import from MobiControl…'}</Button>
            <Button size="sm" variant="ghost" onClick={() => onChange(null)}><Trash2 className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.kiosk.remove') || 'Remove the kiosk'}</Button>
          </span>
        )}
      </div>
      <IssueList issues={issues.filter((i) => i.path === 'kiosk' || /^kiosk\.(enabled|title|columns|showDeviceName)/.test(i.path))} />

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t('legacyAgentPolicy.kiosk.title') || 'Title (optional)'}>
          <input className={fieldCls} disabled={!editable} value={kiosk.title ?? ''} maxLength={LEGACY_AGENT_POLICY_LIMITS.titleMax} onChange={(e) => set({ title: e.target.value || null })} />
        </Field>
        <Field label={t('legacyAgentPolicy.kiosk.columns') || 'Columns'}>
          <ChipChoice disabled={!editable} value={String(cols)} onChange={(v) => set({ columns: Number(v) })} options={['2', '3', '4', '5'].map((c) => ({ id: c, label: c }))} />
        </Field>
      </div>
      <ToggleSwitch checked={kiosk.showDeviceName === true} disabled={!editable} onChange={(v) => set({ showDeviceName: v || undefined })} label={t('legacyAgentPolicy.kiosk.deviceName') || 'Show the name of the device'} />
      <Field label={t('legacyAgentPolicy.kiosk.logo') || 'Logo (optional)'}>
        <StorePicker kind="image" files={store} value={kiosk.logo?.sha256} disabled={!editable} onUploaded={onStoreChanged} onPick={(f) => set({ logo: { sha256: f.sha256, size: f.sizeBytes, name: f.name } })} />
      </Field>

      {/* The grid as the devices show it. */}
      <div className="space-y-2">
        <div className="flex items-center">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('legacyAgentPolicy.kiosk.tiles', { count: tiles.length }) || `${tiles.length} tile(s)`}</h3>
          {editable && tiles.length < LEGACY_AGENT_POLICY_LIMITS.tiles && (
            <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setEditing({ index: null })}><Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.kiosk.addTile') || 'Add a tile'}</Button>
          )}
        </div>
        <div className="rounded-xl bg-bg-secondary p-3">
          <div className="mb-3 flex items-center gap-2">
            {kiosk.logo && <StoreImage file={bySha.get(kiosk.logo.sha256)} className="h-8 w-8" />}
            <span className="text-sm font-medium text-text-primary">{kiosk.title || ''}</span>
            {kiosk.showDeviceName && <span className="ml-auto text-xs text-text-muted">{t('legacyAgentPolicy.kiosk.deviceNameSample') || 'Device name'}</span>}
          </div>
          <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
            {tiles.map((tile, i) => (
              <div key={`${tile.id}-${i}`} className="group flex flex-col items-center gap-1 rounded-lg p-2 text-center hover:bg-bg-tertiary">
                {tile.image ? <StoreImage file={bySha.get(tile.image.sha256)} className="h-12 w-12" /> : <span className="flex h-12 w-12 items-center justify-center rounded-lg bg-bg-tertiary text-lg text-text-muted">{tile.label.charAt(0).toUpperCase()}</span>}
                <span className="line-clamp-2 text-[12px] font-bold text-text-secondary">{tile.label}</span>
                {editable && (
                  <span className="flex opacity-70 group-hover:opacity-100">
                    <button type="button" className="p-1 text-text-muted hover:text-text-primary" aria-label={t('legacyAgentPolicy.kiosk.up') || 'Move up'} onClick={() => move(i, -1)}><ArrowUp className="h-3.5 w-3.5" /></button>
                    <button type="button" className="p-1 text-text-muted hover:text-text-primary" aria-label={t('legacyAgentPolicy.kiosk.down') || 'Move down'} onClick={() => move(i, 1)}><ArrowDown className="h-3.5 w-3.5" /></button>
                    <button type="button" className="p-1 text-text-muted hover:text-text-primary" aria-label={t('common.edit') || 'Edit'} onClick={() => setEditing({ index: i })}><Pencil className="h-3.5 w-3.5" /></button>
                    <button type="button" className="p-1 text-text-muted hover:text-red-400" aria-label={t('common.delete') || 'Delete'} onClick={() => set({ tiles: tiles.filter((_, j) => j !== i) })}><Trash2 className="h-3.5 w-3.5" /></button>
                  </span>
                )}
                <IssueList issues={issuesUnder(issues, `kiosk.tiles[${i}]`)} />
              </div>
            ))}
          </div>
          {tiles.length === 0 && <p className="text-sm text-text-muted">{t('legacyAgentPolicy.kiosk.noTile') || 'Add at least one tile.'}</p>}
        </div>
        <IssueList issues={issues.filter((i) => i.path === 'kiosk.tiles')} />
      </div>

      <Field label={t('legacyAgentPolicy.kiosk.pin') || 'Exit PIN (8 to 12 digits)'} hint={t('legacyAgentPolicy.kiosk.pinHint') || 'Five taps on the header open the PIN pad. One PIN for the policy: change it if a device is lost.'}>
        <SecretInput value={kiosk.exitPin} disabled={!editable} inputMode="numeric" onChange={(v) => set({ exitPin: v ?? { $secretValue: '' } })} />
      </Field>
      <IssueList issues={issuesUnder(issues, 'kiosk.exitPin')} />

      <div className="space-y-2 rounded-lg bg-bg-secondary p-3">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('legacyAgentPolicy.kiosk.hard') || 'Hard lockdown'}</h3>
          <span className="rounded-full bg-violet-400/10 px-2 py-0.5 text-[11px] text-violet-400">{t('legacyAgentPolicy.knoxRequired') || 'Knox licence required'}</span>
        </div>
        {HARD.map((h) => (
          <ToggleSwitch key={h} checked={kiosk.hard?.[h] === true} disabled={!editable} onChange={(v) => setHard({ [h]: v || undefined })} label={t(`legacyAgentPolicy.kiosk.hardOptions.${h}`) || h} />
        ))}
        <Field label={t('legacyAgentPolicy.kiosk.blockKeys') || 'Blocked keys'}>
          <div className="flex flex-wrap gap-1.5">
            {AGENT_KIOSK_BLOCK_KEYS.map((k) => {
              const on = (kiosk.hard?.blockKeys ?? []).includes(k);
              return (
                <button key={k} type="button" disabled={!editable}
                  onClick={() => setHard({ blockKeys: on ? (kiosk.hard?.blockKeys ?? []).filter((x) => x !== k) : [...(kiosk.hard?.blockKeys ?? []), k] })}
                  className={`rounded-full px-2.5 py-1 text-xs ${on ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'}`}>
                  {t(`legacyAgentPolicy.kiosk.keys.${k}`) || k}
                </button>
              );
            })}
          </div>
        </Field>
      </div>

      <TileDialog open={editing !== null} tile={editing?.index != null ? tiles[editing.index] : null} taken={tiles.map((x) => x.id)} files={store}
        onUploaded={onStoreChanged} onClose={() => setEditing(null)}
        onSave={(tile: AgentTile) => { set({ tiles: editing?.index != null ? tiles.map((x, j) => (j === editing.index ? tile : x)) : [...tiles, tile] }); setEditing(null); }} />
      <MobiControlImportDialog open={importOpen} onClose={() => setImportOpen(false)} hasKiosk onStoreChanged={onStoreChanged}
        onApply={(r) => { if (r.kiosk) onChange(r.kiosk); onImportSettings(r); setImportOpen(false); }} />
    </div>
  );
}
