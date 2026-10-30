import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, FileUp } from 'lucide-react';
import type { AgentKiosk, AgentTile, AgentWifiItem, JsonValue, MobiControlTemplate, MobiControlTile } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS, hardOfLockdown, isAgentPackageName, isOwnAgentPackage, lockdownPayloads, parseTemplates, profileSettings, tilesOf } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import { ChipChoice, fieldCls } from './ui';

// The import of a MobiControl kiosk (lot PONT-POL §12.2, §12.3) into the draft of the policy editor: the lockdown
// templates, the profiles export and the images, picked locally and read in the browser (shared/mdm/mobicontrolImport):
// the tiles of a template joined to the menu items of a profile's lockdown, its flags, and the restrictions, password
// and Wi-Fi of the profile. The imported HTML is only read by regular expressions: it never reaches the DOM (B12: no
// raw HTML injection, no inline frame). The images used are uploaded to the store; the exit PIN and the masked values of
// the export stay to be typed; nothing is published.

export interface MobiControlImportResult {
  kiosk: AgentKiosk | null;
  dpm: Record<string, JsonValue>;
  knox: Record<string, JsonValue>;
  wifi: AgentWifiItem[];
  required: string[];
}

interface EditableTile extends MobiControlTile { pkg: string; keep: boolean }

const slug = (s: string, i: number): string => {
  const base = s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return `${base || 'tile'}-${i}`.replace(/^[^a-z0-9]+/, 't');
};

export function MobiControlImportDialog({ open, onClose, hasKiosk, onStoreChanged, onApply }: {
  open: boolean; onClose: () => void; hasKiosk: boolean; onStoreChanged: () => void; onApply: (r: MobiControlImportResult) => void;
}) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [templates, setTemplates] = useState<MobiControlTemplate[]>([]);
  const [profiles, setProfiles] = useState<unknown>(null);
  const [images, setImages] = useState<File[]>([]);
  const [profileName, setProfileName] = useState<string | null>(null);
  const [templateRef, setTemplateRef] = useState<string | null>(null);
  const [tiles, setTiles] = useState<EditableTile[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (!open) { setTemplates([]); setProfiles(null); setImages([]); setProfileName(null); setTemplateRef(null); setTiles([]); setError(null); } }, [open]);

  const lockdowns = useMemo(() => (profiles ? lockdownPayloads(profiles) : []), [profiles]);
  const lockdown = lockdowns.find((l) => l.profileName === profileName) ?? null;
  const template = templates.find((x) => (lockdown?.templateRef ? x.referenceId === lockdown.templateRef : x.referenceId === templateRef || x.name === templateRef)) ?? null;
  const imageNames = useMemo(() => images.map((f) => f.name), [images]);
  const parsed = useMemo(() => (template ? tilesOf(template.html, lockdown ? lockdown.menuItems : null, imageNames) : null), [template, lockdown, imageNames]);
  useEffect(() => {
    setTiles((parsed?.tiles ?? []).map((x) => ({ ...x, pkg: x.action?.type === 'app' ? x.action.package : '', keep: true })));
  }, [parsed]);
  const settings = useMemo(() => (profiles ? profileSettings(profiles, { profile: profileName }) : null), [profiles, profileName]);
  const urls = useMemo(() => new Map(images.map((f) => [f.name, URL.createObjectURL(f)])), [images]);
  useEffect(() => () => { for (const u of urls.values()) URL.revokeObjectURL(u); }, [urls]);

  const readFiles = async (list: FileList | null) => {
    if (!list) return;
    setError(null);
    const tpl: Array<{ name: string; text: string }> = [];
    const imgs: File[] = [];
    for (const f of Array.from(list)) {
      if (/\.(png|jpe?g|gif|ico)$/i.test(f.name)) { imgs.push(f); continue; }
      if (f.size > 4 * 1024 * 1024) continue;
      const text = await f.text();
      if (/\.json$/i.test(f.name) && /^\s*\[/.test(text)) {
        try { setProfiles(JSON.parse(text)); } catch { setError(t('legacyAgentPolicy.import.badProfiles') || 'The profiles export is not valid JSON.'); }
      } else tpl.push({ name: f.name, text });
    }
    if (tpl.length) setTemplates((prev) => [...prev, ...parseTemplates(tpl)]);
    if (imgs.length) setImages((prev) => [...prev, ...imgs]);
  };

  const usable = tiles.filter((x) => x.keep && (x.action?.type !== 'app' || (isAgentPackageName(x.pkg) && !isOwnAgentPackage(x.pkg))) && (x.action || isAgentPackageName(x.pkg)));

  const apply = async () => {
    if (hasKiosk && template && !(await confirm({ message: t('legacyAgentPolicy.import.replace') || 'Replace the kiosk of this draft by the imported one?', danger: true }))) return;
    setBusy(true); setError(null);
    try {
      // The images used, uploaded to the store (the server checks their magic bytes and size).
      const byName = new Map<string, { sha256: string; size: number; name: string }>();
      const wanted = new Set<string>([...usable.map((x) => x.image).filter((x): x is string => !!x), ...(parsed?.logo ? [parsed.logo] : [])]);
      for (const name of wanted) {
        const f = images.find((i) => i.name === name);
        if (!f || f.size > LEGACY_AGENT_POLICY_LIMITS.imageBytes) continue;
        try {
          const up = await legacyAgentApi.files.upload(f, name.replace(/^[0-9a-f]{8}-/i, ''));
          byName.set(name, { sha256: up.sha256, size: up.sizeBytes, name: up.name });
        } catch { /* an image refused: the tile keeps the app icon */ }
      }
      if (byName.size) {
        await legacyAgentApi.importImages([...byName.values()].map((v) => ({ name: v.name, sha256: v.sha256 })));
        onStoreChanged();
      }
      const kioskTiles: AgentTile[] = usable.slice(0, LEGACY_AGENT_POLICY_LIMITS.tiles).map((x, i) => ({
        id: slug(x.label || 'tile', i), label: (x.label || x.pkg || `Tile ${i + 1}`).slice(0, LEGACY_AGENT_POLICY_LIMITS.labelMax),
        action: x.action && x.action.type !== 'app' ? x.action : { type: 'app', package: x.pkg },
        ...(x.image && byName.get(x.image) ? { image: byName.get(x.image)! } : {}),
        ...(x.launchOnStart ? { launchOnStart: true } : {}),
      }));
      const kiosk: AgentKiosk | null = template ? {
        enabled: true, columns: parsed?.columns ?? 3, tiles: kioskTiles, exitPin: { $secretValue: '' },
        ...(parsed?.showDeviceName ? { showDeviceName: true } : {}),
        ...(parsed?.logo && byName.get(parsed.logo) ? { logo: byName.get(parsed.logo)! } : {}),
        ...(lockdown ? { hard: hardOfLockdown(lockdown.flags) } : {}),
      } : null;
      const wifi: AgentWifiItem[] = (settings?.wifi ?? []).filter((w) => w.ssid).map((w) => (w.security === 'wpa2_psk'
        ? { ssid: w.ssid, security: 'wpa2_psk', psk: { $secretValue: '' } }
        : { ssid: w.ssid, security: 'wpa2_eap_peap', eap: { identity: w.identity ?? '', password: { $secretValue: '' }, phase2: 'mschapv2' } }));
      onApply({ kiosk, dpm: settings?.dpm ?? {}, knox: settings?.knox ?? {}, wifi, required: settings?.required ?? [] });
    } catch (err) {
      setError(apiErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={open} onClose={onClose} size="xl" title={t('legacyAgentPolicy.import.title') || 'Import from MobiControl'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button loading={busy} disabled={!template && !settings} onClick={() => void apply()}>{t('legacyAgentPolicy.import.apply') || 'Import into the draft'}</Button>
        </>
      )}>
      <div className="space-y-4 text-sm">
        <p className="text-xs text-text-muted">{t('legacyAgentPolicy.import.intro') || 'Pick the lockdown templates, the profiles export (JSON) and the images. Everything is read in this browser; nothing is published.'}</p>
        <label className="inline-flex cursor-pointer items-center gap-1.5 text-accent hover:underline">
          <input type="file" multiple className="hidden" onChange={(e) => { void readFiles(e.target.files); e.target.value = ''; }} />
          <FileUp className="h-4 w-4" />{t('legacyAgentPolicy.import.pick') || 'Pick files…'}
        </label>
        <p className="text-xs text-text-muted">
          {t('legacyAgentPolicy.import.counts', { templates: templates.length, images: images.length, profiles: lockdowns.length })
            || `${templates.length} template(s), ${images.length} image(s), ${lockdowns.length} profile(s) with a kiosk`}
        </p>
        {error && <p className="text-xs text-red-400">{error}</p>}

        {lockdowns.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-xs text-text-muted">{t('legacyAgentPolicy.import.profile') || 'Profile'}</span>
            <ChipChoice value={profileName ?? ''} onChange={(v) => setProfileName(v || null)}
              options={[{ id: '', label: t('legacyAgentPolicy.import.noProfile') || 'Template only' }, ...lockdowns.map((l) => ({ id: l.profileName, label: l.profileName }))]} />
            {lockdown && lockdown.groupPaths.length > 0 && <p className="text-[11px] text-text-muted">{lockdown.groupPaths.join(' · ')}</p>}
          </div>
        )}
        {!lockdown && templates.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-xs text-text-muted">{t('legacyAgentPolicy.import.template') || 'Template'}</span>
            <ChipChoice value={templateRef ?? ''} onChange={(v) => setTemplateRef(v || null)}
              options={templates.map((x) => ({ id: x.referenceId ?? x.name, label: x.name }))} />
          </div>
        )}

        {parsed && (
          <div className="space-y-2">
            {parsed.issues.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {parsed.issues.map((i, n) => <span key={n} className="rounded-full bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-400">{trCode(`legacyAgentPolicy.import.issues.${i.code}`, i.code)}{i.tile ? ` · ${i.tile}` : ''}</span>)}
              </div>
            )}
            <div className="grid gap-2 rounded-xl bg-bg-secondary p-3" style={{ gridTemplateColumns: `repeat(${parsed.columns}, minmax(0, 1fr))` }}>
              {tiles.map((x, i) => (
                <div key={x.index} className={`space-y-1 rounded-lg p-2 text-center ${x.keep ? '' : 'opacity-40'}`}>
                  {x.image && urls.get(x.image) ? <img src={urls.get(x.image)} alt="" className="mx-auto h-12 w-12 object-contain" />
                    : <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg bg-bg-tertiary text-text-muted">{(x.label || '?').charAt(0)}</span>}
                  <input className={`${fieldCls} text-center text-xs`} value={x.label} maxLength={40} onChange={(e) => setTiles((p) => p.map((y, j) => (j === i ? { ...y, label: e.target.value } : y)))} />
                  {(!x.action || x.action.type === 'app') && (
                    <input className={`${fieldCls} font-mono text-[11px]`} value={x.pkg} placeholder="com.example.app" onChange={(e) => setTiles((p) => p.map((y, j) => (j === i ? { ...y, pkg: e.target.value.trim() } : y)))} />
                  )}
                  {x.action && x.action.type !== 'app' && <span className="block truncate text-[11px] text-text-muted">{x.action.type === 'url' ? x.action.url : x.action.uri}</span>}
                  <div className="flex flex-wrap justify-center gap-1">
                    {x.issues.map((c) => <span key={c} className="rounded-full bg-amber-400/10 px-1.5 text-[10px] text-amber-400">{trCode(`legacyAgentPolicy.import.issues.${c}`, c)}</span>)}
                  </div>
                  <button type="button" className="text-[11px] text-text-muted hover:text-text-primary" onClick={() => setTiles((p) => p.map((y, j) => (j === i ? { ...y, keep: !y.keep } : y)))}>
                    {x.keep ? (t('legacyAgentPolicy.import.leaveOut') || 'Leave out') : (t('legacyAgentPolicy.import.keep') || 'Keep')}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {settings && (settings.required.length > 0 || settings.unmapped.length > 0 || settings.issues.length > 0 || Object.keys(settings.knox).length > 0) && (
          <div className="space-y-1.5 rounded-lg bg-bg-secondary p-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('legacyAgentPolicy.import.settings') || 'Profile settings'}</span>
            <p className="text-xs text-text-secondary">
              {t('legacyAgentPolicy.import.settingsCounts', { knox: Object.keys(settings.knox).length, dpm: Object.keys(settings.dpm).length, wifi: settings.wifi.length })
                || `${Object.keys(settings.knox).length} Knox restriction(s), ${Object.keys(settings.dpm).length} administrator setting(s), ${settings.wifi.length} network(s)`}
            </p>
            {settings.required.length > 0 && (
              <p className="flex gap-1.5 text-xs text-amber-400"><AlertTriangle className="h-3.5 w-3.5 shrink-0" />{t('legacyAgentPolicy.import.required') || 'To type before publishing:'} {settings.required.join(', ')}</p>
            )}
            {settings.issues.map((i, n) => <p key={n} className="text-xs text-amber-400">{trCode(`legacyAgentPolicy.import.issues.${i.code}`, i.code)}{i.detail ? ` (${i.detail})` : ''}</p>)}
            {settings.unmapped.length > 0 && <p className="text-[11px] text-text-muted">{t('legacyAgentPolicy.import.unmapped') || 'Not mapped:'} {settings.unmapped.slice(0, 20).join(', ')}</p>}
          </div>
        )}
      </div>
    </Modal>
  );
}
