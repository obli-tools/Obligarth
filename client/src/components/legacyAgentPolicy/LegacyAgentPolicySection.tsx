import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FileText, KeyRound, LayoutGrid, ShieldBan, Trash2, Wifi } from 'lucide-react';
import type { LegacyAgentPolicySection as Section, PolicyValidationIssue } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { SegmentedTabs, type SegmentedTab } from '@/components/common/SegmentedTabs';
import { CertsPanel } from './CertsPanel';
import { FilesPanel } from './FilesPanel';
import { KioskPanel } from './KioskPanel';
import type { MobiControlImportResult } from './MobiControlImportDialog';
import { RestrictionsPanel } from './RestrictionsPanel';
import { WifiPanel } from './WifiPanel';
import { IssueList, useStoreFiles } from './ui';

// The section of the Android bridge agent in the policy editor (lot PONT-POL §11.1): files deposited, Wi-Fi networks,
// the soft kiosk, the device-administrator and Knox restrictions, the CAs of the system store. It applies to the devices
// of the channel legacy_agent with an agent 1.3.0 or later; an older agent ignores it. Secrets are typed write-only and
// moved to the vault at the save; the server validates everything (issues of the pseudo item 'legacyAgent').

type Tab = 'files' | 'wifi' | 'kiosk' | 'restrictions' | 'certs';

/** A section without any content is dropped from the version. */
function compact(s: Section): Section | undefined {
  const out: Section = {};
  if (s.files?.length) out.files = s.files;
  if (s.wifi?.length) out.wifi = s.wifi;
  if (s.wifiRemove?.length) out.wifiRemove = s.wifiRemove;
  if (s.kiosk) out.kiosk = s.kiosk;
  if (s.dpm && Object.keys(s.dpm).length) out.dpm = s.dpm;
  if (s.knox && Object.keys(s.knox).length) out.knox = s.knox;
  if (s.certs?.length) out.certs = s.certs;
  return Object.keys(out).length ? out : undefined;
}

export function LegacyAgentPolicySection({ section, editable, issues, onChange }: {
  section: Section | undefined; editable: boolean; issues: PolicyValidationIssue[]; onChange: (next: Section | undefined) => void;
}) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>('files');
  const [present, setPresent] = useState(!!section);
  const store = useStoreFiles();
  const s = section ?? {};
  const set = (patch: Partial<Section>) => onChange(compact({ ...s, ...patch }));
  const under = (prefix: string) => issues.filter((i) => i.path === prefix || i.path.startsWith(`${prefix}.`) || i.path.startsWith(`${prefix}[`));
  const loose = issues.filter((i) => !/^(files|wifi|wifiRemove|kiosk|dpm|knox|certs)([.[]|$)/.test(i.path));

  if (!section && !present) {
    if (!editable) return null;
    return (
      <section className="rounded-xl bg-bg-secondary p-3">
        <Button size="sm" variant="secondary" onClick={() => setPresent(true)}>{t('legacyAgentPolicy.addSection') || 'Add a section: Android agent (device administrator)'}</Button>
      </section>
    );
  }

  const count = (n: number) => (n > 0 ? <span className="min-w-5 rounded-full bg-accent/15 px-1.5 text-[11px] leading-5 text-accent tabular-nums">{n}</span> : undefined);
  const tabs: Array<SegmentedTab<Tab>> = [
    { id: 'files', label: t('legacyAgentPolicy.tabs.files') || 'Files', icon: <FileText size={14} />, badge: count(s.files?.length ?? 0) },
    { id: 'wifi', label: t('legacyAgentPolicy.tabs.wifi') || 'Wi-Fi', icon: <Wifi size={14} />, badge: count((s.wifi?.length ?? 0) + (s.wifiRemove?.length ?? 0)) },
    { id: 'kiosk', label: t('legacyAgentPolicy.tabs.kiosk') || 'Kiosk', icon: <LayoutGrid size={14} />, badge: count(s.kiosk ? s.kiosk.tiles.length : 0) },
    { id: 'restrictions', label: t('legacyAgentPolicy.tabs.restrictions') || 'Restrictions', icon: <ShieldBan size={14} />,
      badge: count(Object.keys(s.dpm ?? {}).length + Object.keys(s.knox ?? {}).length) },
    { id: 'certs', label: t('legacyAgentPolicy.tabs.certs') || 'Certificates', icon: <KeyRound size={14} />, badge: count(s.certs?.length ?? 0) },
  ];
  const mergeImport = (r: MobiControlImportResult) => {
    const wifi = [...(s.wifi ?? [])];
    for (const w of r.wifi) if (!wifi.some((x) => x.ssid === w.ssid)) wifi.push(w);
    onChange(compact({ ...s, ...(r.kiosk ? { kiosk: r.kiosk } : {}), dpm: { ...(s.dpm ?? {}), ...r.dpm }, knox: { ...(s.knox ?? {}), ...r.knox }, wifi }));
  };

  return (
    <section className="space-y-3 rounded-xl bg-bg-secondary/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold text-text-primary">{t('legacyAgentPolicy.title') || 'Android agent (device administrator)'}</h2>
        <span className="text-[11px] text-text-muted">{t('legacyAgentPolicy.minVersion') || 'agent 1.3.0 and later'}</span>
        {editable && (
          <Button size="sm" variant="ghost" className="ml-auto" onClick={() => { onChange(undefined); setPresent(false); }}>
            <Trash2 className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.removeSection') || 'Remove the section'}
          </Button>
        )}
      </div>
      <IssueList issues={loose} />
      <SegmentedTabs tabs={tabs} value={tab} onChange={setTab} size="sm" fill={false} ariaLabel={t('legacyAgentPolicy.title') || 'Android agent'} />
      {tab === 'files' && <FilesPanel files={s.files ?? []} editable={editable} issues={under('files')} store={store.files} onStoreChanged={store.reload} onChange={(files) => set({ files })} />}
      {tab === 'wifi' && (
        <WifiPanel wifi={s.wifi ?? []} remove={s.wifiRemove ?? []} editable={editable} issues={[...under('wifi'), ...under('wifiRemove')]} store={store.files}
          onStoreChanged={store.reload} onChange={(n) => set({ wifi: n.wifi, wifiRemove: n.remove })} />
      )}
      {tab === 'kiosk' && (
        <KioskPanel kiosk={s.kiosk} editable={editable} issues={under('kiosk')} store={store.files} onStoreChanged={store.reload}
          onChange={(k) => set({ kiosk: k })} onImportSettings={mergeImport} />
      )}
      {tab === 'restrictions' && (
        <RestrictionsPanel dpm={s.dpm ?? {}} knox={s.knox ?? {}} editable={editable} issues={[...under('dpm'), ...under('knox')]} onChange={(n) => set({ dpm: n.dpm, knox: n.knox })} />
      )}
      {tab === 'certs' && <CertsPanel certs={s.certs ?? []} editable={editable} issues={under('certs')} onChange={(certs) => set({ certs })} />}
    </section>
  );
}
