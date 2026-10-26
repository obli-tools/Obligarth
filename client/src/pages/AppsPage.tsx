import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AppWindow, Archive, LayoutGrid, List, Plus, RefreshCw, Search, ShoppingBag, Smartphone, Target } from 'lucide-react';
import { SocketEvents, type AppCatalogEntry, type AppDetail, type VppAssetView } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { integrationsApi } from '@/api/integrations.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Drawer } from '@/components/common/Drawer';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { AssignmentsPanel } from '@/components/mdm/Assignments';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The catalog of apps (modele-donnees-mdm §8, lot C4): the apps of the tenant (App Store and Custom Apps of Apple
// Business, licensed by Apps and Books), their licences, what the inventory shows of them, their delivery, and their
// assignments (with their options) through the impact preview like a policy's. Reading: any member; writing:
// mdm.apps.manage. An app is added from a licence of the tenant (the content tokens of the Integrations tab) or by
// its App Store id; its bundle identifier and name are typed (no call to Apple from the console). The Android apps of
// the tenant (lot AN-E) are listed here too; they are added from managed Google Play and opened on their own page
// (/apps/android).

const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
}

export function AppsPage() {
  const { t } = useTranslation();
  const { isAdmin, permissions } = useAuthStore();
  const caps = permissions?.tenantCapabilities ?? [];
  const canManage = isAdmin() || caps.includes('mdm.apps.manage');
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [apps, setApps] = useState<AppCatalogEntry[] | null>(null);
  const [q, setQ] = useState('');
  const [archived, setArchived] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const selected = Number(params.get('app')) || null;
  const select = (id: number | null) => setParams((prev) => {
    const p = new URLSearchParams(prev);
    if (id) p.set('app', String(id)); else p.delete('app');
    return p;
  }, { replace: true });

  const load = useCallback(() => {
    mdmApi.listApps({ archived, q: q.trim() || undefined })
      .then((list) => { setApps(list); setError(null); })
      .catch((err) => { setApps([]); setError(apiErrorMessage(err)); });
  }, [archived, q]);
  useEffect(() => {
    const timer = setTimeout(load, 200);
    return () => clearTimeout(timer);
  }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.POLICY_CHANGED, () => load()), [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => load()), [load]);

  const [family, setFamily] = useState<'all' | 'apple' | 'android'>('all');
  const [view, setView] = useState<'grid' | 'list'>(() => {
    try { return localStorage.getItem(VIEW_KEY) === 'list' ? 'list' : 'grid'; } catch { return 'grid'; }
  });
  const changeView = (v: 'grid' | 'list') => {
    setView(v);
    try { localStorage.setItem(VIEW_KEY, v); } catch { /* per-viewer convenience only */ }
  };
  const counts = useMemo(() => ({
    all: apps?.length ?? 0,
    apple: apps?.filter((a) => a.platformFamily === 'apple').length ?? 0,
    android: apps?.filter((a) => a.platformFamily === 'android').length ?? 0,
  }), [apps]);
  const shown = useMemo(() => (apps ?? []).filter((a) => family === 'all' || a.platformFamily === family), [apps, family]);
  // An Android app opens on its own page (managed Google Play); reading it there needs mdm.apps.manage.
  const open = (a: AppCatalogEntry) => {
    if (a.platformFamily === 'android') { if (canManage) navigate(`/apps/android?app=${a.uuid}`); } else select(a.id);
  };

  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('apps.title') || 'Apps'}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('apps.subtitle') || 'The apps of the tenant, licensed by Apps and Books, and the devices they are installed on.'}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('apps.search') || 'Search an app…'}
            className="w-full pl-9 pr-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-text-muted">
          <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} />{t('apps.showArchived') || 'Show the archived apps'}
        </label>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
        {canManage && (
          <span className="ml-auto flex flex-wrap gap-2">
            <Link to="/apps/android" className="inline-flex items-center rounded-md px-3 py-1.5 text-sm font-medium bg-bg-tertiary text-text-primary hover:bg-bg-hover coarse:min-h-10">
              <ShoppingBag className="w-4 h-4 mr-1" />{t('androidApps.openCatalog') || 'Android apps'}
            </Link>
            <Button size="sm" onClick={() => setAdding(true)}><Plus className="w-4 h-4 mr-1" />{t('apps.add') || 'Add an app'}</Button>
          </span>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div role="tablist" className="inline-flex rounded-lg bg-bg-tertiary p-0.5 text-xs">
          {(['all', 'apple', 'android'] as const).map((f) => (
            <button key={f} type="button" role="tab" aria-selected={family === f} onClick={() => setFamily(f)}
              className={`rounded-md px-3 py-1.5 font-medium transition-colors coarse:min-h-10 ${family === f ? 'bg-bg-secondary text-text-primary shadow-sm' : 'text-text-muted hover:text-text-primary'}`}>
              {f === 'all' ? (t('apps.filterAll') || 'All') : f === 'apple' ? (t('apps.filterApple') || 'Apple') : (t('apps.filterAndroid') || 'Android')}
              <span className="ml-1.5 tabular-nums text-text-muted">{counts[f]}</span>
            </button>
          ))}
        </div>
        <div className="ml-auto inline-flex rounded-lg bg-bg-tertiary p-0.5">
          {(['grid', 'list'] as const).map((v) => (
            <button key={v} type="button" aria-pressed={view === v} onClick={() => changeView(v)}
              aria-label={v === 'grid' ? (t('apps.viewGrid') || 'Grid') : (t('apps.viewList') || 'List')}
              title={v === 'grid' ? (t('apps.viewGrid') || 'Grid') : (t('apps.viewList') || 'List')}
              className={`rounded-md p-1.5 coarse:min-h-10 coarse:min-w-10 ${view === v ? 'bg-bg-secondary text-text-primary shadow-sm' : 'text-text-muted hover:text-text-primary'}`}>
              {v === 'grid' ? <LayoutGrid className="w-4 h-4" /> : <List className="w-4 h-4" />}
            </button>
          ))}
        </div>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {apps === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : apps.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">
            <p className="font-medium text-text-primary mb-1">{t('apps.empty') || 'No app yet'}</p>
            <p className="text-sm">{t('apps.emptyHint') || 'Connect a content token of Apps and Books in the Integrations tab, then add the apps whose licences the tenant holds.'}</p>
          </div>
        ) : shown.length === 0 ? (
          <p className="p-6 text-center text-sm text-text-muted">{t('apps.noneForFilter') || 'No app for this platform.'}</p>
        ) : view === 'grid' ? (
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
            {shown.map((a) => (
              <button key={a.id} type="button" onClick={() => open(a)}
                className={`group relative flex flex-col items-center rounded-2xl bg-bg-secondary px-3 pt-5 pb-3 text-center transition hover:-translate-y-0.5 hover:bg-bg-tertiary hover:shadow-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 ${a.archivedAt ? 'opacity-60' : ''}`}>
                <AppIcon app={a} size="lg" />
                <span className="mt-3 line-clamp-2 min-h-[2.5rem] text-sm font-semibold leading-5 text-text-primary">{a.name}</span>
                <span className="w-full truncate text-xs text-text-muted">{a.publisher || a.identifier}</span>
                <span className="mt-3 flex w-full items-center justify-between gap-1 border-t border-border/50 pt-2 text-[11px] text-text-muted">
                  <FamilyTag family={a.platformFamily} />
                  <LicenceTag app={a} />
                  <span className="inline-flex items-center gap-0.5 tabular-nums" title={t('apps.assignments') || 'Assignments'}>
                    <Target className="w-3 h-3" />{a.assignments}
                  </span>
                </span>
                {a.archivedAt && <span className="absolute right-2 top-2"><StateBadge tone="gray" label={t('apps.archived') || 'Archived'} /></span>}
              </button>
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">{t('apps.name') || 'Name'}</th>
                  <th className="font-medium px-3 py-2">{t('apps.identifier') || 'Identifier'}</th>
                  <th className="font-medium px-3 py-2">{t('apps.licences') || 'Licences'}</th>
                  <th className="font-medium px-3 py-2 text-right">{t('apps.assignments') || 'Assignments'}</th>
                  <th className="font-medium px-4 py-2">{t('apps.updated') || 'Updated'}</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((a) => (
                  <tr key={a.id} className="border-t border-border/50 hover:bg-bg-tertiary cursor-pointer" onClick={() => open(a)}>
                    <td className="px-4 py-2">
                      <span className="flex items-center gap-3">
                        <AppIcon app={a} size="sm" />
                        <span className="min-w-0">
                          <span className="font-medium text-text-primary">{a.name}</span>
                          {a.platformFamily === 'android' && <span className="ml-2"><StateBadge tone="green" label={t('androidApps.badge') || 'Android'} /></span>}
                          {a.archivedAt && <span className="ml-2"><StateBadge tone="gray" label={t('apps.archived') || 'Archived'} /></span>}
                          {a.publisher && <span className="block text-xs text-text-muted">{a.publisher}</span>}
                        </span>
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-text-secondary">{a.identifier}</td>
                    <td className="px-3 py-2.5 text-text-secondary">
                      {a.platformFamily === 'android' ? <span className="text-text-muted">—</span> : a.licenses ? (t('apps.licenceCounts', { available: a.licenses.available, total: a.licenses.total }) || `${a.licenses.available} available of ${a.licenses.total}`)
                        : <span className="text-amber-500">{t('apps.noLicence') || 'No licence'}</span>}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums text-text-secondary">{a.assignments}</td>
                    <td className="px-4 py-2.5 text-xs text-text-muted">{formatDateTime(a.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      {adding && <AddAppModal onClose={() => setAdding(false)} onCreated={(a) => { setAdding(false); load(); select(a.id); }} />}
      <Drawer open={selected !== null} onClose={() => select(null)} size="lg" title={t('apps.detailTitle') || 'App'} icon={<AppWindow className="w-5 h-5 text-accent" />}>
        {selected !== null && <AppDetailPanel id={selected} canManage={canManage} onChanged={load} onArchived={() => { select(null); load(); }} />}
      </Drawer>
    </PageContainer>
  );
}

const VIEW_KEY = 'obligarth.apps.view';

// Tile behind an app without an icon (or whose icon fails to load): its initials on a colour taken from its identifier,
// stable from one visit to the next.
function initialsOf(name: string): string {
  const words = name.trim().split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2);
  return letters.toUpperCase();
}

function hueOf(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) % 360;
  return h;
}

function AppIcon({ app, size }: { app: Pick<AppCatalogEntry, 'name' | 'identifier' | 'iconUrl'>; size: 'sm' | 'lg' | 'xl' }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [app.iconUrl]);
  const box = size === 'sm' ? 'h-9 w-9 rounded-lg text-xs' : size === 'lg' ? 'h-16 w-16 rounded-2xl text-lg' : 'h-20 w-20 rounded-[1.4rem] text-2xl';
  if (app.iconUrl && !failed) {
    return <img src={app.iconUrl} alt="" referrerPolicy="no-referrer" loading="lazy" onError={() => setFailed(true)}
      className={`${box} shrink-0 bg-white object-cover shadow-md ring-1 ring-black/5`} />;
  }
  const hue = hueOf(app.identifier || app.name);
  return (
    <span aria-hidden className={`${box} inline-flex shrink-0 items-center justify-center font-bold text-white shadow-md`}
      style={{ background: `linear-gradient(135deg, hsl(${hue} 70% 55%), hsl(${(hue + 40) % 360} 65% 42%))` }}>
      {initialsOf(app.name)}
    </span>
  );
}

function FamilyTag({ family }: { family: AppCatalogEntry['platformFamily'] }) {
  const { t } = useTranslation();
  return (
    <span className={`inline-flex items-center gap-0.5 font-medium ${family === 'android' ? 'text-green-500' : 'text-sky-500'}`}>
      <Smartphone className="w-3 h-3" />{family === 'android' ? (t('apps.filterAndroid') || 'Android') : (t('apps.filterApple') || 'Apple')}
    </span>
  );
}

function LicenceTag({ app }: { app: AppCatalogEntry }) {
  const { t } = useTranslation();
  if (app.platformFamily === 'android') return <span />;
  if (!app.licenses) return <span className="text-amber-500">{t('apps.noLicence') || 'No licence'}</span>;
  return (
    <span className="tabular-nums" title={t('apps.licenceCounts', { available: app.licenses.available, total: app.licenses.total }) || undefined}>
      {app.licenses.available}/{app.licenses.total}
    </span>
  );
}

function AddAppModal({ onClose, onCreated }: { onClose: () => void; onCreated: (a: AppCatalogEntry) => void }) {
  const { t } = useTranslation();
  const [assets, setAssets] = useState<VppAssetView[]>([]);
  const [assetId, setAssetId] = useState<number | ''>('');
  const [storeId, setStoreId] = useState('');
  const [kind, setKind] = useState<'app_store' | 'custom'>('app_store');
  const [identifier, setIdentifier] = useState('');
  const [name, setName] = useState('');
  const [publisher, setPublisher] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { integrationsApi.vppAssets().then((l) => setAssets(l.filter((a) => a.productType !== 'Book' && a.appId === null))).catch(() => setAssets([])); }, []);
  useEffect(() => {
    const a = assets.find((x) => x.id === assetId);
    if (a) setStoreId(a.adamId);
  }, [assetId, assets]);
  const ok = /^[0-9]{1,20}$/.test(storeId) && /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(identifier) && name.trim().length > 0;
  const create = async () => {
    setBusy(true);
    try {
      const a = await mdmApi.createApp({ kind, storeId, identifier: identifier.trim(), name: name.trim(), publisher: publisher.trim() || null });
      toast.success(t('apps.created') || 'App added to the catalog');
      onCreated(a);
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={() => { if (!busy) onClose(); }} title={t('apps.add') || 'Add an app'}
      footer={<Button size="sm" loading={busy} disabled={!ok} onClick={create}>{t('common.create') || 'Create'}</Button>}>
      <div className="space-y-3 text-sm">
        <label className="block">{t('apps.fromLicence') || 'From a licence of the tenant'}
          <select className={fieldCls} value={assetId} onChange={(e) => setAssetId(e.target.value ? Number(e.target.value) : '')}>
            <option value="">{assets.length ? (t('apps.pickLicence') || 'Pick a licence…') : (t('apps.noFreeLicence') || 'No licence without an app of the catalog')}</option>
            {assets.map((a) => (
              <option key={a.id} value={a.id}>{`${a.adamId} · ${a.pricingParam} · ${t('apps.licenceCounts', { available: a.availableCount, total: a.totalCount }) || `${a.availableCount} available of ${a.totalCount}`}`}</option>
            ))}
          </select>
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">{t('apps.storeId') || 'App Store id'}
            <input className={fieldCls} inputMode="numeric" value={storeId} onChange={(e) => { setStoreId(e.target.value.trim()); setAssetId(''); }} placeholder="361309726" />
          </label>
          <label className="block">{t('apps.kind') || 'Kind'}
            <select className={fieldCls} value={kind} onChange={(e) => setKind(e.target.value as 'app_store' | 'custom')}>
              <option value="app_store">{t('apps.kindAppStore') || 'App Store'}</option>
              <option value="custom">{t('apps.kindCustom') || 'Custom App (Apple Business)'}</option>
            </select>
          </label>
        </div>
        <label className="block">{t('apps.identifier') || 'Identifier'}
          <input className={`${fieldCls} font-mono`} value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="com.example.app" autoCapitalize="off" spellCheck={false} />
        </label>
        <label className="block">{t('apps.name') || 'Name'}
          <input className={fieldCls} maxLength={255} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="block">{t('apps.publisher') || 'Publisher'}
          <input className={fieldCls} maxLength={255} value={publisher} onChange={(e) => setPublisher(e.target.value)} />
        </label>
        <p className="text-xs text-text-muted">{t('apps.addHelp') || 'The identifier is the bundle identifier of the app; it must match what the devices report. Without a licence, the app is listed but not installed.'}</p>
      </div>
    </Modal>
  );
}

const DELIVERY_TONE: Record<string, 'green' | 'gray' | 'amber' | 'red' | 'blue'> = {
  applied: 'green', pending: 'blue', delivering: 'blue', error: 'red', not_applicable: 'amber', removing: 'gray',
};

function AppDetailPanel({ id, canManage, onChanged, onArchived }: { id: number; canManage: boolean; onChanged: () => void; onArchived: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [app, setApp] = useState<AppDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    mdmApi.getApp(id).then((a) => { setApp(a); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, [id]);
  useEffect(() => { load(); }, [load]);
  const delivery = useMemo(() => Object.entries(app?.delivery ?? {}).sort(([a], [b]) => a.localeCompare(b)), [app]);
  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!app) return <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>;
  return (
    <div className="space-y-4 text-sm">
      <div className="flex items-center gap-4">
        <AppIcon app={app} size="xl" />
        <div className="min-w-0">
          <p className="text-lg font-semibold text-text-primary">{app.name}</p>
          {app.publisher && <p className="text-xs text-text-muted">{app.publisher}</p>}
          <p className="font-mono text-xs text-text-muted break-all">{app.identifier} · {app.storeId}</p>
        </div>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
        <div><dt className="text-text-muted">{t('apps.kind') || 'Kind'}</dt><dd>{trCode(`apps.kinds.${app.kind}`, app.kind)}</dd></div>
        <div><dt className="text-text-muted">{t('apps.platforms') || 'Platforms'}</dt><dd>{app.supportedPlatforms.length ? app.supportedPlatforms.join(', ') : '—'}</dd></div>
        <div><dt className="text-text-muted">{t('apps.licences') || 'Licences'}</dt>
          <dd>{app.licenses ? (t('apps.licenceDetail', { available: app.licenses.available, assigned: app.licenses.assigned, total: app.licenses.total }) || `${app.licenses.available} available, ${app.licenses.assigned} assigned, ${app.licenses.total} in all`) : (t('apps.noLicence') || 'No licence')}</dd></div>
        <div><dt className="text-text-muted">{t('apps.metadataRefreshed') || 'Synchronised'}</dt><dd>{app.metadataRefreshedAt ? formatDateTime(app.metadataRefreshedAt) : '—'}</dd></div>
      </dl>
      <section className="space-y-1">
        <h3 className="text-sm font-semibold text-text-primary">{t('apps.inventory') || 'On the devices'}</h3>
        <p className="text-xs text-text-secondary">
          {t('apps.installCounts', { installed: app.installs.installed, managed: app.installs.managed, failed: app.installs.failed })
            || `${app.installs.installed} device(s), ${app.installs.managed} managed, ${app.installs.failed} in error`}
        </p>
        {app.installs.versions.length > 0 && (
          <p className="text-xs text-text-muted">{app.installs.versions.map((v) => `${v.version} (${v.devices})`).join(' · ')}</p>
        )}
        {delivery.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {delivery.map(([state, n]) => <StateBadge key={state} tone={DELIVERY_TONE[state] ?? 'gray'} label={`${trCode(`apps.delivery.${state}`, state)} · ${n}`} />)}
          </div>
        )}
      </section>
      {!app.archivedAt && (
        <AssignmentsPanel resource={{ id: app.id, tenantId: app.tenantId, name: app.name, type: 'app', published: true }} canManage={canManage}
          onChanged={() => { load(); onChanged(); }} />
      )}
      {canManage && !app.archivedAt && (
        <Button size="sm" variant="ghost" disabled={app.assignments > 0}
          title={app.assignments > 0 ? (t('apps.archiveBlocked') || 'Remove the assignments of this app first') : undefined}
          onClick={async () => {
            if (!(await confirm({ message: t('apps.confirmArchive', { name: app.name }) || `Archive the app ${app.name}?`, danger: true }))) return;
            try {
              await mdmApi.archiveApp(app.id);
              toast.success(t('apps.archivedDone') || 'App archived');
              onArchived();
            } catch (err) { errorToast(err); }
          }}><Archive className="w-4 h-4 mr-1" />{t('apps.archive') || 'Archive'}</Button>
      )}
    </div>
  );
}
