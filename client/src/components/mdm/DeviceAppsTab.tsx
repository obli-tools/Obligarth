import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AppWindow, Check, Copy, ExternalLink, LayoutGrid, List, RefreshCw, Search } from 'lucide-react';
import type { CollectedField, DeviceAppView } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { useAuthStore } from '@/store/authStore';
import { Drawer } from '@/components/common/Drawer';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { AppIcon } from '@/components/apps/AppIcon';
import { deliveryLabel, deliveryTone } from '@/components/apps/delivery';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatBytes, formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The applications of a device (modele-donnees-mdm §5), as a grid of their icons: the ones installed by the user
// first, the managed ones (with the assignments that deliver them and the state of their delivery), the system ones
// (the services without a launcher icon hidden by default). The icons come from the catalog, or from the bridge
// agent (a PNG re-encoded by the server); the others show their initials. What the privacy rules of the device's
// ownership do not collect is absent from the answer, and said so here (an empty list is not "nothing installed").
// A search covers every category: the matches of the other ones are offered next to (or instead of) the current one's.
// The states of a delivery have the catalog's colours and labels (components/apps/delivery).

type Segment = 'user' | 'managed' | 'system' | 'all';
type Sort = 'name' | 'updated';

const VIEW_KEY = 'obligarth.deviceApps.view';
const PAGE = 300;
const PENDING_STATES = new Set(['pending', 'delivering', 'removing', 'sent']);
const FAILED_STATES = new Set(['error', 'rejected']);
const SEGMENTS = ['user', 'managed', 'system', 'all'] as const;

/** The pill of an app: its delivery when the MDM follows it (pending, failed), else managed, else system, else none. */
function useBadge() {
  const { t } = useTranslation();
  return (a: DeviceAppView): ReactNode => {
    const d = a.delivery;
    const followed = a.category === 'managed' || d?.via === 'agent_command';
    if (d && followed && FAILED_STATES.has(d.state)) return <StateBadge tone="red" label={t('mdm.inventory.apps.badgeFailed') || 'Failed'} />;
    if (d && followed && PENDING_STATES.has(d.state)) return <StateBadge tone="blue" label={t('mdm.inventory.apps.badgePending') || 'In progress'} />;
    if (a.category === 'managed') return <StateBadge tone="violet" label={t('mdm.inventory.apps.badgeManaged') || 'Managed'} />;
    if (a.category === 'system') return <StateBadge tone="gray" label={t('mdm.inventory.apps.badgeSystem') || 'System'} />;
    return null;
  };
}

function readView(): 'grid' | 'list' {
  try { return localStorage.getItem(VIEW_KEY) === 'list' ? 'list' : 'grid'; } catch { return 'grid'; }
}

const byName = (a: DeviceAppView, b: DeviceAppView) =>
  (a.name || a.identifier).localeCompare(b.name || b.identifier, undefined, { sensitivity: 'base' }) || a.identifier.localeCompare(b.identifier);

export function DeviceAppsTab({ deviceId, collected }: { deviceId: number; collected: CollectedField[] }) {
  const { t } = useTranslation();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('mdm.apps.manage');
  const [data, setData] = useState<{ apps: DeviceAppView[]; collectedAt: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [segment, setSegment] = useState<Segment | null>(null);
  const [sort, setSort] = useState<Sort>('name');
  const [view, setView] = useState<'grid' | 'list'>(readView);
  const [hideServices, setHideServices] = useState(true);
  const [limit, setLimit] = useState(PAGE);
  const [selected, setSelected] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const badgeOf = useBadge();

  useEffect(() => {
    setSegment(null);
    setSelected(null);
  }, [deviceId]);
  // A failed load leaves data null (never an empty list nor a collection date it does not know) and offers a retry.
  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    mdmApi.apps(deviceId)
      .then((r) => { if (!cancelled) setData(r); })
      .catch((err) => { if (!cancelled) setError(apiErrorMessage(err)); });
    return () => { cancelled = true; };
  }, [deviceId, attempt]);

  const changeView = (v: 'grid' | 'list') => {
    setView(v);
    try { localStorage.setItem(VIEW_KEY, v); } catch { /* per-viewer convenience only */ }
  };

  const apps = useMemo(() => data?.apps ?? [], [data]);
  // The first segment that is not empty: on an iOS device collecting the managed apps only, or a personal device, the
  // apps of the user are not reported.
  const defaultSegment = useMemo<Segment>(() => {
    if (apps.some((a) => a.category === 'user')) return 'user';
    if (apps.some((a) => a.category === 'managed')) return 'managed';
    return 'all';
  }, [apps]);
  const current = segment ?? defaultSegment;
  const hasLaunchInfo = useMemo(() => apps.some((a) => a.launchable !== null), [apps]);

  const matching = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? apps.filter((a) => a.identifier.toLowerCase().includes(needle) || (a.name ?? '').toLowerCase().includes(needle)) : apps;
  }, [apps, q]);
  const counts = useMemo(() => {
    const c: Record<Segment, number> = { user: 0, managed: 0, system: 0, all: matching.length };
    for (const a of matching) c[a.category]++;
    return c;
  }, [matching]);
  // A search: the categories other than the current one that have matches (an app preinstalled then updated from the
  // store is a system one: never "no result" while it is installed).
  const searching = q.trim() !== '';
  const elsewhere = searching && current !== 'all' ? SEGMENTS.filter((s) => s !== 'all' && s !== current && counts[s] > 0) : [];
  const elsewhereCount = elsewhere.reduce((n, s) => n + counts[s], 0);
  const hidesServices = current === 'system' && hasLaunchInfo && hideServices;
  const { shown, hidden } = useMemo(() => {
    let list = current === 'all' ? matching : matching.filter((a) => a.category === current);
    const before = list.length;
    if (hidesServices) list = list.filter((a) => a.launchable !== false);
    const sorted = [...list].sort(sort === 'name' ? byName : (a, b) => {
      if (a.updatedAt === b.updatedAt) return byName(a, b);
      if (!a.updatedAt) return 1;
      if (!b.updatedAt) return -1;
      return b.updatedAt.localeCompare(a.updatedAt);
    });
    return { shown: sorted, hidden: before - list.length };
  }, [matching, current, hidesServices, sort]);
  useEffect(() => setLimit(PAGE), [current, q, sort, hidesServices, deviceId]);

  const segmentLabel = (s: Segment): string => s === 'user' ? (t('mdm.inventory.apps.filterUser') || 'User')
    : s === 'managed' ? (t('mdm.inventory.apps.filterManaged') || 'Managed')
      : s === 'system' ? (t('mdm.inventory.apps.filterSystem') || 'System')
        : (t('mdm.inventory.apps.filterAll') || 'All');
  const emptyText = searching ? (elsewhere.length ? (t('mdm.inventory.apps.noResultsHere') || 'No result in this category.') : (t('common.noResults') || 'No results'))
    : current === 'user' ? (t('mdm.inventory.apps.emptyUser') || 'No application installed by the user is reported.')
      : current === 'managed' ? (t('mdm.inventory.apps.emptyManaged') || 'No managed application on this device.')
        : current === 'system' ? (t('mdm.inventory.apps.emptySystem') || 'No system application reported.')
          : (t('mdm.inventory.noApps') || 'No application reported.');
  const sel = selected === null ? null : apps.find((a) => a.identifier === selected) ?? null;
  const visible = shown.slice(0, limit);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-0 flex-1 basis-[200px] sm:max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('common.search') || 'Search'}
            className="w-full rounded-lg bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
        </div>
        {data && (
          <span className="text-xs text-text-muted">
            {data.collectedAt
              ? (t('mdm.inventory.apps.collectedAt', { at: formatDateTime(data.collectedAt) }) || `Collected on ${formatDateTime(data.collectedAt)}`)
              : (t('mdm.inventory.apps.neverCollected') || 'Never collected')}
          </span>
        )}
      </div>
      {data && apps.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {/* On a phone the four categories share two rows: none of them is ever out of sight. */}
          <SegmentedTabs<Segment>
            fill={false}
            size="sm"
            className="max-w-full max-sm:grid max-sm:w-full max-sm:grid-cols-2"
            ariaLabel={t('mdm.inventory.apps.category') || 'Category'}
            value={current}
            onChange={setSegment}
            tabs={SEGMENTS.map((s) => ({
              id: s, label: segmentLabel(s), badge: <span className="tabular-nums opacity-70">{counts[s]}</span>,
            }))}
          />
          <div className="ml-auto flex items-center gap-2">
            <select value={sort} onChange={(e) => setSort(e.target.value as Sort)} aria-label={t('mdm.inventory.apps.sort') || 'Sort'}
              className="rounded-lg bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50 coarse:min-h-10">
              <option value="name">{t('mdm.inventory.apps.sortName') || 'By name'}</option>
              <option value="updated">{t('mdm.inventory.apps.sortUpdated') || 'Recently updated'}</option>
            </select>
            <div className="inline-flex rounded-lg bg-bg-tertiary p-0.5">
              {(['grid', 'list'] as const).map((v) => (
                <button key={v} type="button" aria-pressed={view === v} onClick={() => changeView(v)}
                  aria-label={v === 'grid' ? (t('mdm.inventory.apps.viewGrid') || 'Grid') : (t('mdm.inventory.apps.viewList') || 'List')}
                  title={v === 'grid' ? (t('mdm.inventory.apps.viewGrid') || 'Grid') : (t('mdm.inventory.apps.viewList') || 'List')}
                  className={`rounded-md p-1.5 coarse:min-h-10 coarse:min-w-10 ${view === v ? 'bg-bg-secondary text-text-primary shadow-sm' : 'text-text-muted hover:text-text-primary'}`}>
                  {v === 'grid' ? <LayoutGrid className="h-4 w-4" /> : <List className="h-4 w-4" />}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
      {current === 'system' && hasLaunchInfo && data && apps.length > 0 && (
        <label className="flex flex-wrap items-center gap-1.5 text-xs text-text-muted">
          <input type="checkbox" checked={hideServices} onChange={(e) => setHideServices(e.target.checked)} />
          {t('mdm.inventory.apps.hideServices') || 'Hide the services without a launcher icon'}
          {hidden > 0 && <span className="tabular-nums">({t('mdm.inventory.apps.hiddenCount', { count: hidden }) || `${hidden} hidden`})</span>}
        </label>
      )}
      {!collected.includes('allApps') && (
        <p className="rounded-lg bg-bg-tertiary/50 px-3 py-2 text-xs text-text-muted">
          {t('mdm.inventory.managedAppsOnly') || 'Managed applications only: the other applications of this device are not collected (privacy rules of its ownership).'}
        </p>
      )}
      {elsewhere.length > 0 && (
        <p className="flex flex-wrap items-center gap-1.5 text-xs text-text-muted">
          <span>{t('mdm.inventory.apps.otherResults', { count: elsewhereCount }) || `${elsewhereCount} more result(s) in:`}</span>
          {elsewhere.map((s) => (
            <button key={s} type="button" onClick={() => setSegment(s)}
              className="inline-flex items-center gap-1 rounded-full bg-bg-tertiary px-2.5 py-1 font-medium text-text-primary hover:bg-bg-hover coarse:min-h-10">
              {segmentLabel(s)}<span className="tabular-nums opacity-70">{counts[s]}</span>
            </button>
          ))}
        </p>
      )}
      {error ? (
        <div className="flex flex-wrap items-center gap-3 rounded-xl bg-bg-secondary p-4">
          <p className="min-w-0 flex-1 text-sm text-red-400">{error}</p>
          <button type="button" onClick={() => setAttempt((n) => n + 1)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-bg-tertiary px-3 py-1.5 text-sm font-medium text-text-primary hover:bg-bg-hover coarse:min-h-10">
            <RefreshCw className="h-4 w-4" />{t('mdm.inventory.apps.retry') || 'Retry'}
          </button>
        </div>
      ) : data === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
        : shown.length === 0 ? <p className="rounded-xl bg-bg-secondary p-6 text-center text-sm text-text-muted">{apps.length === 0 ? (t('mdm.inventory.noApps') || 'No application reported.') : emptyText}</p>
          : view === 'grid' ? (
            <div className="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(132px,1fr))]">
              {visible.map((a) => {
                const label = a.name || a.identifier;
                return (
                  <button key={a.identifier} type="button" onClick={() => setSelected(a.identifier)}
                    className="flex min-w-0 flex-col items-center rounded-2xl bg-bg-secondary px-2 pb-3 pt-4 text-center transition hover:-translate-y-0.5 hover:bg-bg-tertiary hover:shadow-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 coarse:min-h-[10rem]">
                    <AppIcon app={a} size="lg" />
                    <span title={label} className={`mt-2.5 line-clamp-2 min-h-[2.5rem] w-full text-sm font-semibold leading-5 text-text-primary ${a.name ? 'break-words' : 'break-all'}`}>{label}</span>
                    <span title={a.displayVersion ?? undefined} className="w-full truncate text-[11px] text-text-muted">{a.displayVersion || ' '}</span>
                    <span className="mt-2 flex h-5 items-center">{badgeOf(a)}</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <ul className="divide-y divide-border/50 overflow-hidden rounded-xl bg-bg-secondary">
              {visible.map((a) => (
                <li key={a.identifier}>
                  <button type="button" onClick={() => setSelected(a.identifier)}
                    className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-bg-tertiary focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/60 coarse:min-h-12">
                    <AppIcon app={a} size="sm" />
                    <span className="min-w-0 flex-1">
                      <span className="flex min-w-0 items-center gap-2">
                        <span className="truncate text-sm font-medium text-text-primary">{a.name || a.identifier}</span>
                        {badgeOf(a)}
                      </span>
                      <span className="block truncate font-mono text-[11px] text-text-muted">{a.identifier}</span>
                    </span>
                    <span className="max-w-[7rem] shrink-0 truncate text-xs tabular-nums text-text-secondary">{a.displayVersion || '—'}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
      {shown.length > limit && (
        <div className="flex justify-center">
          <button type="button" onClick={() => setLimit((n) => n + PAGE)}
            className="rounded-lg bg-bg-tertiary px-4 py-2 text-sm font-medium text-text-primary hover:bg-bg-hover coarse:min-h-10">
            {t('mdm.inventory.apps.showMore', { count: shown.length - limit }) || `Show more (${shown.length - limit})`}
          </button>
        </div>
      )}
      <Drawer open={sel !== null} onClose={() => setSelected(null)} size="md" title={t('mdm.inventory.app') || 'Application'}
        icon={<AppWindow className="h-5 w-5 text-accent" />}>
        {sel && <AppDetail app={sel} canManage={canManage} badge={badgeOf(sel)} />}
      </Drawer>
    </div>
  );
}

function Field({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? 'col-span-2' : 'min-w-0'}>
      <dt className="text-text-muted">{label}</dt>
      <dd className="break-words text-text-primary">{children}</dd>
    </div>
  );
}

function AppDetail({ app, canManage, badge }: { app: DeviceAppView; canManage: boolean; badge: ReactNode }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  useEffect(() => setCopied(false), [app.identifier]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(app.identifier);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
    } catch { /* the identifier stays selectable */ }
  };
  const apple = app.platformFamily === 'apple';
  const yesNo = (v: boolean) => (v ? (t('mdm.inventory.apps.yes') || 'Yes') : (t('mdm.inventory.apps.no') || 'No'));
  const categoryLabel = app.category === 'managed' ? (t('mdm.inventory.apps.cat.managed') || 'Managed')
    : app.category === 'system' ? (t('mdm.inventory.apps.cat.system') || 'System')
      : (t('mdm.inventory.apps.cat.user') || 'Installed by the user');
  const scopeLabel = (s: string): string => s === 'device' ? (t('mdm.inventory.apps.scope.device') || 'This device')
    : s === 'group' ? (t('mdm.inventory.apps.scope.group') || 'Group')
      : s === 'smart_group' ? (t('mdm.inventory.apps.scope.smart_group') || 'Dynamic group')
      : s === 'library' ? (t('mdm.inventory.apps.scope.library') || 'Library')
        : (t('mdm.inventory.apps.scope.tenant') || 'Whole tenant');
  const cat = app.catalogApp;
  const catalogHref = !cat || cat.shared ? null : apple ? `/apps?app=${cat.id}` : canManage ? `/apps/android?app=${cat.uuid}` : null;
  const d = app.delivery;
  return (
    <div className="space-y-4 text-sm">
      <div className="flex items-center gap-4">
        <AppIcon app={app} size="xl" />
        <div className="min-w-0 space-y-1">
          <p className="break-words text-lg font-semibold text-text-primary">{app.name || app.identifier}</p>
          {app.displayVersion && <p className="text-xs text-text-muted">{app.displayVersion}</p>}
          {badge}
        </div>
      </div>
      <div className="flex items-center gap-2 rounded-lg bg-bg-tertiary/60 px-3 py-2">
        <span className="min-w-0 flex-1">
          <span className="block text-[11px] text-text-muted">{t('mdm.inventory.apps.identifier') || 'Identifier'}</span>
          <span className="block select-all break-all font-mono text-xs text-text-primary">{app.identifier}</span>
        </span>
        <button type="button" onClick={copy} aria-label={t('mdm.inventory.apps.copy') || 'Copy'} title={t('mdm.inventory.apps.copy') || 'Copy'}
          className="shrink-0 rounded-md p-1.5 text-text-muted hover:bg-bg-hover hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
          {copied ? <Check className="h-4 w-4 text-green-400" /> : <Copy className="h-4 w-4" />}
        </button>
        <span aria-live="polite" className="sr-only">{copied ? (t('mdm.inventory.apps.copied') || 'Copied') : ''}</span>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
        <Field label={t('mdm.inventory.version') || 'Version'}>{app.displayVersion || '—'}</Field>
        <Field label={apple ? (t('mdm.inventory.apps.bundleVersion') || 'Build (CFBundleVersion)') : (t('mdm.inventory.apps.versionCode') || 'Version code')}>
          <span className="font-mono">{app.build || '—'}</span>
        </Field>
        {app.bundleSize !== null && <Field label={t('mdm.inventory.size') || 'Size'}>{formatBytes(app.bundleSize)}</Field>}
        {app.dynamicSize !== null && <Field label={t('mdm.inventory.apps.dataSize') || 'Data'}>{formatBytes(app.dynamicSize)}</Field>}
        <Field label={t('mdm.inventory.apps.category') || 'Category'}>{categoryLabel}</Field>
        <Field label={t('mdm.inventory.apps.source') || 'Source'}>{trCode(`mdm.inventory.apps.src.${app.source}`, app.source)}</Field>
        {app.installer && <Field label={t('mdm.inventory.apps.installer') || 'Installed by'} wide><span className="break-all font-mono">{app.installer}</span></Field>}
        {app.installedAt && <Field label={t('mdm.inventory.apps.installedAt') || 'Installed'}>{formatDateTime(app.installedAt)}</Field>}
        {app.updatedAt && <Field label={t('mdm.inventory.apps.updatedAt') || 'Updated'}>{formatDateTime(app.updatedAt)}</Field>}
        <Field label={t('mdm.inventory.apps.firstSeen') || 'First detected'}>{formatDateTime(app.firstSeenAt)}</Field>
        <Field label={t('mdm.inventory.apps.lastSeen') || 'Last detected'}>{formatDateTime(app.lastSeenAt)}</Field>
        {app.hasConfiguration !== null && <Field label={t('mdm.inventory.apps.hasConfiguration') || 'Managed configuration'}>{yesNo(app.hasConfiguration)}</Field>}
        {app.isValidated !== null && <Field label={t('mdm.inventory.apps.validated') || 'Validated'}>{yesNo(app.isValidated)}</Field>}
        {app.managementStatus && <Field label={t('mdm.inventory.management') || 'Management'}>{app.managementStatus}</Field>}
      </dl>
      {(app.managedBy.length > 0 || d?.via === 'agent_command') && (
        <section className="space-y-1.5">
          <h3 className="text-sm font-semibold text-text-primary">{t('mdm.inventory.apps.managedBy') || 'Managed by'}</h3>
          <ul className="space-y-1.5 text-xs">
            {app.managedBy.map((m) => (
              <li key={`${m.assignmentId}-${m.scope}-${m.scopeId ?? ''}`} className="flex flex-wrap items-center gap-2 rounded-lg bg-bg-tertiary/50 px-3 py-2">
                <StateBadge tone={m.scope === 'device' ? 'amber' : 'violet'} label={scopeLabel(m.scope)} />
                {m.scope === 'group' && m.scopeId !== null && (
                  <Link to={`/group/${m.scopeId}`} className="text-text-primary hover:text-accent">{m.scopeName || `#${m.scopeId}`}</Link>
                )}
                {m.scope === 'smart_group' && m.scopeId !== null && (
                  <span className="text-text-primary">{m.scopeName || `#${m.scopeId}`}</span>
                )}
                <span className="text-text-muted">#{m.assignmentId}</span>
                <span className={`ml-auto ${m.availability === 'available' ? 'text-green-400' : 'text-amber-500'}`}>
                  {m.availability === 'available' ? (t('mdm.config.available') || 'Applies') : trCode(`mdm.inventory.apps.availability.${m.availability}`, m.availability)}
                </span>
              </li>
            ))}
            {d?.via === 'agent_command' && (
              <li className="rounded-lg bg-bg-tertiary/50 px-3 py-2 text-text-secondary">{t('mdm.inventory.apps.agentInstall') || 'Installed by a command of the console'}</li>
            )}
          </ul>
        </section>
      )}
      {d && (
        <section className="space-y-1.5">
          <h3 className="text-sm font-semibold text-text-primary">{t('mdm.inventory.apps.deliveryTitle') || 'Delivery'}</h3>
          <p className="flex flex-wrap items-center gap-2 text-xs">
            <StateBadge tone={deliveryTone(d.state)} label={deliveryLabel(d.state)} />
            {d.at && <span className="text-text-muted">{formatDateTime(d.at)}</span>}
          </p>
          {d.reasons.length > 0 && (
            <ul className="space-y-0.5 text-xs">
              {d.reasons.map((r) => <li key={r} className="break-all font-mono text-text-secondary">{r}</li>)}
            </ul>
          )}
        </section>
      )}
      {cat && (
        <section className="flex flex-wrap items-center gap-2 border-t border-border/50 pt-3 text-xs">
          <span className="text-text-muted">{t('mdm.inventory.apps.inCatalog') || 'In the catalog'}</span>
          <span className="text-text-primary">{cat.name}</span>
          {cat.shared && <StateBadge tone="gray" label={t('mdm.inventory.apps.catalogShared') || 'Shared catalog'} />}
          {catalogHref && (
            <Link to={catalogHref} className="ml-auto inline-flex items-center gap-1 font-medium text-accent hover:underline coarse:min-h-10">
              <ExternalLink className="h-3.5 w-3.5" />{t('mdm.inventory.apps.openInCatalog') || 'View in the catalog'}
            </Link>
          )}
        </section>
      )}
    </div>
  );
}
