import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Archive, ArrowLeft, ExternalLink, Plus, RefreshCw, ShoppingBag, SlidersHorizontal, X } from 'lucide-react';
import { ANDROID_IFRAME_EVENTS, isAndroidPackage, type AndroidAppDetail, type AndroidAppView, type AndroidIframeScreen } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { Drawer } from '@/components/common/Drawer';
import { PageContainer } from '@/components/common/PageContainer';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { AssignmentsPanel } from '@/components/mdm/Assignments';
import { Fact, dateOf, errorToast, fieldClass } from '@/components/android/ui';
import { useOwnDocument } from '@/hooks/useOwnDocument';
import { eventField, openGoogleFrame } from '@/utils/googleIframes';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The catalog of Android apps of the tenant (android-amapi §9.6, §12.1 « Catalogue d'apps Android »; lot AN-E): the
// managed Google Play iframe (search of the public apps, private apps and web apps published for the tenant's
// enterprise, organisation of the store), whose onproductselect event adds the app to the catalog (the server reads
// it at Google for the tenant's enterprise: a package of another enterprise never enters), the page of an app (facts
// minimized by the server, managed configuration, refresh, archive) and its assignments with their Android options.
// The iframe's URL carries a short-lived token (in this page's memory only); parentFrameUrl is this page. The page's
// Content-Security-Policy admits Google's frames (client/nginx.conf); reached by an in-app link, it reloads the
// document at its own path first (useOwnDocument). Capability mdm.apps.manage (route and server).

const PAGE = '/apps/android';
const SCREENS = ['catalog', 'store_builder'] as const satisfies readonly AndroidIframeScreen[];

export function AndroidAppsPage() {
  const own = useOwnDocument(PAGE);
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const [apps, setApps] = useState<AndroidAppView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [screen, setScreen] = useState<AndroidIframeScreen | null>(null);
  const [frameError, setFrameError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [pkg, setPkg] = useState('');
  const [adding, setAdding] = useState(false);
  const frameRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<(() => void) | null>(null);
  const selected = params.get('app');
  const select = (uuid: string | null) => setParams((prev) => {
    const p = new URLSearchParams(prev);
    if (uuid) p.set('app', uuid); else p.delete('app');
    return p;
  }, { replace: true });

  const load = useCallback(() => {
    androidApi.apps().then((l) => { setApps(l); setError(null); }).catch((err) => { setApps([]); setError(apiErrorMessage(err)); });
  }, []);
  useEffect(() => { if (own) load(); }, [own, load]);
  useEffect(() => () => { closeRef.current?.(); }, []);

  const add = useCallback(async (packageName: string) => {
    setAdding(true);
    try {
      const r = await androidApi.addApp({ packageName, languageCode: i18n.language });
      toast.success(r.created ? (t('androidApps.added', { name: r.app.name }) || `${r.app.name} added to the catalog`)
        : (t('androidApps.alreadyThere', { name: r.app.name }) || `${r.app.name} is in the catalog already`));
      setPkg('');
      load();
      select(r.app.uuid);
    } catch (err) { errorToast(err); } finally { setAdding(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [i18n.language, load, t]);

  const openScreen = async (s: AndroidIframeScreen) => {
    closeRef.current?.();
    closeRef.current = null;
    setFrameError(null);
    setOpening(true);
    setScreen(s);
    try {
      const tk = await androidApi.iframeToken({ screen: s, parentPath: PAGE, locale: i18n.language });
      if (!frameRef.current) return;
      closeRef.current = await openGoogleFrame(frameRef.current, tk.iframeUrl, t('androidApps.frameTitle') || 'Managed Google Play', {
        [ANDROID_IFRAME_EVENTS.productSelect]: (payload) => {
          const name = eventField(payload, 'packageName', /^[A-Za-z][A-Za-z0-9_.]*$/);
          const action = eventField(payload, 'action', /^[a-z_]{1,32}$/);
          if (name && isAndroidPackage(name) && (!action || action === 'selected')) void add(name);
        },
      });
    } catch (err) {
      setScreen(null);
      setFrameError(err instanceof Error && /^gapi/.test(err.message) ? (t('androidApps.gapiFailed') || 'Google\'s iframe library could not be loaded.') : apiErrorMessage(err));
    } finally { setOpening(false); }
  };
  const closeScreen = () => { closeRef.current?.(); closeRef.current = null; setScreen(null); };

  if (!own) return <PageContainer><p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p></PageContainer>;
  return (
    <PageContainer className="space-y-5">
      <Link to="/apps" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
        <ArrowLeft size={14} />{t('androidApps.back') || 'Back to the apps'}
      </Link>
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('androidApps.title') || 'Android apps'}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('androidApps.subtitle') || 'Apps of managed Google Play for the tenant\'s Android enterprise: public apps, private apps and web apps, and their assignments.'}</p>
      </div>

      <section className="space-y-3 rounded-lg border border-border bg-bg-secondary p-4">
        <div className="flex flex-wrap items-center gap-2">
          <ShoppingBag className="w-5 h-5 text-accent" />
          <h2 className="text-base font-semibold text-text-primary">{t('androidApps.play.title') || 'Managed Google Play'}</h2>
          <span className="ml-auto flex flex-wrap gap-2">
            {SCREENS.map((s) => (
              <Button key={s} size="sm" variant={screen === s ? 'primary' : 'secondary'} disabled={opening} onClick={() => void openScreen(s)}>
                {t(`androidApps.play.screens.${s}`) || s}
              </Button>
            ))}
            {screen && <Button size="sm" variant="ghost" onClick={closeScreen}><X className="w-4 h-4 mr-1" />{t('androidApps.play.close') || 'Close'}</Button>}
          </span>
        </div>
        <p className="text-xs text-text-muted">{t('androidApps.play.hint') || 'Search an app, or publish a private app or a web app, then select it: it is added to the catalog. A private app never becomes public.'}</p>
        {frameError && <p className="text-sm text-red-400">{frameError}</p>}
        <div ref={frameRef} className={screen ? 'h-[70vh] w-full overflow-hidden rounded-lg border border-border bg-white' : 'hidden'} data-testid="android-play-frame" />
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); if (isAndroidPackage(pkg.trim())) void add(pkg.trim()); }}>
          <label className="block flex-1 min-w-[16rem] text-sm">
            <span className="text-xs text-text-muted">{t('androidApps.addByPackage') || 'Or add by its package name'}</span>
            <input value={pkg} onChange={(e) => setPkg(e.target.value)} placeholder="com.example.app" spellCheck={false} autoCapitalize="off" className={`mt-1 ${fieldClass} font-mono`} />
          </label>
          <Button size="sm" type="submit" disabled={!isAndroidPackage(pkg.trim()) || adding} loading={adding}><Plus className="w-4 h-4 mr-1" />{t('androidApps.add') || 'Add'}</Button>
        </form>
      </section>

      {error && <p className="text-sm text-red-400">{error}</p>}
      {apps === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : apps.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">
            <p className="font-medium text-text-primary mb-1">{t('androidApps.empty') || 'No Android app yet'}</p>
            <p className="text-sm">{t('androidApps.emptyHint') || 'Open managed Google Play above and select the apps of the tenant.'}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">{t('androidApps.name') || 'Name'}</th>
                  <th className="font-medium px-3 py-2">{t('androidApps.package') || 'Package'}</th>
                  <th className="font-medium px-3 py-2">{t('androidApps.kind') || 'Kind'}</th>
                  <th className="font-medium px-3 py-2">{t('androidApps.managedConfiguration') || 'Managed configuration'}</th>
                  <th className="font-medium px-4 py-2">{t('androidApps.refreshed') || 'Read at Google'}</th>
                </tr>
              </thead>
              <tbody>
                {apps.map((a) => (
                  <tr key={a.uuid} className="border-t border-border/50 hover:bg-bg-tertiary cursor-pointer" onClick={() => select(a.uuid)}>
                    <td className="px-4 py-2.5">
                      <span className="flex items-center gap-2">
                        {a.iconUrl && <img src={a.iconUrl} alt="" referrerPolicy="no-referrer" className="h-6 w-6 rounded" loading="lazy" />}
                        <span className="font-medium text-text-primary">{a.name}</span>
                        {a.unavailable && <StateBadge tone="amber" label={t('androidApps.unavailable') || 'Withdrawn by Google'} />}
                      </span>
                      {a.publisher && <span className="block text-xs text-text-muted">{a.publisher}</span>}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-text-secondary">{a.packageName}</td>
                    <td className="px-3 py-2.5 text-text-secondary">{trCode(`androidApps.kinds.${a.kind}`, a.kind)}</td>
                    <td className="px-3 py-2.5 text-text-secondary">{trCode(`androidApps.configKinds.${a.managedConfiguration}`, a.managedConfiguration)}</td>
                    <td className="px-4 py-2.5 text-xs text-text-muted">{dateOf(a.metadataRefreshedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      <Drawer open={selected !== null} onClose={() => select(null)} size="lg" title={t('androidApps.detailTitle') || 'Android app'} icon={<ShoppingBag className="w-5 h-5 text-accent" />}>
        {selected !== null && <AndroidAppPanel uuid={selected} onChanged={load} onArchived={() => { select(null); load(); }} />}
      </Drawer>
    </PageContainer>
  );
}

function AndroidAppPanel({ uuid, onChanged, onArchived }: { uuid: string; onChanged: () => void; onArchived: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [app, setApp] = useState<AndroidAppDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    androidApi.app(uuid).then((a) => { setApp(a); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, [uuid]);
  useEffect(() => { load(); }, [load]);
  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!app) return <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>;
  const refresh = async () => {
    setBusy(true);
    try {
      const r = await androidApi.refreshApp(app.uuid);
      toast.success(trCode(`androidApps.refreshResults.${r}`, r));
      load();
      onChanged();
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-4 text-sm">
      <div className="flex items-start gap-3">
        {app.iconUrl && <img src={app.iconUrl} alt="" referrerPolicy="no-referrer" className="h-12 w-12 rounded" />}
        <div className="min-w-0">
          <p className="text-lg font-semibold text-text-primary break-words">{app.name}</p>
          <p className="font-mono text-xs text-text-muted break-all">{app.packageName}</p>
          {app.publisher && <p className="text-xs text-text-muted">{app.publisher}</p>}
        </div>
      </div>
      {app.unavailable && <p className="text-xs text-amber-400">{t('androidApps.unavailableHint') || 'Google no longer serves this app to the enterprise: its last metadata are kept.'}</p>}
      {app.kind === 'private' && <p className="text-xs text-text-muted">{t('androidApps.privateHint') || 'Private app of the tenant\'s enterprise: it never becomes public.'}</p>}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
        <Fact label={t('androidApps.kind') || 'Kind'}>{trCode(`androidApps.kinds.${app.kind}`, app.kind)}</Fact>
        <Fact label={t('androidApps.managedConfiguration') || 'Managed configuration'}>{trCode(`androidApps.configKinds.${app.managedConfiguration}`, app.managedConfiguration)}</Fact>
        <Fact label={t('androidApps.minSdk') || 'Minimum Android API'}>{app.minAndroidSdkVersion ?? '—'}</Fact>
        <Fact label={t('androidApps.refreshed') || 'Read at Google'}>{dateOf(app.metadataRefreshedAt)}</Fact>
        <Fact label={t('androidApps.permissions') || 'Permissions'}>{app.permissions.length}</Fact>
        <Fact label={t('androidApps.tracks') || 'Test tracks'}>{app.tracks.length ? app.tracks.map((x) => x.trackAlias || x.trackId).join(', ') : '—'}</Fact>
      </dl>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="secondary" loading={busy} onClick={() => void refresh()}><RefreshCw className="w-4 h-4 mr-1" />{t('androidApps.refresh') || 'Read again at Google'}</Button>
        {app.kind !== 'web' && (
          <a href={`/apps/android/${app.uuid}/managed-config`} className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm bg-bg-tertiary text-text-primary hover:bg-bg-tertiary/80 coarse:min-h-10">
            <SlidersHorizontal className="w-4 h-4" />{t('androidApps.managedConfigPage') || 'Managed configuration'}<ExternalLink className="w-3 h-3 text-text-muted" />
          </a>
        )}
      </div>
      <AssignmentsPanel resource={{ id: app.id, tenantId: app.tenantId, name: app.name, type: 'app', published: true, android: app }} canManage
        onChanged={() => { load(); onChanged(); }} />
      <Button size="sm" variant="ghost" disabled={app.assignments > 0}
        title={app.assignments > 0 ? (t('androidApps.archiveBlocked') || 'Remove the assignments of this app first') : undefined}
        onClick={async () => {
          if (!(await confirm({ message: t('androidApps.confirmArchive', { name: app.name }) || `Archive the app ${app.name}?`, danger: true }))) return;
          try {
            await androidApi.archiveApp(app.uuid);
            toast.success(t('androidApps.archivedDone') || 'App archived');
            onArchived();
          } catch (err) { errorToast(err); }
        }}><Archive className="w-4 h-4 mr-1" />{t('androidApps.archive') || 'Archive'}</Button>
    </div>
  );
}
