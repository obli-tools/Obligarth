import { LogOut, Download, Menu, Settings, UserCircle, MoreHorizontal, ChevronDown, KeyRound } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { useUiStore } from '@/store/uiStore';
import { anonymize } from '@/utils/anonymize';
import { useSocketStore } from '@/store/socketStore';
import { NotificationCenter } from './NotificationCenter';
import { TenantSwitcher } from './TenantSwitcher';
import { Logo } from '@/components/common/Logo';
import { IconButton } from '@/components/common/IconButton';
import { ActionMenu, type ActionMenuItem } from '@/components/common/ActionMenu';
import { useLayoutMode } from '@/hooks/useMediaQuery';
import { useClickOutside } from '@/hooks/useClickOutside';
import { useNativeBack } from '@/hooks/useNativeBack';
import { isAndroidApp, canUseNative, native } from '@/native/bridge';
import { cn } from '@/utils/cn';

/** True when running inside the Obligarth native desktop app overlay (ObliTools —
 *  NOT the Android shell, see docs/obli-mobile.md §2). */
const isNativeApp = typeof window !== 'undefined' &&
  !!(window as Window & { __obliance_is_native_app?: boolean }).__obliance_is_native_app;

// ── App switcher data ───────────────────────────────────────────────────────
//
// Pills, current app glowing with its own brand colour. The set, order and
// colours are NOT hard-coded here: they come straight from Obligate
// (`GET /api/auth/connected-apps`, already sorted by `sort_order`, each entry
// carrying `name`/`color`/`icon`), so an app registered in Obligate shows up
// in every app's switcher without a code change here, and nothing it returns
// is filtered out. Each app announces its own colour to Obligate (Obligarth:
// obligateService.announceSelfInfo). Fallback colour for an app Obligate has
// no `color` for.
const FALLBACK_APP_COLOR = '#8b949e';

interface ConnectedApp {
  appType: string;
  name: string;
  baseUrl: string;
  icon: string | null;
  color: string | null;
  /** Marks the entry that is this app itself (resolved by Obligate from the Bearer key). */
  self?: boolean;
  /** Not an Obli* app (filed under "More…" in Obligate): listed in the "More…" dropdown. */
  thirdParty?: boolean;
}

const CURRENT_APP = 'obligarth';
/** Used only until the dynamic list loads / if Obligate ever omits self — never for other apps.
 *  Colour: the brand token of client/src/index.css (APP_ACCENT_COLOR on the server). */
const CURRENT_APP_FALLBACK: ConnectedApp = { appType: CURRENT_APP, name: 'Obligarth', baseUrl: '', icon: '/favicon.svg', color: '#e30557' };
const APPS_REFRESH_INTERVAL_MS = 5 * 60_000;

/**
 * Topbar — degrades with the layout mode (docs/obli-mobile.md §4):
 *  - desktop ≥ 1024: as designed; the app pills fold to their dot when the
 *    labelled row no longer fits.
 *  - tablet 768–1023: hamburger (sidebar drawer), avatar-only user badge
 *    (opens the account menu, which carries the download page).
 *  - phone < 768: hamburger · logo mark · truncated tenant · socket · bell ·
 *    avatar menu (profile, apps, download page, app settings, sign out).
 * In the Android shell the account menu offers "App updates" (the /download
 * page = installed version + update check) and the native settings.
 */
export function Header() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { user, logout, permissions } = useAuthStore();
  // The user's access keys of the MCP server (holders of mcp.access_keys; a platform administrator always).
  const canAccessKeys = user?.role === 'admin' || (permissions?.tenantCapabilities ?? []).includes('mcp.access_keys');
  const { status: socketStatus } = useSocketStore();
  const tenants = useTenantStore((s) => s.tenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const mobileNavOpen = useUiStore((s) => s.mobileNavOpen);
  const toggleMobileNav = useUiStore((s) => s.toggleMobileNav);
  const mode = useLayoutMode();
  const isPhone = mode === 'phone';
  const isDesktop = mode === 'desktop';
  const android = isAndroidApp();
  const [connectedApps, setConnectedApps] = useState<ConnectedApp[]>([]);

  // Refreshed periodically so an app newly registered in Obligate shows up
  // without reloading this tab.
  useEffect(() => {
    const loadApps = () => {
      fetch('/api/auth/connected-apps', { credentials: 'include' })
        .then(r => r.json())
        .then((d: { success: boolean; data?: ConnectedApp[] }) => {
          if (d.success && Array.isArray(d.data)) setConnectedApps(d.data);
        })
        .catch(() => {});
    };
    loadApps();
    const interval = setInterval(loadApps, APPS_REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  // Already sorted by Obligate (sort_order, then name): rendered as-is, no
  // local re-sort nor filter. The current app is the entry Obligate marked
  // `self` (falls back to appType === CURRENT_APP for an Obligate that does
  // not send `self`), synthesised from CURRENT_APP_FALLBACK if Obligate omits
  // it: Obligarth's own pill never disappears from its own switcher.
  const selfEntry = connectedApps.find((a) => a.self) ?? connectedApps.find((a) => a.appType === CURRENT_APP);
  const visibleApps = selfEntry ? connectedApps : [CURRENT_APP_FALLBACK, ...connectedApps];
  // One entry only (another Obligarth instance registered in Obligate stays a
  // normal, reachable pill).
  const isCurrentApp = (a: ConnectedApp) => a === (selfEntry ?? CURRENT_APP_FALLBACK);
  // Obli* apps in the main row, third-party apps in "More…". The current app
  // always stays in the main row, even when it is third-party.
  const mainApps = visibleApps.filter((a) => !a.thirdParty || isCurrentApp(a));
  const moreApps = visibleApps.filter((a) => a.thirdParty && !isCurrentApp(a));

  // "More…" dropdown: outside tap, Escape and Android back close it.
  const [moreOpen, setMoreOpen] = useState(false);
  const moreRef = useRef<HTMLDivElement>(null);
  useClickOutside([moreRef], () => setMoreOpen(false), moreOpen);
  useNativeBack(() => setMoreOpen(false), moreOpen, { escape: true });

  // Pills show their label while the labelled row fits the space flexbox
  // grants the switcher, and fold to the coloured dot otherwise. Measured
  // against a hidden, always-labelled copy (measuring the visible row would
  // never unfold once collapsed); re-measured on resize and list changes.
  const [pillsCollapsed, setPillsCollapsed] = useState(false);
  const switcherSlotRef = useRef<HTMLDivElement>(null);
  const switcherMeasureRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const slot = switcherSlotRef.current;
    const measure = switcherMeasureRef.current;
    if (!slot || !measure) return;
    const update = () => setPillsCollapsed(measure.scrollWidth > slot.clientWidth);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(slot);
    return () => ro.disconnect();
  }, [mainApps.length, moreApps.length, mode]);

  const goApp = (app: ConnectedApp) => {
    if (isCurrentApp(app)) return;
    // Only an http(s) base URL is followed (never javascript: or the like).
    let url: URL;
    try { url = new URL(`${app.baseUrl}/auth/sso-redirect`); } catch { return; }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return;
    // Cross-app tenant handoff: append ?tenant=<slug> so the target app can
    // restore the same tenant context post-SSO. Drops to the user's first
    // tenant on the target app if no match.
    const tenantSlug = tenants.find(t => t.id === currentTenantId)?.slug;
    if (tenantSlug) url.searchParams.set('tenant', tenantSlug);
    window.location.href = url.toString();
  };

  const username = user?.username ?? '';
  const strippedUsername = username.startsWith('og_') ? username.slice(3) : username;
  // Prefer displayName for the topbar badge — falls back to the username minus
  // the og_ SSO prefix if no displayName is set.
  const displayedUsername = anonymize(user?.displayName || strippedUsername);

  const socketLabel =
    socketStatus === 'connected' ? t('header.socketConnected') :
    socketStatus === 'reconnecting' ? t('header.socketReconnecting') :
    t('header.socketDisconnected');

  // The account menu replaces the plain badge below 1024 px, and everywhere
  // in the Android shell (it carries the native "App settings" entry).
  const useAccountMenu = !isDesktop || android;
  // App pills: hidden in the ObliTools desktop shell (its own tab bar).
  const showAppPills = !isNativeApp && !isPhone;
  const otherApps = !isNativeApp ? mainApps.filter((a) => !isCurrentApp(a)) : [];
  const otherThirdPartyApps = !isNativeApp ? moreApps : [];
  const appKey = (app: ConnectedApp) => `${app.appType}|${app.baseUrl}`;

  // One switcher pill. `measure` = the hidden copy used only for sizing:
  // not focusable, no handler, not announced.
  const appPill = (app: ConnectedApp, labelled: boolean, measure = false) => {
    const isCurrent = isCurrentApp(app);
    return (
      <button
        key={appKey(app)}
        type="button"
        tabIndex={measure ? -1 : undefined}
        onClick={measure ? undefined : () => goApp(app)}
        className={cn(
          'flex items-center gap-2 py-1.5 rounded-md text-[12.5px] font-medium transition-colors shrink-0 coarse:min-h-9',
          labelled ? 'px-3' : 'px-2.5',
          isCurrent
            ? 'bg-bg-secondary text-text-primary font-semibold shadow-[0_1px_3px_rgb(46_52_64_/_0.1)]'
            : 'text-text-secondary hover:bg-bg-active hover:text-text-primary',
        )}
        title={measure ? undefined : app.name}
        aria-label={measure ? undefined : app.name}
        aria-current={!measure && isCurrent ? 'page' : undefined}
      >
        <span
          className="w-2 h-2 rounded-full shrink-0"
          style={{ background: app.color || FALLBACK_APP_COLOR }}
        />
        {labelled && <span>{app.name}</span>}
      </button>
    );
  };

  // "More…" button closing the main row. `measure` = the hidden sizing copy.
  const moreButton = (labelled: boolean, measure = false) => (
    <button
      type="button"
      tabIndex={measure ? -1 : undefined}
      onClick={measure ? undefined : () => setMoreOpen((v) => !v)}
      aria-haspopup={measure ? undefined : 'true'}
      aria-expanded={measure ? undefined : moreOpen}
      className={cn(
        'flex items-center gap-1.5 py-1.5 rounded-md text-[12.5px] font-medium transition-colors shrink-0 coarse:min-h-9 text-text-secondary hover:bg-bg-active hover:text-text-primary',
        labelled ? 'px-3' : 'px-2.5',
      )}
      title={measure ? undefined : (t('header.moreApps') || 'More…')}
      aria-label={measure ? undefined : (t('header.moreApps') || 'More…')}
    >
      <MoreHorizontal size={14} className="shrink-0" />
      {labelled && <span>{t('header.moreApps') || 'More…'}</span>}
      {labelled && <ChevronDown size={12} className={cn('shrink-0 text-text-muted transition-transform', moreOpen && 'rotate-180')} />}
    </button>
  );

  const avatar = (size: 'sm' | 'md') => (
    user?.avatar ? (
      <img
        src={user.avatar}
        alt={displayedUsername}
        className={cn('rounded-full object-cover', size === 'md' ? 'w-7 h-7' : 'w-4 h-4')}
      />
    ) : size === 'md' ? (
      // Opaque accent tones of the theme: the white initial stays at 4.8:1 or
      // more on every theme (the former translucent gradient let the header
      // show through: 1.7:1 to 2.7:1 on Obli Daylight).
      <div
        className="w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-semibold text-white"
        style={{ background: 'linear-gradient(135deg, rgb(var(--c-accent)), rgb(var(--c-accent-dark)))' }}
      >
        {(displayedUsername?.[0] ?? '?').toUpperCase()}
      </div>
    ) : (
      <UserCircle className="w-4 h-4" />
    )
  );

  // /download (the Android APK; inside the Android shell the installed
  // version + "Check for updates") — reached from the account menu, i.e.
  // below 1024 px and in the Android shell. Never in ObliTools (it already is
  // the desktop app).
  const showDownloadItem = !isNativeApp;
  const accountItems: ActionMenuItem[] = user ? [
    {
      key: 'profile',
      icon: avatar('sm'),
      label: displayedUsername || (t('nav.profile') || 'Profile'),
      description: `${t('nav.profile') || 'Profile'} · ${user.role}`,
      onClick: () => navigate('/profile'),
    },
    ...(canAccessKeys ? [{
      key: 'access-keys',
      icon: <KeyRound className="w-4 h-4" />,
      label: t('nav.accessKeys') || 'Access keys',
      onClick: () => navigate('/access-keys'),
    } satisfies ActionMenuItem] : []),
    // Phone: the app pills live here.
    ...(isPhone ? otherApps.map((app, i): ActionMenuItem => ({
      key: `app-${appKey(app)}`,
      icon: <span className="block w-2 h-2 rounded-full" style={{ background: app.color || FALLBACK_APP_COLOR }} />,
      label: app.name,
      onClick: () => goApp(app),
      separator: i === 0,
    })) : []),
    // Phone: third-party apps ("More…" in Obligate), as a separate section.
    ...(isPhone ? otherThirdPartyApps.map((app, i): ActionMenuItem => ({
      key: `more-app-${appKey(app)}`,
      icon: <span className="block w-2 h-2 rounded-full" style={{ background: app.color || FALLBACK_APP_COLOR }} />,
      label: app.name,
      description: i === 0 ? (t('header.otherApps') || 'Other apps') : undefined,
      onClick: () => goApp(app),
      separator: i === 0,
    })) : []),
    // Download page — Android shell: the app's version / updates screen.
    ...(showDownloadItem ? [{
      key: 'download',
      icon: <Download className="w-4 h-4" />,
      label: android
        ? (t('header.appUpdates') || 'App updates')
        : (t('nav.downloadApp') || 'Download App'),
      onClick: () => navigate('/download'),
      separator: true,
    } satisfies ActionMenuItem] : []),
    // Android shell: native app settings (server URL, notifications, updates).
    ...(android && canUseNative('openSettings') ? [{
      key: 'app-settings',
      icon: <Settings className="w-4 h-4" />,
      label: t('header.appSettings') || 'App settings',
      onClick: () => { native.openSettings().catch(() => { /* shell too old */ }); },
      separator: !showDownloadItem,
    } satisfies ActionMenuItem] : []),
    {
      key: 'logout',
      icon: <LogOut className="w-4 h-4" />,
      label: t('nav.signOut'),
      onClick: () => { logout(); },
      danger: true,
      separator: true,
    },
  ] : [];

  return (
    <header
      className={cn(
        'relative flex shrink-0 items-center gap-3 bg-bg-secondary',
        // Safe areas (0 on desktop → identical px-4 / 52 px).
        'pt-safe pl-[max(1rem,var(--safe-left))] pr-[max(1rem,var(--safe-right))]',
        'max-md:gap-2 max-md:pl-[max(0.75rem,var(--safe-left))] max-md:pr-[max(0.75rem,var(--safe-right))]',
      )}
      style={{ height: 'calc(52px + var(--safe-top))' }}
    >
      {/* Hamburger — opens the sidebar drawer below 1024 px. */}
      {!isDesktop && (
        <IconButton
          label={t('header.openMenu') || 'Open menu'}
          icon={<Menu className="h-5 w-5" />}
          size="md"
          onClick={toggleMobileNav}
          aria-expanded={mobileNavOpen}
          aria-haspopup="dialog"
          className="-ml-1.5 shrink-0"
        />
      )}

      {/* Logo — always visible in the topbar so it (and the tenant selector
          right next to it) stay accessible regardless of sidebar state
          (pinned, collapsed, floating). Phone: the square mark only. */}
      <Link to="/" className="flex items-center gap-2 shrink-0" aria-label="Obligarth">
        {isPhone ? (
          <img src="/favicon.svg" alt="Obligarth" className="h-8 w-8" />
        ) : (
          <Logo className="h-8 w-auto max-w-[160px] object-contain" />
        )}
      </Link>

      {/* Tenant selector — sits left of the app switcher, preserving the
          context that gets carried across apps. Shrinks (truncates) on
          narrow screens; stays visible in the Android shell. */}
      <TenantSwitcher />

      {/* App switcher pills — only the current app + the apps the user
          actually has access to via Obligate are rendered. Hiding the
          unreachable ones entirely (rather than dimming them) matches
          the pre-Obligate behaviour: an admin without Oblimap rights
          shouldn't even see the Oblimap pill, since there's no path to
          enable it from here. The labels fold to the brand dot as soon as
          the labelled row no longer fits (measured, see pillsCollapsed);
          on phones the apps move to the account menu. */}
      {showAppPills && (
        // No overflow clipping here: it would cut the "More…" dropdown.
        <div ref={switcherSlotRef} className="ml-1 flex-1 min-w-0 flex items-center">
          <nav
            aria-label={t('header.apps') || 'Apps'}
            className="flex items-center gap-1 rounded-lg bg-bg-hover p-1"
          >
            {mainApps.map((app) => appPill(app, !pillsCollapsed))}
            {moreApps.length > 0 && (
              <div ref={moreRef} className="relative">
                {moreButton(!pillsCollapsed)}
                {moreOpen && (
                  <div className="absolute left-0 top-9 z-50 w-56 max-w-[calc(100vw-1.5rem)] rounded-xl bg-bg-secondary shadow-2xl overflow-hidden">
                    <div className="px-3 py-2">
                      <p className="text-xs font-semibold text-text-muted uppercase tracking-wide">{t('header.otherApps') || 'Other apps'}</p>
                    </div>
                    <div className="py-1 max-h-64 overflow-y-auto overscroll-contain">
                      {moreApps.map((app) => (
                        <button
                          key={appKey(app)}
                          type="button"
                          onClick={() => { setMoreOpen(false); goApp(app); }}
                          className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left text-text-primary transition-colors hover:bg-bg-hover coarse:min-h-11"
                        >
                          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: app.color || FALLBACK_APP_COLOR }} />
                          <span className="truncate">{app.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </nav>
        </div>
      )}
      {showAppPills && (
        <div
          ref={switcherMeasureRef}
          aria-hidden
          className="absolute -z-10 opacity-0 pointer-events-none flex items-center gap-1 p-1"
          style={{ top: -9999, left: -9999 }}
        >
          {mainApps.map((app) => appPill(app, true, true))}
          {moreApps.length > 0 && moreButton(true, true)}
        </div>
      )}

      <div className="ml-auto flex shrink-0 items-center gap-3 max-md:gap-1.5">
        {/* Socket connection status dot */}
        <button
          onClick={socketStatus !== 'connected' ? () => window.location.reload() : undefined}
          title={socketLabel}
          aria-label={socketLabel}
          className={cn(
            'flex h-7 w-7 items-center justify-center rounded-md transition-opacity coarse:h-10 coarse:w-10',
            socketStatus !== 'connected' && 'cursor-pointer hover:opacity-70',
            socketStatus === 'connected' && 'cursor-default',
          )}
        >
          <span
            className={cn(
              'h-2 w-2 rounded-full transition-colors',
              socketStatus === 'connected' && 'bg-green-500',
              socketStatus === 'reconnecting' && 'bg-amber-400 animate-pulse',
              socketStatus === 'disconnected' && 'bg-red-500 animate-pulse',
            )}
          />
        </button>

        {/* Notification Center */}
        <NotificationCenter />

        {user && (
          useAccountMenu ? (
            <>
              <ActionMenu
                items={accountItems}
                label={t('header.accountMenu') || 'Account menu'}
                menuClassName="w-64"
                trigger={(p) => (
                  <button
                    {...p}
                    type="button"
                    aria-label={t('header.accountMenu') || 'Account menu'}
                    className={cn(
                      'flex items-center gap-2 rounded-lg bg-bg-hover transition-colors hover:bg-bg-active',
                      isDesktop ? 'pl-1.5 pr-3 py-1' : 'p-1 coarse:p-1.5',
                    )}
                  >
                    {avatar('md')}
                    {isDesktop && (
                      <>
                        <span className="text-[13px] font-medium text-text-primary">{displayedUsername}</span>
                        <span className="text-[10px] font-mono uppercase tracking-wider text-accent pl-2 -light">
                          {user.role}
                        </span>
                      </>
                    )}
                  </button>
                )}
              />
              {/* Tablet keeps the one-tap sign-out next to the avatar. */}
              {mode === 'tablet' && (
                <IconButton
                  label={t('nav.signOut')}
                  icon={<LogOut size={15} />}
                  size="md"
                  variant="ghost"
                  onClick={logout}
                />
              )}
            </>
          ) : (
            <>
              <div className="flex items-center gap-2 pl-1.5 pr-3 py-1 rounded-lg bg-bg-hover">
                {avatar('md')}
                <span className="text-[13px] font-medium text-text-primary">{displayedUsername}</span>
                <span className="text-[10px] font-mono uppercase tracking-wider text-accent pl-2 -light">
                  {user.role}
                </span>
              </div>
              <button
                onClick={logout}
                title={t('nav.signOut')}
                aria-label={t('nav.signOut')}
                className="flex h-7 w-7 items-center justify-center rounded-md text-text-muted hover:bg-bg-hover hover:text-text-primary transition-colors"
              >
                <LogOut size={15} />
              </button>
            </>
          )
        )}
      </div>
    </header>
  );
}
