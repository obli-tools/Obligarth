import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Settings,
  Users,
  UserCircle,
  LogOut,
  Server,
  ArrowLeftRight,
  CalendarClock,
  Building2,
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Pin,
  PinOff,
  Monitor,
  Laptop,
  ShieldCheck,
  Key,
  X,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { anonymize } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import { useAuthStore } from '@/store/authStore';
import { useUiStore, useEffectiveSidebar } from '@/store/uiStore';
import { IconButton } from '@/components/common/IconButton';
import { useTenantStore } from '@/store/tenantStore';
import { groupsApi } from '@/api/groups.api';
import { getSocket } from '@/socket/socketClient';
import type { DeviceGroupTreeNode } from '@obliance/shared';
import { SocketEvents, MASTER_TENANT_ID, isMasterTenant } from '@obliance/shared';

// ── localStorage helpers ─────────────────────────────────────────────────────

function usePersisted<T>(key: string, initial: T): [T, (v: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored !== null ? (JSON.parse(stored) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = useCallback((v: T | ((prev: T) => T)) => {
    setValue(prev => {
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v;
      localStorage.setItem(key, JSON.stringify(next));
      return next;
    });
  }, [key]);
  return [value, set];
}

// ── Cross-mount cache ────────────────────────────────────────────────────────
// Below 1024 px the Sidebar lives in the off-canvas Drawer (AppLayout), which
// unmounts it when closed — and the drawer closes on every navigation. Without
// this cache every hamburger tap would start from an empty tree and fetch it
// again. The last group tree / approvals count are kept here, keyed by user +
// tenant, so a remount renders at once and only refetches once the data is
// REFRESH_MS old. The desktop column stays mounted: first load and tenant
// switches behave as before (empty tree → fetch → refresh every 30 s).

/** Full refresh cadence (socket events keep the tree live in between). */
const REFRESH_MS = 30_000;

interface SidebarData {
  /** User + tenant the rows belong to; null = nothing loaded yet. */
  key: string | null;
  groupTree: DeviceGroupTreeNode[];
}

const EMPTY_SIDEBAR_DATA: SidebarData = { key: null, groupTree: [] };

let sidebarCache: (SidebarData & { key: string; fetchedAt: number }) | null = null;
let pendingApprovalsCache: { key: string; count: number } | null = null;
/** Drawer only: search text + tree scroll position survive a close / re-open. */
let drawerUiCache: { key: string; search: string; scrollTop: number } | null = null;

function sidebarCacheKey(userId: number | null | undefined, tenantId: number | null | undefined): string {
  return `${userId ?? '-'}:${tenantId ?? '-'}`;
}

/** Key for the user + tenant active right now (read outside render). */
function currentSidebarCacheKey(): string {
  return sidebarCacheKey(useAuthStore.getState().user?.id, useTenantStore.getState().currentTenantId);
}

function rememberDrawerUi(key: string, patch: Partial<{ search: string; scrollTop: number }>) {
  const base = drawerUiCache?.key === key ? drawerUiCache : { key, search: '', scrollTop: 0 };
  drawerUiCache = { ...base, ...patch };
}

// ── Group search ─────────────────────────────────────────────────────────────
// Keeps the groups whose name matches (with their whole sub-tree) and the
// ancestors leading to them.

function filterGroupTree(nodes: DeviceGroupTreeNode[], query: string): DeviceGroupTreeNode[] {
  const q = query.trim().toLowerCase();
  if (!q) return nodes;
  const walk = (list: DeviceGroupTreeNode[]): DeviceGroupTreeNode[] => {
    const kept: DeviceGroupTreeNode[] = [];
    for (const node of list) {
      if (node.name.toLowerCase().includes(q)) {
        kept.push(node);
      } else {
        const children = walk(node.children);
        if (children.length > 0) kept.push({ ...node, children });
      }
    }
    return kept;
  };
  return walk(nodes);
}

// ── Collapsible Group Row ─────────────────────────────────────────────────────

function GroupRow({
  group,
  depth = 0,
  forceExpanded = false,
}: {
  group: DeviceGroupTreeNode;
  depth?: number;
  /** While searching: show the matches whatever the saved collapse state. */
  forceExpanded?: boolean;
}) {
  const { t } = useTranslation();
  const location = useLocation();
  const [collapsedPref, setCollapsed] = usePersisted<boolean>(`sidebar-group-collapsed-${group.id}`, false);
  const collapsed = collapsedPref && !forceExpanded;
  const hasChildren = group.children.length > 0;

  const isGroupActive = location.pathname === `/group/${group.id}`;
  const paddingLeft = depth * 12;

  return (
    <div>
      {/* Group header row */}
      <div
        className={cn(
          'flex items-center gap-1 rounded-md transition-colors group',
          isGroupActive
            ? 'bg-bg-active text-text-primary'
            : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
        )}
        style={{ paddingLeft }}
      >
        {/* Collapse toggle — invisible 40 px hit area on touch screens. A
            leaf group gets a spacer of the same width so names stay aligned. */}
        {hasChildren ? (
          <button
            onClick={() => setCollapsed(v => !v)}
            aria-label={collapsed
              ? (t('nav.expandGroup', { name: group.name }) || `Expand ${group.name}`)
              : (t('nav.collapseGroup', { name: group.name }) || `Collapse ${group.name}`)}
            aria-expanded={!collapsed}
            className="relative p-1 rounded hover:bg-bg-hover transition-colors shrink-0 coarse:after:absolute coarse:after:left-1/2 coarse:after:top-1/2 coarse:after:h-10 coarse:after:w-10 coarse:after:-translate-x-1/2 coarse:after:-translate-y-1/2 coarse:after:content-['']"
          >
            {collapsed ? (
              <ChevronRight size={12} className="text-text-muted" />
            ) : (
              <ChevronDown size={12} className="text-text-muted" />
            )}
          </button>
        ) : (
          <span className="w-5 shrink-0" aria-hidden />
        )}

        {/* Group link */}
        <Link
          to={`/group/${group.id}`}
          className="flex items-center gap-2 flex-1 py-1.5 min-w-0 coarse:py-2.5"
        >
          <Server size={14} className="shrink-0 text-text-muted" />
          <span className="truncate flex-1 text-[13px] font-medium">{anonymize(group.name)}</span>
        </Link>
      </div>

      {/* Child groups */}
      {!collapsed && group.children.map(child => (
        <GroupRow
          key={child.id}
          group={child}
          depth={depth + 1}
          forceExpanded={forceExpanded}
        />
      ))}
    </div>
  );
}

// ── Nav link ──────────────────────────────────────────────────────────────────

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
  /** Optional red pill showing a pending-work count next to the label. */
  badgeCount?: number;
}

function NavLink({ item }: { item: NavItem }) {
  const location = useLocation();
  const isActive = location.pathname === item.path ||
    (item.path !== '/' && location.pathname.startsWith(item.path));
  return (
    <Link
      to={item.path}
      className={cn(
        'flex items-center gap-3 rounded-md px-3 py-2 text-[14px] transition-colors coarse:py-2.5',
        isActive
          ? 'bg-bg-active text-text-primary'
          : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
      )}
    >
      {item.icon}
      <span className="flex-1">{item.label}</span>
      {item.badgeCount !== undefined && item.badgeCount > 0 && (
        <span className="shrink-0 min-w-[1.25rem] px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 text-[10px] font-semibold text-center">
          {item.badgeCount > 99 ? '99+' : item.badgeCount}
        </span>
      )}
    </Link>
  );
}

// ── Main Sidebar ──────────────────────────────────────────────────────────────

interface SidebarProps {
  /**
   * 'drawer' = rendered inside the phone / tablet off-canvas Drawer
   * (AppLayout, < 1024 px): always expanded, stacked layout, a close button
   * instead of the collapse / float toggles. Default: the desktop column.
   */
  variant?: 'default' | 'drawer';
  /** Drawer variant: close the drawer. */
  onRequestClose?: () => void;
}

export function Sidebar({ variant = 'default', onRequestClose }: SidebarProps = {}) {
  const { t } = useTranslation();
  const inDrawer = variant === 'drawer';
  const location = useLocation();
  const { user, isAdmin, permissions } = useAuthStore();
  // Tenant capabilities — Capability enum from @obliance/shared.
  // We use them to surface admin-tenant pages to non-admin users who
  // have been granted a specific page-gate capability:
  //   - supervision:read         → Supervision (Reports + History + Remote sessions)
  //   - agent_config:custom_sections / discovery / keys → Agent config tabs
  // Admins implicitly have all capabilities (the sidebar ORs role and
  // cap so the menu still appears for admins regardless of cap state).
  const tenantCaps = new Set(permissions?.tenantCapabilities ?? []);
  const hasSupervisionCap = tenantCaps.has('supervision:read');
  const hasAnyAgentConfigCap =
    tenantCaps.has('agent_config:custom_sections') ||
    tenantCaps.has('agent_config:discovery') ||
    tenantCaps.has('agent_config:keys') ||
    tenantCaps.has('agent_config:approval');
  const { toggleSidebarFloating, toggleSidebarCollapsed } = useUiStore();
  // Effective (device-aware) mode — see useEffectiveSidebar(). The drawer is
  // always the full, expanded sidebar.
  const effective = useEffectiveSidebar();
  const sidebarCollapsed = !inDrawer && effective.collapsed;
  const sidebarFloating = !inDrawer && effective.floating;
  const canFloat = !inDrawer && effective.canFloat;

  const admin = isAdmin();

  // ── Layout preferences ─────────────────────────────────────────────────────
  const [storedSidebarLayout, setSidebarLayout] = usePersisted<'stacked' | 'side-by-side'>('sidebar-layout', 'stacked');
  // A 320 px drawer has no room for two columns: forced stacked, never persisted.
  const sidebarLayout = inDrawer ? 'stacked' : storedSidebarLayout;
  const [splitPercent, setSplitPercent] = usePersisted<number>('sidebar-split-percent', 50);
  const [adminMenuOpen, setAdminMenuOpen] = usePersisted<boolean>('sidebar:admin-open', true);
  const [navMenuOpen, setNavMenuOpen] = usePersisted<boolean>('sidebar:nav-open', true);
  // Per-tenant collapse state for the master/god view buckets. We share
  // the same localStorage key as the /devices GroupSidePanel + the
  // DeviceTable so collapsing "Contoso" once folds it everywhere — one
  // mental model for "this tenant is currently not interesting".
  const [collapsedTenants, setCollapsedTenants] = usePersisted<number[]>('obliance:groupPanelCollapsedTenants', []);
  const isTenantCollapsed = (id: number) => collapsedTenants.includes(id);
  const toggleTenantCollapsed = (id: number) => {
    setCollapsedTenants((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]);
  };
  const splitContainerRef = useRef<HTMLDivElement>(null);

  // ── Group tree state ───────────────────────────────────────────────────────
  // Seeded from the cross-mount cache (see top of file) when it holds this
  // user + tenant, so a re-opened drawer shows the tree immediately.
  const currentTenantId = useTenantStore(s => s.currentTenantId);
  const cacheKey = sidebarCacheKey(user?.id, currentTenantId);
  const [data, setData] = useState<SidebarData>(() => (
    sidebarCache?.key === cacheKey
      ? { key: cacheKey, groupTree: sidebarCache.groupTree }
      : EMPTY_SIDEBAR_DATA
  ));
  const { groupTree } = data;
  const setGroupTree = useCallback((tree: DeviceGroupTreeNode[]) => {
    setData(d => ({ ...d, groupTree: tree }));
  }, []);
  const [search, setSearchState] = useState(() => (
    inDrawer && drawerUiCache?.key === cacheKey ? drawerUiCache.search : ''
  ));
  const setSearch = (value: string) => {
    setSearchState(value);
    if (inDrawer) rememberDrawerUi(cacheKey, { search: value });
  };
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState(() => (
    pendingApprovalsCache?.key === cacheKey ? pendingApprovalsCache.count : 0
  ));

  // Socket updates flow back into the cache. `data.key` always describes
  // `data`, so another tenant's rows can never land in it.
  useEffect(() => {
    if (data.key !== null && sidebarCache?.key === data.key) {
      sidebarCache.groupTree = data.groupTree;
    }
  }, [data]);

  const loadGroupTree = useCallback(async () => {
    const key = currentSidebarCacheKey();
    try {
      const tree = await groupsApi.tree();
      // Tenant switched (or another user signed in) while in flight: the
      // answer belongs to the previous context — drop it.
      if (key !== currentSidebarCacheKey()) return;
      sidebarCache = { key, groupTree: tree, fetchedAt: Date.now() };
      setData({ key, groupTree: tree });
    } catch {
      // fail silently — sidebar will just show empty
    }
  }, []);

  useEffect(() => {
    const cached = sidebarCache?.key === cacheKey ? sidebarCache : null;
    // Never keep another tenant's tree on screen: show the cached rows of
    // this user + tenant, or nothing until the fetch lands.
    setData(prev => (
      prev.key === cacheKey ? prev
        : cached ? { key: cacheKey, groupTree: cached.groupTree }
        : EMPTY_SIDEBAR_DATA
    ));
    // Background tabs / a backgrounded mobile app skip the 30 s full refresh
    // (socket events keep the tree live) and catch up once visible again.
    const refresh = () => {
      if (document.visibilityState !== 'hidden') loadGroupTree();
    };
    let interval: ReturnType<typeof setInterval> | undefined;
    let firstTick: ReturnType<typeof setTimeout> | undefined;
    const age = cached ? Date.now() - cached.fetchedAt : Infinity;
    if (age >= 0 && age < REFRESH_MS) {
      // Remount on recent cached rows (drawer re-opened): they are already
      // on screen — resume the 30 s cadence from the last fetch instead of
      // fetching the tree again right now.
      firstTick = setTimeout(() => {
        refresh();
        interval = setInterval(refresh, REFRESH_MS);
      }, REFRESH_MS - age);
    } else {
      loadGroupTree();
      interval = setInterval(refresh, REFRESH_MS);
    }
    const onVisible = () => {
      if (document.visibilityState === 'visible') loadGroupTree();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearTimeout(firstTick);
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [loadGroupTree, cacheKey]);

  // Drawer: put the tree back where the user left it (the drawer unmounts
  // the Sidebar on close — e.g. after tapping a group).
  const treeScrollRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (!inDrawer) return;
    const el = treeScrollRef.current;
    if (el && drawerUiCache?.key === cacheKey) el.scrollTop = drawerUiCache.scrollTop;
  }, [inDrawer, cacheKey]);
  const handleTreeScroll = inDrawer
    ? (e: React.UIEvent<HTMLDivElement>) => rememberDrawerUi(cacheKey, { scrollTop: e.currentTarget.scrollTop })
    : undefined;

  // ── Pending approvals badge (admin only) ────────────────────────────────
  useEffect(() => {
    if (!admin) return;
    let cancelled = false;
    const load = async () => {
      try {
        const key = currentSidebarCacheKey();
        const { approvalApi } = await import('@/api/approval.api');
        const rows = await approvalApi.list(false);
        if (key === currentSidebarCacheKey()) pendingApprovalsCache = { key, count: rows.length };
        if (!cancelled) setPendingApprovalsCount(rows.length);
      } catch { /* ignore */ }
    };
    load();
    const socket = getSocket();
    const handler = () => load();
    if (socket) {
      socket.on('APPROVAL_CREATED', handler);
      socket.on('APPROVAL_UPDATED', handler);
    }
    const tick = setInterval(load, 60_000);
    return () => {
      cancelled = true;
      clearInterval(tick);
      if (socket) {
        socket.off('APPROVAL_CREATED', handler);
        socket.off('APPROVAL_UPDATED', handler);
      }
    };
  }, [admin, currentTenantId]);

  // ── Real-time group updates ────────────────────────────────────────────────
  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const onGroupChanged = () => {
      const key = currentSidebarCacheKey();
      groupsApi.tree()
        .then(tree => { if (key === currentSidebarCacheKey()) setGroupTree(tree); })
        .catch(() => {});
    };

    socket.on(SocketEvents.GROUP_CREATED, onGroupChanged);
    socket.on(SocketEvents.GROUP_UPDATED, onGroupChanged);
    socket.on(SocketEvents.GROUP_DELETED, onGroupChanged);
    socket.on(SocketEvents.GROUP_MOVED, onGroupChanged);

    return () => {
      socket.off(SocketEvents.GROUP_CREATED, onGroupChanged);
      socket.off(SocketEvents.GROUP_UPDATED, onGroupChanged);
      socket.off(SocketEvents.GROUP_DELETED, onGroupChanged);
      socket.off(SocketEvents.GROUP_MOVED, onGroupChanged);
    };
  }, [setGroupTree]);

  // ── Split column resize ────────────────────────────────────────────────────
  const handleSplitMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const handleMouseMove = (ev: MouseEvent) => {
      if (!splitContainerRef.current) return;
      const rect = splitContainerRef.current.getBoundingClientRect();
      const pct = Math.round(((ev.clientX - rect.left) / rect.width) * 100);
      setSplitPercent(Math.max(20, Math.min(80, pct)));
    };
    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, [setSplitPercent]);

  // ── Nav items ──────────────────────────────────────────────────────────────
  // The sidebar has two collapsible sections. "Navigation" is the
  // top section everyone sees (gated only by login); "Administration"
  // is the bottom section that surfaces only when at least one item
  // is visible to the user. Each item independently checks whether
  // the user can see it, then we hide the entire section if the
  // resulting list is empty.

  const navItems: NavItem[] = [
    { label: t('nav.dashboard'),                  path: '/',           icon: <LayoutDashboard size={18} /> },
    { label: t('nav.devices'),                    path: '/devices',    icon: <Monitor size={18} /> },
    { label: t('nav.automations', 'Automations'), path: '/automations', icon: <CalendarClock size={18} /> },
    { label: t('nav.policies'),                   path: '/policies',   icon: <ShieldCheck size={18} /> },
  ];

  // Admin-tier section. Each item is conditionally added based on
  // `admin` (platform admin) OR the user's relevant capability. When
  // the resulting list is empty (plain user, no caps) the section
  // header is hidden entirely.
  const adminNavItems: NavItem[] = [
    // Users / Teams / Permissions / Restrictions — admin only.
    ...(admin ? [{ label: t('nav.users'), path: '/admin/users', icon: <Users size={18} /> } as NavItem] : []),
    // Security — audit log + approvals + 2FA, admin only.
    ...(admin ? [{ label: t('nav.security', 'Security'), path: '/admin/security', icon: <ShieldCheck size={18} />, badgeCount: pendingApprovalsCount } as NavItem] : []),
    // Supervision — reports + history + remote sessions. Visible if
    // platform admin OR the user has the `supervision:read`
    // capability on at least one team_permission row.
    ...(admin || hasSupervisionCap
      ? [{ label: t('nav.supervision'), path: '/admin/supervision', icon: <Laptop size={18} /> } as NavItem]
      : []),
    // Agent config — Custom Sections / Discovery / API Keys. The
    // page itself shows only the tabs the user has the matching
    // sub-cap for; we surface the menu entry as soon as ANY of them
    // is granted (or the user is admin).
    ...(admin || hasAnyAgentConfigCap
      ? [{ label: t('nav.agentConfig', 'Agent config'), path: '/admin/devices', icon: <Key size={18} /> } as NavItem]
      : []),
    // Workspace + Settings — platform admin on master tenant only.
    // Master gate happens via component-level visibility (the items
    // are rendered only when `admin && currentTenantId === MASTER`).
    ...(admin && isMasterTenant(currentTenantId)
      ? [{ label: t('nav.workspace', 'Workspace'), path: '/workspace', icon: <Building2 size={18} /> } as NavItem]
      : []),
    ...(admin
      ? [{ label: t('nav.settings'), path: '/settings', icon: <Settings size={18} /> } as NavItem]
      : []),
  ];

  // ── Group tree content ─────────────────────────────────────────────────────
  const searchQuery = search.trim();
  const visibleTree = filterGroupTree(groupTree, searchQuery);

  // ── Master/god view: group everything by tenant ───────────────────────────
  // On the master tenant the server returns the groups of every tenant. To
  // keep the sidebar legible we add an extra hierarchy level: a "Tenant X"
  // header above each tenant's group sub-tree, the master tenant first.
  const masterMode = isMasterTenant(currentTenantId);
  const tenantBuckets: Array<{
    id: number;
    name: string;
    groupTree: DeviceGroupTreeNode[];
  }> = [];
  if (masterMode) {
    const byTenant = new Map<number, { name: string; groupRoots: DeviceGroupTreeNode[] }>();
    const ensureBucket = (id: number, name: string | null | undefined) => {
      if (!byTenant.has(id)) byTenant.set(id, { name: name ?? `Tenant ${id}`, groupRoots: [] });
      return byTenant.get(id)!;
    };
    for (const root of visibleTree) ensureBucket(root.tenantId, root.tenantName).groupRoots.push(root);
    // Master tenant first, then alpha.
    const ordered = [...byTenant.entries()].sort(([aId, aV], [bId, bV]) => {
      if (aId === MASTER_TENANT_ID) return -1;
      if (bId === MASTER_TENANT_ID) return 1;
      return aV.name.localeCompare(bV.name);
    });
    for (const [id, b] of ordered) {
      tenantBuckets.push({ id, name: b.name, groupTree: b.groupRoots });
    }
  }

  const renderTenantBucket = (bucket: { id: number; name: string; groupTree: DeviceGroupTreeNode[] }) => {
    const collapsed = isTenantCollapsed(bucket.id);
    // While the user is searching we ignore the per-tenant collapse —
    // otherwise typing a query would silently filter rows out of view
    // because their tenant happens to be folded.
    const showChildren = !collapsed || !!searchQuery;
    return (
      <div key={bucket.id} className="mt-2">
        <button
          type="button"
          onClick={() => toggleTenantCollapsed(bucket.id)}
          className="w-full px-2 py-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-accent hover:bg-accent/5 rounded coarse:py-2.5"
          title={collapsed
            ? (t('nav.expandGroup', { name: bucket.name }) || `Expand ${bucket.name}`)
            : (t('nav.collapseGroup', { name: bucket.name }) || `Collapse ${bucket.name}`)}
          aria-expanded={!collapsed}
        >
          {collapsed ? <ChevronRight size={11} /> : <ChevronDown size={11} />}
          <Building2 size={11} />
          <span className="truncate">{bucket.name}</span>
        </button>
        {showChildren && bucket.groupTree.map((group) => (
          <GroupRow
            key={group.id}
            group={group}
            forceExpanded={!!searchQuery}
          />
        ))}
      </div>
    );
  };

  // `inColumn` = rendered in the side-by-side column, which has its own header.
  const renderGroupTree = (inColumn = false) => (
    <div className={inColumn ? '' : 'mt-2 pt-2 border-t border-border'}>
      {!inColumn && (
        <div className="px-2 py-1.5 flex items-center gap-2 text-[11px] font-mono font-medium text-text-muted uppercase tracking-[0.12em]">
          <Server size={12} />
          <span className="flex-1">{t('nav.groups') || 'Groups'}</span>
          {/* Side-by-side needs the width of the desktop column. */}
          {!inDrawer && groupTree.length > 0 && (
            <button
              onClick={() => setSidebarLayout('side-by-side')}
              title={t('nav.switchSideBySide') || 'Switch to side-by-side'}
              aria-label={t('nav.switchSideBySide') || 'Switch to side-by-side'}
              className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-bg-hover transition-colors shrink-0 coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center"
            >
              <ArrowLeftRight size={13} />
            </button>
          )}
        </div>
      )}

      {masterMode ? (
        tenantBuckets.map((b) => renderTenantBucket(b))
      ) : (
        /* Single-tenant flat tree */
        visibleTree.map(group => (
          <GroupRow
            key={group.id}
            group={group}
            forceExpanded={!!searchQuery}
          />
        ))
      )}
    </div>
  );

  // ── Collapsed mode (Obli Design v1) ─────────────────────────────────
  // 64 px icon-only column. Navigation items keep their tooltips, the
  // group tree + search are hidden, the user avatar + logout stay
  // visible at the bottom. Click the panel toggle to expand back.
  if (sidebarCollapsed) {
    // In collapsed mode we don't surface the Administration label;
    // we just stack the icons. adminNavItems is now built up from
    // the role + cap matrix above so it's empty for plain users
    // (they only see navItems).
    const allItems = [...navItems, ...adminNavItems];
    return (
      <aside className="flex h-full w-16 shrink-0 flex-col bg-bg-secondary">
        <div className="flex h-12 shrink-0 items-center justify-center">
          <button
            onClick={toggleSidebarCollapsed}
            title={t('nav.expandSidebar', 'Expand sidebar')}
            aria-label={t('nav.expandSidebar', 'Expand sidebar')}
            className="rounded-md p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center"
          >
            <ChevronsRight size={16} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 pt-3 space-y-1">
          {allItems.map((item) => {
            const isActive = location.pathname === item.path
              || (item.path !== '/' && location.pathname.startsWith(item.path + '/'));
            return (
              <Link
                key={item.path}
                to={item.path}
                title={item.label}
                aria-label={item.label}
                className={cn(
                  'relative flex h-10 w-full items-center justify-center rounded-md transition-colors',
                  isActive
                    ? 'bg-accent/12 text-accent'
                    : 'text-text-muted hover:bg-bg-hover hover:text-text-primary',
                )}
              >
                {item.icon}
                {item.badgeCount !== undefined && item.badgeCount > 0 && (
                  <span className="absolute -top-1 -right-1 min-w-[1.1rem] px-1 py-0 rounded-full bg-red-500/20 text-red-400 text-[9px] font-semibold text-center">
                    {item.badgeCount > 99 ? '99+' : item.badgeCount}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        <div className="p-2 space-y-1">
          <Link
            to="/profile"
            title={anonymize(user?.displayName || (user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username))}
            className={cn(
              'flex h-10 w-full items-center justify-center rounded-md transition-colors',
              location.pathname === '/profile'
                ? 'bg-bg-active text-text-primary'
                : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
            )}
          >
            {user?.avatar ? (
              <img src={user.avatar} alt="" className="w-6 h-6 rounded-full object-cover" />
            ) : (
              <UserCircle size={18} />
            )}
          </Link>
          <button
            onClick={() => useAuthStore.getState().logout()}
            title={t('nav.signOut')}
            className="flex h-10 w-full items-center justify-center rounded-md text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <LogOut size={18} />
          </button>
        </div>
      </aside>
    );
  }

  return (
    <aside className="flex h-full w-full flex-col bg-bg-secondary">

      {/* Sidebar head — collapse + float/pin toggles only. The logo and
          tenant selector live in the topbar (Header.tsx) so they remain
          visible when the sidebar is collapsed or floating. */}
      <div className="flex h-9 shrink-0 items-center justify-end px-3 pt-2 coarse:h-auto">
        {inDrawer ? (
          <IconButton
            label={t('nav.closeMenu') || 'Close menu'}
            icon={<X className="h-4 w-4" />}
            size="md"
            onClick={onRequestClose}
          />
        ) : (
          <div className="flex items-center gap-1">
            {/* Collapse and Float are mutually exclusive: in collapsed mode
                we already hide the Float button, so do the symmetric thing
                and hide Collapse while floating. */}
            {!sidebarFloating && (
              <button
                onClick={toggleSidebarCollapsed}
                title={t('nav.collapseSidebar', 'Collapse sidebar')}
                aria-label={t('nav.collapseSidebar', 'Collapse sidebar')}
                className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center"
              >
                <ChevronsLeft size={15} />
              </button>
            )}
            {/* Floating (auto-hide on mouse leave) needs a hovering pointer:
                not offered on touch screens (the effective mode is pinned). */}
            {canFloat && (
              <button
                onClick={toggleSidebarFloating}
                title={sidebarFloating ? t('nav.pinSidebar', 'Pin sidebar') : t('nav.floatSidebar', 'Float sidebar (auto-hide)')}
                aria-label={sidebarFloating ? t('nav.pinSidebar', 'Pin sidebar') : t('nav.floatSidebar', 'Float sidebar (auto-hide)')}
                className={cn(
                  'p-1.5 rounded transition-colors',
                  sidebarFloating
                    ? 'text-accent hover:text-accent hover:bg-accent/10'
                    : 'text-text-muted hover:text-text-primary hover:bg-bg-hover',
                )}
              >
                {sidebarFloating ? <PinOff size={15} /> : <Pin size={15} />}
              </button>
            )}
          </div>
        )}
      </div>

      {/* Search — filters the group tree by name */}
      <div className="px-3 py-2.5">
        <input
          type="text"
          placeholder={t('common.search')}
          aria-label={t('common.search')}
          value={search}
          onChange={e => setSearch(e.target.value)}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
      </div>

      {/* Content area — stacked or side-by-side */}
      {sidebarLayout === 'side-by-side' && groupTree.length > 0 ? (
        <div ref={splitContainerRef} className="flex flex-row flex-1 overflow-hidden min-h-0">

          {/* ── Nav column ── */}
          <div className="flex flex-col overflow-hidden min-w-0" style={{ width: `${splitPercent}%` }}>
            <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-border shrink-0">
              <span className="text-[10px] font-bold uppercase tracking-widest text-text-muted">{t('nav.navigation')}</span>
            </div>
            <nav className="flex-1 overflow-y-auto px-2 py-1 min-h-0">
              {navItems.map(item => <NavLink key={item.path} item={item} />)}
            </nav>
          </div>

          {/* ── Resize handle ── */}
          <div
            onMouseDown={handleSplitMouseDown}
            className="w-1 shrink-0 cursor-col-resize bg-border hover:bg-accent/50 active:bg-accent/70 transition-colors"
          />

          {/* ── Groups column ── */}
          <div className="flex flex-col flex-1 overflow-hidden min-w-0">
            <div className="flex items-center justify-between px-3 py-1.5 border-b border-border shrink-0">
              <span className="text-[10px] font-bold uppercase tracking-widest text-text-muted">{t('nav.groups') || 'Groups'}</span>
              <button
                onClick={() => setSidebarLayout('stacked')}
                title={t('nav.switchStacked') || 'Switch to stacked'}
                aria-label={t('nav.switchStacked') || 'Switch to stacked'}
                className="p-0.5 rounded text-text-muted hover:text-text-primary hover:bg-bg-hover transition-colors coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center"
              >
                <ArrowLeftRight size={12} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-2 min-h-0">
              {renderGroupTree(true)}
            </div>
          </div>

        </div>
      ) : (
        <div className="flex flex-col flex-1 min-h-0 px-2">
          {/* Primary nav — collapsible. Folding it gives the group tree
              the full sidebar height. State persisted via usePersisted. */}
          <button
            onClick={() => setNavMenuOpen(v => !v)}
            className="flex w-full items-center gap-2 px-1 py-1.5 text-text-muted hover:text-text-secondary transition-colors shrink-0 coarse:py-2.5"
            aria-expanded={navMenuOpen}
            title={navMenuOpen ? t('nav.collapseNav', 'Collapse navigation') : t('nav.expandNav', 'Expand navigation')}
          >
            <ChevronDown size={12} className={cn('transition-transform duration-200', !navMenuOpen && '-rotate-90')} />
            <span className="text-[10px] font-bold uppercase tracking-widest">{t('nav.navigation', 'Navigation')}</span>
            <div className="flex-1 h-px bg-border" />
          </button>
          {navMenuOpen && (
            <nav className="py-1 shrink-0">
              {navItems.map(item => <NavLink key={item.path} item={item} />)}
            </nav>
          )}

          {/* Group tree — quick navigation to the group pages. */}
          <div ref={treeScrollRef} onScroll={handleTreeScroll} className="flex-1 overflow-y-auto min-h-0">
            {renderGroupTree()}
          </div>
        </div>
      )}

      {/* Administration section — visible if at least one admin /
          cap-gated item resolved to an entry. Plain users with no
          capabilities get nothing rendered here. */}
      {adminNavItems.length > 0 && (
        <>
          <button
            onClick={() => setAdminMenuOpen(v => !v)}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-text-muted hover:text-text-secondary transition-colors coarse:py-2.5"
            aria-expanded={adminMenuOpen}
            title={adminMenuOpen ? t('nav.collapseAdmin', 'Collapse administration') : t('nav.expandAdmin', 'Expand administration')}
          >
            <div className="flex-1 h-px bg-border" />
            <ChevronDown size={12} className={cn('transition-transform duration-200', !adminMenuOpen && '-rotate-90')} />
            <span className="text-[10px] font-bold uppercase tracking-widest">{t('nav.administration', 'Administration')}</span>
            <div className="flex-1 h-px bg-border" />
          </button>

          {adminMenuOpen && (
            <nav className="px-2 pb-1">
              {adminNavItems.map(item => <NavLink key={item.path} item={item} />)}
            </nav>
          )}
        </>
      )}

      {/* User section */}
      <div className="border-t border-border p-2">
        <Link
          to="/profile"
          className={cn(
            'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors coarse:py-2.5',
            location.pathname === '/profile'
              ? 'bg-bg-active text-text-primary'
              : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
          )}
        >
          {user?.avatar ? (
            <img src={user.avatar} alt="" className="w-[20px] h-[20px] rounded-full object-cover" />
          ) : (
            <UserCircle size={18} />
          )}
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] font-medium text-text-primary">
              {anonymize(user?.displayName || (user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username))}
            </div>
            <div className="truncate font-mono text-[10px] text-text-muted">
              {(user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username) ?? ''} · {user?.role ?? ''}
            </div>
          </div>
        </Link>

        <button
          onClick={() => { useAuthStore.getState().logout(); }}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-hover hover:text-text-primary coarse:py-2.5"
        >
          <LogOut size={18} />
          {t('nav.signOut')}
        </button>
      </div>
    </aside>
  );
}
