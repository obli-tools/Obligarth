import { useEffect, useState, useCallback, useRef, useMemo, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { useSessionState } from '@/hooks/useSessionState';
import {
  Search, RefreshCw, ChevronRight, ChevronDown, X, Trash2, Download, Loader2, MoreHorizontal, SortAsc, SortDesc,
  FolderOpen, MousePointerClick, Check, FolderX, Tag, Building2, SlidersHorizontal, Columns3, FolderTree,
  ScrollText, TerminalSquare, ShieldCheck,
} from 'lucide-react';
import { mdmApi, type ContactFilter, type DeviceListParams, type DeviceSortField } from '@/api/mdm.api';
import { appleApi, isAwaitingApproval, newIdempotencyKey } from '@/api/apple.api';
import { isStepUpHandled } from '@/api/client';
import { MASTER_TENANT_ID, SocketEvents } from '@obligarth/shared';
import type {
  ComplianceState, ConfigState, DeviceFacets, DeviceGroupTreeNode, DeviceSummary, EnrollmentState, Ownership,
} from '@obligarth/shared';
import { useTenantStore } from '@/store/tenantStore';
import { groupsApi } from '@/api/groups.api';
import { DeviceRow } from '@/components/devices/DeviceRow';
import { StyledCheckbox } from '@/components/devices/StyledCheckbox';
import { GroupTreePicker } from '@/components/devices/GroupTreePicker';
import { useAuthStore } from '@/store/authStore';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { anonymize } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import { saveBlob } from '@/utils/download';
import { apiErrorMessage } from '@/utils/apiError';
import { useIsCoarsePointer, useLayoutMode, useMediaQuery } from '@/hooks/useMediaQuery';
import { useNativeBack } from '@/hooks/useNativeBack';
import { useAnchoredPosition } from '@/native/overlay';
import { registerSocketListener } from '@/socket/socketListeners';
import { Modal } from '@/components/common/Modal';
import { Drawer } from '@/components/common/Drawer';
import { ActionMenu } from '@/components/common/ActionMenu';
import { IconButton } from '@/components/common/IconButton';
import { Button } from '@/components/common/Button';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { AssignmentCreateDialog } from '@/components/mdm/Assignments';
import {
  COMPLIANCE_TONE, CONFIG_TONE, CONTACT_TONE, complianceLabel, configLabel, contactLabel, enrollmentLabel, toneDot,
} from '@/components/mdm/DeviceStateBadges';
import { ownershipLabel, platformLabel } from '@/components/mdm/PlatformIcon';
import {
  LINE2_FIELDS,
  loadVisibleFields,
  saveVisibleFields,
  defaultVisibleFields,
} from '@/utils/deviceLine2Fields';

// The inventory of the devices (modele-donnees-mdm §11.3): the list of GET /api/mdm/devices with its filters
// (enrollment, contact, compliance, configuration, platform, ownership, supervision, OS version, tags, group, end
// user, free text), the tree by group when nothing is sorted, the exports, and the batch actions (group, policy,
// commands of the integration, deletion of records out of management).

/** The enrollment states the tabs of the toolbar group together. */
export type StateTab = 'managed' | 'enrolling' | 'enrolled' | 'unenrolled' | 'all';
const STATE_TABS: Record<StateTab, EnrollmentState[] | undefined> = {
  managed: ['enrolling', 'awaiting_configuration', 'enrolled', 'unenrolling'],
  enrolling: ['enrolling', 'awaiting_configuration'],
  enrolled: ['enrolled'],
  unenrolled: ['unenrolled'],
  all: undefined,
};
const isStateTab = (v: unknown): v is StateTab => typeof v === 'string' && v in STATE_TABS;

// Empty string = no explicit sort: enrollment order, and the table renders as a tree by group.
type SortField = '' | DeviceSortField;

/** Filters a link may land on (dashboard, end users, groups). */
export interface InitialDeviceFilters {
  state?: string;
  contact?: string;
  compliance?: string;
  config?: string;
  platform?: string;
  ownership?: string;
  endUserId?: number;
}

interface DeviceTableProps {
  initialFilters?: InitialDeviceFilters;
  groupId?: number | null;
  onGroupChange?: (id: number | null) => void;
  /** Below lg the groups column of /devices is an off-canvas drawer:
   * when set, the toolbar shows a "Groups" button that opens it. */
  onOpenGroups?: () => void;
  /** The host page already pads the content (GroupDetailPage): drop the
   * table's own padding below lg. Desktop (lg+) is unchanged. */
  embedded?: boolean;
}

const CONTACTS: ContactFilter[] = ['recent', 'quiet', 'stale', 'never'];
const COMPLIANCES: ComplianceState[] = ['compliant', 'non_compliant', 'unknown'];
const CONFIGS: ConfigState[] = ['applied', 'pending', 'error'];
const OWNERSHIP_ORDER: Ownership[] = ['corporate', 'corporate_personal', 'personal'];

const oneOf = <T extends string>(value: string | undefined, allowed: readonly T[]): Set<T> =>
  (value && (allowed as readonly string[]).includes(value) ? new Set([value as T]) : new Set<T>());

function toggleIn<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value); else next.add(value);
  return next;
}

/** The commands a batch may send from the inventory: no parameter, never a guarded one (those go through the
 *  guard engine, from the device page). */
const BULK_COMMANDS = ['DeviceInformation', 'SecurityInfo', 'InstalledApplicationList', 'ProfileList', 'CertificateList', 'RestartDevice', 'ShutDownDevice'] as const;

export function DeviceTable({
  initialFilters, groupId: externalGroupId, onGroupChange, onOpenGroups, embedded = false,
}: DeviceTableProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  // docs/obli-mobile.md §4: phone < 768 ≤ tablet < 1024 ≤ desktop.
  const layout = useLayoutMode();
  const isPhone = layout === 'phone';
  const isDesktop = layout === 'desktop';
  // The 10px click-to-sort header labels are desktop-mouse only.
  const isCoarse = useIsCoarsePointer();
  const headerSortLabels = isDesktop && !isCoarse;
  // Compact toolbar (search + "Filters" sheet + "⋯" menu) on phones and short touch screens.
  const isShortTouch = useMediaQuery('(pointer: coarse) and (max-height: 520px)');
  const compactToolbar = isPhone || isShortTouch;
  const [filtersOpen, setFiltersOpen] = useState(false);
  // Anchors of the toolbar popovers (viewport-clamped, portal-rendered).
  const exportBtnRef = useRef<HTMLButtonElement>(null);
  const columnsBtnRef = useRef<HTMLButtonElement>(null);
  const tagsBtnRef = useRef<HTMLButtonElement>(null);
  const osBtnRef = useRef<HTMLButtonElement>(null);
  const batchBtnRef = useRef<HTMLButtonElement>(null);
  const { isAdmin, permissions } = useAuthStore();
  const caps = permissions?.tenantCapabilities ?? [];
  const canManageDevices = isAdmin() || caps.includes('devices.manage');
  const canManagePolicies = isAdmin() || caps.includes('mdm.policies.manage');
  const canExport = isAdmin() || caps.includes('reports');

  // ── Filters ───────────────────────────────────────────────────────────────
  // Kept in sessionStorage (per tab) so that coming back from a device page restores them. A link's filters
  // (initialFilters) seed the values when the session holds none, and replace them when the link changes.
  const [search, setSearch] = useSessionState<string>('obligarth:inventory:search', '');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [stateTab, setStateTab] = useSessionState<StateTab>('obligarth:inventory:state',
    () => (isStateTab(initialFilters?.state) ? initialFilters!.state as StateTab : 'managed'));
  const [contactFilters, setContactFilters] = useSessionState<Set<ContactFilter>>('obligarth:inventory:contact',
    () => oneOf(initialFilters?.contact, CONTACTS));
  const [complianceFilters, setComplianceFilters] = useSessionState<Set<ComplianceState>>('obligarth:inventory:compliance',
    () => oneOf(initialFilters?.compliance, COMPLIANCES));
  const [configFilters, setConfigFilters] = useSessionState<Set<ConfigState>>('obligarth:inventory:config',
    () => oneOf(initialFilters?.config, CONFIGS));
  const [platformFilters, setPlatformFilters] = useSessionState<Set<string>>('obligarth:inventory:platform',
    () => (initialFilters?.platform ? new Set([initialFilters.platform]) : new Set<string>()));
  const [ownershipFilters, setOwnershipFilters] = useSessionState<Set<string>>('obligarth:inventory:ownership',
    () => (initialFilters?.ownership ? new Set([initialFilters.ownership]) : new Set<string>()));
  const [supervisedOnly, setSupervisedOnly] = useSessionState<boolean>('obligarth:inventory:supervised', false);
  const [osBelow, setOsBelow] = useSessionState<string>('obligarth:inventory:osBelow', '');
  const [osBelowDraft, setOsBelowDraft] = useState(osBelow);
  const [osMenuOpen, setOsMenuOpen] = useState(false);
  const [tagFilters, setTagFilters] = useSessionState<Set<string>>('obligarth:inventory:tags', new Set<string>());
  const [tagsMenuOpen, setTagsMenuOpen] = useState(false);
  const [endUserId, setEndUserId] = useSessionState<number | undefined>('obligarth:inventory:endUser', initialFilters?.endUserId);
  const [tenantFilters, setTenantFilters] = useSessionState<Set<number>>('obligarth:inventory:tenants', new Set<number>());
  const [facets, setFacets] = useState<DeviceFacets | null>(null);

  // A link followed while the page is mounted (another dashboard card): its filters replace the current ones.
  const linkKey = JSON.stringify(initialFilters ?? {});
  const firstLink = useRef(linkKey);
  useEffect(() => {
    if (firstLink.current === linkKey) return;
    firstLink.current = linkKey;
    const f = initialFilters ?? {};
    setStateTab(isStateTab(f.state) ? f.state : 'managed');
    setContactFilters(oneOf(f.contact, CONTACTS));
    setComplianceFilters(oneOf(f.compliance, COMPLIANCES));
    setConfigFilters(oneOf(f.config, CONFIGS));
    setPlatformFilters(f.platform ? new Set([f.platform]) : new Set());
    setOwnershipFilters(f.ownership ? new Set([f.ownership]) : new Set());
    setEndUserId(f.endUserId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkKey]);

  // Optional line-2 fields, kept in localStorage.
  const [visibleFields, setVisibleFields] = useState<Set<string>>(() => loadVisibleFields());
  const [columnsMenuOpen, setColumnsMenuOpen] = useState(false);
  const toggleColumn = (key: string) => {
    setVisibleFields((prev) => {
      const next = toggleIn(prev, key);
      saveVisibleFields(next);
      return next;
    });
  };
  const resetColumns = () => {
    const def = defaultVisibleFields();
    saveVisibleFields(def);
    setVisibleFields(def);
  };

  const [sortBy, setSortBy] = useSessionState<SortField>('obligarth:inventory:sortBy', '');
  const [sortOrder, setSortOrder] = useSessionState<'asc' | 'desc'>('obligarth:inventory:sortOrder', 'asc');

  // ── Data ──────────────────────────────────────────────────────────────────
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [tree, setTree] = useState<DeviceGroupTreeNode[]>([]);
  const [collapsedGroupIds, setCollapsedGroupIds] = useState<Set<number>>(() => {
    try {
      const raw = localStorage.getItem('obligarth:deviceTableCollapsed');
      return new Set<number>(raw ? JSON.parse(raw) : []);
    } catch {
      return new Set<number>();
    }
  });
  const toggleGroupCollapsed = useCallback((gId: number) => {
    setCollapsedGroupIds((prev) => {
      const next = toggleIn(prev, gId);
      try { localStorage.setItem('obligarth:deviceTableCollapsed', JSON.stringify([...next])); } catch { /* session only */ }
      return next;
    });
  }, []);

  // ── Selection and batch actions ───────────────────────────────────────────
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  // Selection mode: a checkbox on every row and the whole row toggles the selection.
  const [selectionMode, setSelectionMode] = useState(false);
  const [changeGroupOpen, setChangeGroupOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [batchMenuOpen, setBatchMenuOpen] = useState(false);
  const [isBatchRunning, setIsBatchRunning] = useState(false);
  // Deleting records is a guarded action (audit-durci §10.2): records out of management only.
  const [guardedDelete, setGuardedDelete] = useState<number[] | null>(null);

  // Master tenant (global view): tenants fold by default, same key as the group panel.
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const isMaster = currentTenantId === MASTER_TENANT_ID;
  const visibleFieldsForMaster = useMemo(() => {
    if (!isMaster || visibleFields.has('tenant')) return visibleFields;
    const next = new Set(visibleFields);
    next.add('tenant');
    return next;
  }, [visibleFields, isMaster]);
  const [collapsedTenantIds, setCollapsedTenantIds] = useState<Set<number>>(() => {
    try {
      const raw = localStorage.getItem('obligarth:groupPanelCollapsedTenants');
      return new Set(raw ? (JSON.parse(raw) as number[]) : []);
    } catch { return new Set(); }
  });
  useEffect(() => {
    try { localStorage.setItem('obligarth:groupPanelCollapsedTenants', JSON.stringify([...collapsedTenantIds])); } catch { /* session only */ }
  }, [collapsedTenantIds]);

  // Debounced search
  const searchTimer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    searchTimer.current = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(searchTimer.current);
  }, [search]);

  const groupId = externalGroupId ?? null;
  // -1: the "Ungrouped" entry of the group panel.
  const ungroupedOnly = groupId === -1;

  // Tree view: the default landing shape (no search, no explicit sort, not "ungrouped"). On the master tenant
  // without a group nor a tenant chosen it would load every tenant's devices at once: flat pages there.
  const treeViewActive = !debouncedSearch.trim() && !ungroupedOnly && sortBy === ''
    && !(isMaster && groupId == null && tenantFilters.size === 0);
  // The server serves 1 000 devices per page at most.
  const TREE_MAX = 1000;
  const FLAT_PAGE_SIZE = 100;
  const loadedPagesRef = useRef(1);
  const [hasMore, setHasMore] = useState(false);
  const [appending, setAppending] = useState(false);

  /** The filters of the list, as the server takes them (also those of the export). */
  const listParams = useMemo((): DeviceListParams => ({
    q: debouncedSearch.trim() || undefined,
    enrollmentState: STATE_TABS[stateTab],
    contact: [...contactFilters],
    compliance: [...complianceFilters],
    config: [...configFilters],
    platform: [...platformFilters],
    ownership: [...ownershipFilters],
    supervised: supervisedOnly ? true : undefined,
    osBelow: osBelow || undefined,
    tags: [...tagFilters],
    endUserId,
    groupId: ungroupedOnly ? undefined : (groupId ?? undefined),
    includeSubgroups: ungroupedOnly ? undefined : (groupId ? true : undefined),
    ungrouped: ungroupedOnly ? true : undefined,
    tenantIds: isMaster && tenantFilters.size > 0 ? [...tenantFilters] : undefined,
    sortBy: sortBy || undefined,
    sortOrder: sortBy ? sortOrder : undefined,
  }), [debouncedSearch, stateTab, contactFilters, complianceFilters, configFilters, platformFilters, ownershipFilters,
    supervisedOnly, osBelow, tagFilters, endUserId, groupId, ungroupedOnly, isMaster, tenantFilters, sortBy, sortOrder]);

  const load = useCallback(async (reset: boolean) => {
    const pageToFetch = reset ? 1 : loadedPagesRef.current + 1;
    const size = treeViewActive ? TREE_MAX : FLAT_PAGE_SIZE;
    if (reset) { setIsLoading(true); loadedPagesRef.current = 1; } else setAppending(true);
    try {
      const result = await mdmApi.listDevices({ ...listParams, page: pageToFetch, pageSize: size });
      setDevices((prev) => (reset ? result.items : [...prev, ...result.items]));
      setTotal(result.total);
      loadedPagesRef.current = pageToFetch;
      setHasMore(!treeViewActive && pageToFetch * size < result.total);
    } catch (err) {
      toast.error(apiErrorMessage(err));
    } finally {
      if (reset) setIsLoading(false); else setAppending(false);
    }
  }, [listParams, treeViewActive]);

  // Refetch from scratch whenever a filter or the sort changes.
  useEffect(() => { void load(true); }, [load]);

  const loadFacets = useCallback(() => { mdmApi.facets().then(setFacets).catch(() => setFacets(null)); }, []);
  useEffect(() => {
    groupsApi.tree().then(setTree).catch(() => setTree([]));
    loadFacets();
  }, [loadFacets]);

  // Live: a change of the registry (enrollment, check-out, group, state) reloads the list, at most once every
  // two seconds (an inventory refresh of a fleet emits one event per device).
  const reloadTimer = useRef<ReturnType<typeof setTimeout>>();
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    const schedule = () => {
      if (reloadTimer.current) return;
      reloadTimer.current = setTimeout(() => {
        reloadTimer.current = undefined;
        void loadRef.current(true);
        loadFacets();
      }, 2000);
    };
    const offs = [SocketEvents.DEVICE_UPDATED, SocketEvents.DEVICE_DELETED].map((ev) => registerSocketListener(ev, schedule));
    return () => { offs.forEach((off) => off()); clearTimeout(reloadTimer.current); reloadTimer.current = undefined; };
  }, [loadFacets]);

  // Infinite scroll of the flat list.
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (treeViewActive || !hasMore || !sentinelRef.current) return;
    const node = sentinelRef.current;
    const io = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting && !appending && !isLoading) void load(false);
    }, { rootMargin: '200px' });
    io.observe(node);
    return () => io.disconnect();
  }, [treeViewActive, hasMore, appending, isLoading, load]);

  // A changed filter clears the selection: its devices are usually no longer in view.
  useEffect(() => { setSelectedIds(new Set()); }, [listParams]);

  const toggleSelect = (id: number) => setSelectedIds((prev) => toggleIn(prev, id));
  const toggleAll = () => {
    if (selectedIds.size === devices.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(devices.map((d) => d.id)));
  };
  const hasSelection = selectedIds.size > 0;
  const allChecked = devices.length > 0 && devices.every((d) => selectedIds.has(d.id));
  const someChecked = selectedIds.size > 0 && !allChecked;
  const selectedDevices = useMemo(() => devices.filter((d) => selectedIds.has(d.id)), [devices, selectedIds]);
  const clearSelection = () => setSelectedIds(new Set());

  const chipFilterCount = contactFilters.size + complianceFilters.size + configFilters.size + platformFilters.size
    + ownershipFilters.size + tagFilters.size + (supervisedOnly ? 1 : 0) + (osBelow ? 1 : 0) + (endUserId ? 1 : 0);
  const hasFilters = !!debouncedSearch || chipFilterCount > 0;
  const activeFilterCount = chipFilterCount + (stateTab !== 'managed' ? 1 : 0) + (isMaster ? tenantFilters.size : 0);
  const clearAllFilters = () => {
    setSearch('');
    setContactFilters(new Set()); setComplianceFilters(new Set()); setConfigFilters(new Set());
    setPlatformFilters(new Set()); setOwnershipFilters(new Set()); setTagFilters(new Set());
    setSupervisedOnly(false); setOsBelow(''); setOsBelowDraft(''); setEndUserId(undefined);
  };

  const handleSort = (field: SortField) => {
    if (field === '') return;
    if (sortBy === field) {
      // asc → desc → no sort (back to the tree by group).
      if (sortOrder === 'asc') setSortOrder('desc');
      else { setSortBy(''); setSortOrder('asc'); }
    } else {
      setSortBy(field);
      setSortOrder(defaultSortOrder(field));
    }
  };

  // ── Export ────────────────────────────────────────────────────────────────
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const handleExport = async (format: 'csv' | 'xlsx' | 'pdf') => {
    setExportMenuOpen(false);
    setIsExporting(true);
    try {
      const { blob, filename } = await mdmApi.exportDevices(format, listParams);
      // Android shell → native Downloads; browser → anchor download (docs/obli-mobile.md §3).
      if (!(await saveBlob(blob, filename))) toast.error(t('common.error'));
    } catch (err) {
      toast.error(apiErrorMessage(err));
    } finally {
      setIsExporting(false);
    }
  };

  // ── Toolbar building blocks ───────────────────────────────────────────────
  const countOf = (list: Array<{ value: string; count: number }> | undefined, value: string): number =>
    list?.find((x) => x.value === value)?.count ?? 0;
  const stateCount = (tab: StateTab): number => {
    const states = STATE_TABS[tab];
    const list = facets?.enrollmentState ?? [];
    return (states ? list.filter((x) => (states as string[]).includes(x.value)) : list).reduce((n, x) => n + x.count, 0);
  };
  const chipCls = (active: boolean) => clsx('flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full transition-colors coarse:py-2',
    active ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary');
  const divider = <div className="w-px h-4 bg-border mx-1" />;

  // The enrollment states: the devices under management by default; the records out of management apart.
  const stateTabs = (
    <div className="flex items-center gap-2 flex-wrap mb-3">
      {(['managed', 'enrolled', 'enrolling', 'unenrolled', 'all'] as StateTab[]).map((key) => (
        <button key={key} onClick={() => setStateTab(key)}
          className={clsx('px-3 py-1.5 text-sm font-medium rounded-lg transition-colors coarse:min-h-10',
            stateTab === key ? 'bg-accent text-white' : 'bg-bg-tertiary text-text-muted hover:bg-bg-active hover:text-text-primary')}>
          {key === 'managed' ? (t('devices.state.managed') || 'Under management')
            : key === 'all' ? (t('devices.filters.all') || 'All')
              : key === 'enrolling' ? (t('devices.state.enrolling') || 'Enrolling')
                : enrollmentLabel(t, key)}
          {facets && <span className="opacity-60"> ({stateCount(key)})</span>}
        </button>
      ))}
    </div>
  );

  // Master only: narrow the global view to some tenants.
  const tenantChips = isMaster ? (() => {
    const tenants = new Map<number, string>();
    for (const d of devices) if (d.tenantName) tenants.set(d.tenantId, d.tenantName);
    for (const g of tree) if (g.tenantName) tenants.set(g.tenantId, g.tenantName);
    if (tenants.size <= 1) return null;
    const ordered = [...tenants.entries()].sort(([aId, aName], [bId, bName]) => {
      if (aId === MASTER_TENANT_ID) return -1;
      if (bId === MASTER_TENANT_ID) return 1;
      return aName.localeCompare(bName);
    });
    return (
      <div className="flex items-center gap-1.5 flex-wrap mb-2">
        <span className="text-[10px] uppercase tracking-wider text-text-muted mr-1">
          <Building2 size={10} className="inline mr-1" />{t('devices.filters.tenant', 'Tenant')}
        </span>
        {ordered.map(([id, name]) => (
          <button key={id} onClick={() => setTenantFilters((prev) => toggleIn(prev, id))} className={chipCls(tenantFilters.has(id))}>
            <Building2 size={10} className="inline" />
            {id === MASTER_TENANT_ID ? `${name} ${t('devices.filters.masterSuffix', '(master)')}` : name}
          </button>
        ))}
        {tenantFilters.size > 0 && (
          <button onClick={() => setTenantFilters(new Set())}
            className="text-[10px] text-accent hover:underline ml-1 coarse:text-xs coarse:min-h-10 coarse:px-2">
            {t('common.clear', 'Clear')}
          </button>
        )}
      </div>
    );
  })() : null;

  const platformChips = (facets?.platform ?? []).filter((p) => p.count > 0);
  const filterChips = (
    <div className="flex items-center gap-1.5 flex-wrap">
      {CONTACTS.map((c) => (
        <button key={c} onClick={() => setContactFilters((prev) => toggleIn(prev, c))} className={chipCls(contactFilters.has(c))}>
          <div className={clsx('w-2 h-2 rounded-full', toneDot(CONTACT_TONE[c]))} />
          {contactLabel(t, c)}
        </button>
      ))}
      {divider}
      {COMPLIANCES.map((c) => (
        <button key={c} onClick={() => setComplianceFilters((prev) => toggleIn(prev, c))} className={chipCls(complianceFilters.has(c))}>
          <div className={clsx('w-2 h-2 rounded-full', toneDot(COMPLIANCE_TONE[c]))} />
          {complianceLabel(t, c)}
          {facets && <span className="text-text-muted/70">{countOf(facets.complianceState, c)}</span>}
        </button>
      ))}
      {divider}
      {CONFIGS.map((c) => (
        <button key={c} onClick={() => setConfigFilters((prev) => toggleIn(prev, c))} className={chipCls(configFilters.has(c))}>
          <div className={clsx('w-2 h-2 rounded-full', toneDot(CONFIG_TONE[c]))} />
          {configLabel(t, c)}
          {facets && <span className="text-text-muted/70">{countOf(facets.configState, c)}</span>}
        </button>
      ))}
      {platformChips.length > 0 && divider}
      {platformChips.map((p) => (
        <button key={p.value} onClick={() => setPlatformFilters((prev) => toggleIn(prev, p.value))} className={chipCls(platformFilters.has(p.value))}>
          {platformLabel(p.value)} <span className="text-text-muted/70">{p.count}</span>
        </button>
      ))}
      {divider}
      {OWNERSHIP_ORDER.filter((o) => !facets || countOf(facets.ownership, o) > 0 || ownershipFilters.has(o)).map((o) => (
        <button key={o} onClick={() => setOwnershipFilters((prev) => toggleIn(prev, o))} className={chipCls(ownershipFilters.has(o))}>
          {ownershipLabel(t, o)}
          {facets && <span className="text-text-muted/70">{countOf(facets.ownership, o)}</span>}
        </button>
      ))}
      <button onClick={() => setSupervisedOnly(!supervisedOnly)} className={chipCls(supervisedOnly)}>
        <ShieldCheck className="w-3 h-3" />
        {t('devices.filters.supervised') || 'Supervised'}
      </button>
      <button ref={osBtnRef} onClick={() => { setOsBelowDraft(osBelow); setOsMenuOpen((v) => !v); }} className={chipCls(!!osBelow)}
        title={t('devices.filters.osBelowHint') || 'Devices whose operating system is older than a version'}>
        {osBelow ? (t('devices.filters.osBelowValue', { version: osBelow }) || `OS below ${osBelow}`) : (t('devices.filters.osBelow') || 'OS below…')}
      </button>
      <button ref={tagsBtnRef} onClick={() => setTagsMenuOpen((v) => !v)} className={chipCls(tagFilters.size > 0)}
        title={t('devices.filters.tags', 'Filter by tag')}>
        <Tag className="w-3 h-3" />
        {t('devices.filters.tagsLabel', 'Tags')}
        {tagFilters.size > 0 && <span className="text-[10px] text-accent/80">{tagFilters.size}</span>}
      </button>
      {endUserId !== undefined && (
        <button onClick={() => setEndUserId(undefined)} className={chipCls(true)}>
          {t('devices.filters.endUser') || 'One end user'} <X className="w-3 h-3" />
        </button>
      )}
      <span className="ml-auto text-xs text-text-muted">{t('devices.list.count', '{{count}} devices', { count: total, defaultValue_one: '{{count}} device' })}</span>
    </div>
  );

  const popRowCls = 'flex items-center gap-2 px-3 py-1.5 text-sm text-text-primary hover:bg-bg-tertiary cursor-pointer coarse:py-2.5';
  const popHeadCls = 'text-[11px] font-mono uppercase tracking-wider text-text-muted';
  const popLinkCls = 'text-[11px] text-accent hover:underline coarse:text-xs coarse:min-h-10 coarse:px-2';
  const exportContent = (
    <>
      <button onClick={() => handleExport('csv')} className="w-full text-left px-3 py-2 text-sm text-text-primary hover:bg-bg-tertiary coarse:py-3">CSV</button>
      <button onClick={() => handleExport('xlsx')} className="w-full text-left px-3 py-2 text-sm text-text-primary hover:bg-bg-tertiary coarse:py-3">Excel (xlsx)</button>
      <button onClick={() => handleExport('pdf')} className="w-full text-left px-3 py-2 text-sm text-text-primary hover:bg-bg-tertiary coarse:py-3">PDF</button>
    </>
  );
  const columnsContent = (
    <>
      <div className="px-3 py-2 flex items-center justify-between shrink-0">
        <span className={popHeadCls}>{t('devices.columns.title', 'Visible columns')}</span>
        <button onClick={resetColumns} className={popLinkCls}>{t('common.reset', 'Reset')}</button>
      </div>
      <div className="min-h-0 overflow-y-auto">
        {LINE2_FIELDS.map((f) => (
          <label key={f.key} className={popRowCls}>
            <input type="checkbox" checked={visibleFields.has(f.key)} onChange={() => toggleColumn(f.key)} className="accent-accent" />
            <span>{t(`devices.columns.${f.key}`) || f.label}</span>
          </label>
        ))}
      </div>
    </>
  );
  const tagFacets = facets?.tag ?? [];
  const tagsContent = (
    <>
      <div className="px-3 py-2 flex items-center justify-between shrink-0">
        <span className={popHeadCls}>{t('devices.filters.tagsTitle', 'Applied tags')}</span>
        {tagFilters.size > 0 && <button onClick={() => setTagFilters(new Set())} className={popLinkCls}>{t('common.clear', 'Clear')}</button>}
      </div>
      <div className="min-h-0 overflow-y-auto">
        {tagFacets.length === 0 ? (
          <div className="px-3 py-3 text-[12px] text-text-muted italic">{t('devices.filters.noTags', 'No tags in the fleet')}</div>
        ) : tagFacets.map((f) => (
          <label key={f.value} className={popRowCls}>
            <input type="checkbox" checked={tagFilters.has(f.value)} onChange={() => setTagFilters((prev) => toggleIn(prev, f.value))} className="accent-accent" />
            <span className="flex-1 truncate">{f.value}</span>
            <span className="text-[10px] text-text-muted">{f.count}</span>
          </label>
        ))}
      </div>
    </>
  );
  const osVersions = useMemo(() => {
    const seen = new Map<string, number>();
    for (const v of facets?.osVersion ?? []) {
      if (platformFilters.size > 0 && !platformFilters.has(v.platform)) continue;
      seen.set(v.value, (seen.get(v.value) ?? 0) + v.count);
    }
    return [...seen.entries()].sort((a, b) => b[0].localeCompare(a[0], undefined, { numeric: true })).slice(0, 12);
  }, [facets, platformFilters]);
  const applyOsBelow = (v: string) => { setOsBelow(v.trim()); setOsMenuOpen(false); };
  const osContent = (
    <div className="p-3 space-y-2">
      <span className={popHeadCls}>{t('devices.filters.osBelowTitle') || 'Operating system older than'}</span>
      <form onSubmit={(e) => { e.preventDefault(); if (/^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$/.test(osBelowDraft.trim()) || !osBelowDraft.trim()) applyOsBelow(osBelowDraft); }} className="flex gap-2">
        <input value={osBelowDraft} onChange={(e) => setOsBelowDraft(e.target.value)} placeholder="17.5" inputMode="decimal"
          className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 text-sm text-text-primary" />
        <Button size="sm" type="submit" disabled={!!osBelowDraft.trim() && !/^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$/.test(osBelowDraft.trim())}>{t('common.confirm') || 'Confirm'}</Button>
      </form>
      {osVersions.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {osVersions.map(([v, n]) => (
            <button key={v} type="button" onClick={() => applyOsBelow(v)} className="px-1.5 py-0.5 rounded bg-bg-tertiary text-xs text-text-secondary hover:text-text-primary coarse:py-1.5">
              {v} <span className="text-text-muted">{n}</span>
            </button>
          ))}
        </div>
      )}
      {osBelow && <button type="button" onClick={() => { setOsBelowDraft(''); applyOsBelow(''); }} className={popLinkCls}>{t('common.clear', 'Clear')}</button>}
    </div>
  );

  // Batch actions: one list, rendered in the popover (desktop) or a bottom sheet (phone).
  const closeBatchMenuThen = (fn: () => void) => () => { setBatchMenuOpen(false); fn(); };
  const batchItems: Array<{ key: string; icon: ReactNode; label: string; onClick: () => void; danger?: boolean; show?: boolean }> = [
    { key: 'change_group', show: canManageDevices, icon: <FolderOpen className="w-3.5 h-3.5 text-accent" />, label: t('devices.batch.changeGroup', 'Change group'), onClick: closeBatchMenuThen(() => setChangeGroupOpen(true)) },
    {
      key: 'assign_policy', show: canManagePolicies, icon: <ScrollText className="w-3.5 h-3.5 text-accent" />, label: t('devices.batch.assignPolicy') || 'Assign a policy',
      onClick: closeBatchMenuThen(() => {
        if (selectedIds.size > 100) { toast.error(t('devices.batch.assignTooMany') || 'A policy is assigned to 100 devices at most at a time: assign it to their group instead.'); return; }
        setAssignOpen(true);
      }),
    },
    { key: 'command', show: canManageDevices, icon: <TerminalSquare className="w-3.5 h-3.5 text-accent" />, label: t('devices.batch.command') || 'Send a command', onClick: closeBatchMenuThen(() => setCommandOpen(true)) },
    {
      key: 'delete', show: canManageDevices, danger: true, icon: <Trash2 className="w-3.5 h-3.5" />, label: t('devices.batch.deleteRecords') || 'Delete the records',
      onClick: closeBatchMenuThen(() => {
        // A device under management leaves management first (409 deviceUnderManagement on the server).
        if (selectedDevices.some((d) => d.enrollmentState !== 'unenrolled')) {
          toast.error(t('errors.deviceUnderManagement') || 'A device under management leaves management before its record is deleted.', { duration: 7000 });
          return;
        }
        setGuardedDelete(Array.from(selectedIds));
      }),
    },
  ];
  const batchContent = (
    <>
      {batchItems.filter((i) => i.show !== false).map((i) => (
        <button key={i.key} onClick={i.onClick}
          className={clsx('w-full flex items-center gap-2 px-3 py-2 text-xs text-left coarse:py-3 coarse:text-sm',
            i.danger ? 'text-red-400 hover:bg-red-400/10' : 'text-text-primary hover:bg-bg-tertiary')}>
          {i.icon}
          <span className="min-w-0 flex-1">{i.label}</span>
        </button>
      ))}
    </>
  );

  // Phone overflow menu (export / columns / refresh / clear).
  const phoneMenuItems = [
    { key: 'csv', icon: <Download className="w-4 h-4" />, label: t('devices.export.csv', 'Export CSV'), onClick: () => handleExport('csv'), disabled: isExporting, hidden: !canExport },
    { key: 'xlsx', icon: <Download className="w-4 h-4" />, label: t('devices.export.xlsx', 'Export Excel (xlsx)'), onClick: () => handleExport('xlsx'), disabled: isExporting, hidden: !canExport },
    { key: 'pdf', icon: <Download className="w-4 h-4" />, label: t('devices.export.pdf', 'Export PDF'), onClick: () => handleExport('pdf'), disabled: isExporting, hidden: !canExport },
    { key: 'columns', icon: <Columns3 className="w-4 h-4" />, label: t('devices.columns.button', 'Columns'), onClick: () => setColumnsMenuOpen(true), separator: true },
    { key: 'refresh', icon: <RefreshCw className="w-4 h-4" />, label: t('common.refresh', 'Refresh'), onClick: () => { void load(true); loadFacets(); } },
    { key: 'clear', icon: <X className="w-4 h-4" />, label: t('devices.filters.clearAll', 'Clear filters'), onClick: clearAllFilters, hidden: !hasFilters },
  ];

  // Name of the scope shown on the "Groups" drawer button.
  const scopeLabel = (() => {
    if (groupId === -1) return t('groupPanel.ungrouped', 'Ungrouped');
    if (groupId == null) return t('groupPanel.allDevices');
    const find = (nodes: DeviceGroupTreeNode[]): string | null => {
      for (const n of nodes) {
        if (n.id === groupId) return n.name;
        const f = find(n.children);
        if (f) return f;
      }
      return null;
    };
    return anonymize(find(tree)) || t('groupPanel.title');
  })();
  const groupsButton = onOpenGroups ? (
    <button type="button" onClick={onOpenGroups}
      className="flex min-w-0 items-center gap-1.5 px-2.5 py-2.5 text-xs rounded-lg bg-bg-tertiary text-text-primary hover:bg-bg-active transition-colors coarse:min-h-10"
      aria-label={`${t('groupPanel.title')}: ${scopeLabel}`}>
      <FolderTree className="w-3.5 h-3.5 shrink-0 text-accent" />
      <span className="truncate">{scopeLabel}</span>
    </button>
  ) : null;

  const selectToggle = (
    <button
      onClick={() => {
        const next = !selectionMode;
        setSelectionMode(next);
        if (!next) clearSelection();
      }}
      className={clsx('flex items-center gap-1.5 px-2.5 py-2.5 text-xs rounded-lg transition-colors coarse:min-h-10',
        selectionMode ? 'bg-accent text-white' : 'bg-bg-tertiary text-text-muted hover:bg-bg-active hover:text-text-primary')}
      title={selectionMode ? t('devices.selection.exit', 'Exit selection mode') : t('devices.selection.enter', 'Enter selection mode — click any row to select')}
      aria-pressed={selectionMode}
    >
      {selectionMode ? <Check className="w-3.5 h-3.5" /> : <MousePointerClick className="w-3.5 h-3.5" />}
      <span className={compactToolbar ? undefined : 'hidden sm:inline'}>{selectionMode ? t('devices.selection.active', 'Selecting') : t('devices.selection.select', 'Select')}</span>
    </button>
  );

  const SORT_OPTIONS: Array<{ field: Exclude<SortField, ''>; label: string }> = [
    { field: 'name', label: t('sort.name', 'Name') },
    { field: 'state', label: t('sort.state') || 'Enrollment' },
    { field: 'lastCheckin', label: t('sort.lastCheckin') || 'Last contact' },
    { field: 'compliance', label: t('sort.compliance') || 'Compliance' },
    { field: 'platform', label: t('sort.platform') || 'Platform' },
    { field: 'os', label: t('sort.os', 'OS') },
    { field: 'model', label: t('sort.model') || 'Model' },
    { field: 'ownership', label: t('sort.ownership') || 'Ownership' },
    { field: 'group', label: t('sort.group', 'Group') },
    { field: 'enrolledAt', label: t('sort.enrolledAt') || 'Enrolled' },
  ];

  const shownDevices = isMaster && tenantFilters.size > 0 ? devices.filter((d) => tenantFilters.has(d.tenantId)) : devices;
  const shownTree = isMaster && tenantFilters.size > 0 ? tree.filter((g) => tenantFilters.has(g.tenantId)) : tree;

  return (
    <div className={clsx('flex flex-col space-y-3', embedded ? 'lg:p-6' : 'p-3 sm:p-4 lg:p-6')}>
      {/* Sticky toolbar: opaque background, pinned at the top of the scrolling pane. Phone: only the search and a
          compact action row stay sticky; the chips move to the "Filters" sheet. */}
      <div
        className={clsx(
          'sticky top-0 z-20 pb-3 bg-bg-primary space-y-3',
          embedded
            ? 'lg:-mx-6 lg:-mt-6 lg:px-6 lg:pt-6'
            : '-mx-3 -mt-3 px-3 pt-3 sm:-mx-4 sm:-mt-4 sm:px-4 sm:pt-4 lg:-mx-6 lg:-mt-6 lg:px-6 lg:pt-6',
        )}
      >
        {!compactToolbar && stateTabs}

        <div className={clsx('space-y-2', !compactToolbar && 'mb-3')}>
          {compactToolbar ? (
            <>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
                <input type="search" value={search} onChange={(e) => setSearch(e.target.value)}
                  placeholder={t('devices.filters.search')}
                  autoCapitalize="off" autoCorrect="off" spellCheck={false} enterKeyHint="search"
                  className="w-full pl-9 pr-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
              </div>
              <div className="flex items-center gap-2">
                {groupsButton
                  ? <div className="min-w-0 flex-1 [&>button]:w-full">{groupsButton}</div>
                  : <div className="flex-1" />}
                <button type="button" onClick={() => setFiltersOpen(true)}
                  className={clsx('flex shrink-0 items-center gap-1.5 px-2.5 py-2.5 text-xs rounded-lg transition-colors coarse:min-h-10',
                    activeFilterCount > 0 ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:bg-bg-active hover:text-text-primary')}>
                  <SlidersHorizontal className="w-3.5 h-3.5" />
                  {t('devices.filters.button', 'Filters')}
                  {activeFilterCount > 0 && <span className="font-semibold">({activeFilterCount})</span>}
                </button>
                <span className="shrink-0">{selectToggle}</span>
                <ActionMenu
                  items={phoneMenuItems}
                  trigger={(p) => (
                    <button {...p} type="button" aria-label={t('ui.moreActions', 'More actions')}
                      className="flex shrink-0 items-center justify-center rounded-lg bg-bg-tertiary p-2.5 text-text-muted hover:bg-bg-active hover:text-text-primary transition-colors coarse:min-h-10 coarse:min-w-10">
                      {isExporting || isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <MoreHorizontal className="w-4 h-4" />}
                    </button>
                  )}
                />
              </div>
            </>
          ) : (
            <div className="flex items-center gap-2">
              {groupsButton && <div className="shrink-0 max-w-[40%]">{groupsButton}</div>}
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
                <input type="text" value={search} onChange={(e) => setSearch(e.target.value)}
                  placeholder={t('devices.filters.search')}
                  title={t('devices.filters.searchHint', 'Searches the label, the name, the serial number, the model, the end user, the tags and the UUID')}
                  autoCapitalize="off" autoCorrect="off" spellCheck={false}
                  className="w-full pl-9 pr-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
              </div>
              {hasFilters && (
                <button onClick={clearAllFilters} aria-label={t('devices.filters.clearAll', 'Clear filters')}
                  className="p-2 text-text-muted hover:text-text-primary coarse:min-h-10 coarse:min-w-10"><X className="w-3.5 h-3.5" /></button>
              )}
              {canExport && (
                <button ref={exportBtnRef} onClick={() => setExportMenuOpen((v) => !v)} disabled={isExporting}
                  className="p-2 text-text-muted hover:text-text-primary rounded-lg hover:bg-bg-tertiary transition-colors disabled:opacity-50 coarse:min-h-10 coarse:min-w-10"
                  title={t('devices.export.title', 'Export filtered devices')} aria-label={t('devices.export.title', 'Export filtered devices')}>
                  <Download className={clsx('w-4 h-4', isExporting && 'animate-pulse')} />
                </button>
              )}
              {selectToggle}
              <button ref={columnsBtnRef} onClick={() => setColumnsMenuOpen((v) => !v)}
                className={clsx('flex items-center gap-1.5 px-2.5 py-2.5 text-xs rounded-lg transition-colors coarse:min-h-10',
                  columnsMenuOpen ? 'bg-accent text-white' : 'bg-bg-tertiary text-text-muted hover:bg-bg-active hover:text-text-primary')}
                title={t('devices.columns.title', 'Visible columns')}>
                <Columns3 className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{t('devices.columns.button', 'Columns')}</span>
              </button>
              <button onClick={() => { void load(true); loadFacets(); }} aria-label={t('common.refresh', 'Refresh')}
                className="p-2 text-text-muted hover:text-text-primary rounded-lg hover:bg-bg-tertiary transition-colors coarse:min-h-10 coarse:min-w-10">
                <RefreshCw className={clsx('w-4 h-4', isLoading && 'animate-spin')} />
              </button>
            </div>
          )}

          {!compactToolbar && tenantChips}
          {!compactToolbar && filterChips}
        </div>

        {/* Batch action bar */}
        {hasSelection && (
          <div className="flex items-center gap-3 p-2.5 mb-3 bg-accent/10 rounded-lg max-md:flex-wrap max-md:gap-2">
            <StyledCheckbox checked={allChecked} indeterminate={someChecked} onChange={toggleAll} />
            <span className="text-sm font-medium text-text-primary">{t('devices.batch.selected', { count: selectedIds.size })}</span>
            <div className="relative ml-auto">
              <button ref={batchBtnRef} onClick={() => setBatchMenuOpen(!batchMenuOpen)} disabled={isBatchRunning || batchItems.every((i) => i.show === false)}
                aria-haspopup="menu" aria-expanded={batchMenuOpen}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-accent text-white rounded-lg hover:bg-accent/80 disabled:opacity-50 transition-colors coarse:min-h-10">
                {isBatchRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <MoreHorizontal className="w-3.5 h-3.5" />}
                {t('devices.batch.actions')}
              </button>
            </div>
            <button onClick={clearSelection} aria-label={t('devices.batch.clearSelection', 'Clear selection')}
              className="text-xs text-text-muted hover:text-text-primary flex items-center gap-1 coarse:min-h-10 coarse:min-w-10 coarse:justify-center">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>{/* /sticky toolbar */}

      {/* Toolbar popovers: portal-rendered, clamped to the viewport, bottom sheets on phone. */}
      <ToolbarPopover open={exportMenuOpen && !compactToolbar} onClose={() => setExportMenuOpen(false)} anchorRef={exportBtnRef} align="end"
        sheetLabel={t('devices.export.title', 'Export filtered devices')}
        className="w-32 bg-bg-secondary rounded-lg shadow-xl overflow-hidden overflow-y-auto">
        {exportContent}
      </ToolbarPopover>
      <ToolbarPopover open={columnsMenuOpen} onClose={() => setColumnsMenuOpen(false)} anchorRef={columnsBtnRef} align="end" sheet={compactToolbar}
        sheetLabel={t('devices.columns.title', 'Visible columns')}
        className="w-56 flex flex-col bg-bg-secondary rounded-lg shadow-xl overflow-hidden">
        {columnsContent}
      </ToolbarPopover>
      <ToolbarPopover open={tagsMenuOpen} onClose={() => setTagsMenuOpen(false)} anchorRef={tagsBtnRef} align="start" maxHeight={320} sheet={compactToolbar}
        sheetLabel={t('devices.filters.tagsTitle', 'Applied tags')}
        className="w-64 flex flex-col bg-bg-secondary rounded-lg shadow-xl overflow-hidden">
        {tagsContent}
      </ToolbarPopover>
      <ToolbarPopover open={osMenuOpen} onClose={() => setOsMenuOpen(false)} anchorRef={osBtnRef} align="start" sheet={compactToolbar}
        sheetLabel={t('devices.filters.osBelowTitle') || 'Operating system older than'}
        className="w-64 bg-bg-secondary rounded-lg shadow-xl overflow-hidden">
        {osContent}
      </ToolbarPopover>
      <ToolbarPopover open={batchMenuOpen && hasSelection} onClose={() => setBatchMenuOpen(false)} anchorRef={batchBtnRef} align="end" sheet={compactToolbar}
        sheetLabel={t('devices.batch.actions')}
        className="bg-bg-secondary rounded-lg shadow-lg overflow-hidden overflow-y-auto min-w-[200px]">
        {batchContent}
      </ToolbarPopover>

      {/* Phone / short touch screen: filter chips in a bottom sheet. */}
      {compactToolbar && (
        <Drawer
          open={filtersOpen}
          onClose={() => setFiltersOpen(false)}
          side="bottom"
          size="lg"
          title={t('devices.filters.button', 'Filters')}
          headerExtra={activeFilterCount > 0 ? (
            <button type="button" onClick={() => { clearAllFilters(); setTenantFilters(new Set()); setStateTab('managed'); }}
              className="text-xs text-accent hover:underline min-h-10 px-2">
              {t('devices.filters.clearAll', 'Clear filters')}
            </button>
          ) : undefined}
          bodyClassName="px-4 pb-4 pt-1 space-y-3"
          footer={(
            <button type="button" onClick={() => setFiltersOpen(false)} className="w-full min-h-11 rounded-lg bg-accent text-sm font-medium text-white">
              {t('devices.filters.showResults', 'Show {{count}} devices', { count: total, defaultValue_one: 'Show {{count}} device' })}
            </button>
          )}
        >
          {stateTabs}
          {tenantChips}
          {filterChips}
        </Drawer>
      )}

      {/* Device list */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <RefreshCw className="w-5 h-5 animate-spin text-text-muted" />
        </div>
      ) : devices.length === 0 ? (
        <div className="p-12 text-center text-text-muted bg-bg-secondary rounded-xl">
          <p className="font-medium text-text-primary mb-1">{t('devices.noDevices')}</p>
          {(hasFilters || stateTab !== 'managed') && <p className="text-sm">{t('devices.noDevicesFiltered') || 'No device matches these filters.'}</p>}
        </div>
      ) : (
        <div className="bg-bg-secondary rounded-xl overflow-hidden">
          {headerSortLabels ? (
            /* Not a true table (a device is a two-line row): the labels sit near what they sort. */
            <div className="flex items-center gap-3 px-4 py-2 bg-bg-tertiary/50 text-[10px] uppercase tracking-wider font-medium text-text-muted">
              {(isAdmin() || selectionMode) && <StyledCheckbox checked={allChecked} indeterminate={someChecked} onChange={toggleAll} />}
              <SortLabel label={t('sort.name', 'Name')} field="name" sortBy={sortBy} sortOrder={sortOrder} onClick={handleSort} />
              <SortLabel label={t('sort.platform') || 'Platform'} field="platform" sortBy={sortBy} sortOrder={sortOrder} onClick={handleSort} />
              <SortLabel label={t('sort.group', 'Group')} field="group" sortBy={sortBy} sortOrder={sortOrder} onClick={handleSort} />
              <div className="flex-1" />
              <SortLabel label={t('sort.compliance') || 'Compliance'} field="compliance" sortBy={sortBy} sortOrder={sortOrder} onClick={handleSort} />
              <SortLabel label={t('sort.state') || 'Enrollment'} field="state" sortBy={sortBy} sortOrder={sortOrder} onClick={handleSort} className="w-24 justify-center" />
              <SortLabel label={t('sort.lastCheckin') || 'Last contact'} field="lastCheckin" sortBy={sortBy} sortOrder={sortOrder} onClick={handleSort} className="w-24 justify-end" />
              <span className="w-6" />
              {selectionMode && <span className="ml-2 text-accent">{t('devices.selection.modeLabel', 'Selection mode')}</span>}
            </div>
          ) : (
            /* Phone / tablet: a native select lists every sort field, with a direction toggle. */
            <div className="flex items-center gap-2 px-3 py-2 bg-bg-tertiary/50 text-xs text-text-muted">
              {(isAdmin() || selectionMode) && <StyledCheckbox checked={allChecked} indeterminate={someChecked} onChange={toggleAll} className="mr-1" />}
              <label className="flex min-w-0 flex-1 items-center gap-2">
                <span className="shrink-0 text-[10px] uppercase tracking-wider font-medium">{t('devices.sort.label', 'Sort')}</span>
                <select
                  value={sortBy}
                  onChange={(e) => {
                    const f = e.target.value as SortField;
                    if (!f) { setSortBy(''); setSortOrder('asc'); return; }
                    setSortBy(f);
                    setSortOrder(defaultSortOrder(f));
                  }}
                  className="min-w-0 flex-1 rounded-md bg-bg-secondary px-2 py-1.5 text-sm text-text-primary focus:outline-none coarse:min-h-10"
                >
                  <option value="">{t('devices.sort.default', 'Default (by group)')}</option>
                  {SORT_OPTIONS.map((o) => <option key={o.field} value={o.field}>{o.label}</option>)}
                </select>
              </label>
              <IconButton
                label={sortOrder === 'asc' ? t('devices.sort.ascending', 'Ascending') : t('devices.sort.descending', 'Descending')}
                icon={sortOrder === 'asc' ? <SortAsc className="w-4 h-4" /> : <SortDesc className="w-4 h-4" />}
                disabled={sortBy === ''}
                active={sortBy !== ''}
                variant="ghost"
                onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              />
              {selectionMode && (
                <span className="shrink-0 text-[10px] uppercase tracking-wider text-accent">{t('devices.selection.modeLabel', 'Selection mode')}</span>
              )}
            </div>
          )}
          <div>
            <DeviceListBody
              devices={shownDevices}
              tree={shownTree}
              groupId={groupId}
              flat={!treeViewActive}
              collapsedGroupIds={collapsedGroupIds}
              onToggleGroup={toggleGroupCollapsed}
              selectedIds={selectedIds}
              toggleSelect={toggleSelect}
              onNavigate={(id) => navigate(`/devices/${id}`)}
              onGroupChange={onGroupChange}
              selectionMode={selectionMode}
              visibleFields={visibleFieldsForMaster}
              isMaster={isMaster}
              collapsedTenantIds={collapsedTenantIds}
              onToggleTenant={(id) => setCollapsedTenantIds((prev) => toggleIn(prev, id))}
              indentStep={isPhone ? 8 : 16}
            />
          </div>
        </div>
      )}

      {/* Footer: total, and a "Load more" fallback of the infinite scroll. */}
      {total > 0 && (
        <div className="flex items-center justify-between mt-3 text-xs text-text-muted max-md:flex-wrap max-md:gap-2">
          <span>
            {treeViewActive
              ? t('devices.list.count', '{{count}} devices', { count: total, defaultValue_one: '{{count}} device' })
              : `${devices.length} / ${total}`}
          </span>
          {treeViewActive && total > TREE_MAX && (
            <span className="text-amber-400">
              {t('devices.pagination.treeCapped', { shown: TREE_MAX, total }) || `Showing first ${TREE_MAX} of ${total} — use search or pick a sub-group to narrow.`}
            </span>
          )}
          {!treeViewActive && hasMore && (
            <button onClick={() => load(false)} disabled={appending}
              className="px-2 py-1 rounded hover:bg-bg-tertiary disabled:opacity-50 transition-colors coarse:min-h-10 coarse:px-3">
              {appending ? (t('common.loading') || 'Loading…') : (t('devices.pagination.loadMore') || 'Load more')}
            </button>
          )}
        </div>
      )}
      {!treeViewActive && hasMore && <div ref={sentinelRef} className="h-px" aria-hidden />}

      {/* ── Batch: change group ──────────────────────────────────────── */}
      {changeGroupOpen && (
        <ChangeGroupModal
          count={selectedIds.size}
          onCancel={() => setChangeGroupOpen(false)}
          onConfirm={async (newGroupId) => {
            setChangeGroupOpen(false);
            setIsBatchRunning(true);
            try {
              const r = await mdmApi.batchSetGroup(Array.from(selectedIds), newGroupId);
              if (r === null) toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
              else toast.success(t('devices.batch.groupChanged', { count: r.changed, defaultValue: `Moved ${r.changed} device${r.changed > 1 ? 's' : ''}` }));
              clearSelection();
              await load(true);
            } catch (err) {
              if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
            } finally {
              setIsBatchRunning(false);
            }
          }}
        />
      )}

      {/* ── Batch: assign a policy (through the impact preview) ───────── */}
      <AssignmentCreateDialog
        open={assignOpen}
        onClose={() => setAssignOpen(false)}
        targets={selectedDevices.map((d) => ({ scope: 'device' as const, id: d.id, name: d.label }))}
        onDone={() => { clearSelection(); void load(true); }}
      />

      {/* ── Batch: a command of the integration ───────────────────────── */}
      <BulkCommandModal
        open={commandOpen}
        onClose={() => setCommandOpen(false)}
        deviceIds={Array.from(selectedIds)}
        onDone={clearSelection}
      />

      {/* ── Guarded deletion of device records ───────────────────────── */}
      <GuardedActionDialog
        open={guardedDelete !== null}
        onClose={() => setGuardedDelete(null)}
        actionKey="device.delete"
        selection={{ deviceIds: guardedDelete ?? [] }}
        title={t('devices.batch.deleteRecords') || 'Delete the records'}
        onDone={() => { clearSelection(); void load(true); }}
      />
    </div>
  );
}

// Recency and state sorts default to desc (the latest first); the alphabetical ones to asc.
function defaultSortOrder(field: SortField): 'asc' | 'desc' {
  return ['lastCheckin', 'enrolledAt'].includes(field) ? 'desc' : 'asc';
}

// ── Toolbar popover ─────────────────────────────────────────────────────────
//
// Desktop / tablet: a dropdown rendered in a portal with position: fixed and clamped to the viewport (flips
// above the anchor when there is no room below), with a transparent click-catcher so an outside click only
// closes it. Escape / Android back close it too. Phone: a bottom sheet.

function ToolbarPopover({
  open, onClose, anchorRef, align = 'start', maxHeight, className, sheetLabel, sheet, children,
}: {
  open: boolean;
  onClose: () => void;
  anchorRef: RefObject<HTMLElement>;
  align?: 'start' | 'end';
  /** Cap in px; the viewport may cap it lower. */
  maxHeight?: number;
  /** Classes of the floating panel (not used for the phone sheet). */
  className?: string;
  sheetLabel?: string;
  /** Force the bottom-sheet rendering (default: phone layout only). */
  sheet?: boolean;
  children: ReactNode;
}) {
  const layout = useLayoutMode();
  const asSheet = sheet || layout === 'phone';
  const popRef = useRef<HTMLDivElement>(null);
  const floating = open && !asSheet;
  const pos = useAnchoredPosition(anchorRef, popRef, floating, { placement: 'bottom', align, offset: 4 });
  useNativeBack(() => onClose(), floating, { escape: true });

  if (!open) return null;
  if (asSheet) {
    return (
      <Drawer open onClose={onClose} side="bottom" size="md" ariaLabel={sheetLabel} overlayClassName="z-[260]" bodyClassName="px-0 pt-0 pb-3">
        {children}
      </Drawer>
    );
  }
  const cap = pos ? (maxHeight ? Math.min(maxHeight, pos.maxHeight) : pos.maxHeight) : maxHeight;
  return createPortal(
    <>
      <div className="fixed inset-0 z-[259]" onClick={onClose} aria-hidden />
      <div
        ref={popRef}
        style={{ position: 'fixed', top: pos?.top ?? 0, left: pos?.left ?? 0, maxHeight: cap, visibility: pos ? 'visible' : 'hidden' }}
        className={cn('z-[260] max-w-[calc(100vw-1rem)]', className)}
      >
        {children}
      </div>
    </>,
    document.body,
  );
}

// ── Change-group modal ─────────────────────────────────────────────────────
function ChangeGroupModal({ count, onCancel, onConfirm }: {
  count: number;
  onCancel: () => void;
  onConfirm: (groupId: number | null) => void;
}) {
  const { t } = useTranslation();
  const [groupId, setGroupId] = useState<number | null>(null);
  return (
    <Modal
      open
      onClose={onCancel}
      size="sm"
      icon={<FolderOpen className="w-4 h-4 text-accent" />}
      title={t('devices.batch.changeGroupTitle', { count, defaultValue: `Change group for ${count} device${count > 1 ? 's' : ''}` })}
      bodyClassName="px-4 py-4 space-y-3"
      footer={(
        <>
          <button onClick={onCancel} className="px-3 py-1.5 text-xs rounded text-text-muted hover:text-text-primary coarse:min-h-10">
            {t('common.cancel', 'Cancel')}
          </button>
          <button onClick={() => onConfirm(groupId)} className="px-3 py-1.5 text-xs bg-accent text-white rounded hover:bg-accent/90 coarse:min-h-10">
            {t('devices.batch.moveHere', 'Move')}
          </button>
        </>
      )}
    >
      <p className="text-xs text-text-muted">
        {t('devices.batch.changeGroupHint', 'Pick a target group, or leave blank to move to "Ungrouped".')}
      </p>
      <p className="text-xs text-amber-400">
        {t('devices.batch.changeGroupPolicies') || 'The devices then receive the policies assigned to their new group, and lose those of the group they leave.'}
      </p>
      <GroupTreePicker value={groupId} onChange={(id) => setGroupId(id)} />
    </Modal>
  );
}

// ── Batch command modal (POST /api/apple/commands/bulk) ─────────────────────
function BulkCommandModal({ open, onClose, deviceIds, onDone }: {
  open: boolean;
  onClose: () => void;
  deviceIds: number[];
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [requestType, setRequestType] = useState<string>(BULK_COMMANDS[0]);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  // One key per opening: a retry of the same request replays it instead of queueing it twice.
  const keyRef = useRef(newIdempotencyKey());
  useEffect(() => { if (open) { keyRef.current = newIdempotencyKey(); setReason(''); setRequestType(BULK_COMMANDS[0]); } }, [open]);

  const submit = async () => {
    setBusy(true);
    try {
      const r = await appleApi.enqueueBulk({ deviceIds, requestType, reason: reason.trim() || undefined }, keyRef.current);
      if (isAwaitingApproval(r)) {
        toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      } else {
        toast.success(t('apple.commands.queued', { count: r.targets }) || `Command queued for ${r.targets} device(s)`);
        if (r.refused.length > 0) {
          toast(t('apple.commands.refusedSome', { count: r.refused.length }) || `${r.refused.length} device(s) set aside (not enrolled, not supervised, ownership…)`, { duration: 7000 });
        }
      }
      onDone();
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="sm"
      icon={<TerminalSquare className="w-4 h-4 text-accent" />}
      title={t('devices.batch.commandTitle', { count: deviceIds.length }) || `Send a command to ${deviceIds.length} device(s)`}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={submit} loading={busy} disabled={busy || deviceIds.length === 0 || deviceIds.length > 500}>{t('apple.commands.send') || 'Send'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        <label className="block">
          <span className="text-xs text-text-muted">{t('apple.commands.command') || 'Command'}</span>
          <select value={requestType} onChange={(e) => setRequestType(e.target.value)}
            className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary">
            {BULK_COMMANDS.map((c) => <option key={c} value={c}>{t(`apple.commands.types.${c}`) || c}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('apple.commands.reasonOptional') || 'Reason (optional)'}</span>
          <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500}
            className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary" />
        </label>
        <p className="text-[11px] text-text-muted">
          {t('devices.batch.commandHint') || 'The devices that cannot take the command (not enrolled, not supervised, ownership) are set aside. The destructive actions (erase, lock, lost mode, removal from management) are requested from the page of a device.'}
        </p>
        {deviceIds.length > 500 && <p className="text-xs text-red-400">{t('errors.tooManyTargets') || 'Too many devices for one request.'}</p>}
      </div>
    </Modal>
  );
}

// ── Hierarchical list body ────────────────────────────────────────────────
//
// Tree mode: the devices under a nested tree of group headers, each collapsible (state kept in localStorage);
// the branches without a device in view are hidden. Flat mode (search, explicit sort, "ungrouped"): one list.

type GroupRenderContext = {
  devicesByGroupId: Map<number | null, DeviceSummary[]>;
  collapsedGroupIds: Set<number>;
  onToggleGroup: (id: number) => void;
  selectedIds: Set<number>;
  toggleSelect: (id: number) => void;
  onNavigate: (id: number) => void;
  onGroupChange?: (id: number | null) => void;
  selectionMode: boolean;
  visibleFields: Set<string>;
  /** Indentation per tree level in px (16 on tablet / desktop, 8 on phone). */
  indentStep: number;
};

function hasDevicesRecursive(node: DeviceGroupTreeNode, byId: Map<number | null, DeviceSummary[]>): boolean {
  if ((byId.get(node.id) ?? []).length > 0) return true;
  return node.children.some((c) => hasDevicesRecursive(c, byId));
}

function countDevicesRecursive(node: DeviceGroupTreeNode, byId: Map<number | null, DeviceSummary[]>): number {
  let n = (byId.get(node.id) ?? []).length;
  for (const c of node.children) n += countDevicesRecursive(c, byId);
  return n;
}

function renderTreeNode(node: DeviceGroupTreeNode, depth: number, ctx: GroupRenderContext): JSX.Element[] {
  if (!hasDevicesRecursive(node, ctx.devicesByGroupId)) return [];

  const own = ctx.devicesByGroupId.get(node.id) ?? [];
  const isCollapsed = ctx.collapsedGroupIds.has(node.id);
  const totalBelow = countDevicesRecursive(node, ctx.devicesByGroupId);
  // Capped at depth 6, so that a deep tree keeps readable rows.
  const indent = Math.min(depth, 6) * ctx.indentStep;

  const out: JSX.Element[] = [
    <button
      key={`g-${node.id}`}
      onClick={() => ctx.onToggleGroup(node.id)}
      aria-expanded={!isCollapsed}
      className="w-full flex items-center gap-2 px-4 py-1.5 bg-bg-tertiary/70 hover:bg-bg-tertiary transition-colors text-left coarse:min-h-10"
      style={{ paddingLeft: `${(ctx.indentStep === 16 ? 16 : 12) + indent}px` }}
    >
      {isCollapsed
        ? <ChevronRight className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
        : <ChevronDown className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />}
      <FolderOpen className="w-3.5 h-3.5 text-accent flex-shrink-0" />
      <span className="text-xs font-semibold text-text-primary truncate">{anonymize(node.name)}</span>
      <span className="text-[10px] text-text-muted">({totalBelow})</span>
    </button>,
  ];

  if (!isCollapsed) {
    const children = [...node.children].sort((a, b) => a.name.localeCompare(b.name));
    for (const c of children) out.push(...renderTreeNode(c, depth + 1, ctx));
    for (const d of own) {
      out.push(
        <div key={`d-${d.id}`} style={{ paddingLeft: `${indent}px` }}>
          <DeviceRow
            device={d}
            isSelected={ctx.selectedIds.has(d.id)}
            onSelect={ctx.toggleSelect}
            onNavigate={ctx.onNavigate}
            onGroupClick={ctx.onGroupChange}
            selectionMode={ctx.selectionMode}
            visibleFields={ctx.visibleFields}
          />
        </div>,
      );
    }
  }
  return out;
}

function DeviceListBody({
  devices, tree, groupId, flat, collapsedGroupIds, onToggleGroup, selectedIds, toggleSelect, onNavigate, onGroupChange,
  selectionMode, visibleFields, isMaster, collapsedTenantIds, onToggleTenant, indentStep = 16,
}: {
  devices: DeviceSummary[];
  tree: DeviceGroupTreeNode[];
  groupId: number | null;
  /** One flat list (search, explicit sort, "ungrouped", or the master tenant's root). */
  flat: boolean;
  collapsedGroupIds: Set<number>;
  onToggleGroup: (id: number) => void;
  selectedIds: Set<number>;
  toggleSelect: (id: number) => void;
  onNavigate: (id: number) => void;
  onGroupChange?: (id: number | null) => void;
  selectionMode: boolean;
  visibleFields: Set<string>;
  /** Master tenant: one more level above the groups, the tenant. */
  isMaster: boolean;
  collapsedTenantIds: Set<number>;
  onToggleTenant: (tenantId: number) => void;
  indentStep?: number;
}) {
  const { t } = useTranslation();
  const devicesByGroupId = useMemo(() => {
    const map = new Map<number | null, DeviceSummary[]>();
    for (const d of devices) {
      const key = d.groupId ?? null;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(d);
    }
    return map;
  }, [devices]);

  // The roots of the rendered tree: every root, or the subtree of the selected group.
  const roots: DeviceGroupTreeNode[] = useMemo(() => {
    if (groupId === null) return tree;
    const find = (nodes: DeviceGroupTreeNode[]): DeviceGroupTreeNode | null => {
      for (const n of nodes) {
        if (n.id === groupId) return n;
        const f = find(n.children);
        if (f) return f;
      }
      return null;
    };
    const node = find(tree);
    return node ? [node] : [];
  }, [tree, groupId]);

  const row = (device: DeviceSummary) => (
    <DeviceRow
      key={device.id} device={device}
      isSelected={selectedIds.has(device.id)} onSelect={toggleSelect}
      onNavigate={onNavigate} onGroupClick={onGroupChange}
      selectionMode={selectionMode}
      visibleFields={visibleFields}
    />
  );

  // Flat list; also the fallback while the tree is empty or not loaded yet.
  if (flat || groupId === -1 || (roots.length === 0 && tree.length === 0)) return <>{devices.map(row)}</>;

  const ctx: GroupRenderContext = {
    devicesByGroupId, collapsedGroupIds, onToggleGroup, selectedIds, toggleSelect, onNavigate, onGroupChange, selectionMode,
    visibleFields, indentStep,
  };
  const sortedRoots = [...roots].sort((a, b) => a.name.localeCompare(b.name));
  const ungrouped = devicesByGroupId.get(null) ?? [];
  const ungroupedBlock = (list: DeviceSummary[], indented: boolean) => (list.length > 0 ? (
    <div>
      <div className={clsx('flex items-center gap-2 px-4 py-1.5 bg-bg-tertiary/70', indented && 'pl-8')}>
        <FolderX className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
        <span className="text-xs font-semibold text-text-muted">{t('groupPanel.ungrouped', 'Ungrouped')}</span>
        <span className="text-[10px] text-text-muted">({list.length})</span>
      </div>
      {list.map(row)}
    </div>
  ) : null);

  // Master view: the roots and the ungrouped devices bucketed by tenant, the master tenant first.
  if (isMaster && groupId === null) {
    type Bucket = { id: number; name: string; roots: DeviceGroupTreeNode[]; ungrouped: DeviceSummary[] };
    const buckets = new Map<number, Bucket>();
    const ensure = (id: number, name: string | null | undefined): Bucket => {
      if (!buckets.has(id)) buckets.set(id, { id, name: name ?? `Tenant ${id}`, roots: [], ungrouped: [] });
      return buckets.get(id)!;
    };
    for (const r of sortedRoots) ensure(r.tenantId, r.tenantName).roots.push(r);
    for (const d of ungrouped) ensure(d.tenantId, d.tenantName).ungrouped.push(d);
    const ordered = [...buckets.values()].sort((a, b) => {
      if (a.id === MASTER_TENANT_ID) return -1;
      if (b.id === MASTER_TENANT_ID) return 1;
      return a.name.localeCompare(b.name);
    });
    return (
      <>
        {ordered.map((b) => {
          const collapsed = collapsedTenantIds.has(b.id);
          const count = b.ungrouped.length + b.roots.reduce((acc, r) => acc + countDevicesRecursive(r, devicesByGroupId), 0);
          if (count === 0) return null;
          return (
            <div key={`tenant-${b.id}`} className="mb-2">
              <button type="button" onClick={() => onToggleTenant(b.id)} aria-expanded={!collapsed}
                className="w-full flex items-center gap-2 px-3 py-2 bg-accent/10 text-left hover:bg-accent/15 transition-colors coarse:min-h-10">
                {collapsed ? <ChevronRight className="w-3.5 h-3.5 text-accent" /> : <ChevronDown className="w-3.5 h-3.5 text-accent" />}
                <Building2 className="w-3.5 h-3.5 text-accent flex-shrink-0" />
                <span className="text-xs font-semibold uppercase tracking-[0.12em] text-accent flex-1">
                  {b.id === MASTER_TENANT_ID ? `${b.name} ${t('devices.filters.masterSuffix', '(master)')}` : b.name}
                </span>
                <span className="text-[10px] text-text-muted">{t('devices.list.count', '{{count}} devices', { count, defaultValue_one: '{{count}} device' })}</span>
              </button>
              {!collapsed && (
                <>
                  {b.roots.flatMap((r) => renderTreeNode(r, 0, ctx))}
                  {ungroupedBlock(b.ungrouped, true)}
                </>
              )}
            </div>
          );
        })}
      </>
    );
  }

  return (
    <>
      {sortedRoots.flatMap((r) => renderTreeNode(r, 0, ctx))}
      {groupId === null && ungroupedBlock(ungrouped, false)}
    </>
  );
}

// ── Column header sort label ──────────────────────────────────────────────
function SortLabel({ label, field, sortBy, sortOrder, onClick, className }: {
  label: string;
  field: SortField;
  sortBy: SortField;
  sortOrder: 'asc' | 'desc';
  onClick: (f: SortField) => void;
  className?: string;
}) {
  const active = sortBy === field;
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onClick(field); }}
      className={clsx('flex items-center gap-0.5 transition-colors shrink-0', active ? 'text-accent' : 'hover:text-text-primary', className)}
      title={label}
    >
      <span>{label}</span>
      {active ? (
        sortOrder === 'asc' ? <SortAsc className="w-3 h-3" /> : <SortDesc className="w-3 h-3" />
      ) : (
        <span className="w-3 h-3 opacity-30">↕</span>
      )}
    </button>
  );
}
