import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import {
  AlertTriangle, Ban, Copy, Download, FileSpreadsheet, FileUp, KeyRound, Layers, Lock, MessageSquare, Package, PackageOpen, PackageX, Plus, RefreshCw,
  RotateCw, Search, ShieldAlert, ShieldCheck, ShieldOff, SortAsc, SortDesc, Trash2, Upload, WifiOff, XCircle,
} from 'lucide-react';
import {
  isMasterTenant, LEGACY_AGENT_ACTIVATE_SCRIPT, LEGACY_AGENT_KNOX_STATES, LEGACY_AGENT_NAME_IMPORT_MAX_ROWS, LEGACY_AGENT_ADMIN_OFF_SCRIPT, LEGACY_AGENT_AUTO_UPDATE_BOUNDS, LEGACY_AGENT_TOKEN_BOUNDS,
  type DeviceGroup, type LegacyAgentCommandView, type LegacyAgentConsoleType, type LegacyAgentDeviceDetail, type LegacyAgentDeviceView,
  type LegacyAgentInstanceSettings, type LegacyAgentPackageView, type LegacyAgentReleaseView, type LegacyAgentServerKeyView,
  type LegacyAgentKnoxState, type LegacyAgentNameImportFormat, type LegacyAgentNameImportResult, type LegacyAgentNameImportStatus, type LegacyAgentTokenCreated, type LegacyAgentTokenView,
} from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { groupsApi } from '@/api/groups.api';
import { isStepUpHandled } from '@/api/client';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { InfoTip } from '@/components/common/Tip';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { StyledCheckbox } from '@/components/devices/StyledCheckbox';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { apiErrorMessage } from '@/utils/apiError';
import { saveBlob } from '@/utils/download';

// The Android bridge agent (agent-pont-android §7): the devices of the tenant (state of the agent, of the device
// administrator and of Knox, last interrogation, identity conflicts; actions on a selection), the enrollment tokens
// (the value, the encoded configuration and the MobiControl script shown once; the activation script of a device
// already enrolled and the `_adminmode off` return line, lot ADM), the client APKs, the tenant's Knox
// licence; for a platform administrator on the master tenant, the versions of the agent, the instance key (to
// compile in SERVER_KEY_PINS, exported once for the escrow) and the instance settings (automatic update of the fleet
// included; the version embedded in the server image is shown with its image, lot AGENT-RU). Lock and erase go
// through the dialog of the guard engine.

type Tab = 'devices' | 'tokens' | 'packages' | 'platform';
// The look of the suite (the inventory of /devices): fields and cards without borders, lists without separators whose
// rows light up on hover, filters as chips.
const fieldCls = 'mt-1 w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 disabled:opacity-50 coarse:min-h-10';
const labelCls = 'block text-xs font-medium text-text-muted';
const cardCls = 'rounded-xl bg-bg-secondary p-4';
const cardTitleCls = 'mb-3 flex items-center gap-1.5 text-sm font-semibold text-text-primary';
const listCls = 'overflow-x-auto rounded-xl bg-bg-secondary';
const headCls = 'bg-bg-tertiary/50 text-left text-[10px] font-medium uppercase tracking-wider text-text-muted';
const thCls = 'whitespace-nowrap px-4 py-2 font-medium';
const rowCls = 'transition-colors hover:bg-bg-tertiary';
const tdCls = 'px-4 py-2.5';
const chipCls = (on: boolean): string => clsx('flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium transition-colors coarse:py-2',
  on ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary');
const fmt = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleString() : '—');
const yesNo = (t: (k: string) => string, b: boolean | null | undefined): string =>
  (b === null || b === undefined ? '—' : b ? (t('legacyAgent.yes') || 'Yes') : (t('legacyAgent.no') || 'No'));

function fail(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
}

async function copy(text: string, done: string): Promise<void> {
  try { await navigator.clipboard.writeText(text); toast.success(done); } catch { /* selectable */ }
}

/** A file field in the look of the suite: the native input hidden behind a button, and the name of the chosen file. */
function FilePick({ accept, file, label, onPick }: { accept: string; file: File | null; label: string; onPick: (f: File | null) => void | Promise<void> }) {
  const { t } = useTranslation();
  const ref = useRef<HTMLInputElement>(null);
  return (
    <div className="mt-1 flex min-w-0 items-center gap-2">
      <input ref={ref} type="file" accept={accept} className="hidden" onChange={(e) => { void onPick(e.target.files?.[0] ?? null); e.target.value = ''; }} />
      <Button type="button" size="sm" variant="secondary" onClick={() => ref.current?.click()}><FileUp className="mr-1 h-4 w-4" />{label}</Button>
      <span className={clsx('min-w-0 truncate text-xs', file ? 'text-text-primary' : 'text-text-muted')}>{file ? file.name : (t('legacyAgent.file.none') || 'No file chosen')}</span>
    </div>
  );
}

export function LegacyAgentPage() {
  const { t } = useTranslation();
  const admin = useAuthStore((s) => s.isAdmin());
  const tenantId = useTenantStore((s) => s.currentTenantId);
  const platform = admin && isMasterTenant(tenantId);
  const [tab, setTab] = useState<Tab>('devices');
  const tabs: Tab[] = platform ? ['devices', 'tokens', 'packages', 'platform'] : ['devices', 'tokens', 'packages'];
  const label = (k: Tab) => (k === 'devices' ? (t('legacyAgent.tabs.devices') || 'Devices')
    : k === 'tokens' ? (t('legacyAgent.tabs.tokens') || 'Enrollment tokens')
      : k === 'packages' ? (t('legacyAgent.tabs.packages') || 'Packages')
        : (t('legacyAgent.tabs.platform') || 'Platform'));
  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('legacyAgent.title') || 'Android agent'}</h1>
        <p className="mt-1 text-sm text-text-muted">
          {t('legacyAgent.subtitle') || 'Android devices managed by the Obligarth bridge agent (device administrator, Knox when licensed).'}
        </p>
      </div>
      <SegmentedTabs tabs={tabs.map((k) => ({ id: k, label: label(k) }))} value={tab} onChange={setTab} fill={false} ariaLabel={t('legacyAgent.title') || 'Android agent'} />
      {tab === 'devices' && <DevicesTab />}
      {tab === 'tokens' && <TokensTab />}
      {tab === 'packages' && <PackagesTab />}
      {tab === 'platform' && platform && <PlatformTab />}
    </PageContainer>
  );
}

// ── Devices ──────────────────────────────────────────────────────────────────

type Pending = { kind: 'message' | 'install' | 'uninstall' | 'update' } | null;

// The list of the agents, in the look of the inventory of /devices: the whole list of the tenant is loaded once
// (revoked agents included) and filtered and sorted here, so that the tiles and the chips count the fleet (not the
// filtered view) and react at once. A tile, or a chip, toggles its filter; a column header sorts.

type SortKey = 'name' | 'model' | 'android' | 'agent' | 'admin' | 'knox' | 'src' | 'battery' | 'lastPoll';
type Sort = { key: SortKey; dir: 'asc' | 'desc' };
type SrcValue = 'yes' | 'no' | 'unknown';
interface DeviceFilters {
  admin: Set<'on' | 'off'>;
  knox: Set<LegacyAgentKnoxState>;
  src: Set<SrcValue>;
  version: Set<string>;
  silent: boolean;
  conflict: boolean;
  revoked: boolean;
}
const noFilters = (): DeviceFilters => ({ admin: new Set(), knox: new Set(), src: new Set(), version: new Set(), silent: false, conflict: false, revoked: false });
const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const isSilent = (d: LegacyAgentDeviceView, now: number): boolean => !d.lastPollAt || now - new Date(d.lastPollAt).getTime() > DAY_MS;
const srcOf = (d: LegacyAgentDeviceView): SrcValue => (d.unknownSources === null ? 'unknown' : d.unknownSources ? 'yes' : 'no');
const toggleIn = <T,>(s: Set<T>, v: T): Set<T> => { const n = new Set(s); if (n.has(v)) n.delete(v); else n.add(v); return n; };
const only = <T,>(s: Set<T>, v: T): boolean => s.size === 1 && s.has(v);

/** A clock refreshed every 30 seconds (the relative ages of the list). */
function useMinuteClock(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const id = window.setInterval(() => setNow(Date.now()), 30_000); return () => window.clearInterval(id); }, []);
  return now;
}

/**
 * The last interrogation: "5 minutes ago" for a day; then, in orange, the day and the hour ("Thursday at 13:05")
 * up to three days; beyond, in red, the full date and the number of days. The full date on hover.
 */
function PollAge({ at, now }: { at: string | null; now: number }) {
  const { t, i18n } = useTranslation();
  if (!at) return <span className="text-red-400">{t('legacyAgent.lastPoll.never') || 'Never'}</span>;
  const date = new Date(at);
  const age = Math.max(0, now - date.getTime());
  const lang = i18n.language || undefined;
  const full = date.toLocaleString(lang, { dateStyle: 'short', timeStyle: 'short' });
  if (age < DAY_MS) {
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
    const text = age < 60_000 ? (t('legacyAgent.lastPoll.now') || 'just now')
      : age < HOUR_MS ? rtf.format(-Math.floor(age / 60_000), 'minute') : rtf.format(-Math.floor(age / HOUR_MS), 'hour');
    return <time dateTime={at} title={full} className="text-text-secondary">{text}</time>;
  }
  if (age < 3 * DAY_MS) {
    const day = date.toLocaleDateString(lang, { weekday: 'long' });
    const time = date.toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit' });
    const dayCap = day.charAt(0).toUpperCase() + day.slice(1);
    return <time dateTime={at} title={full} className="text-amber-400">{t('legacyAgent.lastPoll.weekday', { day: dayCap, time }) || `${dayCap} at ${time}`}</time>;
  }
  const days = Math.floor(age / DAY_MS);
  return <time dateTime={at} className="text-red-400">{t('legacyAgent.lastPoll.old', { date: full, days }) || `${full} (${days} d)`}</time>;
}

/** A dot and a word: the state of a flag in a row of the list. */
function Flag({ tone, text }: { tone: 'green' | 'red' | 'amber' | 'gray'; text: string }) {
  const dot = tone === 'green' ? 'bg-emerald-500' : tone === 'red' ? 'bg-red-500' : tone === 'amber' ? 'bg-amber-500' : 'bg-text-muted/40';
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs">
      <span className={`h-2 w-2 shrink-0 rounded-full ${dot}`} aria-hidden />
      <span className={tone === 'red' ? 'text-red-400' : tone === 'amber' ? 'text-amber-400' : 'text-text-secondary'}>{text}</span>
    </span>
  );
}

/** A sortable column header (the look of the inventory of /devices). */
function SortTh({ label, k, sort, onSort, className }: { label: string; k: SortKey; sort: Sort; onSort: (k: SortKey) => void; className?: string }) {
  const on = sort.key === k;
  return (
    <th className={clsx(thCls, className)} aria-sort={on ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" onClick={() => onSort(k)}
        className={clsx('inline-flex items-center gap-0.5 uppercase tracking-wider transition-colors', on ? 'text-accent' : 'hover:text-text-primary')}>
        <span>{label}</span>
        {on ? (sort.dir === 'asc' ? <SortAsc className="h-3 w-3" /> : <SortDesc className="h-3 w-3" />) : <span className="h-3 w-3 opacity-30">↕</span>}
      </button>
    </th>
  );
}

const KNOX_RANK: Record<LegacyAgentKnoxState, number> = { licensed: 0, present: 1, license_error: 2, absent: 3 };

function DevicesTab() {
  const { t, i18n } = useTranslation();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const now = useMinuteClock();
  const [params, setParams] = useSearchParams();
  const [all, setAll] = useState<LegacyAgentDeviceView[] | null>(null);
  const [q, setQ] = useState('');
  const [filters, setFilters] = useState<DeviceFilters>(noFilters);
  const [sort, setSort] = useState<Sort>({ key: 'name', dir: 'asc' });
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [pending, setPending] = useState<Pending>(null);
  const [guarded, setGuarded] = useState<'device.lock' | 'device.wipe' | null>(null);
  const [importing, setImporting] = useState(false);
  const [exportMenu, setExportMenu] = useState(false);
  const [exporting, setExporting] = useState(false);
  const canExport = useAuthStore((s) => s.isAdmin() || (s.permissions?.tenantCapabilities ?? []).includes('reports'));
  const detailId = Number(params.get('device') ?? 0) || null;

  const load = useCallback(() => {
    legacyAgentApi.devices({ revoked: true }).then(setAll).catch((err) => { setAll([]); fail(err); });
  }, []);
  useEffect(() => { load(); }, [load]);

  // The fleet: the agents not revoked. Its counts feed the tiles and the chips.
  const fleet = useMemo(() => (all ?? []).filter((d) => !d.revokedAt), [all]);
  const counts = useMemo(() => {
    const c = { total: fleet.length, adminOn: 0, adminOff: 0, silent: 0, conflict: 0, revoked: (all ?? []).length - fleet.length,
      knox: {} as Partial<Record<LegacyAgentKnoxState, number>>, src: { yes: 0, no: 0, unknown: 0 } as Record<SrcValue, number>,
      version: new Map<string, { code: number; n: number }>() };
    for (const d of fleet) {
      if (d.adminActive) c.adminOn++; else c.adminOff++;
      if (isSilent(d, now)) c.silent++;
      if (d.identityConflict) c.conflict++;
      c.knox[d.knoxState] = (c.knox[d.knoxState] ?? 0) + 1;
      c.src[srcOf(d)]++;
      const v = c.version.get(d.agentVersionName) ?? { code: d.agentVersionCode, n: 0 };
      v.n++;
      c.version.set(d.agentVersionName, v);
    }
    return c;
  }, [all, fleet, now]);
  const versions = useMemo(() => [...counts.version.entries()].sort((a, b) => b[1].code - a[1].code), [counts]);

  const rows = useMemo(() => {
    const text = q.trim().toLowerCase();
    const list = (all ?? []).filter((d) => {
      if (!filters.revoked && d.revokedAt) return false;
      if (filters.admin.size && !filters.admin.has(d.adminActive ? 'on' : 'off')) return false;
      if (filters.knox.size && !filters.knox.has(d.knoxState)) return false;
      if (filters.src.size && !filters.src.has(srcOf(d))) return false;
      if (filters.version.size && !filters.version.has(d.agentVersionName)) return false;
      if (filters.silent && !isSilent(d, now)) return false;
      if (filters.conflict && !d.identityConflict) return false;
      if (text && ![d.name, d.serialNumber, d.model, d.modelName].some((v) => v?.toLowerCase().includes(text))) return false;
      return true;
    });
    const poll = (d: LegacyAgentDeviceView) => (d.lastPollAt ? new Date(d.lastPollAt).getTime() : 0);
    const value = (d: LegacyAgentDeviceView): string | number => {
      switch (sort.key) {
        case 'name': return (d.name ?? '').toLowerCase();
        case 'model': return (d.modelName ?? d.model ?? '').toLowerCase();
        case 'android': return d.apiLevel ?? -1;
        case 'agent': return d.agentVersionCode;
        case 'admin': return d.adminActive ? 1 : 0;
        case 'knox': return KNOX_RANK[d.knoxState] ?? 9;
        case 'src': return d.unknownSources === null ? -1 : d.unknownSources ? 1 : 0;
        case 'battery': return d.batteryLevel ?? -1;
        case 'lastPoll': return poll(d);
        default: return 0;
      }
    };
    const dir = sort.dir === 'asc' ? 1 : -1;
    return list.sort((a, b) => {
      const va = value(a); const vb = value(b);
      const c = typeof va === 'string' ? va.localeCompare(vb as string, undefined, { numeric: true }) : (va as number) - (vb as number);
      return c !== 0 ? c * dir : (a.name ?? '').localeCompare(b.name ?? '', undefined, { numeric: true });
    });
  }, [all, filters, q, sort, now]);
  const onSort = (k: SortKey) => setSort((s) => (s.key === k ? { key: k, dir: s.dir === 'asc' ? 'desc' : 'asc' }
    : { key: k, dir: k === 'name' || k === 'model' ? 'asc' : k === 'lastPoll' ? 'desc' : 'asc' }));

  const ids = [...selected].filter((id) => rows.some((r) => r.deviceId === id));
  const toggle = (id: number) => setSelected((s) => toggleIn(s, id));
  const selectable = rows.filter((r) => !r.revokedAt);
  const allChecked = selectable.length > 0 && selectable.every((r) => selected.has(r.deviceId));
  const someChecked = !allChecked && selectable.some((r) => selected.has(r.deviceId));

  const send = async (type: LegacyAgentConsoleType, p: Record<string, unknown>) => {
    try {
      const r = ids.length === 1 ? await legacyAgentApi.send(ids[0], type, p) : await legacyAgentApi.bulk(ids, type, p);
      if ('approvalId' in r) toast.success(t('legacyAgent.awaitingApproval') || 'Request sent for approval');
      else toast.success(t('legacyAgent.queued', { count: r.targets }) || `Queued for ${r.targets} device(s)`);
      if (!('approvalId' in r) && r.refused.length > 0) toast.error(t('legacyAgent.refused', { count: r.refused.length }) || `${r.refused.length} device(s) set aside`);
      setPending(null);
    } catch (err) { fail(err); }
  };

  const revoke = async (d: LegacyAgentDeviceView) => {
    const reason = await prompt({
      title: t('legacyAgent.revokeTitle') || 'Revoke the agent',
      message: t('legacyAgent.revokeMessage', { name: d.name ?? d.deviceId }) || `The agent of ${d.name ?? d.deviceId} will stop receiving orders and forget its key. Reason:`,
    });
    if (!reason) return;
    try { await legacyAgentApi.revoke(d.deviceId, reason); toast.success(t('legacyAgent.revoked') || 'Agent revoked'); load(); } catch (err) { fail(err); }
  };

  // The export: the view as shown (filters, search, sort), headers in the language of the console.
  const exportView = async (format: 'csv' | 'xlsx') => {
    setExportMenu(false);
    if (rows.length === 0) return;
    setExporting(true);
    try {
      const { blob, filename } = await legacyAgentApi.exportDevices(rows.map((r) => r.deviceId), format, i18n.language,
        Intl.DateTimeFormat().resolvedOptions().timeZone);
      if (!(await saveBlob(blob, filename))) toast.error(t('common.error') || 'Error');
    } catch (err) { fail(err); } finally { setExporting(false); }
  };

  // The tiles: each one is a shortcut to one value of a chip group (on when that group holds that value alone).
  type Tile = { key: string; icon: ReactNode; label: string; value: number; tone: 'neutral' | 'red' | 'amber'; on: boolean; toggle: () => void };
  const pickOnly = <T,>(field: 'admin' | 'src', v: T) => setFilters((f) => ({ ...f, [field]: only(f[field] as Set<T>, v) ? new Set() : new Set([v]) }));
  const tiles: Tile[] = [
    { key: 'total', icon: <Layers className="h-4 w-4" />, label: t('legacyAgent.kpi.total') || 'Devices', value: counts.total, tone: 'neutral',
      on: !filters.admin.size && !filters.src.size && !filters.knox.size && !filters.version.size && !filters.silent && !filters.conflict,
      toggle: () => setFilters((f) => ({ ...noFilters(), revoked: f.revoked })) },
    { key: 'adminOn', icon: <ShieldCheck className="h-4 w-4" />, label: t('legacyAgent.kpi.adminOn') || 'Admin mode on', value: counts.adminOn, tone: 'neutral',
      on: only(filters.admin, 'on'), toggle: () => pickOnly('admin', 'on') },
    { key: 'adminOff', icon: <ShieldAlert className="h-4 w-4" />, label: t('legacyAgent.kpi.adminOff') || 'Admin mode off', value: counts.adminOff,
      tone: counts.adminOff > 0 ? 'red' : 'neutral', on: only(filters.admin, 'off'), toggle: () => pickOnly('admin', 'off') },
    { key: 'srcYes', icon: <PackageOpen className="h-4 w-4" />, label: t('legacyAgent.kpi.srcYes') || 'Unknown sources: yes', value: counts.src.yes,
      tone: counts.src.yes > 0 ? 'amber' : 'neutral', on: only(filters.src, 'yes'), toggle: () => pickOnly('src', 'yes') },
    { key: 'srcNo', icon: <PackageX className="h-4 w-4" />, label: t('legacyAgent.kpi.srcNo') || 'Unknown sources: no', value: counts.src.no, tone: 'neutral',
      on: only(filters.src, 'no'), toggle: () => pickOnly('src', 'no') },
    { key: 'silent', icon: <WifiOff className="h-4 w-4" />, label: t('legacyAgent.kpi.silent') || 'Silent for 24 h', value: counts.silent,
      tone: counts.silent > 0 ? 'amber' : 'neutral', on: filters.silent, toggle: () => setFilters((f) => ({ ...f, silent: !f.silent })) },
  ];
  const valueTone = { neutral: 'text-text-primary', red: 'text-red-400', amber: 'text-amber-400' } as const;
  const hasFilters = !!(filters.admin.size || filters.src.size || filters.knox.size || filters.version.size || filters.silent || filters.conflict || q.trim());
  const groupLabel = (text: string) => <span className="mr-0.5 text-[10px] uppercase tracking-wider text-text-muted">{text}</span>;
  const divider = <span className="mx-1 h-4 w-px bg-border" aria-hidden />;
  const n = (v: number | undefined) => <span className="text-text-muted/70">{v ?? 0}</span>;

  return (
    <div className="space-y-4">
      <section aria-label={t('legacyAgent.kpi.title') || 'Fleet'} className="min-w-0">
        <div className="mb-1.5 flex items-center gap-1.5">
          <span className="text-[10px] font-medium uppercase tracking-wider text-text-muted">{t('legacyAgent.kpi.title') || 'Fleet'}</span>
          <InfoTip content={t('legacyAgent.kpi.hint') || 'Counts of the enrolled agents (revoked ones aside), not of the filtered view. A tile toggles its filter.'} />
        </div>
        <div className="-mx-3 flex snap-x snap-mandatory gap-2 overflow-x-auto overscroll-x-contain px-3 pb-1 scrollbar-none sm:mx-0 sm:grid sm:grid-cols-3 sm:overflow-visible sm:px-0 sm:pb-0 lg:grid-cols-6">
          {tiles.map((tile) => (
            <button key={tile.key} type="button" aria-pressed={tile.on} onClick={tile.toggle}
              className={clsx('group flex min-w-[8.5rem] shrink-0 snap-start items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition-colors sm:min-w-0',
                tile.on ? 'border-accent/60 bg-accent/10 ring-1 ring-accent/30' : 'border-border bg-bg-secondary hover:bg-bg-tertiary')}>
              <span className={clsx('flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
                tile.on ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted group-hover:text-text-primary')}>{tile.icon}</span>
              <span className="min-w-0">
                <span className={clsx('block text-lg font-semibold leading-tight tabular-nums', valueTone[tile.tone])}>{all ? tile.value : '—'}</span>
                <span className="block truncate text-[11px] text-text-muted">{tile.label}</span>
              </span>
            </button>
          ))}
        </div>
      </section>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
            <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('legacyAgent.search') || 'Name, serial number, model'}
              autoCapitalize="off" autoCorrect="off" spellCheck={false} enterKeyHint="search"
              className="w-full rounded-lg bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
          </div>
          <span className="text-xs text-text-muted">{t('legacyAgent.shown', { count: rows.length, total: counts.total }) || `${rows.length} / ${counts.total}`}</span>
          <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'} title={t('common.refresh') || 'Refresh'}
            className="rounded-lg p-2 text-text-muted transition-colors hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
            <RefreshCw className="h-4 w-4" />
          </button>
          <div className="ml-auto flex items-center gap-2">
            {canExport && (
              <div className="relative">
                <Button size="sm" variant="secondary" loading={exporting} disabled={exporting || rows.length === 0} aria-haspopup="menu" aria-expanded={exportMenu}
                  onClick={() => setExportMenu((v) => !v)}>
                  <Download className="mr-1 h-4 w-4" />{t('legacyAgent.export.button', { count: rows.length }) || `Export (${rows.length})`}
                </Button>
                {exportMenu && (<>
                  <div className="fixed inset-0 z-30" onClick={() => setExportMenu(false)} aria-hidden />
                  <div role="menu" className="absolute right-0 z-40 mt-1 w-56 overflow-hidden rounded-lg bg-bg-secondary py-1 shadow-xl ring-1 ring-border">
                    <button type="button" role="menuitem" className="block w-full px-3 py-2 text-left text-sm text-text-primary hover:bg-bg-tertiary coarse:py-3" onClick={() => void exportView('csv')}>
                      CSV <span className="text-xs text-text-muted">· {t('legacyAgent.export.csvHint') || 'any spreadsheet'}</span>
                    </button>
                    <button type="button" role="menuitem" className="block w-full px-3 py-2 text-left text-sm text-text-primary hover:bg-bg-tertiary coarse:py-3" onClick={() => void exportView('xlsx')}>
                      Excel (XLSX) <span className="text-xs text-text-muted">· {t('legacyAgent.export.xlsxHint') || 'filters ready'}</span>
                    </button>
                    <p className="px-3 pb-1 pt-1.5 text-[11px] leading-snug text-text-muted">{t('legacyAgent.export.scope') || 'The list as shown: its filters, its search and its sort.'}</p>
                  </div>
                </>)}
              </div>
            )}
            <Button size="sm" variant="secondary" onClick={() => setImporting(true)}>
              <FileSpreadsheet className="mr-1 h-4 w-4" />{t('legacyAgent.importNames.button') || 'Import names'}
            </Button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {groupLabel(t('legacyAgent.cols.admin') || 'Admin mode')}
          {(['on', 'off'] as const).map((v) => (
            <button key={v} type="button" aria-pressed={filters.admin.has(v)} className={chipCls(filters.admin.has(v))} onClick={() => setFilters((f) => ({ ...f, admin: toggleIn(f.admin, v) }))}>
              <span className={clsx('h-2 w-2 rounded-full', v === 'on' ? 'bg-emerald-500' : 'bg-red-500')} />
              {v === 'on' ? (t('legacyAgent.adminOn') || 'On') : (t('legacyAgent.adminOff') || 'Off')} {n(v === 'on' ? counts.adminOn : counts.adminOff)}
            </button>
          ))}
          {divider}
          {groupLabel(t('legacyAgent.cols.knox') || 'Knox')}
          {LEGACY_AGENT_KNOX_STATES.map((s) => (
            <button key={s} type="button" aria-pressed={filters.knox.has(s)} className={chipCls(filters.knox.has(s))} onClick={() => setFilters((f) => ({ ...f, knox: toggleIn(f.knox, s) }))}>
              {t(`legacyAgent.knox.${s}`) || s} {n(counts.knox[s])}
            </button>
          ))}
          {divider}
          {groupLabel(t('legacyAgent.cols.unknownSources') || 'Unknown sources')}
          {(['yes', 'no', 'unknown'] as const).map((v) => (
            <button key={v} type="button" aria-pressed={filters.src.has(v)} className={chipCls(filters.src.has(v))} onClick={() => setFilters((f) => ({ ...f, src: toggleIn(f.src, v) }))}>
              {v === 'yes' ? (t('legacyAgent.yes') || 'Yes') : v === 'no' ? (t('legacyAgent.no') || 'No') : (t('legacyAgent.notReported') || 'Not reported')} {n(counts.src[v])}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {groupLabel(t('legacyAgent.cols.agent') || 'Agent')}
          {versions.map(([name, v]) => (
            <button key={name} type="button" aria-pressed={filters.version.has(name)} className={chipCls(filters.version.has(name))} onClick={() => setFilters((f) => ({ ...f, version: toggleIn(f.version, name) }))}>
              {name} {n(v.n)}
            </button>
          ))}
          {divider}
          <button type="button" aria-pressed={filters.silent} className={chipCls(filters.silent)} onClick={() => setFilters((f) => ({ ...f, silent: !f.silent }))}>
            <WifiOff className="h-3 w-3" /> {t('legacyAgent.filters.silent') || 'Silent for 24 h'} {n(counts.silent)}
          </button>
          <button type="button" aria-pressed={filters.conflict} className={chipCls(filters.conflict)} onClick={() => setFilters((f) => ({ ...f, conflict: !f.conflict }))}>
            <AlertTriangle className="h-3 w-3" /> {t('legacyAgent.filters.conflict') || 'Identity conflict'} {n(counts.conflict)}
          </button>
          <button type="button" aria-pressed={filters.revoked} className={chipCls(filters.revoked)} onClick={() => setFilters((f) => ({ ...f, revoked: !f.revoked }))}>
            <Ban className="h-3 w-3" /> {t('legacyAgent.filters.revoked') || 'Include revoked'} {n(counts.revoked)}
          </button>
          {hasFilters && (
            <button type="button" className="ml-1 text-[11px] text-accent hover:underline" onClick={() => { setFilters((f) => ({ ...noFilters(), revoked: f.revoked })); setQ(''); }}>
              {t('legacyAgent.clearFilters') || 'Clear the filters'}
            </button>
          )}
        </div>
      </div>

      {ids.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl bg-accent/10 px-3 py-2 text-sm">
          <span className="mr-1 font-medium text-accent">{t('legacyAgent.selected', { count: ids.length }) || `${ids.length} selected`}</span>
          <Button size="sm" variant="secondary" onClick={() => setPending({ kind: 'message' })}><MessageSquare className="mr-1 h-4 w-4" />{t('legacyAgent.actions.message') || 'Message'}</Button>
          <Button size="sm" variant="secondary" onClick={() => void send('inventory.refresh', {})}><RefreshCw className="mr-1 h-4 w-4" />{t('legacyAgent.actions.inventory') || 'Inventory'}</Button>
          <Button size="sm" variant="secondary" onClick={async () => { if (await confirm({ message: t('legacyAgent.confirmReboot') || 'Restart the selected devices (Knox required)?' })) void send('device.reboot', {}); }}>
            <RotateCw className="mr-1 h-4 w-4" />{t('legacyAgent.actions.reboot') || 'Restart'}
          </Button>
          <Button size="sm" variant="secondary" onClick={() => setPending({ kind: 'install' })}><Package className="mr-1 h-4 w-4" />{t('legacyAgent.actions.install') || 'Install an app'}</Button>
          <Button size="sm" variant="secondary" onClick={() => setPending({ kind: 'uninstall' })}><Trash2 className="mr-1 h-4 w-4" />{t('legacyAgent.actions.uninstall') || 'Uninstall an app'}</Button>
          <Button size="sm" variant="secondary" onClick={() => setPending({ kind: 'update' })}><Download className="mr-1 h-4 w-4" />{t('legacyAgent.actions.update') || 'Update the agent'}</Button>
          <Button size="sm" variant="secondary" onClick={() => setGuarded('device.lock')}><Lock className="mr-1 h-4 w-4" />{t('legacyAgent.actions.lock') || 'Lock'}</Button>
          <Button size="sm" variant="danger" onClick={() => setGuarded('device.wipe')}><ShieldOff className="mr-1 h-4 w-4" />{t('legacyAgent.actions.wipe') || 'Erase'}</Button>
          <button type="button" className="ml-auto text-xs text-text-muted hover:text-text-primary" onClick={() => setSelected(new Set())}>
            {t('legacyAgent.clearSelection') || 'Clear the selection'}
          </button>
        </div>
      )}

      {all && rows.length === 0 ? (
        <div className="rounded-xl bg-bg-secondary p-12 text-center text-text-muted">
          <p className="mb-1 font-medium text-text-primary">{fleet.length === 0 ? (t('legacyAgent.empty') || 'No agent enrolled yet.') : (t('legacyAgent.noMatch') || 'No device matches these filters.')}</p>
          {hasFilters && <button type="button" className="text-sm text-accent hover:underline" onClick={() => { setFilters((f) => ({ ...noFilters(), revoked: f.revoked })); setQ(''); }}>{t('legacyAgent.clearFilters') || 'Clear the filters'}</button>}
        </div>
      ) : (
        <div className={listCls}>
          <table className="w-full text-sm">
            <thead className={headCls}>
              <tr>
                <th className="w-10 py-2 pl-4"><StyledCheckbox checked={allChecked} indeterminate={someChecked}
                  onChange={() => setSelected(allChecked ? new Set() : new Set(selectable.map((r) => r.deviceId)))} /></th>
                <SortTh label={t('legacyAgent.cols.name') || 'Name'} k="name" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.model') || 'Model'} k="model" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.android') || 'Android'} k="android" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.agent') || 'Agent'} k="agent" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.admin') || 'Admin mode'} k="admin" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.knox') || 'Knox'} k="knox" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.unknownSources') || 'Unknown sources'} k="src" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.battery') || 'Battery'} k="battery" sort={sort} onSort={onSort} />
                <SortTh label={t('legacyAgent.cols.lastPoll') || 'Last interrogation'} k="lastPoll" sort={sort} onSort={onSort} />
                <th className="w-12" />
              </tr>
            </thead>
            <tbody>
              {(all ? rows : []).map((d) => {
                const isSel = selected.has(d.deviceId);
                return (
                  <tr key={d.deviceId} onClick={() => setParams({ device: String(d.deviceId) })}
                    className={clsx(rowCls, 'cursor-pointer', isSel && 'bg-accent/10', d.revokedAt && 'opacity-60')}>
                    <td className="py-2.5 pl-4" onClick={(e) => e.stopPropagation()}>
                      <StyledCheckbox checked={isSel} disabled={!!d.revokedAt} onChange={() => toggle(d.deviceId)} />
                    </td>
                    <td className={tdCls}>
                      <div className="flex items-center gap-1.5">
                        <span className="max-w-[240px] truncate font-semibold text-text-primary" title={d.name ?? undefined}>{d.name ?? `#${d.deviceId}`}</span>
                        {d.identityConflict && <span title={t('legacyAgent.filters.conflict') || 'Identity conflict'}><AlertTriangle className="h-3.5 w-3.5 text-amber-400" /></span>}
                      </div>
                      {d.serialNumber && <div className="text-xs text-text-muted">{d.serialNumber}</div>}
                    </td>
                    <td className={clsx(tdCls, 'text-text-secondary')}>{d.modelName ?? d.model ?? '—'}</td>
                    <td className={clsx(tdCls, 'whitespace-nowrap text-text-secondary')}>
                      {d.osVersion ?? '—'}{d.apiLevel ? <span className="text-text-muted"> · API {d.apiLevel}</span> : null}
                      {d.securityPatch && <div className="text-xs text-text-muted">{d.securityPatch}</div>}
                    </td>
                    <td className={clsx(tdCls, 'whitespace-nowrap text-text-secondary')}>{d.agentVersionName}<span className="text-xs text-text-muted"> ({d.agentVersionCode})</span></td>
                    <td className={tdCls}>{d.adminActive ? <Flag tone="green" text={t('legacyAgent.adminOn') || 'On'} /> : <Flag tone="red" text={t('legacyAgent.adminOff') || 'Off'} />}</td>
                    <td className={tdCls}>
                      <Flag tone={d.knoxState === 'licensed' ? 'green' : d.knoxState === 'license_error' ? 'red' : d.knoxState === 'present' ? 'amber' : 'gray'}
                        text={t(`legacyAgent.knox.${d.knoxState}`) || d.knoxState} />
                    </td>
                    <td className={tdCls}>{d.unknownSources === null ? <span className="text-text-muted">—</span>
                      : <Flag tone={d.unknownSources ? 'amber' : 'gray'} text={yesNo(t, d.unknownSources)} />}</td>
                    <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-secondary')}>{d.batteryLevel === null ? '—' : `${d.batteryLevel} %`}</td>
                    <td className={clsx(tdCls, 'whitespace-nowrap text-xs')}>
                      {d.revokedAt ? <span className="text-text-muted">{t('legacyAgent.revokedState') || 'Revoked'}</span> : <PollAge at={d.lastPollAt} now={now} />}
                    </td>
                    <td className="py-2.5 pr-3 text-right" onClick={(e) => e.stopPropagation()}>
                      {!d.revokedAt && (
                        <button type="button" title={t('legacyAgent.actions.revoke') || 'Revoke'} aria-label={t('legacyAgent.actions.revoke') || 'Revoke'} onClick={() => void revoke(d)}
                          className="rounded p-1 text-text-muted transition-colors hover:bg-bg-hover hover:text-red-400">
                          <Ban className="h-4 w-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!all && <tr><td colSpan={11} className="p-8 text-center text-text-muted">{t('common.loading') || 'Loading…'}</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      {importing && <NameImportDialog onClose={() => setImporting(false)} onDone={load} />}
      {pending && <CommandDialog kind={pending.kind} count={ids.length} onClose={() => setPending(null)} onSend={send} />}
      {guarded && (
        <GuardedActionDialog open onClose={() => setGuarded(null)}
          actionKey={guarded === 'device.wipe' ? 'legacy_agent.erase_device' : 'legacy_agent.device_lock'}
          selection={{ deviceIds: ids }} params={guarded === 'device.wipe' ? { wipeExternal: false } : {}}
          title={guarded === 'device.wipe' ? (t('legacyAgent.actions.wipe') || 'Erase') : (t('legacyAgent.actions.lock') || 'Lock')}
          onDone={() => { setGuarded(null); load(); }} />
      )}
      {detailId && <DeviceDetail id={detailId} onClose={() => { params.delete('device'); setParams(params); }} />}
    </div>
  );
}

// ── Import of device names (an export of MobiControl, of Omnissa Workspace ONE, or any CSV) ─────────────────────────

/** The text of a CSV file: UTF-16 by its BOM (Excel "Unicode text"), else UTF-8, else Windows-1252. */
async function readCsvFile(file: File): Promise<string> {
  const buf = new Uint8Array(await file.arrayBuffer());
  if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder('utf-16le').decode(buf);
  if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder('utf-16be').decode(buf);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { return new TextDecoder('windows-1252').decode(buf); }
}

function splitCsvLine(line: string, sep: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') quoted = false; else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === sep) { out.push(cur.trim()); cur = ''; } else cur += c;
  }
  out.push(cur.trim());
  return out;
}

const looksLikeImei = (v: string): boolean => /^\d{14,16}$/.test(v.replace(/[\s-]/g, ''));

/** A CSV as its header and its cells: separator , ; or tab (the most frequent in the first line); a first line that
 *  holds an IMEI is data, and the columns are then named by their number. */
function parseCsv(text: string): { header: string[]; rows: string[][] } {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/).filter((l) => l.trim() !== '');
  if (lines.length === 0) return { header: [], rows: [] };
  const sep = [',', ';', '\t'].map((c) => ({ c, n: lines[0].split(c).length })).sort((a, b) => b.n - a.n)[0].c;
  const cells = lines.map((l) => splitCsvLine(l, sep));
  const width = Math.max(...cells.map((c) => c.length));
  if (cells[0].some(looksLikeImei)) return { header: Array.from({ length: width }, (_, i) => `#${i + 1}`), rows: cells };
  return { header: cells[0], rows: cells.slice(1) };
}

type Columns = { name: number; imei: number; serial: number };
/** The header names each format puts in its export (fr and en consoles), the first match wins. */
const FORMAT_COLUMNS: Record<LegacyAgentNameImportFormat, { name: RegExp[]; imei: RegExp[]; serial: RegExp[] }> = {
  mobicontrol: {
    name: [/^nom term/i, /^device name$/i, /^nom$/i, /^name$/i],
    imei: [/^imei/i, /imei/i],
    serial: [/^(num[ée]ro de s[ée]rie|serial number|n° de s[ée]rie)$/i],
  },
  omnissa: {
    name: [/^friendly name$/i, /^nom convivial$/i, /^device friendly name$/i, /^nom$/i, /^name$/i],
    imei: [/^imei$/i, /imei/i],
    serial: [/^serial number$/i, /^num[ée]ro de s[ée]rie$/i, /serial/i],
  },
  csv: {
    name: [/^(nom|name|friendly name|device name|nom term.*)$/i],
    imei: [/imei/i],
    serial: [/serial|s[ée]rie/i],
  },
};
function guessColumns(header: string[], rows: string[][], format: LegacyAgentNameImportFormat): Columns {
  const find = (res: RegExp[]) => { for (const re of res) { const i = header.findIndex((h) => re.test(h.trim())); if (i >= 0) return i; } return -1; };
  const spec = FORMAT_COLUMNS[format];
  let imei = find(spec.imei);
  if (imei < 0 && rows[0]) imei = rows[0].findIndex(looksLikeImei);
  let name = find(spec.name);
  if (name < 0) name = header.findIndex((_, i) => i !== imei);
  return { name, imei, serial: find(spec.serial) };
}

const IMPORT_ORDER: LegacyAgentNameImportStatus[] = ['rename', 'renamed', 'same', 'notFound', 'ambiguous', 'duplicate', 'forbidden', 'invalid'];

function NameImportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [format, setFormat] = useState<LegacyAgentNameImportFormat>('mobicontrol');
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState('');
  const [cols, setCols] = useState<Columns>({ name: -1, imei: -1, serial: -1 });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LegacyAgentNameImportResult | null>(null);
  const csv = useMemo(() => parseCsv(text), [text]);
  // A new content or a new format: the columns guessed again (the operator can still change them).
  useEffect(() => { setCols(guessColumns(csv.header, csv.rows, format)); setResult(null); }, [csv, format]);
  const pairs = useMemo(() => csv.rows.map((r) => ({
    name: cols.name >= 0 ? r[cols.name] ?? '' : '',
    ...(cols.imei >= 0 && r[cols.imei] ? { imei: r[cols.imei] } : {}),
    ...(cols.serial >= 0 && r[cols.serial] ? { serial: r[cols.serial] } : {}),
  })).filter((p) => p.name || p.imei || p.serial), [csv, cols]);
  const counts = useMemo(() => {
    const c: Partial<Record<LegacyAgentNameImportStatus, number>> = {};
    for (const r of result?.rows ?? []) c[r.status] = (c[r.status] ?? 0) + 1;
    return c;
  }, [result]);
  const sorted = useMemo(() => [...(result?.rows ?? [])].sort((a, b) => IMPORT_ORDER.indexOf(a.status) - IMPORT_ORDER.indexOf(b.status)), [result]);
  const label = (s: LegacyAgentNameImportStatus) => t(`legacyAgent.importNames.status.${s}`) || s;
  const tone = (s: LegacyAgentNameImportStatus) => (s === 'rename' || s === 'renamed' ? 'text-accent'
    : s === 'same' ? 'text-text-muted' : s === 'notFound' ? 'text-amber-400' : 'text-red-400');
  const toRename = counts.rename ?? 0;
  const ready = pairs.length > 0 && cols.name >= 0 && (cols.imei >= 0 || cols.serial >= 0);

  const run = async (apply: boolean) => {
    if (!ready) return;
    if (pairs.length > LEGACY_AGENT_NAME_IMPORT_MAX_ROWS) {
      toast.error(t('legacyAgent.importNames.tooMany', { max: LEGACY_AGENT_NAME_IMPORT_MAX_ROWS }) || `${LEGACY_AGENT_NAME_IMPORT_MAX_ROWS} rows at most`);
      return;
    }
    setBusy(true);
    try {
      const r = await legacyAgentApi.importNames(pairs, apply, format);
      setResult(r);
      if (apply) {
        toast.success(t('legacyAgent.importNames.done', { count: r.applied }) || `${r.applied} device(s) renamed`);
        onDone();
      }
    } catch (err) { fail(err); } finally { setBusy(false); }
  };

  const formats: Array<{ id: LegacyAgentNameImportFormat; label: string; hint: string }> = [
    { id: 'mobicontrol', label: 'SOTI MobiControl', hint: t('legacyAgent.importNames.formats.mobicontrol') || 'Export of the devices: "Nom term." / "Device Name" and "IMEI / MEID / ESN".' },
    { id: 'omnissa', label: 'Omnissa Workspace ONE', hint: t('legacyAgent.importNames.formats.omnissa') || 'Export of the device list as CSV: "Friendly Name", "IMEI" and "Serial Number".' },
    { id: 'csv', label: t('legacyAgent.importNames.formats.csvLabel') || 'Other CSV', hint: t('legacyAgent.importNames.formats.csv') || 'Any CSV: choose the column of the name, and that of the IMEI or of the serial number.' },
  ];
  const colSelect = (k: keyof Columns, text: string, optional: boolean) => (
    <label className={labelCls}>{text}
      <select className={fieldCls} value={cols[k]} onChange={(e) => { setCols((c) => ({ ...c, [k]: Number(e.target.value) })); setResult(null); }}>
        <option value={-1}>{optional ? (t('legacyAgent.importNames.none') || '— none —') : '—'}</option>
        {csv.header.map((h, i) => <option key={i} value={i}>{h || `#${i + 1}`}</option>)}
      </select>
    </label>
  );

  return (
    <Modal open onClose={onClose} size="2xl" title={t('legacyAgent.importNames.title') || 'Import device names'}>
      <div className="space-y-4 text-sm">
        <div>
          <span className={labelCls}>{t('legacyAgent.importNames.format') || 'Format of the export'}</span>
          <div className="mt-1 grid gap-2 sm:grid-cols-3">
            {formats.map((f) => (
              <button key={f.id} type="button" aria-pressed={format === f.id} onClick={() => setFormat(f.id)}
                className={clsx('rounded-xl border px-3 py-2 text-left transition-colors',
                  format === f.id ? 'border-accent/60 bg-accent/10 ring-1 ring-accent/30' : 'border-border bg-bg-secondary hover:bg-bg-tertiary')}>
                <span className={clsx('block text-sm font-medium', format === f.id ? 'text-accent' : 'text-text-primary')}>{f.label}</span>
                <span className="mt-0.5 block text-[11px] leading-snug text-text-muted">{f.hint}</span>
              </button>
            ))}
          </div>
        </div>

        <div>
          <span className={labelCls}>{t('legacyAgent.importNames.file') || 'File'}</span>
          <FilePick accept=".csv,.txt,text/csv,text/plain" file={file} label={t('legacyAgent.importNames.choose') || 'Choose a CSV file'}
            onPick={async (f) => { setFile(f); if (f) setText(await readCsvFile(f)); }} />
          <details className="mt-2 text-xs text-text-muted">
            <summary className="cursor-pointer select-none hover:text-text-primary">{t('legacyAgent.importNames.orPaste') || 'or paste the content'}</summary>
            <textarea className={clsx(fieldCls, 'font-mono text-xs')} rows={5} value={text} spellCheck={false}
              placeholder={'Nom term.,IMEI / MEID / ESN\nC0000001,350000000000000'} onChange={(e) => { setFile(null); setText(e.target.value); }} />
          </details>
        </div>

        {csv.header.length > 0 && (
          <div className="grid gap-3 rounded-xl bg-bg-secondary p-3 sm:grid-cols-3">
            {colSelect('name', t('legacyAgent.importNames.cols.nameCol') || 'Column of the name', false)}
            {colSelect('imei', t('legacyAgent.importNames.cols.imeiCol') || 'Column of the IMEI', true)}
            {colSelect('serial', t('legacyAgent.importNames.cols.serialCol') || 'Column of the serial number', true)}
            <p className="text-[11px] text-text-muted sm:col-span-3">
              {t('legacyAgent.importNames.matching') || 'A row is matched by its IMEI when it has one, else by its serial number. Nothing changes before "Rename".'}
            </p>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-text-muted">{t('legacyAgent.importNames.lines', { count: pairs.length }) || `${pairs.length} line(s) read`}</span>
          <Button size="sm" variant="secondary" className="ml-auto" disabled={busy || !ready} onClick={() => void run(false)}>
            <Search className="mr-1 h-4 w-4" />{t('legacyAgent.importNames.preview') || 'Preview'}
          </Button>
          <Button size="sm" disabled={busy || !result || toRename === 0} onClick={() => void run(true)}>
            <FileSpreadsheet className="mr-1 h-4 w-4" />{t('legacyAgent.importNames.apply', { count: toRename }) || `Rename ${toRename} device(s)`}
          </Button>
        </div>

        {result && (<>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
            {IMPORT_ORDER.filter((s) => counts[s]).map((s) => (
              <span key={s} className={tone(s)}>{label(s)} <span className="font-semibold tabular-nums">{counts[s]}</span></span>
            ))}
          </div>
          <div className="max-h-80 overflow-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-xs">
              <thead className={clsx(headCls, 'sticky top-0 bg-bg-tertiary')}>
                <tr>
                  <th className={thCls}>{t('legacyAgent.importNames.cols.name') || 'New name'}</th>
                  <th className={thCls}>{t('legacyAgent.importNames.cols.key') || 'IMEI / serial'}</th>
                  <th className={thCls}>{t('legacyAgent.importNames.cols.current') || 'Current name'}</th>
                  <th className={thCls}>{t('legacyAgent.importNames.cols.status') || 'Result'}</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((r, i) => (
                  <tr key={`${r.imei}-${r.serial}-${i}`} className={rowCls}>
                    <td className="px-4 py-1.5 text-text-primary">{r.name || '—'}</td>
                    <td className="px-4 py-1.5 font-mono text-text-secondary">{r.matchedBy === 'serial' ? r.serial : (r.imei || r.serial || '—')}</td>
                    <td className="px-4 py-1.5 text-text-muted">{r.currentName ?? '—'}</td>
                    <td className={clsx('px-4 py-1.5', tone(r.status))}>{label(r.status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>)}
      </div>
    </Modal>
  );
}

function CommandDialog({ kind, count, onClose, onSend }: { kind: 'message' | 'install' | 'uninstall' | 'update'; count: number; onClose: () => void;
  onSend: (type: LegacyAgentConsoleType, params: Record<string, unknown>) => Promise<void> }) {
  const { t } = useTranslation();
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [mode, setMode] = useState<'notification' | 'fullscreen'>('notification');
  const [packageName, setPackageName] = useState('');
  const [choice, setChoice] = useState('');
  const [packages, setPackages] = useState<LegacyAgentPackageView[]>([]);
  const [releases, setReleases] = useState<LegacyAgentReleaseView[]>([]);
  useEffect(() => {
    if (kind === 'install') legacyAgentApi.packages().then(setPackages).catch(fail);
    if (kind === 'update') legacyAgentApi.releases().then(setReleases).catch(fail);
  }, [kind]);
  const submit = () => {
    if (kind === 'message') void onSend('device.message', { title, text, mode });
    else if (kind === 'install') void onSend('app.install', { packageId: choice });
    else if (kind === 'uninstall') void onSend('app.uninstall', { packageName });
    else void onSend('agent.update', { releaseId: choice });
  };
  const heading = kind === 'message' ? (t('legacyAgent.actions.message') || 'Message') : kind === 'install' ? (t('legacyAgent.actions.install') || 'Install an app')
    : kind === 'uninstall' ? (t('legacyAgent.actions.uninstall') || 'Uninstall an app') : (t('legacyAgent.actions.update') || 'Update the agent');
  return (
    <Modal open onClose={onClose} title={`${heading} (${count})`}>
      <div className="space-y-3 text-sm">
        {kind === 'message' && (<>
          <label className={labelCls}>{t('legacyAgent.message.title') || 'Title'}<input className={fieldCls} maxLength={80} value={title} onChange={(e) => setTitle(e.target.value)} /></label>
          <label className={labelCls}>{t('legacyAgent.message.text') || 'Text'}<textarea className={fieldCls} maxLength={500} rows={4} value={text} onChange={(e) => setText(e.target.value)} /></label>
          <label className={labelCls}>{t('legacyAgent.message.mode') || 'Display'}
            <select className={fieldCls} value={mode} onChange={(e) => setMode(e.target.value as 'notification' | 'fullscreen')}>
              <option value="notification">{t('legacyAgent.message.notification') || 'Notification'}</option>
              <option value="fullscreen">{t('legacyAgent.message.fullscreen') || 'Full screen'}</option>
            </select></label>
        </>)}
        {kind === 'install' && (
          <label className={labelCls}>{t('legacyAgent.packages.choose') || 'Package'}
            <select className={fieldCls} value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">—</option>
              {packages.map((p) => <option key={p.id} value={p.id}>{p.label ?? p.packageName} {p.versionName ?? ''} ({p.versionCode})</option>)}
            </select></label>
        )}
        {kind === 'uninstall' && (
          <label className={labelCls}>{t('legacyAgent.packages.packageName') || 'Package name'}<input className={fieldCls} value={packageName} onChange={(e) => setPackageName(e.target.value)} placeholder="com.example.app" /></label>
        )}
        {kind === 'update' && (
          <label className={labelCls}>{t('legacyAgent.releases.choose') || 'Version of the agent'}
            <select className={fieldCls} value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">—</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.versionName} ({r.versionCode}){r.bundledIn ? ` — ${bundledLabel(t, r.bundledIn)}` : ''}</option>)}
            </select></label>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={submit} disabled={(kind === 'message' && (!title || !text)) || ((kind === 'install' || kind === 'update') && !choice) || (kind === 'uninstall' && !packageName)}>
            {t('legacyAgent.send') || 'Send'}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function DeviceDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const { t } = useTranslation();
  const [d, setD] = useState<LegacyAgentDeviceDetail | null>(null);
  const [cmds, setCmds] = useState<LegacyAgentCommandView[]>([]);
  const load = useCallback(() => {
    legacyAgentApi.device(id).then(setD).catch(fail);
    legacyAgentApi.deviceCommands(id).then(setCmds).catch(fail);
  }, [id]);
  useEffect(() => { load(); }, [load]);
  const cancel = async (c: LegacyAgentCommandView) => { try { await legacyAgentApi.cancel(c.id); load(); } catch (err) { fail(err); } };
  /** app.pull (agent 1.2.0): the APK comes back to the Packages tab. */
  const pull = async (packageName: string) => {
    try {
      await legacyAgentApi.send(id, 'app.pull', { packageName });
      toast.success(t('legacyAgent.pull.queued') || 'Requested: the APK will appear in Packages once the device sent it.');
      load();
    } catch (err) { if (!isStepUpHandled(err)) fail(err); }
  };
  const row = (k: string, v: ReactNode) => <div key={k} className="flex justify-between gap-4 rounded-md px-3 py-1.5 transition-colors hover:bg-bg-tertiary"><span className="text-text-muted">{k}</span><span className="break-all text-right text-text-primary">{v}</span></div>;
  return (
    <Modal open onClose={onClose} size="2xl" title={d?.name ?? `#${id}`}>
      {d && (
        <div className="space-y-4 text-sm">
          {d.identityConflict && <div className="flex items-start gap-2 rounded-xl bg-amber-500/10 px-3 py-2 text-amber-400"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />{t('legacyAgent.detail.conflict') || 'Identity conflict: the serial number or the IMEI declared by this agent is held by another managed device.'}</div>}
          <div className="rounded-xl bg-bg-secondary py-1">
            {row(t('legacyAgent.detail.agentId') || 'Agent', d.agentId)}
            {row(t('legacyAgent.cols.model') || 'Model', d.modelName ?? '—')}
            {row(t('legacyAgent.detail.serial') || 'Serial number', d.serialNumber ?? '—')}
            {row(t('legacyAgent.detail.samsungSerial') || 'Samsung serial', d.samsungSerial ?? '—')}
            {row(t('legacyAgent.detail.claimedSerial') || 'Build serial', d.claimedSerial ?? '—')}
            {row('IMEI', d.imeis.join(', ') || '—')}
            {row(t('legacyAgent.detail.androidId') || 'Android ID', d.androidId ?? '—')}
            {row(t('legacyAgent.detail.keyStorage') || 'Key storage', d.keyStorage)}
            {row(t('legacyAgent.cols.knox') || 'Knox', `${t(`legacyAgent.knox.${d.knoxState}`) || d.knoxState}${d.knoxInfo?.version ? ` (${String(d.knoxInfo.version)})` : ''}`)}
            {row(t('legacyAgent.detail.clock') || 'Clock offset', d.clockOffsetSeconds === null ? '—' : `${d.clockOffsetSeconds} s`)}
            {row(t('legacyAgent.cols.lastPoll') || 'Last interrogation', fmt(d.lastPollAt))}
            {row(t('legacyAgent.detail.lastInventory') || 'Last inventory', fmt(d.lastInventoryAt))}
            {row(t('legacyAgent.detail.enrolledAt') || 'Enrolled', fmt(d.enrolledAt))}
          </div>
          <div>
            <h3 className={cardTitleCls}>{t('legacyAgent.detail.status') || 'Status'}</h3>
            <div className="rounded-xl bg-bg-secondary py-1">{d.status.map((s) => row(s.item, `${JSON.stringify(s.value)} · ${fmt(s.observedAt)}`))}</div>
          </div>
          <div>
            <h3 className={cardTitleCls}>{t('legacyAgent.detail.queue') || 'Commands'}</h3>
            <div className={listCls}>
            <table className="w-full text-xs">
              <tbody>
                {cmds.map((c) => (
                  <tr key={c.id} className={rowCls}>
                    <td className="px-3 py-1.5 font-mono text-text-primary">{c.type}</td>
                    <td className="px-3 py-1.5 text-text-secondary">{t(`legacyAgent.state.${c.state}`) || c.state}{c.holdReason ? ` (${c.holdReason})` : ''}</td>
                    <td className="px-3 py-1.5 text-text-muted">{c.resultCode ?? ''}</td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-text-muted">{fmt(c.createdAt)}</td>
                    <td className="px-3 py-1.5 text-right">{c.state === 'pending' && !c.guardActionUuid && (
                      <Button variant="ghost" title={t('legacyAgent.cancel') || 'Cancel'} onClick={() => void cancel(c)}><XCircle size={12} /></Button>)}</td>
                  </tr>
                ))}
                {cmds.length === 0 && <tr><td className="px-3 py-3 text-center text-text-muted">{t('legacyAgent.detail.noCommand') || 'No command.'}</td></tr>}
              </tbody>
            </table>
            </div>
          </div>
          <div>
            <h3 className={cardTitleCls}>{t('legacyAgent.detail.apps', { count: d.apps.length }) || `Apps (${d.apps.length})`}</h3>
            <div className="max-h-64 overflow-y-auto rounded-xl bg-bg-secondary py-1 text-xs">
              {d.apps.map((a) => (
                <div key={a.packageName} className="group flex items-center justify-between gap-3 px-3 py-1 transition-colors hover:bg-bg-tertiary">
                  <span>{a.label ?? a.packageName}<span className="text-text-muted"> {a.packageName}</span></span>
                  <span className="flex items-center gap-2">
                    {a.versionName ?? ''}{a.managed ? ' ●' : ''}
                    {!a.system && (
                      <button type="button" className="rounded p-0.5 text-text-muted opacity-0 transition-opacity hover:text-accent group-hover:opacity-100"
                        title={t('legacyAgent.pull.button') || 'Get the APK from this device'} onClick={() => void pull(a.packageName)}>
                        <Download className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}

// ── Tokens ───────────────────────────────────────────────────────────────────

/** A script or a value to copy into MobiControl. */
function ScriptBlock({ title, value, rows }: { title: string; value: string; rows: number }) {
  const { t } = useTranslation();
  return (
    <div>
      <div className="flex items-center justify-between"><span className="text-xs font-medium text-text-muted">{title}</span>
        <Button variant="ghost" onClick={() => void copy(value, t('legacyAgent.copied') || 'Copied')}><Copy size={14} /></Button></div>
      <textarea readOnly className={`${fieldCls} font-mono text-xs`} rows={rows} value={value} />
    </div>
  );
}

/** Lot ADM: the MobiControl Lockdown keeps the ACTIVATE button from working, `_adminmode on` suspends it and
 *  `_adminmode off` goes on its own, once the Devices tab shows the administrator active. */
function AdminModeNote() {
  const { t } = useTranslation();
  return (
    <div className="space-y-1 text-xs text-text-muted">
      <p>{t('legacyAgent.adminMode.intro') || 'The MobiControl Lockdown keeps the ACTIVATE button of the Android screen from activating the administrator: the enrollment and activation scripts first suspend it with _adminmode on.'}</p>
      <p className="text-amber-600">{t('legacyAgent.adminMode.note') || 'Send _adminmode off on its own, once the administrator is active (the Devices tab shows Admin active for each device). Until then the phone is in administrator mode, out of the Lockdown.'}</p>
    </div>
  );
}

function TokensTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [rows, setRows] = useState<LegacyAgentTokenView[] | null>(null);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [form, setForm] = useState({ label: '', groupId: '', days: String(LEGACY_AGENT_TOKEN_BOUNDS.daysDefault), maxUses: String(LEGACY_AGENT_TOKEN_BOUNDS.maxUsesDefault) });
  const [created, setCreated] = useState<LegacyAgentTokenCreated | null>(null);
  const [knoxSet, setKnoxSet] = useState<boolean | null>(null);
  const [knox, setKnox] = useState('');
  const load = useCallback(() => { legacyAgentApi.tokens().then(setRows).catch((err) => { setRows([]); fail(err); }); }, []);
  useEffect(() => {
    load();
    groupsApi.list().then(setGroups).catch(() => setGroups([]));
    legacyAgentApi.settings().then((s) => setKnoxSet(s.knoxLicenseSet)).catch(() => setKnoxSet(null));
  }, [load]);
  const create = async () => {
    try {
      const r = await legacyAgentApi.createToken({ label: form.label, groupId: form.groupId ? Number(form.groupId) : null, days: Number(form.days), maxUses: Number(form.maxUses) });
      setCreated(r);
      setForm((f) => ({ ...f, label: '' }));
      load();
    } catch (err) { fail(err); }
  };
  const revoke = async (r: LegacyAgentTokenView) => {
    if (!(await confirm({ message: t('legacyAgent.tokens.confirmRevoke', { label: r.label }) || `Revoke the token ${r.label}?`, danger: true }))) return;
    try { await legacyAgentApi.revokeToken(r.id); load(); } catch (err) { fail(err); }
  };
  const saveKnox = async (value: string | null) => {
    try { const s = await legacyAgentApi.setKnoxLicense(value); setKnoxSet(s.knoxLicenseSet); setKnox(''); toast.success(t('legacyAgent.knox.saved') || 'Knox licence saved'); } catch (err) { fail(err); }
  };
  return (
    <div className="space-y-4">
      <div className={clsx(cardCls, 'grid gap-3 text-sm md:grid-cols-5')}>
        <label className={labelCls}>{t('legacyAgent.tokens.label') || 'Label'}<input className={fieldCls} maxLength={100} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder={t('legacyAgent.tokens.labelHint') || 'Wave 1'} /></label>
        <label className={labelCls}>{t('legacyAgent.tokens.group') || 'Group'}
          <select className={fieldCls} value={form.groupId} onChange={(e) => setForm({ ...form, groupId: e.target.value })}>
            <option value="">—</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select></label>
        <label className={labelCls}>{t('legacyAgent.tokens.days') || 'Validity (days)'}<input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.daysMax} value={form.days} onChange={(e) => setForm({ ...form, days: e.target.value })} /></label>
        <label className={labelCls}>{t('legacyAgent.tokens.maxUses') || 'Quota'}<input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax} value={form.maxUses} onChange={(e) => setForm({ ...form, maxUses: e.target.value })} /></label>
        <div className="flex items-end"><Button onClick={() => void create()} disabled={!form.label.trim()}><Plus className="mr-1 h-4 w-4" />{t('legacyAgent.tokens.create') || 'New token'}</Button></div>
      </div>
      <div className={listCls}>
      <table className="w-full text-sm">
        <thead className={headCls}><tr>
          <th className={thCls}>{t('legacyAgent.tokens.label') || 'Label'}</th><th className={thCls}>{t('legacyAgent.tokens.uses') || 'Uses'}</th>
          <th className={thCls}>{t('legacyAgent.tokens.expires') || 'Expires'}</th><th className={thCls}>{t('legacyAgent.tokens.state') || 'State'}</th><th className="w-12" />
        </tr></thead>
        <tbody>
          {(rows ?? []).map((r) => (
            <tr key={r.id} className={rowCls}>
              <td className={clsx(tdCls, 'font-medium text-text-primary')}>{r.label}</td><td className={clsx(tdCls, 'tabular-nums text-text-secondary')}>{r.uses} / {r.maxUses}</td>
              <td className={clsx(tdCls, 'text-text-secondary')}>{fmt(r.expiresAt)}</td>
              <td className={tdCls}><Flag tone={r.state === 'active' ? 'green' : 'gray'} text={t(`legacyAgent.tokens.states.${r.state}`) || r.state} /></td>
              <td className="py-2.5 pr-3 text-right">{r.state === 'active' && (
                <button type="button" title={t('legacyAgent.tokens.revoke') || 'Revoke'} onClick={() => void revoke(r)} className="rounded p-1 text-text-muted transition-colors hover:bg-bg-hover hover:text-red-400"><Ban className="h-4 w-4" /></button>)}</td>
            </tr>
          ))}
          {rows && rows.length === 0 && <tr><td colSpan={5} className="p-8 text-center text-text-muted">{t('legacyAgent.tokens.empty') || 'No token yet.'}</td></tr>}
        </tbody>
      </table>
      </div>
      <div className={clsx(cardCls, 'space-y-3 text-sm')}>
        <h3 className={cardTitleCls}><ShieldOff size={14} /> {t('legacyAgent.adminMode.title') || 'Device administrator and MobiControl Lockdown'}</h3>
        <AdminModeNote />
        <ScriptBlock title={t('legacyAgent.adminMode.activateScript') || 'Activation script (device already enrolled, administrator off)'} value={LEGACY_AGENT_ACTIVATE_SCRIPT} rows={2} />
        <ScriptBlock title={t('legacyAgent.adminMode.adminOffScript') || 'Return script (_adminmode off)'} value={LEGACY_AGENT_ADMIN_OFF_SCRIPT} rows={1} />
      </div>
      <div className={clsx(cardCls, 'text-sm')}>
        <h3 className={cardTitleCls}><KeyRound size={14} /> {t('legacyAgent.knox.title') || 'Knox licence'}</h3>
        <p className="text-xs text-text-muted">{knoxSet ? (t('legacyAgent.knox.set') || 'A licence key is set (sealed; never shown again).') : (t('legacyAgent.knox.unset') || 'No licence key: the agents work without Knox (no silent installation, no restart).')}</p>
        <div className="mt-2 flex gap-2">
          <input className={fieldCls} value={knox} onChange={(e) => setKnox(e.target.value)} placeholder={t('legacyAgent.knox.placeholder') || 'Licence key'} autoComplete="off" />
          <Button onClick={() => void saveKnox(knox.trim())} disabled={knox.trim().length < 8}>{t('common.save') || 'Save'}</Button>
          {knoxSet && <Button variant="ghost" onClick={() => void saveKnox(null)}>{t('legacyAgent.knox.remove') || 'Remove'}</Button>}
        </div>
      </div>
      {created && (
        <Modal open onClose={() => setCreated(null)} size="xl" title={t('legacyAgent.tokens.createdTitle') || 'Token created: copy it now'}>
          <div className="space-y-3 text-sm">
            <p className="text-amber-600">{t('legacyAgent.tokens.onceWarning') || 'The token, the configuration and the script are shown only once.'}</p>
            <ScriptBlock title={t('legacyAgent.tokens.script') || 'MobiControl script (after installation)'} value={created.script} rows={3} />
            <AdminModeNote />
            <ScriptBlock title={t('legacyAgent.adminMode.adminOffScript') || 'Return script (_adminmode off)'} value={created.adminOffScript} rows={1} />
            {[
              [t('legacyAgent.tokens.config') || 'Encoded configuration (extra "config")', created.config],
              [t('legacyAgent.tokens.configJson') || 'Configuration file (obligarth-agent.json)', created.configJson],
              [t('legacyAgent.tokens.token') || 'Token', created.token],
            ].map(([title, value]) => <ScriptBlock key={title} title={title} value={value} rows={value === created.token ? 1 : 3} />)}
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── Packages ─────────────────────────────────────────────────────────────────

function PackagesTab() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<LegacyAgentPackageView[] | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [meta, setMeta] = useState({ packageName: '', versionCode: '', versionName: '', signerSha256: '', label: '' });
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { legacyAgentApi.packages().then(setRows).catch((err) => { setRows([]); fail(err); }); }, []);
  useEffect(() => { load(); }, [load]);
  const upload = async () => {
    if (!file) return;
    setBusy(true);
    try {
      await legacyAgentApi.uploadPackage(file, { packageName: meta.packageName.trim(), versionCode: meta.versionCode.trim(), versionName: meta.versionName.trim() || undefined,
        signerSha256: meta.signerSha256.trim() || undefined, label: meta.label.trim() || undefined });
      toast.success(t('legacyAgent.packages.uploaded') || 'Package uploaded');
      setFile(null);
      load();
    } catch (err) { fail(err); } finally { setBusy(false); }
  };
  const field = (k: keyof typeof meta, label: string, ph = '') => (
    <label className={labelCls}>{label}<input className={fieldCls} value={meta[k]} placeholder={ph} onChange={(e) => setMeta({ ...meta, [k]: e.target.value })} /></label>
  );
  return (
    <div className="space-y-4">
      <div className={clsx(cardCls, 'grid gap-3 text-sm md:grid-cols-3')}>
        <div><span className={labelCls}>{t('legacyAgent.packages.file') || 'APK'}</span>
          <FilePick accept=".apk,application/vnd.android.package-archive" file={file} label={t('legacyAgent.packages.chooseApk') || 'Choose an APK'} onPick={setFile} /></div>
        {field('packageName', t('legacyAgent.packages.packageName') || 'Package name', 'com.example.app')}
        {field('versionCode', t('legacyAgent.packages.versionCode') || 'versionCode', '42')}
        {field('versionName', t('legacyAgent.packages.versionName') || 'Version name', '4.2')}
        {field('signerSha256', t('legacyAgent.packages.signer') || 'Signer SHA-256 (optional)')}
        {field('label', t('legacyAgent.packages.label') || 'Label')}
        <div className="flex items-end"><Button onClick={() => void upload()} disabled={busy || !file || !meta.packageName || !meta.versionCode}><Upload className="mr-1 h-4 w-4" />{t('legacyAgent.packages.upload') || 'Upload'}</Button></div>
      </div>
      <div className={listCls}>
      <table className="w-full text-sm">
        <thead className={headCls}><tr>
          <th className={thCls}>{t('legacyAgent.packages.label') || 'Label'}</th><th className={thCls}>{t('legacyAgent.packages.packageName') || 'Package name'}</th>
          <th className={thCls}>{t('legacyAgent.packages.version') || 'Version'}</th><th className={thCls}>SHA-256</th><th className={thCls}>{t('legacyAgent.packages.size') || 'Size'}</th>
        </tr></thead>
        <tbody>{(rows ?? []).map((p) => (
          <tr key={p.id} className={rowCls}>
            <td className={clsx(tdCls, 'font-medium text-text-primary')}>{p.label ?? '—'}</td><td className={clsx(tdCls, 'font-mono text-xs text-text-secondary')}>{p.packageName}</td>
            <td className={clsx(tdCls, 'text-text-secondary')}>{p.versionName ?? ''} <span className="text-xs text-text-muted">({p.versionCode})</span></td>
            <td className={clsx(tdCls, 'font-mono text-xs text-text-muted')}>{p.sha256.slice(0, 16)}…</td><td className={clsx(tdCls, 'text-text-secondary')}>{t('legacyAgent.packages.mib', { size: (p.sizeBytes / 1048576).toFixed(1) }) || `${(p.sizeBytes / 1048576).toFixed(1)} MiB`}</td>
          </tr>))}
          {rows && rows.length === 0 && <tr><td colSpan={5} className="p-8 text-center text-text-muted">{t('legacyAgent.packages.empty') || 'No package yet.'}</td></tr>}
        </tbody>
      </table>
      </div>
    </div>
  );
}

// ── Platform (master tenant, platform administrators) ───────────────────────

function PlatformTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [releases, setReleases] = useState<LegacyAgentReleaseView[]>([]);
  const [settings, setSettings] = useState<LegacyAgentInstanceSettings | null>(null);
  const [key, setKey] = useState<LegacyAgentServerKeyView | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [meta, setMeta] = useState({ versionCode: '', versionName: '', signerSha256: '', notes: '' });
  const load = useCallback(() => {
    legacyAgentApi.admin.releases().then(setReleases).catch(fail);
    legacyAgentApi.admin.settings().then(setSettings).catch(fail);
    legacyAgentApi.admin.serverKey().then(setKey).catch(fail);
  }, []);
  useEffect(() => { load(); }, [load]);
  const addRelease = async () => {
    if (!file) return;
    try {
      const staged = await legacyAgentApi.admin.uploadRelease(file);
      await legacyAgentApi.admin.createRelease({ sha256: staged.sha256, versionCode: Number(meta.versionCode), versionName: meta.versionName.trim(),
        signerSha256: meta.signerSha256.trim(), ...(meta.notes.trim() ? { notes: meta.notes.trim() } : {}) });
      toast.success(t('legacyAgent.releases.added') || 'Version added');
      setFile(null);
      load();
    } catch (err) { fail(err); }
  };
  const withdraw = async (r: LegacyAgentReleaseView) => {
    if (!(await confirm({ message: t('legacyAgent.releases.confirmWithdraw', { version: r.versionName }) || `Withdraw the version ${r.versionName}?`, danger: true }))) return;
    try { await legacyAgentApi.admin.withdraw(r.id); load(); } catch (err) { fail(err); }
  };
  const exportKey = async () => {
    if (!(await confirm({ message: t('legacyAgent.serverKey.confirmExport') || 'Export the instance key for the escrow? It can be exported only once.', danger: true }))) return;
    try { const r = await legacyAgentApi.admin.exportServerKey(); setExported(r.pkcs8); load(); } catch (err) { fail(err); }
  };
  const saveSettings = async (patch: Partial<LegacyAgentInstanceSettings>) => {
    try { setSettings(await legacyAgentApi.admin.saveSettings(patch)); toast.success(t('common.saved') || 'Saved'); } catch (err) { fail(err); }
  };
  const signers = useMemo(() => settings?.signers ?? [], [settings]);
  return (
    <div className="space-y-5 text-sm">
      <section className={cardCls}>
        <h3 className={cardTitleCls}>{t('legacyAgent.serverKey.title') || 'Instance key (to pin in the APK)'}</h3>
        {key && (key.missing
          ? <p className="text-red-500">{t('legacyAgent.serverKey.missing') || 'The instance key is missing from the vault: restore the escrowed key.'}</p>
          : (<>
            <div className="font-mono text-xs break-all">SHA-256 : {key.spkiSha256}</div>
            <div className="font-mono text-xs break-all">keyId : {key.keyId}</div>
            <div className="mt-1 flex items-center gap-2">
              <Button variant="ghost" onClick={() => void copy(key.spkiSha256, t('legacyAgent.copied') || 'Copied')}><Copy className="mr-1 h-4 w-4" />{t('legacyAgent.serverKey.copyPin') || 'Copy the fingerprint'}</Button>
              {key.exportedAt ? <span className="text-xs text-text-muted">{t('legacyAgent.serverKey.exportedAt', { at: fmt(key.exportedAt) }) || `Exported on ${fmt(key.exportedAt)}`}</span>
                : <Button variant="danger" onClick={() => void exportKey()}>{t('legacyAgent.serverKey.export') || 'Export for escrow'}</Button>}
            </div>
          </>))}
        {exported && (
          <div className="mt-2">
            <p className="text-amber-600">{t('legacyAgent.serverKey.exportWarning') || 'PKCS#8 private key (base64): store it with the APK signing key, now. It will not be shown again.'}</p>
            <textarea readOnly className={`${fieldCls} font-mono text-xs`} rows={3} value={exported} />
          </div>
        )}
      </section>
      <section className={cardCls}>
        <h3 className={cardTitleCls}>{t('legacyAgent.releases.title') || 'Versions of the agent'}</h3>
        <p className="text-xs text-text-muted">{signers.length > 0 ? `LEGACY_AGENT_SIGNERS : ${signers.map((s) => s.slice(0, 12)).join(', ')}…`
          : (t('legacyAgent.releases.noSigners') || 'LEGACY_AGENT_SIGNERS is empty: no version can be added.')}</p>
        {settings?.bundle && <BundleLine bundle={settings.bundle} />}
        <div className="mt-3 grid gap-3 md:grid-cols-5">
          <div><span className={labelCls}>{t('legacyAgent.packages.file') || 'APK'}</span>
            <FilePick accept=".apk" file={file} label={t('legacyAgent.packages.chooseApk') || 'Choose an APK'} onPick={setFile} /></div>
          <label className={labelCls}>versionCode<input className={fieldCls} value={meta.versionCode} onChange={(e) => setMeta({ ...meta, versionCode: e.target.value })} /></label>
          <label className={labelCls}>{t('legacyAgent.packages.versionName') || 'Version name'}<input className={fieldCls} value={meta.versionName} onChange={(e) => setMeta({ ...meta, versionName: e.target.value })} /></label>
          <label className={labelCls}>{t('legacyAgent.releases.signer') || 'Signer SHA-256'}<input className={fieldCls} value={meta.signerSha256} onChange={(e) => setMeta({ ...meta, signerSha256: e.target.value })} /></label>
          <div className="flex items-end"><Button onClick={() => void addRelease()} disabled={!file || !meta.versionCode || !meta.versionName || !meta.signerSha256}><Upload className="mr-1 h-4 w-4" />{t('legacyAgent.releases.add') || 'Add'}</Button></div>
        </div>
        <div className="mt-3 overflow-x-auto rounded-xl bg-bg-tertiary/40">
        <table className="w-full">
          <tbody>{releases.map((r) => (
            <tr key={r.id} className={rowCls}>
              <td className={clsx(tdCls, 'font-medium text-text-primary')}>{r.versionName} <span className="text-xs text-text-muted">({r.versionCode})</span></td><td className={clsx(tdCls, 'font-mono text-xs text-text-muted')}>{r.sha256.slice(0, 16)}…</td>
              <td className={clsx(tdCls, 'text-xs text-text-muted')}>{r.bundledIn ? bundledLabel(t, r.bundledIn) : (t('legacyAgent.releases.uploaded') || 'Uploaded')}</td>
              <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-secondary')}>{fmt(r.createdAt)}</td>
              <td className="py-2.5 pr-3 text-right">{r.withdrawnAt ? <span className="text-xs text-text-muted">{t('legacyAgent.releases.withdrawn') || 'Withdrawn'}</span> : (
                <button type="button" title={t('legacyAgent.releases.withdraw') || 'Withdraw'} onClick={() => void withdraw(r)} className="rounded p-1 text-text-muted transition-colors hover:bg-bg-hover hover:text-red-400"><Ban className="h-4 w-4" /></button>)}</td>
            </tr>))}
          </tbody>
        </table>
        </div>
      </section>
      {settings && (
        <section className={cardCls}>
          <h3 className={cardTitleCls}>{t('legacyAgent.settings.title') || 'Instance settings'}</h3>
          <SettingsForm settings={settings} onSave={saveSettings} />
          <p className="mt-1 text-xs text-text-muted">MDM_PUBLIC_BASE : {settings.publicBase ?? '—'}</p>
        </section>
      )}
    </div>
  );
}

type TFn = ReturnType<typeof useTranslation>['t'];

/** « Embedded in the image vX » of a version brought by the server image. */
function bundledLabel(t: TFn, image: string): string {
  return t('legacyAgent.releases.bundledIn', { image }) || `Embedded in the image v${image}`;
}

/** What the start of this server found in its image: the version registered, present, withdrawn, or why it was refused. */
function BundleLine({ bundle }: { bundle: NonNullable<LegacyAgentInstanceSettings['bundle']> }) {
  const { t } = useTranslation();
  const image = bundle.imageVersion;
  if (bundle.state === 'absent') {
    return <p className="mt-1 text-xs text-text-muted">{t('legacyAgent.releases.bundle.absent', { image }) || `The image v${image} carries no version of the agent.`}</p>;
  }
  const version = bundle.versionName ? `${bundle.versionName} (${bundle.versionCode})` : '—';
  const fallback: Record<string, string> = {
    registered: `Version ${version} embedded in the image v${image}: registered at start.`,
    present: `Version ${version} embedded in the image v${image}: already registered.`,
    withdrawn: `Version ${version} embedded in the image v${image}: withdrawn, never offered again.`,
    refused: `Version embedded in the image v${image} refused:`,
    storeError: `Version embedded in the image v${image}: not copied to the store of the APKs (full or read-only volume, rights), tried again at the next start.`,
    error: `Version embedded in the image v${image}: not registered (database error), tried again at the next start.`,
  };
  const reason = bundle.reason ? (t(`legacyAgent.releases.bundle.reasons.${bundle.reason}`) || bundle.reason) : '';
  const text = t(`legacyAgent.releases.bundle.${bundle.state}`, { version, image }) || fallback[bundle.state];
  const tone = bundle.state === 'refused' || bundle.state === 'storeError' || bundle.state === 'error' ? 'text-red-500' : 'text-text-muted';
  return <p className={`mt-1 text-xs ${tone}`}>{text}{bundle.state === 'refused' ? ` ${reason}` : ''}</p>;
}

/** The instance settings: one button sends the fields changed (turning the automatic update on, or raising its pace
 *  while on, asks for a second factor: the dialog of the client handles it). */
function SettingsForm({ settings, onSave }: { settings: LegacyAgentInstanceSettings; onSave: (p: Partial<LegacyAgentInstanceSettings>) => Promise<void> }) {
  const { t } = useTranslation();
  const [v, setV] = useState({ pollSeconds: String(settings.pollSeconds), minVersionCode: String(settings.minVersionCode), inventorySeconds: String(settings.inventorySeconds) });
  const [auto, setAuto] = useState({ on: settings.autoUpdate, perHour: String(settings.autoUpdatePerHour) });
  const perHour = Number(auto.perHour);
  const perHourValid = Number.isInteger(perHour) && perHour >= LEGACY_AGENT_AUTO_UPDATE_BOUNDS.min && perHour <= LEGACY_AGENT_AUTO_UPDATE_BOUNDS.max;
  const patch: Partial<LegacyAgentInstanceSettings> = {};
  if (auto.on !== settings.autoUpdate) patch.autoUpdate = auto.on;
  if (perHourValid && perHour !== settings.autoUpdatePerHour) patch.autoUpdatePerHour = perHour;
  for (const k of ['pollSeconds', 'minVersionCode', 'inventorySeconds'] as const) {
    if (Number(v[k]) !== settings[k]) patch[k] = Number(v[k]);
  }
  return (
    <div className="grid gap-3 md:grid-cols-4">
      <div className="flex items-center md:col-span-3">
        <ToggleSwitch checked={auto.on} onChange={(on) => setAuto({ ...auto, on })}
          label={t('legacyAgent.settings.autoUpdate') || 'Update the agents automatically to the version embedded in the server image'} />
      </div>
      <label className={labelCls}>{t('legacyAgent.settings.autoUpdatePerHour') || 'Devices per hour'}<input className={fieldCls} type="number" min={LEGACY_AGENT_AUTO_UPDATE_BOUNDS.min} max={LEGACY_AGENT_AUTO_UPDATE_BOUNDS.max} value={auto.perHour} disabled={!auto.on} onChange={(e) => setAuto({ ...auto, perHour: e.target.value })} /></label>
      <p className="text-xs text-text-muted md:col-span-4">{t('legacyAgent.settings.autoUpdateHint') || 'Every 10 minutes, the enrolled agents older than the latest version embedded in the server image (not withdrawn) get it, in batches: those that install silently (device administrator and Knox licence) first. Only the agents that interrogated in the last 24 hours; a refusal, a failure or an expiry is tried again after 24 hours. An uploaded version is never pushed automatically. A frozen tenant, or a device the restrictions matrix holds for the agent update, gets nothing. Turning it on or raising the pace asks for a second factor.'}</p>
      <label className={labelCls}>{t('legacyAgent.settings.pollSeconds') || 'Interrogation period (s)'}<input className={fieldCls} type="number" min={60} max={3600} value={v.pollSeconds} onChange={(e) => setV({ ...v, pollSeconds: e.target.value })} /></label>
      <label className={labelCls}>{t('legacyAgent.settings.minVersionCode') || 'Minimal versionCode'}<input className={fieldCls} type="number" min={0} value={v.minVersionCode} onChange={(e) => setV({ ...v, minVersionCode: e.target.value })} /></label>
      <label className={labelCls}>{t('legacyAgent.settings.inventorySeconds') || 'Inventory period (s)'}<input className={fieldCls} type="number" min={3600} value={v.inventorySeconds} onChange={(e) => setV({ ...v, inventorySeconds: e.target.value })} /></label>
      <div className="flex items-end"><Button onClick={() => void onSave(patch)} disabled={Object.keys(patch).length === 0 || (auto.on && !perHourValid)}>{t('common.save') || 'Save'}</Button></div>
    </div>
  );
}
