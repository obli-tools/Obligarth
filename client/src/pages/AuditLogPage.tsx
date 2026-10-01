import { useEffect, useState, useCallback, useRef } from 'react';
import { FileText, RefreshCw, Search, Download, Filter, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { clsx } from 'clsx';
import type { AuditActorSide, AuditChainStatus, AuditCriticality, AuditOutcome, User } from '@obligarth/shared';
import { AUDIT_ACTOR_SIDES, AUDIT_CRITICALITIES, AUDIT_OUTCOMES } from '@obligarth/shared';
import { auditApi, type AuditLogRow, type AuditLogFilters } from '@/api/audit.api';
import { usersApi } from '@/api/users.api';
import { TenantBadge } from '@/components/common/TenantBadge';
import { TenantFilterChips } from '@/components/common/TenantFilterChips';
import { useTenantFilter } from '@/hooks/useTenantFilter';
import { useIsMasterTenant } from '@/hooks/useIsMasterTenant';
import { MEDIA, useIsCoarsePointer, useMediaQuery } from '@/hooks/useMediaQuery';
import { useClickOutside } from '@/hooks/useClickOutside';
import { PageContainer } from '@/components/common/PageContainer';
import { TableScroll } from '@/components/common/TableScroll';
import { IconButton } from '@/components/common/IconButton';
import { AuditEntryDrawer } from '@/components/audit/AuditEntryDrawer';
import { AuditStatusBanner } from '@/components/audit/AuditStatusBanner';
import {
  actionLabel, criticalityLabel, CriticalityPill, EntryFlags, errorText, OutcomeText, outcomeLabel, SidePill, sideLabel,
} from '@/components/audit/auditLabels';
import { useAuthStore } from '@/store/authStore';
import { saveBlob } from '@/utils/download';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';

// The tenant's journal (hardened: one hash chain per tenant, sealed every
// hour, exported to the SIEM): who did what, when, on whose behalf, with
// which outcome. Read by the holders of audit.read (tenant administrators,
// the client sets approver and auditor) and the platform administrators,
// who see every chain from the master tenant. Nothing can be deleted from
// here: only the retention job purges. A row opens the entry's detail (body
// as hashed, chain hashes, seal and proof).

const PAGE_SIZE = 50;

function actionCategory(action: string): string {
  const root = action.split('.')[0];
  return root.charAt(0).toUpperCase() + root.slice(1);
}

function targetOf(row: AuditLogRow) {
  if (row.deviceId) {
    return (
      <Link to={`/devices/${row.deviceId}`} onClick={(e) => e.stopPropagation()} className="text-accent hover:underline">
        {row.deviceName || `#${row.deviceId}`}
      </Link>
    );
  }
  if (!row.resourceType) return <span className="text-text-muted">—</span>;
  return row.resourceName ? (
    <span className="inline-flex items-baseline gap-1 max-lg:flex-wrap">
      <span className="text-text-primary">{row.resourceName}</span>
      <span className="text-[10px] text-text-muted font-mono">{row.resourceType}#{row.resourcePath}</span>
    </span>
  ) : (
    <span className="text-text-muted font-mono">{row.resourceType}:{row.resourcePath}</span>
  );
}

export function AuditLogPage({ embedded = false }: { embedded?: boolean } = {}) {
  const { t } = useTranslation();
  const isWide = useMediaQuery(MEDIA.lg);
  const isMaster = useIsMasterTenant();
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');
  // The global view (every chain) opens for platform administrators on the
  // master tenant only; anyone else reads the chain of their tenant.
  const globalView = isMaster && isPlatformAdmin;
  // Global view: single-select tenant chips (one chain at a time, as the
  // export and the verification need one).
  const tenantFilter = useTenantFilter();
  const filterTenantId = globalView && tenantFilter.value.size === 1 ? [...tenantFilter.value][0] : undefined;

  const [items, setItems] = useState<AuditLogRow[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [filters, setFilters] = useState<AuditLogFilters>({ limit: PAGE_SIZE, offset: 0 });
  const [actions, setActions] = useState<string[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<AuditChainStatus | null>(null);
  const [openUuid, setOpenUuid] = useState<string | null>(null);
  const [busy, setBusy] = useState<'verify' | 'jsonl' | 'csv' | null>(null);

  const load = useCallback(async (spinner = true) => {
    if (spinner) setIsLoading(true);
    try {
      const { items, total } = await auditApi.list({ ...filters, filterTenantId });
      setItems(items);
      setTotal(total);
    } catch (err) {
      toast.error(errorText(err, t('audit.loadFailed') || 'Failed to load the journal'));
    } finally {
      if (spinner) setIsLoading(false);
    }
  }, [filters, filterTenantId, t]);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await auditApi.status(filterTenantId));
    } catch {
      setStatus(null);
    }
  }, [filterTenantId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadStatus(); }, [loadStatus]);

  useEffect(() => {
    // Actions present in the chain read (the tenant filter narrows it).
    auditApi.distinctActions(filterTenantId).then(setActions).catch(() => {});
    // Tenant users for the "By user" filter (administrators only: the
    // other readers filter by side instead).
    usersApi.list().then(setUsers).catch(() => setUsers([]));
  }, [filterTenantId]);

  const applySearch = () => setFilters({ ...filters, search: search.trim() || undefined, offset: 0 });
  const clearFilters = () => {
    setSearch('');
    setFilters({ limit: PAGE_SIZE, offset: 0 });
  };

  const verify = async () => {
    setBusy('verify');
    try {
      await auditApi.verify(filterTenantId);
      toast.success(t('audit.verifyStarted') || 'Integrity check started: the result appears above in a moment');
      setTimeout(() => { loadStatus(); }, 3000);
    } catch (err) {
      toast.error(errorText(err, t('audit.verifyFailed') || 'Integrity check not started'));
    } finally {
      setBusy(null);
    }
  };

  const exportAs = async (format: 'jsonl' | 'csv') => {
    setBusy(format);
    try {
      const { blob, filename } = await auditApi.export(format, filterTenantId);
      const ok = await saveBlob(blob, filename, format === 'csv' ? 'text/csv' : 'application/x-ndjson');
      if (!ok) toast.error(t('common.error') || 'Error');
    } catch (err) {
      toast.error(errorText(err, t('audit.exportFailed') || 'Export failed'));
    } finally {
      setBusy(null);
    }
  };

  const page = Math.floor((filters.offset ?? 0) / (filters.limit ?? PAGE_SIZE)) + 1;
  const pages = Math.max(1, Math.ceil(total / (filters.limit ?? PAGE_SIZE)));
  // An export or a check is about one chain: in the global view, a tenant
  // must be chosen.
  const oneChain = !globalView || filterTenantId !== undefined;

  const groupedActions: Record<string, string[]> = {};
  for (const a of actions) {
    const root = a.split('.')[0];
    if (!groupedActions[root]) groupedActions[root] = [];
    groupedActions[root].push(a);
  }

  const th = 'px-2 py-1.5 text-left text-[10px] uppercase text-text-muted font-medium';
  const btn = 'flex items-center gap-1.5 text-xs px-2.5 py-1 coarse:px-3 coarse:py-2 rounded text-text-muted hover:text-text-primary transition-colors disabled:opacity-50';

  return (
    <PageContainer embedded={embedded}>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        {!embedded ? (
          <div className="flex items-center gap-3">
            <FileText className="w-6 h-6 text-accent" />
            <div>
              <h1 className="text-xl font-semibold text-text-primary">{t('audit.title') || 'Audit log'}</h1>
              <p className="text-sm text-text-muted">{t('audit.subtitle') || 'Who did what, when, and from where.'}</p>
            </div>
          </div>
        ) : <div />}
        <div className="flex items-center gap-2 coarse:gap-3 flex-wrap">
          <button onClick={verify} disabled={!oneChain || busy !== null} className={btn}
            title={oneChain ? (t('audit.verifyHint') || 'Recompute the chain and check its seals') : (t('audit.chooseTenant') || 'Choose one tenant first')}>
            <ShieldCheck className="w-3.5 h-3.5" /> {t('audit.verify') || 'Verify integrity'}
          </button>
          <button onClick={() => exportAs('jsonl')} disabled={!oneChain || busy !== null} className={btn}
            title={oneChain ? (t('audit.exportJsonlHint') || 'Verifiable export (entries, seals, keys)') : (t('audit.chooseTenant') || 'Choose one tenant first')}>
            <Download className="w-3.5 h-3.5" /> JSONL
          </button>
          <button onClick={() => exportAs('csv')} disabled={!oneChain || busy !== null} className={btn}
            title={oneChain ? (t('audit.exportCsvHint') || 'Readable export (not verifiable)') : (t('audit.chooseTenant') || 'Choose one tenant first')}>
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <IconButton
            label={t('common.refresh')}
            icon={<RefreshCw className="w-4 h-4" />}
            variant="plain"
            onClick={() => { load(true); loadStatus(); }}
            className="hover:border-accent/40"
          />
        </div>
      </div>

      {globalView && (
        <div className="mb-3">
          <TenantFilterChips
            value={tenantFilter.value}
            onChange={(next) => {
              // Single-select: keep only the most recently toggled-on chip.
              if (next.size <= 1) tenantFilter.setValue(next);
              else {
                const previous = tenantFilter.value;
                const added = [...next].find((id) => !previous.has(id));
                tenantFilter.setValue(added ? new Set([added]) : new Set());
              }
            }}
          />
        </div>
      )}

      <AuditStatusBanner status={status} />

      {/* Filters */}
      <div className="flex items-end gap-2 mb-4 flex-wrap">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.filter.search') || 'Search'}</label>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && applySearch()}
              placeholder={t('audit.filter.searchPlaceholder') || 'action, target, author, reason...'}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              enterKeyHint="search"
              className="w-full pl-7 pr-2 py-1.5 coarse:py-2 text-xs bg-bg-secondary rounded text-text-primary"
            />
          </div>
        </div>
        <div>
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.col.action') || 'Action'}</label>
          <select
            value={filters.action || ''}
            onChange={(e) => setFilters({ ...filters, action: e.target.value || undefined, offset: 0 })}
            className="py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary min-w-[180px] max-w-full"
          >
            <option value="">{t('audit.filter.all') || 'All'}</option>
            {Object.entries(groupedActions).map(([root, acts]) => (
              <optgroup key={root} label={actionCategory(root)}>
                <option value={`${root}.`}>{t('audit.filter.allOf', { family: root }) || `All ${root}.*`}</option>
                {acts.map((a) => <option key={a} value={a}>{actionLabel(t, a)}</option>)}
              </optgroup>
            ))}
          </select>
        </div>
        {users.length > 0 && (
          <div>
            <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.col.actor') || 'Author'}</label>
            <UserCombobox
              users={users}
              value={filters.userId ?? null}
              onChange={(id) => setFilters({ ...filters, userId: id ?? undefined, offset: 0 })}
            />
          </div>
        )}
        <div>
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.filter.side') || 'Side'}</label>
          <select
            value={filters.actorSide || ''}
            onChange={(e) => setFilters({ ...filters, actorSide: (e.target.value || undefined) as AuditActorSide | undefined, offset: 0 })}
            className="py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary"
          >
            <option value="">{t('audit.filter.all') || 'All'}</option>
            {AUDIT_ACTOR_SIDES.map((s) => <option key={s} value={s}>{sideLabel(t, s)}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.col.outcome') || 'Outcome'}</label>
          <select
            value={filters.outcome || ''}
            onChange={(e) => setFilters({ ...filters, outcome: (e.target.value || undefined) as AuditOutcome | undefined, offset: 0 })}
            className="py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary"
          >
            <option value="">{t('audit.filter.all') || 'All'}</option>
            {AUDIT_OUTCOMES.map((o) => <option key={o} value={o}>{outcomeLabel(t, o)}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.col.class') || 'Class'}</label>
          <select
            value={filters.criticality || ''}
            onChange={(e) => setFilters({ ...filters, criticality: (e.target.value || undefined) as AuditCriticality | undefined, offset: 0 })}
            className="py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary"
          >
            <option value="">{t('audit.filter.all') || 'All'}</option>
            {AUDIT_CRITICALITIES.map((c) => <option key={c} value={c}>{criticalityLabel(t, c)}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.filter.since') || 'Since'}</label>
          <input
            type="datetime-local"
            value={filters.since?.slice(0, 16) || ''}
            onChange={(e) => setFilters({ ...filters, since: e.target.value ? new Date(e.target.value).toISOString() : undefined, offset: 0 })}
            className="py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary max-w-full"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase text-text-muted mb-0.5">{t('audit.filter.until') || 'Until'}</label>
          <input
            type="datetime-local"
            value={filters.until?.slice(0, 16) || ''}
            onChange={(e) => setFilters({ ...filters, until: e.target.value ? new Date(e.target.value).toISOString() : undefined, offset: 0 })}
            className="py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary max-w-full"
          />
        </div>
        <button
          onClick={applySearch}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 coarse:py-2.5 rounded border border-accent/40 bg-accent/10 text-accent hover:bg-accent/20"
        >
          <Filter className="w-3.5 h-3.5" /> {t('audit.filter.apply') || 'Apply'}
        </button>
        <button onClick={clearFilters} className="text-xs px-2 py-1.5 coarse:px-3 coarse:py-2.5 rounded text-text-muted hover:text-text-primary">
          {t('audit.filter.reset') || 'Reset'}
        </button>
      </div>

      <TableScroll className="rounded bg-bg-secondary" stickyFirstCol={!isWide}>
        {isLoading ? (
          <div className="p-8 text-center text-text-muted text-sm italic">{t('common.loading') || 'Loading...'}</div>
        ) : items.length === 0 ? (
          <div className="p-8 text-center text-text-muted text-sm italic">{t('audit.empty') || 'No entries match your filters.'}</div>
        ) : (
          <table className="w-full border-collapse min-w-[760px]">
            <thead>
              <tr className="bg-bg-primary/40">
                <th className={clsx(th, 'max-lg:[background-image:linear-gradient(rgb(var(--c-bg-primary)/0.4),rgb(var(--c-bg-primary)/0.4))]')}>{t('audit.col.when') || 'When'}</th>
                {globalView && <th className={th}>{t('audit.col.tenant') || 'Tenant'}</th>}
                <th className={th}>{t('audit.col.actor') || 'Author'}</th>
                <th className={th}>{t('audit.col.action') || 'Action'}</th>
                <th className={th}>{t('audit.col.target') || 'Target'}</th>
                <th className={th}>{t('audit.col.outcome') || 'Outcome'}</th>
                <th className={th}>{t('audit.col.class') || 'Class'}</th>
                <th className={th}>{t('audit.col.reason') || 'Reason'}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={row.uuid} className="hover:bg-bg-tertiary/30 cursor-pointer" onClick={() => setOpenUuid(row.uuid)}>
                  <td className="px-2 py-1.5 text-[11px] text-text-muted whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      {new Date(row.occurredAt || row.createdAt).toLocaleString()}
                      <EntryFlags legacy={row.legacy} late={row.late} t={t} />
                    </div>
                  </td>
                  {globalView && (
                    <td className="px-2 py-1.5"><TenantBadge tenantId={row.tenantId} tenantName={row.tenantName ?? undefined} /></td>
                  )}
                  <td className="px-2 py-1.5 text-xs text-text-primary">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="truncate max-w-[160px]" title={row.actor.ref}>{row.actor.displayName || row.actor.label || row.actor.ref}</span>
                      <SidePill side={row.actor.side} t={t} />
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-xs text-text-primary" title={row.action}>
                    {actionLabel(t, row.action)}
                    {row.targetCount !== null && row.targetCount > 1 && (
                      <span className="ml-1 text-[10px] text-text-muted">×{row.targetCount}</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-[11px] max-w-[240px] lg:truncate max-lg:min-w-[160px] max-lg:break-all">{targetOf(row)}</td>
                  <td className="px-2 py-1.5"><OutcomeText outcome={row.outcome} t={t} /></td>
                  <td className="px-2 py-1.5"><CriticalityPill criticality={row.criticality} t={t} /></td>
                  <td className="px-2 py-1.5 text-[11px] text-text-secondary max-w-[220px] lg:truncate" title={[row.reason, row.ticket].filter(Boolean).join(' · ')}>
                    {row.reason || row.ticket ? [row.reason, row.ticket].filter(Boolean).join(' · ') : <span className="text-text-muted">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </TableScroll>

      {total > (filters.limit ?? PAGE_SIZE) && (
        <div className="flex flex-wrap items-center justify-between gap-2 mt-3 text-xs text-text-muted">
          <span>{t('audit.pagination', { total, page, pages }) || `${total} entries · page ${page} of ${pages}`}</span>
          <div className="flex items-center gap-1 coarse:gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setFilters({ ...filters, offset: Math.max(0, (filters.offset ?? 0) - (filters.limit ?? PAGE_SIZE)) })}
              className="px-2 py-1 coarse:px-4 coarse:py-2.5 rounded hover:text-text-primary disabled:opacity-30"
            >
              {t('audit.prev') || 'Previous'}
            </button>
            <button
              disabled={page >= pages}
              onClick={() => setFilters({ ...filters, offset: (filters.offset ?? 0) + (filters.limit ?? PAGE_SIZE) })}
              className="px-2 py-1 coarse:px-4 coarse:py-2.5 rounded hover:text-text-primary disabled:opacity-30"
            >
              {t('audit.next') || 'Next'}
            </button>
          </div>
        </div>
      )}

      <AuditEntryDrawer uuid={openUuid} filterTenantId={filterTenantId} onClose={() => setOpenUuid(null)} />
    </PageContainer>
  );
}

// ── Searchable user combobox ────────────────────────────────────────────────
// The native <select> picks up the OS chrome on some browsers; this one keeps
// the popover inside the theme and filters as the reader types.

function UserCombobox({
  users,
  value,
  onChange,
}: {
  users: User[];
  value: number | null;
  onChange: (id: number | null) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const ref = useRef<HTMLDivElement>(null);
  const selected = users.find((u) => u.id === value) ?? null;
  // No autofocus on touch: the soft keyboard would cover the list.
  const coarse = useIsCoarsePointer();
  useClickOutside(ref, () => setOpen(false), open);

  const q = query.trim().toLowerCase();
  const filtered = users.filter((u) => !q || u.username.toLowerCase().includes(q) || (u.displayName ?? '').toLowerCase().includes(q));
  const anyUser = t('audit.filter.anyUser') || 'Any user';

  return (
    <div ref={ref} className="relative min-w-[160px]">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-2 py-1.5 coarse:py-2 px-2 text-xs bg-bg-secondary rounded text-text-primary hover:border-accent/40"
      >
        <span className="truncate">{selected ? selected.username : anyUser}</span>
        <span className="text-text-muted shrink-0">▾</span>
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1 z-20 w-full max-h-64 overflow-y-auto overscroll-contain bg-bg-secondary rounded shadow-xl">
          <div className="p-1.5 sticky top-0 bg-bg-secondary">
            <input
              autoFocus={!coarse}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('audit.filter.searchUser') || 'Search…'}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              className="w-full px-2 py-1 coarse:py-2 text-xs bg-bg-tertiary rounded text-text-primary focus:outline-none focus:border-accent"
            />
          </div>
          <button
            type="button"
            onClick={() => { onChange(null); setOpen(false); setQuery(''); }}
            className={clsx('w-full text-left px-2.5 py-1.5 coarse:py-3 text-xs hover:bg-bg-tertiary', value === null ? 'text-accent' : 'text-text-muted')}
          >
            {anyUser}
          </button>
          {filtered.length === 0 ? (
            <div className="px-2.5 py-2 text-xs text-text-muted italic">{t('audit.filter.noMatch') || 'No match'}</div>
          ) : filtered.map((u) => (
            <button
              key={u.id}
              type="button"
              onClick={() => { onChange(u.id); setOpen(false); setQuery(''); }}
              className={clsx('w-full text-left px-2.5 py-1.5 coarse:py-3 text-xs hover:bg-bg-tertiary flex items-center gap-1.5', value === u.id ? 'text-accent' : 'text-text-primary')}
            >
              <span className="truncate">{u.username}</span>
              {u.displayName && <span className="text-[10px] text-text-muted truncate">({u.displayName})</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
