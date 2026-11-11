import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { MapPin, Search, SortAsc, SortDesc } from 'lucide-react';
import { isSiteWritePending, type SiteDeviceReason, type SiteDeviceState, type SiteView, type SiteWritePending } from '@obligarth/shared';
import { sitesApi, type SiteAttachOutcome } from '@/api/sites.api';
import { isStepUpHandled } from '@/api/client';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { useDeviceMove } from '@/components/mdm/DeviceMoveChange';
import { anonymize } from '@/utils/anonymize';
import { apiErrorBody, apiErrorMessage } from '@/utils/apiError';

// The building blocks of the sites in the console (lot P1-SITE §2.4): the state of a device of a site (Prêt, À faire,
// Ne répond plus) and what to do about it in plain words, the picker of a site, and the change of site of devices
// followed, when the site has a group, by the guarded move into it (useDeviceMove: the same preview and the same
// second factor or second approver as any move, S12; never a move without them).

export const SITE_STATE_TONE: Record<SiteDeviceState, 'green' | 'amber' | 'red'> = { ready: 'green', todo: 'amber', stale: 'red' };

export const siteStateLabel = (t: TFunction, s: SiteDeviceState): string =>
  s === 'ready' ? (t('sites.state.ready') || 'Ready') : s === 'todo' ? (t('sites.state.todo') || 'To do') : (t('sites.state.stale') || 'Not answering');

export function SiteStateBadge({ state }: { state: SiteDeviceState }) {
  const { t } = useTranslation();
  return <StateBadge tone={SITE_STATE_TONE[state]} label={siteStateLabel(t, state)} />;
}

/** What to do about a reason, as a sentence a store can follow. */
export function reasonSentence(t: TFunction, r: SiteDeviceReason, missing: string[] = []): string {
  switch (r) {
    case 'no_contact': return t('sites.reason.no_contact') || 'The phone has not contacted the server for more than 24 hours: check that it is switched on and connected to the Wi-Fi.';
    case 'agent_too_old': return t('sites.reason.agent_too_old') || 'The Obligarth agent of the phone is too old: update it.';
    case 'admin_inactive': return t('sites.reason.admin_inactive') || 'The management of the phone is not active: open Agent Obligarth on the phone and tap "Activate".';
    case 'low_storage': return t('sites.reason.low_storage') || 'The phone has less than 0.5 GB of free storage: delete photos or unused apps.';
    case 'file_not_created':
      return missing.length
        ? (t('sites.reason.file_not_created_vars', { vars: missing.join(', ') }) || `The file of the store apps is not created: fill in ${missing.join(', ')} on the site or the phone.`)
        : (t('sites.reason.file_not_created') || 'The file of the store apps is not created: a value of the site or of the phone is missing.');
    case 'appconfig_unresolved':
      return missing.length
        ? (t('sites.reason.appconfig_unresolved_vars', { vars: missing.join(', ') }) || `The configuration of a store app is not sent: fill in ${missing.join(', ')} on the site or the phone.`)
        : (t('sites.reason.appconfig_unresolved') || 'The configuration of a store app is not sent: a value of the site or of the phone is missing.');
    default: return r;
  }
}

/** The pastilles of the counts of a site. */
export function SiteCountsPills({ counts, compact = false }: { counts: SiteView['counts']; compact?: boolean }): ReactNode {
  const { t } = useTranslation();
  const pill = (n: number, tone: string, label: string) => (
    <span className={clsx('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium tabular-nums', tone)} title={label}>
      {n}{!compact && <span className="font-normal">{label}</span>}
    </span>
  );
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {pill(counts.ready, counts.ready ? 'bg-green-500/15 text-green-400' : 'bg-bg-tertiary text-text-muted', t('sites.state.ready') || 'Ready')}
      {pill(counts.todo, counts.todo ? 'bg-amber-500/15 text-amber-400' : 'bg-bg-tertiary text-text-muted', t('sites.state.todo') || 'To do')}
      {pill(counts.stale, counts.stale ? 'bg-red-500/15 text-red-400' : 'bg-bg-tertiary text-text-muted', t('sites.state.stale') || 'Not answering')}
    </span>
  );
}

/** The alert of a site whose devices lack the file of the store apps. */
export function FileNotCreatedBadge({ count }: { count: number }) {
  const { t } = useTranslation();
  if (count <= 0) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-[11px] font-medium text-red-400"
      title={t('sites.fileNotCreatedHint') || 'A variable of a file template has no value for these phones: the file is not deposited.'}>
      {t('sites.fileNotCreated', { count }) || `File of the apps not created (${count})`}
    </span>
  );
}

/** A searchable list of the sites of the tenant; `allowNone`: a first entry "No site". */
export function SitePickerDialog({ open, onClose, value, onPick, allowNone = true, title }: {
  open: boolean; onClose: () => void; value: string | null; onPick: (site: SiteView | null) => Promise<void> | void; allowNone?: boolean; title?: string;
}) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [sites, setSites] = useState<SiteView[] | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      sitesApi.list({ q: q.trim() || undefined }).then((r) => { if (!cancelled) setSites(r); }).catch(() => { if (!cancelled) setSites([]); });
    }, 200);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [open, q]);
  useEffect(() => { if (open) setQ(''); }, [open]);
  const pick = async (s: SiteView | null) => {
    setBusy(true);
    try { await onPick(s); } finally { setBusy(false); }
  };
  const rowCls = 'flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm hover:bg-bg-tertiary disabled:opacity-50 coarse:py-2.5';
  return (
    <Modal open={open} onClose={() => { if (!busy) onClose(); }} size="sm" title={title ?? (t('sites.picker.title') || 'Choose the site')}
      footer={<Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>}>
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('sites.searchPlaceholder') || 'Code, name, city…'}
          autoCapitalize="off" spellCheck={false}
          className="w-full rounded-lg bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
      </div>
      <div className="mt-2 max-h-72 space-y-0.5 overflow-auto">
        {allowNone && (
          <button type="button" disabled={busy} onClick={() => { void pick(null); }} className={clsx(rowCls, value === null && 'bg-accent/10')}>
            <span className="text-text-muted">{t('sites.none') || 'No site'}</span>
          </button>
        )}
        {sites === null && <p className="px-2 py-3 text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>}
        {sites?.map((s) => (
          <button key={s.id} type="button" disabled={busy} onClick={() => { void pick(s); }} className={clsx(rowCls, value === s.id && 'bg-accent/10')}>
            <MapPin className="h-3.5 w-3.5 shrink-0 text-text-muted" />
            <span className="font-mono text-xs text-text-muted">{anonymize(s.code)}</span>
            <span className="truncate text-text-primary">{anonymize(s.name)}</span>
            {s.city && <span className="ml-auto truncate text-xs text-text-muted">{anonymize(s.city)}</span>}
          </button>
        ))}
        {sites?.length === 0 && <p className="px-2 py-3 text-sm text-text-muted">{t('sites.empty') || 'No site yet.'}</p>}
      </div>
    </Modal>
  );
}

/**
 * The change of site of devices, then their move into the group of the site when it has one (the guarded move of
 * useDeviceMove: its preview, its confirmation, its second factor or approver). `change` returns what the server did;
 * `dialog` is rendered once by the caller.
 */
export function useSiteChange(onDone?: () => void): {
  change: (op: () => Promise<SiteAttachOutcome>, opts?: { single?: boolean }) => Promise<void>;
  dialog: ReactNode;
} {
  const { t } = useTranslation();
  const move = useDeviceMove(() => onDone?.());
  const change = async (op: () => Promise<SiteAttachOutcome>, opts: { single?: boolean } = {}): Promise<void> => {
    let out: SiteAttachOutcome;
    try {
      out = await op();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
      return;
    }
    // Several phones whose files change: the attachment may be held for a second person (202), nothing applied yet.
    if (pendingSaid(t, out)) { onDone?.(); return; }
    toast.success(t('sites.attached', { count: out.changed.length }) || `${out.changed.length} phone(s) changed site`);
    onDone?.();
    if (out.siteGroupId !== null && out.outsideGroup.length > 0) {
      // The group of the site: the same guarded move as the group dialog of the record (never a move without it).
      await move.request({ deviceIds: out.outsideGroup, groupId: out.siteGroupId, single: opts.single === true && out.outsideGroup.length === 1 });
    }
  };
  return { change, dialog: move.dialog };
}

/** The values of a site as editable rows (key → text). */
export function useValueRows(values: Record<string, string> | undefined): {
  rows: Array<{ key: string; value: string }>;
  setRows: (rows: Array<{ key: string; value: string }>) => void;
  asValues: () => Record<string, string>;
} {
  const initial = useMemo(() => Object.entries(values ?? {}).map(([key, value]) => ({ key, value })), [values]);
  const [rows, setRows] = useState(initial);
  useEffect(() => { setRows(initial); }, [initial]);
  const asValues = () => Object.fromEntries(rows.filter((r) => r.key.trim() && r.value.trim()).map((r) => [r.key.trim(), r.value.trim()]));
  return { rows, setRows, asValues };
}

// ── Writes held for a second person, plans that changed ──────────────────────

/** A write held for a second person (202): said, and true (the caller closes its dialog without applying anything). */
export function pendingSaid(t: TFunction, v: unknown): v is SiteWritePending {
  if (!isSiteWritePending(v)) return false;
  const n = v.policyImpact ?? 0;
  toast.success(t('sites.pendingApproval', { count: n }) || `Sent for approval: a second person must approve it (${n} phone(s) whose files change).`, { duration: 8000 });
  return true;
}

/** The sites changed between the dry run shown and the apply (409 planChanged): the caller shows the plan again. */
export const isPlanChanged = (err: unknown): boolean => apiErrorBody(err)?.code === 'planChanged';

// ── Sortable lists (the model of /devices) ───────────────────────────────────

export type SortOrder = 'asc' | 'desc';

/** The sort of a list: a field and an order; a click on the active field turns the order, on another field sorts it
 *  ascending. */
export function useSort<F extends string>(initial: F, order: SortOrder = 'asc'): {
  sortBy: F; sortOrder: SortOrder; toggle: (f: F) => void;
} {
  const [state, setState] = useState<{ sortBy: F; sortOrder: SortOrder }>({ sortBy: initial, sortOrder: order });
  const toggle = (f: F) => setState((x) => (x.sortBy === f ? { sortBy: f, sortOrder: x.sortOrder === 'asc' ? 'desc' : 'asc' } : { sortBy: f, sortOrder: 'asc' }));
  return { ...state, toggle };
}

/** Compares two values of a sort (texts by the locale, numerically; null last). */
export function compareSort(a: string | number | null, b: string | number | null, order: SortOrder): number {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  const c = typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  return order === 'asc' ? c : -c;
}

/** A sortable column header (as SortLabel of the device table). */
export function SortHeader<F extends string>({ label, field, sortBy, sortOrder, onClick, className }: {
  label: string; field: F; sortBy: F; sortOrder: SortOrder; onClick: (f: F) => void; className?: string;
}) {
  const active = sortBy === field;
  return (
    <button type="button" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onClick(field); }} title={label}
      aria-sort={active ? (sortOrder === 'asc' ? 'ascending' : 'descending') : undefined}
      className={clsx('flex items-center gap-0.5 text-left uppercase tracking-wider transition-colors', active ? 'text-accent' : 'hover:text-text-primary', className)}>
      <span className="truncate">{label}</span>
      {active ? (sortOrder === 'asc' ? <SortAsc className="h-3 w-3 shrink-0" /> : <SortDesc className="h-3 w-3 shrink-0" />)
        : <span className="h-3 w-3 shrink-0 opacity-30">↕</span>}
    </button>
  );
}
