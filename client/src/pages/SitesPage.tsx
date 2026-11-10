import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Archive, ChevronRight, FileUp, FolderOpen, MapPin, Plus, RefreshCw, Search, Smartphone, Wand2 } from 'lucide-react';
import type { SiteImportResult, SitesFromDevicesResult, SiteView } from '@obligarth/shared';
import { SITE_LIMITS, isSiteWritePending } from '@obligarth/shared';
import { sitesApi } from '@/api/sites.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { FileNotCreatedBadge, SiteCountsPills, SortHeader, compareSort, isPlanChanged, pendingSaid, useSort } from '@/components/sites/siteUi';
import { SiteEditDialog } from '@/components/sites/SiteEditDialog';
import { anonymize } from '@/utils/anonymize';
import { apiErrorBody, apiErrorMessage, trCode } from '@/utils/apiError';

// The sites of the tenant (lot P1-SITE §2.4), on the model of /devices: a search, the pastilles of the state of the
// phones (Prêt, À faire, Ne répond plus: the rules of the inventory of 01/11), the alert of the file of the store apps
// not created, and for devices.manage: a new site, the import of a CSV file (a dry run first, then applied), the sites
// made from the custom fields of the phones (a dry run first). The tiles filter the list (Prêt: the sites whose phones
// are all ready), its headers sort it. An apply sends back the digest of the dry run shown: the sites changed meanwhile,
// the plan is shown again; a write held for a second person is said (202).

type Focus = 'all' | 'ready' | 'todo' | 'stale' | 'file';
type SortField = 'code' | 'name' | 'city' | 'group' | 'phones' | 'todo' | 'stale';

const sortValue = (s: SiteView, f: SortField): string | number | null => {
  switch (f) {
    case 'code': return s.code;
    case 'name': return s.name;
    case 'city': return s.city;
    case 'group': return s.groupName;
    case 'phones': return s.counts.devices;
    case 'todo': return s.counts.todo;
    case 'stale': return s.counts.stale;
    default: return null;
  }
};

const chipCls = (active: boolean) => clsx('flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full transition-colors coarse:py-2',
  active ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary');

/** The message of a refused import: its reason (importRefused details.reason) translated first. */
export function importErrorMessage(err: unknown): string {
  const d = apiErrorBody(err)?.details as { reason?: unknown; column?: unknown } | undefined;
  if (typeof d?.reason === 'string' && /^[a-z_]+$/.test(d.reason)) {
    const why = trCode(`sites.importRefused.${d.reason}`, '');
    if (why) return typeof d.column === 'string' && d.column ? `${why} (${d.column})` : why;
  }
  return apiErrorMessage(err);
}

export function SitesPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('devices.manage');
  const [q, setQ] = useState('');
  const [archived, setArchived] = useState(false);
  const [focus, setFocus] = useState<Focus>('all');
  const [sites, setSites] = useState<SiteView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [fromDevicesOpen, setFromDevicesOpen] = useState(false);
  const sort = useSort<SortField>('code');

  const load = useCallback(() => {
    sitesApi.list({ q: q.trim() || undefined, archived })
      .then((r) => { setSites(r); setError(null); })
      .catch((err) => { setSites([]); setError(apiErrorMessage(err)); });
  }, [q, archived]);
  useEffect(() => {
    const timer = setTimeout(load, 200);
    return () => clearTimeout(timer);
  }, [load]);

  const totals = useMemo(() => (sites ?? []).reduce((a, s) => ({
    devices: a.devices + s.counts.devices, ready: a.ready + s.counts.ready, todo: a.todo + s.counts.todo, stale: a.stale + s.counts.stale,
    file: a.file + (s.counts.fileNotCreated > 0 ? 1 : 0),
  }), { devices: 0, ready: 0, todo: 0, stale: 0, file: 0 }), [sites]);
  const shown = useMemo(() => (sites ?? [])
    .filter((s) => focus === 'all' || (focus === 'ready' && s.counts.devices > 0 && s.counts.ready === s.counts.devices)
      || (focus === 'todo' && s.counts.todo > 0) || (focus === 'stale' && s.counts.stale > 0) || (focus === 'file' && s.counts.fileNotCreated > 0))
    .sort((a, b) => compareSort(sortValue(a, sort.sortBy), sortValue(b, sort.sortBy), sort.sortOrder) || a.code.localeCompare(b.code)),
  [sites, focus, sort.sortBy, sort.sortOrder]);
  const header = (f: SortField, label: string, className?: string) => (
    <SortHeader field={f} label={label} sortBy={sort.sortBy} sortOrder={sort.sortOrder} onClick={sort.toggle} className={className} />
  );

  const tile = (id: Focus, label: string, value: number, tone: string) => (
    <button type="button" onClick={() => setFocus(focus === id ? 'all' : id)}
      className={clsx('rounded-xl bg-bg-secondary p-3 text-left transition-colors hover:bg-bg-tertiary', focus === id && 'ring-2 ring-accent/50')}>
      <span className="block text-[10px] uppercase tracking-wider text-text-muted">{label}</span>
      <span className={clsx('mt-1 block text-2xl font-semibold tabular-nums', tone)}>{value}</span>
    </button>
  );

  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('sites.title') || 'Sites'}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('sites.subtitle') || 'Where the phones are, and the values of each site their files are made with.'}</p>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {tile('ready', t('sites.kpi.ready') || 'Phones ready', totals.ready, 'text-green-400')}
        {tile('todo', t('sites.kpi.todo') || 'Phones to look after', totals.todo, totals.todo ? 'text-amber-400' : 'text-text-primary')}
        {tile('stale', t('sites.kpi.stale') || 'Phones not answering', totals.stale, totals.stale ? 'text-red-400' : 'text-text-primary')}
        {tile('file', t('sites.kpi.file') || 'Sites without the file of the apps', totals.file, totals.file ? 'text-red-400' : 'text-text-primary')}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[200px] max-w-sm flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('sites.searchPlaceholder') || 'Code, name, city…'}
            autoCapitalize="off" spellCheck={false}
            className="w-full rounded-lg bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
        </div>
        <button type="button" onClick={() => setArchived(!archived)} className={chipCls(archived)} aria-pressed={archived}>
          <Archive className="h-3 w-3" />{t('sites.showArchived') || 'Archived sites'}
        </button>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="h-4 w-4" />
        </button>
        {canManage && (
          <span className="ml-auto flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => setFromDevicesOpen(true)}>
              <Wand2 className="mr-1 h-4 w-4" />{t('sites.fromDevices.open') || 'From the phones\' fields'}
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setImportOpen(true)}>
              <FileUp className="mr-1 h-4 w-4" />{t('sites.import.open') || 'Import a CSV'}
            </Button>
            <Button size="sm" onClick={() => setCreating(true)}><Plus className="mr-1 h-4 w-4" />{t('sites.new') || 'New site'}</Button>
          </span>
        )}
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}

      {sites === null ? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
        : shown.length === 0 ? (
          <div className="rounded-xl bg-bg-secondary p-10 text-center text-text-muted">
            {sites.length === 0 ? (t('sites.empty') || 'No site yet.') : (t('sites.noneMatch') || 'No site matches.')}
          </div>
        ) : (
          <div className="rounded-xl bg-bg-secondary py-1">
            <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto_auto] gap-3 px-4 py-2 text-[10px] uppercase tracking-wider text-text-muted md:grid">
              <span className="flex min-w-0 items-center gap-3">{header('code', t('sites.columns.code') || 'Code')}{header('name', t('sites.columns.site') || 'Site')}</span>
              {header('city', t('sites.columns.city') || 'City')}
              {header('group', t('sites.columns.group') || 'Group')}
              <span className="flex items-center gap-3">
                {header('phones', t('sites.columns.phones') || 'Phones')}
                {header('todo', t('sites.state.todo') || 'To do')}
                {header('stale', t('sites.state.stale') || 'Not answering')}
              </span>
              <span />
            </div>
            {shown.map((s) => (
              <Link key={s.id} to={`/sites/${s.id}`}
                className="grid grid-cols-1 items-center gap-1 px-4 py-2.5 transition-colors hover:bg-bg-tertiary md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto_auto] md:gap-3">
                <span className="flex min-w-0 items-center gap-2">
                  <MapPin className="h-4 w-4 shrink-0 text-text-muted" />
                  <span className="font-mono text-xs text-text-muted">{anonymize(s.code)}</span>
                  <span className="truncate text-sm font-medium text-text-primary">{anonymize(s.name)}</span>
                  {s.archivedAt && <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">{t('sites.archived') || 'Archived'}</span>}
                  <FileNotCreatedBadge count={s.counts.fileNotCreated} />
                </span>
                <span className="truncate text-xs text-text-secondary">{s.city ? anonymize(s.city) : '—'}</span>
                <span className="inline-flex min-w-0 items-center gap-1 text-xs text-text-secondary">
                  <FolderOpen className="h-3 w-3 shrink-0" /><span className="truncate">{s.groupName ? anonymize(s.groupName) : '—'}</span>
                </span>
                <span className="inline-flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 text-xs tabular-nums text-text-muted"><Smartphone className="h-3 w-3" />{s.counts.devices}</span>
                  <SiteCountsPills counts={s.counts} compact />
                </span>
                <ChevronRight className="hidden h-4 w-4 text-text-muted md:block" />
              </Link>
            ))}
          </div>
        )}

      <SiteEditDialog open={creating} site={null} onClose={() => setCreating(false)}
        onSaved={(s) => { setCreating(false); navigate(`/sites/${s.id}`); }} />
      <ImportDialog open={importOpen} onClose={() => setImportOpen(false)} onApplied={load} />
      <FromDevicesDialog open={fromDevicesOpen} onClose={() => setFromDevicesOpen(false)} onApplied={load} />
    </PageContainer>
  );
}

/** How many phones' files the plan changes (the dry run of the console). */
function ImpactPill({ count }: { count: number | undefined }) {
  const { t } = useTranslation();
  if (count === undefined) return null;
  return (
    <span className={clsx('rounded-full px-2 py-0.5', count > 0 ? 'bg-amber-500/15 text-amber-400' : 'bg-bg-tertiary text-text-muted')}>
      {t('sites.impact', { count }) || `${count} phone(s) whose files change`}
    </span>
  );
}

const actionTone: Record<string, string> = {
  create: 'text-green-400', update: 'text-accent', unchanged: 'text-text-muted', error: 'text-red-400',
};

/** The import of a CSV file: chosen, its dry run shown (creations, updates, errors per line), then applied. */
function ImportDialog({ open, onClose, onApplied }: { open: boolean; onClose: () => void; onApplied: () => void }) {
  const { t } = useTranslation();
  const fileRef = useRef<HTMLInputElement>(null);
  const [csv, setCsv] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [plan, setPlan] = useState<SiteImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setCsv(null); setName(''); setPlan(null); } }, [open]);

  /** The dry run of a text (its digest kept: the apply sends it back). */
  const preview = async (text: string): Promise<void> => {
    const r = await sitesApi.importCsv(text, true);
    setPlan(isSiteWritePending(r) ? null : r);
  };
  const pick = async (file: File) => {
    if (file.size > SITE_LIMITS.importBytes) { toast.error(t('sites.import.tooLarge') || 'The file is larger than 2 MiB.'); return; }
    const text = await file.text();
    setName(file.name);
    setCsv(text);
    setBusy(true);
    try {
      await preview(text);
    } catch (err) {
      setPlan(null);
      if (!isStepUpHandled(err)) toast.error(importErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };
  const apply = async () => {
    if (!csv || !plan) return;
    setBusy(true);
    try {
      const r = await sitesApi.importCsv(csv, false, plan.digest);
      if (!pendingSaid(t, r)) toast.success(t('sites.import.applied', { created: r.created, updated: r.updated }) || `${r.created} site(s) created, ${r.updated} updated`);
      onApplied();
      onClose();
    } catch (err) {
      if (isPlanChanged(err)) {
        // The sites changed since the dry run: the new plan is shown, applied only once checked again.
        toast.error(t('sites.planChangedPreview') || 'The sites changed since the preview: the new preview is shown, check it and apply again.', { duration: 8000 });
        await preview(csv).catch(() => setPlan(null));
      } else if (!isStepUpHandled(err)) toast.error(importErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const writes = plan ? plan.created + plan.updated : 0;
  return (
    <Modal open={open} onClose={() => { if (!busy) onClose(); }} size="lg" title={t('sites.import.title') || 'Import sites from a CSV file'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={apply} loading={busy && !!plan} disabled={!plan || writes === 0}>
            {t('sites.import.apply', { count: writes }) || `Apply (${writes})`}
          </Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-text-muted">
          {t('sites.import.hint') || 'A header line, separator ";" or ",". Columns code (or codeMag) and name (or nameMag); city and contact optional; every other column becomes a value of the site. An empty cell keeps the value of the site. Nothing is written before you apply.'}
        </p>
        <input ref={fileRef} type="file" accept=".csv,text/csv,text/plain" className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) void pick(f); }} />
        <Button size="sm" variant="secondary" loading={busy && !plan} onClick={() => fileRef.current?.click()}>
          <FileUp className="mr-1 h-4 w-4" />{name || (t('sites.import.choose') || 'Choose a file')}
        </Button>
        {plan && (
          <>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="rounded-full bg-green-500/15 px-2 py-0.5 text-green-400">{t('sites.import.created', { count: plan.created }) || `${plan.created} to create`}</span>
              <span className="rounded-full bg-accent/15 px-2 py-0.5 text-accent">{t('sites.import.updated', { count: plan.updated }) || `${plan.updated} to update`}</span>
              <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-text-muted">{t('sites.import.unchanged', { count: plan.unchanged }) || `${plan.unchanged} unchanged`}</span>
              {plan.errors > 0 && <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-red-400">{t('sites.import.errors', { count: plan.errors }) || `${plan.errors} refused`}</span>}
              <ImpactPill count={plan.policyImpact} />
            </div>
            <p className="text-[11px] text-text-muted">
              {t('sites.import.columns', { code: plan.columns.code, name: plan.columns.name, values: plan.columns.values.join(', ') || '—' })
                || `Code: ${plan.columns.code} · Name: ${plan.columns.name} · Values: ${plan.columns.values.join(', ') || '—'}`}
            </p>
            <div className="max-h-72 overflow-auto rounded-xl bg-bg-secondary py-1">
              {plan.lines.filter((l) => l.action !== 'unchanged').slice(0, 500).map((l) => (
                <div key={l.line} className="flex items-baseline gap-3 px-3 py-1 text-xs hover:bg-bg-tertiary">
                  <span className="w-12 shrink-0 tabular-nums text-text-muted">{t('sites.import.line', { line: l.line }) || `Line ${l.line}`}</span>
                  <span className="w-24 shrink-0 truncate font-mono text-text-primary">{anonymize(l.code) || '—'}</span>
                  <span className={clsx('w-20 shrink-0', actionTone[l.action])}>{trCode(`sites.import.action.${l.action}`, l.action)}</span>
                  <span className="min-w-0 flex-1 truncate text-text-muted">
                    {l.issues.length ? l.issues.map((i) => trCode(`sites.issue.${i}`, i)).join(', ') : l.changes.join(', ')}
                  </span>
                </div>
              ))}
              {plan.lines.every((l) => l.action === 'unchanged') && <p className="px-3 py-2 text-xs text-text-muted">{t('sites.import.nothing') || 'Nothing to change.'}</p>}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}

const fieldCls = 'mt-1 w-full rounded-lg bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50';

/** The sites made from the custom fields of the phones (codeMag, nameMag…): a dry run, then applied. */
function FromDevicesDialog({ open, onClose, onApplied }: { open: boolean; onClose: () => void; onApplied: () => void }) {
  const { t } = useTranslation();
  const [codeKey, setCodeKey] = useState('codeMag');
  const [nameKey, setNameKey] = useState('nameMag');
  const [valuesKeys, setValuesKeys] = useState('');
  const [plan, setPlan] = useState<SitesFromDevicesResult | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) setPlan(null); }, [open]);
  const keys = () => ({
    codeKey: codeKey.trim() || undefined, nameKey: nameKey.trim() || undefined,
    valuesKeys: [...new Set(valuesKeys.split(',').map((x) => x.trim()).filter(Boolean))],
  });
  const run = async (dryRun: boolean) => {
    setBusy(true);
    try {
      const r = await sitesApi.fromDevices(keys(), dryRun, dryRun ? undefined : plan?.digest);
      if (dryRun) { setPlan(isSiteWritePending(r) ? null : r); return; }
      if (!pendingSaid(t, r)) toast.success(t('sites.fromDevices.applied', { sites: r.sites.length, devices: r.attached }) || `${r.sites.length} site(s), ${r.attached} phone(s) attached`);
      onApplied();
      onClose();
    } catch (err) {
      if (!dryRun && isPlanChanged(err)) {
        toast.error(t('sites.planChangedPreview') || 'The sites changed since the preview: the new preview is shown, check it and apply again.', { duration: 8000 });
        const again = await sitesApi.fromDevices(keys(), true).catch(() => null);
        setPlan(again && !isSiteWritePending(again) ? again : null);
      } else if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const writes = plan ? plan.sites.filter((s) => s.action !== 'unchanged').length + plan.attached : 0;
  return (
    <Modal open={open} onClose={() => { if (!busy) onClose(); }} size="lg" title={t('sites.fromDevices.title') || 'Create the sites from the phones\' fields'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button variant="secondary" onClick={() => { void run(true); }} loading={busy && !plan}>{t('sites.fromDevices.preview') || 'Preview'}</Button>
          <Button onClick={() => { void run(false); }} loading={busy && !!plan} disabled={!plan || writes === 0}>{t('sites.fromDevices.apply') || 'Apply'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-text-muted">
          {t('sites.fromDevices.hint') || 'One site per value of the code field of the phones, named after their name field; the phones are attached to it. An existing site keeps its name and values. No phone changes group.'}
        </p>
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fromDevices.codeKey') || 'Code field'}</span>
            <input value={codeKey} onChange={(e) => { setCodeKey(e.target.value); setPlan(null); }} className={fieldCls} autoCapitalize="off" spellCheck={false} /></label>
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fromDevices.nameKey') || 'Name field'}</span>
            <input value={nameKey} onChange={(e) => { setNameKey(e.target.value); setPlan(null); }} className={fieldCls} autoCapitalize="off" spellCheck={false} /></label>
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fromDevices.valuesKeys') || 'Other fields to copy (comma-separated)'}</span>
            <input value={valuesKeys} onChange={(e) => { setValuesKeys(e.target.value); setPlan(null); }} placeholder="codeEns" className={fieldCls} autoCapitalize="off" spellCheck={false} /></label>
        </div>
        {plan && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="rounded-full bg-green-500/15 px-2 py-0.5 text-green-400">
                {t('sites.fromDevices.sitesCount', { count: plan.sites.filter((s) => s.action === 'create').length }) || `${plan.sites.filter((s) => s.action === 'create').length} site(s) to create`}
              </span>
              <span className="rounded-full bg-accent/15 px-2 py-0.5 text-accent">{t('sites.fromDevices.attachCount', { count: plan.attached }) || `${plan.attached} phone(s) to attach`}</span>
              <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-text-muted">{t('sites.fromDevices.already', { count: plan.alreadyAttached }) || `${plan.alreadyAttached} already attached`}</span>
              {plan.withoutField.length > 0 && <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-400">{t('sites.fromDevices.withoutField', { count: plan.withoutField.length }) || `${plan.withoutField.length} phone(s) without the field`}</span>}
              {plan.conflicts.length > 0 && <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-red-400">{t('sites.fromDevices.conflicts', { count: plan.conflicts.length }) || `${plan.conflicts.length} conflict(s)`}</span>}
              <ImpactPill count={plan.policyImpact} />
            </div>
            <div className="max-h-64 overflow-auto rounded-xl bg-bg-secondary py-1">
              {plan.sites.slice(0, 500).map((s) => (
                <div key={s.code} className="flex items-baseline gap-3 px-3 py-1 text-xs hover:bg-bg-tertiary">
                  <span className="w-24 shrink-0 truncate font-mono text-text-primary">{anonymize(s.code)}</span>
                  <span className="min-w-0 flex-1 truncate text-text-secondary">{anonymize(s.name)}</span>
                  <span className={clsx('w-20 shrink-0', actionTone[s.action])}>{trCode(`sites.import.action.${s.action}`, s.action)}</span>
                  <span className="w-16 shrink-0 text-right tabular-nums text-text-muted">+{s.devices}</span>
                </div>
              ))}
            </div>
            {plan.conflicts.length > 0 && (
              <p className="text-xs text-red-400">
                {t('sites.fromDevices.conflictsHint') || 'Several names for one code (the most frequent is kept):'}{' '}
                {plan.conflicts.slice(0, 10).map((c) => `${anonymize(c.code)} (${c.names.map((n) => anonymize(n)).join(' / ')})`).join(' · ')}
              </p>
            )}
            {plan.withoutField.length > 0 && (
              <p className="text-xs text-amber-400">
                {t('sites.fromDevices.withoutFieldHint') || 'Left as they are (no code field):'} {plan.withoutField.slice(0, 20).map((d) => anonymize(d.label)).join(', ')}
                {plan.withoutField.length > 20 ? ` +${plan.withoutField.length - 20}` : ''}
              </p>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
