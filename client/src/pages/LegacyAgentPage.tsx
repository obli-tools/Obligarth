import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Ban, Copy, Download, FileSpreadsheet, KeyRound, Lock, MessageSquare, Package, Plus, RefreshCw, RotateCw, Search, ShieldOff, Trash2, Upload, XCircle } from 'lucide-react';
import {
  isMasterTenant, LEGACY_AGENT_ACTIVATE_SCRIPT, LEGACY_AGENT_NAME_IMPORT_MAX_ROWS, LEGACY_AGENT_ADMIN_OFF_SCRIPT, LEGACY_AGENT_AUTO_UPDATE_BOUNDS, LEGACY_AGENT_TOKEN_BOUNDS,
  type DeviceGroup, type LegacyAgentCommandView, type LegacyAgentConsoleType, type LegacyAgentDeviceDetail, type LegacyAgentDeviceView,
  type LegacyAgentInstanceSettings, type LegacyAgentPackageView, type LegacyAgentReleaseView, type LegacyAgentServerKeyView,
  type LegacyAgentNameImportResult, type LegacyAgentNameImportStatus, type LegacyAgentTokenCreated, type LegacyAgentTokenView,
} from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { groupsApi } from '@/api/groups.api';
import { isStepUpHandled } from '@/api/client';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { GuardedActionDialog } from '@/components/guard/GuardedActionDialog';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { apiErrorMessage } from '@/utils/apiError';

// The Android bridge agent (agent-pont-android §7): the devices of the tenant (state of the agent, of the device
// administrator and of Knox, last interrogation, identity conflicts; actions on a selection), the enrollment tokens
// (the value, the encoded configuration and the MobiControl script shown once; the activation script of a device
// already enrolled and the `_adminmode off` return line, lot ADM), the client APKs, the tenant's Knox
// licence; for a platform administrator on the master tenant, the versions of the agent, the instance key (to
// compile in SERVER_KEY_PINS, exported once for the escrow) and the instance settings (automatic update of the fleet
// included; the version embedded in the server image is shown with its image, lot AGENT-RU). Lock and erase go
// through the dialog of the guard engine.

type Tab = 'devices' | 'tokens' | 'packages' | 'platform';
const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
const fmt = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleString() : '—');
const yesNo = (t: (k: string) => string, b: boolean | null | undefined): string =>
  (b === null || b === undefined ? '—' : b ? (t('legacyAgent.yes') || 'Yes') : (t('legacyAgent.no') || 'No'));

function fail(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
}

async function copy(text: string, done: string): Promise<void> {
  try { await navigator.clipboard.writeText(text); toast.success(done); } catch { /* selectable */ }
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
      <div className="flex gap-1 border-b border-border">
        {tabs.map((k) => (
          <button key={k} type="button" onClick={() => setTab(k)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px coarse:min-h-10 ${tab === k ? 'border-accent text-accent' : 'border-transparent text-text-muted hover:text-text-primary'}`}>
            {label(k)}
          </button>
        ))}
      </div>
      {tab === 'devices' && <DevicesTab />}
      {tab === 'tokens' && <TokensTab />}
      {tab === 'packages' && <PackagesTab />}
      {tab === 'platform' && platform && <PlatformTab />}
    </PageContainer>
  );
}

// ── Devices ──────────────────────────────────────────────────────────────────

type Pending = { kind: 'message' | 'install' | 'uninstall' | 'update' } | null;

function DevicesTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const [params, setParams] = useSearchParams();
  const [rows, setRows] = useState<LegacyAgentDeviceView[] | null>(null);
  const [q, setQ] = useState('');
  const [filters, setFilters] = useState({ conflict: false, adminInactive: false, silent: false, revoked: false });
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [pending, setPending] = useState<Pending>(null);
  const [guarded, setGuarded] = useState<'device.lock' | 'device.wipe' | null>(null);
  const [importing, setImporting] = useState(false);
  const detailId = Number(params.get('device') ?? 0) || null;

  const load = useCallback(() => {
    legacyAgentApi.devices({ q, ...filters }).then((r) => { setRows(r); }).catch((err) => { setRows([]); fail(err); });
  }, [q, filters]);
  useEffect(() => { load(); }, [load]);

  const ids = [...selected];
  const toggle = (id: number) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const all = rows && rows.length > 0 && rows.every((r) => selected.has(r.deviceId));
  // Counts of the listed rows (they follow the search and the filters): administrator, unknown sources.
  const counts = useMemo(() => {
    const c = { total: 0, adminOn: 0, adminOff: 0, srcYes: 0, srcNo: 0, srcNull: 0 };
    for (const r of rows ?? []) {
      c.total++;
      if (r.adminActive) c.adminOn++; else c.adminOff++;
      if (r.unknownSources === null) c.srcNull++; else if (r.unknownSources) c.srcYes++; else c.srcNo++;
    }
    return c;
  }, [rows]);

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

  const filter = (k: keyof typeof filters, text: string) => (
    <label className="flex items-center gap-1 text-xs text-text-muted">
      <input type="checkbox" checked={filters[k]} onChange={(e) => setFilters((f) => ({ ...f, [k]: e.target.checked }))} />
      {text}
    </label>
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={14} className="absolute left-2 top-2.5 text-text-muted" />
          <input className="rounded border border-border bg-bg-secondary pl-7 pr-2 py-1.5 text-sm" value={q} onChange={(e) => setQ(e.target.value)}
            placeholder={t('legacyAgent.search') || 'Name, serial number, model'} />
        </div>
        {filter('conflict', t('legacyAgent.filters.conflict') || 'Identity conflict')}
        {filter('adminInactive', t('legacyAgent.filters.adminInactive') || 'Administrator inactive')}
        {filter('silent', t('legacyAgent.filters.silent') || 'Silent for 24 h')}
        {filter('revoked', t('legacyAgent.filters.revoked') || 'Include revoked')}
        <Button variant="ghost" onClick={load}><RefreshCw size={14} /></Button>
        <Button variant="secondary" className="ml-auto" onClick={() => setImporting(true)}><FileSpreadsheet size={14} /> {t('legacyAgent.importNames.button') || 'Import names'}</Button>
      </div>
      {rows && rows.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 rounded border border-border bg-bg-secondary px-3 py-2 text-sm">
          <span className="font-medium text-text-primary">{t('legacyAgent.summary.devices', { count: counts.total }) || `${counts.total} device(s)`}</span>
          <span className="text-text-muted">
            {t('legacyAgent.summary.admin') || 'Device admin:'}{' '}
            <span className="font-medium text-text-primary">{t('legacyAgent.summary.adminActive', { count: counts.adminOn }) || `${counts.adminOn} active`}</span>
            {' · '}
            <span className={`font-medium ${counts.adminOff > 0 ? 'text-red-500' : 'text-text-primary'}`}>{t('legacyAgent.summary.adminInactive', { count: counts.adminOff }) || `${counts.adminOff} inactive`}</span>
          </span>
          <span className="text-text-muted">
            {t('legacyAgent.summary.unknownSources') || 'Unknown sources:'}{' '}
            <span className="font-medium text-text-primary">{t('legacyAgent.yes') || 'Yes'} {counts.srcYes}</span>
            {' · '}
            <span className="font-medium text-text-primary">{t('legacyAgent.no') || 'No'} {counts.srcNo}</span>
            {counts.srcNull > 0 && <>{' · '}{t('legacyAgent.summary.notReported', { count: counts.srcNull }) || `${counts.srcNull} not reported`}</>}
          </span>
        </div>
      )}
      {ids.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded border border-border bg-bg-secondary p-2 text-sm">
          <span className="text-text-muted">{t('legacyAgent.selected', { count: ids.length }) || `${ids.length} selected`}</span>
          <Button variant="secondary" onClick={() => setPending({ kind: 'message' })}><MessageSquare size={14} /> {t('legacyAgent.actions.message') || 'Message'}</Button>
          <Button variant="secondary" onClick={() => void send('inventory.refresh', {})}><RefreshCw size={14} /> {t('legacyAgent.actions.inventory') || 'Inventory'}</Button>
          <Button variant="secondary" onClick={async () => { if (await confirm({ message: t('legacyAgent.confirmReboot') || 'Restart the selected devices (Knox required)?' })) void send('device.reboot', {}); }}>
            <RotateCw size={14} /> {t('legacyAgent.actions.reboot') || 'Restart'}
          </Button>
          <Button variant="secondary" onClick={() => setPending({ kind: 'install' })}><Package size={14} /> {t('legacyAgent.actions.install') || 'Install an app'}</Button>
          <Button variant="secondary" onClick={() => setPending({ kind: 'uninstall' })}><Trash2 size={14} /> {t('legacyAgent.actions.uninstall') || 'Uninstall an app'}</Button>
          <Button variant="secondary" onClick={() => setPending({ kind: 'update' })}><Download size={14} /> {t('legacyAgent.actions.update') || 'Update the agent'}</Button>
          <Button variant="secondary" onClick={() => setGuarded('device.lock')}><Lock size={14} /> {t('legacyAgent.actions.lock') || 'Lock'}</Button>
          <Button variant="danger" onClick={() => setGuarded('device.wipe')}><ShieldOff size={14} /> {t('legacyAgent.actions.wipe') || 'Erase'}</Button>
        </div>
      )}
      <div className="overflow-x-auto rounded border border-border">
        <table className="w-full text-sm">
          <thead className="bg-bg-secondary text-left text-xs text-text-muted">
            <tr>
              <th className="p-2"><input type="checkbox" checked={!!all} onChange={() => setSelected(all ? new Set() : new Set((rows ?? []).map((r) => r.deviceId)))} /></th>
              <th className="p-2">{t('legacyAgent.cols.name') || 'Name'}</th>
              <th className="p-2">{t('legacyAgent.cols.model') || 'Model'}</th>
              <th className="p-2">{t('legacyAgent.cols.android') || 'Android'}</th>
              <th className="p-2">{t('legacyAgent.cols.patch') || 'Security patch'}</th>
              <th className="p-2">{t('legacyAgent.cols.agent') || 'Agent'}</th>
              <th className="p-2">{t('legacyAgent.cols.admin') || 'Admin active'}</th>
              <th className="p-2">{t('legacyAgent.cols.knox') || 'Knox'}</th>
              <th className="p-2">{t('legacyAgent.cols.unknownSources') || 'Unknown sources'}</th>
              <th className="p-2">{t('legacyAgent.cols.lastPoll') || 'Last interrogation'}</th>
              <th className="p-2">{t('legacyAgent.cols.battery') || 'Battery'}</th>
              <th className="p-2">{t('legacyAgent.cols.conflict') || 'Conflict'}</th>
              <th className="p-2" />
            </tr>
          </thead>
          <tbody>
            {(rows ?? []).map((d) => (
              <tr key={d.deviceId} className="border-t border-border">
                <td className="p-2"><input type="checkbox" checked={selected.has(d.deviceId)} disabled={!!d.revokedAt} onChange={() => toggle(d.deviceId)} /></td>
                <td className="p-2"><button type="button" className="text-accent hover:underline" onClick={() => setParams({ device: String(d.deviceId) })}>{d.name ?? `#${d.deviceId}`}</button>
                  {d.serialNumber && <div className="text-xs text-text-muted">{d.serialNumber}</div>}</td>
                <td className="p-2">{d.modelName ?? d.model ?? '—'}</td>
                <td className="p-2">{d.osVersion ?? '—'}{d.apiLevel ? ` (API ${d.apiLevel})` : ''}</td>
                <td className="p-2">{d.securityPatch ?? '—'}</td>
                <td className="p-2">{d.agentVersionName} ({d.agentVersionCode})</td>
                <td className={`p-2 ${d.adminActive ? '' : 'text-red-500'}`}>{yesNo(t, d.adminActive)}</td>
                <td className="p-2">{t(`legacyAgent.knox.${d.knoxState}`) || d.knoxState}</td>
                <td className="p-2">{yesNo(t, d.unknownSources)}</td>
                <td className="p-2">{fmt(d.lastPollAt)}</td>
                <td className="p-2">{d.batteryLevel === null ? '—' : `${d.batteryLevel} %`}</td>
                <td className={`p-2 ${d.identityConflict ? 'text-amber-500' : ''}`}>{d.identityConflict ? (t('legacyAgent.yes') || 'Yes') : ''}</td>
                <td className="p-2 text-right">
                  {d.revokedAt ? <span className="text-xs text-text-muted">{t('legacyAgent.revokedState') || 'Revoked'}</span>
                    : <Button variant="ghost" title={t('legacyAgent.actions.revoke') || 'Revoke'} onClick={() => void revoke(d)}><Ban size={14} /></Button>}
                </td>
              </tr>
            ))}
            {rows && rows.length === 0 && <tr><td colSpan={13} className="p-4 text-center text-text-muted">{t('legacyAgent.empty') || 'No agent enrolled yet.'}</td></tr>}
          </tbody>
        </table>
      </div>
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

// ── Import of device names (a MobiControl export of the devices: "Nom term.", "IMEI / MEID / ESN") ──────────────────────

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

/** The (name, IMEI) pairs of a CSV: separator , ; or tab; the header (if any) names the columns, else name then IMEI. */
function parseNameCsv(text: string): Array<{ name: string; imei: string }> {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/).filter((l) => l.trim() !== '');
  if (lines.length === 0) return [];
  const first = lines[0];
  const sep = [',', ';', '\t'].map((c) => ({ c, n: first.split(c).length })).sort((a, b) => b.n - a.n)[0].c;
  const head = splitCsvLine(first, sep);
  const isImei = (v: string) => /^\d{14,16}$/.test(v.replace(/[\s-]/g, ''));
  let nameCol = 0;
  let imeiCol = 1;
  let start = 0;
  if (!head.some(isImei)) {
    start = 1;
    const i = head.findIndex((h) => /imei/i.test(h));
    const n = head.findIndex((h) => /^(nom|name)|device name/i.test(h));
    if (i >= 0) imeiCol = i;
    if (n >= 0 && n !== imeiCol) nameCol = n; else if (imeiCol === 0) nameCol = 1;
  } else {
    imeiCol = head.findIndex(isImei);
    nameCol = imeiCol === 0 ? 1 : 0;
  }
  return lines.slice(start).map((l) => {
    const cells = splitCsvLine(l, sep);
    return { name: cells[nameCol] ?? '', imei: cells[imeiCol] ?? '' };
  });
}

const IMPORT_ORDER: LegacyAgentNameImportStatus[] = ['rename', 'renamed', 'same', 'notFound', 'ambiguous', 'duplicate', 'forbidden', 'invalid'];

function NameImportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LegacyAgentNameImportResult | null>(null);
  const pairs = useMemo(() => parseNameCsv(text), [text]);
  const counts = useMemo(() => {
    const c: Partial<Record<LegacyAgentNameImportStatus, number>> = {};
    for (const r of result?.rows ?? []) c[r.status] = (c[r.status] ?? 0) + 1;
    return c;
  }, [result]);
  const sorted = useMemo(() => [...(result?.rows ?? [])].sort((a, b) => IMPORT_ORDER.indexOf(a.status) - IMPORT_ORDER.indexOf(b.status)), [result]);
  const label = (s: LegacyAgentNameImportStatus) => t(`legacyAgent.importNames.status.${s}`) || s;
  const tone = (s: LegacyAgentNameImportStatus) => (s === 'rename' || s === 'renamed' ? 'text-accent'
    : s === 'same' ? 'text-text-muted' : s === 'notFound' ? 'text-amber-500' : 'text-red-500');
  const toRename = counts.rename ?? 0;

  const run = async (apply: boolean) => {
    if (pairs.length === 0) return;
    if (pairs.length > LEGACY_AGENT_NAME_IMPORT_MAX_ROWS) {
      toast.error(t('legacyAgent.importNames.tooMany', { max: LEGACY_AGENT_NAME_IMPORT_MAX_ROWS }) || `${LEGACY_AGENT_NAME_IMPORT_MAX_ROWS} rows at most`);
      return;
    }
    setBusy(true);
    try {
      const r = await legacyAgentApi.importNames(pairs, apply);
      setResult(r);
      if (apply) {
        toast.success(t('legacyAgent.importNames.done', { count: r.applied }) || `${r.applied} device(s) renamed`);
        onDone();
      }
    } catch (err) { fail(err); } finally { setBusy(false); }
  };

  return (
    <Modal open onClose={onClose} size="2xl" title={t('legacyAgent.importNames.title') || 'Import device names'}>
      <div className="space-y-3 text-sm">
        <p className="text-text-muted">
          {t('legacyAgent.importNames.help') || 'A CSV export of MobiControl with the columns "Nom term." and "IMEI / MEID / ESN". Each IMEI is compared with the one the agent reported (or the MobiControl enrollment script); the matching device takes the name. Nothing changes before "Rename".'}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <input type="file" accept=".csv,.txt,text/csv,text/plain" className="text-xs"
            onChange={async (e) => { const f = e.target.files?.[0]; if (f) { setText(await readCsvFile(f)); setResult(null); } }} />
          <span className="text-xs text-text-muted">{t('legacyAgent.importNames.orPaste') || 'or paste the content below'}</span>
        </div>
        <textarea className={`${fieldCls} font-mono text-xs`} rows={6} value={text} spellCheck={false}
          placeholder={'Nom term.,IMEI / MEID / ESN\nC0000001,350000000000000'}
          onChange={(e) => { setText(e.target.value); setResult(null); }} />
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-text-muted">{t('legacyAgent.importNames.lines', { count: pairs.length }) || `${pairs.length} line(s) read`}</span>
          <Button variant="secondary" className="ml-auto" disabled={busy || pairs.length === 0} onClick={() => void run(false)}>
            <Search size={14} /> {t('legacyAgent.importNames.preview') || 'Preview'}
          </Button>
          <Button disabled={busy || !result || toRename === 0} onClick={() => void run(true)}>
            <FileSpreadsheet size={14} /> {t('legacyAgent.importNames.apply', { count: toRename }) || `Rename ${toRename} device(s)`}
          </Button>
        </div>
        {result && (<>
          <div className="flex flex-wrap gap-x-4 gap-y-1 rounded border border-border bg-bg-secondary px-3 py-2 text-xs">
            {IMPORT_ORDER.filter((s) => counts[s]).map((s) => (
              <span key={s} className={tone(s)}>{label(s)} : <span className="font-semibold">{counts[s]}</span></span>
            ))}
          </div>
          <div className="max-h-80 overflow-auto rounded border border-border">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-bg-secondary text-left text-text-muted">
                <tr>
                  <th className="p-2">{t('legacyAgent.importNames.cols.name') || 'New name'}</th>
                  <th className="p-2">{t('legacyAgent.importNames.cols.imei') || 'IMEI'}</th>
                  <th className="p-2">{t('legacyAgent.importNames.cols.current') || 'Current name'}</th>
                  <th className="p-2">{t('legacyAgent.importNames.cols.status') || 'Result'}</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((r, i) => (
                  <tr key={`${r.imei}-${i}`} className="border-t border-border">
                    <td className="p-2">{r.name || '—'}</td>
                    <td className="p-2 font-mono">{r.imei || '—'}</td>
                    <td className="p-2 text-text-muted">{r.currentName ?? '—'}</td>
                    <td className={`p-2 ${tone(r.status)}`}>{label(r.status)}</td>
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
          <label className="block">{t('legacyAgent.message.title') || 'Title'}<input className={fieldCls} maxLength={80} value={title} onChange={(e) => setTitle(e.target.value)} /></label>
          <label className="block">{t('legacyAgent.message.text') || 'Text'}<textarea className={fieldCls} maxLength={500} rows={4} value={text} onChange={(e) => setText(e.target.value)} /></label>
          <label className="block">{t('legacyAgent.message.mode') || 'Display'}
            <select className={fieldCls} value={mode} onChange={(e) => setMode(e.target.value as 'notification' | 'fullscreen')}>
              <option value="notification">{t('legacyAgent.message.notification') || 'Notification'}</option>
              <option value="fullscreen">{t('legacyAgent.message.fullscreen') || 'Full screen'}</option>
            </select></label>
        </>)}
        {kind === 'install' && (
          <label className="block">{t('legacyAgent.packages.choose') || 'Package'}
            <select className={fieldCls} value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">—</option>
              {packages.map((p) => <option key={p.id} value={p.id}>{p.label ?? p.packageName} {p.versionName ?? ''} ({p.versionCode})</option>)}
            </select></label>
        )}
        {kind === 'uninstall' && (
          <label className="block">{t('legacyAgent.packages.packageName') || 'Package name'}<input className={fieldCls} value={packageName} onChange={(e) => setPackageName(e.target.value)} placeholder="com.example.app" /></label>
        )}
        {kind === 'update' && (
          <label className="block">{t('legacyAgent.releases.choose') || 'Version of the agent'}
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
  const row = (k: string, v: ReactNode) => <div className="flex justify-between gap-4 border-b border-border py-1"><span className="text-text-muted">{k}</span><span className="text-right break-all">{v}</span></div>;
  return (
    <Modal open onClose={onClose} size="2xl" title={d?.name ?? `#${id}`}>
      {d && (
        <div className="space-y-4 text-sm">
          {d.identityConflict && <div className="rounded border border-amber-500 p-2 text-amber-600">{t('legacyAgent.detail.conflict') || 'Identity conflict: the serial number or the IMEI declared by this agent is held by another managed device.'}</div>}
          <div>
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
            <h3 className="mb-1 font-semibold">{t('legacyAgent.detail.status') || 'Status'}</h3>
            {d.status.map((s) => row(s.item, `${JSON.stringify(s.value)} · ${fmt(s.observedAt)}`))}
          </div>
          <div>
            <h3 className="mb-1 font-semibold">{t('legacyAgent.detail.queue') || 'Commands'}</h3>
            <table className="w-full text-xs">
              <tbody>
                {cmds.map((c) => (
                  <tr key={c.id} className="border-t border-border">
                    <td className="p-1">{c.type}</td>
                    <td className="p-1">{t(`legacyAgent.state.${c.state}`) || c.state}{c.holdReason ? ` (${c.holdReason})` : ''}</td>
                    <td className="p-1">{c.resultCode ?? ''}</td>
                    <td className="p-1">{fmt(c.createdAt)}</td>
                    <td className="p-1 text-right">{c.state === 'pending' && !c.guardActionUuid && (
                      <Button variant="ghost" title={t('legacyAgent.cancel') || 'Cancel'} onClick={() => void cancel(c)}><XCircle size={12} /></Button>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div>
            <h3 className="mb-1 font-semibold">{t('legacyAgent.detail.apps', { count: d.apps.length }) || `Apps (${d.apps.length})`}</h3>
            <div className="max-h-64 overflow-y-auto text-xs">
              {d.apps.map((a) => <div key={a.packageName} className="flex justify-between border-b border-border py-0.5"><span>{a.label ?? a.packageName}<span className="text-text-muted"> {a.packageName}</span></span><span>{a.versionName ?? ''}{a.managed ? ' ●' : ''}</span></div>)}
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
      <div className="flex items-center justify-between"><span className="font-semibold">{title}</span>
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
      <div className="grid gap-2 rounded border border-border p-3 text-sm md:grid-cols-5">
        <label>{t('legacyAgent.tokens.label') || 'Label'}<input className={fieldCls} maxLength={100} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder={t('legacyAgent.tokens.labelHint') || 'Wave 1'} /></label>
        <label>{t('legacyAgent.tokens.group') || 'Group'}
          <select className={fieldCls} value={form.groupId} onChange={(e) => setForm({ ...form, groupId: e.target.value })}>
            <option value="">—</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select></label>
        <label>{t('legacyAgent.tokens.days') || 'Validity (days)'}<input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.daysMax} value={form.days} onChange={(e) => setForm({ ...form, days: e.target.value })} /></label>
        <label>{t('legacyAgent.tokens.maxUses') || 'Quota'}<input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax} value={form.maxUses} onChange={(e) => setForm({ ...form, maxUses: e.target.value })} /></label>
        <div className="flex items-end"><Button onClick={() => void create()} disabled={!form.label.trim()}><Plus size={14} /> {t('legacyAgent.tokens.create') || 'New token'}</Button></div>
      </div>
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-text-muted"><tr>
          <th className="p-2">{t('legacyAgent.tokens.label') || 'Label'}</th><th className="p-2">{t('legacyAgent.tokens.uses') || 'Uses'}</th>
          <th className="p-2">{t('legacyAgent.tokens.expires') || 'Expires'}</th><th className="p-2">{t('legacyAgent.tokens.state') || 'State'}</th><th />
        </tr></thead>
        <tbody>
          {(rows ?? []).map((r) => (
            <tr key={r.id} className="border-t border-border">
              <td className="p-2">{r.label}</td><td className="p-2">{r.uses} / {r.maxUses}</td><td className="p-2">{fmt(r.expiresAt)}</td>
              <td className="p-2">{t(`legacyAgent.tokens.states.${r.state}`) || r.state}</td>
              <td className="p-2 text-right">{r.state === 'active' && <Button variant="ghost" onClick={() => void revoke(r)}><Ban size={14} /></Button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="space-y-2 rounded border border-border p-3 text-sm">
        <h3 className="flex items-center gap-1 font-semibold"><ShieldOff size={14} /> {t('legacyAgent.adminMode.title') || 'Device administrator and MobiControl Lockdown'}</h3>
        <AdminModeNote />
        <ScriptBlock title={t('legacyAgent.adminMode.activateScript') || 'Activation script (device already enrolled, administrator off)'} value={LEGACY_AGENT_ACTIVATE_SCRIPT} rows={2} />
        <ScriptBlock title={t('legacyAgent.adminMode.adminOffScript') || 'Return script (_adminmode off)'} value={LEGACY_AGENT_ADMIN_OFF_SCRIPT} rows={1} />
      </div>
      <div className="rounded border border-border p-3 text-sm">
        <h3 className="mb-1 flex items-center gap-1 font-semibold"><KeyRound size={14} /> {t('legacyAgent.knox.title') || 'Knox licence'}</h3>
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
    <label>{label}<input className={fieldCls} value={meta[k]} placeholder={ph} onChange={(e) => setMeta({ ...meta, [k]: e.target.value })} /></label>
  );
  return (
    <div className="space-y-4">
      <div className="grid gap-2 rounded border border-border p-3 text-sm md:grid-cols-3">
        <label>{t('legacyAgent.packages.file') || 'APK'}<input className={fieldCls} type="file" accept=".apk,application/vnd.android.package-archive" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
        {field('packageName', t('legacyAgent.packages.packageName') || 'Package name', 'com.example.app')}
        {field('versionCode', t('legacyAgent.packages.versionCode') || 'versionCode', '42')}
        {field('versionName', t('legacyAgent.packages.versionName') || 'Version name', '4.2')}
        {field('signerSha256', t('legacyAgent.packages.signer') || 'Signer SHA-256 (optional)')}
        {field('label', t('legacyAgent.packages.label') || 'Label')}
        <div className="flex items-end"><Button onClick={() => void upload()} disabled={busy || !file || !meta.packageName || !meta.versionCode}><Upload size={14} /> {t('legacyAgent.packages.upload') || 'Upload'}</Button></div>
      </div>
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-text-muted"><tr>
          <th className="p-2">{t('legacyAgent.packages.label') || 'Label'}</th><th className="p-2">{t('legacyAgent.packages.packageName') || 'Package name'}</th>
          <th className="p-2">{t('legacyAgent.packages.version') || 'Version'}</th><th className="p-2">SHA-256</th><th className="p-2">{t('legacyAgent.packages.size') || 'Size'}</th>
        </tr></thead>
        <tbody>{(rows ?? []).map((p) => (
          <tr key={p.id} className="border-t border-border">
            <td className="p-2">{p.label ?? '—'}</td><td className="p-2">{p.packageName}</td><td className="p-2">{p.versionName ?? ''} ({p.versionCode})</td>
            <td className="p-2 font-mono text-xs">{p.sha256.slice(0, 16)}…</td><td className="p-2">{t('legacyAgent.packages.mib', { size: (p.sizeBytes / 1048576).toFixed(1) }) || `${(p.sizeBytes / 1048576).toFixed(1)} MiB`}</td>
          </tr>))}
        </tbody>
      </table>
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
      <section className="rounded border border-border p-3">
        <h3 className="mb-2 font-semibold">{t('legacyAgent.serverKey.title') || 'Instance key (to pin in the APK)'}</h3>
        {key && (key.missing
          ? <p className="text-red-500">{t('legacyAgent.serverKey.missing') || 'The instance key is missing from the vault: restore the escrowed key.'}</p>
          : (<>
            <div className="font-mono text-xs break-all">SHA-256 : {key.spkiSha256}</div>
            <div className="font-mono text-xs break-all">keyId : {key.keyId}</div>
            <div className="mt-1 flex items-center gap-2">
              <Button variant="ghost" onClick={() => void copy(key.spkiSha256, t('legacyAgent.copied') || 'Copied')}><Copy size={14} /> {t('legacyAgent.serverKey.copyPin') || 'Copy the fingerprint'}</Button>
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
      <section className="rounded border border-border p-3">
        <h3 className="mb-2 font-semibold">{t('legacyAgent.releases.title') || 'Versions of the agent'}</h3>
        <p className="text-xs text-text-muted">{signers.length > 0 ? `LEGACY_AGENT_SIGNERS : ${signers.map((s) => s.slice(0, 12)).join(', ')}…`
          : (t('legacyAgent.releases.noSigners') || 'LEGACY_AGENT_SIGNERS is empty: no version can be added.')}</p>
        {settings?.bundle && <BundleLine bundle={settings.bundle} />}
        <div className="mt-2 grid gap-2 md:grid-cols-5">
          <label>{t('legacyAgent.packages.file') || 'APK'}<input className={fieldCls} type="file" accept=".apk" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
          <label>versionCode<input className={fieldCls} value={meta.versionCode} onChange={(e) => setMeta({ ...meta, versionCode: e.target.value })} /></label>
          <label>{t('legacyAgent.packages.versionName') || 'Version name'}<input className={fieldCls} value={meta.versionName} onChange={(e) => setMeta({ ...meta, versionName: e.target.value })} /></label>
          <label>{t('legacyAgent.releases.signer') || 'Signer SHA-256'}<input className={fieldCls} value={meta.signerSha256} onChange={(e) => setMeta({ ...meta, signerSha256: e.target.value })} /></label>
          <div className="flex items-end"><Button onClick={() => void addRelease()} disabled={!file || !meta.versionCode || !meta.versionName || !meta.signerSha256}><Upload size={14} /> {t('legacyAgent.releases.add') || 'Add'}</Button></div>
        </div>
        <div className="mt-2 overflow-x-auto">
        <table className="w-full">
          <tbody>{releases.map((r) => (
            <tr key={r.id} className="border-t border-border">
              <td className="p-2">{r.versionName} ({r.versionCode})</td><td className="p-2 font-mono text-xs">{r.sha256.slice(0, 16)}…</td>
              <td className="p-2 text-xs text-text-muted">{r.bundledIn ? bundledLabel(t, r.bundledIn) : (t('legacyAgent.releases.uploaded') || 'Uploaded')}</td>
              <td className="p-2">{fmt(r.createdAt)}</td>
              <td className="p-2 text-right">{r.withdrawnAt ? (t('legacyAgent.releases.withdrawn') || 'Withdrawn') : <Button variant="ghost" onClick={() => void withdraw(r)}><Ban size={14} /></Button>}</td>
            </tr>))}
          </tbody>
        </table>
        </div>
      </section>
      {settings && (
        <section className="rounded border border-border p-3">
          <h3 className="mb-2 font-semibold">{t('legacyAgent.settings.title') || 'Instance settings'}</h3>
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
    <div className="grid gap-2 md:grid-cols-4">
      <label className="flex items-center gap-2 md:col-span-3">
        <input type="checkbox" checked={auto.on} onChange={(e) => setAuto({ ...auto, on: e.target.checked })} />
        {t('legacyAgent.settings.autoUpdate') || 'Update the agents automatically to the version embedded in the server image'}
      </label>
      <label>{t('legacyAgent.settings.autoUpdatePerHour') || 'Devices per hour'}<input className={fieldCls} type="number" min={LEGACY_AGENT_AUTO_UPDATE_BOUNDS.min} max={LEGACY_AGENT_AUTO_UPDATE_BOUNDS.max} value={auto.perHour} disabled={!auto.on} onChange={(e) => setAuto({ ...auto, perHour: e.target.value })} /></label>
      <p className="text-xs text-text-muted md:col-span-4">{t('legacyAgent.settings.autoUpdateHint') || 'Every 10 minutes, the enrolled agents older than the latest version embedded in the server image (not withdrawn) get it, in batches: those that install silently (device administrator and Knox licence) first. Only the agents that interrogated in the last 24 hours; a refusal, a failure or an expiry is tried again after 24 hours. An uploaded version is never pushed automatically. A frozen tenant, or a device the restrictions matrix holds for the agent update, gets nothing. Turning it on or raising the pace asks for a second factor.'}</p>
      <label>{t('legacyAgent.settings.pollSeconds') || 'Interrogation period (s)'}<input className={fieldCls} type="number" min={60} max={3600} value={v.pollSeconds} onChange={(e) => setV({ ...v, pollSeconds: e.target.value })} /></label>
      <label>{t('legacyAgent.settings.minVersionCode') || 'Minimal versionCode'}<input className={fieldCls} type="number" min={0} value={v.minVersionCode} onChange={(e) => setV({ ...v, minVersionCode: e.target.value })} /></label>
      <label>{t('legacyAgent.settings.inventorySeconds') || 'Inventory period (s)'}<input className={fieldCls} type="number" min={3600} value={v.inventorySeconds} onChange={(e) => setV({ ...v, inventorySeconds: e.target.value })} /></label>
      <div className="flex items-end"><Button onClick={() => void onSave(patch)} disabled={Object.keys(patch).length === 0 || (auto.on && !perHourValid)}>{t('common.save') || 'Save'}</Button></div>
    </div>
  );
}
