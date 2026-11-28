import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Ban, Building2, Download, LifeBuoy, Pause, Pencil, Play, Plus, ShieldAlert, ShieldCheck, Tag, Trash2, Usb } from 'lucide-react';
import {
  BENCH_ROLE_POLICIES, MASTER_TENANT_ID,
  type BenchRolePolicy, type BenchStationDetail, type BenchStationInstallerInfo, type BenchStationView, type BenchTargetView,
} from '@obligarth/shared';
import { benchStationsApi, type BenchServedInfo } from '@/api/benchStations.api';
import { apiErrorCode } from '@/utils/apiError';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { StationDecisionDialog } from '@/components/bench/StationDecisionDialog';
import { NameTemplateDialog, NameTemplateField, templateCheck } from '@/components/bench/NameTemplateField';
import {
  StationStatusPill, cardCls, cardTitleCls, chipCls, fail, fieldCls, fmt, headCls, labelCls, listCls, rowCls, tdCls, thCls, useRolePolicyLabel,
} from '@/components/bench/benchUi';

// The bench stations of the platform (lot BANC §3.12; master tenant, platform administrators): the stations, pending
// first; the approval (code typed again, second factor), the suspension (no second factor), the revocation (second
// factor: tokens not consumed revoked, open provisionings abandoned, session closed); the targets (tenant and group,
// role policy, name prefix, developer options cut at the end, the exception D3); the bench session of the administrator;
// the version of the agent served to the stations; the installer of the station; what to do when a PC is stolen.
// Lot BANC-T: the platform's stations belong to the master tenant (Default); a client's station shows « Belongs to
// <tenant> » and the platform only watches and cuts it (Q1): it reads it, suspends it (the client does not lift that),
// resumes its own suspension, revokes it, closes its session, suspends one of its targets. A platform station is given
// to a client (Q2, strict second factor, every target in that tenant), never the other way.

/** The station belongs to a client (not the platform): the platform watches and cuts it only. */
const isClientStation = (s: Pick<BenchStationView, 'ownerTenantId'>): boolean => s.ownerTenantId !== MASTER_TENANT_ID;

/** « Platform », « Belongs to <tenant> », or a revoked station whose tenant was deleted. */
function OwnerBadge({ station: s }: { station: Pick<BenchStationView, 'ownerTenantId' | 'ownerTenantName'> }) {
  const { t } = useTranslation();
  if (s.ownerTenantId === MASTER_TENANT_ID) return <span className="whitespace-nowrap rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-muted">{t('bench.owned.platform') || 'Platform'}</span>;
  if (s.ownerTenantId === null) return <span className="whitespace-nowrap rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-muted">{t('bench.owned.ownerDeleted') || 'Tenant deleted'}</span>;
  const name = s.ownerTenantName ?? `#${s.ownerTenantId}`;
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-full bg-accent/15 px-2 py-0.5 text-[11px] font-medium text-accent">
      <Building2 className="h-3 w-3" />{t('bench.owned.belongsTo', { tenant: name }) || `Belongs to ${name}`}
    </span>
  );
}

export function BenchStationsPage() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<BenchStationView[] | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const load = useCallback(() => {
    benchStationsApi.list().then(setRows).catch((err) => { setRows([]); fail(err); });
  }, []);
  useEffect(() => { load(); }, [load]);
  // The stations that wait for their approval poll every 5 s: the list follows them.
  useEffect(() => { const id = window.setInterval(load, 30_000); return () => window.clearInterval(id); }, [load]);

  return (
    <PageContainer className="space-y-5">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-bold text-text-primary">{t('bench.stations.title') || 'Bench stations'}</h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('bench.stations.subtitle') || 'Windows stations of the technicians that enroll new Android devices by USB (ADB), the agent as the owner of the device when possible.'}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => setHelpOpen((v) => !v)}><LifeBuoy className="mr-1 h-4 w-4" />{t('bench.stations.theft.button') || 'Stolen PC'}</Button>
      </div>
      {helpOpen && <TheftHelp />}
      <ServedReleaseCard />
      <StationsList rows={rows} onOpen={setOpenId} />
      {openId && <StationDetail id={openId} onClose={() => setOpenId(null)} onChanged={load} />}
    </PageContainer>
  );
}

function TheftHelp() {
  const { t } = useTranslation();
  const steps = [
    t('bench.stations.theft.step1') || 'Suspend the station (one click, no second factor): it can no longer act.',
    t('bench.stations.theft.step2') || 'Revoke it: its unused tokens are revoked and its open enrollments abandoned.',
    t('bench.stations.theft.step3') || 'Review the devices this station enrolled since the theft, and put the doubtful ones in identity quarantine.',
    t('bench.stations.theft.step4') || 'The renewed station creates a new ADB key: the old authorisation expires on Android 11 and later after 7 days; on Android 7 to 9, revoke the USB debugging authorisations at the next visit.',
  ];
  return (
    <div className={clsx(cardCls, 'text-sm')}>
      <h3 className={cardTitleCls}><ShieldAlert size={14} className="text-amber-400" /> {t('bench.stations.theft.title') || 'A PC of a technician is stolen'}</h3>
      <ol className="list-decimal space-y-1 pl-5 text-text-secondary">{steps.map((s) => <li key={s}>{s}</li>)}</ol>
    </div>
  );
}

function ServedReleaseCard() {
  const { t } = useTranslation();
  const [info, setInfo] = useState<BenchServedInfo | null>(null);
  const [installer, setInstaller] = useState<BenchStationInstallerInfo | null>(null);
  const [choice, setChoice] = useState('');
  const load = useCallback(() => {
    benchStationsApi.release().then((r) => { setInfo(r); setChoice(r.served?.releaseId ?? ''); }).catch(fail);
    benchStationsApi.installer().then(setInstaller).catch(() => setInstaller(null));
  }, []);
  useEffect(() => { load(); }, [load]);
  const save = async () => {
    try {
      await benchStationsApi.setRelease(choice || null);
      toast.success(t('bench.stations.release.saved') || 'Version served to the bench saved');
      load();
    } catch (err) { fail(err); }
  };
  const served = info?.served ?? null;
  return (
    <section className={clsx(cardCls, 'grid gap-4 text-sm md:grid-cols-2')}>
      <div>
        <h3 className={cardTitleCls}><Usb size={14} /> {t('bench.stations.release.title') || 'Agent version served to the bench'}</h3>
        <p className="text-xs text-text-muted">{t('bench.stations.release.hint') || 'Chosen explicitly (second factor): an uploaded version, never pushed to the fleet by the automatic update. The station checks its signer against the fingerprint pinned in its binary. The public link of the agent (/api/legacy-agent/public/agent.apk) serves this version too: a version uploaded for a pilot group stays off it until it is chosen here.'}</p>
        <div className="mt-2 flex flex-wrap items-end gap-2">
          <label className={clsx(labelCls, 'min-w-[14rem] flex-1')}>{t('bench.stations.release.version') || 'Version'}
            <select className={fieldCls} value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">{t('bench.stations.release.none') || 'None (the stations get no APK)'}</option>
              {(info?.releases ?? []).map((r) => <option key={r.id} value={r.id}>{`${r.versionName} (${r.versionCode})`}</option>)}
            </select>
          </label>
          <Button onClick={() => void save()} disabled={choice === (served?.releaseId ?? '')}>{t('common.save') || 'Save'}</Button>
        </div>
        {served && (
          <p className="mt-2 text-xs text-text-muted">
            {served.deviceOwnerCapable ? (t('bench.stations.release.ownerCapable') || 'This version can own the device (1.4.0 and later).')
              : (t('bench.stations.release.adminOnly') || 'This version is older than 1.4.0: device administrator only (unless the exception D3 of a target).')}
            {!served.signerAdmitted && <span className="ml-1 text-red-400">{t('bench.stations.release.signerRefused') || 'Its signer is no longer admitted: not served.'}</span>}
          </p>
        )}
      </div>
      <div>
        <h3 className={cardTitleCls}><Download size={14} /> {t('bench.stations.installer.title') || 'Installer of the station'}</h3>
        {installer?.available ? (
          <div className="space-y-1 text-xs">
            <a className="text-accent hover:underline" href="/api/bench/download/obligarth-bench.msi">
              {t('bench.stations.installer.download', { version: installer.version ?? '' }) || `Download the bench station ${installer.version ?? ''}`}
            </a>
            <div className="break-all font-mono text-text-muted">SHA-256 : {installer.sha256}</div>
          </div>
        ) : <p className="text-xs text-text-muted">{t('bench.stations.installer.unavailable') || 'No installer in this server image.'}</p>}
      </div>
    </section>
  );
}

type Filter = 'all' | 'pending' | 'approved' | 'suspended' | 'revoked';
/** The owner filter: every station, the platform's, every client's, or one client's (its tenant id). */
type OwnerFilter = 'all' | 'platform' | 'clients' | number;

function StationsList({ rows: all, onOpen }: { rows: BenchStationView[] | null; onOpen: (id: string) => void }) {
  const { t } = useTranslation();
  const [filter, setFilter] = useState<Filter>('all');
  const [owner, setOwner] = useState<OwnerFilter>('all');
  const owners = useMemo(() => {
    const m = new Map<number, { name: string; count: number }>();
    for (const r of all ?? []) {
      if (r.ownerTenantId === null || r.ownerTenantId === MASTER_TENANT_ID) continue;
      const e = m.get(r.ownerTenantId) ?? { name: r.ownerTenantName ?? `#${r.ownerTenantId}`, count: 0 };
      e.count++;
      m.set(r.ownerTenantId, e);
    }
    return [...m.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name));
  }, [all]);
  const ownerMatch = (r: BenchStationView): boolean => (owner === 'all' ? true : owner === 'platform' ? r.ownerTenantId === MASTER_TENANT_ID
    : owner === 'clients' ? isClientStation(r) : r.ownerTenantId === owner);
  const rows = all ? all.filter(ownerMatch) : null;
  const platformCount = (all ?? []).filter((r) => r.ownerTenantId === MASTER_TENANT_ID).length;
  const clientCount = (all ?? []).filter(isClientStation).length;
  const counts = useMemo(() => {
    const c: Record<Filter, number> = { all: 0, pending: 0, approved: 0, suspended: 0, revoked: 0 };
    for (const r of rows ?? []) { c.all++; c[r.status]++; }
    return c;
  }, [rows]);
  const shown = (rows ?? []).filter((r) => filter === 'all' || r.status === filter);
  const filters: Filter[] = ['all', 'pending', 'approved', 'suspended', 'revoked'];
  const filterLabel = (f: Filter) => (f === 'all' ? (t('bench.stations.filter.all') || 'All') : (t(`bench.stations.status.${f}`) || f));
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1">
        {filters.map((f) => (
          <button key={f} type="button" className={chipCls(filter === f)} onClick={() => setFilter(f)}>
            {filterLabel(f)}<span className="tabular-nums opacity-70">{counts[f]}</span>
          </button>
        ))}
      </div>
      {clientCount > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="mr-1 text-[10px] font-medium uppercase tracking-wider text-text-muted">{t('bench.owned.ownerFilter') || 'Owner'}</span>
          <button type="button" className={chipCls(owner === 'all')} onClick={() => setOwner('all')}>{t('bench.stations.filter.all') || 'All'}<span className="tabular-nums opacity-70">{(all ?? []).length}</span></button>
          <button type="button" className={chipCls(owner === 'platform')} onClick={() => setOwner('platform')}>{t('bench.owned.platform') || 'Platform'}<span className="tabular-nums opacity-70">{platformCount}</span></button>
          <button type="button" className={chipCls(owner === 'clients')} onClick={() => setOwner('clients')}>{t('bench.owned.clients') || 'Clients'}<span className="tabular-nums opacity-70">{clientCount}</span></button>
          {owners.map(([id, o]) => (
            <button key={id} type="button" className={chipCls(owner === id)} onClick={() => setOwner(id)}>{o.name}<span className="tabular-nums opacity-70">{o.count}</span></button>
          ))}
        </div>
      )}
      <div className={listCls}>
        <table className="w-full text-sm">
          <thead className={headCls}><tr>
            <th className={thCls}>{t('bench.stations.name') || 'Name'}</th>
            <th className={thCls}>{t('bench.owned.ownerFilter') || 'Owner'}</th>
            <th className={thCls}>{t('bench.stations.host') || 'Host'}</th>
            <th className={thCls}>{t('bench.stations.version') || 'Version'}</th>
            <th className={thCls}>{t('bench.stations.state') || 'State'}</th>
            <th className={thCls}>{t('bench.stations.lastSeen') || 'Last activity'}</th>
            <th className={thCls}>{t('bench.stations.targetsCount') || 'Targets'}</th>
            <th className={thCls}>{t('bench.stations.enrolledCount') || 'Enrolled'}</th>
          </tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id} className={clsx(rowCls, 'cursor-pointer')} onClick={() => onOpen(r.id)}>
                <td className={clsx(tdCls, 'font-medium text-text-primary')}>{r.name}</td>
                <td className={tdCls}><OwnerBadge station={r} /></td>
                <td className={clsx(tdCls, 'text-text-secondary')}>{r.hostname || '—'}</td>
                <td className={clsx(tdCls, 'text-text-secondary')}>{r.stationVersion ?? '—'}</td>
                <td className={tdCls}><StationStatusPill status={r.status} /></td>
                <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-secondary')}>{fmt(r.lastSeenAt)}<span className="ml-1 font-mono text-text-muted">{r.lastIp ?? ''}</span></td>
                <td className={clsx(tdCls, 'tabular-nums text-text-secondary')}>{r.targetCount}</td>
                <td className={clsx(tdCls, 'tabular-nums text-text-secondary')}>{r.enrolledCount}</td>
              </tr>
            ))}
            {rows && shown.length === 0 && <tr><td colSpan={8} className="p-8 text-center text-text-muted">{t('bench.stations.empty') || 'No station.'}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StationDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const [s, setS] = useState<BenchStationDetail | null>(null);
  const [approving, setApproving] = useState(false);
  const [adding, setAdding] = useState(false);
  const [giving, setGiving] = useState(false);
  const load = useCallback(() => { benchStationsApi.get(id).then(setS).catch(fail); }, [id]);
  useEffect(() => { load(); }, [load]);
  const act = async (fn: () => Promise<BenchStationDetail>, done?: string) => {
    try { setS(await fn()); onChanged(); if (done) toast.success(done); } catch (err) {
      if (apiErrorCode(err) === 'stationOwned') toast.error(t('bench.owned.stationOwnedError') || 'This station belongs to a client: the platform only suspends or revokes it.', { duration: 7000 });
      else fail(err);
      load();
    }
  };
  if (!s) return <Modal open onClose={onClose} size="2xl" title={t('bench.stations.title') || 'Bench stations'}><div className="p-6 text-sm text-text-muted">…</div></Modal>;

  const revoke = async () => {
    const ok = await confirm({
      title: t('bench.stations.revokeTitle', { name: s.name }) || `Revoke ${s.name}`, danger: true, confirmLabel: t('bench.stations.revoke') || 'Revoke',
      message: t('bench.stations.revokeConfirm') || 'Final: its unused enrollment tokens are revoked, its open provisionings abandoned and its session closed. A second factor is asked.',
    });
    if (ok) await act(() => benchStationsApi.revoke(s.id), t('bench.stations.revoked') || 'Station revoked');
  };
  const rename = async () => {
    const name = await prompt({ title: t('bench.stations.rename') || 'Rename', defaultValue: s.name, required: true });
    if (name && name.trim() !== s.name) await act(() => benchStationsApi.rename(s.id, name.trim()));
  };
  const owned = isClientStation(s);
  const givable = s.ownerTenantId === MASTER_TENANT_ID && (s.status === 'approved' || s.status === 'suspended');
  const row = (k: string, v: ReactNode) => (
    <div key={k} className="flex justify-between gap-4 rounded-md px-3 py-1.5 transition-colors hover:bg-bg-tertiary">
      <span className="text-text-muted">{k}</span><span className="break-all text-right text-text-primary">{v}</span>
    </div>
  );
  return (
    <Modal open onClose={onClose} size="2xl" title={s.name} headerExtra={<span className="flex items-center gap-2"><StationStatusPill status={s.status} /><OwnerBadge station={s} /></span>}>
      <div className="space-y-4 text-sm">
        <div className="flex flex-wrap gap-2">
          {s.status === 'pending' && <Button size="sm" onClick={() => setApproving(true)}><ShieldCheck className="mr-1 h-4 w-4" />{t('bench.stations.approve') || 'Approve'}</Button>}
          {/* A client's station its owner suspended: the platform makes that suspension its own (Q1, the client then no longer lifts it). */}
          {(s.status === 'approved' || (owned && s.status === 'suspended' && !s.suspendedByPlatform)) && <Button size="sm" variant="secondary" onClick={() => void act(() => benchStationsApi.suspend(s.id), t('bench.stations.suspended') || 'Station suspended')}><Pause className="mr-1 h-4 w-4" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
          {s.status === 'suspended' && (!owned || s.suspendedByPlatform) && <Button size="sm" variant="secondary" onClick={() => void act(() => benchStationsApi.resume(s.id))}><Play className="mr-1 h-4 w-4" />{t('bench.stations.resume') || 'Resume'}</Button>}
          {s.status !== 'revoked' && <Button size="sm" variant="danger" onClick={() => void revoke()}><Ban className="mr-1 h-4 w-4" />{t('bench.stations.revoke') || 'Revoke'}</Button>}
          {!owned && <Button size="sm" variant="ghost" onClick={() => void rename()}><Pencil className="mr-1 h-4 w-4" />{t('bench.stations.rename') || 'Rename'}</Button>}
          {givable && <Button size="sm" variant="ghost" onClick={() => setGiving(true)}><Building2 className="mr-1 h-4 w-4" />{t('bench.owned.give') || 'Give to a client'}</Button>}
        </div>
        {owned && (
          <div className="flex items-start gap-2 rounded-xl bg-accent/10 px-3 py-2 text-xs text-text-secondary">
            <Building2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
            <span>
              {s.ownerTenantId === null
                ? (t('bench.owned.platformViewDeleted') || 'Its tenant was deleted: the station was revoked.')
                : (t('bench.owned.platformView', { tenant: s.ownerTenantName ?? '', since: fmt(s.ownerSince) }) || `This station belongs to ${s.ownerTenantName ?? ''} since ${fmt(s.ownerSince)}: the client manages its name, targets and sessions. The platform watches it and cuts it: suspend, revoke, close its session, suspend a target.`)}
              {s.status === 'suspended' && (s.suspendedByPlatform
                ? <span className="ml-1 text-amber-400">{t('bench.owned.suspendedByPlatformNote') || 'Suspended by the platform: the client cannot lift it.'}</span>
                : <span className="ml-1 text-text-muted">{t('bench.owned.suspendedByOwnerNote') || 'Suspended by its owner: the client resumes it.'}</span>)}
            </span>
          </div>
        )}
        <div className="rounded-xl bg-bg-secondary py-1">
          {row(t('bench.stations.host') || 'Host', s.hostname || '—')}
          {row(t('bench.stations.version') || 'Version', s.stationVersion ?? '—')}
          {row(t('bench.stations.createdAt') || 'Registered', `${fmt(s.createdAt)} · ${s.registerIp ?? '—'}`)}
          {row(t('bench.stations.lastSeen') || 'Last activity', `${fmt(s.lastSeenAt)} · ${s.lastIp ?? '—'}`)}
          {s.approvedAt && row(t('bench.stations.approvedAt') || 'Approved', fmt(s.approvedAt))}
          {s.revokedAt && row(t('bench.stations.revokedAt') || 'Revoked', `${fmt(s.revokedAt)}${s.revokedReason ? ` (${t(`bench.stations.revokedReason.${s.revokedReason}`) || s.revokedReason})` : ''}`)}
          {row(t('bench.stations.enrolledCount') || 'Enrolled', s.enrolledCount)}
        </div>

        {/* 28/11/2026: no bench session any more; an approved station enrolls within its targets by itself. */}
        <p className="text-xs text-text-muted">{t('bench.stations.autonomy') || 'An approved station enrolls by itself within its targets (tenant and group, the sites below them), with no session to open: each token, conversion and app it installs is audited in the name of the station. To stop it, suspend it (one click) or revoke it.'}</p>

        <section>
          <div className="mb-2 flex items-center">
            <h3 className={clsx(cardTitleCls, 'mb-0')}>{t('bench.stations.targets.title') || 'Targets'}</h3>
            {s.status !== 'revoked' && !owned && <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setAdding(true)}><Plus className="mr-1 h-4 w-4" />{t('bench.stations.targets.add') || 'Add a target'}</Button>}
          </div>
          <TargetsList station={s} readOnly={owned} onChange={(fn) => void act(fn)} />
        </section>
      </div>
      {approving && (
        <StationDecisionDialog station={s} onClose={() => setApproving(false)}
          onApprove={async (code) => {
            try { setS(await benchStationsApi.approve(s.id, code)); onChanged(); setApproving(false); toast.success(t('bench.stations.approved') || 'Station approved'); } catch (err) {
              if (apiErrorCode(err) === 'verification_mismatch') toast.error(t('bench.stations.verificationMismatch') || 'The verification code does not match this station.');
              else fail(err);
            }
          }} />
      )}
      {giving && <AssignOwnerDialog station={s} onClose={() => setGiving(false)} onGiven={(d) => { setS(d); onChanged(); setGiving(false); }} />}
      {adding && <AddTargetDialog station={s} onClose={() => setAdding(false)} onAdded={(d) => { setS(d); onChanged(); setAdding(false); }} />}
    </Modal>
  );
}

/** The targets; readOnly (a client's station, Q1): shown, and only a target suspended (the rest is the client's). */
function TargetsList({ station, readOnly, onChange }: { station: BenchStationDetail; readOnly: boolean; onChange: (fn: () => Promise<BenchStationDetail>) => void }) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<BenchTargetView | null>(null);
  const confirm = useConfirm();
  const policyLabel = useRolePolicyLabel();
  const patch = (x: BenchTargetView, p: Parameters<typeof benchStationsApi.patchTarget>[3]) => onChange(() => benchStationsApi.patchTarget(station.id, x.tenantId, x.groupId, p));
  const allowLegacy = async (x: BenchTargetView, on: boolean) => {
    if (on && !(await confirm({
      danger: true, confirmLabel: t('common.confirm') || 'Confirm',
      message: t('bench.stations.targets.legacyOwnerWarning') || 'Exception: the agent 1.3.0 set as the owner of the device cannot give it back; only a reset removes it. For a test target only. A second factor is asked.',
    }))) return;
    patch(x, { allowLegacyOwner: on });
  };
  const remove = async (x: BenchTargetView) => {
    if (await confirm({ danger: true, message: t('bench.stations.targets.removeConfirm', { group: x.groupPath }) || `Remove the target ${x.groupPath}?` })) {
      onChange(() => benchStationsApi.removeTarget(station.id, x.tenantId, x.groupId));
    }
  };
  if (station.targets.length === 0) return <p className={clsx(cardCls, 'text-center text-text-muted')}>{t('bench.stations.targets.empty') || 'No target: the station can enroll nothing.'}</p>;
  return (
    <ul className="space-y-2">
      {station.targets.map((x) => (
        <li key={`${x.tenantId}:${x.groupId}`} className={clsx(cardCls, 'space-y-2 transition-colors hover:bg-bg-tertiary')}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-text-primary">{x.tenantName}</span><span className="text-text-muted">›</span>
            <span className="text-text-primary">{x.groupPath || `#${x.groupId}`}</span>
            {x.suspendedAt && <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-400">{x.suspendedByPlatform
              ? (t('bench.owned.targetSuspendedByPlatform') || 'Suspended by the platform')
              : (t('bench.stations.targets.suspended') || 'Suspended')}</span>}
            <span className="ml-auto flex gap-1">
              {readOnly
                // A client's station (Q1): suspend (also over a suspension of the client), resume only its own suspension.
                ? (x.suspendedByPlatform
                  ? <Button size="sm" variant="ghost" onClick={() => patch(x, { suspended: false })}><Play className="mr-1 h-3.5 w-3.5" />{t('bench.stations.resume') || 'Resume'}</Button>
                  : <Button size="sm" variant="ghost" onClick={() => patch(x, { suspended: true })}><Pause className="mr-1 h-3.5 w-3.5" />{t('bench.stations.suspend') || 'Suspend'}</Button>)
                : x.suspendedAt
                  ? <Button size="sm" variant="ghost" onClick={() => patch(x, { suspended: false })}><Play className="mr-1 h-3.5 w-3.5" />{t('bench.stations.resume') || 'Resume'}</Button>
                  : <Button size="sm" variant="ghost" onClick={() => patch(x, { suspended: true })}><Pause className="mr-1 h-3.5 w-3.5" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
              {!readOnly && <Button size="sm" variant="ghost" onClick={() => void remove(x)} title={t('bench.stations.targets.remove') || 'Remove'}><Trash2 className="h-3.5 w-3.5" /></Button>}
            </span>
          </div>
          {readOnly ? (
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
              <span>{policyLabel(x.rolePolicy)}</span>
              {x.disableDevOptions && <span>{t('bench.stations.targets.disableDevOptions') || 'Turn the developer options off at the end'}</span>}
              {x.allowLegacyOwner && <span className="text-amber-400">{t('bench.stations.targets.allowLegacyOwner') || 'Exception: device owner with the agent 1.3.0'}</span>}
            </div>
          ) : (
            <>
              <div className="flex flex-wrap gap-1">
                {BENCH_ROLE_POLICIES.map((p) => (
                  <button key={p} type="button" className={chipCls(x.rolePolicy === p)} onClick={() => { if (x.rolePolicy !== p) patch(x, { rolePolicy: p }); }}>{policyLabel(p)}</button>
                ))}
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                <ToggleSwitch size="sm" checked={x.disableDevOptions} onChange={(on) => patch(x, { disableDevOptions: on })}
                  label={t('bench.stations.targets.disableDevOptions') || 'Turn the developer options off at the end'} />
                <ToggleSwitch size="sm" checked={x.allowLegacyOwner} onChange={(on) => void allowLegacy(x, on)}
                  label={t('bench.stations.targets.allowLegacyOwner') || 'Exception: device owner with the agent 1.3.0'} />
              </div>
            </>
          )}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
            <span>{t('bench.stations.targets.namePrefix') || 'Name prefix'} : <span className="font-mono text-text-secondary">{x.namePrefix || '—'}</span></span>
            <span className="inline-flex items-center gap-1"><Tag className="h-3.5 w-3.5" />{t('bench.nameTemplate.short') || 'Suggested name'} : <span className="font-mono text-text-secondary">{x.nameTemplate || '—'}</span></span>
            {!readOnly && <Button size="sm" variant="ghost" onClick={() => setEditing(x)}><Pencil className="mr-1 h-3.5 w-3.5" />{t('bench.nameTemplate.edit') || 'Change'}</Button>}
          </div>
        </li>
      ))}
      {editing && (
        <NameTemplateDialog initial={editing.nameTemplate} target={`${editing.tenantName} › ${editing.groupPath}`} onClose={() => setEditing(null)}
          onSave={async (nameTemplate) => { patch(editing, { nameTemplate }); setEditing(null); }} />
      )}
    </ul>
  );
}

function AddTargetDialog({ station, onClose, onAdded }: { station: BenchStationDetail; onClose: () => void; onAdded: (d: BenchStationDetail) => void }) {
  const { t } = useTranslation();
  const policyLabel = useRolePolicyLabel();
  const [tenants, setTenants] = useState<Array<{ id: number; name: string }>>([]);
  const [groups, setGroups] = useState<Array<{ id: number; path: string }>>([]);
  const [form, setForm] = useState<{ tenantId: string; groupId: string; rolePolicy: BenchRolePolicy; namePrefix: string; nameTemplate: string; disableDevOptions: boolean }>(
    { tenantId: '', groupId: '', rolePolicy: 'owner_preferred', namePrefix: '', nameTemplate: '', disableDevOptions: true });
  const [q, setQ] = useState('');
  useEffect(() => { benchStationsApi.tenants().then(setTenants).catch(fail); }, []);
  useEffect(() => {
    setGroups([]);
    if (form.tenantId) benchStationsApi.tenantGroups(Number(form.tenantId)).then(setGroups).catch(fail);
  }, [form.tenantId]);
  const prefixOk = /^[A-Za-z0-9_-]{0,32}$/.test(form.namePrefix);
  const shown = groups.filter((g) => !q.trim() || g.path.toLowerCase().includes(q.trim().toLowerCase())).slice(0, 200);
  const add = async () => {
    try {
      onAdded(await benchStationsApi.addTarget(station.id, {
        tenantId: Number(form.tenantId), groupId: Number(form.groupId), rolePolicy: form.rolePolicy, namePrefix: form.namePrefix || null,
        nameTemplate: form.nameTemplate || null, disableDevOptions: form.disableDevOptions,
      }));
    } catch (err) { fail(err); }
  };
  return (
    <Modal open onClose={onClose} size="lg" title={t('bench.stations.targets.add') || 'Add a target'}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void add()} disabled={!form.tenantId || !form.groupId || !prefixOk || !templateCheck(form.nameTemplate).ok}>{t('bench.stations.targets.add') || 'Add a target'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <label className={labelCls}>{t('bench.stations.targets.tenant') || 'Tenant'}
          <select className={fieldCls} value={form.tenantId} onChange={(e) => setForm({ ...form, tenantId: e.target.value, groupId: '' })}>
            <option value="">—</option>
            {tenants.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
          </select>
        </label>
        {form.tenantId && (
          <div>
            <span className={labelCls}>{t('bench.stations.targets.group') || 'Group'}</span>
            <input className={fieldCls} value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('bench.stations.targets.search') || 'Search a group'} />
            <div className="mt-1 max-h-56 overflow-y-auto rounded-xl bg-bg-secondary py-1">
              {shown.map((g) => (
                <button key={g.id} type="button" onClick={() => setForm({ ...form, groupId: String(g.id) })}
                  className={clsx('block w-full px-3 py-1.5 text-left text-sm transition-colors hover:bg-bg-tertiary', String(g.id) === form.groupId ? 'text-accent' : 'text-text-primary')}>
                  {g.path}
                </button>
              ))}
              {shown.length === 0 && <div className="px-3 py-2 text-xs text-text-muted">{t('bench.stations.targets.noGroup') || 'No group.'}</div>}
            </div>
          </div>
        )}
        <div>
          <span className={labelCls}>{t('bench.stations.targets.rolePolicy') || 'Role'}</span>
          <div className="mt-1 flex flex-wrap gap-1">
            {BENCH_ROLE_POLICIES.map((p) => <button key={p} type="button" className={chipCls(form.rolePolicy === p)} onClick={() => setForm({ ...form, rolePolicy: p })}>{policyLabel(p)}</button>)}
          </div>
        </div>
        <NameTemplateField value={form.nameTemplate} onChange={(v) => setForm({ ...form, nameTemplate: v })} />
        <label className={labelCls}>{t('bench.stations.targets.namePrefix') || 'Name prefix'}
          <input className={fieldCls} value={form.namePrefix} maxLength={32} onChange={(e) => setForm({ ...form, namePrefix: e.target.value })} placeholder="AB" />
        </label>
        <ToggleSwitch size="sm" checked={form.disableDevOptions} onChange={(on) => setForm({ ...form, disableDevOptions: on })}
          label={t('bench.stations.targets.disableDevOptions') || 'Turn the developer options off at the end'} />
        <p className="text-xs text-text-muted">{t('bench.stations.targets.addHint') || 'A second factor is asked. The tenant sees the stations that target it and can suspend or remove a target.'}</p>
      </div>
    </Modal>
  );
}

/** Lot BANC-T, Q2: a platform station given to a client tenant (strict second factor). Every target and open
 *  provisioning must already be in that tenant (409 foreignTargets); its open session is closed; never the other way. */
function AssignOwnerDialog({ station, onClose, onGiven }: { station: BenchStationDetail; onClose: () => void; onGiven: (d: BenchStationDetail) => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [tenants, setTenants] = useState<Array<{ id: number; name: string }>>([]);
  const [tenantId, setTenantId] = useState<number | null>(() => {
    // The tenant of the targets is the natural choice: the only one the server accepts when the station has targets.
    const ids = [...new Set(station.targets.map((x) => x.tenantId))];
    return ids.length === 1 && ids[0] !== MASTER_TENANT_ID ? ids[0] : null;
  });
  const [busy, setBusy] = useState(false);
  useEffect(() => { benchStationsApi.tenants().then((l) => setTenants(l.filter((x) => x.id !== MASTER_TENANT_ID))).catch(fail); }, []);
  const foreign = tenantId === null ? [] : station.targets.filter((x) => x.tenantId !== tenantId);
  const chosen = tenants.find((x) => x.id === tenantId);
  const give = async () => {
    if (tenantId === null || !chosen) return;
    const ok = await confirm({
      danger: true, confirmLabel: t('bench.owned.giveSubmit') || 'Give the station',
      message: t('bench.owned.giveConfirm', { name: station.name, tenant: chosen.name }) || `${station.name} will belong to ${chosen.name} for good. Continue?`,
    });
    if (!ok) return;
    setBusy(true);
    try {
      const d = await benchStationsApi.assignOwner(station.id, tenantId);
      toast.success(t('bench.owned.given', { name: station.name, tenant: chosen.name }) || `${station.name} now belongs to ${chosen.name}`);
      onGiven(d);
    } catch (err) {
      if (apiErrorCode(err) === 'foreignTargets') toast.error(t('bench.owned.foreignTargets') || 'The station targets or provisions another tenant: remove those targets first.', { duration: 9000 });
      else fail(err);
    } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} size="md" icon={<Building2 className="h-4 w-4 text-accent" />}
      title={t('bench.owned.giveTitle', { name: station.name }) || `Give ${station.name} to a client`}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button variant="danger" onClick={() => void give()} disabled={!chosen || foreign.length > 0 || busy}>{t('bench.owned.giveSubmit') || 'Give the station'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <p className="text-text-secondary">
          {t('bench.owned.giveHint') || 'Final: the station then belongs to this client, who manages its name, targets and sessions; it never comes back to the platform. The platform keeps watching it: suspend, revoke. Its open session is closed. A second factor is asked.'}
        </p>
        <div>
          <span className={labelCls}>{t('bench.stations.targets.tenant') || 'Tenant'}</span>
          <div className="mt-1 max-h-56 overflow-y-auto rounded-xl bg-bg-secondary py-1">
            {tenants.map((x) => (
              <button key={x.id} type="button" onClick={() => setTenantId(x.id)}
                className={clsx('block w-full px-3 py-1.5 text-left text-sm transition-colors hover:bg-bg-tertiary', x.id === tenantId ? 'text-accent' : 'text-text-primary')}>
                {x.name}
              </button>
            ))}
            {tenants.length === 0 && <div className="px-3 py-2 text-xs text-text-muted">{t('bench.owned.noClient') || 'No client tenant.'}</div>}
          </div>
        </div>
        {foreign.length > 0 && (
          <div className="rounded-xl bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
            <div>{t('bench.owned.foreignTargetsList') || 'These targets are in another tenant: remove them first.'}</div>
            <ul className="mt-1 list-disc pl-5">{foreign.map((x) => <li key={`${x.tenantId}:${x.groupId}`}>{x.tenantName} › {x.groupPath}</li>)}</ul>
          </div>
        )}
      </div>
    </Modal>
  );
}
