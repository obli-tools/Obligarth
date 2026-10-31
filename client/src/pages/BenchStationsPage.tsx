import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Ban, Download, LifeBuoy, Pause, Pencil, Play, Plus, ShieldAlert, ShieldCheck, Timer, Trash2, Usb, XCircle } from 'lucide-react';
import {
  BENCH_LIMITS, BENCH_ROLE_POLICIES,
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
import {
  StationStatusPill, cardCls, cardTitleCls, chipCls, fail, fieldCls, fmt, headCls, labelCls, listCls, rowCls, tdCls, thCls, useRolePolicyLabel,
} from '@/components/bench/benchUi';

// The bench stations of the platform (lot BANC §3.12; master tenant, platform administrators): the stations, pending
// first; the approval (code typed again, second factor), the suspension (no second factor), the revocation (second
// factor: tokens not consumed revoked, open provisionings abandoned, session closed); the targets (tenant and group,
// role policy, name prefix, developer options cut at the end, the exception D3); the bench session of the administrator;
// the version of the agent served to the stations; the installer of the station; what to do when a PC is stolen.

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
    t('bench.stations.theft.step2') || 'Revoke it: its unused tokens are revoked, its open provisionings abandoned, its session closed.',
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
        <p className="text-xs text-text-muted">{t('bench.stations.release.hint') || 'Chosen explicitly (second factor): an uploaded version, never pushed to the fleet by the automatic update. The station checks its signer against the fingerprint pinned in its binary.'}</p>
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

function StationsList({ rows, onOpen }: { rows: BenchStationView[] | null; onOpen: (id: string) => void }) {
  const { t } = useTranslation();
  const [filter, setFilter] = useState<Filter>('all');
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
      <div className={listCls}>
        <table className="w-full text-sm">
          <thead className={headCls}><tr>
            <th className={thCls}>{t('bench.stations.name') || 'Name'}</th>
            <th className={thCls}>{t('bench.stations.host') || 'Host'}</th>
            <th className={thCls}>{t('bench.stations.version') || 'Version'}</th>
            <th className={thCls}>{t('bench.stations.state') || 'State'}</th>
            <th className={thCls}>{t('bench.stations.lastSeen') || 'Last activity'}</th>
            <th className={thCls}>{t('bench.stations.targetsCount') || 'Targets'}</th>
            <th className={thCls}>{t('bench.stations.enrolledCount') || 'Enrolled'}</th>
            <th className={thCls}>{t('bench.session.title') || 'Bench session'}</th>
          </tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id} className={clsx(rowCls, 'cursor-pointer')} onClick={() => onOpen(r.id)}>
                <td className={clsx(tdCls, 'font-medium text-text-primary')}>{r.name}</td>
                <td className={clsx(tdCls, 'text-text-secondary')}>{r.hostname || '—'}</td>
                <td className={clsx(tdCls, 'text-text-secondary')}>{r.stationVersion ?? '—'}</td>
                <td className={tdCls}><StationStatusPill status={r.status} /></td>
                <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-secondary')}>{fmt(r.lastSeenAt)}<span className="ml-1 font-mono text-text-muted">{r.lastIp ?? ''}</span></td>
                <td className={clsx(tdCls, 'tabular-nums text-text-secondary')}>{r.targetCount}</td>
                <td className={clsx(tdCls, 'tabular-nums text-text-secondary')}>{r.enrolledCount}</td>
                <td className={clsx(tdCls, 'text-xs text-text-secondary')}>{r.session ? `${r.session.technician ?? '—'} · ${fmt(r.session.expiresAt)}` : '—'}</td>
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
  const [minutes, setMinutes] = useState(String(BENCH_LIMITS.sessionMaxHours * 60));
  const load = useCallback(() => { benchStationsApi.get(id).then(setS).catch(fail); }, [id]);
  useEffect(() => { load(); }, [load]);
  const act = async (fn: () => Promise<BenchStationDetail>, done?: string) => {
    try { setS(await fn()); onChanged(); if (done) toast.success(done); } catch (err) { fail(err); }
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
  const row = (k: string, v: ReactNode) => (
    <div key={k} className="flex justify-between gap-4 rounded-md px-3 py-1.5 transition-colors hover:bg-bg-tertiary">
      <span className="text-text-muted">{k}</span><span className="break-all text-right text-text-primary">{v}</span>
    </div>
  );
  return (
    <Modal open onClose={onClose} size="2xl" title={s.name} headerExtra={<StationStatusPill status={s.status} />}>
      <div className="space-y-4 text-sm">
        <div className="flex flex-wrap gap-2">
          {s.status === 'pending' && <Button size="sm" onClick={() => setApproving(true)}><ShieldCheck className="mr-1 h-4 w-4" />{t('bench.stations.approve') || 'Approve'}</Button>}
          {s.status === 'approved' && <Button size="sm" variant="secondary" onClick={() => void act(() => benchStationsApi.suspend(s.id), t('bench.stations.suspended') || 'Station suspended')}><Pause className="mr-1 h-4 w-4" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
          {s.status === 'suspended' && <Button size="sm" variant="secondary" onClick={() => void act(() => benchStationsApi.resume(s.id))}><Play className="mr-1 h-4 w-4" />{t('bench.stations.resume') || 'Resume'}</Button>}
          {s.status !== 'revoked' && <Button size="sm" variant="danger" onClick={() => void revoke()}><Ban className="mr-1 h-4 w-4" />{t('bench.stations.revoke') || 'Revoke'}</Button>}
          <Button size="sm" variant="ghost" onClick={() => void rename()}><Pencil className="mr-1 h-4 w-4" />{t('bench.stations.rename') || 'Rename'}</Button>
        </div>
        <div className="rounded-xl bg-bg-secondary py-1">
          {row(t('bench.stations.host') || 'Host', s.hostname || '—')}
          {row(t('bench.stations.version') || 'Version', s.stationVersion ?? '—')}
          {row(t('bench.stations.createdAt') || 'Registered', `${fmt(s.createdAt)} · ${s.registerIp ?? '—'}`)}
          {row(t('bench.stations.lastSeen') || 'Last activity', `${fmt(s.lastSeenAt)} · ${s.lastIp ?? '—'}`)}
          {s.approvedAt && row(t('bench.stations.approvedAt') || 'Approved', fmt(s.approvedAt))}
          {s.revokedAt && row(t('bench.stations.revokedAt') || 'Revoked', `${fmt(s.revokedAt)}${s.revokedReason ? ` (${t(`bench.stations.revokedReason.${s.revokedReason}`) || s.revokedReason})` : ''}`)}
          {row(t('bench.stations.enrolledCount') || 'Enrolled', s.enrolledCount)}
        </div>

        <section>
          <h3 className={cardTitleCls}><Timer size={14} /> {t('bench.session.title') || 'Bench session'}</h3>
          <div className={clsx(cardCls, 'space-y-2')}>
            {s.session ? (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-text-secondary">{t('bench.session.current', { technician: s.session.technician ?? '—', until: fmt(s.session.expiresAt) }) || `Session of ${s.session.technician ?? '—'}, until ${fmt(s.session.expiresAt)}`}</span>
                <Button size="sm" variant="ghost" className="ml-auto" onClick={() => void act(() => benchStationsApi.closeSession(s.id))}><XCircle className="mr-1 h-4 w-4" />{t('bench.session.close') || 'Close the session'}</Button>
              </div>
            ) : (
              <div className="flex flex-wrap items-end gap-2">
                <p className="w-full text-xs text-text-muted">{t('bench.session.hint') || 'The station issues enrollment tokens only during an open session (8 hours at most), each one checked against the rights of the technician in the tenant of the target.'}</p>
                <label className={labelCls}>{t('bench.session.duration') || 'Duration (minutes)'}
                  <input className={`${fieldCls} max-w-[8rem]`} type="number" min={15} max={BENCH_LIMITS.sessionMaxHours * 60} value={minutes} onChange={(e) => setMinutes(e.target.value)} />
                </label>
                <Button size="sm" disabled={s.status !== 'approved'} onClick={() => void act(() => benchStationsApi.openSession(s.id, Number(minutes) || BENCH_LIMITS.sessionMaxHours * 60))}>
                  <Play className="mr-1 h-4 w-4" />{t('bench.session.open') || 'Open a bench session'}
                </Button>
              </div>
            )}
          </div>
        </section>

        <section>
          <div className="mb-2 flex items-center">
            <h3 className={clsx(cardTitleCls, 'mb-0')}>{t('bench.stations.targets.title') || 'Targets'}</h3>
            {s.status !== 'revoked' && <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setAdding(true)}><Plus className="mr-1 h-4 w-4" />{t('bench.stations.targets.add') || 'Add a target'}</Button>}
          </div>
          <TargetsList station={s} onChange={(fn) => void act(fn)} />
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
      {adding && <AddTargetDialog station={s} onClose={() => setAdding(false)} onAdded={(d) => { setS(d); onChanged(); setAdding(false); }} />}
    </Modal>
  );
}

function TargetsList({ station, onChange }: { station: BenchStationDetail; onChange: (fn: () => Promise<BenchStationDetail>) => void }) {
  const { t } = useTranslation();
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
            {x.suspendedAt && <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-400">{t('bench.stations.targets.suspended') || 'Suspended'}</span>}
            <span className="ml-auto flex gap-1">
              {x.suspendedAt
                ? <Button size="sm" variant="ghost" onClick={() => patch(x, { suspended: false })}><Play className="mr-1 h-3.5 w-3.5" />{t('bench.stations.resume') || 'Resume'}</Button>
                : <Button size="sm" variant="ghost" onClick={() => patch(x, { suspended: true })}><Pause className="mr-1 h-3.5 w-3.5" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
              <Button size="sm" variant="ghost" onClick={() => void remove(x)} title={t('bench.stations.targets.remove') || 'Remove'}><Trash2 className="h-3.5 w-3.5" /></Button>
            </span>
          </div>
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
          <div className="text-xs text-text-muted">{t('bench.stations.targets.namePrefix') || 'Name prefix'} : <span className="font-mono text-text-secondary">{x.namePrefix || '—'}</span></div>
        </li>
      ))}
    </ul>
  );
}

function AddTargetDialog({ station, onClose, onAdded }: { station: BenchStationDetail; onClose: () => void; onAdded: (d: BenchStationDetail) => void }) {
  const { t } = useTranslation();
  const policyLabel = useRolePolicyLabel();
  const [tenants, setTenants] = useState<Array<{ id: number; name: string }>>([]);
  const [groups, setGroups] = useState<Array<{ id: number; path: string }>>([]);
  const [form, setForm] = useState<{ tenantId: string; groupId: string; rolePolicy: BenchRolePolicy; namePrefix: string; disableDevOptions: boolean }>(
    { tenantId: '', groupId: '', rolePolicy: 'owner_preferred', namePrefix: '', disableDevOptions: true });
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
        disableDevOptions: form.disableDevOptions,
      }));
    } catch (err) { fail(err); }
  };
  return (
    <Modal open onClose={onClose} size="lg" title={t('bench.stations.targets.add') || 'Add a target'}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void add()} disabled={!form.tenantId || !form.groupId || !prefixOk}>{t('bench.stations.targets.add') || 'Add a target'}</Button>
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
        <label className={labelCls}>{t('bench.stations.targets.namePrefix') || 'Name prefix'}
          <input className={fieldCls} value={form.namePrefix} maxLength={32} onChange={(e) => setForm({ ...form, namePrefix: e.target.value })} placeholder="C01" />
        </label>
        <ToggleSwitch size="sm" checked={form.disableDevOptions} onChange={(on) => setForm({ ...form, disableDevOptions: on })}
          label={t('bench.stations.targets.disableDevOptions') || 'Turn the developer options off at the end'} />
        <p className="text-xs text-text-muted">{t('bench.stations.targets.addHint') || 'A second factor is asked. The tenant sees the stations that target it and can suspend or remove a target.'}</p>
      </div>
    </Modal>
  );
}
