import { Fragment, useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { ChevronDown, ChevronRight, Pause, Play, Timer, Trash2, XCircle } from 'lucide-react';
import { BENCH_LIMITS, type BenchProvisioningView, type BenchTenantStationView } from '@obligarth/shared';
import { benchStationsApi } from '@/api/benchStations.api';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { useAuthStore } from '@/store/authStore';
import {
  ProvisioningStatePill, StationStatusPill, cardCls, cardTitleCls, fail, fmt, headCls, listCls, rowCls, tdCls, thCls,
  useBenchErrorLabel, useRoleLabel, useRolePolicyLabel,
} from './benchUi';

// The Bench tab of the Android agent (lot BANC §3.7, §3.12; mdm.bench.manage): the stations that target the tenant (no
// token, no address), the bench session (mdm.bench.operate, second factor), the suspension (no second factor) or the
// removal (second factor) of a target of the tenant, and the history of the provisionings with their journal of steps.

export function BenchTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const policyLabel = useRolePolicyLabel();
  const roleLabel = useRoleLabel();
  const errorLabel = useBenchErrorLabel();
  const canOperate = useAuthStore((s) => s.isAdmin() || (s.permissions?.tenantCapabilities ?? []).includes('mdm.bench.operate'));
  const isAdmin = useAuthStore((s) => s.isAdmin());
  const [stations, setStations] = useState<BenchTenantStationView[] | null>(null);
  const [rows, setRows] = useState<BenchProvisioningView[] | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const load = useCallback(() => {
    benchStationsApi.tenantStations().then(setStations).catch((err) => { setStations([]); fail(err); });
    benchStationsApi.history().then(setRows).catch((err) => { setRows([]); fail(err); });
  }, []);
  useEffect(() => { load(); }, [load]);
  const run = async (fn: () => Promise<unknown>) => { try { await fn(); load(); } catch (err) { fail(err); } };
  const remove = async (s: BenchTenantStationView, groupId: number, path: string) => {
    if (await confirm({ danger: true, message: t('bench.tenant.removeConfirm', { station: s.name, group: path }) || `Remove the group ${path} from the station ${s.name}?` })) {
      await run(() => benchStationsApi.removeTenantTarget(s.id, groupId));
    }
  };
  const toggle = (id: string) => setOpen((o) => { const n = new Set(o); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="space-y-5">
      <section>
        <h3 className={cardTitleCls}>{t('bench.tenant.stations') || 'Bench stations of this tenant'}</h3>
        {stations && stations.length === 0 && <p className={clsx(cardCls, 'text-center text-sm text-text-muted')}>{t('bench.tenant.noStation') || 'No bench station targets this tenant.'}</p>}
        <ul className="space-y-2">
          {(stations ?? []).map((s) => (
            <li key={s.id} className={clsx(cardCls, 'space-y-2 text-sm')}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-text-primary">{s.name}</span>
                <StationStatusPill status={s.status} />
                <span className="text-xs text-text-muted">{t('bench.stations.lastSeen') || 'Last activity'} : {fmt(s.lastSeenAt)}</span>
                <span className="ml-auto flex items-center gap-2">
                  {s.session ? (
                    <>
                      <span className="text-xs text-text-secondary"><Timer className="mr-1 inline h-3.5 w-3.5" />{t('bench.session.current', { technician: s.session.technician ?? '—', until: fmt(s.session.expiresAt) }) || `Session of ${s.session.technician ?? '—'}, until ${fmt(s.session.expiresAt)}`}</span>
                      {(s.session.mine || isAdmin) && <Button size="sm" variant="ghost" onClick={() => void run(() => benchStationsApi.closeTenantSession(s.session!.id))}><XCircle className="mr-1 h-3.5 w-3.5" />{t('bench.session.close') || 'Close the session'}</Button>}
                    </>
                  ) : canOperate && s.status === 'approved' && s.targets.some((x) => !x.suspendedAt) && (
                    <Button size="sm" onClick={() => void run(() => benchStationsApi.openTenantSession(s.id, BENCH_LIMITS.sessionMaxHours * 60))}>
                      <Play className="mr-1 h-3.5 w-3.5" />{t('bench.session.open') || 'Open a bench session'}
                    </Button>
                  )}
                </span>
              </div>
              {s.targets.map((x) => (
                <div key={x.groupId} className="flex flex-wrap items-center gap-2 rounded-md px-2 py-1 text-xs transition-colors hover:bg-bg-tertiary">
                  <span className="text-text-primary">{x.groupPath}</span>
                  <span className="text-text-muted">{policyLabel(x.rolePolicy)}</span>
                  {x.suspendedAt && <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-400">{t('bench.stations.targets.suspended') || 'Suspended'}</span>}
                  <span className="ml-auto flex gap-1">
                    {x.suspendedAt
                      ? <span className="text-[11px] text-text-muted">{t('bench.tenant.resumeByPlatform') || 'Resumed by a platform administrator only'}</span>
                      : <Button size="sm" variant="ghost" onClick={() => void run(() => benchStationsApi.suspendTarget(s.id, x.groupId))}><Pause className="mr-1 h-3.5 w-3.5" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
                    <Button size="sm" variant="ghost" title={t('bench.stations.targets.remove') || 'Remove'} onClick={() => void remove(s, x.groupId, x.groupPath)}><Trash2 className="h-3.5 w-3.5" /></Button>
                  </span>
                </div>
              ))}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h3 className={cardTitleCls}>{t('bench.history.title') || 'Provisioning history'}</h3>
        <div className={listCls}>
          <table className="w-full text-sm">
            <thead className={headCls}><tr>
              <th className="w-6" />
              <th className={thCls}>{t('bench.history.date') || 'Date'}</th>
              <th className={thCls}>{t('bench.history.station') || 'Station'}</th>
              <th className={thCls}>{t('bench.history.device') || 'Device'}</th>
              <th className={thCls}>{t('bench.history.model') || 'Model'}</th>
              <th className={thCls}>Android</th>
              <th className={thCls}>{t('bench.history.role') || 'Role aimed / obtained'}</th>
              <th className={thCls}>{t('bench.history.stateCol') || 'State'}</th>
              <th className={thCls}>{t('bench.history.error') || 'Error'}</th>
            </tr></thead>
            <tbody>
              {(rows ?? []).map((r) => (
                <Fragment key={r.id}>
                  <tr className={clsx(rowCls, 'cursor-pointer')} onClick={() => toggle(r.id)}>
                    <td className="pl-3 text-text-muted">{open.has(r.id) ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</td>
                    <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-secondary')}>{fmt(r.createdAt)}</td>
                    <td className={clsx(tdCls, 'text-text-secondary')}>{r.stationName ?? '—'}</td>
                    <td className={tdCls}>
                      {r.deviceId
                        ? <Link to={`/devices/${r.deviceId}`} className="text-accent hover:underline" onClick={(e) => e.stopPropagation()}>{r.deviceName ?? r.adbSerial}</Link>
                        : <span className="text-text-primary">{r.deviceName ?? r.adbSerial}</span>}
                      <div className="font-mono text-[11px] text-text-muted">{r.adbSerial}{r.hwSerial ? ` · ${r.hwSerial}` : ''}</div>
                    </td>
                    <td className={clsx(tdCls, 'text-text-secondary')}>{r.model}</td>
                    <td className={clsx(tdCls, 'text-text-secondary')}>{r.osRelease ?? '—'} <span className="text-xs text-text-muted">(API {r.sdkInt})</span></td>
                    <td className={clsx(tdCls, 'text-xs text-text-secondary')}>{roleLabel(r.roleTarget)} / {r.managementMode ? roleLabel(r.managementMode) : '—'}</td>
                    <td className={tdCls}><ProvisioningStatePill state={r.state} /></td>
                    <td className={clsx(tdCls, 'text-xs', r.errorCode ? 'text-red-400' : 'text-text-muted')}>{errorLabel(r.errorCode)}</td>
                  </tr>
                  {open.has(r.id) && (
                    <tr>
                      <td />
                      <td colSpan={8} className="px-4 pb-3">
                        <div className="rounded-xl bg-bg-tertiary/40 py-1 text-xs">
                          {r.technician && <div className="px-3 py-1 text-text-muted">{t('bench.history.technician') || 'Technician'} : <span className="text-text-primary">{r.technician}</span></div>}
                          {r.stepsDropped > 0 && <div className="px-3 py-1 text-text-muted">{t('bench.history.stepsDropped', { count: r.stepsDropped }) || `${r.stepsDropped} older step(s) left out`}</div>}
                          {r.steps.map((s, i) => (
                            <div key={i} className="flex flex-wrap gap-2 px-3 py-1 transition-colors hover:bg-bg-tertiary">
                              <span className="w-36 shrink-0 text-text-muted">{fmt(s.at)}</span>
                              <span className="w-40 shrink-0 text-text-primary">{t(`bench.step.${s.step}`) || s.step}</span>
                              <span className="text-text-secondary">{t(`bench.stepStatus.${s.status}`) || s.status}</span>
                              {s.code && <span className="text-text-muted">{errorLabel(s.code)}</span>}
                            </div>
                          ))}
                          {r.steps.length === 0 && <div className="px-3 py-1 text-text-muted">{t('bench.history.noStep') || 'No step reported.'}</div>}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {rows && rows.length === 0 && <tr><td colSpan={9} className="p-8 text-center text-text-muted">{t('bench.history.empty') || 'No provisioning yet.'}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
