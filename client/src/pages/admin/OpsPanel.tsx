import { useEffect, useState, type ReactNode } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Circle, Gauge, RefreshCw, XCircle } from 'lucide-react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import type { OpsPilotCheckDto, OpsStatusDto } from '@obligarth/shared';
import { opsApi } from '@/api/ops.api';
import { Button } from '@/components/common/Button';
import { formatBytes } from '@/components/mdm/PlatformIcon';

// The operations of the instance (P0-13 T11; platform administrators, master tenant): the stage of the instance and
// the prerequisites of a pilot (D8), the readiness in detail (GET /health/ready), the backups and their last reports,
// the restore drill, the profile signing identity. Read only: the signing identity is imported on the host with the
// command of apple-edge (D12), the stage is OBLIGARTH_STAGE in .env. Codes, dates and counts only.

function when(iso: string | null | undefined): string {
 if (!iso) return '—';
 const d = new Date(iso);
 return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function errorText(err: unknown, fallback: string): string {
 const e = err as { response?: { data?: { error?: string } } };
 return e?.response?.data?.error || fallback;
}

function duration(t: TFunction, seconds: number): string {
 const d = Math.floor(seconds / 86_400);
 const h = Math.floor((seconds % 86_400) / 3_600);
 const m = Math.floor((seconds % 3_600) / 60);
 if (d > 0) return t('ops.duration.days', { d, h }) || `${d} d ${h} h`;
 if (h > 0) return t('ops.duration.hours', { h, m }) || `${h} h ${m} min`;
 return t('ops.duration.minutes', { m }) || `${m} min`;
}

// Theme tokens (index.css): readable on the dark and the light themes alike.
const STATE_STYLE: Record<OpsPilotCheckDto['state'], string> = {
 ok: 'text-status-up',
 warning: 'text-status-warning',
 error: 'text-status-critical',
 not_applicable: 'text-text-muted',
};

const STATE_FALLBACK: Record<OpsPilotCheckDto['state'], string> = {
 ok: 'Met', warning: 'To complete or to watch', error: 'Blocking', not_applicable: 'Not applicable',
};

/** The state of a prerequisite: an icon for the eye, its name for a screen reader (never the colour alone). */
function StateIcon({ state }: { state: OpsPilotCheckDto['state'] }) {
 const { t } = useTranslation();
 const cls = clsx('shrink-0', STATE_STYLE[state]);
 const icon = state === 'ok' ? <CheckCircle2 size={16} className={cls} aria-hidden="true" />
 : state === 'warning' ? <AlertTriangle size={16} className={cls} aria-hidden="true" />
 : state === 'error' ? <XCircle size={16} className={cls} aria-hidden="true" />
 : <Circle size={16} className={cls} aria-hidden="true" />;
 return (
 <>
 {icon}
 <span className="sr-only">{t(`ops.state.${state}`) || STATE_FALLBACK[state]}</span>
 </>
 );
}

export function OpsPanel() {
 const { t } = useTranslation();
 const [status, setStatus] = useState<OpsStatusDto | null>(null);
 const [loading, setLoading] = useState(true);
 const [loadError, setLoadError] = useState<string | null>(null);

 const load = async () => {
 setLoading(true);
 try {
 setStatus(await opsApi.status());
 setLoadError(null);
 } catch (err) {
 const text = errorText(err, t('ops.loadFailed') || 'Could not load the state of the instance');
 setLoadError(text);
 toast.error(text);
 } finally {
 setLoading(false);
 }
 };

 useEffect(() => { void load(); }, []);

 if (loading && !status) {
 return <p className="text-sm text-text-muted">{t('common.loading') || 'Loading…'}</p>;
 }
 if (!status) {
 // The first load failed: say so, and offer to try again (the toast goes away).
 return (
 <div className="flex items-start justify-between gap-3 rounded-lg border border-status-critical/30 bg-status-critical/10 p-3 text-sm text-status-critical">
 <span role="alert">{loadError || (t('ops.loadFailed') || 'Could not load the state of the instance')}</span>
 <Button size="sm" variant="secondary" onClick={() => void load()} loading={loading}>
 <RefreshCw size={14} className="mr-1.5" aria-hidden="true" />
 {t('ops.refresh') || 'Refresh'}
 </Button>
 </div>
 );
 }

 const codeText = (code: string | null, params?: Record<string, number>): string =>
 code ? (t(`ops.codes.${code}`, params ?? {}) || code) : '';
 const stage = status.stage.stage;
 const yesNo = (v: boolean | null): string => (v === null ? '—' : v ? (t('ops.yes') || 'Yes') : (t('ops.no') || 'No'));
 const blocking = status.stage.checks.filter((c) => c.state === 'error').length;
 const toDo = status.stage.checks.filter((c) => c.state === 'warning').length;
 const backups = status.backups;
 const drill = status.restoreDrill;
 const appleOn = status.appleEdge.mode === 'on';
 const notApplicable = t('ops.notApplicable') || 'Not applicable';

 return (
 <div className="space-y-6">
 <div className="flex items-start justify-between gap-3">
 <div>
 <h2 className="text-lg font-semibold text-text-primary">{t('ops.title') || 'Operations of the instance'}</h2>
 <p className="text-sm text-text-muted">
 {t('ops.description') || 'Stage of the instance, prerequisites of a pilot, readiness, backups and restore drill. Codes and counts only: no tenant data.'}
 </p>
 </div>
 <Button size="sm" variant="secondary" onClick={() => void load()} loading={loading}>
 <RefreshCw size={14} className="mr-1.5" />
 {t('ops.refresh') || 'Refresh'}
 </Button>
 </div>

 <div className={clsx(
 'flex items-start gap-2 rounded-lg border p-3 text-sm',
 status.readiness.ok ? 'border-status-up/30 bg-status-up/10 text-status-up' : 'border-status-critical/30 bg-status-critical/10 text-status-critical',
 )}>
 <Activity size={18} className="shrink-0 mt-0.5" aria-hidden="true" />
 <span>
 {status.readiness.ok
 ? (t('ops.readyBanner') || 'The instance is ready (GET /health/ready answers 200).')
 : (t('ops.notReadyBanner') || 'The instance is not ready (GET /health/ready answers 503): see the failing checks below.')}
 </span>
 </div>

 <section className="rounded-lg bg-bg-secondary p-4 space-y-3">
 <div className="flex flex-wrap items-center gap-3">
 <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">{t('ops.stage.title') || 'Stage of the instance'}</h3>
 <span className={clsx(
 'rounded-full border px-2.5 py-0.5 text-xs font-semibold',
 stage === 'lab' ? 'border-status-pending/30 bg-status-pending/10 text-status-pending'
 : stage === 'pilot' ? 'border-status-warning/30 bg-status-warning/10 text-status-warning'
 : 'border-status-up/30 bg-status-up/10 text-status-up',
 )}>
 {t(`ops.stage.${stage}`) || stage}
 </span>
 </div>
 <p className="text-xs text-text-muted">
 {stage === 'lab'
 ? (t('ops.stage.labHelp') || 'Laboratory: the prerequisites below are not imposed. Complete them, then set OBLIGARTH_STAGE=pilot in .env before the first pilot: the server refuses to start without the backups and, with Apple, the signed profiles.')
 : (t('ops.stage.beyondHelp') || 'Outside the laboratory the prerequisites are imposed: the server does not start without them, an enrollment is refused while the notice of its tenant is incomplete, and a signing identity missing or expired makes the instance not ready.')}
 </p>
 <p className="text-xs text-text-muted">
 {blocking > 0
 ? (t('ops.stage.blocking', { count: blocking }) || `${blocking} prerequisite(s) blocking at this stage.`)
 : toDo > 0
 ? (t('ops.stage.toDo', { count: toDo }) || `${toDo} prerequisite(s) to complete or to watch.`)
 : (t('ops.stage.allOk') || 'Every prerequisite of a pilot is met.')}
 </p>
 <ul className="divide-y divide-border">
 {status.stage.checks.map((c) => (
 <li key={c.key} className="flex items-start gap-2 py-2 text-sm">
 <StateIcon state={c.state} />
 <div className="min-w-0">
 <div className="text-text-primary">{t(`ops.pilot.${c.key}`) || c.key}</div>
 {c.state === 'not_applicable'
 ? <div className="text-xs text-text-muted">{t('ops.notApplicable') || 'Not applicable'}</div>
 : c.code
 ? <div className={clsx('text-xs', STATE_STYLE[c.state])}>{codeText(c.code, c.params)}</div>
 : c.params && typeof c.params.daysLeft === 'number'
 ? <div className="text-xs text-text-muted">{t('ops.daysLeft', { count: c.params.daysLeft }) || `${c.params.daysLeft} day(s) left`}</div>
 : null}
 </div>
 </li>
 ))}
 </ul>
 <p className="text-xs text-text-muted">
 {t('ops.stage.signingHelp') || 'The profile signing identity (an organization-validated S/MIME certificate) is imported on the host, never from this console: apple-edge signing-identity import <chain.pem> <key.pem>.'}
 </p>
 </section>

 <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
 <Card title={t('ops.readiness.title') || 'Readiness'}>
 {status.readiness.checks.map((c) => (
 <Line
 key={c.name}
 label={t(`ops.checks.${c.name}`) || c.name}
 value={c.ok
 ? <span className="text-status-up">{t('ops.ok') || 'OK'}</span>
 : <span className="text-status-critical">{codeText(c.code) || (t('ops.failed') || 'Failed')}</span>}
 />
 ))}
 <Line label={t('ops.readiness.checkedAt') || 'Checked'} value={when(status.readiness.checkedAt)} />
 </Card>
 <Card title={t('ops.instance.title') || 'Instance'}>
 <Line label={t('ops.instance.version') || 'Version'} value={status.version} />
 <Line label={t('ops.instance.uptime') || 'Running for'} value={duration(t, status.uptimeSeconds)} />
 <Line label={t('ops.instance.jobs') || 'Background jobs'} value={`${status.jobs.mode} · ${status.jobs.healthy ? (t('ops.ok') || 'OK') : (t('ops.failed') || 'Failed')}`} />
 <Line label={t('ops.instance.vault') || 'Vault'} value={status.vault.ready ? (t('ops.ok') || 'OK') : (t('ops.locked') || 'Locked')} />
 <Line
 label={t('ops.instance.metrics') || 'Metrics listener'}
 value={status.metrics.enabled
 ? `${status.metrics.listening ? (t('ops.listening') || 'listening') : (t('ops.notListening') || 'not listening')} · ${status.metrics.port ?? '—'}`
 : (t('ops.off') || 'Off')}
 />
 <Line label={t('ops.instance.memory') || 'Memory (RSS)'} value={formatBytes(status.process.rssBytes)} />
 </Card>
 <Card title={t('ops.signing.title') || 'Signed profiles (Apple)'}>
 <Line label={t('ops.signing.mode') || 'apple-edge'} value={appleOn
 ? `${status.appleEdge.version ?? '—'} · ${status.appleEdge.up ? (t('ops.up') || 'up') : status.appleEdge.up === false ? (t('ops.down') || 'down') : '—'}`
 : (t('ops.off') || 'Off')} />
 {/* Apple off: neither a signature nor an identity applies (as the prerequisites say). */}
 <Line label={t('ops.signing.required') || 'Signature required'} value={appleOn ? yesNo(status.appleEdge.requireSignedProfiles) : notApplicable} />
 <Line label={t('ops.signing.identity') || 'Signing identity'} value={appleOn
 ? (t(`ops.signing.states.${status.appleEdge.signingIdentityState}`) || status.appleEdge.signingIdentityState)
 : notApplicable} />
 <Line label={t('ops.signing.notAfter') || 'Valid until'} value={appleOn ? when(status.appleEdge.signingIdentityNotAfter) : notApplicable} />
 </Card>
 </div>

 <section className="rounded-lg bg-bg-secondary p-4 space-y-3">
 <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">{t('ops.backups.title') || 'Backups'}</h3>
 {!backups ? (
 <p className="text-sm text-text-muted">{t('ops.backups.unreadable') || 'The reports of the backups cannot be read right now.'}</p>
 ) : (
 <>
 <p className="text-xs text-text-muted">
 {backups.expected
 ? (t('ops.backups.expected') || 'Expected (BACKUP_EXPECTED=true): the instance is not ready while the last base backup is older than 26 h or the WAL stream than 15 min.')
 : (t('ops.backups.notExpected') || 'Not expected (BACKUP_EXPECTED=false): start the compose profile backup, check the first reports here, then set BACKUP_EXPECTED=true.')}
 {backups.disk && ` ${t('ops.backups.disk', { free: formatBytes(backups.disk.freeBytes), total: formatBytes(backups.disk.totalBytes) }) || `Free space: ${formatBytes(backups.disk.freeBytes)} of ${formatBytes(backups.disk.totalBytes)}.`}`}
 </p>
 <div className="overflow-x-auto">
 <table className="w-full text-sm">
 <thead>
 <tr className="text-left text-text-muted">
 <th className="px-2 py-2 font-medium">{t('ops.backups.kind') || 'Kind'}</th>
 <th className="px-2 py-2 font-medium">{t('ops.backups.lastSuccess') || 'Last success'}</th>
 <th className="px-2 py-2 font-medium">{t('ops.backups.lastReport') || 'Last report'}</th>
 <th className="px-2 py-2 font-medium">{t('ops.backups.failures') || 'Failures since the last success'}</th>
 <th className="px-2 py-2 font-medium">{t('ops.backups.size') || 'Size'}</th>
 </tr>
 </thead>
 <tbody className="divide-y divide-border">
 {backups.kinds.map((k) => (
 <tr key={k.kind}>
 <td className="px-2 py-2">{t(`ops.backups.kinds.${k.kind}`) || k.kind}</td>
 <td className="px-2 py-2 whitespace-nowrap">{when(k.lastSuccessAt)}</td>
 <td className={clsx('px-2 py-2 whitespace-nowrap', k.lastOk === false && 'text-status-critical')}>{when(k.lastReportAt)}</td>
 <td className={clsx('px-2 py-2', k.failuresSinceSuccess > 0 && 'text-status-critical')}>{k.failuresSinceSuccess}</td>
 <td className="px-2 py-2">{formatBytes(k.lastBytes)}</td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wide">{t('ops.backups.recent') || 'Last reports'}</h4>
 {backups.recent.length === 0 ? (
 <p className="text-sm text-text-muted">{t('ops.backups.none') || 'No report yet.'}</p>
 ) : (
 <div className="overflow-x-auto">
 <table className="w-full text-sm">
 <tbody className="divide-y divide-border">
 {backups.recent.slice(0, 10).map((r) => (
 <tr key={r.id}>
 <td className="px-2 py-1.5 whitespace-nowrap">{when(r.finishedAt)}</td>
 <td className="px-2 py-1.5">{t(`ops.backups.kinds.${r.kind}`) || r.kind}</td>
 <td className={clsx('px-2 py-1.5', r.ok ? 'text-status-up' : 'text-status-critical')}>{r.ok ? (t('ops.ok') || 'OK') : (t('ops.failed') || 'Failed')}</td>
 <td className="px-2 py-1.5">{formatBytes(r.bytes)}</td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 )}
 </>
 )}
 </section>

 <Card title={t('ops.drill.title') || 'Restore drill'}>
 {!drill ? (
 <div className="text-sm text-text-muted">{t('ops.drill.unreadable') || 'The deadline of the drill cannot be read right now.'}</div>
 ) : (
 <>
 <Line label={t('ops.drill.dueAt') || 'Next drill due'} value={when(drill.dueAt)} />
 {/* The brain's item before any drill: 182 days from the start of the backups, not from a drill. */}
 <Line label={t('ops.drill.source') || 'Set by'} value={!drill.source ? '—'
 : drill.source === 'brain' && !drill.lastSuccessAt ? (t('ops.drill.sources.brainFirst') || 'Backups in service + 182 days')
 : (t(`ops.drill.sources.${drill.source}`) || drill.source)} />
 <Line label={t('ops.drill.lastSuccess') || 'Last successful drill'} value={when(drill.lastSuccessAt)} />
 <div className="pt-1 text-xs text-text-muted">{t('ops.drill.help') || 'Every six months: docker compose --profile restore-drill run --rm drill-report (procedure of backup and recovery). A successful drill moves the deadline by 182 days.'}</div>
 </>
 )}
 </Card>
 </div>
 );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
 return (
 <div className="rounded-lg bg-bg-secondary p-4">
 <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-secondary">
 <Gauge size={14} className="text-accent" aria-hidden="true" />
 {title}
 </div>
 <dl className="space-y-1">{children}</dl>
 </div>
 );
}

function Line({ label, value }: { label: string; value: ReactNode }) {
 return (
 <div className="flex items-center justify-between gap-3 text-sm">
 <dt className="text-text-muted">{label}</dt>
 <dd className="text-text-primary text-right">{value}</dd>
 </div>
 );
}
