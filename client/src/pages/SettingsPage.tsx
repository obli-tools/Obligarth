import { useState, useEffect, type FormEvent, type KeyboardEvent } from 'react';
import { Shield, Server, Plus, Pencil, Trash2, Wifi, Eye, EyeOff, ArrowLeftRight, Info, Cpu, HardDrive, Database, Clock } from 'lucide-react';
import { SettingsPanel } from '@/components/settings/SettingsPanel';
import { DeviceKeysSettingsSection } from '@/components/settings/DeviceKeysSettingsSection';
import { RemoteSettingsSection } from '@/components/settings/RemoteSettingsSection';
import { useAuthStore } from '@/store/authStore';
import { smtpServerApi, type CreateSmtpServerRequest } from '@/api/smtpServer.api';
import { appConfigApi } from '@/api/appConfig.api';
import { systemApi, type SystemInfo } from '@/api/system.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import type { SmtpServer, AppConfigData, ObligateConfig } from '@obligarth/shared';
import toast from 'react-hot-toast';
import { cn } from '@/utils/cn';
import { useTranslation } from 'react-i18next';
import { PageContainer } from '@/components/common/PageContainer';
import { TableScroll } from '@/components/common/TableScroll';
import { IconButton } from '@/components/common/IconButton';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { MEDIA, matchesMedia, useMediaQuery } from '@/hooks/useMediaQuery';
import { openExternal } from '@/utils/openExternal';

// Invisible ≥40px hit area around small hand-rolled switches / icon toggles
// (touch only — desktop geometry unchanged). The element must be positioned.
const TOUCH_HIT = "coarse:after:absolute coarse:after:-inset-2.5 coarse:after:content-['']";
/** Minimum length of the Obligate inbound secret (same rule as the server). */
const INBOUND_SECRET_MIN = 16;

// Touch: the keyboard's Done/Enter key commits a blur-saved field (closing
// the Android keyboard does not blur it). Mouse/keyboard desktop: Enter keeps
// doing nothing, as before (these inputs are not in a <form>).
function blurOnEnterTouch(e: KeyboardEvent<HTMLInputElement>) {
 if (e.key === 'Enter' && matchesMedia(MEDIA.coarse)) {
 e.preventDefault();
 e.currentTarget.blur();
 }
}

function AboutRow({ label, value }: { label: string; value: string }) {
 return (
 <div className="flex items-center justify-between gap-4">
 <span className="text-xs text-text-muted shrink-0">{label}</span>
 <span className="font-mono text-xs text-text-primary min-w-0 text-right break-all">{value}</span>
 </div>
 );
}

type SmtpFormMode = 'create' | 'edit' | null;

interface SmtpForm {
 name: string;
 host: string;
 port: string;
 secure: boolean;
 username: string;
 password: string;
 fromAddress: string;
}

const emptySmtpForm = (): SmtpForm => ({
 name: '',
 host: '',
 port: '587',
 secure: false,
 username: '',
 password: '',
 fromAddress: '',
});

export function SettingsPage() {
 const { t } = useTranslation();
 const confirm = useConfirm();
 const isWide = useMediaQuery(MEDIA.lg);
 const { isAdmin } = useAuthStore();
 const admin = isAdmin();

 // ── SMTP Servers ──
 const [servers, setServers] = useState<SmtpServer[]>([]);
 const [smtpMode, setSmtpMode] = useState<SmtpFormMode>(null);
 const [editingServer, setEditingServer] = useState<SmtpServer | null>(null);
 const [smtpForm, setSmtpForm] = useState<SmtpForm>(emptySmtpForm());
 const [showPassword, setShowPassword] = useState(false);
 const [smtpSaving, setSmtpSaving] = useState(false);
 const [testingId, setTestingId] = useState<number | null>(null);

 // ── App Config (2FA) ──
 const [appConfig, setAppConfig] = useState<AppConfigData | null>(null);
 const [configSaving, setConfigSaving] = useState(false);

 // ── System info (About section) ──
 const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
 const [systemInfoLoading, setSystemInfoLoading] = useState(false);

 // ── Obligate SSO Integration ──
 const [obligateCfg, setObligateCfg] = useState<ObligateConfig | null>(null);
 const [obligateUrl, setObligateUrl] = useState('');
 const [obligateApiKey, setObligateApiKey] = useState('');
 const [showObligateKey, setShowObligateKey] = useState(false);
 // Optional split of the Obligate secrets (both default to today's behaviour)
 const [obligateInboundSecret, setObligateInboundSecret] = useState('');
 const [showInboundSecret, setShowInboundSecret] = useState(false);

 useEffect(() => {
 if (!admin) return;
 setSystemInfoLoading(true);
 systemApi.getInfo().then(setSystemInfo).catch(() => {}).finally(() => setSystemInfoLoading(false));
 smtpServerApi.list().then(setServers).catch(() => {});
 appConfigApi.getConfig().then(setAppConfig).catch(() => {});
 appConfigApi.getObligateConfig().then((cfg) => {
 setObligateCfg(cfg);
 setObligateUrl(cfg.url ?? '');
 }).catch(() => {});
 }, [admin]);

 function openCreate() {
 setEditingServer(null);
 setSmtpForm(emptySmtpForm());
 setShowPassword(false);
 setSmtpMode('create');
 }

 function openEdit(server: SmtpServer) {
 setEditingServer(server);
 setSmtpForm({
 name: server.name,
 host: server.host,
 port: String(server.port),
 secure: server.secure,
 username: server.username ?? '',
 password: '',
 fromAddress: server.fromAddress ?? '',
 });
 setShowPassword(false);
 setSmtpMode('edit');
 }

 function closeSmtpModal() {
 setSmtpMode(null);
 setEditingServer(null);
 }

 async function handleSmtpSubmit(e: FormEvent) {
 e.preventDefault();
 setSmtpSaving(true);
 try {
 const data: CreateSmtpServerRequest = {
 name: smtpForm.name,
 host: smtpForm.host,
 port: parseInt(smtpForm.port, 10),
 secure: smtpForm.secure,
 username: smtpForm.username,
 password: smtpForm.password,
 fromAddress: smtpForm.fromAddress,
 };
 if (smtpMode === 'create') {
 const created = await smtpServerApi.create(data);
 setServers((prev) => [...prev, created]);
 toast.success(t('settings.smtp.created'));
 } else if (editingServer) {
 const payload = smtpForm.password ? data : { ...data, password: undefined };
 const updated = await smtpServerApi.update(editingServer.id, payload);
 setServers((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
 toast.success(t('settings.smtp.updated'));
 }
 closeSmtpModal();
 } catch {
 toast.error(t('settings.smtp.failedSave'));
 } finally {
 setSmtpSaving(false);
 }
 }

 async function handleDelete(server: SmtpServer) {
 if (!(await confirm({ message: t('settings.smtp.confirmDelete', { defaultValue: 'Delete SMTP server "{{name}}"?', name: server.name }), danger: true }))) return;
 try {
 await smtpServerApi.delete(server.id);
 setServers((prev) => prev.filter((s) => s.id !== server.id));
 toast.success(t('settings.smtp.deleted'));
 } catch {
 toast.error(t('settings.smtp.failedDelete'));
 }
 }

 async function handleTest(server: SmtpServer) {
 setTestingId(server.id);
 try {
 await smtpServerApi.test(server.id);
 toast.success(t('settings.smtp.testOk', { name: server.name }));
 } catch (err: unknown) {
 const msg = err instanceof Error ? err.message : t('settings.smtp.testFailed');
 toast.error(msg);
 } finally {
 setTestingId(null);
 }
 }

 async function setConfigKey(key: keyof AppConfigData, value: boolean | number | null) {
 if (!appConfig) return;
 setConfigSaving(true);
 try {
 await appConfigApi.setConfig(key, value);
 setAppConfig((prev) => prev ? { ...prev, [key]: String(value) } : prev);
 } catch {
 toast.error(t('settings.failedUpdate'));
 } finally {
 setConfigSaving(false);
 }
 }

 /** 202 of a 'restricted' settings write: { approvalId, status: 'pending_approval' }. */
 const isPendingApproval = (x: unknown): boolean =>
 !!x && typeof x === 'object' && (x as { status?: unknown }).status === 'pending_approval';

 async function saveObligateConfig() {
 try {
 const trimmedUrl = obligateUrl.trim().replace(/\/$/, '');
 if (trimmedUrl && trimmedUrl === window.location.origin.replace(/\/$/, '')) {
 toast.error('Obligate URL cannot point to this application. Enter the URL of your Obligate SSO gateway.');
 return;
 }
 const patch: { url?: string | null; apiKey?: string | null; enabled?: boolean } = { url: trimmedUrl || null };
 if (obligateApiKey.trim()) patch.apiKey = obligateApiKey.trim();
 const updated = await appConfigApi.patchObligateConfig(patch);
 // 'restricted' settings: 202, a second administrator approves the change.
 if (isPendingApproval(updated)) {
 toast.success(t('users.sentForApproval', 'Sent for approval to a second administrator'));
 return;
 }
 setObligateCfg(updated);
 setObligateApiKey('');
 toast.success(t('settings.obligate.saved', 'Obligate configuration saved'));
 } catch (err: any) {
 toast.error(err?.response?.status === 409
 ? t('settings.obligate.splitRequired', 'A second administrator must approve changes to these settings, and an approval never keeps a secret: save the gateway address on its own first (a second administrator approves it), then the API key on its own (a code is asked).')
 : t('settings.obligate.saveFailed', 'Failed to save Obligate configuration'));
 }
 }

 // Inbound secret: saved on its own, never with the URL
 // or the key (a failed save must not touch the other fields).
 async function patchObligateSecrets(patch: { inboundSecret?: string | null }) {
 try {
 const updated = await appConfigApi.patchObligateConfig(patch);
 if (isPendingApproval(updated)) {
 toast.success(t('users.sentForApproval', 'Sent for approval to a second administrator'));
 return;
 }
 setObligateCfg(updated);
 if ('inboundSecret' in patch) setObligateInboundSecret('');
 toast.success(t('settings.obligate.secretsSaved', 'Obligate configuration saved'));
 } catch (err: any) {
 const serverError = String(err?.response?.data?.error ?? '');
 toast.error(/at least 16 characters/i.test(serverError)
 ? t('settings.obligate.inboundSecret.tooShort', 'The inbound secret must be at least 16 characters long.')
 : t('settings.obligate.secretsSaveFailed', 'Failed to save Obligate configuration'));
 }
 }

 // The inbound secret is only saved on an explicit action, after a warning:
 // no Obligate version sends a separate secret yet, so once it is set every
 // Obligate call to this server is refused (user deactivations and deletions
 // included) until Obligate is updated to send it.
 async function saveInboundSecret() {
 const value = obligateInboundSecret.trim();
 if (!value) return;
 if (value.length < INBOUND_SECRET_MIN) {
 toast.error(t('settings.obligate.inboundSecret.tooShort', 'The inbound secret must be at least 16 characters long.'));
 return;
 }
 const ok = await confirm({
 title: t('settings.obligate.inboundSecret.confirmTitle', 'Set an inbound secret?'),
 message: t('settings.obligate.inboundSecret.confirmMessage', 'From now on, Obligate calls to this server must present this secret instead of the API key. Obligate does not send a separate secret yet: until it is updated to send this one, all of its calls will be refused, including the deactivations and deletions of SSO users, which will then no longer reach this server.'),
 confirmLabel: t('settings.obligate.inboundSecret.confirmButton', 'Set the secret'),
 danger: true,
 });
 if (!ok) return;
 await patchObligateSecrets({ inboundSecret: value });
 }

 function formatUptime(seconds: number): string {
 const d = Math.floor(seconds / 86400);
 const h = Math.floor((seconds % 86400) / 3600);
 const m = Math.floor((seconds % 3600) / 60);
 const parts: string[] = [];
 if (d > 0) parts.push(`${d}d`);
 if (h > 0) parts.push(`${h}h`);
 parts.push(`${m}m`);
 return parts.join(' ');
 }

 return (
 <PageContainer className="space-y-8">
 <div>
 <h1 className="text-2xl font-semibold text-text-primary mb-2">{t('settings.title')}</h1>
 <p className="text-sm text-text-muted">
 {t('settings.globalDesc')}
 </p>
 </div>

 {/* ── About ── */}
 {admin && (
 <div>
 <div className="flex items-center gap-2 mb-4">
 <Info size={18} className="text-accent" />
 <h2 className="text-lg font-semibold text-text-primary">{t('about.title')}</h2>
 </div>
 <div className="rounded-lg bg-bg-secondary p-5">
 {systemInfoLoading ? (
 <p className="text-sm text-text-muted animate-pulse">{t('about.loading')}</p>
 ) : systemInfo ? (
 <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6">
 <div className="space-y-2">
 <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted mb-3">
 <Server size={12} /> {t('about.versions')}
 </p>
 <AboutRow label={t('about.server')} value={`v${systemInfo.appVersion}`} />
 <AboutRow label={t('about.client')} value={`v${__APP_VERSION__}`} />
 <AboutRow label="Node.js" value={systemInfo.nodeVersion} />
 </div>
 <div className="space-y-2">
 <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted mb-3">
 <Clock size={12} /> {t('about.instance')}
 </p>
 <AboutRow label={t('about.uptime')} value={formatUptime(systemInfo.uptimeSeconds)} />
 <AboutRow label={t('about.environment')} value={systemInfo.environment.isDocker ? 'Docker' : 'Native'} />
 <AboutRow label={t('about.platform')} value={systemInfo.environment.platform} />
 <AboutRow label={t('about.cpuCores')} value={String(systemInfo.cpu.cores)} />
 </div>
 <div className="space-y-2">
 <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted mb-3">
 <HardDrive size={12} /> {t('about.memory')}
 </p>
 <AboutRow label={t('about.processRss')} value={`${systemInfo.memory.processRssMb} MB`} />
 <AboutRow label={t('about.heapUsed')} value={`${systemInfo.memory.processHeapMb} MB`} />
 <AboutRow label={t('about.systemFree')} value={`${systemInfo.memory.systemFreeMb} / ${systemInfo.memory.systemTotalMb} MB`} />
 </div>
 <div className="space-y-2">
 <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted mb-3">
 <Cpu size={12} /> {t('about.cpuLoad')}
 </p>
 <AboutRow label="1 min" value={String(systemInfo.cpu.loadAvg1)} />
 <AboutRow label="5 min" value={String(systemInfo.cpu.loadAvg5)} />
 <AboutRow label="15 min" value={String(systemInfo.cpu.loadAvg15)} />
 </div>
 <div className="space-y-2">
 <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted mb-3">
 <Database size={12} /> {t('about.database')}
 </p>
 <div className="flex items-center justify-between">
 <span className="text-xs text-text-muted">PostgreSQL</span>
 <span className={cn(
 'flex items-center gap-1.5 text-xs font-medium',
 systemInfo.environment.dbStatus === 'ok' ? 'text-status-up' : 'text-status-down',
 )}>
 <span className={cn(
 'h-1.5 w-1.5 rounded-full',
 systemInfo.environment.dbStatus === 'ok' ? 'bg-status-up' : 'bg-status-down',
 )} />
 {systemInfo.environment.dbStatus === 'ok' ? t('about.connected') : t('about.error')}
 </span>
 </div>
 </div>
 </div>
 ) : (
 <p className="text-sm text-text-muted">{t('about.loadFailed')}</p>
 )}
 </div>
 </div>
 )}

 {/* ── Default Monitor Settings ── */}
 <SettingsPanel scope="global" scopeId={null} title={t('settings.defaultMonitorSettings')} />

 {/* ── Remote assistance (P0-15): hidden when the settings cannot be read ── */}
 <RemoteSettingsSection />

 {admin && (
 <>
 {/* ── SMTP Servers ── */}
 <div>
 <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
 <h2 className="text-lg font-semibold text-text-primary">{t('settings.smtp.title')}</h2>
 <Button size="sm" onClick={openCreate}>
 <Plus size={14} className="mr-1" /> {t('settings.smtp.addServer')}
 </Button>
 </div>
 {servers.length === 0 ? (
 <div className="rounded-lg bg-bg-secondary p-5 text-sm text-text-muted flex items-center gap-3">
 <Server size={16} className="shrink-0" />
 {t('settings.smtp.noServers')}
 </div>
 ) : (
 // Horizontal scroll instead of clipping the Actions column on
 // narrow screens (name column pinned while scrolling below lg).
 <TableScroll className="rounded-lg bg-bg-secondary" stickyFirstCol={!isWide}>
 <table className="w-full text-sm min-w-[560px]">
 <thead>
 <tr className=" text-left">
 <th className="px-4 py-2.5 font-medium text-text-secondary">{t('settings.smtp.colName')}</th>
 <th className="px-4 py-2.5 font-medium text-text-secondary">{t('settings.smtp.colHost')}</th>
 <th className="px-4 py-2.5 font-medium text-text-secondary">{t('settings.smtp.colFrom')}</th>
 <th className="px-4 py-2.5 font-medium text-text-secondary text-right">{t('settings.smtp.colActions')}</th>
 </tr>
 </thead>
 <tbody>
 {servers.map((server) => (
 <tr key={server.id} className=" last:border-0 hover:bg-bg-hover transition-colors hover:[--table-sticky-bg:rgb(var(--c-bg-hover))]">
 <td className="px-4 py-3 text-text-primary font-medium">{server.name}</td>
 <td className="px-4 py-3 text-text-secondary whitespace-nowrap">
 {server.host}:{server.port}
 {server.secure && <span className="ml-1.5 text-xs bg-green-500/10 text-green-400 rounded px-1">{t('settings.smtp.tlsBadge')}</span>}
 </td>
 <td className="px-4 py-3 text-text-muted">{server.fromAddress}</td>
 <td className="px-4 py-3">
 <div className="flex items-center justify-end gap-1.5">
 <IconButton
 label={t('settings.smtp.testConnection')}
 icon={<Wifi size={14} />}
 onClick={() => handleTest(server)}
 disabled={testingId === server.id}
 className="hover:text-blue-400 hover:bg-blue-400/10 disabled:opacity-50"
 />
 <IconButton
 label={t('common.edit')}
 icon={<Pencil size={14} />}
 onClick={() => openEdit(server)}
 />
 <IconButton
 label={t('common.delete')}
 icon={<Trash2 size={14} />}
 variant="danger"
 onClick={() => handleDelete(server)}
 />
 </div>
 </td>
 </tr>
 ))}
 </tbody>
 </table>
 </TableScroll>
 )}
 </div>

 {/* ── Security / 2FA ── */}
 <div>
 <h2 className="text-lg font-semibold text-text-primary mb-4">{t('settings.security.title')}</h2>
 <div className="rounded-lg bg-bg-secondary divide-y divide-border">
 <div className="flex items-start justify-between gap-4 p-4">
 <div className="flex items-start gap-3">
 <Shield size={16} className="text-text-muted mt-0.5 shrink-0" />
 <div>
 <p className="text-sm font-medium text-text-primary">{t('settings.security.allow2fa')}</p>
 <p className="text-xs text-text-muted mt-0.5">{t('settings.security.allow2faDesc')}</p>
 </div>
 </div>
 <button
 role="switch"
 aria-checked={appConfig?.allow_2fa === 'true'}
 disabled={configSaving || !appConfig}
 onClick={() => setConfigKey('allow_2fa', appConfig?.allow_2fa !== 'true')}
 aria-label={t('settings.security.allow2fa')}
 className={cn(
 'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none disabled:opacity-50',
 TOUCH_HIT,
 appConfig?.allow_2fa === 'true' ? 'bg-primary' : 'bg-bg-tertiary',
 )}
 >
 <span className={cn('pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transition-transform', appConfig?.allow_2fa === 'true' ? 'translate-x-4' : 'translate-x-0')} />
 </button>
 </div>

 <div className={cn('flex items-start justify-between gap-4 p-4', appConfig?.allow_2fa !== 'true' && 'opacity-50 pointer-events-none')}>
 <div className="flex items-start gap-3">
 <Shield size={16} className="text-text-muted mt-0.5 shrink-0" />
 <div>
 <p className="text-sm font-medium text-text-primary">{t('settings.security.force2fa')}</p>
 <p className="text-xs text-text-muted mt-0.5">
 {t('settings.security.force2faDesc').split('\n')[0]}
 {' '}
 Bypass via <code className="text-xs font-mono">DISABLE_2FA_FORCE=true</code> in .env.
 </p>
 </div>
 </div>
 <button
 role="switch"
 aria-checked={appConfig?.force_2fa === 'true'}
 disabled={configSaving || !appConfig || appConfig.allow_2fa !== 'true'}
 onClick={() => setConfigKey('force_2fa', appConfig?.force_2fa !== 'true')}
 aria-label={t('settings.security.force2fa')}
 className={cn(
 'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none disabled:opacity-50',
 TOUCH_HIT,
 appConfig?.force_2fa === 'true' ? 'bg-primary' : 'bg-bg-tertiary',
 )}
 >
 <span className={cn('pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transition-transform', appConfig?.force_2fa === 'true' ? 'translate-x-4' : 'translate-x-0')} />
 </button>
 </div>

 <div className={cn('flex items-start gap-4 p-4', appConfig?.allow_2fa !== 'true' && 'opacity-50 pointer-events-none')}>
 <Server size={16} className="text-text-muted mt-0.5 shrink-0" />
 <div className="flex-1 min-w-0">
 <p className="text-sm font-medium text-text-primary">{t('settings.security.otpSmtp')}</p>
 <p className="text-xs text-text-muted mt-0.5">{t('settings.security.otpSmtpDesc')}</p>
 <select
 className="mt-2 w-full max-w-xs rounded-md bg-bg-primary px-3 py-1.5 coarse:py-2 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
 value={appConfig?.otp_smtp_server_id ?? ''}
 disabled={configSaving || !appConfig || appConfig.allow_2fa !== 'true'}
 onChange={(e) => setConfigKey('otp_smtp_server_id', e.target.value ? parseInt(e.target.value, 10) : null)}
 >
 <option value="">{t('settings.security.noneOption')}</option>
 {servers.map((s) => (
 <option key={s.id} value={s.id}>{s.name}</option>
 ))}
 </select>
 </div>
 </div>
 </div>
 </div>

 {/* ── Obligate SSO Gateway ── */}
 <div>
 <div className="flex items-center gap-2 mb-4">
 <ArrowLeftRight size={16} className="text-text-muted" />
 <h2 className="text-lg font-semibold text-text-primary">Obligate SSO Gateway</h2>
 </div>
 <div className="rounded-lg bg-bg-secondary p-5 space-y-4">
 <p className="text-sm text-text-muted">
 {t('settings.obligate.description', 'Connect this app to your Obligate SSO gateway for centralized authentication and cross-app navigation. Register this app in Obligate first, then paste the API key here.')}
 </p>
 <div className="bg-status-pending-bg border border-status-pending/30 rounded-md p-3 text-sm text-status-pending">
 {t('settings.obligate.warning', 'When enabled, local authentication is disabled. Users must sign in through the Obligate gateway. If the gateway becomes unreachable, local authentication is automatically restored as a fallback.')}
 </div>

 <div>
 <div className="flex items-center gap-2 mb-1">
 <label className="text-sm font-medium text-text-secondary">Obligate URL</label>
 {obligateCfg?.url && (
 <a
 href={obligateCfg.url}
 target="_blank"
 rel="noopener noreferrer"
 onClick={(e) => { e.preventDefault(); void openExternal(obligateCfg.url!); }}
 className="text-xs text-accent hover:underline coarse:py-2"
 >
 {t('settings.obligate.open', 'Open ↗')}
 </a>
 )}
 </div>
 <div className="flex gap-2">
 <input
 type="url"
 inputMode="url"
 enterKeyHint="done"
 autoCapitalize="off"
 autoCorrect="off"
 spellCheck={false}
 placeholder="https://obligate.example.com"
 value={obligateUrl}
 onChange={(e) => setObligateUrl(e.target.value)}
 onBlur={() => void saveObligateConfig()}
 onKeyDown={blurOnEnterTouch}
 className="w-full min-w-0 flex-1 rounded-lg bg-bg-primary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/30"
 />
 {/* Touch: closing the Android keyboard does not blur the field,
     so offer an explicit Save while the value is unsaved. */}
 {obligateUrl.trim().replace(/\/$/, '') !== (obligateCfg?.url ?? '').replace(/\/$/, '') && (
 <Button type="button" size="sm" className="hidden coarse:inline-flex shrink-0" onMouseDown={(e) => e.preventDefault()} onClick={() => void saveObligateConfig()}>
 {t('common.save')}
 </Button>
 )}
 </div>
 </div>

 <div>
 <label className="block text-sm font-medium text-text-secondary mb-1">
 API Key
 {obligateCfg?.apiKeySet && (
 <span className="ml-2 text-[10px] font-semibold rounded px-1.5 py-0.5 bg-green-500/10 text-green-400 border border-green-500/20">SET</span>
 )}
 </label>
 <div className="flex gap-2">
 <div className="relative flex-1">
 <input
 type={showObligateKey ? 'text' : 'password'}
 placeholder={obligateCfg?.apiKeySet ? '••••••••••••••••••••••••••••••••••••' : 'Paste the API key from Obligate\u2026'}
 value={obligateApiKey}
 onChange={(e) => setObligateApiKey(e.target.value)}
 onBlur={() => { if (obligateApiKey.trim()) void saveObligateConfig(); }}
 onKeyDown={blurOnEnterTouch}
 enterKeyHint="done"
 autoCapitalize="off"
 autoCorrect="off"
 autoComplete="off"
 spellCheck={false}
 className="w-full rounded-lg bg-bg-primary px-3 py-2 pr-8 text-sm font-mono text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/30"
 />
 <button
 type="button"
 onClick={() => setShowObligateKey((v) => !v)}
 aria-label={t('settings.toggleSecretVisibility', 'Show / hide')}
 aria-pressed={showObligateKey}
 className={`absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary ${TOUCH_HIT}`}
 >
 {showObligateKey ? <EyeOff size={14} /> : <Eye size={14} />}
 </button>
 </div>
 {obligateApiKey.trim() && (
 <Button type="button" size="sm" className="hidden coarse:inline-flex shrink-0" onMouseDown={(e) => e.preventDefault()} onClick={() => void saveObligateConfig()}>
 {t('common.save')}
 </Button>
 )}
 </div>
 <p className="mt-1.5 text-xs text-text-muted">
 Generate this key in{' '}
 <span className="text-text-secondary font-medium">Obligate → Connected Apps → Add App</span>.
 </p>
 </div>

 {obligateCfg?.apiKeySet && (
 <>
 {/* Optional distinct secret Obligate must present on its calls to this server */}
 <div>
 <label className="block text-sm font-medium text-text-secondary mb-1">
 {t('settings.obligate.inboundSecret.label', 'Inbound secret (optional)')}
 {obligateCfg.inboundSecretSet && (
 <span className="ml-2 text-[10px] font-semibold rounded px-1.5 py-0.5 bg-green-500/10 text-green-400 border border-green-500/20">{t('settings.obligate.setBadge', 'SET')}</span>
 )}
 </label>
 <div className="flex gap-2">
 <div className="relative flex-1">
 <input
 type={showInboundSecret ? 'text' : 'password'}
 placeholder={obligateCfg.inboundSecretSet ? '••••••••••••••••••••••••••••••••••••' : t('settings.obligate.inboundSecret.placeholder', 'Empty: the API key is expected')}
 value={obligateInboundSecret}
 disabled={!!obligateCfg.inboundSecretFromEnv}
 onChange={(e) => setObligateInboundSecret(e.target.value)}
 onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void saveInboundSecret(); } }}
 enterKeyHint="done"
 autoCapitalize="off"
 autoCorrect="off"
 autoComplete="off"
 spellCheck={false}
 aria-label={t('settings.obligate.inboundSecret.label', 'Inbound secret (optional)')}
 className="w-full rounded-lg bg-bg-primary px-3 py-2 pr-8 text-sm font-mono text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/30 disabled:opacity-50"
 />
 <button
 type="button"
 onClick={() => setShowInboundSecret((v) => !v)}
 aria-label={t('settings.toggleSecretVisibility', 'Show / hide')}
 aria-pressed={showInboundSecret}
 className={`absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary ${TOUCH_HIT}`}
 >
 {showInboundSecret ? <EyeOff size={14} /> : <Eye size={14} />}
 </button>
 </div>
 {obligateInboundSecret.trim() && (
 <Button type="button" size="sm" className="shrink-0" onClick={() => void saveInboundSecret()}>
 {t('common.save')}
 </Button>
 )}
 {obligateCfg.inboundSecretSet && !obligateCfg.inboundSecretFromEnv && (
 <Button type="button" size="sm" variant="ghost" className="shrink-0" onClick={() => void patchObligateSecrets({ inboundSecret: null })}>
 {t('settings.obligate.inboundSecret.clear', 'Clear')}
 </Button>
 )}
 </div>
 <p className="mt-1.5 text-xs text-text-muted">
 {obligateCfg.inboundSecretFromEnv
 ? t('settings.obligate.inboundSecret.fromEnv', 'Set by the OBLIGATE_INBOUND_SECRET environment variable.')
 : t('settings.obligate.inboundSecret.hint', 'Secret that Obligate must present when it calls this server (user sync, app info, dashboard stats), at least 16 characters. Leave empty to keep expecting the API key. Set it only once Obligate sends a separate secret: otherwise all of its calls are refused, and the deactivations and deletions of SSO users no longer reach this server.')}
 </p>
 </div>
 </>
 )}

 {obligateCfg?.url && obligateCfg.apiKeySet && (
 <div className="pt-4 mt-4">
 <div className="flex items-center justify-between gap-4">
 <div>
 <p className="text-sm font-medium text-text-primary">Enable SSO</p>
 <p className="text-xs text-text-muted mt-0.5">
 When enabled, the login page redirects to Obligate for authentication.
 Users are auto-provisioned on first login. Cross-app navigation buttons appear in the header.
 </p>
 </div>
 <button
 type="button"
 role="switch"
 aria-checked={appConfig?.obligate_enabled === 'true'}
 disabled={configSaving || !appConfig}
 onClick={() => setConfigKey('obligate_enabled', appConfig?.obligate_enabled === 'true' ? false : true)}
 aria-label={t('settings.obligate.enableSso', 'Enable SSO')}
 className={cn('relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus:outline-none', TOUCH_HIT, appConfig?.obligate_enabled === 'true' ? 'bg-primary' : 'bg-bg-hover')}
 >
 <span className={cn('inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform', appConfig?.obligate_enabled === 'true' ? 'translate-x-6' : 'translate-x-1')} />
 </button>
 </div>
 </div>
 )}
 </div>
 </div>
 </>
 )}

 {/* Shared Modal: scrollable body + sticky footer so Save stays
     reachable with the soft keyboard open; full-screen on phones. */}
 <Modal
 open={!!smtpMode}
 onClose={closeSmtpModal}
 size="sm"
 closeOnBackdrop={false}
 // Same header as the former hand-rolled dialog from sm up
 // (text-base title, px-5 py-4).
 title={<span className="text-base">{smtpMode === 'create' ? t('settings.smtp.addTitle') : t('settings.smtp.editTitle')}</span>}
 className="sm:[&>div:first-child]:px-5 sm:[&>div:first-child]:py-4"
 bodyClassName="p-5"
 footer={
 <>
 <Button type="button" variant="ghost" onClick={closeSmtpModal}>{t('common.cancel')}</Button>
 <Button type="submit" form="smtp-server-form" disabled={smtpSaving}>
 {smtpSaving ? t('common.saving') : smtpMode === 'create' ? t('common.create') : t('common.save')}
 </Button>
 </>
 }
 >
 <form id="smtp-server-form" onSubmit={handleSmtpSubmit} className="space-y-3">
 <Input
 label={t('settings.smtp.nameLabel')}
 value={smtpForm.name}
 onChange={(e) => setSmtpForm((f) => ({ ...f, name: e.target.value }))}
 placeholder={t('settings.smtp.namePlaceholder')}
 required
 />
 <div className="grid grid-cols-3 gap-3">
 <div className="col-span-2">
 <Input
 label={t('settings.smtp.hostLabel')}
 value={smtpForm.host}
 onChange={(e) => setSmtpForm((f) => ({ ...f, host: e.target.value }))}
 placeholder={t('settings.smtp.hostPlaceholder')}
 autoCapitalize="off"
 autoCorrect="off"
 spellCheck={false}
 required
 />
 </div>
 <Input
 label={t('settings.smtp.portLabel')}
 type="number"
 value={smtpForm.port}
 onChange={(e) => setSmtpForm((f) => ({ ...f, port: e.target.value }))}
 placeholder={t('settings.smtp.portPlaceholder')}
 required
 />
 </div>
 <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer select-none">
 <input
 type="checkbox"
 checked={smtpForm.secure}
 onChange={(e) => setSmtpForm((f) => ({ ...f, secure: e.target.checked }))}
 className="rounded border-transparent coarse:h-5 coarse:w-5"
 />
 {t('settings.smtp.tlsLabel')}
 </label>
 <Input
 label={t('settings.smtp.usernameLabel')}
 value={smtpForm.username}
 onChange={(e) => setSmtpForm((f) => ({ ...f, username: e.target.value }))}
 autoCapitalize="off"
 autoCorrect="off"
 spellCheck={false}
 required
 />
 <div className="relative">
 <Input
 label={smtpMode === 'edit' ? t('settings.smtp.passwordEditLabel') : t('settings.smtp.passwordLabel')}
 type={showPassword ? 'text' : 'password'}
 value={smtpForm.password}
 onChange={(e) => setSmtpForm((f) => ({ ...f, password: e.target.value }))}
 required={smtpMode === 'create'}
 />
 <button
 type="button"
 onClick={() => setShowPassword((v) => !v)}
 aria-label={t('settings.toggleSecretVisibility', 'Show / hide')}
 aria-pressed={showPassword}
 className={`absolute right-2.5 bottom-2 text-text-muted hover:text-text-primary ${TOUCH_HIT}`}
 >
 {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
 </button>
 </div>
 <Input
 label={t('settings.smtp.fromLabel')}
 type="email"
 value={smtpForm.fromAddress}
 onChange={(e) => setSmtpForm((f) => ({ ...f, fromAddress: e.target.value }))}
 placeholder={t('settings.smtp.fromPlaceholder')}
 autoCapitalize="off"
 autoCorrect="off"
 spellCheck={false}
 required
 />
 </form>
 </Modal>

 {/* ── Device-bound 2FA (fingerprint on the Android app) ── */}
 {admin && <DeviceKeysSettingsSection />}
 </PageContainer>
 );
}
