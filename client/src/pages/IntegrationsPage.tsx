import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { CheckCircle2, CircleDashed, Download, ExternalLink, KeyRound, Plus, RefreshCw, Server, Trash2, Upload, XCircle } from 'lucide-react';
import {
  isMasterTenant, MANUAL_DEADLINE_KINDS, SocketEvents,
  type AdeServerState, type AdeServerView, type DeadlineLevel, type DeadlineView, type IntegrationCardState, type IntegrationsSummary,
  type ManualDeadlineKind, type PushCertState, type PushOverview, type PushRequestView, type ReadinessItem, type ReadinessState, type TenantCapability,
  type VppOperationListItem, type VppTokenState, type VppTokenView,
} from '@obligarth/shared';
import { integrationsApi, isPendingApproval, type Download as FileDownload } from '@/api/integrations.api';
import { isStepUpHandled } from '@/api/client';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { registerSocketListener } from '@/socket/socketListeners';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import { saveBlob } from '@/utils/download';
import { AndroidEnterpriseCard } from '@/components/android/AndroidEnterpriseCard';

// The Integrations tab (integration-apple-edge §11.7, INT-04, lot C3): the readiness checklist of the tenant
// (§11.5), then five cards: the device service, the push certificate (its five steps with the vendor's offline
// signing tool and Apple's portal, opened in a new tab), the ADE servers of Apple Business, Apps and Books (lot C4:
// content tokens, takeover of a token another MDM uses under guard, recent licence operations)
// and the deadlines (INT-05; for the platform administrators in the master tenant, every tenant's and the
// instance's, with the deadlines typed by hand). Reading: 'settings' or mdm.integrations.manage; writing:
// mdm.integrations.manage. No device data on these cards.

const CARD_TONE: Record<IntegrationCardState, 'green' | 'gray' | 'amber' | 'red'> = { ready: 'green', todo: 'gray', attention: 'amber', error: 'red' };
const READY_TONE: Record<ReadinessState, 'green' | 'gray' | 'amber' | 'red' | 'blue'> = { ready: 'green', todo: 'gray', warning: 'amber', error: 'red', not_applicable: 'blue' };
const LEVEL_TONE: Record<DeadlineLevel, 'green' | 'gray' | 'amber' | 'red'> = { ok: 'green', warning: 'amber', critical: 'red', expired: 'red', unknown: 'gray', retired: 'gray' };
const PUSH_TONE: Record<PushCertState, 'green' | 'gray' | 'amber' | 'red' | 'blue' | 'violet'> = {
  vendor_signature_pending: 'blue', apple_upload_pending: 'violet', active: 'green', legacy: 'amber', superseded: 'gray', expired: 'red', revoked: 'red', abandoned: 'gray',
};
const ADE_TONE: Record<AdeServerState, 'green' | 'gray' | 'amber' | 'red'> = {
  awaiting_token: 'gray', active: 'green', terms_not_signed: 'red', expired: 'red', error: 'red', removed: 'gray',
};
const APPLE_PUSH_PORTAL = 'https://identity.apple.com/pushcert/';
const APPLE_BUSINESS_PORTAL = 'https://business.apple.com/';

const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
const dateOf = (v: string | null | undefined): string => (v ? formatDateTime(v) : '—');

function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
}

async function save(d: Promise<FileDownload>, failed: string): Promise<void> {
  try {
    const f = await d;
    if (!(await saveBlob(f.blob, f.filename))) toast.error(failed);
  } catch (err) { errorToast(err); }
}

/** A file chosen by the user, as bytes; resets the input so the same file can be chosen again. */
function FilePicker({ label, accept, onFile, disabled }: { label: string; accept?: string; onFile: (b: ArrayBuffer) => void; disabled?: boolean }) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <>
      <input ref={ref} type="file" accept={accept} className="hidden" onChange={async (e) => {
        const f = e.target.files?.[0];
        e.target.value = '';
        if (f) onFile(await f.arrayBuffer());
      }} />
      <Button size="sm" variant="secondary" disabled={disabled} onClick={() => ref.current?.click()}><Upload className="w-4 h-4 mr-1" />{label}</Button>
    </>
  );
}

function Card({ title, icon, state, children, action }: { title: string; icon: ReactNode; state: IntegrationCardState; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {icon}
        <h2 className="text-base font-semibold text-text-primary">{title}</h2>
        <StateBadge tone={CARD_TONE[state]} label={trCode(`apple.integrations.cardState.${state}`, state)} />
        <span className="ml-auto flex flex-wrap gap-2">{action}</span>
      </div>
      {children}
    </section>
  );
}

export function IntegrationsPage() {
  const { t } = useTranslation();
  const [summary, setSummary] = useState<IntegrationsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    integrationsApi.summary().then((s) => { setSummary(s); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => { load(); }), [load]);
  return (
    <PageContainer className="space-y-5">
      <div className="flex flex-wrap items-start gap-2">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{t('apple.integrations.title') || 'Integrations'}</h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('apple.integrations.subtitle') || 'Apple certificates and tokens of this tenant, their renewals, and what remains to do before enrolling devices.'}
          </p>
        </div>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="ml-auto p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      {error && <p className="text-sm text-status-down">{error}</p>}
      {summary && <ReadinessPanel items={summary.readiness} />}
      {summary && <EdgeCard s={summary} />}
      {summary && <PushCard state={summary.push.state} onChange={load} />}
      {summary && <AdeCard state={summary.ade.state} onChange={load} />}
      {summary && <VppCard s={summary} onChange={load} />}
      {summary && <DeadlinesCard state={summary.deadlines.state} />}
      {/* Android Enterprise (android-amapi §12.1, lot AN-C2): the tenant's enterprise, its linking and its operation. */}
      <AndroidEnterpriseCard />
    </PageContainer>
  );
}

// ── Readiness (§11.5) ───────────────────────────────────────────────────────────

const READINESS_FALLBACK: Record<string, string> = {
  'tenant.provisioned': 'Device service of the tenant', 'push.active': 'Push certificate', 'enrollment.profile': 'Enrollment profile',
  'ade.server': 'ADE server (Apple Business)', 'byod.discovery': 'Account-driven enrollment declared', 'vpp.token': 'Apps and Books token',
  'signing.identity': 'Signing of the enrollment profiles', 'notice.custom': 'Notice of the employees', 'privacy.profile': 'Privacy rules',
  'ddm.relay': 'Declarative management relay',
};
/** The items settled on the privacy page (P0-13 T7): their label leads there. */
const READINESS_LINK: Record<string, string> = { 'notice.custom': '/privacy?tab=notice', 'privacy.profile': '/privacy?tab=profiles' };
const PRIVACY_READER_CAPS: readonly TenantCapability[] = ['settings', 'audit.read', 'mdm.privacy.manage'];

export function ReadinessPanel({ items, compact = false }: { items: ReadinessItem[]; compact?: boolean }) {
  const { t } = useTranslation();
  const shown = compact ? items.filter((i) => i.state !== 'ready' && i.state !== 'not_applicable') : items;
  // The privacy page opens with settings, audit.read or mdm.privacy.manage (its route's gate).
  const privacyReader = useAuthStore((s) => s.user?.role === 'admin'
    || (s.permissions?.tenantCapabilities ?? []).some((c) => PRIVACY_READER_CAPS.includes(c)));
  if (compact && shown.length === 0) return null;
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="text-sm font-semibold text-text-primary mb-2">{t('apple.readiness.title') || 'Readiness of the tenant'}</h2>
      <ul className="grid gap-1 sm:grid-cols-2">
        {shown.map((i) => (
          <li key={i.key} className="flex items-center gap-2 text-sm">
            {i.state === 'ready' ? <CheckCircle2 className="w-4 h-4 text-status-up" /> : i.state === 'error' ? <XCircle className="w-4 h-4 text-status-down" />
              : <CircleDashed className="w-4 h-4 text-text-muted" />}
            {READINESS_LINK[i.key] && privacyReader
              ? <Link to={READINESS_LINK[i.key]} className="text-accent hover:underline">{trCode(`apple.readiness.key.${i.key.replace('.', '_')}`, READINESS_FALLBACK[i.key] ?? i.key)}</Link>
              : <span className="text-text-primary">{trCode(`apple.readiness.key.${i.key.replace('.', '_')}`, READINESS_FALLBACK[i.key] ?? i.key)}</span>}
            <StateBadge tone={READY_TONE[i.state]} label={trCode(`apple.readiness.state.${i.state}`, i.state)} />
            {i.reason && <span className="text-xs text-text-muted">{t(`apple.readiness.reason.${i.reason}`, { ...(i.params ?? {}), defaultValue: i.reason })}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}

// ── Device service ──────────────────────────────────────────────────────────────

function EdgeCard({ s }: { s: IntegrationsSummary }) {
  const { t } = useTranslation();
  return (
    <Card title={t('apple.integrations.edge.title') || 'Device service'} icon={<Server className="w-5 h-5 text-accent" />} state={s.edge.state}>
      <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
        <div><dt className="text-text-muted">{t('apple.integrations.edge.state') || 'State'}</dt><dd>{trCode(`apple.integrations.edge.edgeState.${s.edge.edgeState}`, s.edge.edgeState)}</dd></div>
        <div><dt className="text-text-muted">{t('apple.integrations.edge.key') || 'MDM key'}</dt><dd className="font-mono">{s.edge.mdmKey ?? '—'}</dd></div>
        <div><dt className="text-text-muted">{t('apple.integrations.edge.frozen') || 'Commands'}</dt>
          <dd>{s.edge.commandsFrozen ? (t('apple.integrations.edge.commandsFrozen') || 'Frozen') : (t('apple.integrations.edge.commandsLive') || 'Running')}</dd></div>
      </dl>
      {s.edge.reachable === false && <p className="text-sm text-status-down">{t('apple.integrations.edge.unreachable') || 'The device service does not answer.'}</p>}
    </Card>
  );
}

// ── Push certificate (§11.1) ────────────────────────────────────────────────────

const PURPOSE_FALLBACK: Record<string, string> = { initial: 'First certificate', renewal: 'Renewal (same Apple account)', topic_change: 'Change of topic', import: 'Import' };

function PushCard({ state, onChange }: { state: IntegrationCardState; onChange: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const [o, setO] = useState<PushOverview | null>(null);
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [lab, setLab] = useState(false);
  const load = useCallback(() => { integrationsApi.push().then(setO).catch(errorToast); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => { load(); }), [load]);
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    try {
      const r = await fn();
      if (isPendingApproval(r)) toast.success(t('apple.integrations.push.topicChangePending') || 'A second approver must approve the change of topic');
      else if (done) toast.success(done);
      load();
      onChange();
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  const open = o?.open ?? null;
  const step = !open ? 1 : open.state === 'vendor_signature_pending' ? 2 : 4;
  return (
    <Card title={t('apple.integrations.push.title') || 'Push certificate'} icon={<KeyRound className="w-5 h-5 text-accent" />} state={state}
      action={!open && o && (
        <Button size="sm" onClick={() => setCreating(true)}><Plus className="w-4 h-4 mr-1" />
          {o.active ? (t('apple.integrations.push.renew') || 'Renew') : (t('apple.integrations.push.create') || 'Create a request')}</Button>
      )}>
      <p className="text-xs text-text-muted">
        {t('apple.integrations.push.help') || 'Apple issues the push certificate of this tenant to an Apple account of the client: always use the same service account, and « Renew » (never « Create ») at each renewal, or every device must enroll again.'}
      </p>
      {o?.active && (
        <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
          <div><dt className="text-text-muted">{t('apple.integrations.push.topic') || 'Topic'}</dt><dd className="font-mono break-all">{o.active.topic}</dd></div>
          <div><dt className="text-text-muted">{t('apple.integrations.push.notAfter') || 'Expires'}</dt><dd>{dateOf(o.active.notAfter)}</dd></div>
          <div><dt className="text-text-muted">{t('apple.integrations.push.account') || 'Apple account'}</dt><dd>{o.active.appleAccountHint ?? '—'}</dd></div>
          <div><dt className="text-text-muted">{t('apple.integrations.push.devices') || 'Devices on this topic'}</dt><dd>{o.devicesOnActiveTopic}</dd></div>
        </dl>
      )}
      {o && o.legacy.length > 0 && (
        <div className="rounded border border-amber-500/40 p-2 text-sm">
          {o.legacy.map((l) => (
            <p key={l.id}>{t('apple.integrations.push.legacy', { topic: l.topic, count: l.devices }) || `${l.devices} device(s) still on the previous topic ${l.topic}: they must enroll again.`}</p>
          ))}
        </div>
      )}
      {open && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <StateBadge tone={PUSH_TONE[open.state]} label={trCode(`apple.integrations.push.state.${open.state}`, open.state)} />
            <span className="text-text-muted">{trCode(`apple.integrations.push.purpose.${open.purpose}`, PURPOSE_FALLBACK[open.purpose])}</span>
            {open.appleAccountHint && <span className="text-text-muted">· {open.appleAccountHint}</span>}
            <span className="ml-auto"><Button size="sm" variant="ghost" disabled={busy} onClick={async () => {
              if (await confirm({ message: t('apple.integrations.push.confirmAbandon') || 'Abandon this request?', danger: true })) {
                await run(() => integrationsApi.abandonPushRequest(open.id), t('apple.integrations.push.abandoned') || 'Request abandoned');
              }
            }}>{t('apple.integrations.push.abandon') || 'Abandon'}</Button></span>
          </div>
          <ol className="space-y-2 text-sm">
            <Step n={1} current={step} label={t('apple.integrations.push.step1') || 'Request created (the key stays in the device service)'} />
            <Step n={2} current={step} label={t('apple.integrations.push.step2') || 'Send the request file to the vendor, then import the file it signed'}>
              {step === 2 && (
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" disabled={!open.csrReady} onClick={() => save(integrationsApi.vendorFile(open.id), t('common.error') || 'Error')}>
                    <Download className="w-4 h-4 mr-1" />{t('apple.integrations.push.downloadVendorFile') || 'Download the request for the vendor'}</Button>
                  <FilePicker label={t('apple.integrations.push.importVendorFile') || 'Import the signed request'} accept=".json,application/json" disabled={busy}
                    onFile={(b) => run(() => integrationsApi.importVendorSigned(open.id, b), t('apple.integrations.push.vendorImported') || 'Signed request imported')} />
                </div>
              )}
            </Step>
            <Step n={3} current={step === 4 ? 4 : step} label={t('apple.integrations.push.step3') || 'Signed request checked'} />
            <Step n={4} current={step} label={t('apple.integrations.push.step4') || 'Upload the file for Apple on Apple\'s portal with the client\'s service account'}>
              {step === 4 && (
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" onClick={() => save(integrationsApi.appleFile(open.id), t('common.error') || 'Error')}>
                    <Download className="w-4 h-4 mr-1" />{t('apple.integrations.push.downloadAppleFile') || 'Download the file for Apple'}</Button>
                  <a href={APPLE_PUSH_PORTAL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-accent hover:underline">
                    <ExternalLink className="w-4 h-4" />{t('apple.integrations.push.openPortal') || 'Open Apple\'s push certificates portal'}</a>
                </div>
              )}
            </Step>
            <Step n={5} current={step === 4 ? 5 : step} label={t('apple.integrations.push.step5') || 'Import the certificate Apple issued (.pem)'}>
              {step === 4 && (open.topicChangePending
                ? <p className="text-xs text-text-muted">{t('apple.integrations.push.topicChangePending') || 'A second approver must approve the change of topic'}</p>
                : <FilePicker label={t('apple.integrations.push.importCertificate') || 'Import the certificate of Apple'} accept=".pem,.cer,.crt" disabled={busy}
                  onFile={(b) => run(() => integrationsApi.importCertificate(open.id, b), t('apple.integrations.push.activated') || 'Push certificate active')} />)}
            </Step>
          </ol>
        </div>
      )}
      {o && o.history.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-text-muted">{t('apple.integrations.push.history') || 'History'}</summary>
          <table className="mt-2 w-full text-left text-xs">
            <tbody>
              {o.history.map((r: PushRequestView) => (
                <tr key={r.id} className="border-t border-border">
                  <td className="py-1"><StateBadge tone={PUSH_TONE[r.state]} label={trCode(`apple.integrations.push.state.${r.state}`, r.state)} /></td>
                  <td>{trCode(`apple.integrations.push.purpose.${r.purpose}`, PURPOSE_FALLBACK[r.purpose])}</td>
                  <td className="font-mono break-all">{r.topic ?? '—'}</td>
                  <td>{dateOf(r.notAfter)}</td>
                  <td>{dateOf(r.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      {o?.keyImportAllowed && isAdmin && (
        <Button size="sm" variant="ghost" onClick={() => setLab(true)}>{t('apple.integrations.push.labImport') || 'Import a certificate with its key (laboratory)'}</Button>
      )}
      {creating && o && <CreatePushModal hasActive={!!o.active} hint={o.active?.appleAccountHint ?? ''} onClose={() => setCreating(false)}
        onCreate={(purpose, hint) => run(async () => { await integrationsApi.createPushRequest({ purpose, appleAccountHint: hint || null }); setCreating(false); },
          t('apple.integrations.push.created') || 'Request created')} />}
      {lab && <LabImportModal onClose={() => setLab(false)} onImport={(c, k) => run(async () => { await integrationsApi.importPushWithKey(c, k); setLab(false); },
        t('apple.integrations.push.activated') || 'Push certificate active')} />}
    </Card>
  );
}

function Step({ n, current, label, children }: { n: number; current: number; label: string; children?: ReactNode }) {
  const done = n < current;
  return (
    <li className="flex gap-2">
      <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] ${done ? 'bg-status-up text-white' : n === current ? 'bg-accent text-white' : 'bg-bg-tertiary text-text-muted'}`}>{n}</span>
      <div className="space-y-1"><p className={n === current ? 'text-text-primary' : 'text-text-muted'}>{label}</p>{children}</div>
    </li>
  );
}

function CreatePushModal({ hasActive, hint, onClose, onCreate }: {
  hasActive: boolean; hint: string; onClose: () => void; onCreate: (purpose: 'initial' | 'renewal' | 'topic_change', hint: string) => void;
}) {
  const { t } = useTranslation();
  const [purpose, setPurpose] = useState<'initial' | 'renewal' | 'topic_change'>(hasActive ? 'renewal' : 'initial');
  const [account, setAccount] = useState(hint);
  return (
    <Modal open onClose={onClose} title={t('apple.integrations.push.createTitle') || 'New push certificate request'}
      footer={<Button size="sm" onClick={() => onCreate(purpose, account.trim())}>{t('apple.integrations.push.create') || 'Create a request'}</Button>}>
      <div className="space-y-3 text-sm">
        {hasActive && (
          <label className="block">{t('apple.integrations.push.purposeLabel') || 'Purpose'}
            <select className={fieldCls} value={purpose} onChange={(e) => setPurpose(e.target.value as 'renewal' | 'topic_change')}>
              <option value="renewal">{trCode('apple.integrations.push.purpose.renewal', PURPOSE_FALLBACK.renewal)}</option>
              <option value="topic_change">{trCode('apple.integrations.push.purpose.topic_change', PURPOSE_FALLBACK.topic_change)}</option>
            </select>
          </label>
        )}
        {purpose === 'topic_change' && (
          <p className="text-status-down">{t('apple.integrations.push.topicChangeWarning') || 'A new topic means that every device enrolled under the current one must enroll again; a second approver must agree.'}</p>
        )}
        <label className="block">{t('apple.integrations.push.accountLabel') || 'Apple account of the client used at Apple (a hint, never a password)'}
          <input className={fieldCls} maxLength={200} value={account} onChange={(e) => setAccount(e.target.value)} placeholder="apple-mdm@example.net" />
        </label>
      </div>
    </Modal>
  );
}

function LabImportModal({ onClose, onImport }: { onClose: () => void; onImport: (cert: string, key: string) => void }) {
  const { t } = useTranslation();
  const [cert, setCert] = useState('');
  const [key, setKey] = useState('');
  return (
    <Modal open onClose={onClose} size="lg" title={t('apple.integrations.push.labImport') || 'Import a certificate with its key (laboratory)'}
      footer={<Button size="sm" disabled={!cert || !key} onClick={() => onImport(cert, key)}>{t('common.import') || 'Import'}</Button>}>
      <div className="space-y-2 text-sm">
        <p className="text-text-muted">{t('apple.integrations.push.labHelp') || 'Laboratory only: the key goes to the device service once and is never kept by the console.'}</p>
        <textarea className={`${fieldCls} font-mono h-32`} value={cert} onChange={(e) => setCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        <textarea className={`${fieldCls} font-mono h-32`} value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" autoComplete="off" />
      </div>
    </Modal>
  );
}

// ── ADE servers (§11.2) ─────────────────────────────────────────────────────────

function AdeCard({ state, onChange }: { state: IntegrationCardState; onChange: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [rows, setRows] = useState<AdeServerView[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const load = useCallback(() => { integrationsApi.adeServers().then(setRows).catch(errorToast); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => { load(); }), [load]);
  const run = async (id: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(id);
    try {
      const r = await fn();
      if (isPendingApproval(r)) toast.success(t('apple.integrations.ade.deletePending') || 'A second approver must approve the deletion');
      else if (done) toast.success(done);
      load();
      onChange();
    } catch (err) { errorToast(err); } finally { setBusy(null); }
  };
  return (
    <Card title={t('apple.integrations.ade.title') || 'Apple Business: ADE servers'} icon={<Server className="w-5 h-5 text-accent" />} state={state}
      action={<Button size="sm" onClick={() => setAdding(true)}><Plus className="w-4 h-4 mr-1" />{t('apple.integrations.ade.add') || 'Add a server'}</Button>}>
      <p className="text-xs text-text-muted">
        {t('apple.integrations.ade.help') || 'In Apple Business (Preferences, device management servers), add a server, upload its public key, then download its server token (.p7m) and import it here. An organisation holds 250 keys at most.'}{' '}
        <a href={APPLE_BUSINESS_PORTAL} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">{t('apple.integrations.ade.openPortal') || 'Open Apple Business'}</a>
      </p>
      {rows && rows.length === 0 && <p className="text-sm text-text-muted">{t('apple.integrations.ade.none') || 'No ADE server yet.'}</p>}
      <ul className="space-y-2">
        {rows?.map((s) => (
          <li key={s.id} className="rounded border border-border p-3 text-sm space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-text-primary">{s.label}</span>
              {s.serverName && s.serverName !== s.label && <span className="text-text-muted">({s.serverName})</span>}
              <StateBadge tone={ADE_TONE[s.state]} label={trCode(`apple.integrations.ade.state.${s.state}`, s.state)} />
              {s.byodDiscovery && <StateBadge tone="blue" label={t('apple.integrations.ade.byodDeclared') || 'Account-driven enrollment'} />}
            </div>
            <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-4 text-xs">
              <div><dt className="text-text-muted">{t('apple.integrations.ade.notAfter') || 'Token expires'}</dt><dd>{dateOf(s.notAfter)}</dd></div>
              <div><dt className="text-text-muted">{t('apple.integrations.ade.lastSync') || 'Last synchronisation'}</dt><dd>{dateOf(s.lastSyncAt)}</dd></div>
              <div><dt className="text-text-muted">{t('apple.integrations.ade.devices') || 'Devices'}</dt><dd>{s.devices} · {t('apple.integrations.ade.enrolled', { count: s.enrolledDevices }) || `${s.enrolledDevices} enrolled`}</dd></div>
              <div><dt className="text-text-muted">{t('apple.integrations.ade.account') || 'Apple account'}</dt><dd>{s.appleAccountHint ?? '—'}</dd></div>
            </dl>
            {s.state === 'terms_not_signed' && <p className="text-xs text-status-down">{t('apple.integrations.ade.termsHelp') || 'New terms must be accepted in Apple Business by the client.'}</p>}
            {s.lastErrorCode && s.state !== 'active' && <p className="text-xs text-status-down">{t('apple.integrations.ade.lastError', { code: s.lastErrorCode }) || `Last error: ${s.lastErrorCode}`}</p>}
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" onClick={() => save(integrationsApi.adePublicKey(s.id), t('common.error') || 'Error')}>
                <Download className="w-4 h-4 mr-1" />{t('apple.integrations.ade.publicKey') || 'Public key for Apple Business'}</Button>
              <FilePicker label={s.state === 'awaiting_token' ? (t('apple.integrations.ade.importToken') || 'Import the server token') : (t('apple.integrations.ade.renewToken') || 'Renew the token')}
                accept=".p7m" disabled={busy === s.id}
                onFile={(b) => run(s.id, () => integrationsApi.uploadAdeToken(s.id, b), t('apple.integrations.ade.tokenImported') || 'Server token imported')} />
              {s.state !== 'awaiting_token' && (
                <Button size="sm" variant="ghost" disabled={busy === s.id} onClick={() => run(s.id, () => integrationsApi.syncAdeServer(s.id), t('apple.integrations.ade.syncRequested') || 'Synchronisation requested')}>
                  <RefreshCw className="w-4 h-4 mr-1" />{t('apple.integrations.ade.sync') || 'Synchronise now'}</Button>
              )}
              {s.state === 'active' && !s.byodDiscovery && (
                <Button size="sm" variant="ghost" disabled={busy === s.id} onClick={() => run(s.id, () => integrationsApi.declareByod(s.id), t('apple.integrations.ade.byodDone') || 'Account-driven enrollment declared')}>
                  {t('apple.integrations.ade.declareByod') || 'Enable account-driven enrollment'}</Button>
              )}
              <Button size="sm" variant="ghost" disabled={busy === s.id || s.enrolledDevices > 0} title={s.enrolledDevices > 0 ? (t('apple.integrations.ade.deleteBlocked') || 'Devices enrolled from this server are still managed') : undefined}
                onClick={async () => {
                  if (await confirm({ message: t('apple.integrations.ade.confirmDelete', { name: s.label }) || `Delete the ADE server ${s.label}?`, danger: true })) {
                    await run(s.id, () => integrationsApi.deleteAdeServer(s.id));
                  }
                }}><Trash2 className="w-4 h-4 mr-1" />{t('common.delete') || 'Delete'}</Button>
            </div>
          </li>
        ))}
      </ul>
      {adding && <AddAdeModal onClose={() => setAdding(false)} onAdd={(label, hint) => run('new', async () => {
        await integrationsApi.createAdeServer({ label, appleAccountHint: hint || null });
        setAdding(false);
      }, t('apple.integrations.ade.added') || 'Server added: upload its public key into Apple Business')} />}
    </Card>
  );
}

function AddAdeModal({ onClose, onAdd }: { onClose: () => void; onAdd: (label: string, hint: string) => void }) {
  const { t } = useTranslation();
  const [label, setLabel] = useState('');
  const [hint, setHint] = useState('');
  return (
    <Modal open onClose={onClose} title={t('apple.integrations.ade.addTitle') || 'New ADE server'}
      footer={<Button size="sm" disabled={!label.trim()} onClick={() => onAdd(label.trim(), hint.trim())}>{t('apple.integrations.ade.add') || 'Add a server'}</Button>}>
      <div className="space-y-3 text-sm">
        <label className="block">{t('apple.integrations.ade.labelLabel') || 'Name (as in Apple Business)'}
          <input className={fieldCls} maxLength={100} value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="block">{t('apple.integrations.ade.accountLabel') || 'Apple account of the client in Apple Business (a hint, never a password)'}
          <input className={fieldCls} maxLength={200} value={hint} onChange={(e) => setHint(e.target.value)} placeholder="it-admin@example.net" />
        </label>
      </div>
    </Modal>
  );
}

// ── Apps and Books (§11.3, lot C4) ──────────────────────────────────────────────

const VPP_TONE: Record<VppTokenState, 'green' | 'gray' | 'amber' | 'red'> = {
  active: 'green', foreign_mdm: 'amber', expired: 'red', invalid: 'red', removed: 'gray',
};

function VppCard({ s, onChange }: { s: IntegrationsSummary; onChange: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [rows, setRows] = useState<VppTokenView[] | null>(null);
  const [ops, setOps] = useState<VppOperationListItem[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [takeover, setTakeover] = useState<VppTokenView | null>(null);
  const load = useCallback(() => {
    integrationsApi.vppTokens().then(setRows).catch(errorToast);
    integrationsApi.vppOperations().then((o) => setOps(o.slice(0, 10))).catch(() => setOps([]));
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => { load(); }), [load]);
  const run = async (id: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(id);
    try {
      const r = await fn();
      if (isPendingApproval(r)) toast.success(t('apple.integrations.vpp.takeoverPending') || 'A second approver must approve the takeover');
      else if (done) toast.success(done);
      load();
      onChange();
    } catch (err) { errorToast(err); } finally { setBusy(null); }
  };
  return (
    <Card title={t('apple.integrations.vpp.title') || 'Apps and Books'} icon={<KeyRound className="w-5 h-5 text-accent" />} state={s.vpp.state}
      action={<Button size="sm" onClick={() => setAdding(true)}><Plus className="w-4 h-4 mr-1" />{t('apple.integrations.vpp.add') || 'Connect a content token'}</Button>}>
      <p className="text-xs text-text-muted">
        {t('apple.integrations.vpp.help') || 'In Apple Business (Preferences, Payments and Billing), download the content token (.vpptoken) of the location whose apps this tenant installs, and import it here. The token is kept encrypted by the console; the licences are synchronised every hour.'}{' '}
        <a href={APPLE_BUSINESS_PORTAL} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">{t('apple.integrations.ade.openPortal') || 'Open Apple Business'}</a>
      </p>
      {rows && rows.length === 0 && <p className="text-sm text-text-muted">{t('apple.integrations.vpp.noneYet') || 'No content token yet.'}</p>}
      <ul className="space-y-2">
        {rows?.map((v) => (
          <li key={v.id} className="rounded border border-border p-3 text-sm space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-text-primary">{v.label}</span>
              {v.locationName && <span className="text-text-muted">({v.locationName})</span>}
              <StateBadge tone={VPP_TONE[v.state]} label={trCode(`apple.integrations.vpp.state.${v.state}`, v.state)} />
            </div>
            <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-4 text-xs">
              <div><dt className="text-text-muted">{t('apple.integrations.vpp.expires') || 'Token expires'}</dt><dd>{dateOf(v.expDate)}</dd></div>
              <div><dt className="text-text-muted">{t('apple.integrations.vpp.lastSync') || 'Last synchronisation'}</dt><dd>{dateOf(v.lastSyncAt)}</dd></div>
              <div><dt className="text-text-muted">{t('apple.integrations.vpp.licences') || 'Licences'}</dt>
                <dd>{t('apple.integrations.vpp.assetsCount', { count: v.assets }) || `${v.assets} app(s)`}{v.pendingOperations > 0 ? ` · ${t('apple.integrations.vpp.pendingOps', { count: v.pendingOperations }) || `${v.pendingOperations} operation(s) in progress`}` : ''}</dd></div>
              <div><dt className="text-text-muted">{t('apple.integrations.vpp.notifications') || 'Notifications of Apple'}</dt>
                <dd>{v.testNotificationAt ? (t('apple.integrations.vpp.notificationsOk') || 'Received') : (t('apple.integrations.vpp.notificationsNone') || 'Not received yet')}</dd></div>
            </dl>
            {v.state === 'foreign_mdm' && (
              <p className="text-xs text-amber-500">{t('apple.integrations.vpp.foreignHelp') || 'Another MDM uses this content token. Taking it over moves the management of the licences of this location here: that MDM can no longer install them.'}</p>
            )}
            {v.state === 'invalid' && <p className="text-xs text-status-down">{t('apple.integrations.vpp.invalidHelp') || 'Apple no longer accepts this content token: download a new one from Apple Business and replace it.'}</p>}
            {v.state === 'expired' && <p className="text-xs text-status-down">{t('apple.integrations.vpp.expiredHelp') || 'This content token is expired: download a new one from Apple Business and replace it.'}</p>}
            {v.lastErrorCode && v.state === 'active' && v.consecutiveErrors > 0 && (
              <p className="text-xs text-status-down">{t('apple.integrations.vpp.lastError', { code: v.lastErrorCode }) || `Last error: ${v.lastErrorCode}`}</p>
            )}
            <div className="flex flex-wrap gap-2">
              {v.state === 'foreign_mdm' && (
                <Button size="sm" disabled={busy === v.id} onClick={() => setTakeover(v)}>{t('apple.integrations.vpp.takeover') || 'Take over the token'}</Button>
              )}
              {v.state === 'active' && (
                <Button size="sm" variant="ghost" disabled={busy === v.id} onClick={() => run(v.id, () => integrationsApi.syncVppToken(v.id), t('apple.integrations.vpp.syncRequested') || 'Synchronisation requested')}>
                  <RefreshCw className="w-4 h-4 mr-1" />{t('apple.integrations.vpp.sync') || 'Synchronise now'}</Button>
              )}
              <FilePicker label={t('apple.integrations.vpp.replace') || 'Replace the token'} accept=".vpptoken" disabled={busy === v.id}
                onFile={(b) => run(v.id, () => integrationsApi.replaceVppToken(v.id, b), t('apple.integrations.vpp.replaced') || 'Content token replaced')} />
              <Button size="sm" variant="ghost" disabled={busy === v.id}
                onClick={async () => {
                  if (await confirm({ message: t('apple.integrations.vpp.confirmRemove', { name: v.label }) || `Remove the content token ${v.label}? Its licences are no longer managed by this tenant.`, danger: true })) {
                    await run(v.id, () => integrationsApi.removeVppToken(v.id), t('apple.integrations.vpp.removed') || 'Content token removed');
                  }
                }}><Trash2 className="w-4 h-4 mr-1" />{t('common.delete') || 'Delete'}</Button>
            </div>
          </li>
        ))}
      </ul>
      {ops.length > 0 && (
        <div className="space-y-1">
          <h3 className="text-xs font-semibold text-text-secondary">{t('apple.integrations.vpp.operations') || 'Recent licence operations'}</h3>
          <ul className="divide-y divide-border/50 rounded border border-border text-xs">
            {ops.map((o) => (
              <li key={o.id} className="flex flex-wrap items-center gap-2 px-2 py-1.5">
                <span className="text-text-primary">{trCode(`apple.integrations.vpp.kind.${o.kind}`, o.kind)}</span>
                <span className="text-text-muted">{t('apple.integrations.vpp.opTargets', { assets: o.assets, targets: o.serialNumbers + o.clientUserIds }) || `${o.assets} app(s), ${o.serialNumbers + o.clientUserIds} target(s)`}</span>
                <StateBadge tone={o.state === 'complete' ? 'green' : o.state === 'failed' ? 'red' : o.state === 'abandoned' ? 'gray' : 'blue'}
                  label={trCode(`apple.integrations.vpp.opState.${o.state}`, o.state)} />
                <span className="ml-auto text-text-muted">{dateOf(o.completedAt ?? o.createdAt)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {adding && <AddVppModal onClose={() => setAdding(false)} onAdd={(label, hint, file) => run('new', async () => {
        const r = await integrationsApi.importVppToken(label, file, hint || null);
        setAdding(false);
        if (r.outcome === 'foreign_mdm') toast(t('apple.integrations.vpp.importedForeign') || 'Content token connected, but another MDM uses it: take it over to manage its licences here.', { duration: 9000 });
      }, t('apple.integrations.vpp.imported') || 'Content token connected')} />}
      {takeover && <TakeoverModal token={takeover} onClose={() => setTakeover(null)} onConfirm={() => run(takeover.id, async () => {
        const r = await integrationsApi.takeOverVppToken(takeover.id);
        setTakeover(null);
        return r;
      }, t('apple.integrations.vpp.takenOver') || 'Content token taken over')} />}
    </Card>
  );
}

function AddVppModal({ onClose, onAdd }: { onClose: () => void; onAdd: (label: string, hint: string, file: ArrayBuffer) => void }) {
  const { t } = useTranslation();
  const [label, setLabel] = useState('');
  const [hint, setHint] = useState('');
  const [file, setFile] = useState<ArrayBuffer | null>(null);
  return (
    <Modal open onClose={onClose} title={t('apple.integrations.vpp.addTitle') || 'Connect a content token'}
      footer={<Button size="sm" disabled={!label.trim() || !file} onClick={() => onAdd(label.trim(), hint.trim(), file!)}>{t('apple.integrations.vpp.add') || 'Connect a content token'}</Button>}>
      <div className="space-y-3 text-sm">
        <label className="block">{t('apple.integrations.vpp.labelLabel') || 'Name (the location in Apple Business)'}
          <input className={fieldCls} maxLength={100} value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="block">{t('apple.integrations.ade.accountLabel') || 'Apple account of the client in Apple Business (a hint, never a password)'}
          <input className={fieldCls} maxLength={200} value={hint} onChange={(e) => setHint(e.target.value)} placeholder="it-admin@example.net" />
        </label>
        <div className="flex items-center gap-2">
          <FilePicker label={t('apple.integrations.vpp.chooseFile') || 'Choose the .vpptoken file'} accept=".vpptoken" onFile={setFile} />
          {file && <span className="text-xs text-text-muted">{t('apple.integrations.vpp.fileChosen') || 'File chosen'}</span>}
        </div>
      </div>
    </Modal>
  );
}

/** The takeover of a token another MDM uses (decision of 15/10): a warning to acknowledge, then the second factor
 *  (asked by the console when the server requires it) or a second approver. */
function TakeoverModal({ token, onClose, onConfirm }: { token: VppTokenView; onClose: () => void; onConfirm: () => void }) {
  const { t } = useTranslation();
  const [ack, setAck] = useState(false);
  return (
    <Modal open onClose={onClose} title={t('apple.integrations.vpp.takeoverTitle') || 'Take over a content token'}
      footer={<Button size="sm" variant="danger" disabled={!ack} onClick={onConfirm}>{t('apple.integrations.vpp.takeover') || 'Take over the token'}</Button>}>
      <div className="space-y-3 text-sm">
        <p className="text-amber-500">
          {t('apple.integrations.vpp.takeoverWarning', { name: token.label }) || `The content token ${token.label} is used by another MDM. Taking it over writes this console as its MDM at Apple: the other MDM can no longer assign nor reclaim the licences of this location, and the apps it installed may stop updating. Do it only if that MDM is being replaced.`}
        </p>
        <p className="text-text-muted">{t('apple.integrations.vpp.takeoverGuard') || 'Your second factor is asked (or a second approver, depending on the restrictions of the tenant); the takeover is written in the audit log as a critical action.'}</p>
        <label className="flex items-start gap-2">
          <input type="checkbox" className="mt-1" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>{t('apple.integrations.vpp.takeoverAck') || 'I understand that the other MDM loses the licences of this location.'}</span>
        </label>
      </div>
    </Modal>
  );
}

// ── Deadlines (INT-05) ──────────────────────────────────────────────────────────

const KIND_FALLBACK: Record<string, string> = {
  apns_certificate: 'Push certificate', ade_token: 'ADE server token', vpp_token: 'Content token', device_ca: 'Device CA',
  mdm_tls_certificate: 'TLS certificate', vendor_certificate: 'MDM Vendor certificate', mdm_domain: 'Domain name',
  profile_signing_identity: 'Profile signing identity', vault_escrow_test: 'Escrow test', vault_kek_rotation: 'Key rotation',
  vault_old_shares: 'Old escrow shares', vault_dek_destruction: 'Data key destruction',
};

function DeadlinesCard({ state }: { state: IntegrationCardState }) {
  const { t } = useTranslation();
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const platform = isAdmin && isMasterTenant(currentTenantId);
  const [all, setAll] = useState(false);
  const [rows, setRows] = useState<DeadlineView[] | null>(null);
  const [editing, setEditing] = useState<ManualDeadlineKind | null>(null);
  const load = useCallback(() => {
    (all && platform ? integrationsApi.allDeadlines() : integrationsApi.deadlines()).then(setRows).catch(errorToast);
  }, [all, platform]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.INTEGRATION_CHANGED, () => { load(); }), [load]);
  return (
    <Card title={t('apple.integrations.deadlines.title') || 'Deadlines'} icon={<CircleDashed className="w-5 h-5 text-accent" />} state={state}
      action={platform && (
        <>
          <label className="flex items-center gap-2 text-xs text-text-muted">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
            {t('apple.integrations.deadlines.allTenants') || 'Every tenant and the instance'}
          </label>
          {MANUAL_DEADLINE_KINDS.map((k) => (
            <Button key={k} size="sm" variant="ghost" onClick={() => setEditing(k)}>{trCode(`apple.integrations.deadlines.kind.${k}`, KIND_FALLBACK[k])}</Button>
          ))}
        </>
      )}>
      {rows && rows.length === 0 && <p className="text-sm text-text-muted">{t('apple.integrations.deadlines.none') || 'No deadline yet.'}</p>}
      {rows && rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-text-muted">
              <tr>
                {all && platform && <th className="py-1">{t('apple.integrations.deadlines.tenant') || 'Tenant'}</th>}
                <th>{t('apple.integrations.deadlines.kindHeader') || 'Subject'}</th>
                <th>{t('apple.integrations.deadlines.label') || 'Label'}</th>
                <th>{t('apple.integrations.deadlines.notAfter') || 'Expires'}</th>
                <th>{t('apple.integrations.deadlines.daysLeft') || 'Days left'}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.id} className="border-t border-border">
                  {all && platform && <td className="py-1">{d.tenantId === null ? (t('apple.integrations.deadlines.instance') || 'Instance') : (d.tenantName ?? `#${d.tenantId}`)}</td>}
                  <td className="py-1">{trCode(`apple.integrations.deadlines.kind.${d.kind}`, KIND_FALLBACK[d.kind] ?? d.kind)}</td>
                  <td className="break-all">{d.label}</td>
                  <td>{dateOf(d.notAfter)}</td>
                  <td>{d.daysLeft ?? '—'}</td>
                  <td><StateBadge tone={LEVEL_TONE[d.level]} label={trCode(`apple.integrations.deadlines.level.${d.level}`, d.level)} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing && <ManualDeadlineModal kind={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load(); }} />}
    </Card>
  );
}

function ManualDeadlineModal({ kind, onClose, onSaved }: { kind: ManualDeadlineKind; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation();
  const [date, setDate] = useState('');
  const [label, setLabel] = useState('');
  const submit = async (clear: boolean) => {
    try {
      await integrationsApi.setManualDeadline(kind, { notAfter: clear ? null : new Date(`${date}T00:00:00Z`).toISOString(), ...(label.trim() ? { label: label.trim() } : {}) });
      toast.success(t('common.saved') || 'Saved');
      onSaved();
    } catch (err) { errorToast(err); }
  };
  return (
    <Modal open onClose={onClose} title={trCode(`apple.integrations.deadlines.kind.${kind}`, KIND_FALLBACK[kind])}
      footer={<div className="flex gap-2">
        <Button size="sm" variant="ghost" onClick={() => submit(true)}>{t('apple.integrations.deadlines.clear') || 'Remove'}</Button>
        <Button size="sm" disabled={!date} onClick={() => submit(false)}>{t('common.save') || 'Save'}</Button>
      </div>}>
      <div className="space-y-3 text-sm">
        <label className="block">{t('apple.integrations.deadlines.notAfter') || 'Expires'}
          <input type="date" className={fieldCls} value={date} onChange={(e) => setDate(e.target.value)} />
        </label>
        <label className="block">{t('apple.integrations.deadlines.label') || 'Label'}
          <input className={fieldCls} maxLength={200} value={label} onChange={(e) => setLabel(e.target.value)} />
        </label>
      </div>
    </Modal>
  );
}
