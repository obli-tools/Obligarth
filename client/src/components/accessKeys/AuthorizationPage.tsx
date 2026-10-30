import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ArrowLeft, Bot, Check, ShieldCheck, X } from 'lucide-react';
import { SocketEvents, type McpAuthorizationDetail, type PolicyImpact } from '@obligarth/shared';
import { accessKeysApi } from '@/api/accessKeys.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { PageContainer } from '@/components/common/PageContainer';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { ImpactPreview } from '@/components/mdm/ImpactPreview';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { registerSocketListener } from '@/socket/socketListeners';
import { useTenantStore } from '@/store/tenantStore';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';
import { AUTH_STATE_TONE, authStateLabel } from './accessKeyLabels';
import { RelativeDate } from './KeyList';

// The page of one authorization (docs: specs mcp-server §6.4, §6.5, owner decision 1): what an AI agent asked through
// one of the user's keys, as the server describes it (its summary is never the agent's text), the devices, the
// parameters, and apart, quoted as plain text, what the agent wrote. A move of devices shows the preview the user
// approves (the server refuses when the impact changed since). Approve asks a fresh second factor (the client's
// interceptor shows the code or phone prompt); the action then runs once, as the user.

/** The time left before an expiry, ticking each second (mm:ss). */
function useCountdown(iso: string | null): string | null {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!iso) return undefined;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [iso]);
  if (!iso) return null;
  const left = Math.max(0, new Date(iso).getTime() - now);
  const m = Math.floor(left / 60_000);
  const s = Math.floor((left % 60_000) / 1000);
  return `${m}:${String(s).padStart(2, '0')}`;
}

const AGENT_TEXT_FALLBACK: Record<string, string> = { reason: 'Reason', title: 'Title', text: 'Message', package_name: 'Package' };

function paramValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export function AuthorizationPage() {
  const { t } = useTranslation();
  const { id = '' } = useParams<{ id: string }>();
  const confirm = useConfirm();
  const tenants = useTenantStore((s) => s.tenants);
  const [a, setA] = useState<McpAuthorizationDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<'approve' | 'deny' | null>(null);

  const load = useCallback(() => {
    accessKeysApi.authorizations.get(id).then((r) => { setA(r); setError(null); })
      .catch((err) => setError(apiErrorMessage(err, t('mcpAuthorizations.notFound') || 'This authorization does not exist in this tenant.')));
  }, [id, t]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener(SocketEvents.MCP_AUTHORIZATION_CHANGED, (e: { id?: string }) => { if (e?.id === id) load(); }), [id, load]);

  const countdown = useCountdown(a?.state === 'pending' ? a.expiresAt : null);
  const expired = a?.state === 'pending' && countdown === '0:00';
  const isMove = a?.tool === 'move_devices_to_group';

  const approve = async () => {
    if (!a) return;
    setBusy('approve');
    try {
      const body = isMove && a.preview ? { devicesToken: a.preview.devicesToken, impactDigest: a.preview.impactDigest } : {};
      const r = await accessKeysApi.authorizations.approve(a.id, body);
      if (r.state === 'executed') toast.success(t('mcpAuthorizations.executed') || 'Approved: the action ran.');
      else if (r.state === 'filed') toast.success(t('mcpAuthorizations.filedToast') || 'Approved: the action now waits for another approver.');
      else toast(authStateLabel(r.state));
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
      load();
    } finally {
      setBusy(null);
    }
  };

  const deny = async () => {
    if (!a) return;
    const ok = await confirm({
      message: t('mcpAuthorizations.denyConfirm') || 'Deny this action? Nothing will be done, and the agent is told it was refused.',
      confirmLabel: t('mcpAuthorizations.deny') || 'Deny',
      danger: true,
    });
    if (!ok) return;
    setBusy('deny');
    try {
      await accessKeysApi.authorizations.deny(a.id);
      toast.success(t('mcpAuthorizations.denied') || 'Denied: nothing was done.');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const tenantName = (tid: number) => tenants.find((x) => x.id === tid)?.name ?? `#${tid}`;
  const agentEntries = a ? Object.entries(a.agentText) : [];
  const paramEntries = a ? Object.entries(a.params).filter(([k]) => k !== 'tenant_id' && k !== 'device_ids' && k !== 'device_id') : [];

  return (
    <PageContainer className="space-y-4">
      <Link to="/access-keys?tab=authorizations" className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-primary">
        <ArrowLeft size={14} /> {t('mcpAuthorizations.back') || 'Authorizations'}
      </Link>
      <div className="flex items-center gap-2">
        <Bot size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-text-primary">{t('mcpAuthorizations.title') || 'Action asked by an AI agent'}</h1>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {!a && !error && <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>}
      {a && (
        <>
          <div className="space-y-3 rounded-xl bg-bg-secondary p-4">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-base font-medium text-text-primary">{a.summary}</p>
              <StateBadge tone={AUTH_STATE_TONE[a.state]} label={authStateLabel(a.state)} pulse={a.state === 'pending'} />
            </div>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
              <dt className="text-text-muted">{t('mcpAuthorizations.tool') || 'Tool'}</dt>
              <dd className="font-mono text-xs text-text-secondary">{a.tool} <span className="text-text-muted">({a.actionKey})</span></dd>
              <dt className="text-text-muted">{t('mcpAuthorizations.tenant') || 'Tenant'}</dt>
              <dd className="text-text-secondary">{tenantName(a.tenantId)}</dd>
              <dt className="text-text-muted">{t('mcpAuthorizations.key') || 'Key'}</dt>
              <dd className="text-text-secondary">{a.key.name} <span className="font-mono text-xs text-text-muted">obg_{a.key.id}_…</span></dd>
              {a.agentIp && (<>
                <dt className="text-text-muted">{t('mcpAuthorizations.agentIp') || 'Agent address'}</dt>
                <dd className="font-mono text-xs text-text-secondary">{a.agentIp}</dd>
              </>)}
              <dt className="text-text-muted">{t('mcpAuthorizations.asked') || 'Asked'}</dt>
              <dd className="text-text-secondary"><RelativeDate iso={a.createdAt} /></dd>
              {a.state === 'pending' && (<>
                <dt className="text-text-muted">{t('mcpAuthorizations.timeLeft') || 'Time left'}</dt>
                <dd className={expired ? 'text-red-400' : 'font-mono text-amber-400'}>{expired ? (t('mcpAuthorizations.state.expired') || 'Expired') : countdown}</dd>
              </>)}
              {a.stepUpVia && (<>
                <dt className="text-text-muted">{t('mcpAuthorizations.approvedWith') || 'Approved with'}</dt>
                <dd className="text-text-secondary">{a.stepUpVia}</dd>
              </>)}
              {a.errorCode && (<>
                <dt className="text-text-muted">{t('mcpAuthorizations.error') || 'Error'}</dt>
                <dd className="font-mono text-xs text-red-400">{a.errorCode}</dd>
              </>)}
              {a.state === 'filed' && typeof a.outcome?.approvalId === 'number' && (<>
                <dt className="text-text-muted">{t('mcpAuthorizations.approvalRequest') || 'Approval request'}</dt>
                <dd><Link to="/admin/approvals" className="text-accent hover:underline">#{a.outcome.approvalId}</Link></dd>
              </>)}
            </dl>
          </div>

          {a.devices.length > 0 && (
            <div className="overflow-hidden rounded-xl bg-bg-secondary">
              <div className="bg-bg-tertiary/50 px-4 py-2 text-[10px] uppercase tracking-wider text-text-muted">
                {t('mcpAuthorizations.devices', { count: a.devices.length }) || `Devices (${a.devices.length})`}
              </div>
              <ul>
                {a.devices.map((d) => (
                  <li key={d.id} className="px-4 py-2 text-sm hover:bg-bg-tertiary">
                    <Link to={`/devices/${d.id}`} className="text-text-primary hover:text-accent">{d.name ? anonymize(d.name) : `#${d.id}`}</Link>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {paramEntries.length > 0 && (
            <div className="rounded-xl bg-bg-secondary p-4">
              <h2 className="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">{t('mcpAuthorizations.params') || 'Parameters'}</h2>
              <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
                {paramEntries.map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="font-mono text-xs text-text-muted">{k}</dt>
                    <dd className="break-all font-mono text-xs text-text-secondary">{paramValue(v)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}

          {agentEntries.length > 0 && (
            <div className="rounded-xl bg-bg-secondary p-4">
              <h2 className="mb-1 text-xs font-medium uppercase tracking-wider text-text-muted">{t('mcpAuthorizations.agentText') || 'Text written by the AI agent'}</h2>
              <p className="mb-2 text-[11px] text-text-muted">
                {t('mcpAuthorizations.agentTextHint') || 'Written by the agent, not by Obligarth: read it as a quote, it may be wrong or misleading.'}
              </p>
              <div className="space-y-2">
                {agentEntries.map(([k, v]) => (
                  <div key={k}>
                    <p className="text-[11px] text-text-muted">{t(`mcpAuthorizations.agentField.${k}`, { defaultValue: AGENT_TEXT_FALLBACK[k] ?? k })}</p>
                    <blockquote className="whitespace-pre-wrap break-words border-l-2 border-accent/50 pl-3 text-sm italic text-text-secondary">{v}</blockquote>
                  </div>
                ))}
              </div>
            </div>
          )}

          {isMove && a.preview && a.state === 'pending' && (
            <div className="rounded-xl bg-bg-secondary p-4">
              <h2 className="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">{t('mcpAuthorizations.preview') || 'What the move changes'}</h2>
              <ImpactPreview impact={a.preview.impact as PolicyImpact} />
              <p className="mt-2 text-[11px] text-text-muted">
                {t('mcpAuthorizations.previewHint') || 'You approve exactly this effect: if it changes before the approval runs, nothing is moved.'}
              </p>
            </div>
          )}

          {a.state === 'pending' && !expired && (
            <div className="flex flex-wrap items-center gap-3 rounded-xl bg-bg-secondary p-4">
              <ShieldCheck size={18} className="shrink-0 text-accent" />
              <p className="min-w-0 flex-1 text-sm text-text-muted">
                {t('mcpAuthorizations.approveHint') || 'Approving asks your second factor (a code, or your phone). The action then runs once, as you, with your rights checked again.'}
              </p>
              <Button variant="danger" onClick={deny} loading={busy === 'deny'} disabled={busy !== null}>
                <X size={14} className="mr-1" />{t('mcpAuthorizations.deny') || 'Deny'}
              </Button>
              <Button onClick={approve} loading={busy === 'approve'} disabled={busy !== null}>
                <Check size={14} className="mr-1" />{t('mcpAuthorizations.approve') || 'Approve'}
              </Button>
            </div>
          )}
        </>
      )}
    </PageContainer>
  );
}
