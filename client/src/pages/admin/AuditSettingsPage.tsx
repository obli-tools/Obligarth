import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Archive, Clock, KeyRound, Lock, RefreshCw, Send, Server, ShieldCheck, Trash2 } from 'lucide-react';
import toast from 'react-hot-toast';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import {
  AUDIT_RETENTION_MAX_MONTHS, AUDIT_RETENTION_MIN_MONTHS,
  type AuditDestinationDto, type AuditRetentionRow, type AuditSealKeyDto, type AuditSealingStatus, type AuditSpoolStatus,
} from '@obligarth/shared';
import { auditAdminApi } from '@/api/audit.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { errorText, when } from '@/components/audit/auditLabels';
import { useTenantStore } from '@/store/tenantStore';

// Settings of the hardened journal (platform administrators, master tenant):
// retention per tenant (12 months by default, 6 to 36 with a justification,
// a decrease applied after 30 days, legal holds), SIEM destinations (syslog
// over TLS, signed webhook), sealing (last seal, time stamping authority,
// signing keys) and the local spool. Every change that weakens the journal
// goes through a second administrator's approval; secrets never come back
// (a webhook's HMAC secret is shown once, at its creation or rotation).

function Section({ icon, title, children, extra }: { icon: ReactNode; title: string; children: ReactNode; extra?: ReactNode }) {
  return (
    <section className="rounded bg-bg-secondary p-4 mb-4">
      <div className="flex items-center justify-between gap-2 mb-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-text-primary">{icon}{title}</h2>
        {extra}
      </div>
      {children}
    </section>
  );
}

function approvalOr(t: TFunction, r: { approvalId?: number; status?: string } | unknown, done: string): void {
  const x = r as { approvalId?: number; status?: string } | undefined;
  if (x?.approvalId || x?.status === 'pending_approval') {
    toast.success(t('auditSettings.approvalFiled') || 'Request filed: another platform administrator must approve it');
  } else {
    toast.success(done);
  }
}

export function AuditSettingsPage() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const { tenants } = useTenantStore();
  const [retention, setRetention] = useState<AuditRetentionRow[]>([]);
  const [destinations, setDestinations] = useState<AuditDestinationDto[]>([]);
  const [sealing, setSealing] = useState<AuditSealingStatus | null>(null);
  const [keys, setKeys] = useState<AuditSealKeyDto[]>([]);
  const [spool, setSpool] = useState<AuditSpoolStatus | null>(null);
  const [editRetention, setEditRetention] = useState<AuditRetentionRow | null>(null);
  const [editHold, setEditHold] = useState<AuditRetentionRow | null>(null);
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [r, d, s, k, sp] = await Promise.allSettled([
      auditAdminApi.retention(), auditAdminApi.destinations(), auditAdminApi.sealing(), auditAdminApi.sealKeys(), auditAdminApi.spool(),
    ]);
    if (r.status === 'fulfilled') setRetention(r.value);
    if (d.status === 'fulfilled') setDestinations(d.value);
    if (s.status === 'fulfilled') setSealing(s.value);
    if (k.status === 'fulfilled') setKeys(k.value);
    if (sp.status === 'fulfilled') setSpool(sp.value);
    const failed = [r, d, s, k, sp].find((x) => x.status === 'rejected') as PromiseRejectedResult | undefined;
    if (failed) toast.error(errorText(failed.reason, t('auditSettings.loadFailed') || 'Could not load the journal settings'));
  }, [t]);

  useEffect(() => { load(); }, [load]);

  const tenantName = (id: number | null) => (id === null ? (t('auditSettings.allTenants') || 'Every tenant') : (tenants.find((x) => x.id === id)?.name ?? `#${id}`));

  const sealNow = async () => {
    try {
      await auditAdminApi.sealNow();
      toast.success(t('auditSettings.sealQueued') || 'Seal requested');
      setTimeout(() => { load(); }, 2000);
    } catch (err) {
      toast.error(errorText(err, t('auditSettings.sealFailed') || 'Seal not requested'));
    }
  };

  const rotateKey = async () => {
    if (!(await confirm({
      title: t('auditSettings.rotateKeyTitle') || 'Rotate the seal key',
      message: t('auditSettings.rotateKeyConfirm') || 'A new key signs the next seals; the old one stays published to verify the past ones. Another platform administrator must approve.',
      confirmLabel: t('auditSettings.rotateKey') || 'Rotate',
    }))) return;
    try {
      approvalOr(t, await auditAdminApi.rotateSealKey(), t('auditSettings.keyRotated') || 'Key rotated');
      load();
    } catch (err) {
      toast.error(errorText(err, t('auditSettings.rotateKeyFailed') || 'Rotation not requested'));
    }
  };

  const testDestination = async (d: AuditDestinationDto) => {
    try {
      const r = await auditAdminApi.testDestination(d.id);
      if (r.delivered) toast.success(t('auditSettings.testDelivered') || 'Test message delivered');
      else toast.error(`${t('auditSettings.testFailed') || 'Test message not delivered'} (${r.code ?? '?'})`);
    } catch (err) {
      toast.error(errorText(err, t('auditSettings.testFailed') || 'Test message not delivered'));
    }
  };

  const toggleDestination = async (d: AuditDestinationDto) => {
    try {
      const r = await auditAdminApi.updateDestination(d.id, { enabled: !d.enabled });
      approvalOr(t, r, d.enabled ? (t('auditSettings.disabled') || 'Destination disabled') : (t('auditSettings.enabled') || 'Destination enabled'));
      load();
    } catch (err) {
      toast.error(errorText(err, t('common.error') || 'Error'));
    }
  };

  const deleteDestination = async (d: AuditDestinationDto) => {
    if (!(await confirm({
      title: t('auditSettings.deleteTitle') || 'Delete the destination',
      message: t('auditSettings.deleteConfirm', { name: d.name }) || `Stop sending the journal to "${d.name}"? Another platform administrator must approve.`,
      danger: true,
      confirmLabel: t('common.delete') || 'Delete',
    }))) return;
    try {
      approvalOr(t, await auditAdminApi.deleteDestination(d.id), t('auditSettings.deleted') || 'Destination deleted');
      load();
    } catch (err) {
      toast.error(errorText(err, t('common.error') || 'Error'));
    }
  };

  const rotateSecret = async (d: AuditDestinationDto) => {
    if (!(await confirm({
      title: t('auditSettings.rotateSecretTitle') || 'New signing secret',
      message: t('auditSettings.rotateSecretConfirm') || 'The receiver must be given the new secret: until then it refuses the deliveries.',
      confirmLabel: t('auditSettings.rotateSecret') || 'New secret',
    }))) return;
    try {
      const r = await auditAdminApi.rotateDestinationSecret(d.id);
      setSecret(r.hmacSecret);
    } catch (err) {
      toast.error(errorText(err, t('common.error') || 'Error'));
    }
  };

  const th = 'px-2 py-1.5 text-left text-[10px] uppercase text-text-muted font-medium';
  const td = 'px-2 py-1.5 text-xs text-text-primary';

  return (
    <div>
      <div className="flex justify-end mb-2">
        <Button variant="ghost" size="sm" onClick={() => load()}><RefreshCw className="w-3.5 h-3.5 mr-1.5" />{t('common.refresh') || 'Refresh'}</Button>
      </div>

      <Section icon={<ShieldCheck className="w-4 h-4 text-accent" />} title={t('auditSettings.sealing') || 'Sealing'}
        extra={(
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" onClick={sealNow}>{t('auditSettings.sealNow') || 'Seal now'}</Button>
            <Button variant="secondary" size="sm" onClick={rotateKey}><KeyRound className="w-3.5 h-3.5 mr-1.5" />{t('auditSettings.rotateKey') || 'Rotate the key'}</Button>
          </div>
        )}>
        <div className="grid gap-1 text-xs sm:grid-cols-2">
          <div><span className="text-text-muted">{t('auditSettings.lastSeal') || 'Last seal'}: </span>
            {sealing?.lastSeal ? `#${sealing.lastSeal.seq} · ${when(sealing.lastSeal.sealedAt)} · ${t('auditSettings.leaves', { count: sealing.lastSeal.leaves }) || `${sealing.lastSeal.leaves} chains`}` : '—'}
          </div>
          <div><span className="text-text-muted">{t('auditSettings.tsa') || 'Time stamping authority'}: </span>
            {sealing?.tsaConfigured
              ? (sealing.lastSeal?.tsaStatus === 'failed' ? (t('auditSettings.tsaFailing') || 'configured, last stamp failed') : (t('auditSettings.tsaOn') || 'configured'))
              : (t('auditSettings.tsaOff') || 'not configured')}
          </div>
          <div className="min-w-0 break-all"><span className="text-text-muted">{t('auditSettings.activeKey') || 'Signing key'}: </span><span className="font-mono text-[11px]">{sealing?.activeKeyId ?? '—'}</span></div>
          <div className="min-w-0 break-all"><span className="text-text-muted">{t('auditSettings.instance') || 'Instance'}: </span><span className="font-mono text-[11px]">{sealing?.instanceId ?? '—'}</span></div>
        </div>
        {keys.length > 0 && (
          <table className="w-full mt-3 border-collapse">
            <thead><tr><th className={th}>{t('auditSettings.keyId') || 'Key'}</th><th className={th}>{t('auditSettings.createdAt') || 'Created'}</th><th className={th}>{t('auditSettings.retiredAt') || 'Retired'}</th></tr></thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.keyId}>
                  <td className={`${td} font-mono text-[11px] break-all`}>{k.keyId}</td>
                  <td className={td}>{when(k.createdAt)}</td>
                  <td className={td}>{k.retiredAt ? when(k.retiredAt) : (t('auditSettings.active') || 'active')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section icon={<Clock className="w-4 h-4 text-accent" />} title={t('auditSettings.retention') || 'Retention'}>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse min-w-[640px]">
            <thead>
              <tr>
                <th className={th}>{t('auditSettings.tenant') || 'Tenant'}</th>
                <th className={th}>{t('auditSettings.months') || 'Months'}</th>
                <th className={th}>{t('auditSettings.pending') || 'Pending'}</th>
                <th className={th}>{t('auditSettings.legalHold') || 'Legal hold'}</th>
                <th className={th}>{t('auditSettings.chain') || 'Chain'}</th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {retention.map((r) => (
                <tr key={r.tenantId}>
                  <td className={td}>{r.tenantName ?? `#${r.tenantId}`}{!r.tenantExists && <span className="ml-1 text-[10px] text-text-muted">({t('auditSettings.deletedTenant') || 'deleted'})</span>}</td>
                  <td className={td} title={r.justification ?? ''}>{r.effectiveMonths}</td>
                  <td className={td}>{r.pendingMonths !== null ? `${r.pendingMonths} · ${when(r.pendingEffectiveAt)}` : '—'}</td>
                  <td className={td}>{r.legalHoldUntil ? <span className="inline-flex items-center gap-1 text-accent"><Lock className="w-3 h-3" />{when(r.legalHoldUntil)}</span> : '—'}</td>
                  <td className={`${td} text-text-muted`}>{r.anchorSeq > 0 ? `${r.anchorSeq + 1}…${r.headSeq}` : `1…${r.headSeq}`}</td>
                  <td className={`${td} whitespace-nowrap text-right`}>
                    {r.tenantExists && (
                      <>
                        <button className="text-accent hover:underline mr-3" onClick={() => setEditRetention(r)}>{t('auditSettings.change') || 'Change'}</button>
                        <button className="text-accent hover:underline" onClick={() => setEditHold(r)}>{t('auditSettings.hold') || 'Legal hold'}</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section icon={<Server className="w-4 h-4 text-accent" />} title={t('auditSettings.destinations') || 'SIEM destinations'}
        extra={<Button variant="secondary" size="sm" onClick={() => setCreating(true)}>{t('auditSettings.addDestination') || 'Add a destination'}</Button>}>
        {destinations.length === 0 ? (
          <p className="text-xs text-yellow-400">{t('auditSettings.noDestination') || 'No destination: the journal is copied nowhere outside the database. Production needs one.'}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse min-w-[720px]">
              <thead>
                <tr>
                  <th className={th}>{t('auditSettings.name') || 'Name'}</th>
                  <th className={th}>{t('auditSettings.kind') || 'Kind'}</th>
                  <th className={th}>{t('auditSettings.scope') || 'Scope'}</th>
                  <th className={th}>{t('auditSettings.state') || 'State'}</th>
                  <th className={th}>{t('auditSettings.lag') || 'Lag'}</th>
                  <th className={th} />
                </tr>
              </thead>
              <tbody>
                {destinations.map((d) => (
                  <tr key={d.id}>
                    <td className={td}>{d.name}{d.requiredForPurge && <span className="ml-1 text-[10px] text-text-muted">({t('auditSettings.requiredForPurge') || 'required for the purge'})</span>}</td>
                    <td className={td}>{d.kind === 'webhook' ? 'Webhook' : 'Syslog TLS'}</td>
                    <td className={td}>{tenantName(d.scopeTenantId)}</td>
                    <td className={td}>
                      {!d.enabled ? <span className="text-text-muted">{t('auditSettings.off') || 'disabled'}</span>
                        : d.lastErrorAt && (!d.lastSuccessAt || d.lastErrorAt > d.lastSuccessAt)
                          ? <span className="text-red-400" title={when(d.lastErrorAt)}>{t('auditSettings.failing') || 'failing'} ({d.lastErrorCode})</span>
                          : <span className="text-green-400" title={when(d.lastSuccessAt)}>{t('auditSettings.ok') || 'delivering'}</span>}
                    </td>
                    <td className={td}>{d.lagSeconds === null ? '—' : d.lagSeconds < 60 ? `${d.lagSeconds} s` : `${Math.round(d.lagSeconds / 60)} min`}</td>
                    <td className={`${td} whitespace-nowrap text-right`}>
                      <button className="text-accent hover:underline mr-3" onClick={() => testDestination(d)}><Send className="inline w-3 h-3 mr-0.5" />{t('auditSettings.test') || 'Test'}</button>
                      <button className="text-accent hover:underline mr-3" onClick={() => toggleDestination(d)}>{d.enabled ? (t('common.disable') || 'Disable') : (t('common.enable') || 'Enable')}</button>
                      {d.kind === 'webhook' && <button className="text-accent hover:underline mr-3" onClick={() => rotateSecret(d)}>{t('auditSettings.rotateSecret') || 'New secret'}</button>}
                      <button className="text-red-400 hover:underline" onClick={() => deleteDestination(d)} aria-label={t('common.delete') || 'Delete'}><Trash2 className="inline w-3 h-3" /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section icon={<Archive className="w-4 h-4 text-accent" />} title={t('auditSettings.spool') || 'Local spool'}>
        <p className="text-xs text-text-secondary">
          {spool && spool.entries > 0
            ? (t('auditSettings.spoolWaiting', { count: spool.entries, at: when(spool.oldestSpooledAt) }) || `${spool.entries} entries wait to be replayed (oldest ${when(spool.oldestSpooledAt)})`)
            : (t('auditSettings.spoolEmpty') || 'Empty: every entry reached the journal.')}
          {spool && spool.rejected > 0 && (
            <span className="ml-2 text-red-400">{t('auditSettings.spoolRejected', { count: spool.rejected }) || `${spool.rejected} refused (see the procedures)`}</span>
          )}
        </p>
      </Section>

      {editRetention && <RetentionModal row={editRetention} onClose={() => setEditRetention(null)} onDone={() => { setEditRetention(null); load(); }} />}
      {editHold && <LegalHoldModal row={editHold} onClose={() => setEditHold(null)} onDone={() => { setEditHold(null); load(); }} />}
      {creating && (
        <DestinationModal
          onClose={() => setCreating(false)}
          onCreated={(hmacSecret) => { setCreating(false); if (hmacSecret) setSecret(hmacSecret); load(); }}
        />
      )}
      <Modal open={secret !== null} onClose={() => setSecret(null)} title={t('auditSettings.secretTitle') || 'Signing secret of the webhook'} size="md">
        <div className="p-4 space-y-3 text-sm">
          <p className="text-text-secondary">{t('auditSettings.secretOnce') || 'Shown once: give it to the receiver, which checks the X-Obligarth-Signature header with it.'}</p>
          <pre className="font-mono text-xs break-all whitespace-pre-wrap rounded bg-bg-tertiary p-2 select-all">{secret}</pre>
        </div>
      </Modal>
    </div>
  );
}

function RetentionModal({ row, onClose, onDone }: { row: AuditRetentionRow; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [months, setMonths] = useState(String(row.months));
  const [justification, setJustification] = useState(row.justification ?? '');
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await auditAdminApi.setRetention(row.tenantId, Number(months), justification.trim() || null);
      approvalOr(t, r, t('auditSettings.retentionSaved') || 'Retention changed');
      onDone();
    } catch (err) {
      toast.error(errorText(err, t('auditSettings.retentionFailed') || 'Retention not changed'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open onClose={onClose} title={`${t('auditSettings.retention') || 'Retention'} · ${row.tenantName ?? `#${row.tenantId}`}`} size="md">
      <form onSubmit={submit} className="p-4 space-y-3">
        <Input label={t('auditSettings.monthsLabel', { min: AUDIT_RETENTION_MIN_MONTHS, max: AUDIT_RETENTION_MAX_MONTHS }) || `Months (${AUDIT_RETENTION_MIN_MONTHS} to ${AUDIT_RETENTION_MAX_MONTHS})`}
          type="number" min={AUDIT_RETENTION_MIN_MONTHS} max={AUDIT_RETENTION_MAX_MONTHS} value={months} onChange={(e) => setMonths(e.target.value)} required />
        <Input label={t('auditSettings.justification') || 'Justification (required other than 12 months)'} value={justification} onChange={(e) => setJustification(e.target.value)} maxLength={1000} />
        <p className="text-xs text-text-muted">{t('auditSettings.retentionHint') || 'A decrease takes effect after 30 days; an increase at once. Another platform administrator approves.'}</p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button type="submit" loading={busy}>{t('auditSettings.request') || 'Request'}</Button>
        </div>
      </form>
    </Modal>
  );
}

function LegalHoldModal({ row, onClose, onDone }: { row: AuditRetentionRow; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [until, setUntil] = useState(row.legalHoldUntil ? row.legalHoldUntil.slice(0, 10) : '');
  const [reason, setReason] = useState(row.legalHoldReason ?? '');
  const [busy, setBusy] = useState(false);
  const save = async (lift: boolean) => {
    setBusy(true);
    try {
      const r = await auditAdminApi.setLegalHold(row.tenantId, lift || !until ? null : new Date(`${until}T23:59:59Z`).toISOString(), reason.trim() || null);
      approvalOr(t, r, lift ? (t('auditSettings.holdLifted') || 'Legal hold lifted') : (t('auditSettings.holdSet') || 'Legal hold set'));
      onDone();
    } catch (err) {
      toast.error(errorText(err, t('auditSettings.holdFailed') || 'Legal hold not changed'));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open onClose={onClose} title={`${t('auditSettings.legalHold') || 'Legal hold'} · ${row.tenantName ?? `#${row.tenantId}`}`} size="md">
      <form onSubmit={(e) => { e.preventDefault(); save(false); }} className="p-4 space-y-3">
        <Input label={t('auditSettings.holdUntil') || 'Until'} type="date" value={until} onChange={(e) => setUntil(e.target.value)} required />
        <Input label={t('auditSettings.holdReason') || 'Reason (10 characters at least)'} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} required minLength={10} />
        <p className="text-xs text-text-muted">{t('auditSettings.holdHint') || 'Setting or extending a hold asks for your second factor; lifting or shortening it, for another administrator\'s approval.'}</p>
        <div className="flex justify-between gap-2">
          {row.legalHoldUntil ? <Button type="button" variant="danger" onClick={() => save(true)} disabled={busy}>{t('auditSettings.liftHold') || 'Lift'}</Button> : <span />}
          <div className="flex gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
            <Button type="submit" loading={busy}>{t('common.save') || 'Save'}</Button>
          </div>
        </div>
      </form>
    </Modal>
  );
}

function DestinationModal({ onClose, onCreated }: { onClose: () => void; onCreated: (hmacSecret?: string) => void }) {
  const { t } = useTranslation();
  const { tenants } = useTenantStore();
  const [kind, setKind] = useState<'syslog_tls' | 'webhook'>('syslog_tls');
  const [name, setName] = useState('');
  const [scope, setScope] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('6514');
  const [caPem, setCaPem] = useState('');
  const [clientCertPem, setClientCertPem] = useState('');
  const [clientKeyPem, setClientKeyPem] = useState('');
  const [url, setUrl] = useState('');
  const [bearerToken, setBearerToken] = useState('');
  const [requiredForPurge, setRequiredForPurge] = useState(true);
  const [startFrom, setStartFrom] = useState<'beginning' | 'now'>('beginning');
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const config: Record<string, unknown> = kind === 'syslog_tls'
        ? { host: host.trim(), port: Number(port), ...(caPem.trim() ? { caPem: caPem.trim() } : {}), ...(clientCertPem.trim() ? { clientCertPem: clientCertPem.trim() } : {}) }
        : { url: url.trim(), ...(caPem.trim() ? { caPem: caPem.trim() } : {}) };
      const out = await auditAdminApi.createDestination({
        name: name.trim(), kind, scopeTenantId: scope ? Number(scope) : null, config, requiredForPurge, startFrom,
        ...(kind === 'syslog_tls' && clientKeyPem.trim() ? { clientKeyPem: clientKeyPem.trim() } : {}),
        ...(kind === 'webhook' && bearerToken.trim() ? { bearerToken: bearerToken.trim() } : {}),
      });
      toast.success(t('auditSettings.created') || 'Destination added');
      onCreated(out.hmacSecret);
    } catch (err) {
      toast.error(errorText(err, t('auditSettings.createFailed') || 'Destination not added'));
    } finally {
      setBusy(false);
    }
  };

  const area = 'w-full rounded-md bg-bg-tertiary px-3 py-2 text-xs font-mono text-text-primary min-h-[4.5rem]';
  return (
    <Modal open onClose={onClose} title={t('auditSettings.addDestination') || 'Add a destination'} size="lg">
      <form onSubmit={submit} className="p-4 space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Input label={t('auditSettings.name') || 'Name'} value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} />
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('auditSettings.kind') || 'Kind'}</label>
            <select value={kind} onChange={(e) => setKind(e.target.value as 'syslog_tls' | 'webhook')} className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary">
              <option value="syslog_tls">Syslog TLS (RFC 5424)</option>
              <option value="webhook">Webhook (JSON, HMAC)</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('auditSettings.scope') || 'Scope'}</label>
            <select value={scope} onChange={(e) => setScope(e.target.value)} className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary">
              <option value="">{t('auditSettings.allTenants') || 'Every tenant'}</option>
              {tenants.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('auditSettings.startFrom') || 'Start from'}</label>
            <select value={startFrom} onChange={(e) => setStartFrom(e.target.value as 'beginning' | 'now')} className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary">
              <option value="beginning">{t('auditSettings.fromBeginning') || 'The beginning of each chain'}</option>
              <option value="now">{t('auditSettings.fromNow') || 'Now'}</option>
            </select>
          </div>
        </div>
        {kind === 'syslog_tls' ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <Input label={t('auditSettings.host') || 'Host'} value={host} onChange={(e) => setHost(e.target.value)} required maxLength={253} />
            <Input label={t('auditSettings.port') || 'Port'} type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} required />
            <textarea className={area} placeholder={t('auditSettings.caPem') || 'Authority of the receiver (PEM, optional)'} value={caPem} onChange={(e) => setCaPem(e.target.value)} />
            <textarea className={area} placeholder={t('auditSettings.clientCert') || 'Client certificate (PEM, optional)'} value={clientCertPem} onChange={(e) => setClientCertPem(e.target.value)} />
            <textarea className={`${area} sm:col-span-2`} placeholder={t('auditSettings.clientKey') || 'Client key (PEM, sealed by the vault, never shown again)'} value={clientKeyPem} onChange={(e) => setClientKeyPem(e.target.value)} />
          </div>
        ) : (
          <div className="grid gap-3">
            <Input label={t('auditSettings.url') || 'URL (https)'} type="url" value={url} onChange={(e) => setUrl(e.target.value)} required maxLength={2000} />
            <Input label={t('auditSettings.bearer') || 'Bearer token (optional, never shown again)'} value={bearerToken} onChange={(e) => setBearerToken(e.target.value)} maxLength={2000} />
            <textarea className={area} placeholder={t('auditSettings.caPem') || 'Authority of the receiver (PEM, optional)'} value={caPem} onChange={(e) => setCaPem(e.target.value)} />
          </div>
        )}
        <label className="flex items-center gap-2 text-xs text-text-secondary">
          <input type="checkbox" checked={requiredForPurge} onChange={(e) => setRequiredForPurge(e.target.checked)} />
          {t('auditSettings.requiredForPurgeLabel') || 'The purge waits until this destination has received the entries'}
        </label>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button type="submit" loading={busy}>{t('common.create') || 'Create'}</Button>
        </div>
      </form>
    </Modal>
  );
}
