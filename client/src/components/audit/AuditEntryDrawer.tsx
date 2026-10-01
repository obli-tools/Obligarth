import { useEffect, useState, type ReactNode } from 'react';
import { Copy, FileText, ShieldCheck, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import type { AuditEntryDetailDto } from '@obligarth/shared';
import { auditApi } from '@/api/audit.api';
import { Drawer } from '@/components/common/Drawer';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { actionLabel, CriticalityPill, EntryFlags, errorText, OutcomeText, SidePill, when } from './auditLabels';

// Detail of one journal entry: the canonical body as hashed (pretty printed,
// copyable as is), its number and hashes, the seal that covers it and the
// inclusion proof of the tenant's chain head in that seal.

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] gap-2 py-1 text-xs">
      <div className="text-text-muted">{label}</div>
      <div className="text-text-primary min-w-0 break-words">{children}</div>
    </div>
  );
}

function Hash({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-text-muted">—</span>;
  return <span className="font-mono text-[11px] break-all">{value}</span>;
}

export function AuditEntryDrawer({ uuid, filterTenantId, onClose }: { uuid: string | null; filterTenantId?: number; onClose: () => void }) {
  const { t } = useTranslation();
  const [entry, setEntry] = useState<AuditEntryDetailDto | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!uuid) { setEntry(null); return; }
    let cancelled = false;
    setLoading(true);
    auditApi.entry(uuid, filterTenantId)
      .then((e) => { if (!cancelled) setEntry(e); })
      .catch((err) => {
        if (!cancelled) {
          toast.error(errorText(err, t('audit.entryLoadFailed') || 'Could not load the entry'));
          onClose();
        }
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uuid, filterTenantId]);

  let pretty = '';
  if (entry) {
    try { pretty = JSON.stringify(JSON.parse(entry.body), null, 2); } catch { pretty = entry.body; }
  }

  const copyBody = async () => {
    if (!entry) return;
    try {
      // The body exactly as hashed (not the pretty print): it is what a
      // verifier recomputes the chain hash from.
      await navigator.clipboard.writeText(entry.body);
      toast.success(t('audit.bodyCopied') || 'Body copied');
    } catch {
      toast.error(t('common.error') || 'Error');
    }
  };

  return (
    <Drawer
      open={uuid !== null}
      onClose={onClose}
      side="right"
      size="lg"
      title={entry ? actionLabel(t, entry.action) : (t('audit.entryTitle') || 'Journal entry')}
      icon={<FileText className="w-4 h-4 text-accent" />}
      footer={entry ? (
        <Button variant="secondary" size="sm" onClick={copyBody}>
          <Copy className="w-3.5 h-3.5 mr-1.5" />{t('audit.copyBody') || 'Copy the body'}
        </Button>
      ) : undefined}
    >
      {loading || !entry ? (
        <div className="p-8 flex justify-center"><LoadingSpinner /></div>
      ) : (
        <div className="p-4 space-y-4">
          <section>
            <Field label={t('audit.col.when') || 'When'}>{when(entry.occurredAt)}</Field>
            <Field label={t('audit.recordedAt') || 'Recorded'}>{when(entry.recordedAt)}</Field>
            <Field label={t('audit.col.action') || 'Action'}>
              <span className="font-mono text-[11px]">{entry.action}</span>
            </Field>
            <Field label={t('audit.col.outcome') || 'Outcome'}>
              <span className="inline-flex items-center gap-2"><OutcomeText outcome={entry.outcome} t={t} /><CriticalityPill criticality={entry.criticality} t={t} /><EntryFlags legacy={entry.legacy} late={entry.late} t={t} /></span>
            </Field>
            <Field label={t('audit.col.actor') || 'Author'}>
              <span className="inline-flex items-center gap-2 flex-wrap">
                <span>{entry.actor.displayName || entry.actor.label || entry.actor.ref}</span>
                <SidePill side={entry.actor.side} t={t} />
                {entry.actor.role && <span className="text-text-muted">{entry.actor.role}</span>}
              </span>
            </Field>
            {entry.onBehalfOfTenantId !== null && (
              <Field label={t('audit.onBehalfOf') || 'On behalf of'}>#{entry.onBehalfOfTenantId}</Field>
            )}
            <Field label={t('audit.col.target') || 'Target'}>
              {entry.deviceId ? (
                <Link to={`/devices/${entry.deviceId}`} className="text-accent hover:underline">{entry.deviceName || `#${entry.deviceId}`}</Link>
              ) : entry.resourceType ? (
                <span>{entry.resourceName || `${entry.resourceType}:${entry.resourcePath ?? ''}`}</span>
              ) : '—'}
              {entry.targetCount !== null && entry.targetCount > 1 && (
                <span className="ml-2 text-text-muted">({t('audit.targets', { count: entry.targetCount }) || `${entry.targetCount} targets`})</span>
              )}
            </Field>
            {entry.reason && <Field label={t('audit.col.reason') || 'Reason'}>{entry.reason}</Field>}
            {entry.ticket && <Field label={t('audit.ticket') || 'Ticket'}>{entry.ticket}</Field>}
            {entry.approvalIds.length > 0 && <Field label={t('audit.approvals') || 'Approvals'}>{entry.approvalIds.map((id) => `#${id}`).join(', ')}</Field>}
            <Field label={t('audit.col.ip') || 'Address'}><span className="font-mono text-[11px]">{entry.ipAddress || '—'}</span></Field>
            {entry.userAgent && <Field label={t('audit.userAgent') || 'Agent'}><span className="text-[11px]">{entry.userAgent}</span></Field>}
            {entry.requestId && <Field label={t('audit.requestId') || 'Request'}><span className="font-mono text-[11px]">{entry.requestId}</span></Field>}
          </section>

          <section className="rounded bg-bg-tertiary/40 p-3">
            <div className="text-[10px] uppercase text-text-muted mb-1">{t('audit.chain') || 'Chain'}</div>
            <Field label={t('audit.seq') || 'Number'}>{entry.chainSeq}</Field>
            <Field label={t('audit.prevHash') || 'Previous hash'}><Hash value={entry.prevHash} /></Field>
            <Field label={t('audit.hash') || 'Hash'}><Hash value={entry.hash} /></Field>
          </section>

          <section className="rounded bg-bg-tertiary/40 p-3">
            <div className="flex items-center gap-1.5 text-[10px] uppercase text-text-muted mb-1">
              {entry.seal ? <ShieldCheck className="w-3.5 h-3.5 text-green-400" /> : <ShieldAlert className="w-3.5 h-3.5 text-yellow-400" />}
              {t('audit.seal') || 'Seal'}
            </div>
            {entry.seal ? (
              <>
                <Field label={t('audit.sealSeq') || 'Seal number'}>{entry.seal.seq}</Field>
                <Field label={t('audit.sealedAt') || 'Sealed at'}>{when(entry.seal.sealedAt)}</Field>
                <Field label={t('audit.sealKey') || 'Key'}><Hash value={entry.seal.keyId} /></Field>
                <Field label={t('audit.tsa') || 'Time stamp'}>
                  {entry.seal.tsa.status === 'ok'
                    ? `${t('audit.tsaOk') || 'Stamped'} ${when(entry.seal.tsa.genTime)}`
                    : entry.seal.tsa.status === 'failed' ? (t('audit.tsaFailed') || 'Failed') : (t('audit.tsaDisabled') || 'Not configured')}
                </Field>
                {entry.seal.leaf && (
                  <Field label={t('audit.proof') || 'Inclusion proof'}>
                    <span className="text-[11px]">
                      {t('audit.proofText', { index: entry.seal.leaf.index, seq: entry.seal.leaf.seq, count: entry.seal.leaf.proof.length })
                        || `Leaf ${entry.seal.leaf.index} (head ${entry.seal.leaf.seq}), ${entry.seal.leaf.proof.length} hashes`}
                    </span>
                  </Field>
                )}
              </>
            ) : (
              <p className="text-xs text-text-muted">{t('audit.notSealedYet') || 'Not sealed yet: the next hourly seal will cover this entry.'}</p>
            )}
          </section>

          <section>
            <div className="text-[10px] uppercase text-text-muted mb-1">{t('audit.body') || 'Body (as hashed)'}</div>
            <pre className="text-[11px] text-text-secondary font-mono whitespace-pre-wrap break-all max-h-96 overflow-auto rounded bg-bg-primary/50 p-2">{pretty}</pre>
          </section>
        </div>
      )}
    </Drawer>
  );
}
