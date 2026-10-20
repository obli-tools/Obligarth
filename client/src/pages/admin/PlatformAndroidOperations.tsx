import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Eye, KeyRound, RefreshCw, RotateCcw, Trash2, Upload } from 'lucide-react';
import type { AndroidDeadLetterDetail, AndroidDeadLetterView, AndroidDeadline } from '@obligarth/shared';
import { androidPlatformApi } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { AndroidCard, Labeled, dateOf, errorToast, fieldClass } from '@/components/android/ui';
import { useTenantStore } from '@/store/tenantStore';
import { trCode } from '@/utils/apiError';

// The operation cards of « Platform > Android » (android-amapi §5.2, §7.2, §12.1, AN51; lot AN-C2; platform
// administrators of the master tenant): the deposit of the JSON key of the service account (vault_key mode, strict
// step-up; only its fingerprint comes back) and its deadline, the orphan enterprises of a tenant and their adoption (a
// restricted request), the dead letters of the inbox of every tenant (list without payload, audited detail, redrive or
// discard under the restriction jobs.manage).

const DEADLINE_TONE: Record<AndroidDeadline['status'], 'green' | 'amber' | 'red'> = { ok: 'green', warning: 'amber', overdue: 'red' };

export function KeyCard({ onDeposited }: { onDeposited: () => void }) {
  const { t } = useTranslation();
  const [deadline, setDeadline] = useState<AndroidDeadline | null>(null);
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { androidPlatformApi.keyDeadline().then(setDeadline).catch(() => setDeadline(null)); }, []);
  useEffect(() => { load(); }, [load]);
  const deposit = async () => {
    setBusy(true);
    try {
      const r = await androidPlatformApi.depositKey(text.trim());
      setText('');
      setOpen(false);
      toast.success(t('androidPlatform.key.deposited', { fingerprint: r.fingerprint }) || `Key deposited (${r.fingerprint})`, { duration: 7000 });
      load();
      onDeposited();
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  const readFile = async (f: File) => { setText(await f.text()); };
  return (
    <AndroidCard title={t('androidPlatform.key.title') || 'Key of the service account'} icon={<KeyRound className="w-5 h-5 text-accent" />}
      badge={deadline && <StateBadge tone={DEADLINE_TONE[deadline.status]} label={trCode(`android.deadlines.status.${deadline.status}`, deadline.status)} />}
      action={<Button size="sm" onClick={() => setOpen(true)}><Upload className="w-4 h-4 mr-1" />{t('androidPlatform.key.deposit') || 'Deposit a key'}</Button>}>
      <p className="text-xs text-text-muted">
        {t('androidPlatform.key.help') || 'The JSON key is sealed in the vault and never read back by a route; only its fingerprint is shown. Rotate it every 90 days (organisation policy of the Google project).'}
      </p>
      {deadline && <p className="text-sm text-text-secondary">{t('androidPlatform.key.due', { at: dateOf(deadline.dueAt) }) || `Rotation due ${dateOf(deadline.dueAt)}`}</p>}
      <Modal open={open} onClose={() => { if (!busy) setOpen(false); }} size="lg" title={t('androidPlatform.key.deposit') || 'Deposit a key'}
        footer={(
          <>
            <Button variant="secondary" disabled={busy} onClick={() => setOpen(false)}>{t('common.cancel') || 'Cancel'}</Button>
            <Button disabled={busy || text.trim().length < 20} onClick={() => void deposit()}>{t('androidPlatform.key.seal') || 'Seal in the vault'}</Button>
          </>
        )}>
        <div className="space-y-3">
          <input type="file" accept="application/json,.json" onChange={(e) => { const f = e.target.files?.[0]; if (f) void readFile(f); e.target.value = ''; }}
            className="text-sm text-text-secondary" />
          <Labeled label={t('androidPlatform.key.json') || 'JSON key (or paste it here)'} hint={t('androidPlatform.key.jsonHint') || 'Sent once over the session, sealed at once; a second factor is asked.'}>
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} spellCheck={false} autoComplete="off" className={`${fieldClass} font-mono text-xs`} />
          </Labeled>
        </div>
      </Modal>
    </AndroidCard>
  );
}

export function OrphansCard() {
  const { t } = useTranslation();
  const prompt = usePrompt();
  const tenants = useTenantStore((s) => s.tenants);
  const [tenantId, setTenantId] = useState('');
  const [list, setList] = useState<Array<{ enterpriseName: string; signupId: string }> | null>(null);
  const [busy, setBusy] = useState(false);
  const search = async () => {
    if (!tenantId) return;
    setBusy(true);
    try { setList(await androidPlatformApi.orphans(Number(tenantId))); } catch (err) { setList(null); errorToast(err); } finally { setBusy(false); }
  };
  const adopt = async (o: { enterpriseName: string; signupId: string }) => {
    const reason = await prompt({
      title: t('androidPlatform.orphans.adoptTitle') || 'Adopt the orphan enterprise',
      message: t('androidPlatform.orphans.adoptHint') || 'Reason (audited). Another platform administrator approves the adoption.', multiline: true, required: true,
    });
    if (!reason) return;
    setBusy(true);
    try {
      await androidPlatformApi.adopt({ tenantId: Number(tenantId), enterpriseName: o.enterpriseName, signupId: o.signupId, reason });
      toast.success(t('androidPlatform.orphans.requested') || 'Adoption requested: another platform administrator must approve it.', { duration: 7000 });
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <AndroidCard title={t('androidPlatform.orphans.title') || 'Orphan enterprises'}>
      <p className="text-xs text-text-muted">
        {t('androidPlatform.orphans.help') || 'An enterprise created at Google whose signup was interrupted before it reached the registry. Only one that carries the marker of a failed signup of the tenant can be adopted.'}
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <Labeled label={t('androidPlatform.orphans.tenant') || 'Tenant'}>
          <select value={tenantId} onChange={(e) => { setTenantId(e.target.value); setList(null); }} className={`${fieldClass} sm:w-72`}>
            <option value="">{t('androidPlatform.orphans.chooseTenant') || '— choose —'}</option>
            {tenants.map((tn) => <option key={tn.id} value={tn.id}>{tn.name}</option>)}
          </select>
        </Labeled>
        <Button size="sm" variant="secondary" disabled={!tenantId || busy} onClick={() => void search()}>{t('androidPlatform.orphans.search') || 'Look for orphans'}</Button>
      </div>
      {list && list.length === 0 && <p className="text-sm text-text-muted">{t('androidPlatform.orphans.none') || 'No adoptable enterprise for this tenant.'}</p>}
      {list && list.length > 0 && (
        <ul className="divide-y divide-border/50 rounded-lg bg-bg-primary">
          {list.map((o) => (
            <li key={o.enterpriseName} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
              <span className="font-mono text-text-primary">{o.enterpriseName}</span>
              <Button size="sm" className="ml-auto" disabled={busy} onClick={() => void adopt(o)}>{t('androidPlatform.orphans.adopt') || 'Adopt…'}</Button>
            </li>
          ))}
        </ul>
      )}
    </AndroidCard>
  );
}

export function DeadLettersCard() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const tenants = useTenantStore((s) => s.tenants);
  const [rows, setRows] = useState<AndroidDeadLetterView[] | null>(null);
  const [detail, setDetail] = useState<AndroidDeadLetterDetail | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const load = useCallback(() => { androidPlatformApi.deadLetters().then(setRows).catch((err) => { setRows([]); errorToast(err); }); }, []);
  useEffect(() => { load(); }, [load]);
  const tenantName = (id: number) => tenants.find((x) => x.id === id)?.name ?? `#${id}`;
  const run = async (id: string, fn: () => Promise<{ approvalId?: number }>, done: string) => {
    setBusy(id);
    try {
      const r = await fn();
      if (r && r.approvalId) toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
      else toast.success(done);
      setDetail(null);
      load();
    } catch (err) { errorToast(err); } finally { setBusy(null); }
  };
  const view = async (id: string) => {
    if (!(await confirm({ message: t('androidPlatform.deadLetters.viewConfirm') || 'The notification carries device data: its consultation is written to the audit journal. Open it?' }))) return;
    setBusy(id);
    try { setDetail(await androidPlatformApi.deadLetter(id)); } catch (err) { errorToast(err); } finally { setBusy(null); }
  };
  return (
    <AndroidCard title={t('androidPlatform.deadLetters.title') || 'Dead letters of the inbox'}
      badge={rows && <StateBadge tone={rows.length ? 'red' : 'green'} label={String(rows.length)} />}
      action={<Button size="sm" variant="secondary" onClick={load} aria-label={t('common.refresh') || 'Refresh'}><RefreshCw className="w-4 h-4" /></Button>}>
      <p className="text-xs text-text-muted">
        {t('androidPlatform.deadLetters.help') || 'Notifications of Google whose application failed five times. Apply one again once its cause is fixed, or discard it.'}
      </p>
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <p className="text-sm text-text-muted">{t('androidPlatform.deadLetters.none') || 'No dead letter.'}</p> : (
          <ul className="divide-y divide-border/50 rounded-lg bg-bg-primary">
            {rows.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                <span className="text-text-primary">{trCode(`androidPlatform.deadLetters.types.${r.eventType.replace('.', '_')}`, r.eventType)}</span>
                <span className="text-xs text-text-muted">{tenantName(r.tenantId)}</span>
                {r.lastError && <span className="text-xs text-red-400">{trCode(`androidPlatform.deadLetters.errors.${r.lastError}`, r.lastError)}</span>}
                <span className="text-xs text-text-muted">{dateOf(r.receivedAt)}</span>
                <span className="ml-auto flex gap-1.5">
                  <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void view(r.id)} aria-label={t('androidPlatform.deadLetters.view') || 'View'}><Eye className="w-3.5 h-3.5" /></Button>
                  <Button size="sm" variant="secondary" disabled={busy !== null}
                    onClick={() => void run(r.id, () => androidPlatformApi.redrive(r.id), t('androidPlatform.deadLetters.redriven') || 'Notification applied again')}>
                    <RotateCcw className="w-3.5 h-3.5 mr-1" />{t('androidPlatform.deadLetters.redrive') || 'Apply again'}
                  </Button>
                  <Button size="sm" variant="danger" disabled={busy !== null} aria-label={t('androidPlatform.deadLetters.discard') || 'Discard'} onClick={async () => {
                    if (await confirm({ message: t('androidPlatform.deadLetters.discardConfirm') || 'Discard this notification? It is not applied.', danger: true })) {
                      await run(r.id, () => androidPlatformApi.discard(r.id), t('androidPlatform.deadLetters.discarded') || 'Notification discarded');
                    }
                  }}><Trash2 className="w-3.5 h-3.5" /></Button>
                </span>
              </li>
            ))}
          </ul>
        )}
      <Modal open={detail !== null} onClose={() => setDetail(null)} size="2xl" title={t('androidPlatform.deadLetters.detail') || 'Dead letter'}
        footer={<Button onClick={() => setDetail(null)}>{t('common.close') || 'Close'}</Button>}>
        {detail && (
          <div className="space-y-2 text-sm">
            <p className="text-text-secondary">{detail.eventType} · {tenantName(detail.tenantId)} · {detail.resourceName ?? '—'}</p>
            <pre className="max-h-[60vh] overflow-auto rounded bg-bg-primary p-2 font-mono text-xs text-text-primary">{JSON.stringify(detail.payload, null, 2)}</pre>
          </div>
        )}
      </Modal>
    </AndroidCard>
  );
}
