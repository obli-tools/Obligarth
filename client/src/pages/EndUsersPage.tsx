import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { FileUp, Pencil, Plus, RefreshCw, Search, UserMinus } from 'lucide-react';
import type { EndUser, EndUserImportReport } from '@obligarth/shared';
import { mdmApi, type EndUserFields } from '@/api/mdm.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDate } from '@/components/mdm/PlatformIcon';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The end users of the tenant (modele-donnees-mdm §4.8, PLT-28): the employees of the client a device is
// assigned to. They have no account here: a name, an e-mail, a Managed Apple Account, an identifier of the
// client's directory. Created by hand, by a CSV import, or at an enrollment.

const PAGE_SIZE = 100;
const nameOf = (u: EndUser): string => u.displayName || u.email || u.managedAppleAccount || u.externalId || `#${u.id}`;

export function EndUsersPage() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('users.manage');
  const [status, setStatus] = useState<'active' | 'departed' | ''>('active');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const [data, setData] = useState<{ items: EndUser[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<EndUser | 'new' | null>(null);
  const [report, setReport] = useState<EndUserImportReport | null>(null);
  const [importing, setImporting] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    mdmApi.listEndUsers({ status: status || undefined, q: q.trim() || undefined, page, pageSize: PAGE_SIZE })
      .then((r) => { setData({ items: r.items, total: r.total }); setError(null); })
      .catch((err) => { setData({ items: [], total: 0 }); setError(apiErrorMessage(err)); });
  }, [status, q, page]);
  useEffect(() => {
    const timer = setTimeout(load, 200);
    return () => clearTimeout(timer);
  }, [load]);
  useEffect(() => { setPage(1); }, [status, q]);

  const depart = async (u: EndUser) => {
    const ok = await confirm({
      message: t('endUsers.confirmDepart', { name: anonymize(nameOf(u)) })
        || `Mark ${nameOf(u)} as departed? Their devices stay assigned for 90 days, then the record is erased.`,
      danger: true,
    });
    if (!ok) return;
    try {
      await mdmApi.departEndUser(u.id);
      toast.success(t('endUsers.departed') || 'Marked as departed');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    }
  };

  const importFile = async (file: File) => {
    if (file.size > 1024 * 1024) { toast.error(t('endUsers.importTooLarge') || 'The file is larger than 1 MiB.'); return; }
    setImporting(true);
    try {
      setReport(await mdmApi.importEndUsers(await file.text()));
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setImporting(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('endUsers.title') || 'End users'}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('endUsers.subtitle') || 'The people the devices are assigned to. They have no account in this console.'}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('endUsers.search') || 'Name, e-mail, identifier…'}
            autoCapitalize="off" spellCheck={false}
            className="w-full pl-9 pr-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
        </div>
        {(['active', 'departed', ''] as const).map((s) => (
          <button key={s || 'all'} type="button" onClick={() => setStatus(s)}
            className={`px-2.5 py-1.5 text-xs font-medium rounded-full coarse:min-h-10 ${status === s ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary'}`}>
            {s === '' ? (t('common.all') || 'All') : s === 'active' ? (t('endUsers.active') || 'Active') : (t('endUsers.departedLabel') || 'Departed')}
          </button>
        ))}
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
        {canManage && (
          <span className="ml-auto flex gap-2">
            <input ref={fileRef} type="file" accept=".csv,text/csv,text/plain" className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) void importFile(f); }} />
            <Button size="sm" variant="secondary" loading={importing} onClick={() => fileRef.current?.click()}>
              <FileUp className="w-4 h-4 mr-1" />{t('endUsers.import') || 'Import a CSV'}
            </Button>
            <Button size="sm" onClick={() => setEditing('new')}><Plus className="w-4 h-4 mr-1" />{t('endUsers.new') || 'New end user'}</Button>
          </span>
        )}
      </div>
      {canManage && (
        <p className="text-[11px] text-text-muted">
          {t('endUsers.importHint') || 'CSV columns: email, display_name, managed_apple_account, external_id (a header line; an existing line is updated by its external_id, then by its e-mail).'}
        </p>
      )}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {data === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : data.items.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">{t('endUsers.none') || 'No end user.'}</div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">{t('endUsers.name') || 'Name'}</th>
                  <th className="font-medium px-3 py-2">{t('endUsers.email') || 'E-mail'}</th>
                  <th className="font-medium px-3 py-2">{t('endUsers.managedAppleAccount') || 'Managed Apple Account'}</th>
                  <th className="font-medium px-3 py-2">{t('endUsers.externalId') || 'Directory identifier'}</th>
                  <th className="font-medium px-3 py-2 text-right">{t('endUsers.devices') || 'Devices'}</th>
                  <th className="font-medium px-3 py-2">{t('common.status') || 'Status'}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((u) => (
                  <tr key={u.id} className="border-t border-border/50">
                    <td className="px-4 py-2.5 text-text-primary">
                      {anonymize(u.displayName) || <span className="text-text-muted">—</span>}
                      <span className="block text-[10px] uppercase text-text-muted">{trCode(`endUsers.source.${u.source}`, u.source)}</span>
                    </td>
                    <td className="px-3 py-2.5 text-text-secondary break-all">{anonymize(u.email) || '—'}</td>
                    <td className="px-3 py-2.5 text-text-secondary break-all">{anonymize(u.managedAppleAccount) || '—'}</td>
                    <td className="px-3 py-2.5 text-text-secondary font-mono text-xs break-all">{anonymize(u.externalId) || '—'}</td>
                    <td className="px-3 py-2.5 text-right tabular-nums">
                      {(u.deviceCount ?? 0) > 0
                        ? <Link to={`/devices?endUserId=${u.id}`} className="text-accent hover:underline">{u.deviceCount}</Link>
                        : <span className="text-text-muted">0</span>}
                    </td>
                    <td className="px-3 py-2.5">
                      <StateBadge
                        tone={u.status === 'active' ? 'green' : 'gray'}
                        label={u.status === 'active' ? (t('endUsers.active') || 'Active') : (t('endUsers.departedLabel') || 'Departed')}
                        title={u.departedAt ? formatDate(u.departedAt) : undefined}
                      />
                    </td>
                    <td className="px-3 py-2.5">
                      {canManage && (
                        <span className="flex justify-end gap-1">
                          <button type="button" onClick={() => setEditing(u)} aria-label={t('common.edit') || 'Edit'} title={t('common.edit') || 'Edit'}
                            className="p-1.5 rounded text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
                            <Pencil className="w-4 h-4" />
                          </button>
                          {u.status === 'active' && (
                            <button type="button" onClick={() => { void depart(u); }} aria-label={t('endUsers.depart') || 'Mark as departed'} title={t('endUsers.depart') || 'Mark as departed'}
                              className="p-1.5 rounded text-text-muted hover:text-red-400 hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
                              <UserMinus className="w-4 h-4" />
                            </button>
                          )}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-end gap-2 text-xs text-text-muted">
          <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>{t('common.back') || 'Back'}</Button>
          <span className="tabular-nums">{page} / {pages} · {data.total}</span>
          <Button size="sm" variant="secondary" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>{t('common.next') || 'Next'}</Button>
        </div>
      )}

      <EndUserDialog target={editing} onClose={() => setEditing(null)} onSaved={load} />
      <ImportReportDialog report={report} onClose={() => setReport(null)} />
    </PageContainer>
  );
}

function EndUserDialog({ target, onClose, onSaved }: { target: EndUser | 'new' | null; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState<Record<keyof EndUserFields, string>>({ email: '', displayName: '', managedAppleAccount: '', externalId: '' });
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (target === null) return;
    const u = target === 'new' ? null : target;
    setF({ email: u?.email ?? '', displayName: u?.displayName ?? '', managedAppleAccount: u?.managedAppleAccount ?? '', externalId: u?.externalId ?? '' });
  }, [target]);
  // One identity at least (e-mail, Managed Apple Account or directory identifier): a name alone is refused by
  // the server (identity_required), such a line could never be matched again by an import or an enrollment.
  const ok = [f.email, f.managedAppleAccount, f.externalId].some((v) => v.trim().length > 0);
  const save = async () => {
    const body: EndUserFields = {
      email: f.email.trim() || null, displayName: f.displayName.trim() || null,
      managedAppleAccount: f.managedAppleAccount.trim() || null, externalId: f.externalId.trim() || null,
    };
    setBusy(true);
    try {
      if (target === 'new') await mdmApi.createEndUser(body);
      else if (target) await mdmApi.updateEndUser(target.id, body);
      toast.success(t('common.saved') || 'Saved');
      onSaved();
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const field = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
  const input = (key: keyof EndUserFields, label: string, max: number, type = 'text') => (
    <label className="block">
      <span className="text-xs text-text-muted">{label}</span>
      <input type={type} value={f[key]} onChange={(e) => setF((prev) => ({ ...prev, [key]: e.target.value }))} maxLength={max}
        autoCapitalize="off" spellCheck={false} className={field} />
    </label>
  );
  return (
    <Modal
      open={target !== null}
      onClose={() => { if (!busy) onClose(); }}
      size="md"
      title={target === 'new' ? (t('endUsers.new') || 'New end user') : (t('endUsers.edit') || 'Edit the end user')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy} disabled={!ok}>{t('common.save') || 'Save'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        {input('displayName', t('endUsers.name') || 'Name', 200)}
        {input('email', t('endUsers.email') || 'E-mail', 320, 'email')}
        {input('managedAppleAccount', t('endUsers.managedAppleAccount') || 'Managed Apple Account', 320, 'email')}
        {input('externalId', t('endUsers.externalId') || 'Directory identifier', 255)}
        <p className="text-[11px] text-text-muted">{t('endUsers.variablesHint', { variables: '{{user.email}}, {{user.display_name}}' })}</p>
      </div>
    </Modal>
  );
}

function ImportReportDialog({ report, onClose }: { report: EndUserImportReport | null; onClose: () => void }) {
  const { t } = useTranslation();
  const rejected = report?.lines.filter((l) => l.outcome === 'rejected') ?? [];
  return (
    <Modal open={report !== null} onClose={onClose} size="md" title={t('endUsers.importReport') || 'Import report'}
      footer={<Button onClick={onClose}>{t('common.close') || 'Close'}</Button>}>
      {report && (
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap gap-2">
            {([
              ['created', report.created, 'text-green-400'], ['updated', report.updated, 'text-accent'],
              ['unchanged', report.unchanged, 'text-text-secondary'], ['rejected', report.rejected, 'text-red-400'],
            ] as const).map(([k, n, cls]) => (
              <div key={k} className="rounded-lg bg-bg-tertiary px-3 py-2 min-w-[90px]">
                <div className={`text-lg font-semibold tabular-nums ${cls}`}>{n}</div>
                <div className="text-[11px] text-text-muted">{t(`endUsers.report.${k}`) || k}</div>
              </div>
            ))}
          </div>
          {rejected.length > 0 && (
            <ul className="max-h-56 overflow-auto rounded border border-border text-xs divide-y divide-border/50">
              {rejected.slice(0, 200).map((l) => (
                <li key={l.line} className="px-2 py-1.5">
                  <span className="text-text-muted">{t('endUsers.report.line', { line: l.line }) || `Line ${l.line}`}:</span>{' '}
                  <span className="text-red-400">{trCode(`endUsers.report.code.${l.code}`, l.code ?? 'rejected')}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Modal>
  );
}
