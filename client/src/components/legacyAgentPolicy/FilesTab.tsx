import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Copy, Eye, Pencil, RefreshCw, SortAsc, SortDesc, Trash2, Upload } from 'lucide-react';
import type { LegacyAgentFileView } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { useAuthStore } from '@/store/authStore';
import { apiErrorMessage } from '@/utils/apiError';
import { humanSize, useStoreFiles } from './ui';

// The file store of the agent policies (lot PONT-POL §11.2): the files a policy deposits, the images of the kiosk, the
// CAs of the Wi-Fi networks, by content. Upload (drag and drop, several at once), a sortable list (name, kind, size,
// SHA-256, use, date), rename, delete (greyed while a policy uses the file). The preview (images, small files as plain
// text) is for the editors of the policies only.

type SortKey = 'name' | 'kind' | 'size' | 'usedBy' | 'createdAt';

const thCls = 'whitespace-nowrap px-4 py-2 font-medium';
const tdCls = 'px-4 py-2.5';

export function FilesTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const canManage = useAuthStore((s) => s.isAdmin() || (s.permissions?.tenantCapabilities ?? []).includes('mdm.policies.manage'));
  const { files, reload } = useStoreFiles();
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'createdAt', dir: -1 });
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [preview, setPreview] = useState<{ file: LegacyAgentFileView; url?: string; text?: string } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const rows = useMemo(() => {
    const list = [...(files ?? [])];
    const v = (f: LegacyAgentFileView): string | number => (sort.key === 'name' ? f.name.toLowerCase() : sort.key === 'kind' ? f.kind
      : sort.key === 'size' ? f.sizeBytes : sort.key === 'usedBy' ? f.usedBy : f.createdAt);
    return list.sort((a, b) => { const x = v(a); const y = v(b); return (typeof x === 'string' ? x.localeCompare(y as string) : x - (y as number)) * sort.dir; });
  }, [files, sort]);

  const upload = async (list: FileList | File[] | null) => {
    if (!list || !canManage) return;
    setBusy(true);
    let ok = 0;
    for (const f of Array.from(list)) {
      try { await legacyAgentApi.files.upload(f); ok++; } catch (err) { if (!isStepUpHandled(err)) toast.error(`${f.name}: ${apiErrorMessage(err)}`, { duration: 7000 }); }
    }
    setBusy(false);
    if (ok) toast.success(t('legacyAgentPolicy.store.uploaded', { count: ok }) || `${ok} file(s) uploaded`);
    reload();
  };
  const rename = async (f: LegacyAgentFileView) => {
    const name = await prompt({ title: t('legacyAgentPolicy.store.rename') || 'Rename', message: t('legacyAgentPolicy.store.renamePrompt') || 'New name', defaultValue: f.name });
    if (!name || name === f.name) return;
    try { await legacyAgentApi.files.patch(f.id, { name }); reload(); } catch (err) { if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err)); }
  };
  const remove = async (f: LegacyAgentFileView) => {
    if (!(await confirm({ message: t('legacyAgentPolicy.store.confirmDelete', { name: f.name }) || `Delete ${f.name}?`, danger: true }))) return;
    try { await legacyAgentApi.files.remove(f.id); reload(); } catch (err) { if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 }); }
  };
  const open = async (f: LegacyAgentFileView) => {
    try {
      const blob = await legacyAgentApi.files.content(f.id);
      if (f.kind === 'image') setPreview({ file: f, url: URL.createObjectURL(blob) });
      else setPreview({ file: f, text: await blob.text() });
    } catch (err) { toast.error(apiErrorMessage(err)); }
  };
  const closePreview = () => { if (preview?.url) URL.revokeObjectURL(preview.url); setPreview(null); };
  const head = (label: string, key: SortKey) => (
    <th className={thCls} aria-sort={sort.key === key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button type="button" onClick={() => setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 }))}
        className={clsx('inline-flex items-center gap-0.5 uppercase tracking-wider', sort.key === key ? 'text-accent' : 'hover:text-text-primary')}>
        {label}{sort.key === key ? (sort.dir === 1 ? <SortAsc className="h-3 w-3" /> : <SortDesc className="h-3 w-3" />) : null}
      </button>
    </th>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm text-text-muted">{t('legacyAgentPolicy.store.intro') || 'Files the policies deposit, kiosk images and Wi-Fi CAs (2 GiB per tenant).'}</p>
        <button type="button" onClick={reload} aria-label={t('common.refresh') || 'Refresh'} className="ml-auto rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"><RefreshCw className="h-4 w-4" /></button>
        {canManage && (
          <>
            <input ref={inputRef} type="file" multiple className="hidden" onChange={(e) => { void upload(e.target.files); e.target.value = ''; }} />
            <Button size="sm" loading={busy} onClick={() => inputRef.current?.click()}><Upload className="mr-1 h-4 w-4" />{t('legacyAgentPolicy.store.upload') || 'Upload a file…'}</Button>
          </>
        )}
      </div>
      {canManage && (
        <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); void upload(e.dataTransfer.files); }}
          className={clsx('rounded-xl border border-dashed px-4 py-6 text-center text-sm', drag ? 'border-accent bg-accent/10 text-accent' : 'border-border text-text-muted')}>
          {t('legacyAgentPolicy.store.drop') || 'Drop files here'}
        </div>
      )}
      <div className="overflow-x-auto rounded-xl bg-bg-secondary">
        <table className="w-full text-sm">
          <thead className="bg-bg-tertiary/50 text-left text-[10px] font-medium uppercase tracking-wider text-text-muted">
            <tr>
              {head(t('legacyAgentPolicy.store.name') || 'Name', 'name')}
              {head(t('legacyAgentPolicy.store.kind') || 'Kind', 'kind')}
              {head(t('legacyAgentPolicy.store.size') || 'Size', 'size')}
              <th className={thCls}>SHA-256</th>
              {head(t('legacyAgentPolicy.store.usedBy') || 'Used by', 'usedBy')}
              {head(t('legacyAgentPolicy.store.date') || 'Added', 'createdAt')}
              <th className="w-28" />
            </tr>
          </thead>
          <tbody>
            {files === null && <tr><td colSpan={7} className="p-8 text-center text-text-muted">{t('common.loading') || 'Loading…'}</td></tr>}
            {files !== null && rows.length === 0 && <tr><td colSpan={7} className="p-8 text-center text-text-muted">{t('legacyAgentPolicy.store.none') || 'No file yet.'}</td></tr>}
            {rows.map((f) => (
              <tr key={f.id} className="transition-colors hover:bg-bg-tertiary">
                <td className={clsx(tdCls, 'font-medium text-text-primary')}>{f.name}{f.origin === 'import' && <span className="ml-2 text-[10px] uppercase text-text-muted">{t('legacyAgentPolicy.store.imported') || 'imported'}</span>}</td>
                <td className={tdCls}><span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-secondary">{t(`legacyAgentPolicy.store.kinds.${f.kind}`) || f.kind}</span></td>
                <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-secondary')}>{humanSize(f.sizeBytes)}</td>
                <td className={tdCls}>
                  <button type="button" className="inline-flex items-center gap-1 font-mono text-[11px] text-text-muted hover:text-text-primary" title={f.sha256}
                    onClick={() => { void navigator.clipboard?.writeText(f.sha256); toast.success(t('common.copied') || 'Copied'); }}>{f.sha256.slice(0, 12)}<Copy className="h-3 w-3" /></button>
                </td>
                <td className={clsx(tdCls, 'text-xs tabular-nums text-text-secondary')}>{f.usedBy}</td>
                <td className={clsx(tdCls, 'whitespace-nowrap text-xs text-text-muted')}>{formatDateTime(f.createdAt)}</td>
                <td className="py-2.5 pr-3 text-right whitespace-nowrap">
                  {canManage && (f.kind !== 'file' || f.sizeBytes <= 64 * 1024) && (
                    <button type="button" className="rounded p-1 text-text-muted hover:text-text-primary" aria-label={t('legacyAgentPolicy.store.preview') || 'Preview'} onClick={() => void open(f)}><Eye className="h-4 w-4" /></button>
                  )}
                  {canManage && <button type="button" className="rounded p-1 text-text-muted hover:text-text-primary" aria-label={t('common.edit') || 'Edit'} onClick={() => void rename(f)}><Pencil className="h-4 w-4" /></button>}
                  {canManage && (
                    <button type="button" disabled={f.usedBy > 0} title={f.usedBy > 0 ? (t('legacyAgentPolicy.store.inUse') || 'Used by a policy') : undefined}
                      className="rounded p-1 text-text-muted enabled:hover:text-red-400 disabled:opacity-40" aria-label={t('common.delete') || 'Delete'} onClick={() => void remove(f)}><Trash2 className="h-4 w-4" /></button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Modal open={!!preview} onClose={closePreview} size="lg" title={preview?.file.name ?? ''}>
        {preview?.url && <img src={preview.url} alt="" className="mx-auto max-h-[60vh] object-contain" />}
        {preview?.text !== undefined && <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap rounded bg-bg-tertiary p-3 font-mono text-xs text-text-primary">{preview.text}</pre>}
      </Modal>
    </div>
  );
}
