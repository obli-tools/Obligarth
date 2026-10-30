import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import type { AgentFileItem, LegacyAgentFileView, PolicyValidationIssue } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { FileDialog } from './FileDialog';
import { IssueList, issuesUnder } from './ui';

// The files a policy deposits on the bridge devices (lot PONT-POL §11.1): one borderless row per file (its first path
// and a "+n" chip, its source, its overwrite and removal behaviour), edited in FileDialog.

export function FilesPanel({ files, editable, issues, store, onStoreChanged, onChange }: {
  files: AgentFileItem[]; editable: boolean; issues: PolicyValidationIssue[]; store: LegacyAgentFileView[] | null; onStoreChanged: () => void;
  onChange: (next: AgentFileItem[]) => void;
}) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<{ index: number | null } | null>(null);
  return (
    <div className="space-y-2">
      <div className="flex items-center">
        <p className="text-xs text-text-muted">{t('legacyAgentPolicy.files.intro') || 'Files written into the storage of the devices, checked by their SHA-256.'}</p>
        {editable && files.length < LEGACY_AGENT_POLICY_LIMITS.files && (
          <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setEditing({ index: null })}><Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.files.add') || 'Add a file'}</Button>
        )}
      </div>
      {files.length === 0 ? <p className="text-sm text-text-muted">{t('legacyAgentPolicy.files.none') || 'No file.'}</p> : (
        <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
          {files.map((f, i) => (
            <li key={`${f.id}-${i}`} className="px-3 py-2 text-sm hover:bg-bg-tertiary">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-text-primary">{f.paths[0] || '/'}</span>
                {f.paths.length > 1 && <span className="rounded-full bg-bg-tertiary px-1.5 text-[11px] text-text-muted">+{f.paths.length - 1}</span>}
                <span className="rounded-full bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
                  {f.source.kind === 'store' ? (t('legacyAgentPolicy.files.storeSource') || 'Stored file') : (t('legacyAgentPolicy.files.templateSource') || 'Per-device template')}
                </span>
                <span className="text-[11px] text-text-muted">
                  {(f.overwrite ?? 'always') === 'always' ? (t('legacyAgentPolicy.files.always') || 'Overwrite') : (t('legacyAgentPolicy.files.ifAbsent') || 'Keep (once)')}
                  {' · '}
                  {(f.onRemove ?? 'keep') === 'keep' ? (t('legacyAgentPolicy.files.keep') || 'Keep the file') : (t('legacyAgentPolicy.files.delete') || 'Delete it')}
                </span>
                <span className="ml-auto font-mono text-[11px] text-text-muted">{f.id}</span>
                {editable && (
                  <>
                    <button type="button" className="rounded p-1.5 text-text-muted hover:text-text-primary" aria-label={t('common.edit') || 'Edit'} onClick={() => setEditing({ index: i })}><Pencil className="h-4 w-4" /></button>
                    <button type="button" className="rounded p-1.5 text-text-muted hover:text-red-400" aria-label={t('common.delete') || 'Delete'} onClick={() => onChange(files.filter((_, j) => j !== i))}><Trash2 className="h-4 w-4" /></button>
                  </>
                )}
              </div>
              {f.source.kind === 'store' && <span className="block text-[11px] text-text-muted">{f.source.name}</span>}
              <IssueList issues={issuesUnder(issues, `files[${i}]`)} />
            </li>
          ))}
        </ul>
      )}
      <FileDialog open={editing !== null} item={editing?.index != null ? files[editing.index] : null} files={store} onUploaded={onStoreChanged}
        taken={files.map((f) => f.id)} onClose={() => setEditing(null)}
        onSave={(item) => {
          onChange(editing?.index != null ? files.map((f, j) => (j === editing.index ? item : f)) : [...files, item]);
          setEditing(null);
        }} />
    </div>
  );
}
