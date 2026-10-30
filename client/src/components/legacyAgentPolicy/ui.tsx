import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, KeyRound } from 'lucide-react';
import type { AgentPolicyItemState, LegacyAgentFileKind, LegacyAgentFileView, PolicyValidationIssue, SecretSlot } from '@obligarth/shared';
import { agentKeyLabelParts } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// Small pieces shared by the editor of the bridge agent's policies (lot PONT-POL §11): the input style, a choice of
// chips (never a native select), a write-only secret input, the issues of a path, the labels of the keys, states and
// codes of the agent's report, the store files and their images (fetched as blobs: never an URL of the API in an <img>).

export const fieldCls = 'w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

/** A choice among a few values, as chips. */
export function ChipChoice<T extends string>({ value, options, onChange, disabled }: {
  value: T | null | undefined; options: ReadonlyArray<{ id: T; label: string }>; onChange: (v: T) => void; disabled?: boolean;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => (
        <button key={o.id} type="button" disabled={disabled} onClick={() => onChange(o.id)}
          className={`rounded-full px-2.5 py-1 text-xs coarse:py-2 ${value === o.id ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'} disabled:opacity-50`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="text-xs text-text-muted">{label}</span>
      <div className="mt-1">{children}</div>
      {hint && <span className="mt-0.5 block text-[11px] text-text-muted">{hint}</span>}
    </label>
  );
}

/** A secret slot: write-only. A stored reference shows a "Set" chip; typing replaces it by {"$secretValue"}. */
export function SecretInput({ value, onChange, disabled, placeholder, inputMode }: {
  value: SecretSlot | undefined | null; onChange: (v: SecretSlot | undefined) => void; disabled?: boolean; placeholder?: string;
  inputMode?: 'numeric' | 'text';
}) {
  const { t } = useTranslation();
  const isSet = !!value && '$secret' in value;
  const typed = value && '$secretValue' in value ? value.$secretValue : '';
  return (
    <div className="flex items-center gap-2">
      <input type="password" autoComplete="new-password" className={fieldCls} disabled={disabled} inputMode={inputMode}
        placeholder={isSet ? (t('legacyAgentPolicy.secret.keep') || 'Leave empty to keep the stored value') : placeholder}
        value={typed} onChange={(e) => onChange(e.target.value ? { $secretValue: e.target.value } : (isSet ? value! : undefined))} />
      {isSet && !typed && (
        <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-green-400/10 px-2 py-0.5 text-[11px] text-green-400">
          <KeyRound className="h-3 w-3" />{t('legacyAgentPolicy.secret.set') || 'Set'}
        </span>
      )}
    </div>
  );
}

/** The issues of a path (and of the paths under it). */
export function issuesUnder(issues: PolicyValidationIssue[], prefix: string): PolicyValidationIssue[] {
  return issues.filter((i) => i.path === prefix || i.path.startsWith(`${prefix}.`) || i.path.startsWith(`${prefix}[`));
}

export function IssueList({ issues }: { issues: PolicyValidationIssue[] }) {
  if (!issues.length) return null;
  return (
    <ul className="space-y-0.5 text-xs text-red-400">
      {issues.map((i, n) => (
        <li key={n} className="flex gap-1.5"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />{trCode(`mdm.validation.${i.code}`, i.code)}{i.path ? ` (${i.path})` : ''}</li>
      ))}
    </ul>
  );
}

/** The label of a key of the agent policy: its family translated and its instance or field. */
export function agentKeyLabel(key: string): string {
  const p = agentKeyLabelParts(key);
  if (p.family === 'policy') return trCode('legacyAgentPolicy.keys.policy', 'Policy');
  if (!p.family) return key;
  if (p.family === 'dpm') return trCode(`legacyAgentPolicy.dpm.${p.name}`, p.name);
  if (p.family === 'knox') return `Knox · ${trCode(`legacyAgentPolicy.knox.${p.name}`, p.name)}`;
  const family = trCode(`legacyAgentPolicy.keys.${p.family.replace('.', '_')}`, p.family);
  return p.name ? `${family} · ${p.name}` : family;
}

export const ITEM_STATE_TONE: Record<AgentPolicyItemState, 'green' | 'gray' | 'blue' | 'amber' | 'red' | 'violet'> = {
  compliant: 'green', non_compliant: 'amber', pending: 'blue', pending_licence: 'violet', unsupported: 'gray', error: 'red',
};
export const itemStateLabel = (s: string): string => trCode(`legacyAgentPolicy.itemStates.${s}`, s);
export const codeLabel = (c: string): string => trCode(`legacyAgentPolicy.codes.${c}`, c);

/** The store files of the tenant (one read per mount). */
export function useStoreFiles(): { files: LegacyAgentFileView[] | null; reload: () => void } {
  const [files, setFiles] = useState<LegacyAgentFileView[] | null>(null);
  const [n, setN] = useState(0);
  useEffect(() => {
    let alive = true;
    legacyAgentApi.files.list().then((f) => { if (alive) setFiles(f); }).catch(() => { if (alive) setFiles([]); });
    return () => { alive = false; };
  }, [n]);
  return { files, reload: () => setN((x) => x + 1) };
}

/** An image of the store as an object URL (revoked on unmount); null while it loads or when it cannot be read. */
export function useStoreImage(file: LegacyAgentFileView | undefined | null): string | null {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!file || file.kind !== 'image') { setUrl(null); return; }
    let alive = true;
    let made: string | null = null;
    legacyAgentApi.files.content(file.id).then((b) => { if (alive) { made = URL.createObjectURL(b); setUrl(made); } }).catch(() => setUrl(null));
    return () => { alive = false; if (made) URL.revokeObjectURL(made); };
  }, [file]);
  return url;
}

export function StoreImage({ file, className }: { file: LegacyAgentFileView | undefined | null; className?: string }) {
  const url = useStoreImage(file);
  if (!url) return <span className={`inline-block bg-bg-tertiary ${className ?? ''}`} />;
  return <img src={url} alt="" className={`object-contain ${className ?? ''}`} />;
}

/** A pick among the store files of one kind (chips of names), with an upload button. */
export function StorePicker({ kind, files, value, onPick, onUploaded, disabled }: {
  kind: LegacyAgentFileKind; files: LegacyAgentFileView[] | null; value: string | null | undefined;
  onPick: (f: LegacyAgentFileView) => void; onUploaded: () => void; disabled?: boolean;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = (files ?? []).filter((f) => f.kind === kind);
  const accept = kind === 'image' ? 'image/png,image/jpeg,image/gif,.ico' : kind === 'certificate' ? '.crt,.pem,.cer,.der' : undefined;
  return (
    <div className="space-y-1.5">
      {files === null ? <p className="text-xs italic text-text-muted">{t('common.loading') || 'Loading…'}</p>
        : list.length === 0 ? <p className="text-xs text-text-muted">{t('legacyAgentPolicy.store.empty') || 'No file of this kind in the store yet.'}</p> : (
          <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
            {list.map((f) => (
              <button key={f.id} type="button" disabled={disabled} onClick={() => onPick(f)} title={f.sha256}
                className={`rounded-full px-2.5 py-1 text-xs ${value === f.sha256 ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'}`}>
                {f.name}
              </button>
            ))}
          </div>
        )}
      {!disabled && (
        <label className="inline-flex cursor-pointer items-center gap-1 text-xs text-accent hover:underline">
          <input type="file" className="hidden" accept={accept} onChange={async (e) => {
            const file = e.target.files?.[0];
            e.target.value = '';
            if (!file) return;
            setBusy(true); setError(null);
            try { const f = await legacyAgentApi.files.upload(file); onUploaded(); onPick(f); } catch (err) { setError(apiErrorMessage(err)); } finally { setBusy(false); }
          }} />
          {busy ? (t('legacyAgentPolicy.store.uploading') || 'Uploading…') : (t('legacyAgentPolicy.store.upload') || 'Upload a file…')}
        </label>
      )}
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}

export const humanSize = (n: number): string => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1024 / 1024).toFixed(1)} MiB`);
