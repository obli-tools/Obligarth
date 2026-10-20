import type { ReactNode } from 'react';
import { Copy } from 'lucide-react';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';
import { isStepUpHandled } from '@/api/client';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage } from '@/utils/apiError';

// Small pieces shared by the Android screens of the console (lot AN-C2): a card, a row of facts, the input style and
// the error toast (a step-up the client already reported is not toasted again).

export const fieldClass = 'w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

export const dateOf = (v: string | null | undefined): string => (v ? formatDateTime(v) : '—');

export function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
}

export function AndroidCard({ title, icon, badge, action, children }: {
  title: string; icon?: ReactNode; badge?: ReactNode; action?: ReactNode; children?: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {icon}
        <h2 className="text-base font-semibold text-text-primary">{title}</h2>
        {badge}
        {action && <span className="ml-auto flex flex-wrap gap-2">{action}</span>}
      </div>
      {children}
    </section>
  );
}

export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-text-muted">{label}</dt>
      <dd className="text-sm text-text-primary break-words">{children}</dd>
    </div>
  );
}

export function Labeled({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="text-xs text-text-muted">{label}</span>
      <div className="mt-1">{children}</div>
      {hint && <span className="mt-0.5 block text-[11px] text-text-muted">{hint}</span>}
    </label>
  );
}

/** A copyable value (a token value, a link, a JSON). */
export function CopyBox({ value, label, copied, copyLabel, multiline = false }: { value: string; label: string; copied: string; copyLabel: string; multiline?: boolean }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); toast.success(copied); } catch { /* the text stays selectable */ }
  };
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <span className="text-xs text-text-muted">{label}</span>
        <button type="button" onClick={() => void copy()} aria-label={copyLabel} title={copyLabel}
          className="ml-auto inline-flex items-center gap-1 text-xs text-accent hover:underline coarse:min-h-10"><Copy className="w-3.5 h-3.5" />{copyLabel}</button>
      </div>
      {multiline
        ? <textarea readOnly value={value} rows={4} className={`${fieldClass} font-mono text-xs`} onFocus={(e) => e.currentTarget.select()} />
        : <input readOnly value={value} className={`${fieldClass} font-mono text-xs`} onFocus={(e) => e.currentTarget.select()} />}
    </div>
  );
}

/** A copyable value with the console's own labels. */
export function CopyValue({ value, label = '', multiline }: { value: string; label?: string; multiline?: boolean }) {
  const { t } = useTranslation();
  return <CopyBox value={value} label={label} multiline={multiline} copied={t('android.common.copied') || 'Copied'} copyLabel={t('android.common.copy') || 'Copy'} />;
}
