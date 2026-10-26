import { useState, type ReactNode } from 'react';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Check, Copy, type LucideIcon } from 'lucide-react';
import { copyText } from '@/utils/clipboard';

// The one card style of a device record (it replaces the three styles of the former overview): a titled card, rows of
// label and value that stack on a phone, and a copy button that stays visible on touch screens (hover elsewhere).

export type InfoCardTone = 'default' | 'danger' | 'warning';

const TONE_BORDER: Record<InfoCardTone, string> = {
  default: 'border-border',
  danger: 'border-red-400/40',
  warning: 'border-amber-400/40',
};

export function InfoCard({ icon: Icon, title, action, tone = 'default', className, children, id }: {
  icon?: LucideIcon; title: ReactNode;
  /** Right of the title (a link, a small button). */
  action?: ReactNode;
  tone?: InfoCardTone; className?: string; children: ReactNode;
  /** Anchor of the card (a link from another card). */
  id?: string;
}) {
  return (
    <section id={id} className={clsx('rounded-xl border bg-bg-secondary p-4 min-w-0', TONE_BORDER[tone], className)}>
      <header className="mb-3 flex items-center gap-2 min-w-0">
        {Icon && <Icon className={clsx('w-4 h-4 shrink-0', tone === 'danger' ? 'text-red-400' : tone === 'warning' ? 'text-amber-400' : 'text-text-muted')} />}
        <h3 className="text-sm font-semibold text-text-primary truncate">{title}</h3>
        {action && <div className="ml-auto shrink-0">{action}</div>}
      </header>
      {children}
    </section>
  );
}

/** Copy a value to the clipboard, with a toast. Always visible on touch (coarse), on hover of its row elsewhere. */
export function CopyButton({ value, label, className }: { value: string; label?: string; className?: string }) {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  const copy = async () => {
    let ok = false;
    try { ok = await copyText(value); } catch { ok = false; }
    if (ok) {
      toast.success(t('mdm.ui.copied') || 'Copied');
      setDone(true);
      window.setTimeout(() => setDone(false), 1500);
    } else {
      toast.error(t('mdm.ui.copyFailed') || 'Could not copy');
    }
  };
  return (
    <button
      type="button"
      onClick={() => { void copy(); }}
      aria-label={label ?? (t('mdm.ui.copy') || 'Copy')}
      title={label ?? (t('mdm.ui.copy') || 'Copy')}
      className={clsx(
        'inline-flex shrink-0 items-center justify-center rounded p-1 text-text-muted hover:text-text-primary',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:opacity-100',
        'coarse:min-h-10 coarse:min-w-10 can-hover:opacity-0 can-hover:group-hover:opacity-100',
        className,
      )}
    >
      {done ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

/** One row of a card: label and value side by side from sm, stacked on a phone. `copy`: the text to copy (the value). */
export function InfoRow({ label, value, copy, mono = false, className }: {
  label: ReactNode; value: ReactNode;
  copy?: string | null;
  mono?: boolean; className?: string;
}) {
  const empty = value === null || value === undefined || value === '';
  return (
    <div className={clsx('group grid grid-cols-1 gap-0.5 py-1.5 sm:grid-cols-[minmax(0,40%)_minmax(0,1fr)] sm:gap-3', className)}>
      <dt className="text-xs text-text-muted sm:text-sm">{label}</dt>
      <dd className={clsx('flex min-w-0 items-center gap-1 text-sm text-text-primary', mono && 'font-mono text-[13px]')}>
        <span className="min-w-0 break-words">{empty ? '—' : value}</span>
        {copy && !empty && <CopyButton value={copy} />}
      </dd>
    </div>
  );
}

/** The rows of a card (a definition list). */
export function InfoRows({ children, className }: { children: ReactNode; className?: string }) {
  return <dl className={clsx('divide-y divide-border/60', className)}>{children}</dl>;
}
