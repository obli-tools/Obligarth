import { useTranslation } from 'react-i18next';
import { CheckCircle2, MinusCircle, XCircle } from 'lucide-react';

// A yes / no value of a device record, coloured by whether it is the good answer (passcode set: yes is good; unknown
// sources allowed: yes is bad). Neutral when neither is (Find My, roaming). Null: not reported.

export function Flag({ value, good = true, neutral = false }: { value: boolean | null | undefined; good?: boolean; neutral?: boolean }) {
  const { t } = useTranslation();
  if (value === null || value === undefined) return <span className="text-text-muted">—</span>;
  const label = value ? (t('deviceSummary.yes') || 'Yes') : (t('deviceSummary.no') || 'No');
  if (neutral) {
    return (
      <span className="inline-flex items-center gap-1.5 text-text-primary">
        <MinusCircle className="w-3.5 h-3.5 shrink-0 text-text-muted" aria-hidden />{label}
      </span>
    );
  }
  const ok = value === good;
  return (
    <span className={`inline-flex items-center gap-1.5 ${ok ? 'text-green-400' : 'text-red-400'}`}>
      {ok ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden /> : <XCircle className="w-3.5 h-3.5 shrink-0" aria-hidden />}
      {label}
    </span>
  );
}
