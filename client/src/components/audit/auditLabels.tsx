import type { TFunction } from 'i18next';
import type { AuditActorSide, AuditCriticality, AuditOutcome } from '@obligarth/shared';
import { cn } from '@/utils/cn';

// Labels and pills of the hardened journal, shared by the list, the detail
// drawer and the status banner. An action's label comes from the catalogue of
// translations (audit.actions.<family>_<verb>), with the raw name as fallback.

export function actionKey(action: string): string {
  return `audit.actions.${action.replace(/\./g, '_')}`;
}

/** The action's own label; else its family's label and the verb; else the
 *  raw name (an action of a module the translations do not know yet). */
export function actionLabel(t: TFunction, action: string): string {
  const exact = String(t(actionKey(action), { defaultValue: action }));
  if (exact !== action) return exact;
  const dot = action.indexOf('.');
  if (dot > 0) {
    const familyKey = `audit.families.${action.slice(0, dot)}`;
    const family = String(t(familyKey, { defaultValue: familyKey }));
    if (family !== familyKey) return `${family} · ${action.slice(dot + 1).replace(/_/g, ' ')}`;
  }
  return action;
}

export function when(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

const SIDE_CLASS: Record<AuditActorSide, string> = {
  msp: 'bg-accent/10 text-accent border-accent/30',
  client: 'bg-emerald-400/10 text-emerald-400 border-emerald-400/30',
  system: 'bg-bg-tertiary text-text-secondary border-transparent',
  unknown: 'bg-bg-tertiary text-text-muted border-transparent',
};

export function sideLabel(t: TFunction, side: AuditActorSide): string {
  switch (side) {
    case 'msp': return t('audit.side.msp') || 'MSP';
    case 'client': return t('audit.side.client') || 'Client';
    case 'system': return t('audit.side.system') || 'System';
    default: return t('audit.side.unknown') || 'Unknown';
  }
}

export function SidePill({ side, t }: { side: AuditActorSide; t: TFunction }) {
  return (
    <span className={cn('inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border whitespace-nowrap', SIDE_CLASS[side] ?? SIDE_CLASS.unknown)}>
      {sideLabel(t, side)}
    </span>
  );
}

const OUTCOME_CLASS: Record<AuditOutcome, string> = {
  success: 'text-green-400',
  failure: 'text-red-400',
  denied: 'text-red-400',
  requested: 'text-yellow-400',
  scheduled: 'text-yellow-400',
  cancelled: 'text-text-muted',
};

export function outcomeLabel(t: TFunction, outcome: AuditOutcome): string {
  switch (outcome) {
    case 'success': return t('audit.outcome.success') || 'Success';
    case 'failure': return t('audit.outcome.failure') || 'Failure';
    case 'denied': return t('audit.outcome.denied') || 'Denied';
    case 'requested': return t('audit.outcome.requested') || 'Requested';
    case 'scheduled': return t('audit.outcome.scheduled') || 'Scheduled';
    case 'cancelled': return t('audit.outcome.cancelled') || 'Cancelled';
    default: return outcome;
  }
}

export function OutcomeText({ outcome, t }: { outcome: AuditOutcome; t: TFunction }) {
  return <span className={cn('text-[11px] font-medium whitespace-nowrap', OUTCOME_CLASS[outcome] ?? 'text-text-secondary')}>{outcomeLabel(t, outcome)}</span>;
}

export function criticalityLabel(t: TFunction, c: AuditCriticality): string {
  switch (c) {
    case 'critical': return t('audit.criticality.critical') || 'Critical';
    case 'protective': return t('audit.criticality.protective') || 'Protective';
    default: return t('audit.criticality.standard') || 'Standard';
  }
}

export function CriticalityPill({ criticality, t }: { criticality: AuditCriticality; t: TFunction }) {
  const c = criticality === 'critical'
    ? 'bg-red-400/10 text-red-400 border-red-400/30'
    : criticality === 'protective'
      ? 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30'
      : 'bg-bg-tertiary text-text-muted border-transparent';
  return <span className={cn('inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border whitespace-nowrap', c)}>{criticalityLabel(t, criticality)}</span>;
}

/** "Before the hardening" (an entry migrated from the old table) and
 *  "replayed" (written late from the local spool). */
export function EntryFlags({ legacy, late, t }: { legacy: boolean; late: boolean; t: TFunction }) {
  if (!legacy && !late) return null;
  return (
    <span className="inline-flex gap-1">
      {legacy && (
        <span className="inline-block px-1.5 py-0.5 rounded text-[10px] border border-transparent bg-bg-tertiary text-text-muted whitespace-nowrap"
          title={t('audit.legacyHint') || 'Written before the hardened journal: no author snapshot, chained at the migration'}>
          {t('audit.legacy') || 'Before hardening'}
        </span>
      )}
      {late && (
        <span className="inline-block px-1.5 py-0.5 rounded text-[10px] border border-yellow-400/30 bg-yellow-400/10 text-yellow-400 whitespace-nowrap"
          title={t('audit.lateHint') || 'Written late from the local spool (the journal was unavailable)'}>
          {t('audit.late') || 'Replayed'}
        </span>
      )}
    </span>
  );
}

/** The API's error text, or a fallback. */
export function errorText(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { error?: string } } };
  return e?.response?.data?.error || fallback;
}
