import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import type { BenchProvisioningState, BenchRolePolicy, BenchStationStatus } from '@obligarth/shared';
import { isStepUpHandled } from '@/api/client';
import { apiErrorMessage } from '@/utils/apiError';

// The look of the suite (the inventory of /devices): fields and cards without borders, lists without separators whose rows
// light up on hover, states as dots. Shared by the platform page of the bench stations and the Bench tab of the agent.

export const fieldCls = 'mt-1 w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 disabled:opacity-50 coarse:min-h-10';
export const labelCls = 'block text-xs font-medium text-text-muted';
export const cardCls = 'rounded-xl bg-bg-secondary p-4';
export const cardTitleCls = 'mb-3 flex items-center gap-1.5 text-sm font-semibold text-text-primary';
export const listCls = 'overflow-x-auto rounded-xl bg-bg-secondary';
export const headCls = 'bg-bg-tertiary/50 text-left text-[10px] font-medium uppercase tracking-wider text-text-muted';
export const thCls = 'whitespace-nowrap px-4 py-2 font-medium';
export const rowCls = 'transition-colors hover:bg-bg-tertiary';
export const tdCls = 'px-4 py-2.5';
export const chipCls = (on: boolean): string => clsx('flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium transition-colors coarse:py-2',
  on ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-bg-tertiary hover:text-text-primary');
export const fmt = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleString() : '—');

export function fail(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
}

export type Tone = 'green' | 'red' | 'amber' | 'gray' | 'orange';

/** A dot and a word. */
export function Pill({ tone, text }: { tone: Tone; text: string }) {
  const dot = tone === 'green' ? 'bg-emerald-500' : tone === 'red' ? 'bg-red-500' : tone === 'amber' ? 'bg-amber-500' : tone === 'orange' ? 'bg-orange-500' : 'bg-text-muted/40';
  const txt = tone === 'red' ? 'text-red-400' : tone === 'amber' ? 'text-amber-400' : tone === 'orange' ? 'text-orange-400' : 'text-text-secondary';
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs">
      <span className={`h-2 w-2 shrink-0 rounded-full ${dot}`} aria-hidden />
      <span className={txt}>{text}</span>
    </span>
  );
}

const STATUS_TONE: Record<BenchStationStatus, Tone> = { pending: 'orange', approved: 'green', suspended: 'amber', revoked: 'gray' };

export function StationStatusPill({ status }: { status: BenchStationStatus }) {
  const { t } = useTranslation();
  const fallback: Record<BenchStationStatus, string> = { pending: 'Pending', approved: 'Approved', suspended: 'Suspended', revoked: 'Revoked' };
  return <Pill tone={STATUS_TONE[status] ?? 'gray'} text={t(`bench.stations.status.${status}`) || fallback[status] || status} />;
}

const STATE_TONE: Record<BenchProvisioningState, Tone> = {
  planned: 'gray', token_issued: 'amber', enrolled: 'amber', completed: 'green', failed: 'red', abandoned: 'gray', expired: 'gray',
};

export function ProvisioningStatePill({ state }: { state: BenchProvisioningState }) {
  const { t } = useTranslation();
  const fallback: Record<BenchProvisioningState, string> = {
    planned: 'Planned', token_issued: 'Token issued', enrolled: 'Enrolled', completed: 'Completed', failed: 'Failed', abandoned: 'Abandoned', expired: 'Expired',
  };
  return <Pill tone={STATE_TONE[state] ?? 'gray'} text={t(`bench.history.state.${state}`) || fallback[state] || state} />;
}

export function useRolePolicyLabel(): (p: BenchRolePolicy) => string {
  const { t } = useTranslation();
  const fallback: Record<BenchRolePolicy, string> = {
    owner_required: 'Device owner required', owner_preferred: 'Device owner preferred', admin_only: 'Device administrator only',
  };
  return (p) => t(`bench.stations.rolePolicy.${p}`) || fallback[p] || p;
}

export function useRoleLabel(): (r: string | null | undefined) => string {
  const { t } = useTranslation();
  return (r) => (r === 'device_owner' ? (t('legacyAgent.role.device_owner') || 'Device owner')
    : r === 'device_admin' ? (t('legacyAgent.role.device_admin') || 'Device administrator')
      : r === 'inactive' ? (t('legacyAgent.role.inactive') || 'Inactive') : '—');
}

/** The text of an error code of the bench (bench.error.<code>). */
export function useBenchErrorLabel(): (code: string | null | undefined) => string {
  const { t } = useTranslation();
  return (code) => (code ? (t(`bench.error.${code}`) || code) : '—');
}
