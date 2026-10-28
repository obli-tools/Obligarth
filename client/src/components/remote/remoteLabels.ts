import type { TFunction } from 'i18next';
import type { RemoteEndReason, RemoteEndedBy, RemoteMode, RemoteRequesterSide, RemoteSessionState } from '@obligarth/shared';
import { trCode } from '@/utils/apiError';

// The words of the remote assistance in the console (P0-15 §7): states, modes, reasons of the end, sides.

type Tone = 'green' | 'gray' | 'blue' | 'red' | 'amber';

export const STATE_TONE: Record<RemoteSessionState, Tone> = {
  awaiting_approval: 'amber', queued: 'blue', awaiting_consent: 'blue', connecting: 'blue', live: 'green',
  ended: 'gray', expired: 'gray', cancelled: 'gray', failed: 'red',
};

const STATE_FALLBACK: Record<RemoteSessionState, string> = {
  awaiting_approval: 'Awaiting approval', queued: 'Waiting for the device', awaiting_consent: 'Starting the capture',
  connecting: 'Connecting', live: 'In progress', ended: 'Ended', expired: 'Expired', cancelled: 'Cancelled', failed: 'Failed',
};

const END_FALLBACK: Record<RemoteEndReason, string> = {
  operator: 'Ended by the technician',
  projection_denied: 'The screen capture was not authorised on the device',
  device_timeout: 'The device did not answer in time',
  idle: 'Ended after a period without activity',
  max_duration: 'Maximum duration reached',
  screen_off_timeout: 'The screen of the device stayed off too long',
  freeze: 'The tenant was frozen',
  revoked: 'A right or a condition of the session was withdrawn',
  agent_error: 'Error of the agent on the device',
  server_restart: 'The server restarted',
  approval_denied: 'The approval was refused',
  approval_expired: 'The approval request expired',
};

const ENDED_BY_FALLBACK: Record<RemoteEndedBy, string> = { operator: 'the technician', user: 'the device', system: 'the system' };

export const remoteStateLabel = (s: RemoteSessionState): string => trCode(`remote.state.${s}`, STATE_FALLBACK[s] ?? s);
export const remoteEndReasonLabel = (r: RemoteEndReason): string => trCode(`remote.endReason.${r}`, END_FALLBACK[r] ?? r);
export const remoteEndedByLabel = (b: RemoteEndedBy): string => trCode(`remote.endedBy.${b}`, ENDED_BY_FALLBACK[b] ?? b);

export function remoteModeLabel(t: TFunction, m: RemoteMode): string {
  return m === 'control' ? (t('remote.mode.control') || 'Control') : (t('remote.mode.view') || 'View');
}

export function remoteSideLabel(t: TFunction, s: RemoteRequesterSide): string {
  return s === 'msp' ? (t('remote.side.msp') || 'Provider') : (t('remote.side.client') || 'Client');
}

/** 75 → "1 min 15 s"; null → "—". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return '—';
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h > 0) return `${h} h ${String(m).padStart(2, '0')} min`;
  if (m > 0) return `${m} min ${String(r).padStart(2, '0')} s`;
  return `${r} s`;
}

/** Seconds left until an ISO time (0 when past). */
export const secondsUntil = (iso: string | null | undefined, now = Date.now()): number =>
  iso ? Math.max(0, Math.ceil((new Date(iso).getTime() - now) / 1000)) : 0;
