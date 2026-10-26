import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import type {
  ComplianceReason, ComplianceState, ConfigState, ContactState, EnrollmentState, LostModeState,
} from '@obligarth/shared';
import { Tip } from '@/components/common/Tip';

// The four separate states of a device (modele-donnees-mdm §4.4, criterion 6) and its lost mode: enrollment,
// contact (derived from the last check-in, never stored), compliance (with its reasons) and configuration. They
// replace the single status of the removed agent.

type Tone = 'green' | 'gray' | 'blue' | 'amber' | 'red' | 'violet';

const TONES: Record<Tone, { badge: string; dot: string }> = {
  green:  { badge: 'text-green-400 bg-green-400/10 border-green-400/30',    dot: 'bg-green-400' },
  gray:   { badge: 'text-gray-400 bg-gray-400/10 border-gray-400/30',       dot: 'bg-gray-400' },
  blue:   { badge: 'text-blue-400 bg-blue-400/10 border-blue-400/30',       dot: 'bg-blue-400' },
  amber:  { badge: 'text-amber-400 bg-amber-400/10 border-amber-400/30',    dot: 'bg-amber-400' },
  red:    { badge: 'text-red-400 bg-red-400/10 border-red-400/30',          dot: 'bg-red-400' },
  violet: { badge: 'text-violet-400 bg-violet-400/10 border-violet-400/30', dot: 'bg-violet-400' },
};

export const ENROLLMENT_TONE: Record<EnrollmentState, Tone> = {
  enrolling: 'blue', awaiting_configuration: 'blue', enrolled: 'green', unenrolling: 'amber', unenrolled: 'gray',
};
export const CONTACT_TONE: Record<ContactState, Tone> = { recent: 'green', quiet: 'gray', stale: 'amber', never: 'gray' };
export const COMPLIANCE_TONE: Record<ComplianceState, Tone> = { compliant: 'green', non_compliant: 'red', unknown: 'gray', exempt: 'violet' };
export const CONFIG_TONE: Record<ConfigState, Tone> = { applied: 'green', pending: 'blue', error: 'red', unknown: 'gray' };

/** Dot colour of a state, for chips and legends. */
export const toneDot = (tone: Tone): string => TONES[tone].dot;

const ENROLLMENT_FALLBACK: Record<EnrollmentState, string> = {
  enrolling: 'Enrolling', awaiting_configuration: 'Awaiting configuration', enrolled: 'Enrolled', unenrolling: 'Leaving management', unenrolled: 'Unenrolled',
};
const CONTACT_FALLBACK: Record<ContactState, string> = { recent: 'Recent contact', quiet: 'Quiet', stale: 'No contact', never: 'Never seen' };
const COMPLIANCE_FALLBACK: Record<ComplianceState, string> = { compliant: 'Compliant', non_compliant: 'Non compliant', unknown: 'Compliance unknown', exempt: 'Exempt' };
const CONFIG_FALLBACK: Record<ConfigState, string> = { applied: 'Configuration applied', pending: 'Configuration pending', error: 'Configuration error', unknown: 'Configuration unknown' };
const LOST_FALLBACK: Record<LostModeState, string> = { off: 'Off', enabling: 'Lost mode: enabling', on: 'Lost mode', disabling: 'Lost mode: disabling' };
const REASON_FALLBACK: Record<ComplianceReason['code'], string> = {
  config_error: 'A configuration could not be applied',
  passcode: 'The passcode does not meet the policy',
  os_update_overdue: 'An operating system update is overdue',
  stale: 'No contact for too long',
  supervision_required: 'Supervision is required',
  // The Android evaluator's (android/inventory/compliance.ts).
  os_outdated: 'The security patch level is too old',
  amapi_noncompliant: 'The device does not apply some settings of its policy',
  integrity_at_risk: 'The device integrity is at risk',
  no_contact: 'No status report for too long',
  policy_not_applied: 'The latest policy is not applied yet',
  management_disabled: 'Management is disabled on the device',
};

export const enrollmentLabel = (t: TFunction, s: EnrollmentState): string => t(`mdm.enrollmentState.${s}`) || ENROLLMENT_FALLBACK[s] || s;
export const contactLabel = (t: TFunction, s: ContactState): string => t(`mdm.contactState.${s}`) || CONTACT_FALLBACK[s] || s;
export const complianceLabel = (t: TFunction, s: ComplianceState): string => t(`mdm.complianceState.${s}`) || COMPLIANCE_FALLBACK[s] || s;
export const configLabel = (t: TFunction, s: ConfigState): string => t(`mdm.configState.${s}`) || CONFIG_FALLBACK[s] || s;
export const lostModeLabel = (t: TFunction, s: LostModeState): string => t(`mdm.lostModeState.${s}`) || LOST_FALLBACK[s] || s;
export const complianceReasonLabel = (t: TFunction, code: ComplianceReason['code']): string =>
  t(`mdm.complianceReason.${code}`) || REASON_FALLBACK[code] || code;

export function StateBadge({ tone, label, size = 'sm', pulse = false, title }: {
  tone: Tone; label: string; size?: 'sm' | 'md'; pulse?: boolean; title?: string;
}) {
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex items-center gap-1.5 font-medium border rounded-full whitespace-nowrap',
        size === 'sm' ? 'text-[11px] px-2 py-0.5' : 'text-xs px-2.5 py-1',
        TONES[tone].badge,
      )}
    >
      <span className={clsx('rounded-full w-1.5 h-1.5', TONES[tone].dot, pulse && 'animate-pulse')} />
      {label}
    </span>
  );
}

export function EnrollmentBadge({ state, size }: { state: EnrollmentState; size?: 'sm' | 'md' }) {
  const { t } = useTranslation();
  return <StateBadge tone={ENROLLMENT_TONE[state] ?? 'gray'} label={enrollmentLabel(t, state)} size={size} pulse={state === 'enrolling' || state === 'unenrolling'} />;
}

export function ContactBadge({ state, lastCheckinAt, size }: { state: ContactState; lastCheckinAt?: string | null; size?: 'sm' | 'md' }) {
  const { t } = useTranslation();
  return (
    <StateBadge
      tone={CONTACT_TONE[state] ?? 'gray'}
      label={contactLabel(t, state)}
      size={size}
      title={lastCheckinAt ? new Date(lastCheckinAt).toLocaleString() : undefined}
    />
  );
}

/** Compliance, with its reasons on hover (or on tap on a touch screen). */
export function ComplianceBadge({ state, reasons, size }: { state: ComplianceState; reasons?: ComplianceReason[]; size?: 'sm' | 'md' }) {
  const { t } = useTranslation();
  const badge = <StateBadge tone={COMPLIANCE_TONE[state] ?? 'gray'} label={complianceLabel(t, state)} size={size} />;
  if (state !== 'non_compliant' || !reasons?.length) return badge;
  return (
    <Tip
      content={(
        <ul className="space-y-0.5 text-left">
          {reasons.map((r, i) => <li key={`${r.code}-${i}`}>{complianceReasonLabel(t, r.code)}</li>)}
        </ul>
      )}
    >
      {badge}
    </Tip>
  );
}

export function ConfigBadge({ state, size }: { state: ConfigState; size?: 'sm' | 'md' }) {
  const { t } = useTranslation();
  return <StateBadge tone={CONFIG_TONE[state] ?? 'gray'} label={configLabel(t, state)} size={size} pulse={state === 'pending'} />;
}

/** Shown only while the lost mode is on or changing. */
export function LostModeBadge({ state, size, pulse }: {
  state: LostModeState; size?: 'sm' | 'md';
  /** Pulse even when on (a list row, where it must catch the eye); by default only while changing. */
  pulse?: boolean;
}) {
  const { t } = useTranslation();
  if (state === 'off') return null;
  return <StateBadge tone="red" label={lostModeLabel(t, state)} size={size} pulse={pulse || state !== 'on'} />;
}

/**
 * The states of a device in a row: the enrollment always; the contact, the compliance and the configuration only
 * when they say something (an enrolled device in recent contact, compliant and configured shows one green badge).
 */
export function DeviceStateBadges({ device, size = 'sm', all = false, pulseLost = false }: {
  device: {
    enrollmentState: EnrollmentState; contactState: ContactState; lastCheckinAt: string | null;
    complianceState: ComplianceState; complianceReasons: ComplianceReason[]; configState: ConfigState; lostModeState: LostModeState;
  };
  size?: 'sm' | 'md';
  /** Every state, whatever its value (device page). */
  all?: boolean;
  /** The lost-mode badge pulses even when on (a list row). */
  pulseLost?: boolean;
}) {
  const managed = device.enrollmentState !== 'unenrolled';
  return (
    <span className="inline-flex items-center gap-1 flex-wrap">
      <EnrollmentBadge state={device.enrollmentState} size={size} />
      {(all || (managed && (device.contactState === 'stale' || device.contactState === 'never'))) && (
        <ContactBadge state={device.contactState} lastCheckinAt={device.lastCheckinAt} size={size} />
      )}
      {(all || (managed && device.complianceState === 'non_compliant')) && (
        <ComplianceBadge state={device.complianceState} reasons={device.complianceReasons} size={size} />
      )}
      {(all || (managed && (device.configState === 'error' || device.configState === 'pending'))) && (
        <ConfigBadge state={device.configState} size={size} />
      )}
      <LostModeBadge state={device.lostModeState} size={size} pulse={pulseLost} />
    </span>
  );
}
