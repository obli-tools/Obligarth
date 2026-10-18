// Follow-ups of the enrollment and inventory handlers (G-A3: a handler never calls the network; its follow-ups are
// durable jobs sent in its transaction). jobs.ts binds these hooks to the queues of section 22.7; the tests replace
// them by recorders. Payloads: internal identifiers only (never an AMAPI name of a device in a job: G-A4).
import type { Knex } from 'knex';

export interface DevicePayload { tenantId: number; deviceId: number }
export interface QuarantinePayload { tenantId: number; quarantineId: number }
export interface CleanupPayload { tenantId: number; deviceId: number }
export interface ProfilePayload { tenantId: number; profileId: string }

type Sender<P> = (trx: Knex.Transaction, p: P) => Promise<unknown>;
const none = async (): Promise<undefined> => undefined;

export const androidSenders = {
  /** android.device-onboard: own policy compiled, pushed, then devices.patch policyName. */
  onboard: none as Sender<DevicePayload>,
  /** android.device-hold: the device enrolled with a token that requires an approval is DISABLED meanwhile. */
  hold: none as Sender<DevicePayload>,
  /** android.device-quarantine: DISABLED under its minimal policy, the operator decides. */
  quarantine: none as Sender<QuarantinePayload>,
  /** android.device-reject: devices.delete within the narrow window, conditions checked again. */
  reject: none as Sender<QuarantinePayload>,
  /** android.device-cleanup: deletes at Google the resource a re-enrollment replaced (previousDeviceNames). */
  cleanup: none as Sender<CleanupPayload>,
  /** android.policies.push-device: the device's own policy (stately t:<tenant>:d:<device>). */
  push: none as Sender<DevicePayload>,
  /** android.policies.enrollment-policy: the enrollment policy of a profile. */
  enrollmentPolicy: none as Sender<ProfilePayload>,
};

export function setAndroidSenders(s: Partial<typeof androidSenders>): void {
  Object.assign(androidSenders, s);
}
