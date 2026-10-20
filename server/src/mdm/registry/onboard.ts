import type { JobContext } from '../../jobs';
import type { ManagementChannel } from '../../guard/types';

// =============================================================================
// The steps of the onboarding of a device, by management channel (docs: integration-apple-edge §8.10, modele §10.4;
// android-amapi §10.4 step 8, §22.6, COH-22, lot AN-P): what the other modules do once a device of a channel is
// enrolled, run by the onboarding job of that channel, in registration order:
//   apple_mdm  apple.device-onboard, after the identity certificate of the device: the initial inventory of the
//              command queue (§8.10), the first DDM synchronisation (§9.4), the resolution of the policies;
//   amapi      android.policies.push-device, as long as the device is not attached to its own policy yet (no queue
//              of its own: file-durable L3): the resolution of the policies (its artifact amapi:policy), before the
//              compilation, the push and devices.patch policyName of the job itself.
// A step that fails fails the job (retried): steps are idempotent. Registered before jobs.start(), no I/O.
// =============================================================================

type DevicePayload = { tenantId: number; deviceId: number };

export interface OnboardStepContext {
  /** The onboarding job of the channel (its tenant context, its transactions, its actor). */
  job: JobContext<DevicePayload>;
  tenantId: number;
  deviceId: number;
}

export interface OnboardStep {
  name: string;
  run(ctx: OnboardStepContext): Promise<void>;
}

const steps = new Map<ManagementChannel, OnboardStep[]>();

/** A step of the onboarding of the devices of `channel`. */
export function registerOnboardStep(channel: ManagementChannel, step: OnboardStep): void {
  if (!/^[a-z][a-z0-9_.-]{0,40}$/.test(step.name)) throw new Error('onboard step: invalid name');
  const list = steps.get(channel) ?? [];
  if (list.some((s) => s.name === step.name)) throw new Error(`onboard step ${channel}/${step.name}: registered twice`);
  list.push(step);
  steps.set(channel, list);
}

/** The steps of a channel, in registration order. */
export function onboardStepsOf(channel: ManagementChannel): readonly OnboardStep[] {
  return steps.get(channel) ?? [];
}

/** Runs the steps of `channel` for the device of the job; returns how many ran. */
export async function runOnboardSteps(channel: ManagementChannel, ctx: OnboardStepContext): Promise<number> {
  const list = onboardStepsOf(channel);
  for (const s of list) await s.run(ctx);
  return list.length;
}
