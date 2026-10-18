// Enterprise states in which an AMAPI command is admitted (review AN-H1, H1R-1; android-amapi §6.5 step 2): one rule for
// the gateway (issueCommand), the command bus (enqueue) and the submission (android.commands.submit).
//   - linked: every command type;
//   - unlinking (an offboarding in progress): only WIPE and RELINQUISH_OWNERSHIP, the commands of the guarded actions
//     mdm.erase_device and mdm.remove_management the console offers, by batch, while the procedure waits for the
//     managed devices to be gone;
//   - error, pending, unlinked: none.
import type { AndroidEnterpriseRef } from './names';

export const UNLINKING_COMMANDS: ReadonlySet<string> = new Set(['WIPE', 'RELINQUISH_OWNERSHIP']);

const LINKED: ReadonlyArray<AndroidEnterpriseRef['state']> = Object.freeze(['linked'] as const);
const LINKED_OR_UNLINKING: ReadonlyArray<AndroidEnterpriseRef['state']> = Object.freeze(['linked', 'unlinking'] as const);

export function commandEnterpriseStates(type: unknown): ReadonlyArray<AndroidEnterpriseRef['state']> {
  return typeof type === 'string' && UNLINKING_COMMANDS.has(type) ? LINKED_OR_UNLINKING : LINKED;
}

/** Is a command of this type admitted for an enterprise in this state? */
export function commandAdmitted(type: unknown, state: AndroidEnterpriseRef['state'] | null | undefined): boolean {
  return !!state && commandEnterpriseStates(type).includes(state);
}
