import { registerAuditActions } from '../audit';

// =============================================================================
// The audit actions of the remote assistance (P0-15 §4.6, §0.1 of the spec: each session audited critical — who, the
// console's address, the step-up, the device, the mode, the duration), declared once by modules/remote.ts. No token, no
// image and no typed text ever in an entry (the number of input events only); an entry names the row remote_sessions
// (target remote_session/<id>, device) and the command of the queue (links.command).
//   remote.session_requested             critical, written in the transaction of the request (before its commit):
//                                        device, mode, reason and ticket (optional), channel, side, organisation of
//                                        the operator, the console's address, the strict step-up
//   remote.session_consented             the device took the session (/accept, T4): the mode it took (nothing is asked
//                                        of its user, §0.1 rule 1)
//   remote.session_started               critical: both ends attached (T5), the console's address, the step-up
//   remote.session_escalation_granted    critical: the control granted by the server after the technician's strict
//                                        step-up (§0.1 rule 3), the console's address
//   remote.session_control_released      the technician went back to the view
//   remote.session_viewer_reattached     a second attachment of the viewer replaced the first (T5)
//   remote.session_ended                 protective: who, when, device, mode, duration, endedBy, endReason, bytes, input
//                                        events, reason, ticket (an end after the start, an expiry or a failure)
//   remote.session_cancelled             protective: the session ended before its start (the operator, an approval
//                                        denied, the conditions lost, the freeze)
//   remote.settings_change_requested     critical: a change of the settings filed for approval
//   remote.settings_changed              critical: the settings changed at the execution of the approval
// =============================================================================

let registered = false;

export function registerRemoteAuditActions(): void {
  if (registered) return;
  registered = true;
  registerAuditActions([
    { name: 'remote.session_requested', criticality: 'critical', label: 'Remote assistance session requested' },
    { name: 'remote.session_consented', criticality: 'standard', label: 'Remote assistance session taken by the device' },
    { name: 'remote.session_started', criticality: 'critical', label: 'Remote assistance session started' },
    { name: 'remote.session_escalation_granted', criticality: 'critical', label: 'Remote control granted during a session' },
    { name: 'remote.session_control_released', criticality: 'standard', label: 'Remote control released during a session' },
    { name: 'remote.session_viewer_reattached', criticality: 'standard', label: 'Remote assistance viewer reattached' },
    { name: 'remote.session_ended', criticality: 'protective', label: 'Remote assistance session ended' },
    { name: 'remote.session_cancelled', criticality: 'protective', label: 'Remote assistance session cancelled' },
    { name: 'remote.settings_change_requested', criticality: 'critical', label: 'Change of the remote assistance settings requested' },
    { name: 'remote.settings_changed', criticality: 'critical', label: 'Remote assistance settings changed' },
  ]);
}
