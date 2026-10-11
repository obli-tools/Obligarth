import { registerAdeHandlers } from './handlers.ade';
import { registerApnsHandlers } from './handlers.apns';
import { registerMdmHandlers } from './handlers.mdm';
import { registerSecurityHandlers } from './handlers.security';
import { registerTenantHandlers } from './handlers.tenant';

// =============================================================================
// The handlers of apple-edge's events (docs: integration-apple-edge §7.4),
// registered with the outbox consumer of the durable queue (jobs/outbox/): the
// 32 types of the catalogue, two of them with a handler per scope, 34 in all.
//   handlers.tenant.ts    tenant.* (lot B1)
//   handlers.mdm.ts       mdm.*, scep.* (enrollment cycles, commands, presence)
//   handlers.security.ts  security.*, device.*
//   handlers.apns.ts      apns.*
//   handlers.ade.ts       ade.*
// With every handler delivered (lot B3), OUTBOX_CONSUMER may be turned on; an
// event of a type or a version the brain does not know goes to the dead
// letters (redrivable once a later version handles it).
// =============================================================================

/** The (scope, type) pairs of the catalogue: one handler each, checked at the start (§7.4, criterion 3). */
export const APPLE_OUTBOX_CATALOGUE: ReadonlyArray<readonly ['tenant' | 'platform', string]> = Object.freeze([
  ['tenant', 'mdm.authenticate'], ['tenant', 'mdm.token_update'], ['tenant', 'mdm.checkout'], ['tenant', 'mdm.command_delivered'],
  ['tenant', 'mdm.command_result'], ['tenant', 'mdm.command_expired'], ['tenant', 'mdm.seen_batch'], ['tenant', 'scep.certificate_issued'],
  ['tenant', 'security.topic_mismatch'], ['tenant', 'security.identity_expired'], ['tenant', 'security.identity_revoked'],
  ['tenant', 'security.identity_mismatch'], ['tenant', 'security.device_id_conflict'], ['platform', 'security.device_id_conflict'],
  ['platform', 'security.foreign_certificate'], ['tenant', 'device.id_released'], ['tenant', 'device.transfer_completed'],
  ['platform', 'device.transfer_completed'], ['platform', 'tenant.created'], ['platform', 'tenant.state_changed'],
  ['platform', 'tenant.load_failed'], ['tenant', 'tenant.ca_rotated'], ['tenant', 'apns.push_failed'], ['tenant', 'apns.token_inactive'],
  ['tenant', 'apns.throttled'], ['tenant', 'apns.certificate_expiring'], ['tenant', 'apns.certificate_activated'],
  ['tenant', 'apns.certificate_expired'], ['tenant', 'ade.token_activated'], ['tenant', 'ade.devices'], ['tenant', 'ade.profile_assignment'],
  ['tenant', 'ade.sync_error'], ['tenant', 'ade.terms_not_signed'], ['tenant', 'ade.token_expiring'],
] as const);

export function registerAppleOutboxHandlers(): void {
  registerTenantHandlers();
  registerMdmHandlers();
  registerSecurityHandlers();
  registerApnsHandlers();
  registerAdeHandlers();
}
