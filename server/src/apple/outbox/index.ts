import { registerTenantHandlers } from './handlers.tenant';

// =============================================================================
// The handlers of apple-edge's events (docs: integration-apple-edge §7.4),
// registered with the outbox consumer of the durable queue (jobs/outbox/).
// Lot B1: the tenant registry's (tenant.*); the devices, commands, security,
// push and ADE families come with lot B3. Until every handler is delivered,
// OUTBOX_CONSUMER stays off (an event without handler goes to the dead
// letters, redrivable once its handler exists).
// =============================================================================

export function registerAppleOutboxHandlers(): void {
  registerTenantHandlers();
}
