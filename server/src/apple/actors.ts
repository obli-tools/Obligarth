import type { DbActor } from '../db/context';

// =============================================================================
// Actors of the apple-edge integration (docs: integration-apple-edge §3.4;
// rls-tenant §7.3): the database actors of its entries into the brain, and
// the X-Obligarth-Actor sent to apple-edge (an opaque reference there:
// user:<id>, job:<queue>, integration:<name>, enrollment:<flow>).
// =============================================================================

/** The DDM relay (POST /internal/apple-edge/ddm). */
export const EDGE_INTEGRATION: DbActor = Object.freeze({ type: 'integration', name: 'apple-edge' }) as DbActor;
/** Notifications of Apps and Books. */
export const VPP_INTEGRATION: DbActor = Object.freeze({ type: 'integration', name: 'apple-vpp' }) as DbActor;
/** Enrollment flows: OTA, ADE (url and web view), account-driven (BYOD). */
export const ENROLL_OTA: DbActor = Object.freeze({ type: 'enrollment', name: 'enroll' }) as DbActor;
export const ENROLL_ADE_WEB: DbActor = Object.freeze({ type: 'enrollment', name: 'ade-web' }) as DbActor;
export const ENROLL_BYOD: DbActor = Object.freeze({ type: 'enrollment', name: 'byod' }) as DbActor;

/** The X-Obligarth-Actor of a database actor (100 characters at most). */
export function edgeActorOf(actor: DbActor | null | undefined): string {
  if (!actor) return 'job:unknown';
  switch (actor.type) {
    case 'user': return `user:${actor.userId}`;
    case 'job': return `job:${actor.name}`.slice(0, 100);
    case 'integration': return `integration:${actor.name}`.slice(0, 100);
    case 'enrollment': return `enrollment:${actor.name}`.slice(0, 100);
    default: return `anonymous:${actor.name}`.slice(0, 100);
  }
}
