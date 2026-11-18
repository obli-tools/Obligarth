import type { DbActor } from '../../db/context';

// =============================================================================
// Obliwatch integration (brief GTH-01..09; plan §0 F8): the switch of the instance and the constants of the module.
//   OBLIWATCH_INTEGRATION=off|on  off by default: nothing is mounted (read API, console consent routes), no minute
//                                 step, no restrictable action. Read per call, so a test can flip it before createApp().
// Obliwatch's URL is not configured here: it is discovered from Obligate's connected apps (app type 'obliwatch'),
// as Obliguard's (security/obliguard.ts), by the push of lot L3.
// =============================================================================

export function obliwatchIntegrationEnabled(): boolean {
  // The exact value 'on' only (as documented): 'ON', ' on' or a quoted value leave the integration off.
  return process.env.OBLIWATCH_INTEGRATION === 'on';
}

/** The app type of Obliwatch at Obligate: the only `azp` (and sub app:<type>) the read API accepts. */
export const OBLIWATCH_APP = 'obliwatch';

/** The database actor of the integration (audit ref i:obliwatch). */
export const OBLIWATCH_ACTOR: DbActor = { type: 'integration', name: 'obliwatch' };

/** Requests per minute and per (calling app, tenant) on the read API (plan §0 F7). */
export const OBLIWATCH_RPM = 60;

/** Body size of the read API's JSON parser (the routes of L5 post small bodies only). */
export const OBLIWATCH_JSON_LIMIT = '64kb';
