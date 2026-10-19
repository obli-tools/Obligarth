import type { DbActor } from '../db/context';

/** The actor of the agent surface (§2): an integration, token i:legacy-agent (admitted by the bus's ACTOR_RE). */
export const LEGACY_AGENT_ACTOR: DbActor = { type: 'integration', name: 'legacy-agent' };
export const LEGACY_AGENT_ACTOR_TOKEN = 'i:legacy-agent';
/** The actor of the module's jobs. */
export const legacyAgentJobActor = (name: string): DbActor => ({ type: 'job', name });
