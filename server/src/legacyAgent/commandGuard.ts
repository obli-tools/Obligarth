import { LEGACY_AGENT_COMMANDS_SENSITIVE_ACTION, LEGACY_AGENT_SENSITIVE_COMMAND_TYPES } from '@obligarth/shared';
import { readSettings } from '../guard/settings';
import { restrictionService, type RestrictionLevel } from '../services/restriction.service';
import type { CommandSpec } from './commands';

// =============================================================================
// The restriction a HUMAN request of a bridge agent command goes through (review F115, decision of the owners): the
// type's own key of the matrix (legacy_agent.apps, .update, .restart, .policy_commands, no level by default) as
// before; and, when the tenant turned on the guard setting legacyAgentCommandsSensitive (GET/PUT /api/guard/settings,
// off by default), the commands of LEGACY_AGENT_SENSITIVE_COMMAND_TYPES go through legacy_agent.commands_sensitive
// (floor 'sensitive': a second factor) unless their own key asks more. One function for every path: the record of a
// device and the batch (routes.ts), the MCP server and the approval of its authorizations (console.ts). The automatic
// flows (harvest.ts, autoUpdate.ts) never call it: they read their own key of the matrix as before, so the setting
// never stops them.
// =============================================================================

const RANK: Record<RestrictionLevel, number> = { none: 0, sensitive: 1, restricted: 2 };

/** Is this type one the setting makes 'sensitive'? */
export const isSensitiveCommandType = (type: string): boolean => (LEGACY_AGENT_SENSITIVE_COMMAND_TYPES as readonly string[]).includes(type);

/** The dependencies, an object so that the local tests replace them (mock.method). */
export const commandGuardDeps = {
  settingOn: async (tenantId: number): Promise<boolean> => (await readSettings(tenantId)).legacy_agent_commands_sensitive,
  level: (tenantId: number, actionKey: string, deviceIds: number[]): Promise<RestrictionLevel> =>
    restrictionService.getLevelFor({ tenantId, actionKey, deviceIds }),
};

/**
 * The key of the restrictions matrix a human request of `spec` on `deviceIds` goes through; null: none (the type has
 * no restriction). The type's own key unless the setting is on, the type is one it covers, and the setting's key is
 * stricter than the type's own key on these devices (on a tie the type's own key stays: an authorization or a step-up
 * already asked for it keeps holding). `settingOn`: the setting already read by the caller (a loop over the types of
 * a menu reads it once, review T1-R3-6); omitted, it is read here.
 */
export async function commandRestrictionKey(tenantId: number, spec: Pick<CommandSpec, 'type' | 'restrictionKey'>, deviceIds: number[],
  settingOn?: boolean): Promise<string | null> {
  const own = spec.restrictionKey;
  if (!own || !isSensitiveCommandType(spec.type)) return own;
  if (!(settingOn ?? await commandGuardDeps.settingOn(tenantId))) return own;
  const [mine, setting] = await Promise.all([
    commandGuardDeps.level(tenantId, own, deviceIds),
    commandGuardDeps.level(tenantId, LEGACY_AGENT_COMMANDS_SENSITIVE_ACTION, deviceIds),
  ]);
  return RANK[setting] > RANK[mine] ? LEGACY_AGENT_COMMANDS_SENSITIVE_ACTION : own;
}
