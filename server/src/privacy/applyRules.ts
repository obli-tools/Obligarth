import type { Knex } from 'knex';
import { DEFAULT_PRIVACY_PROFILE, privacyRuleChanges, type Ownership, type PrivacyProfileRules, type PrivacyRuleKey } from '@obligarth/shared';
import { privacyRulesFor, type PrivacyRules } from '../apple/devices/privacy';
import {
  PrivacyProfileRulesSchema, androidPrivacyRulesFor, currentProfile, invalidatePrivacyProfiles, legacyAgentPrivacyRulesFor,
  lostModeLocationAllowed, type AndroidProfileRules, type LegacyAgentProfileRules,
} from './profiles';

// =============================================================================
// The rules a run of privacy.apply-profile applies (P0-13 T3; privacy/apply.ts): those in force for each channel, and
// the keys narrowed since the version in force before the publication (only those are cleaned). In the caller's
// connection or transaction, the tenant's context. No database import (unit tests).
// =============================================================================

type Q = Knex | Knex.Transaction;

export interface ApplyRules {
  ownership: Ownership;
  narrowed: ReadonlySet<PrivacyRuleKey>;
  apple: PrivacyRules;
  android: AndroidProfileRules;
  agent: LegacyAgentProfileRules;
  locate: boolean;
}

/** The rules of a version of the ownership (null: the defaults, as before the first version); null when unreadable. */
async function rulesOfVersion(q: Q, tenantId: number, ownership: Ownership, version: number | null): Promise<PrivacyProfileRules | null> {
  if (version === null) return DEFAULT_PRIVACY_PROFILE[ownership];
  const row = await q('privacy_profile_versions').where({ tenant_id: tenantId, ownership, version }).first('rules') as { rules: unknown } | undefined;
  const parsed = row ? PrivacyProfileRulesSchema.safeParse(row.rules) : null;
  return parsed?.success ? parsed.data : null;
}

/** The rules of a run: those in force (the current version, read again from the base), and the keys narrowed since
 *  `fromVersion`. Null: the ownership has no version (nothing to apply). Two publications folded into one run (the
 *  oldest fromVersion): the net narrowing. */
export async function resolveApplyRules(q: Q, tenantId: number, ownership: Ownership, fromVersion: number | null): Promise<ApplyRules | null> {
  invalidatePrivacyProfiles(tenantId);
  const current = await currentProfile(q, tenantId, ownership);
  if (!current) return null;
  // A version that cannot be read back (never: immutable rows): every key is cleaned as if narrowed.
  const from = await rulesOfVersion(q, tenantId, ownership, fromVersion);
  const narrowed = from ? privacyRuleChanges(from, current.rules).narrowed : Object.keys(current.rules) as PrivacyRuleKey[];
  return {
    ownership,
    narrowed: new Set(narrowed),
    apple: await privacyRulesFor(q, tenantId, ownership, 'Device'),
    android: await androidPrivacyRulesFor(q, tenantId, ownership),
    agent: await legacyAgentPrivacyRulesFor(q, tenantId),
    locate: await lostModeLocationAllowed(q, tenantId, ownership),
  };
}
