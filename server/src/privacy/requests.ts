import { z } from 'zod';
import { OWNERSHIPS, RETENTION_CATEGORY_KEYS, type RetentionCategory } from '@obligarth/shared';
import { PrivacyProfileRulesSchema } from './profiles';

// =============================================================================
// The requests of the privacy pages (P0-13 T3, CNF-02; T4, CNF-04; D3): their type, their validity and their payload,
// shown to the reviewers (no secret). No database here (unit tests); the examination and the execution are in
// privacy/approvals.ts (profiles) and privacy/retentionPolicy.ts (retention).
// =============================================================================

export const PROFILE_CHANGE_REQUEST_TYPE = 'privacy_profile_change' as const;
/** A request waits for its examination one day (the client approver may need it). */
export const PROFILE_CHANGE_EXPIRY_MINUTES = 24 * 60;

/** Who examines a request of the privacy pages: a designated client approver of the tenant, or another platform
 *  administrator when the tenant has none. */
export type PrivacyReviewerSide = 'client' | 'platform';

/** The payload of a change of a profile. */
export const ProfileChangePayload = z.object({
  action: z.literal(PROFILE_CHANGE_REQUEST_TYPE),
  ownership: z.enum(OWNERSHIPS),
  rules: PrivacyProfileRulesSchema,
  justification: z.string().min(10).max(1000),
  /** The version in force when the request was filed (null: none, the defaults). */
  baseVersion: z.number().int().positive().nullable(),
  reviewerSide: z.enum(['client', 'platform']),
  narrowed: z.array(z.string()).max(8),
  widened: z.array(z.string()).max(8),
}).strict();
export type ProfileChange = z.infer<typeof ProfileChangePayload>;

// ── Retention (P0-13 T4, CNF-04, D3, D4) ─────────────────────────────────────────────────────────────────────

export const RETENTION_CHANGE_REQUEST_TYPE = 'privacy_retention_change' as const;
/** As a change of a profile: one day to decide. */
export const RETENTION_CHANGE_EXPIRY_MINUTES = 24 * 60;

/** Values of a request: categories of RETENTION_CATEGORIES, integers (their ranges are checked by the route, the
 *  executor and the database). */
export const RetentionValuesSchema = z.record(z.enum(RETENTION_CATEGORY_KEYS as [RetentionCategory, ...RetentionCategory[]]),
  z.number().int().positive().max(1000));

/** The payload of a change of the retention. */
export const RetentionChangePayload = z.object({
  action: z.literal(RETENTION_CHANGE_REQUEST_TYPE),
  values: RetentionValuesSchema,
  justification: z.string().min(10).max(1000),
  /** tenant_retention_policies.version when the request was filed (0: never set). */
  baseVersion: z.number().int().min(0),
  reviewerSide: z.enum(['client', 'platform']),
  raised: z.array(z.string()).max(8),
  lowered: z.array(z.string()).max(8),
  restored: z.array(z.string()).max(8),
}).strict();
export type RetentionChange = z.infer<typeof RetentionChangePayload>;
