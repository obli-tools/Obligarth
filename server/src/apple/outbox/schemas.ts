import { z } from 'zod';
import { MDM_KEY_RE } from '../tenants/key';

// =============================================================================
// Schemas of the payloads of apple-edge's events (docs: integration-apple-
// edge §7.5; apple-edge §5.6): NOT strict (unknown fields ignored, apple-edge
// §5.5), only the fields used declared. Lot B1 delivers those of the tenant
// registry; the other families come with their handlers (lot B3).
// =============================================================================

const iso = z.string().datetime({ offset: true });
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const uuid = z.string().uuid();
const key = z.string().regex(MDM_KEY_RE);

export const P = {
  'tenant.created': z.object({ key, state: z.string().max(32), external_ref: uuid }),
  'tenant.state_changed': z.object({ key, state: z.enum(['active', 'suspended', 'retiring', 'retired']) }),
  'tenant.load_failed': z.object({ key }),
  'tenant.ca_rotated': z.object({
    ca_id: uuid, sha256, not_after: iso, verify_only: z.array(uuid).nullable().transform((v) => v ?? []),
  }),
} as const;
