import { z } from 'zod';
import { knownDeviceCapabilities } from '@obligarth/shared';

export const createTeamSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).nullable().optional(),
  canCreate: z.boolean().optional(),
  // Master-only field — when a platform admin creates a team while
  // logged into the master tenant, this picks which child tenant the
  // team will operate in. The controller drops this field for any
  // non-master caller (security), so it's safe to accept here.
  tenantId: z.number().int().positive().optional(),
});

export const updateTeamSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).nullable().optional(),
  canCreate: z.boolean().optional(),
});

export const setTeamMembersSchema = z.object({
  memberIds: z.array(z.number().int().positive()),
});

export const setTeamPermissionsSchema = z.object({
  permissions: z.array(
    z.object({
      scope: z.enum(['group', 'device', 'ungrouped']),
      // scope='ungrouped' uses scope_id=0 by convention (no real row
      // to point at); 'group' / 'device' use the actual row id which
      // is always >= 1. Accept anything >= 0 here and let the service
      // verify the (scope, scope_id) pairing makes sense.
      scopeId: z.number().int().nonnegative(),
      level: z.enum(['ro', 'rw']),
      // Device capabilities of the row (shared capabilities.ts). A value
      // outside that vocabulary (a removed capability, sent back by an
      // older client or kept in a pending approval) is dropped, not refused.
      capabilities: z.array(z.string()).transform(knownDeviceCapabilities).optional(),
    }),
  ),
});

export type CreateTeamInput = z.infer<typeof createTeamSchema>;
export type UpdateTeamInput = z.infer<typeof updateTeamSchema>;
export type SetTeamMembersInput = z.infer<typeof setTeamMembersSchema>;
export type SetTeamPermissionsInput = z.infer<typeof setTeamPermissionsSchema>;
