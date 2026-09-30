import { z } from 'zod';

const userPreferencesSchema = z.object({
  toastEnabled:              z.boolean().optional(),
  toastPosition:             z.enum(['top-center', 'bottom-right']).optional(),
  multiTenantNotifications:  z.boolean().optional(),
  sidebarFloating:           z.boolean().optional(),
  theme:                     z.enum(['dark', 'light']).optional(),
  // Keep in sync with AppTheme (shared/src/types.ts) and enrollment.controller.ts:
  // a zod enum answers 400 on an id it does not list (Obli Daylight used to).
  preferredTheme:            z.enum(['obli-operator', 'obli-daylight', 'obli-dim', 'modern', 'neon']).optional(),
}).passthrough().nullable().optional();

export const updateProfileSchema = z.object({
  displayName: z.string().max(100).nullable().optional(),
  preferences: userPreferencesSchema,
  email: z.string().email().max(255).nullable().optional(),
  preferredLanguage: z.string().max(10).optional(),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(6).max(128),
});

export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
