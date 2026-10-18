import { registerAdeProfileJobs } from './adeProfiles';
import { registerEnrollmentJobs } from './jobs';

// =============================================================================
// Enrollment (docs: integration-apple-edge §10): lot C1, OTA; lot C2, ADE and
// account-driven enrollment (BYOD). The device
// surface (surface.ts) is mounted by app.ts at /t/:key, the console API
// (routes.ts) by routes/index.ts at /api/apple/enrollment; the jobs are
// registered by registerAppleModule().
// =============================================================================

export { createAppleDeviceSurface } from './surface';
export { createEnrollmentRouter } from './routes';
export { setEnrollmentNoticeProvider, usesDefaultNotice, type EnrollmentNotice, type EnrollmentNoticeProvider } from './notice';

export function registerAppleEnrollment(): void {
  registerEnrollmentJobs();
  registerAdeProfileJobs();
}
