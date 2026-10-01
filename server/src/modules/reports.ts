import { registerReportJobs } from '../services/report.service';

// =============================================================================
// REPORTS — their hooks into the core's registries: the durable jobs of the
// report outputs (generation, sweep of the stuck ones, retention of the
// expired ones and of their files). index.ts calls registerReportsModule()
// before anything starts. The job definitions and their handles live in
// report.service.ts, next to the code that enqueues them.
// =============================================================================

let registered = false;

export function registerReportsModule(): void {
  if (registered) return;
  registered = true;
  registerReportJobs();
}
