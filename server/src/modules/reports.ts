import { registerReportJobs } from '../services/report.service';
import { registerAuditResourceName } from '../audit/read';

// =============================================================================
// REPORTS — their hooks into the core's registries: the durable jobs of the
// report outputs (generation, sweep of the stuck ones, retention of the
// expired ones and of their files), and the name of a report in the audit
// journal (its entries: report.created, report.updated, report.deleted,
// report.generated, report.output_cancelled, report.output_downloaded, family
// 'report.' of the core catalogue). index.ts calls registerReportsModule()
// before anything starts. The job definitions and their handles live in
// report.service.ts, next to the code that enqueues them.
// =============================================================================

let registered = false;

export function registerReportsModule(): void {
  if (registered) return;
  registered = true;
  registerReportJobs();
  registerAuditResourceName('report', 'reports');
}
