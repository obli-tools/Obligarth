import { Router, type Request } from 'express';
import { reportService } from '../services/report.service';
import { requireTenantCapability, requireAnyTenantCapability } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { auditService } from '../services/audit.service';
import { permissionService } from '../services/permission.service';
import { db } from '../db';
import { changedFields, parseReportCreate, parseReportUpdate, type Validation } from '../reports/validate';

const router = Router();

/** The positive integer id of a path parameter, or 404 (an unknown id and
 *  another tenant's answer alike: its existence is not told). */
function idOf(req: Request, param: string, what: string): number {
  const raw = String(req.params[param] ?? '');
  const id = /^\d{1,10}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isSafeInteger(id) || id <= 0 || id > 2_147_483_647) throw new AppError(404, `${what} not found`);
  return id;
}

/** The report of the path, in the request's tenant (404 otherwise). */
async function reportOfPath(req: Request): Promise<number> {
  const id = idOf(req, 'id', 'Report');
  if (!(await reportService.exists(id, req.tenantId!))) throw new AppError(404, 'Report not found');
  return id;
}

/** The value of a validation, or 400 with its stable code. */
function valid<T>(v: Validation<T>): T {
  if (!v.ok) throw new AppError(400, v.message, v.code);
  return v.data;
}

/**
 * A group or a device scope names one of the request's tenant that the
 * caller sees (a non-administrator: through their teams). Otherwise 400
 * invalidScope, the same answer for an unknown id, another tenant's and an
 * unseen one (none is told apart).
 */
async function assertScope(req: Request, scopeType: string | undefined, scopeId: number | null | undefined): Promise<void> {
  if (scopeType !== 'group' && scopeType !== 'device') return;
  const tenantId = req.tenantId!;
  const id = Number(scopeId);
  const table = scopeType === 'group' ? 'device_groups' : 'devices';
  const exists = !!(await db(table).where({ id, tenant_id: tenantId }).first('id'));
  let seen = exists;
  if (exists && req.session.role !== 'admin') {
    const userId = Number(req.session.userId);
    const visible = scopeType === 'group'
      ? await permissionService.getVisibleGroupIds(userId, false)
      : await permissionService.getVisibleDeviceIds(userId, false);
    seen = visible === 'all' || visible.map(Number).includes(id);
  }
  if (!seen) throw new AppError(400, `scopeId: not a ${scopeType} of this tenant`, 'invalidScope');
}

// Reading: holders of the `reports` tenant capability, or of
// `supervision:read`, which opens the Supervision page (it holds the
// reports). Writing (create, change, delete, generate, cancel): `reports`
// only. A stored legacy value such as `manage_reports` grants nothing
// (shared capabilities.ts).
router.use(requireAnyTenantCapability('reports', 'supervision:read'));
const canWrite = requireTenantCapability('reports');

router.get('/', async (req, res, next) => {
  try { res.json({ data: await reportService.getReports(req.tenantId!) }); } catch (err) { next(err); }
});

router.post('/', canWrite, async (req, res, next) => {
  try {
    const input = valid(parseReportCreate(req.body));
    await assertScope(req, input.scopeType, input.scopeId);
    const report = await reportService.createReport(req.tenantId!, { ...input, createdBy: req.session.userId });
    await auditService.logReq(req, 'report.created', {
      resourceType: 'report', resourcePath: String(report.id),
      details: { type: report.type, format: report.format, scopeType: report.scopeType },
    });
    res.status(201).json({ data: report });
  } catch (err) { next(err); }
});

router.patch('/:id', canWrite, async (req, res, next) => {
  try {
    const id = await reportOfPath(req);
    const current = await reportService.getReport(id, req.tenantId!);
    if (!current) throw new AppError(404, 'Report not found');
    const input = valid(parseReportUpdate(req.body, { scopeType: current.scopeType, scopeId: current.scopeId }));
    // The console sends the whole definition back: only a scope that changes
    // is checked again (a member still renames or pauses a report whose
    // stored scope is out of their teams, or was deleted since).
    // An unchanged scope is not written either: the trigger reports_scope_tenant
    // would check it again (a group deleted since: 23503).
    const scopeChanged = (input.scopeType !== undefined || input.scopeId !== undefined)
      && (input.scopeType !== current.scopeType || (input.scopeId ?? null) !== (current.scopeId ?? null));
    if (scopeChanged) await assertScope(req, input.scopeType, input.scopeId);
    else { delete input.scopeType; delete input.scopeId; }
    const updated = await reportService.updateReport(id, req.tenantId!, input);
    if (!updated) throw new AppError(404, 'Report not found');
    await auditService.logReq(req, 'report.updated', {
      resourceType: 'report', resourcePath: String(id),
      details: { fields: changedFields(input) },
    });
    res.json({ data: updated });
  } catch (err) { next(err); }
});

router.delete('/:id', canWrite, async (req, res, next) => {
  try {
    const id = await reportOfPath(req);
    const { deleted, outputs } = await reportService.deleteReport(id, req.tenantId!);
    if (!deleted) throw new AppError(404, 'Report not found');
    await auditService.logReq(req, 'report.deleted', { resourceType: 'report', resourcePath: String(id), details: { outputs } });
    res.status(204).send();
  } catch (err) { next(err); }
});

router.post('/:id/generate', canWrite, async (req, res, next) => {
  try {
    const id = await reportOfPath(req);
    const output = await reportService.generateReport(id, req.tenantId!, Number(req.session.userId));
    await auditService.logReq(req, 'report.generated', {
      resourceType: 'report', resourcePath: String(id), details: { outputId: output.id },
    });
    res.status(202).json({ data: output });
  } catch (err) { next(err); }
});

router.get('/:id/outputs', async (req, res, next) => {
  try {
    const outputs = await reportService.getOutputs(await reportOfPath(req), req.tenantId!);
    res.json({ data: outputs });
  } catch (err) { next(err); }
});

// Client builds /reports/outputs/:outputId/download (no report id) — authorize
// by outputId + tenant: every reader of the tenant's reports (`reports` or
// `supervision:read`, P0-12 §3) downloads a ready output. The file goes under
// `<report name>-<YYYY-MM-DD>.<ext>`, never under its name on the server.
router.get('/outputs/:outputId/download', async (req, res, next) => {
  try {
    const outputId = idOf(req, 'outputId', 'Output');
    const found = await reportService.outputForDownload(outputId, req.tenantId!);
    if (!found) throw new AppError(404, 'Output not found');
    await auditService.logReq(req, 'report.output_downloaded', {
      resourceType: 'report', resourcePath: String(found.reportId), details: { outputId },
    });
    res.download(found.filePath, found.fileName, { dotfiles: 'allow' }, (err) => {
      if (err && !res.headersSent) next(err);
    });
  } catch (err) { next(err); }
});

// Cancel an output stuck in 'generating' (e.g. left orphaned by a restart).
// Scoped by outputId + tenant; only 'generating' rows flip (returns 404 if
// already resolved or foreign).
router.post('/outputs/:outputId/cancel', canWrite, async (req, res, next) => {
  try {
    const outputId = idOf(req, 'outputId', 'Output');
    const output = await reportService.cancelOutput(outputId, req.tenantId!);
    if (!output) throw new AppError(404, 'No generating output to cancel');
    await auditService.logReq(req, 'report.output_cancelled', {
      resourceType: 'report', resourcePath: String(output.reportId), details: { outputId },
    });
    res.json({ data: output });
  } catch (err) { next(err); }
});

export default router;
