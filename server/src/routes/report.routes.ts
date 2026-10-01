import { Router, type Request } from 'express';
import { reportService } from '../services/report.service';
import { requireTenantCapability, requireAnyTenantCapability } from '../middleware/rbac';
import fs from 'fs';
import { AppError } from '../middleware/errorHandler';

const router = Router();

/** The report of the path, in the request's tenant: an unknown id and
 *  another tenant's answer alike (404, its existence is not told). */
async function reportOfPath(req: Request): Promise<number> {
  const id = Number.parseInt(String(req.params.id), 10);
  if (!Number.isSafeInteger(id) || id <= 0 || !(await reportService.exists(id, req.tenantId!))) {
    throw new AppError(404, 'Report not found');
  }
  return id;
}

// Reports: holders of the `reports` tenant capability, or of
// `supervision:read`, which opens the Supervision page (it holds the
// reports). A stored legacy value such as `manage_reports` grants
// nothing (shared capabilities.ts).
router.use(requireAnyTenantCapability('reports', 'supervision:read'));

router.get('/', async (req, res, next) => {
  try { res.json({ data: await reportService.getReports(req.tenantId!) }); } catch (err) { next(err); }
});

router.post('/', async (req, res, next) => {
  try {
    const report = await reportService.createReport(req.tenantId!, {
      ...req.body, createdBy: req.session.userId,
    });
    res.status(201).json({ data: report });
  } catch (err) { next(err); }
});

router.patch('/:id', async (req, res, next) => {
  try {
    const updated = await reportService.updateReport(await reportOfPath(req), req.tenantId!, req.body);
    if (!updated) throw new AppError(404, 'Report not found');
    res.json({ data: updated });
  } catch (err) { next(err); }
});

router.delete('/:id', async (req, res, next) => {
  try {
    if (!(await reportService.deleteReport(await reportOfPath(req), req.tenantId!))) throw new AppError(404, 'Report not found');
    res.status(204).send();
  } catch (err) { next(err); }
});

router.post('/:id/generate', async (req, res, next) => {
  try {
    const output = await reportService.generateReport(await reportOfPath(req), req.tenantId!);
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
// by outputId + tenant (the report id in the path was never used).
router.get('/outputs/:outputId/download', async (req, res, next) => {
  try {
    const { db } = await import('../db');
    const output = await db('report_outputs').where({ id: parseInt(req.params.outputId), tenant_id: req.tenantId! }).first();
    if (!output?.file_path) return res.status(404).json({ error: 'Output not found' });
    if (!fs.existsSync(output.file_path)) return res.status(404).json({ error: 'File not found' });
    res.download(output.file_path);
  } catch (err) { next(err); }
});

// Cancel an output stuck in 'generating' (e.g. left orphaned by a restart).
// Scoped by outputId + tenant; only 'generating' rows flip (returns 404 if
// already resolved or foreign).
router.post('/outputs/:outputId/cancel', async (req, res, next) => {
  try {
    const output = await reportService.cancelOutput(parseInt(req.params.outputId), req.tenantId!);
    if (!output) return res.status(404).json({ error: 'No generating output to cancel' });
    res.json({ data: output });
  } catch (err) { next(err); }
});

export default router;
