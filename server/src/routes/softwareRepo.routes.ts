import { AsyncResource } from 'node:async_hooks';
import { Router, type NextFunction, type Request, type Response } from 'express';
import * as fs from 'node:fs';
import multer from 'multer';
import { softwareRepoService, RepoError } from '../services/softwareRepo.service';
import { requireRole, requireTenantCapability } from '../middleware/rbac';

const router = Router();
// multer 2 refuses, when the middleware is built (module load), a limit that is not a non-negative integer: a
// REPO_MAX_FILE_SIZE that does not parse (NaN) would stop the server at startup, where multer 1 silently dropped
// the limit. Such a value falls back to the default of 500 MB.
const configuredMaxFileSize = softwareRepoService.maxFileSize();
const uploadMaxFileSize = Number.isSafeInteger(configuredMaxFileSize) && configuredMaxFileSize >= 0
  ? configuredMaxFileSize : 500 * 1024 * 1024;
// Streamed to disk (never held in memory: a few concurrent uploads of the maximum size would take the process down),
// under a name of multer's own; the service checks, hashes and renames it into the depot.
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => {
      // The partial files of uploads cut by a crash or a restart (throttled, never blocks).
      void softwareRepoService.sweepIncoming();
      const dir = softwareRepoService.incomingDir();
      fs.mkdir(dir, { recursive: true }, (err) => cb(err ?? null, dir));
    },
  }),
  limits: { fileSize: uploadMaxFileSize, files: 1 },
}).single('file');
// The depot's reads (packages, settings, downloads): the members who manage the apps of the tenant, not every member.
const requireRepoReader = requireTenantCapability('mdm.apps.manage');
// The body is read from the events of the socket, outside the asynchronous context of the request: a file that
// does not fit in what was already buffered would reach the route without its database context (every query
// refused, 500). The continuation is bound to the context this middleware was called in (as policies.routes.ts).
const uploadFile = (req: Request, res: Response, next: NextFunction): void => {
  upload(req, res, AsyncResource.bind((err?: unknown) => next(err)));
};
// A disabled depot refuses the upload before its body is written to disk.
const requireRepoEnabled = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    await softwareRepoService.assertEnabled(req.tenantId!);
    next();
  } catch (err) {
    if (err instanceof RepoError) { res.status(err.status).json({ error: err.message }); return; }
    next(err);
  }
};
// Leftovers of a previous run (the first sweep is not throttled).
void softwareRepoService.sweepIncoming();

// GET /software-repo/packages — list all packages for tenant
router.get('/packages', requireRepoReader, async (req, res, next) => {
  try {
    const packages = await softwareRepoService.list(req.tenantId!);
    res.json({ data: packages });
  } catch (err) { next(err); }
});

// GET /software-repo/settings — depot state, quota + live usage, key prefix
router.get('/settings', requireRepoReader, async (req, res, next) => {
  try {
    const settings = await softwareRepoService.getSettings(req.tenantId!);
    res.json({ data: settings });
  } catch (err) { next(err); }
});

// PUT /software-repo/settings — enable/disable + quota (admin only).
// A platform admin sitting on the master tenant edits child tenants by
// switching into them.
router.put('/settings', requireRole('admin'), async (req, res, next) => {
  try {
    const { enabled, quotaBytes } = req.body as { enabled?: boolean; quotaBytes?: number | null };
    const settings = await softwareRepoService.updateSettings(req.tenantId!, { enabled, quotaBytes });
    res.json({ data: settings });
  } catch (err) { next(err); }
});

// POST /software-repo/access-key — (re)generate the tenant script key (admin).
// Returns the plaintext ONCE; only the hash is persisted.
router.post('/access-key', requireRole('admin'), async (req, res, next) => {
  try {
    const result = await softwareRepoService.generateAccessKey(req.tenantId!);
    res.status(201).json({ data: result });
  } catch (err) { next(err); }
});

// DELETE /software-repo/access-key — revoke the tenant script key (admin)
router.delete('/access-key', requireRole('admin'), async (req, res, next) => {
  try {
    await softwareRepoService.revokeAccessKey(req.tenantId!);
    res.status(204).send();
  } catch (err) { next(err); }
});

// POST /software-repo/packages — upload (admin only)
router.post('/packages', requireRole('admin'), requireRepoEnabled, uploadFile, async (req, res, next) => {
  try {
    if (!req.file?.path) return res.status(400).json({ error: 'No file uploaded' });
    const platform = (req.body.platform || 'windows') as 'windows' | 'linux' | 'macos';
    const displayName = req.body.displayName || null;
    const pkg = await softwareRepoService.upload(
      req.tenantId!, req.file as any, platform, displayName, req.session.userId!,
    );
    res.status(201).json({ data: pkg });
  } catch (err) {
    // Surface precise HTTP codes for quota/disabled/type errors.
    if (err instanceof RepoError) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

// DELETE /software-repo/packages/:id — delete (admin only)
router.delete('/packages/:id', requireRole('admin'), async (req, res, next) => {
  try {
    if (!(await softwareRepoService.delete(parseInt(req.params.id), req.tenantId!))) {
      return res.status(404).json({ error: 'Package not found' });
    }
    res.status(204).send();
  } catch (err) { next(err); }
});

// GET /software-repo/packages/:uuid/download — download for UI preview.
// Blocked when the depot is disabled for the tenant.
router.get('/packages/:uuid/download', requireRepoReader, async (req, res, next) => {
  try {
    await softwareRepoService.assertEnabled(req.tenantId!);
    const result = await softwareRepoService.getFilePath(req.params.uuid, req.tenantId!);
    if (!result) return res.status(404).json({ error: 'Package not found' });
    res.set('Content-Disposition', `attachment; filename="${result.filename}"`);
    res.set('Content-Type', result.mimeType);
    res.sendFile(result.filePath);
  } catch (err) {
    if (err instanceof RepoError) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

export default router;
