import { clientIp, clientAddress } from '../utils/clientIp';
import { Router, Request, Response, NextFunction } from 'express';
import express from 'express';
import { commandService } from '../services/command.service';
import { auditService } from '../services/audit.service';
import { permissionService } from '../services/permission.service';
import { AppError } from '../middleware/errorHandler';
import { sessionHash } from '../utils/sessionHash';
import {
  FILE_EXPLORER_COMMANDS, EXPLORER_RESTRICTED_TEXT, EXPLORER_BROWSE_ACTION, EXPLORER_OP_MAX_USES,
  explorerDeviceAccess, explorerRestrictionLevel, grantExplorerStepUp, parseDeviceId,
} from '../services/fileExplorerGate.service';

const router = Router();

/**
 * The tenant's restriction on `command.<type>` for these queued file
 * operations, like POST /api/commands: 'sensitive' → the step-up proof of the
 * request (401 twoFactorRequired, the client resends with the proof),
 * 'restricted' → refused (403, no approval path: the result of a file
 * operation run by an approval would reach no explorer). The strictest of the
 * session's tenant and the device's (a master admin's god view). false: the
 * response was written.
 */
async function fileRestriction(req: Request, res: Response, type: string, deviceId: number): Promise<boolean> {
  const { applyRestriction } = await import('../services/restriction.service');
  const deviceTenantId = Number(res.locals.fileDevice?.tenant_id) || undefined;
  return applyRestriction(res, { req, actionKey: `command.${type}`, deviceIds: [deviceId], deviceTenantId });
}

// All file operations require device access. Uses router.param() to check it
// once for every route with :deviceId, with the REST rules
// (services/deviceScope.service.ts): the device in the session's tenant (any
// tenant for an admin on the master tenant), and for a non-admin membership of
// that tenant, the device visible to one of their teams and the 'files'
// capability. The device is kept in res.locals.fileDevice.
router.param('deviceId', async (req: Request, res: Response, next: NextFunction, val: string) => {
  try {
    const { resolveRequestDevice } = await import('../services/deviceScope.service');
    const access = await resolveRequestDevice(req, val, {
      capability: 'files', capabilityError: 'File access not permitted for your team',
    });
    if (!access.ok) {
      return next(new AppError(access.status, access.error, access.status === 404 ? 'not_found' : 'forbidden'));
    }
    res.locals.fileDevice = access.device;
    next();
  } catch (err) { next(err); }
});

// Upload route needs larger body limit for base64 file content
const uploadBodyParser = express.json({ limit: '200mb' });

// POST /api/devices/:deviceId/files/list
router.post('/:deviceId/files/list', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const { path } = req.body;
    if (!(await fileRestriction(req, res, 'list_directory', deviceId))) return;
    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type: 'list_directory',
      payload: { path: path || '' },
      priority: 'high',
      createdBy: req.session?.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:deviceId/files/create-directory
router.post('/:deviceId/files/create-directory', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const { path } = req.body;
    if (!path) return res.status(400).json({ error: 'path is required' });
    if (!(await fileRestriction(req, res, 'create_directory', deviceId))) return;
    await auditService.log({
      tenantId: req.tenantId!,
      userId: req.session?.userId,
      deviceId,
      action: 'file_explorer.create_directory',
      resourceType: 'directory',
      resourcePath: path,
      ipAddress: clientIp(req),
    });
    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type: 'create_directory',
      payload: { path },
      priority: 'high',
      createdBy: req.session?.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:deviceId/files/rename
router.post('/:deviceId/files/rename', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const { oldPath, newPath } = req.body;
    if (!oldPath || !newPath) return res.status(400).json({ error: 'oldPath and newPath are required' });
    if (!(await fileRestriction(req, res, 'rename_file', deviceId))) return;
    await auditService.log({
      tenantId: req.tenantId!,
      userId: req.session?.userId,
      deviceId,
      action: 'file_explorer.rename',
      resourceType: 'file',
      resourcePath: oldPath,
      details: { newPath },
      ipAddress: clientIp(req),
    });
    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type: 'rename_file',
      payload: { oldPath, newPath },
      priority: 'high',
      createdBy: req.session?.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:deviceId/files/delete
router.post('/:deviceId/files/delete', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const { path, recursive } = req.body;
    if (!path) return res.status(400).json({ error: 'path is required' });
    if (!(await fileRestriction(req, res, 'delete_file', deviceId))) return;
    await auditService.log({
      tenantId: req.tenantId!,
      userId: req.session?.userId,
      deviceId,
      action: 'file_explorer.delete',
      resourceType: recursive ? 'directory' : 'file',
      resourcePath: path,
      details: { recursive: !!recursive },
      ipAddress: clientIp(req),
    });
    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type: 'delete_file',
      payload: { path, recursive: !!recursive },
      priority: 'high',
      createdBy: req.session?.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:deviceId/files/download
router.post('/:deviceId/files/download', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const { path } = req.body;
    if (!path) return res.status(400).json({ error: 'path is required' });
    if (!(await fileRestriction(req, res, 'download_file', deviceId))) return;
    await auditService.log({
      tenantId: req.tenantId!,
      userId: req.session?.userId,
      deviceId,
      action: 'file_explorer.download',
      resourceType: 'file',
      resourcePath: path,
      ipAddress: clientIp(req),
    });
    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type: 'download_file',
      payload: { path },
      priority: 'high',
      createdBy: req.session?.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/devices/:deviceId/files/upload
router.post('/:deviceId/files/upload', uploadBodyParser, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const { path, data, overwrite } = req.body;
    if (!path || !data) return res.status(400).json({ error: 'path and data are required' });
    if (!(await fileRestriction(req, res, 'upload_file', deviceId))) return;
    await auditService.log({
      tenantId: req.tenantId!,
      userId: req.session?.userId,
      deviceId,
      action: 'file_explorer.upload',
      resourceType: 'file',
      resourcePath: path,
      details: { overwrite: !!overwrite, sizeBytes: Math.round(data.length * 0.75) },
      ipAddress: clientIp(req),
    });
    const cmd = await commandService.enqueue({
      deviceId,
      tenantId: req.tenantId!,
      type: 'upload_file',
      payload: { path, data, overwrite: !!overwrite },
      priority: 'high',
      createdBy: req.session?.userId,
    });
    res.json({ data: cmd });
  } catch (err) { next(err); }
});

// POST /api/files/:deviceId/files/step-up {commandType, count?}
// The step-up of the file explorer's socket channel (FILE_EXPLORER_CMD answers
// `step_up_required` with `action: 'command.<type>'` when the tenant marks that
// action sensitive): the same verifier as every sensitive action
// (checkSecondFactor: TOTP, Obligate code, phone key, trusted IP), so the
// clients' usual prompt handles the 401 twoFactorRequired and resends this body
// with the proof. On success THIS session holds a grant for (device, action)
// and resends its command (fileExplorerGate.service.ts: browsing 15 min
// sliding; any other action ONE operation — or `count` for a multi-file
// operation — within 2 min; a trusted-IP grant only from that address). Same
// device authorization as the socket channel.
//   200 {data: {required: false}}                 nothing to confirm (level none)
//   200 {data: {required: true, granted: true, action, expiresInSeconds}}
//   401 twoFactorRequired / Invalid 2FA code …    (the step-up protocol)
//   403 {error, code: 'restricted'|'forbidden'}   404 {error, code: 'not_found'}
router.post('/:deviceId/files/step-up', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseDeviceId(req.params.deviceId);
    const commandType = (req.body ?? {}).commandType;
    if (deviceId === null || typeof commandType !== 'string' || !FILE_EXPLORER_COMMANDS.has(commandType)) {
      return res.status(400).json({ error: 'Invalid request', code: 'invalid' });
    }
    const userId = req.session.userId!;
    const access = await explorerDeviceAccess(userId, req.session.role === 'admin', deviceId);
    if (!access.ok) {
      return res.status(access.failure.code === 'not_found' ? 404 : 403).json({ error: access.failure.error, code: access.failure.code });
    }
    const actionKey = `command.${commandType}`;
    const level = await explorerRestrictionLevel(commandType, deviceId, access.device.tenant_id, req.tenantId);
    if (level === 'none') return res.json({ data: { required: false, action: actionKey } });
    if (level === 'restricted') {
      return res.status(403).json({ error: EXPLORER_RESTRICTED_TEXT, code: 'restricted', action: actionKey });
    }
    const { checkSecondFactor, sendStepUpFailure } = await import('../services/deviceKey/stepUpProof');
    const outcome = await checkSecondFactor(req, { actionKey, deviceIds: [deviceId], allowTrustedIp: true, allowDevice: true });
    if (!outcome.ok) { sendStepUpFailure(res, outcome); return; }
    if (!req.sessionID) return res.status(401).json({ error: 'Unauthenticated' });
    // A multi-file operation (upload / delete of several items) confirms its
    // size once: `count` operations, at most EXPLORER_OP_MAX_USES (browsing
    // ignores it: its window slides).
    const rawCount = Number((req.body ?? {}).count);
    const uses = Number.isInteger(rawCount) && rawCount >= 1 ? Math.min(rawCount, EXPLORER_OP_MAX_USES) : 1;
    const expiresInSeconds = grantExplorerStepUp(sessionHash(req.sessionID), userId, deviceId, actionKey, {
      uses, via: outcome.via, ip: clientAddress(req).ip,
    });
    await auditService.logReqAs(req, access.device.tenant_id, 'file_explorer.step_up', {
      deviceId, resourceType: 'device', resourcePath: String(deviceId),
      details: { action: actionKey, via: outcome.via, ...(actionKey === EXPLORER_BROWSE_ACTION ? {} : { operations: uses }) },
    });
    res.json({ data: { required: true, granted: true, action: actionKey, expiresInSeconds } });
  } catch (err) { next(err); }
});

// POST /api/devices/:deviceId/files/open-explorer (audit: user opened file explorer)
router.post('/:deviceId/files/open-explorer', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    await auditService.log({
      tenantId: req.tenantId!,
      userId: req.session?.userId,
      deviceId,
      action: 'file_explorer.open',
      ipAddress: clientIp(req),
    });
    res.json({ data: { logged: true } });
  } catch (err) { next(err); }
});

// GET /api/devices/:deviceId/files/audit-log
router.get('/:deviceId/files/audit-log', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = parseInt(req.params.deviceId, 10);
    const logs = await auditService.getByDevice(deviceId, req.tenantId!);
    res.json({ data: logs });
  } catch (err) { next(err); }
});

export default router;
