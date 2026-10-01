import type { Request, Response, NextFunction } from 'express';
import { smtpServerService } from '../services/smtpServer.service';
import { AppError } from '../middleware/errorHandler';
import { isVaultError } from '../vault/errors';
import { hasGlobalView } from '../services/deviceScope.service';

export const smtpServerController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const servers = await smtpServerService.list(req.tenantId);
      res.json({ success: true, data: servers });
    } catch (err) { next(err); }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { name, host, port, secure, username, password, fromAddress } = req.body;
      if (!name || !host || !port || !username || !password || !fromAddress) {
        throw new AppError(400, 'Missing required fields');
      }
      const server = await smtpServerService.create({ name, host, port: Number(port), secure: Boolean(secure), username, password, fromAddress, tenantId: req.tenantId });
      res.status(201).json({ success: true, data: server });
    } catch (err) { next(err); }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const { name, host, port, secure, username, password, fromAddress } = req.body;
      const server = await smtpServerService.update(id, {
        ...(name !== undefined && { name }),
        ...(host !== undefined && { host }),
        ...(port !== undefined && { port: Number(port) }),
        ...(secure !== undefined && { secure: Boolean(secure) }),
        ...(username !== undefined && { username }),
        ...(password !== undefined && { password }),
        ...(fromAddress !== undefined && { fromAddress }),
      // The password is sealed under the DEK of the server's tenant (the
      // row's); a server of another tenant is refused, except from the
      // master tenant's global view (coffre-secrets R1).
      }, { requestTenantId: req.tenantId, globalView: hasGlobalView(req) });
      if (!server) throw new AppError(404, 'SMTP server not found');
      res.json({ success: true, data: server });
    } catch (err) { next(err); }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const removed = await smtpServerService.delete(id);
      if (!removed) throw new AppError(404, 'SMTP server not found');
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  async test(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // A server out of reach (unknown, or another tenant's: the row level
      // security hides it) answers 404, like the other routes of a server.
      if (!(await smtpServerService.getTransportConfig(id, { requestTenantId: req.tenantId, globalView: hasGlobalView(req) }))) {
        throw new AppError(404, 'SMTP server not found');
      }
      await smtpServerService.test(id, { requestTenantId: req.tenantId, globalView: hasGlobalView(req) });
      res.json({ success: true, message: 'Connection successful' });
    } catch (err) {
      // A vault error (the password cannot be opened) is never echoed: the
      // error handler answers 500, the vault logged and alerted.
      if (isVaultError(err) || err instanceof AppError) { next(err); return; }
      const msg = err instanceof Error ? err.message : 'Connection failed';
      next(new AppError(400, `SMTP test failed: ${msg}`));
    }
  },
};
