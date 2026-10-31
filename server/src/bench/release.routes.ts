import { createReadStream } from 'node:fs';
import { Router, type Request, type Response } from 'express';
import { BENCH_MSI, installerState } from './apk.service';

// =============================================================================
// The installer of the bench station next to the server image (lot BANC §3.5, §3.9), public:
//   GET /api/bench/version          { version, available, sha256, size, file }
//   GET /api/bench/download/:file   a fixed list ['obligarth-bench.msi']; Content-Length and X-Content-SHA256; 404 else
// =============================================================================

export function createBenchReleaseRouter(): Router {
  const router = Router();

  router.get('/version', (_req: Request, res: Response, next) => {
    installerState().then((s) => {
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, data: { version: s.version, available: s.available, sha256: s.sha256, size: s.size, file: BENCH_MSI } });
    }).catch(next);
  });

  router.get('/download/:file', (req: Request, res: Response, next) => {
    if (req.params.file !== BENCH_MSI) { res.status(404).json({ success: false, error: 'Not found', code: 'not_found' }); return; }
    installerState().then((s) => {
      if (!s.available || !s.sha256 || !s.size) { res.status(404).json({ success: false, error: 'Not found', code: 'not_found' }); return; }
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Type', 'application/x-msi');
      res.setHeader('Content-Length', String(s.size));
      res.setHeader('X-Content-SHA256', s.sha256);
      res.setHeader('Content-Disposition', `attachment; filename="${BENCH_MSI}"`);
      createReadStream(s.file).on('error', next).pipe(res);
    }).catch(next);
  });

  return router;
}
