import { Router, type Request, type Response } from 'express';
import path from 'path';
import { db } from '../db';
import { logger } from '../utils/logger';
import { apkDir } from './config';

// =============================================================================
// The APK of the bridge agent, public (the last resort of a migration): a
// device the console no longer reaches (MobiControl gone, no Knox, an agent
// too old to update itself) is put right in the shop by opening this link in
// Chrome and installing. Mounted at /api/legacy-agent/public, before every
// authenticated route.
//
//   GET /api/legacy-agent/public/agent.apk[?v=<versionCode>]
//     the newest version not withdrawn, or that version (404 when withdrawn
//     or unknown). Nothing about a tenant leaves: no configuration, no token
//     (an agent installed this way still needs its enrolment).
//
// The APK is no secret (anyone holding a managed device holds it), and its
// authenticity is Android's: an update installs only over the same signer.
// =============================================================================

const APK_MIME = 'application/vnd.android.package-archive';

async function releaseOf(req: Request): Promise<{ sha256: string; versionName: string } | null> {
  const wanted = typeof req.query.v === 'string' && /^\d{1,9}$/.test(req.query.v) ? Number(req.query.v) : null;
  const q = db('legacy_agent_releases').whereNull('withdrawn_at');
  const row = await (wanted !== null ? q.where({ version_code: wanted }) : q.orderBy('version_code', 'desc'))
    .first('sha256', 'version_name') as { sha256: string; version_name: string } | undefined;
  if (!row || !/^[0-9a-f]{64}$/.test(String(row.sha256).trim())) return null;
  return { sha256: String(row.sha256).trim(), versionName: String(row.version_name ?? '').replace(/[^0-9A-Za-z.-]/g, '') || 'agent' };
}

async function download(req: Request, res: Response): Promise<void> {
  const release = await releaseOf(req);
  if (!release) {
    res.setHeader('Cache-Control', 'no-store');
    res.status(404).json({ error: 'No version of the agent' });
    return;
  }
  res.type(APK_MIME);
  res.attachment(`obligarth-agent-${release.versionName}.apk`);
  res.setHeader('X-Content-SHA256', release.sha256);
  res.sendFile(path.join(apkDir(), `${release.sha256}.apk`), {
    acceptRanges: true, cacheControl: false, lastModified: true, headers: { 'Cache-Control': 'no-cache' },
  }, (err) => {
    if (!err || res.headersSent) return;
    const status = (err as Error & { status?: number }).status ?? 500;
    if (status >= 500) logger.warn({ err }, 'legacy agent: public APK download failed');
    res.removeHeader('Content-Type');
    res.removeHeader('Content-Disposition');
    res.removeHeader('X-Content-SHA256');
    res.setHeader('Cache-Control', 'no-store');
    res.status(status === 404 ? 404 : 500).json({ error: status === 404 ? 'APK missing' : 'Download failed' });
  });
}

export function createLegacyAgentPublicRouter(): Router {
  const router = Router();
  router.get('/agent.apk', (req, res, next) => { download(req, res).catch(next); });
  return router;
}
