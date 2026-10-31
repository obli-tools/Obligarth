import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  isMasterTenant, LEGACY_AGENT_AUTO_UPDATE_BOUNDS, LEGACY_AGENT_POLL_BOUNDS, MASTER_TENANT_ID, type LegacyAgentInstanceSettings,
} from '@obligarth/shared';
import { audit } from '../audit';
import { config } from '../config';
import { db } from '../db';
import { switchToIdentity } from '../db/context';
import { AppError } from '../middleware/errorHandler';
import { checkSecondFactor, sendStepUpFailure } from '../services/deviceKey/stepUpProof';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { bundleStatus } from './bundled';
import { apkDir, CONFIG_KEYS, forgetInstanceSettings, instanceSettings, signersFromEnv } from './config';
import { looksLikeApk, receiveApk } from './packages';
import { releaseView } from './routes';
import { exportServerKey, serverKeyView } from './serverKey';

// =============================================================================
// Platform console of the bridge agent (docs: agent-pont-android §7, RC-3),
// mounted at /api/admin/legacy-agent: the master tenant (404 elsewhere), a
// platform administrator (403 otherwise).
//   GET  /releases                    the versions of the agent (uploaded, or embedded in the server image: origin,
//                                     bundledIn; lot AGENT-RU)
//   POST /releases/upload             the APK (raw body), stored by content: { sha256, size }
//   POST /releases                    { sha256, versionCode, versionName, signerSha256, notes }: strict second factor;
//                                     the signer must be in LEGACY_AGENT_SIGNERS
//   POST /releases/:id/withdraw       strict second factor
//   GET  /settings, PUT /settings     poll period, minimal version, inventory period, automatic update of the fleet
//                                     and its pace per hour (app_config; turning it on or raising the pace while on:
//                                     strict second factor); GET also tells what the start found in the image (bundle)
//   GET  /server-key                  public key of the instance and its fingerprint (to compile in SERVER_KEY_PINS)
//   POST /server-key/export           the private key, ONCE, strict second factor (escrow)
// =============================================================================

function masterPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!isMasterTenant(req.tenantId)) { next(new AppError(404, 'Not found')); return; }
  if (req.session?.role !== 'admin') { next(new AppError(403, 'Insufficient permissions')); return; }
  next();
}

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

async function strictStepUp(req: Request, res: Response, actionKey: string): Promise<boolean> {
  const step = await checkSecondFactor(req, { actionKey, allowTrustedIp: false, allowDevice: true });
  if (!step.ok) { sendStepUpFailure(res, step); return false; }
  return true;
}

const ReleaseMeta = z.object({
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  versionCode: z.number().int().min(1).max(2_000_000_000),
  versionName: z.string().trim().min(1).max(32).regex(/^[0-9A-Za-z.+_-]+$/),
  signerSha256: z.string().transform((s) => s.replace(/:/g, '').toLowerCase()).pipe(z.string().regex(/^[0-9a-f]{64}$/)),
  notes: z.string().trim().max(500).optional(),
}).strict();

const SettingsBody = z.object({
  pollSeconds: z.number().int().min(LEGACY_AGENT_POLL_BOUNDS.min).max(LEGACY_AGENT_POLL_BOUNDS.max).optional(),
  minVersionCode: z.number().int().min(0).max(2_000_000_000).optional(),
  inventorySeconds: z.number().int().min(3_600).max(30 * 86_400).optional(),
  autoUpdate: z.boolean().optional(),
  autoUpdatePerHour: z.number().int().min(LEGACY_AGENT_AUTO_UPDATE_BOUNDS.min).max(LEGACY_AGENT_AUTO_UPDATE_BOUNDS.max).optional(),
}).strict();

async function settingsView(): Promise<LegacyAgentInstanceSettings> {
  const s = await instanceSettings(true);
  return { ...s, signers: signersFromEnv().signers, publicBase: config.apple.mdmPublicBase ?? null, bundle: bundleStatus() };
}

export function createLegacyAgentAdminRouter(): Router {
  const router = Router();
  router.use(masterPlatformAdmin);

  router.get('/releases', wrap(async (_req, res) => {
    const rows = await db('legacy_agent_releases').orderBy('version_code', 'desc').limit(500).select('*');
    res.json({ success: true, data: rows.map(releaseView) });
  }));

  // Two steps: the APK first (raw body, stored by content), then the version itself (JSON, strict second factor):
  // the second factor travels in a JSON body only (captureStepUpProof).
  router.post('/releases/upload', wrap(async (req, res) => {
    const file = await receiveApk(req);
    if (!(await looksLikeApk(file.sha256))) throw new AppError(422, 'This file is not an APK (ZIP archive)', 'notAnApk');
    res.status(201).json({ success: true, data: file });
  }));

  router.post('/releases', wrap(async (req, res) => {
    const meta = ReleaseMeta.safeParse(req.body ?? {});
    if (!meta.success) throw new AppError(400, meta.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const m = meta.data;
    const { signers } = signersFromEnv();
    if (signers.length === 0) throw new AppError(409, 'LEGACY_AGENT_SIGNERS is empty: no version of the agent can be uploaded', 'signersNotConfigured');
    if (!signers.includes(m.signerSha256)) throw new AppError(422, 'This signer is not admitted for the agent (LEGACY_AGENT_SIGNERS)', 'signerNotAdmitted');
    if (await db('legacy_agent_releases').where({ version_code: m.versionCode }).first('id')) {
      throw new AppError(409, 'A version with this versionCode exists already', 'versionExists');
    }
    const size = await stat(path.join(apkDir(), `${m.sha256}.apk`)).then((st) => (st.isFile() ? st.size : 0)).catch(() => 0);
    if (size <= 0) throw new AppError(404, 'Upload the APK first (POST /releases/upload)', 'apkNotUploaded');
    if (!(await strictStepUp(req, res, 'legacy_agent.release_upload'))) return;
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    const row = await switchToIdentity(() => db.transaction(async (trx) => {
      if (await trx('legacy_agent_releases').where({ sha256: m.sha256 }).first('id')) throw new AppError(409, 'This APK is already a version', 'versionExists');
      const id = (await trx.raw('SELECT gen_random_uuid() AS id') as { rows: Array<{ id: string }> }).rows[0].id;
      await audit.appendInTx(trx, {
        tenantId: MASTER_TENANT_ID, action: 'legacy_agent.release_uploaded', target: { type: 'legacy_agent_release', id },
        details: { versionCode: m.versionCode, versionName: m.versionName, sha256: m.sha256, size, signerSha256: m.signerSha256 },
      }, ctx);
      const [r] = await trx('legacy_agent_releases').insert({
        id, version_code: m.versionCode, version_name: m.versionName, sha256: m.sha256, size_bytes: size, signer_sha256: m.signerSha256,
        notes: m.notes || null, created_by: req.session.userId!, origin: 'upload',
      }).returning('*') as Array<Record<string, any>>;
      return r;
    }));
    res.status(201).json({ success: true, data: releaseView(row) });
  }));

  router.post('/releases/:id/withdraw', wrap(async (req, res) => {
    const id = String(req.params.id ?? '');
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new AppError(404, 'Release not found');
    const row = await db('legacy_agent_releases').where({ id }).first('id', 'withdrawn_at', 'version_code') as { id: string; withdrawn_at: Date | null; version_code: number } | undefined;
    if (!row) throw new AppError(404, 'Release not found');
    if (row.withdrawn_at) { res.json({ success: true, data: { withdrawn: false } }); return; }
    if (!(await strictStepUp(req, res, 'legacy_agent.release_withdraw'))) return;
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToIdentity(() => db.transaction(async (trx) => {
      await audit.appendInTx(trx, {
        tenantId: MASTER_TENANT_ID, action: 'legacy_agent.release_withdrawn', target: { type: 'legacy_agent_release', id }, details: { versionCode: Number(row.version_code) },
      }, ctx);
      // A withdrawn version is never served to the bench stations (lot BANC §3.1 h): its mark goes with it.
      await trx('legacy_agent_releases').where({ id }).whereNull('withdrawn_at').update({ withdrawn_at: new Date(), bench_served: false });
    }));
    res.json({ success: true, data: { withdrawn: true } });
  }));

  router.get('/settings', wrap(async (_req, res) => {
    res.json({ success: true, data: await settingsView() });
  }));

  router.put('/settings', wrap(async (req, res) => {
    const parsed = SettingsBody.safeParse(req.body ?? {});
    if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
    const b = parsed.data;
    const pairs: Array<[string, number | boolean]> = [];
    if (b.pollSeconds !== undefined) pairs.push([CONFIG_KEYS.pollSeconds, b.pollSeconds]);
    if (b.minVersionCode !== undefined) pairs.push([CONFIG_KEYS.minVersionCode, b.minVersionCode]);
    if (b.inventorySeconds !== undefined) pairs.push([CONFIG_KEYS.inventorySeconds, b.inventorySeconds]);
    if (b.autoUpdate !== undefined) pairs.push([CONFIG_KEYS.autoUpdate, b.autoUpdate]);
    if (b.autoUpdatePerHour !== undefined) pairs.push([CONFIG_KEYS.autoUpdatePerHour, b.autoUpdatePerHour]);
    // Widening the automatic update (turning it on, or raising its pace while it is on) pushes a version to the
    // fleet of every tenant without any other step: a strict second factor, like the upload of that version.
    const before = await instanceSettings(true);
    const on = b.autoUpdate ?? before.autoUpdate;
    if ((b.autoUpdate === true && !before.autoUpdate) || (on && b.autoUpdatePerHour !== undefined && b.autoUpdatePerHour > before.autoUpdatePerHour)) {
      if (!(await strictStepUp(req, res, 'legacy_agent.auto_update'))) return;
    }
    const ctx = await audit.fromRequest(req, MASTER_TENANT_ID);
    await switchToIdentity(() => db.transaction(async (trx) => {
      for (const [key, value] of pairs) await trx('app_config').insert({ key, value: String(value) }).onConflict('key').merge({ value: String(value) });
      if (pairs.length > 0) {
        await audit.appendInTx(trx, { tenantId: MASTER_TENANT_ID, action: 'legacy_agent.settings_changed', details: Object.fromEntries(pairs) }, ctx);
      }
    }));
    forgetInstanceSettings();
    res.json({ success: true, data: await settingsView() });
  }));

  router.get('/server-key', wrap(async (_req, res) => {
    res.json({ success: true, data: await serverKeyView() });
  }));

  router.post('/server-key/export', wrap(async (req, res) => {
    if (!(await strictStepUp(req, res, 'legacy_agent.server_key_export'))) return;
    const out = await exportServerKey(await audit.fromRequest(req, MASTER_TENANT_ID));
    if (out === 'missing') throw new AppError(503, 'The instance key is missing from the vault', 'serverKeyMissing');
    if (out === 'already_exported') throw new AppError(409, 'The instance key was already exported for escrow', 'alreadyExported');
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, data: out });
  }));

  return router;
}
