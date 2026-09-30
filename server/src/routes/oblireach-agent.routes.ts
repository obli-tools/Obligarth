import { Router } from 'express';
import { agentAuth } from '../middleware/agentAuth';
import { db } from '../db';
import { logger } from '../utils/logger';
import { oblireachHub } from '../services/oblireachHub.service';
import { agentKeyMayActForDevice, isUuid } from '../services/remoteSessionSecurity';
import { enqueueOrCommand, takeFirstOrCommand, toWire } from '../services/oblireachQueue';
import {
  buildObliReachUpdateCommand, claimAutoUpdate, lastOrUpdateSentAt, noteOrUpdateSent, obliReachUpdateInFlight,
} from '../services/oblireachUpdateGate';
import { getShippedObliReachVersion } from '../services/oblireachAutoInstall.service';
import { isMasterTenant } from '@obliance/shared';
import { permissionService } from '../services/permission.service';
import { getWebView2Mode, webview2ManualRetryAt } from '../services/oblireachWebView2.service';

// ── Auto-update version check ─────────────────────────────────────────────────

// Version shipped by this server (agent/dist/oblireach-version.txt), re-read at
// most once per 60 s so that a new build is picked up without a restart — the
// same reader as the Obliance agent's target and the WS hub.
function getLatestObliReachVersion(): string | null {
  return getShippedObliReachVersion();
}

/** Returns true when `current` is strictly older than `latest` (semver x.y.z). */
function isOlderVersion(current: string, latest: string): boolean {
  const parse = (v: string) => v.replace(/^v/, '').split('.').map(Number);
  const [cm, cmi, cp] = parse(current);
  const [lm, lmi, lp] = parse(latest);
  if (cm !== lm) return cm < lm;
  if (cmi !== lmi) return cmi < lmi;
  return cp < lp;
}

// (Download filename per OS/arch: oblireachUpdateGate.obliReachUpdateFile.)

// ── Agent push router (public, agentAuth) ────────────────────────────────────
const router = Router();

/**
 * POST /api/oblireach/push
 *
 * Heartbeat endpoint for the Oblireach agent binary.
 * Authenticated with the same agent_api_keys as the Obliance agent.
 *
 * Body: { deviceUuid, hostname, os, arch, version, sessions? }
 * Response: { status: "ok", command: { type, id, payload } | null }
 */
router.post('/push', agentAuth, async (req, res, next) => {
  try {
    const tenantId = req.agentTenantId!;
    const { deviceUuid, hostname, os, arch, version, sessions } = req.body as {
      deviceUuid?: string;
      hostname?: string;
      os?: string;
      arch?: string;
      version?: string;
      sessions?: Array<{
        id: number;
        username: string;
        state: string;
        stationName?: string;
        isConsole: boolean;
      }>;
    };

    if (!deviceUuid) {
      return res.status(400).json({ error: 'deviceUuid required' });
    }

    // Check feature flag
    const flag = await db('app_config').where({ key: 'integrated_oblireach_enabled' }).first();
    if (flag && flag.value === 'false') {
      return res.status(403).json({ error: 'Integrated Oblireach is disabled on this server' });
    }

    // SECURITY: the reply hands over (and clears) pending_command, which may
    // be an open_remote_tunnel carrying the relay + privacy unlock tokens.
    // For an enrolled device, only the key that device is bound to may poll
    // for it — same rule as the /api/oblireach/ws channel. A uuid with no
    // devices row (standalone agent) keeps working: no session can target it.
    if (isUuid(deviceUuid)) {
      const device = await db('devices').where({ uuid: deviceUuid }).first('id', 'tenant_id', 'api_key_id');
      if (device && !agentKeyMayActForDevice({ id: req.agentApiKeyId!, tenant_id: tenantId }, device)) {
        logger.warn({ deviceId: device.id, apiKeyId: req.agentApiKeyId }, 'Oblireach push refused: device/API-key mismatch');
        return res.status(403).json({ error: 'Device/API-key mismatch' });
      }
    }

    // Upsert the device record
    const existing = await db('oblireach_devices')
      .where({ device_uuid: deviceUuid, tenant_id: tenantId })
      .first();

    let pendingCommand: { type: string; id: string; payload: Record<string, unknown> } | null = null;
    const sessionsJson = sessions ? JSON.stringify(sessions) : null;

    if (existing) {
      await db('oblireach_devices')
        .where({ id: existing.id })
        .update({
          hostname,
          os,
          arch,
          version,
          sessions: sessionsJson,
          last_seen_at: new Date(),
        });
      // pending_command is a queue (JSON array, see oblireachQueue): a push
      // takes ONE deliverable command, the others stay for the next pushes.
      // (It is jsonb: pg returns it parsed — the old JSON.parse of that
      // object threw, so a queued command never reached a push-only agent.)
      // Re-read under the row lock: `existing` is a snapshot, and a session
      // enqueued since would be lost by writing its leftovers back.
      const first = await takeFirstOrCommand(existing.id);
      pendingCommand = first ? toWire(first) : null;
    } else {
      await db('oblireach_devices').insert({
        tenant_id: tenantId,
        device_uuid: deviceUuid,
        hostname,
        os,
        arch,
        version,
        sessions: sessionsJson,
        last_seen_at: new Date(),
      });
    }

    // ── Auto-update injection ──────────────────────────────────────────────
    // If no pending command is queued and the agent is running an older version,
    // synthesise an update command so the agent installs the new MSI — at most
    // once per device and target version every 10 min, and not while an
    // update / install is already in flight (same gate as the WS heartbeat).
    if (!pendingCommand && version) {
      const latest = getLatestObliReachVersion();
      if (latest && isOlderVersion(version, latest)) {
        const claim = await claimAutoUpdate(deviceUuid, tenantId, latest);
        if (claim.send) {
          pendingCommand = await buildObliReachUpdateCommand('auto_update', os, arch, latest);
          logger.info({ deviceUuid, version, latest }, 'Oblireach agent update queued (next one not before 10 min)');
        } else if (claim.reason !== 'throttled') {
          logger.info({ deviceUuid, version, latest, reason: claim.reason }, 'Oblireach agent update not sent — an update / install is already in progress');
        }
      }
    }

    logger.debug({ deviceUuid, tenantId, version }, 'Oblireach agent push');

    return res.json({
      status: 'ok',
      command: pendingCommand,
    });
  } catch (err) {
    next(err);
  }
});

export default router;

// ── Devices listing router (tenant-scoped, mounted in index.ts) ──────────────

const devicesRouter = Router();

/**
 * GET /latest-version  (mounted at /oblireach/devices in the tenant router)
 * Returns the latest available Oblireach agent version from the build artefact.
 * Registered before /:deviceUuid so the static segment wins.
 */
devicesRouter.get('/latest-version', (_req, res) => {
  const version = getLatestObliReachVersion();
  return res.json({ data: { version } });
});

/**
 * GET /  (mounted at /oblireach/devices in the tenant router)
 * List all Oblireach devices for a tenant.
 */
// Fallback threshold for legacy push-only agents (no persistent WS).
// WS-connected agents always show as online via oblireachHub.isConnected().
const OR_ONLINE_THRESHOLD_MS = 2 * 60 * 1000;

/**
 * oblireach_devices rows visible to this request: an admin of the master
 * tenant (god view) sees every tenant's agents — otherwise a child-tenant
 * device opened from the master showed "Install ObliReach" although it is
 * installed. Everyone else stays tenant-scoped.
 */
function scopedOrDevices(req: any) {
  const tenantId = req.tenantId as number;
  const q = db('oblireach_devices');
  if (!(isMasterTenant(tenantId) && req.session?.role === 'admin')) q.where({ tenant_id: tenantId });
  return q;
}

/** One device's row (god view: the most recently seen row for that uuid in any tenant). */
function findOrDevice(req: any, deviceUuid: string) {
  return scopedOrDevices(req)
    .where({ device_uuid: deviceUuid })
    .orderByRaw('last_seen_at DESC NULLS LAST')
    .first();
}

/**
 * Device uuids a non-admin may see (their teams' devices — the same rule as
 * every other device listing); null = no restriction (admins). A user with
 * no team sees nothing.
 */
async function visibleOrUuids(req: any): Promise<Set<string> | null> {
  if (req.session?.role === 'admin') return null;
  const userId = req.session?.userId;
  if (!userId) return new Set();
  const ids = await permissionService.getVisibleDeviceIds(userId, false);
  if (ids === 'all') return null;
  if (ids.length === 0) return new Set();
  const rows = await db('devices').whereIn('id', ids).whereNotNull('uuid').select('uuid') as Array<{ uuid: string }>;
  return new Set(rows.map((r) => String(r.uuid)));
}

/**
 * User-facing shape of an oblireach_devices row. pending_command is the
 * agent's offline queue: its open_remote_tunnel entries carry the relay
 * sessionToken and the privacy unlockToken (never shown to users).
 */
function publicOrDevice(r: any, now: number) {
  const { pending_command: _queue, ...row } = r;
  return {
    ...row,
    sessions: row.sessions ? JSON.parse(row.sessions) : [],
    // WS-connected agents are always online; fall back to last_seen_at for legacy push agents.
    is_online: oblireachHub.isConnected(row.device_uuid) || (row.last_seen_at
      ? now - new Date(row.last_seen_at).getTime() < OR_ONLINE_THRESHOLD_MS
      : false),
    // Its own self-update (attempt in progress, last result, next attempt),
    // as its last heartbeat reported it; null when offline / not reported.
    self_update: oblireachHub.selfUpdateOf(row.device_uuid),
    // Microsoft Edge WebView2 runtime of the chat window (Windows builds
    // that report it), as its last heartbeat reported it; null otherwise.
    webview2: oblireachHub.webview2Of(row.device_uuid),
  };
}

devicesRouter.get('/', async (req, res, next) => {
  try {
    const visible = await visibleOrUuids(req);
    if (visible && visible.size === 0) return res.json({ data: { items: [] } });
    const q = scopedOrDevices(req);
    if (visible) q.whereIn('device_uuid', [...visible]);
    const rows = await q.orderBy('last_seen_at', 'desc');
    const now = Date.now();
    const items = rows.map((r: any) => publicOrDevice(r, now));
    return res.json({ data: { items } });
  } catch (err) {
    next(err);
  }
});

/** 404 unless this user may see the device (same answer as a missing one). */
async function isOrDeviceVisible(req: any, deviceUuid: string): Promise<boolean> {
  const visible = await visibleOrUuids(req);
  return !visible || visible.has(deviceUuid);
}

/**
 * GET /:deviceUuid/sessions  (mounted at /oblireach/devices in the tenant router)
 * Returns the last-known session list for a specific Oblireach device.
 */
devicesRouter.get('/:deviceUuid/sessions', async (req, res, next) => {
  try {
    const { deviceUuid } = req.params;
    if (!(await isOrDeviceVisible(req, deviceUuid))) return res.status(404).json({ error: 'device not found' });
    const row = await findOrDevice(req, deviceUuid);
    if (!row) {
      return res.status(404).json({ error: 'device not found' });
    }
    const sessions = row.sessions ? JSON.parse(row.sessions) : [];
    return res.json({ data: { sessions } });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /:deviceUuid  (mounted at /oblireach/devices in the tenant router)
 * Returns the device record for a specific Oblireach device (version, os, arch, …).
 */
devicesRouter.get('/:deviceUuid', async (req, res, next) => {
  try {
    const { deviceUuid } = req.params;
    if (!(await isOrDeviceVisible(req, deviceUuid))) return res.status(404).json({ error: 'device not found' });
    const row = await findOrDevice(req, deviceUuid);
    if (!row) return res.status(404).json({ error: 'device not found' });
    // + the platform's WebView2 install mode (the device page's Install button).
    return res.json({ data: { device: { ...publicOrDevice(row, Date.now()), webview2_mode: await getWebView2Mode() } } });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /:deviceUuid/webview2/install  (mounted at /oblireach/devices in the tenant router)
 * The device page's Install button: this device's ObliReach installs the
 * Microsoft Edge WebView2 runtime (chat window) per machine, with the
 * Microsoft-signed bootstrapper it ships — at once, its back-off ignored
 * (one attempt at a time and a 1-min floor still apply on the agent).
 *
 * Rights: admins; anyone else must be a member of the device's tenant, see
 * the device, have write access to it and the capability 'remote' (the
 * chat's right). The device is looked up in the session's tenant (a master
 * tenant admin: any tenant). Refused when the platform setting is 'disabled'.
 *
 * Answer: { status: 'ok', delivered: 'sent' | 'already_installed' | 'in_progress' }
 * Errors: 404 device; 403 {code:'forbidden', error:<text>} (rights; the web
 * client's interceptor shows the text); 409 {error: disabled (platform
 * setting) | not_reporting (offline, or an ObliReach build that does not
 * report WebView2) | no_installer (build without the bootstrapper: update
 * ObliReach) | unsupported (Windows too old) | too_soon (+ retryAt: the
 * previous attempt started less than a minute ago — the agent would ignore
 * it)}.
 */
devicesRouter.post('/:deviceUuid/webview2/install', async (req, res, next) => {
  try {
    const { deviceUuid } = req.params;
    const sessionTenant = (req as any).tenantId as number;
    const userId = (req as any).session?.userId as number | undefined;
    const isAdmin = (req as any).session?.role === 'admin';
    if (!isUuid(deviceUuid) || !userId) return res.status(404).json({ error: 'device not found' });

    const devQ = db('devices').where({ uuid: deviceUuid });
    if (!(isAdmin && isMasterTenant(sessionTenant))) devQ.where({ tenant_id: sessionTenant });
    const device = await devQ.first('id', 'tenant_id');
    if (!device) return res.status(404).json({ error: 'device not found' });
    if (!isAdmin) {
      const member = await db('user_tenants').where({ user_id: userId, tenant_id: device.tenant_id }).first('user_id');
      if (!member || !(await permissionService.canReadDevice(userId, device.id, false))) {
        return res.status(404).json({ error: 'device not found' });
      }
      const allowed = await permissionService.canWriteDevice(userId, device.id, false)
        && await permissionService.canUseCapability(userId, device.id, false, 'remote');
      if (!allowed) {
        return res.status(403).json({
          code: 'forbidden',
          error: 'Installing the chat component on this device needs write access to it and the Remote capability.',
        });
      }
    }

    const mode = await getWebView2Mode();
    if (mode === 'disabled') return res.status(409).json({ error: 'disabled' });
    const wv2 = oblireachHub.webview2Of(deviceUuid);
    if (!wv2 || !oblireachHub.isConnected(deviceUuid)) return res.status(409).json({ error: 'not_reporting' });
    if (wv2.state === 'ok') return res.json({ status: 'ok', delivered: 'already_installed' });
    if (wv2.state === 'installing') return res.json({ status: 'ok', delivered: 'in_progress' });
    if (wv2.state === 'unsupported') return res.status(409).json({ error: 'unsupported' });
    if (!wv2.installer) return res.status(409).json({ error: 'no_installer' });
    // The agent ignores a forced attempt within 1 min of the previous one's
    // start: say so (with when) instead of "started" and nothing happening.
    const retryAt = webview2ManualRetryAt(wv2);
    if (retryAt !== null) {
      return res.status(409).json({ error: 'too_soon', retryAt: new Date(retryAt).toISOString() });
    }

    const sent = oblireachHub.requestWebView2Install(deviceUuid, device.tenant_id);
    if (sent !== 'sent') return res.status(409).json({ error: 'not_reporting' });
    logger.info({ deviceUuid, tenantId: device.tenant_id, userId, state: wv2.state }, 'ObliReach WebView2: install requested from the device page');
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReqAs(req, device.tenant_id, 'oblireach.webview2_install', {
        deviceId: device.id, resourceType: 'device',
        details: { state: wv2.state, reason: wv2.reason, attempts: wv2.attempts, mode },
      });
    } catch { /* audit is best-effort */ }
    return res.json({ status: 'ok', delivered: 'sent' });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /:deviceUuid/command  (mounted at /oblireach/devices in the tenant router)
 * Asks an ObliReach agent to update itself (`update`, the only type).
 * Sent right away over its open command channel; queued (delivered at its
 * next connection) only when it is offline — the queue used to be the only
 * path, and a WS-connected agent only drains it at reconnect, i.e. after the
 * update the click was meant to start. Nothing is sent when it already runs
 * the server's version, nor while an update / install is in flight: the
 * Obliance agent installing it (report / install_oblireach command), its own
 * attempt (guarded builds report it in their heartbeat), or — builds that do
 * not report it — an `update` sent to it within the last 5 min.
 * (For an admin, the device page prefers install_oblireach {mode:'upgrade'}
 * through the Obliance agent 4.5.82+ — verified download, an update rather
 * than a reinstall — when that agent is online: POST /api/commands.)
 *
 * Answer: { status: 'ok', delivered: 'sent' | 'queued' | 'up_to_date' | 'in_progress', reason? }
 * (reason of in_progress: manager_installing | manager_busy_msi |
 * manager_busy_agent_update | install_command | self_update_running | update_sent)
 */
devicesRouter.post('/:deviceUuid/command', async (req, res, next) => {
  try {
    const tenantId = (req as any).tenantId as number;
    const { deviceUuid } = req.params;
    const { type } = req.body as { type: string };

    if (type !== 'update') {
      return res.status(400).json({ error: `unsupported command type: ${type}` });
    }

    if (!(await isOrDeviceVisible(req, deviceUuid))) return res.status(404).json({ error: 'device not found' });
    const row = await findOrDevice(req, deviceUuid);
    if (!row) return res.status(404).json({ error: 'device not found' });

    const latest = getLatestObliReachVersion();
    const current = typeof row.version === 'string' ? row.version.trim() : '';
    if (latest && /^v?\d+\.\d+\.\d+/.test(current) && /^v?\d+\.\d+\.\d+/.test(latest) && !isOlderVersion(current, latest)) {
      return res.json({ status: 'ok', delivered: 'up_to_date' });
    }
    const inFlight = await obliReachUpdateInFlight(row.device_uuid, row.tenant_id);
    if (inFlight) {
      logger.info({ deviceUuid, tenantId, latest, reason: inFlight }, 'Oblireach manual update not sent — an update / install is already in progress');
      return res.json({ status: 'ok', delivered: 'in_progress', reason: inFlight });
    }
    // Its own self-update: a guarded build reports it in its heartbeat (its
    // guard also refuses a second attempt); for an older build, an `update`
    // sent within the last 5 min (automatic or manual) counts as running —
    // a second one would start another download + msiexec on top of it.
    const su = oblireachHub.selfUpdateOf(row.device_uuid);
    const ownReason = su?.inProgress
      ? 'self_update_running'
      : (!su && latest && lastOrUpdateSentAt(row.device_uuid, row.tenant_id, latest) !== null ? 'update_sent' : null);
    if (ownReason) {
      logger.info({ deviceUuid, tenantId, latest, reason: ownReason }, 'Oblireach manual update not sent — its own update is already in progress');
      return res.json({ status: 'ok', delivered: 'in_progress', reason: ownReason });
    }

    const command = await buildObliReachUpdateCommand('manual_update', row.os, row.arch, latest ?? 'latest');

    // Live channel first (the channel must belong to the row's tenant).
    const sent = oblireachHub.pushDetailed(row.device_uuid, command, { tenantId: row.tenant_id, apiKeyId: null });
    if (sent === 'sent') {
      if (latest) noteOrUpdateSent(row.device_uuid, row.tenant_id, latest);
      logger.info({ deviceUuid, tenantId, latest }, 'Oblireach update command sent manually over the command channel');
      return res.json({ status: 'ok', delivered: 'sent' });
    }

    // Offline: appended to the device's queue (it used to overwrite a queued session).
    await enqueueOrCommand(row.device_uuid, row.tenant_id, command);

    logger.info({ deviceUuid, tenantId, latest }, 'Oblireach update command queued manually (agent offline)');
    return res.json({ status: 'ok', delivered: 'queued' });
  } catch (err) {
    next(err);
  }
});

export { devicesRouter as obliReachDevicesRouter };
