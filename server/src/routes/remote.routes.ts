import { Router } from 'express';
import { remoteService } from '../services/remote.service';
import { agentHub } from '../services/agentHub.service';
import { isUuid } from '../services/remoteSessionSecurity';
import { isMasterTenant, type RemoteProtocol } from '@obliance/shared';
import { permissionService } from '../services/permission.service';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import { sessionHash } from '../utils/sessionHash';

const router = Router();

/** The protocols a client may start here. 'sshjump' is the SSH bastion's
 *  own tunnel (services/sshBastion/proxyJump.ts: one-time key grant), never
 *  a client's. */
const CLIENT_PROTOCOLS: ReadonlySet<string> = new Set(['oblireach', 'ssh', 'cmd', 'powershell', 'rdp', 'vmconsole']);

router.post('/sessions', async (req, res, next) => {
  try {
    const { deviceId: rawDeviceId, protocol, sessionId, vmId } = req.body ?? {};
    if (typeof protocol !== 'string' || !CLIENT_PROTOCOLS.has(protocol)) {
      return next(new AppError(400, 'Invalid protocol'));
    }

    // The device, with the REST rules (services/deviceScope.service.ts): the
    // session's tenant (any tenant for an admin on the master tenant: god
    // view); a non-admin must be a member of that tenant, see the device and
    // hold the 'remote' capability. These sessions are SYSTEM / root shells:
    // the capability alone (team grants) never reaches a device outside the
    // caller's tenant.
    const { resolveRequestDevice } = await import('../services/deviceScope.service');
    const access = await resolveRequestDevice(req, rawDeviceId, {
      capability: 'remote', capabilityError: 'Remote access not permitted for your team',
    });
    if (!access.ok) return next(new AppError(access.status, access.error));
    const dev = access.device;
    const deviceId = dev.id;

    // Legacy-agent compatibility gate. No remote shell tunnels on the Go
    // 1.20 build — it has no WebSocket / Oblireach code.
    if (dev.agent_flavor === 'legacy') {
      return next(new AppError(409,
        'Remote sessions (SSH / CMD / PowerShell / ObliReach) are not supported on the legacy agent. Upgrade the agent first.'));
    }

    // The VM console is live-only (no queue fallback): refuse up front when
    // the host agent's command channel is down, instead of creating a
    // session that is already dead (and, on a viewer's reconnect path, one
    // more per retry). createSession re-checks on the actual push.
    if (protocol === 'vmconsole' && !agentHub.isConnected(deviceId)) {
      return next(new AppError(409, 'The host agent is not connected — the VM console needs a live agent connection.'));
    }

    // Action restriction gate — any remote session (SSH, CMD, PowerShell,
    // ObliReach) is controlled by the single `remote.session_start` key: the
    // strictest of the session's tenant and the device's (god view).
    const { applyRestriction } = await import('../services/restriction.service');
    const approved = await applyRestriction(res, {
      req,
      actionKey: 'remote.session_start',
      deviceIds: [deviceId],
      deviceTenantId: dev.tenant_id,
      approvalRequestType: 'batch_command',
      approvalDescription: `Start ${protocol} session on device #${deviceId}`,
      approvalPayload: { action: `open_${protocol}_session`, deviceIds: [deviceId] },
    });
    if (!approved) return;

    const session = await remoteService.createSession(
      deviceId, req.tenantId!, req.session.userId!, protocol as RemoteProtocol,
      typeof sessionId === 'number' ? sessionId : undefined,
      typeof vmId === 'string' ? vmId : undefined,
    );
    // Device-bound 2FA (§6.7): revoking the phone whose session started this
    // ends it, even through a relay that is not attached here.
    if (req.sessionID) remoteService.noteCreatorSession(String(session.id), sessionHash(req.sessionID));
    try {
      const { auditService } = await import('../services/audit.service');
      await auditService.logReq(req, `remote.session_started.${protocol}`, {
        deviceId,
        resourceType: 'remote_session',
        resourcePath: String(session.id),
        // Never the session token (relay key) — the session id is the reference.
        details: { protocol, sessionId: session.id, delivery: session.delivery },
      });
    } catch {}
    res.status(201).json({ data: session });
  } catch (err) { next(err); }
});

router.get('/sessions', async (req, res, next) => {
  try {
    const { deviceId, status } = req.query as any;
    const items = await remoteService.getSessions(req.tenantId!, {
      deviceId: deviceId ? parseInt(deviceId) : undefined, status,
      // Master tenant gets god-view (every session install-wide).
      // Tenant admin sees their tenant's sessions.
      // Plain user sees only their OWN started_by sessions.
      // The service interprets these flags below.
      callerUserId: req.session.userId!,
      callerIsAdmin: req.session.role === 'admin',
    });
    res.json({ data: { items, total: items.length } });
  } catch (err) { next(err); }
});

// Plain users may only end sessions they started — the same visibility rule
// as GET /sessions (they never see other users' sessions). Admins keep the
// supervision "End" action on any session of the tenant.
async function assertCanEndSession(req: any): Promise<void> {
  if (!isUuid(req.params.id)) throw new AppError(404, 'Session not found');
  if (req.session.role === 'admin') return;
  // Same scope as remoteService.endSession (master = god view).
  const q = db('remote_sessions').where({ id: req.params.id });
  if (!isMasterTenant(req.tenantId!)) q.where({ tenant_id: req.tenantId! });
  const row = await q.first('started_by');
  if (row && Number(row.started_by) !== Number(req.session.userId)) {
    throw new AppError(403, 'You can only end remote sessions you started');
  }
}

// POST /sessions/:id/end — matches client remoteApi.endSession
router.post('/sessions/:id/end', async (req, res, next) => {
  try {
    await assertCanEndSession(req);
    // A session already over (failed, timeout…) is left untouched — a
    // viewer's Retry ends the previous session, which must keep its reason.
    const ended = await remoteService.endSession(req.params.id, req.tenantId!, 'user_disconnect');
    if (ended) {
      try {
        const { auditService } = await import('../services/audit.service');
        await auditService.logReq(req, 'remote.session_ended', {
          resourceType: 'remote_session', resourcePath: req.params.id,
        });
      } catch {}
    }
    res.status(204).send();
  } catch (err) { next(err); }
});

// DELETE /sessions/:id — legacy path kept for backward compat
router.delete('/sessions/:id', async (req, res, next) => {
  try {
    await assertCanEndSession(req);
    await remoteService.endSession(req.params.id, req.tenantId!, 'user_disconnect');
    res.status(204).send();
  } catch (err) { next(err); }
});

// ─── Oblireach relay authentication ─────────────────────────────────────────
//
// POST /relay/validate-agent
// Called by the standalone Oblireach relay server to verify that a connecting
// agent is authorised for the given session.  This endpoint is NOT behind the
// normal auth middleware — the relay uses a shared internal secret
// (OBLIREACH_SECRET) passed as the X-Internal-Secret header.
//
// Body:   { sessionToken: string, apiKey: string }
// Returns { valid: boolean, sessionToken: string }
router.post('/relay/validate-agent', async (req, res, next) => {
  try {
    const internalSecret = process.env.OBLIREACH_SECRET;
    if (!internalSecret || req.headers['x-internal-secret'] !== internalSecret) {
      return res.status(403).json({ valid: false, error: 'forbidden' });
    }

    const { sessionToken, apiKey } = req.body as { sessionToken?: string; apiKey?: string };
    if (!sessionToken || !apiKey) {
      return res.status(400).json({ valid: false, error: 'missing fields' });
    }

    // Look up the session and the device's API key together. agent_api_keys
    // has no device_id: a device points at its key via devices.api_key_id
    // (a device whose key was deleted — api_key_id NULL — is refused).
    const row = await db('remote_sessions as rs')
      .join('devices as d', 'd.id', 'rs.device_id')
      .join('agent_api_keys as k', 'k.id', 'd.api_key_id')
      .where('rs.session_token', sessionToken)
      .where('k.key', apiKey)
      .where((q) => q.whereNull('k.is_active').orWhere('k.is_active', true)) // NULL = legacy key (see agentAuth)
      .whereIn('rs.status', ['waiting', 'connecting', 'active'])
      .select('rs.session_token', 'rs.protocol')
      .first();

    if (!row || row.protocol !== 'oblireach') {
      return res.json({ valid: false });
    }

    return res.json({ valid: true, sessionToken: row.session_token });
  } catch (err) { next(err); }
});

// POST /relay/issue-viewer-token
// Called by the Obliance server itself (or by the browser via the regular
// authenticated session) to obtain a short-lived viewer token for the
// Oblireach relay.  Uses the OBLIREACH_SECRET + sessionToken to mint a HMAC
// token that the relay can verify locally.
router.post('/relay/issue-viewer-token', async (req, res, next) => {
  try {
    const { sessionId } = req.body as { sessionId?: string };
    if (!sessionId) return res.status(400).json({ error: 'missing sessionId' });

    // SECURITY: a viewer token lets its bearer watch/drive the stream through
    // the standalone relay, so — like the built-in relay upgrade — only the
    // user who started the session may get one (was: any tenant member).
    const session = await db('remote_sessions')
      .where({ id: sessionId, tenant_id: req.tenantId!, started_by: req.session.userId! })
      .whereIn('status', ['waiting', 'connecting', 'active'])
      .first();

    if (!session || session.protocol !== 'oblireach') {
      return res.status(404).json({ error: 'session not found or wrong protocol' });
    }

    // Derive the relay URL from env (defaults to same host, port 7900)
    const relayHost = process.env.OBLIREACH_RELAY_URL || '';
    const secret    = process.env.OBLIREACH_SECRET    || 'change-me-in-production';
    const viewerToken = issueRelayToken(session.session_token, secret);

    return res.json({ viewerToken, relayHost, sessionToken: session.session_token });
  } catch (err) { next(err); }
});

// ── Helper: mint a relay viewer token identical to the Go relay's format ──────
// Format: "<sessionToken>.<expireUnix>.<hmac-sha256-hex>"
function issueRelayToken(sessionToken: string, secret: string, ttlSeconds = 3600): string {
  const crypto = require('crypto') as typeof import('crypto');
  const expire = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `${sessionToken}.${expire}`;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

export default router;
