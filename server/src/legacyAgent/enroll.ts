import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Knex } from 'knex';
import { LEGACY_AGENT_TOKEN_RE } from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { asNone, asTenant } from '../db/context';
import { raiseInTx } from '../apple/alerts/service';
import { LEGACY_AGENT_ACTOR } from './actor';
import { agentConfigFor } from './agentConfig';
import { instanceSettings } from './config';
import { EnrollBody } from './schemas';
import { currentServerKey } from './serverKey';
import { fromB64url, p256PublicKey, sha256Hex } from './signature';
import { errorReply, signatureHolds, type Exchange, type Reply } from './surface';

// =============================================================================
// POST /agent/v1/enroll (docs: agent-pont-android §4.4, RS-7, PB13): the
// token of a tenant and the proof of possession of the agent's key (the
// request is signed by the key whose SPKI is in its body).
//   - token: OLE1.<publicId>.<secret>; unknown, revoked, expired, used up or a
//     wrong secret: the same 403 tokenInvalid; the secret compared in constant
//     time with its SHA-256;
//   - the same key already enrolled in the token's tenant: 200 and the same
//     answer, no use consumed, checked BEFORE the token's usability (RS-7: an
//     agent whose answer was lost is not stuck after the expiry); enrolled in
//     another tenant: 403 tokenInvalid;
//   - one transaction of the tenant: the use of the token (no race: the
//     UPDATE … WHERE uses < max_uses), the record (devices), the satellite, the
//     audit entry; a serial or an IMEI already carried by a managed record of
//     the tenant: a new record without serial, identity_conflict, an alert.
// =============================================================================

const SERIAL_JUNK = new Set(['', 'unknown', '0', 'null', 'none', '0123456789abcdef', '0123456789ABCDEF']);

function serialOf(v: string | null | undefined): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (SERIAL_JUNK.has(s) || !/^[A-Za-z0-9-]{3,64}$/.test(s)) return null;
  return s;
}

const clean = (v: string | null | undefined, max: number): string | null => {
  if (typeof v !== 'string') return null;
  // Control characters out (the console shows these values).
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s ? s.slice(0, max) : null;
};

const tokenInvalid = (): Reply => errorReply(403, 'tokenInvalid', 'Enrollment token invalid');

export interface EnrollOutcome { reply: Reply; tenantId?: number }

function sameSecret(secret: string, expectedHex: string): boolean {
  const a = Buffer.from(sha256Hex(Buffer.from(secret, 'utf8')), 'hex');
  const b = Buffer.from(String(expectedHex), 'hex');
  return a.length === 32 && b.length === 32 && timingSafeEqual(a, b);
}

async function answer(trx: Knex.Transaction, tenantId: number, agentId: string, deviceUuid: string, status: 200 | 201): Promise<Reply> {
  const key = await currentServerKey();
  const s = await instanceSettings();
  const sat = await trx('legacy_agent_devices').where({ tenant_id: tenantId, agent_id: agentId }).first('poll_seconds') as { poll_seconds: number | null } | undefined;
  return {
    status,
    body: {
      agentId, deviceUuid, serverTime: Math.floor(Date.now() / 1000), pollSeconds: sat?.poll_seconds ?? s.pollSeconds,
      serverKeys: key ? [{ keyId: key.keyId, spki: key.spkiB64url }] : [],
      config: await agentConfigFor(trx, tenantId),
    },
  };
}

export async function handleEnroll(ex: Exchange, raw: Buffer, perToken: (publicId: string) => number): Promise<EnrollOutcome> {
  let json: unknown;
  try { json = JSON.parse(raw.toString('utf8')); } catch { return { reply: errorReply(400, 'badRequest', 'Malformed JSON') }; }
  const parsed = EnrollBody.safeParse(json);
  if (!parsed.success) return { reply: errorReply(400, 'badRequest', `Invalid body: ${parsed.error.issues[0]?.path.join('.') ?? ''}`.slice(0, 200)) };
  const b = parsed.data;

  // The key and the proof of possession first: nothing is looked up for a request its key does not sign.
  const spki = fromB64url(b.publicKey, 200);
  if (!spki || !p256PublicKey(spki)) return { reply: errorReply(400, 'badKey', 'The key must be an EC P-256 SubjectPublicKeyInfo') };
  if (!signatureHolds(ex, spki)) return { reply: { ...errorReply(401, 'badSignature', 'Bad signature'), signed: false } };
  if (!LEGACY_AGENT_TOKEN_RE.test(b.token)) return { reply: tokenInvalid() };
  const [, publicId, secret] = b.token.split('.');
  const wait = perToken(publicId);
  if (wait) return { reply: errorReply(429, 'rateLimited', 'Too many requests', {}, { 'Retry-After': String(wait) }) };

  const lookup = await asNone(LEGACY_AGENT_ACTOR, () => db.raw('SELECT tenant_id, token_id, secret_sha256, usable FROM obligarth.legacy_agent_token_lookup(?)', [publicId])) as
    { rows: Array<{ tenant_id: number; token_id: string; secret_sha256: string; usable: boolean }> };
  const tok = lookup.rows[0];
  if (!tok || !sameSecret(secret, tok.secret_sha256)) return { reply: tokenInvalid() };
  const tenantId = Number(tok.tenant_id);
  const keySha = sha256Hex(spki);

  try {
    const reply = await asTenant(tenantId, LEGACY_AGENT_ACTOR, () => db.transaction(async (trx) => {
      // RS-7: the same key already enrolled in this tenant: the same answer, no use consumed.
      const existing = await trx('legacy_agent_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
        .where({ 'a.tenant_id': tenantId, 'a.key_sha256': keySha }).first('a.agent_id', 'a.revoked_at', 'd.uuid') as
        { agent_id: string; revoked_at: Date | null; uuid: string } | undefined;
      if (existing) {
        if (existing.revoked_at) return errorReply(403, 'agentRevoked', 'This device was removed from management');
        return answer(trx, tenantId, String(existing.agent_id), String(existing.uuid), 200);
      }
      if (!tok.usable) return tokenInvalid();
      const used = await trx('legacy_agent_enrollment_tokens')
        .where({ tenant_id: tenantId, id: tok.token_id }).where('uses', '<', trx.raw('max_uses')).whereNull('revoked_at').where('expires_at', '>', trx.fn.now())
        .update({ uses: trx.raw('uses + 1'), last_used_at: trx.fn.now() }).returning(['id', 'group_id']) as Array<{ id: string; group_id: number | null }>;
      if (used.length === 0) return tokenInvalid();
      let groupId = used[0].group_id === null ? null : Number(used[0].group_id);
      if (groupId !== null && !(await trx('device_groups').where({ tenant_id: tenantId, id: groupId }).first('id'))) groupId = null;

      const d = b.device;
      const serial = serialOf(d.samsungSerial) ?? serialOf(d.serial);
      const imeis = [...new Set(d.imeis ?? [])];
      // PB13: a serial or an IMEI never takes the record of a device still under management.
      let conflict = false;
      if (serial) {
        const held = await trx('devices').where({ tenant_id: tenantId, serial_number: serial }).select('id', 'enrollment_state', 'management_channel') as
          Array<{ id: number; enrollment_state: string; management_channel: string }>;
        if (held.some((h) => h.enrollment_state !== 'unenrolled')) conflict = true;
        // A record of this channel that left management keeps its history, not the serial (the unique index).
        const old = held.filter((h) => h.enrollment_state === 'unenrolled' && h.management_channel === 'legacy_agent').map((h) => Number(h.id));
        if (!conflict && old.length > 0) await trx('devices').where({ tenant_id: tenantId }).whereIn('id', old).update({ serial_number: null, updated_at: new Date() });
      }
      if (!conflict && imeis.length > 0) {
        const hit = await trx('legacy_agent_devices').where({ tenant_id: tenantId }).whereNull('revoked_at')
          .whereRaw('imeis && ?::text[]', [imeis]).first('device_id');
        if (hit) conflict = true;
      }

      const now = new Date();
      const manufacturer = clean(d.manufacturer, 64);
      const model = clean(d.model, 64);
      const [dev] = await trx('devices').insert({
        tenant_id: tenantId, group_id: groupId, platform: 'android', management_channel: 'legacy_agent', ownership: 'corporate',
        enrollment_type: 'agent_token', management_mode: 'device_admin', supervised: false, usage: 'standard',
        enrollment_state: 'enrolled', enrollment_state_at: now, enrolled_at: now, last_checkin_at: now,
        serial_number: conflict ? null : serial, model, model_name: [manufacturer, model].filter(Boolean).join(' ').slice(0, 128) || null,
        os_version: clean(d.osVersion, 32), os_build: clean(d.build, 32), device_name: clean(d.deviceName, 255),
        display_name: clean(b.hints?.deviceName, 255), updated_at: now,
      }).returning(['id', 'uuid']) as Array<{ id: number; uuid: string }>;
      const deviceId = Number(dev.id);
      const agentId = randomUUID();
      await trx('legacy_agent_devices').insert({
        device_id: deviceId, tenant_id: tenantId, agent_id: agentId, public_key_spki: spki, key_sha256: keySha, key_storage: b.keyStorage,
        attestation: b.attestation && b.attestation.length > 0 ? JSON.stringify({ certificates: b.attestation.length, verified: false }) : null,
        token_id: tok.token_id, last_seq: 0, agent_version_code: b.agent.versionCode, agent_version_name: clean(b.agent.versionName, 32) ?? '?',
        admin_active: b.capabilities.adminActive, knox_state: b.capabilities.knox.state,
        knox_info: JSON.stringify({ version: clean(b.capabilities.knox.version, 64), mdmApiLevel: clean(b.capabilities.knox.mdmApiLevel, 64), error: null }),
        api_level: d.apiLevel ?? null, security_patch: d.securityPatch ?? null, android_id: d.androidId ? d.androidId.toLowerCase() : null,
        claimed_serial: serialOf(d.serial), samsung_serial: serialOf(d.samsungSerial), imeis,
        hints: b.hints ? JSON.stringify({ deviceName: clean(b.hints.deviceName, 255), serial: clean(b.hints.serial, 64), imei: clean(b.hints.imei, 32) }) : null,
        identity_conflict: conflict, last_poll_at: now, enrolled_at: now,
      });
      const ctx = await audit.fromDbActor(LEGACY_AGENT_ACTOR, tenantId);
      await audit.appendInTx(trx, {
        tenantId, action: 'legacy_agent.device_enrolled', target: { type: 'device', id: String(deviceId), device: deviceId },
        details: { tokenId: tok.token_id, agentVersionCode: b.agent.versionCode, keyStorage: b.keyStorage, adminActive: b.capabilities.adminActive,
          knoxState: b.capabilities.knox.state, identityConflict: conflict },
      }, ctx, { onFailure: 'spool' });
      if (conflict) {
        await audit.appendInTx(trx, {
          tenantId, action: 'legacy_agent.identity_conflict', target: { type: 'device', id: String(deviceId), device: deviceId }, details: { at: 'enroll' },
        }, ctx, { onFailure: 'spool' });
        await raiseInTx(trx, tenantId, 'legacy_agent.identity_conflict', { discriminant: deviceId, navigateTo: `/legacy-agent?device=${deviceId}` });
      }
      return answer(trx, tenantId, agentId, String(dev.uuid), 201);
    }));
    return { reply, tenantId };
  } catch (err) {
    // The key enrolled in another tenant (unique key_sha256): the same refusal as a bad token.
    if ((err as { code?: string })?.code === '23505' && /key_sha256|agent_id/.test(String((err as { constraint?: string }).constraint ?? ''))) {
      return { reply: tokenInvalid() };
    }
    throw err;
  }
}
