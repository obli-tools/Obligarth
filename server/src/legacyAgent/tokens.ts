import type { Knex } from 'knex';
import { randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import {
  LEGACY_AGENT_ACTIVATE_SCRIPT, LEGACY_AGENT_ADMIN_OFF_SCRIPT, LEGACY_AGENT_PUBLIC_APK_PATH, LEGACY_AGENT_TOKEN_BOUNDS,
  legacyAgentEnrollmentScript, legacyAgentQrText, type LegacyAgentTokenCreated, type LegacyAgentTokenView,
} from '@obligarth/shared';
import { audit, type AuditWriteContext } from '../audit';
import { config } from '../config';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { lockSites } from '../sites/lock';
import { currentServerKey, type ServerKey } from './serverKey';
import { sha256Hex } from './signature';

// =============================================================================
// The enrollment tokens of the console (docs: agent-pont-android §4.9; lot P1-QR §3.1-3.2), shared by POST
// /api/legacy-agent/tokens and the enrollment sheet of a site (POST /api/sites/:id/enrollment-sheet):
//   - a token OLE1.<publicId>.<secret>, its secret kept as a SHA-256 only, optionally bound to a group and to a site
//     (the devices it enrolls are attached to the site, then filed in its group when the token names none: enroll.ts);
//   - the configuration v1 shown once (JSON, base64url, the MobiControl script), and its enrollment QR code: OLQ1: then
//     the configuration in base64url, drawn here as a PNG (the library qrcode, never a third-party service), level M;
//   - a sheet of a site (siteSheet) revokes, in its transaction, the sheets of the site still active: one sheet in use
//     per site (a lost or old sheet stops enrolling as soon as the next one is printed); a sheet names no group (the
//     group of its site is read at each enrollment), and archiving the site revokes every token naming it.
// =============================================================================

const keyOfUser = (req: Request): string => `u:${req.session?.userId ?? 'anonymous'}`;
const limitedHandler = (_q: Request, res: Response): void => { res.status(429).json({ success: false, error: 'Too many requests', code: 'rateLimited' }); };
/** The creations of tokens of a user (tokens and sheets alike): 20 a minute. */
export const tokenLimiter = rateLimit({ windowMs: 60_000, max: 20, keyGenerator: keyOfUser, standardHeaders: true, legacyHeaders: false, handler: limitedHandler });

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);

export const TOKEN_COLUMNS = ['id', 'public_id', 'label', 'group_id', 'max_uses', 'uses', 'expires_at', 'revoked_at', 'created_at', 'last_used_at', 'origin',
  'site_id', 'site_sheet'];

export function tokenView(r: Record<string, any>): LegacyAgentTokenView {
  const now = Date.now();
  const state = r.revoked_at ? 'revoked' : new Date(r.expires_at).getTime() <= now ? 'expired' : Number(r.uses) >= Number(r.max_uses) ? 'used_up' : 'active';
  return {
    id: String(r.id), publicId: r.public_id, label: r.label, groupId: r.group_id ?? null, maxUses: Number(r.max_uses), uses: Number(r.uses),
    expiresAt: iso(r.expires_at) as string, revokedAt: iso(r.revoked_at), createdAt: iso(r.created_at) as string, lastUsedAt: iso(r.last_used_at), state,
    origin: r.origin === 'bench' ? 'bench' : 'console', siteId: r.site_id ? String(r.site_id) : null, siteSheet: r.site_sheet === true,
  };
}

/** The image of an enrollment QR code: a PNG data URL (level M: the configuration v1, about 390 characters, makes a
 *  version 15 or so; 640 pixels print sharp at 95 mm). Never stored nor logged: it carries the token. */
export function enrollmentQrPng(text: string): Promise<string> {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: 640 });
}

/** The public link of the agent's APK (step 1 of a sheet), or null when the public address of the instance is unset. */
export function agentApkUrl(): string | null {
  const base = (config.publicUrl || '').replace(/\/+$/, '');
  return base ? `${base}${LEGACY_AGENT_PUBLIC_APK_PATH}` : null;
}

/** Where a device enrolled with a token goes (lot P1-QR §3.2): the site of the token (none when it is archived or gone),
 *  and the group of the token, else the group of its site. A sheet names no group: the group its site has at the
 *  enrollment (a change of the site's group reaches the sheets already printed). Pure: enroll.ts reads the rows. */
export function enrollmentPlacement(token: { groupId: number | null; siteId: string | null },
  site: SiteOfToken | null): { siteId: string | null; groupId: number | null } {
  const usable = token.siteId !== null && site !== null && site.id === token.siteId && !site.archived ? site : null;
  return { siteId: usable?.id ?? null, groupId: token.groupId ?? usable?.groupId ?? null };
}

export interface SiteOfToken { id: string; groupId: number | null; archived: boolean }

/** The site a token names, read at an enrollment (enroll.ts) under the sites lock, taken BEFORE the use of the token is
 *  consumed (sites/lock.ts: the order of the archive, which revokes the tokens of its site). An archive of the site
 *  then runs before (the token is revoked) or after (it counts the device and refuses, siteNotEmpty). null: no site
 *  named, or gone. */
export async function enrollmentSiteInTx(trx: Knex.Transaction, tenantId: number, siteId: string | null): Promise<SiteOfToken | null> {
  if (siteId === null) return null;
  await lockSites(trx, tenantId);
  const r = await trx('sites').where({ tenant_id: tenantId, id: siteId }).first('id', 'group_id', 'archived_at') as
    { id: string; group_id: number | null; archived_at: Date | null } | undefined;
  return r ? { id: String(r.id), groupId: r.group_id === null || r.group_id === undefined ? null : Number(r.group_id), archived: !!r.archived_at } : null;
}

export type TokenRevokeReason = 'sheet_replaced' | 'site_archived';

/** Revokes, in the caller's transaction (under the sites lock), the tokens still usable that name a site: its sheets
 *  only (`sheetsOnly`: a new sheet replaces them) or every one (the site is archived). One entry
 *  legacy_agent.token_revoked each; `by`: the user who revokes (null: another actor, the token's creator is named, as
 *  the bench does). Returns their ids. */
export async function revokeSiteTokensInTx(trx: Knex.Transaction, tenantId: number, siteId: string,
  o: { by: number | null; ctx: AuditWriteContext; reason: TokenRevokeReason; sheetsOnly: boolean }): Promise<string[]> {
  const now = new Date();
  const q = trx('legacy_agent_enrollment_tokens').where({ tenant_id: tenantId, site_id: siteId }).whereNull('revoked_at')
    .where('expires_at', '>', now).where('uses', '<', trx.raw('max_uses'));
  if (o.sheetsOnly) q.where({ site_sheet: true, origin: 'console' });
  const ids = (await q.update({ revoked_at: now, revoked_by: o.by ?? trx.raw('created_by') }).returning('id') as Array<{ id: string }>)
    .map((r) => String(r.id)).sort();
  for (const id of ids) {
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.token_revoked', target: { type: 'legacy_agent_token', id }, details: { reason: o.reason, siteId },
    }, o.ctx);
  }
  return ids;
}

export interface TokenInput {
  label: string;
  /** A sheet names none: the group of its site is read at each enrollment. */
  groupId: number | null;
  siteId: string | null;
  /** The sheet of its site: the sheets of the site still active are revoked. */
  siteSheet: boolean;
  days?: number;
  maxUses?: number;
}

export interface IssuedToken { token: LegacyAgentTokenCreated; revokedPrevious: number }

/** Creates a token of the console in the session's tenant (the caller checked the group and the site). `inTx` runs in
 *  its transaction first (the lock and the check of the site of a sheet). */
export async function issueEnrollmentToken(req: Request, tenantId: number, b: TokenInput,
  inTx?: (trx: Knex.Transaction) => Promise<void>): Promise<IssuedToken> {
  const key = await currentServerKey();
  if (!key) throw new AppError(503, 'The instance key of the Android agents is unavailable', 'serverKeyMissing');
  return issueEnrollmentTokenWith(key, req, tenantId, b, inTx);
}

/** issueEnrollmentToken with the instance key given (its tests). What can fail without the database (the configuration,
 *  the QR code and its PNG) is made BEFORE the transaction: a failure there revokes no sheet and stores no token whose
 *  secret nobody would ever see. */
export async function issueEnrollmentTokenWith(key: Pick<ServerKey, 'sha256'>, req: Request, tenantId: number, b: TokenInput,
  inTx?: (trx: Knex.Transaction) => Promise<void>): Promise<IssuedToken> {
  if (b.siteSheet && !b.siteId) throw new AppError(400, 'A sheet names its site', 'invalidRequest');
  if (b.siteSheet && b.groupId !== null) throw new AppError(400, 'A sheet takes the group of its site at each enrollment', 'invalidRequest');
  const publicId = randomBytes(16).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const token = `OLE1.${publicId}.${secret}`;
  const days = b.days ?? LEGACY_AGENT_TOKEN_BOUNDS.daysDefault;
  // §4.9: the configuration MobiControl deposits (JSON v1, base64url for the extra 'config'), shown once; the same text
  // behind OLQ1: in the QR code the agent scans (lot P1-QR §3.1).
  const conf = { v: 1, server: config.apple.mdmPublicBase ?? '', token, serverKeySha256: key.sha256, knoxLicenseKey: null, hints: { deviceName: null, serial: null, imei: null } };
  const configJson = JSON.stringify(conf);
  const encoded = Buffer.from(configJson, 'utf8').toString('base64url');
  const qrText = legacyAgentQrText(encoded);
  const qrPng = await enrollmentQrPng(qrText);
  const now = new Date();
  const auditCtx = await audit.fromRequest(req, tenantId);
  const { row, revoked } = await db.transaction(async (trx) => {
    if (inTx) await inTx(trx);
    // The sheets of the site still usable: replaced by this one.
    const gone = b.siteSheet
      ? await revokeSiteTokensInTx(trx, tenantId, b.siteId!, { by: req.session.userId!, ctx: auditCtx, reason: 'sheet_replaced', sheetsOnly: true })
      : [];
    const [r] = await trx('legacy_agent_enrollment_tokens').insert({
      tenant_id: tenantId, public_id: publicId, secret_sha256: sha256Hex(Buffer.from(secret, 'utf8')), label: b.label, group_id: b.groupId,
      site_id: b.siteId, site_sheet: b.siteSheet,
      max_uses: b.maxUses ?? LEGACY_AGENT_TOKEN_BOUNDS.maxUsesDefault, expires_at: new Date(now.getTime() + days * 86_400_000), created_by: req.session.userId!,
      created_at: now,
    }).returning(TOKEN_COLUMNS) as Array<Record<string, any>>;
    await audit.appendInTx(trx, {
      tenantId, action: 'legacy_agent.token_created', target: { type: 'legacy_agent_token', id: String(r.id) },
      details: {
        label: b.label, groupId: b.groupId, days, maxUses: Number(r.max_uses),
        ...(b.siteId ? { siteId: b.siteId, siteSheet: b.siteSheet } : {}), ...(gone.length ? { replaced: gone } : {}),
      },
    }, auditCtx);
    return { row: r, revoked: gone.length };
  });
  // `_adminmode on` first (lot ADM): the Lockdown of MobiControl keeps the ACTIVATE button from activating the
  // administrator. The configuration rides on both sendintent lines (legacyAgentEnrollmentScript). The activation
  // script of a device already enrolled and the return line (`_adminmode off`, sent on its own once the
  // administrator is active) hold no secret and come along.
  return {
    token: {
      ...tokenView(row), token, config: encoded, configJson, script: legacyAgentEnrollmentScript(encoded),
      activateScript: LEGACY_AGENT_ACTIVATE_SCRIPT, adminOffScript: LEGACY_AGENT_ADMIN_OFF_SCRIPT, qrText, qrPng,
    },
    revokedPrevious: revoked,
  };
}
