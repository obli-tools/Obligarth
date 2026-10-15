import nodemailer from 'nodemailer';
import type { EnrollmentMailOutcome } from '@obligarth/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { smtpServerService, type SmtpTransport } from '../../services/smtpServer.service';
import { fill, isSurfaceLocale, textsFor } from './i18n';
import { esc } from './pages';

// =============================================================================
// E-mail of an enrollment link or an invitation (decision of the owners,
// 15/10: shown to the administrator, and sent by e-mail when a channel is
// configured). The channel: an SMTP server of the tenant (the first one),
// else the platform's server of the one-time codes (app_config
// otp_smtp_server_id). Sent right after the creation, outside any
// transaction, in the request's tenant context, never through a durable job:
// the message carries the secret (link or code), which must not be stored in
// a job's data. Never logged: the recipient, the link, the code.
// =============================================================================

export interface EnrollmentMail {
  to: string;
  locale: string;
  organization: string;
  expiresAt: Date;
  link?: { url: string };
  invitation?: { code: string; account: string; url: string };
}

const MAIL_TIMEOUT_MS = 10_000;
/** The whole sending, in the console's request (review of lot C1, INT-C1-R4): beyond it, 'failed' (the link or the
 *  code is shown to the administrator anyway). */
const MAIL_DEADLINE_MS = 15_000;

/** The SMTP transport of the tenant's channel (in the tenant's context), or null when none is configured. */
export async function enrollmentMailChannel(tenantId: number): Promise<SmtpTransport | null> {
  const own = await db('smtp_servers').where({ tenant_id: tenantId }).orderBy('id').first('id') as { id: number } | undefined;
  if (own) return smtpServerService.getTransportConfig(Number(own.id), { requestTenantId: tenantId });
  const cfg = await db('app_config').where({ key: 'otp_smtp_server_id' }).first('value') as { value: string | null } | undefined;
  const platformId = Number(cfg?.value ?? 0);
  if (!Number.isInteger(platformId) || platformId <= 0) return null;
  const row = await db('smtp_servers').where({ id: platformId }).whereNull('tenant_id').first('id') as { id: number } | undefined;
  return row ? smtpServerService.getTransportConfig(platformId, { requestTenantId: tenantId }) : null;
}

/** A recipient address the mailer accepts (one address, no header injection). */
export const isMailAddress = (v: unknown): v is string =>
  typeof v === 'string' && v.length <= 320 && /^[^\s@<>,;"']+@[^\s@<>,;"']+\.[^\s@<>,;"']+$/.test(v);

/** Sends the message; never throws (the outcome tells). */
export async function sendEnrollmentMail(tenantId: number, m: EnrollmentMail): Promise<EnrollmentMailOutcome> {
  if (!isMailAddress(m.to)) return 'failed';
  let smtp: SmtpTransport | null;
  try {
    smtp = await enrollmentMailChannel(tenantId);
  } catch (err) {
    logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'enrollment e-mail: the channel could not be read');
    return 'failed';
  }
  if (!smtp) return 'not_configured';
  const t = textsFor(isSurfaceLocale(m.locale) ? m.locale : 'fr');
  const expires = m.expiresAt.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const values: Record<string, string> = { org: m.organization, expires, url: m.link?.url ?? m.invitation?.url ?? '',
    code: m.invitation?.code ?? '', account: m.invitation?.account ?? '' };
  const lines = (m.invitation ? t.mailInviteBody : t.mailLinkBody).map((l) => fill(l, values));
  const subject = fill(m.invitation ? t.mailInviteSubject : t.mailLinkSubject, values).replace(/[\r\n]+/g, ' ');
  const html = lines.map((l) => {
    const u = values.url;
    if (u && l === u) return `<p><a href="${esc(u)}">${esc(u)}</a></p>`;
    return `<p>${esc(l)}</p>`;
  }).join('\n');
  let transport: ReturnType<typeof nodemailer.createTransport> | null = null;
  let timer: NodeJS.Timeout | undefined;
  try {
    transport = nodemailer.createTransport({
      host: smtp.host, port: smtp.port, secure: smtp.secure,
      ...(smtp.username ? { auth: { user: smtp.username, pass: smtp.password } } : {}),
      connectionTimeout: MAIL_TIMEOUT_MS, greetingTimeout: MAIL_TIMEOUT_MS, socketTimeout: MAIL_TIMEOUT_MS,
    });
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('deadline'), { code: 'EDEADLINE' })), MAIL_DEADLINE_MS);
      timer.unref?.();
    });
    await Promise.race([transport.sendMail({ from: smtp.fromAddress, to: m.to, subject, text: lines.join('\n\n'), html }), deadline]);
    return 'sent';
  } catch (err) {
    // The error of nodemailer may quote the envelope: its code only.
    logger.warn({ tenantId, code: (err as { code?: unknown; responseCode?: unknown })?.code ?? (err as { responseCode?: unknown })?.responseCode ?? null },
      'enrollment e-mail not sent');
    return 'failed';
  } finally {
    if (timer) clearTimeout(timer);
    try { transport?.close(); } catch { /* already closed */ }
  }
}
