// E-mail of an Android BYOD invitation (lot AN-F1, section 10.5; decision of the owners of 15/10: the code and the
// link shown to the administrator, and sent by e-mail when a channel is configured), with the channel rules of the
// e-mails of lot C (apple/enrollment/mail.ts on main): an SMTP server of the tenant (the first one), else the
// platform's server of the one-time codes (app_config otp_smtp_server_id). Sent right after the creation, outside
// any transaction, in the request's tenant context, never through a durable job (the message carries the code,
// which must not be stored in a job's data). Never logged: the recipient, the link, the code. At the junction the
// channel of lot C (enrollmentMailChannel) may replace byodMailChannel.
import nodemailer from 'nodemailer';
import type { AndroidByodMailOutcome } from '@obligarth/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { smtpServerService, type SmtpTransport } from '../../services/smtpServer.service';
import { byodTexts, fill, isByodLocale } from './i18n';
import { esc } from './pages';

export interface ByodMail {
  to: string;
  locale: string;
  organization: string;
  expiresAt: Date;
  code: string;
  url: string;
}

const MAIL_TIMEOUT_MS = 10_000;
/** The whole sending, in the console's request: beyond it, 'failed' (the code is shown to the administrator anyway). */
const MAIL_DEADLINE_MS = 15_000;

/** The SMTP transport of the tenant's channel (in the tenant's context), or null when none is configured. */
export async function byodMailChannel(tenantId: number): Promise<SmtpTransport | null> {
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

/** The subject, the text and the HTML of the message (pure; the values escaped in the HTML). */
export function composeByodMail(m: ByodMail): { subject: string; text: string; html: string } {
  const t = byodTexts(isByodLocale(m.locale) ? m.locale : 'fr');
  const expires = m.expiresAt.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const values: Record<string, string> = { org: m.organization, expires, url: m.url, code: m.code };
  const lines = t.mailBody.map((l) => fill(l, values));
  const subject = fill(t.mailSubject, values).replace(/[\r\n]+/g, ' ');
  const html = lines.map((l) => `<p>${esc(l)}</p>`).join('\n');
  return { subject, text: lines.join('\n\n'), html };
}

/** Sends the message; never throws (the outcome tells). */
export async function sendByodMail(tenantId: number, m: ByodMail): Promise<AndroidByodMailOutcome> {
  if (!isMailAddress(m.to)) return 'failed';
  let smtp: SmtpTransport | null;
  try {
    smtp = await byodMailChannel(tenantId);
  } catch (err) {
    logger.warn({ tenantId, code: (err as { code?: unknown })?.code }, 'android BYOD e-mail: the channel could not be read');
    return 'failed';
  }
  if (!smtp) return 'not_configured';
  const msg = composeByodMail(m);
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
    await Promise.race([transport.sendMail({ from: smtp.fromAddress, to: m.to, subject: msg.subject, text: msg.text, html: msg.html }), deadline]);
    return 'sent';
  } catch (err) {
    // The error of nodemailer may quote the envelope: its code only.
    logger.warn({ tenantId, code: (err as { code?: unknown; responseCode?: unknown })?.code ?? (err as { responseCode?: unknown })?.responseCode ?? null },
      'android BYOD e-mail not sent');
    return 'failed';
  } finally {
    if (timer) clearTimeout(timer);
    try { transport?.close(); } catch { /* already closed */ }
  }
}
