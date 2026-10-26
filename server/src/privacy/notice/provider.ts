import type { Knex } from 'knex';
import {
  EMPTY_NOTICE_SETTINGS, NOTICE_LOCALES, type NoticeAckChannel, type NoticeLocale, type NoticePlatform, type NoticeSettings, type Ownership,
} from '@obligarth/shared';
import { audit } from '../../audit';
import type { AuditWriteContext } from '../../audit';
import type { EnrollmentNotice, EnrollmentNoticeProvider } from '../../apple/enrollment/notice';
import type { AndroidNotice, AndroidNoticeProvider } from '../../android/byod/notice';
import { instanceStage } from '../../ops/stage';
import { logger } from '../../utils/logger';
import { privacyMetrics } from '../metrics';
import { androidPrivacyRulesFor, currentProfile, effectiveProfileRules } from '../profiles';
import { retentionValues } from '../retention';
import { backupRetentionDays } from '../retentionPolicy';
import { NoticeIncompleteError } from './errors';
import { noticeGate } from './gate';
import { NOTICE_GENERATOR_VERSION, generateNotice, noticeCollection, type NoticeContent } from './generate';

// =============================================================================
// The notice of the employees served by the enrollments (P0-13 T5, USR-01), replacing the laboratory's default notices
// of Apple (apple/enrollment/notice.ts: OTA, ADE web view, account-driven) and of personal Android devices
// (android/byod/notice.ts: BYOD link, sign-in), installed by installNoticeProviders (registerPrivacyModule) before
// anything starts.
//   - ensureNotice: the notice generated now from the inputs in force (privacy profile of the ownership as each channel
//     applies it, retention values, rotation of the backups, settings, name of the tenant), and its version:
//     obligarth.notice_ensure answers the current version when its content is this one, else publishes it (a new row,
//     or an earlier row of the same content) and supersedes the previous one. A change of the inputs is therefore seen
//     at the next page even before privacy.notice-regenerate runs (a decrease of the retention reaching its date, a
//     renamed tenant); the version of a page stays the same while its content does (the acknowledgement compares it).
//   - noticeFor (both providers): ensureNotice, after the completeness of the settings (D7: warning in lab, refusal
//     outside: NoticeIncompleteError; the Android provider answers null instead, the surfaces of Android show their page
//     "enrollment unavailable"). A version published there gets its audit entry privacy.notice_published (in the
//     caller's transaction when it is one, else its own), as one published by the job.
//   - recordAcknowledgement: one row of notice_acknowledgements for the version shown (its language), the session or
//     invitation, the end user when known; its id is kept by the session or the invitation (notice_ack_id).
//   - publicNoticeFor (P0-13 T6, D6): the same notice for the public page /t/<key>/notice (surface.ts), the same
//     version, published as at an enrollment page when its content changed (audit trigger public_page);
//     generateNoticeNow: the content alone, nothing written (the preview of the console, routes.ts).
// Reads in the caller's connection or transaction, in the tenant's context (the surfaces' asTenant, the job's).
// =============================================================================

type Q = Knex | Knex.Transaction;

/** What published a version: the job privacy.notice-regenerate, an enrollment page, the public page of the notice. */
export type NoticePublishTrigger = 'regeneration' | 'enrollment' | 'public_page';

const isLocale = (v: unknown): v is NoticeLocale => (NOTICE_LOCALES as readonly string[]).includes(v as string);
const localeOf = (v: string): NoticeLocale => (isLocale(v) ? v : 'fr');

/** The settings of the notice of the tenant and their version (0: never set). */
export async function noticeSettingsOf(q: Q, tenantId: number): Promise<{ settings: NoticeSettings; version: number }> {
  const r = await q('tenant_notice_settings').where({ tenant_id: tenantId })
    .first('controller_name', 'controller_address', 'dpo_contact', 'contact', 'recipients_extra', 'intro_fr', 'intro_en', 'version') as
    Record<string, unknown> | undefined;
  if (!r) return { settings: { ...EMPTY_NOTICE_SETTINGS }, version: 0 };
  const s = (k: string): string | null => (typeof r[k] === 'string' && (r[k] as string).trim() !== '' ? r[k] as string : null);
  return {
    settings: {
      controllerName: s('controller_name'), controllerAddress: s('controller_address'), dpoContact: s('dpo_contact'), contact: s('contact'),
      recipientsExtra: s('recipients_extra'), introFr: s('intro_fr'), introEn: s('intro_en'),
    },
    version: Number(r.version ?? 0),
  };
}

/** The version of the retention of the tenant (0: never set). */
async function retentionVersionOf(q: Q, tenantId: number): Promise<number> {
  const r = await q('tenant_retention_policies').where({ tenant_id: tenantId }).first('version') as { version: number } | undefined;
  return r ? Number(r.version) : 0;
}

/** A notice version, current for its platform, ownership and language. */
export interface EnsuredNotice {
  id: string;
  /** Published by this call (a new content became current). */
  published: boolean;
  previousId: string | null;
  sha256: string;
  content: NoticeContent;
  locale: NoticeLocale;
  profileVersion: number | null;
  settingsVersion: number;
  retentionVersion: number;
}

/** The notice the inputs in force give now, and those inputs' versions: nothing is written (the preview of the
 *  console, P0-13 T6; ensureNotice publishes it). */
export async function generateNoticeNow(q: Q, tenantId: number, platform: NoticePlatform, ownership: Ownership, locale: NoticeLocale,
  organization: string, pre?: { settings: NoticeSettings; version: number }): Promise<{
    content: NoticeContent; settings: { settings: NoticeSettings; version: number }; profile: { id: string; version: number } | null;
    retentionVersion: number;
  }> {
  const settings = pre ?? await noticeSettingsOf(q, tenantId);
  const rules = await effectiveProfileRules(q, tenantId, ownership);
  const profile = await currentProfile(q, tenantId, ownership);
  const android = platform === 'android' ? await androidPrivacyRulesFor(q, tenantId, ownership) : undefined;
  const retention = await retentionValues(q, tenantId);
  const retentionVersion = await retentionVersionOf(q, tenantId);
  const content = generateNotice({
    platform, ownership, locale, organization, collection: noticeCollection(platform, ownership, rules, android),
    retention, backupDays: backupRetentionDays(), settings: settings.settings,
  });
  return { content, settings, profile: profile ? { id: profile.id, version: profile.version } : null, retentionVersion };
}

/** The notice of `platform`, `ownership` and `locale` generated from the inputs in force, and its current version. */
export async function ensureNotice(q: Q, tenantId: number, platform: NoticePlatform, ownership: Ownership, locale: NoticeLocale,
  organization: string, pre?: { settings: NoticeSettings; version: number }): Promise<EnsuredNotice> {
  const { content, settings, profile, retentionVersion } = await generateNoticeNow(q, tenantId, platform, ownership, locale, organization, pre);
  const res = await q.raw('SELECT notice_id, published, previous_id, content_sha FROM obligarth.notice_ensure(?, ?, ?, ?::jsonb, ?::uuid, ?, ?, ?)',
    [platform, ownership, locale, JSON.stringify(content), profile?.id ?? null, settings.version, retentionVersion, NOTICE_GENERATOR_VERSION]) as {
    rows: Array<{ notice_id: string; published: boolean; previous_id: string | null; content_sha: string }>;
  };
  const row = res.rows[0];
  if (!row?.notice_id) throw Object.assign(new Error('notice: no version answered'), { code: 'noticeUnavailable' });
  return {
    id: String(row.notice_id), published: row.published === true, previousId: row.previous_id ? String(row.previous_id) : null,
    sha256: String(row.content_sha), content, locale, profileVersion: profile?.version ?? null, settingsVersion: settings.version, retentionVersion,
  };
}

/** The audit entry of a version published (privacy.notice_published, standard: hash and versions, never the text). */
export function noticePublishedEntry(tenantId: number, platform: NoticePlatform, ownership: Ownership, n: EnsuredNotice,
  trigger: NoticePublishTrigger) {
  return {
    tenantId, action: 'privacy.notice_published', target: { type: 'notice_version', id: n.id },
    details: {
      platform, ownership, locale: n.locale, sha256: n.sha256, previousId: n.previousId, profileVersion: n.profileVersion,
      settingsVersion: n.settingsVersion, retentionVersion: n.retentionVersion, generator: NOTICE_GENERATOR_VERSION, trigger,
    },
  };
}

const isTransaction = (q: Q): q is Knex.Transaction => (q as Knex.Transaction).isTransaction === true;

/** The audit entry of a version a page published (an enrollment page, the public page of the notice): in the caller's
 *  transaction, else its own. */
async function auditPublishedByPage(q: Q, tenantId: number, platform: NoticePlatform, ownership: Ownership, n: EnsuredNotice,
  trigger: 'enrollment' | 'public_page'): Promise<void> {
  privacyMetrics.noticePublished(trigger);
  const entry = noticePublishedEntry(tenantId, platform, ownership, n, trigger);
  const ctx: AuditWriteContext = audit.system('enrollment', 'notice');
  if (isTransaction(q)) await audit.appendInTx(q, entry, ctx);
  else await audit.append(entry, ctx);
}

/** A warning in lab is logged once every ten minutes per tenant at most. */
const WARN_EVERY_MS = 10 * 60_000;
const warnedAt = new Map<number, number>();

/** The notice of an enrollment page (both providers): its completeness first (D7), then the current version. */
export async function enrollmentNoticeFor(q: Q, tenantId: number, platform: NoticePlatform, ownership: Ownership, locale: string,
  organization: string): Promise<EnsuredNotice> {
  const settings = await noticeSettingsOf(q, tenantId);
  const gate = noticeGate(settings.settings, instanceStage());
  if (gate.kind === 'refuse') {
    privacyMetrics.noticeIncomplete('refused');
    logger.warn({ tenantId, platform, missing: gate.missing, stage: instanceStage() }, 'notice: incomplete, enrollment refused outside the laboratory');
    throw new NoticeIncompleteError(gate.missing);
  }
  if (gate.kind === 'warn') {
    privacyMetrics.noticeIncomplete('warned');
    const now = Date.now();
    if (now - (warnedAt.get(tenantId) ?? 0) >= WARN_EVERY_MS) {
      if (warnedAt.size >= 5_000) warnedAt.clear();
      warnedAt.set(tenantId, now);
      logger.warn({ tenantId, platform, missing: gate.missing }, 'notice: incomplete (laboratory: served; refused in pilot and production)');
    }
  }
  const n = await ensureNotice(q, tenantId, platform, ownership, localeOf(locale), organization, settings);
  if (n.published) await auditPublishedByPage(q, tenantId, platform, ownership, n, 'enrollment');
  return n;
}

/** The notice of the public page of a tenant (P0-13 T6, D6: GET /t/<key>/notice, privacy/notice/surface.ts): the notice
 *  an enrollment would show now, the same version. Not complete outside the laboratory: NoticeIncompleteError (the page
 *  says the notice is not available yet; not counted as an enrollment refused, nothing logged: anyone may open it). */
export async function publicNoticeFor(q: Q, tenantId: number, platform: NoticePlatform, ownership: Ownership, locale: NoticeLocale,
  organization: string): Promise<EnsuredNotice> {
  const settings = await noticeSettingsOf(q, tenantId);
  const gate = noticeGate(settings.settings, instanceStage());
  if (gate.kind === 'refuse') throw new NoticeIncompleteError(gate.missing);
  const n = await ensureNotice(q, tenantId, platform, ownership, locale, organization, settings);
  if (n.published) await auditPublishedByPage(q, tenantId, platform, ownership, n, 'public_page');
  return n;
}

/** The acknowledgement of a version shown to the employee (its language is the version's). */
export async function recordNoticeAcknowledgement(trx: Knex.Transaction, tenantId: number, ack: {
  channel: NoticeAckChannel; subjectRef: string; versionId: string; at: Date; endUserId?: number | null;
}): Promise<string> {
  const r = await trx.raw(`
    INSERT INTO notice_acknowledgements (tenant_id, notice_version_id, channel, subject_ref, end_user_id, locale, acknowledged_at)
    SELECT v.tenant_id, v.id, ?, ?::uuid, ?, v.locale, ? FROM notice_versions v WHERE v.tenant_id = ? AND v.id = ?::uuid
    RETURNING id`, [ack.channel, ack.subjectRef, ack.endUserId ?? null, ack.at, tenantId, ack.versionId]) as { rows: Array<{ id: string }> };
  const id = r.rows[0]?.id;
  // The version was answered by noticeFor in the same transaction: never missing, unless a caller passes another one.
  if (!id) throw Object.assign(new Error('notice: acknowledgement of an unknown version'), { code: 'noticeVersionUnknown' });
  return String(id);
}

const asNotice = (n: EnsuredNotice): EnrollmentNotice & AndroidNotice => ({
  versionId: n.id, locale: n.locale, title: n.content.title, sections: n.content.sections, consentSummary: n.content.consentSummary,
  contact: n.content.contact,
});

/** The provider of the Apple enrollments (OTA, ADE web view, account-driven: the channel apple_session). */
export const appleNoticeProvider: EnrollmentNoticeProvider = {
  async noticeFor(q, tenantId, ownership, locale, ctx) {
    return asNotice(await enrollmentNoticeFor(q, tenantId, 'apple', ownership, locale, ctx.organization));
  },
  async recordAcknowledgement(trx, tenantId, ack) {
    return recordNoticeAcknowledgement(trx, tenantId, {
      channel: 'apple_session', subjectRef: ack.sessionId, versionId: ack.versionId, at: ack.at, endUserId: ack.endUserId ?? null,
    });
  },
};

/** The provider of the personal Android devices (BYOD invitation, sign-in). An incomplete notice outside lab: no notice
 *  (the surfaces answer "enrollment unavailable"; the refusal is logged and counted by enrollmentNoticeFor). */
export const androidNoticeProvider: AndroidNoticeProvider = {
  async noticeFor(q, tenantId, ownership, locale, ctx) {
    try {
      return asNotice(await enrollmentNoticeFor(q, tenantId, 'android', ownership, locale, ctx.organization));
    } catch (err) {
      if (err instanceof NoticeIncompleteError) return null;
      throw err;
    }
  },
  async recordAcknowledgement(trx, tenantId, ack) {
    return recordNoticeAcknowledgement(trx, tenantId, {
      channel: ack.channel ?? 'android_byod_invitation', subjectRef: ack.sessionId, versionId: ack.versionId, at: ack.at,
      endUserId: ack.endUserId ?? null,
    });
  },
};
