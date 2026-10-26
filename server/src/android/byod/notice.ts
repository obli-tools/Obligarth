// Notice of a personal Android device, shown by the device surface before the Google link (lot AN-F1, section 10.5,
// USR-01). Same interface as the notice of the device surface of lot C (apple/enrollment/notice.ts on main:
// EnrollmentNotice, noticeFor, recordAcknowledgement; version ids derived by nameUuid from
// 'default-<method>-<ownership>-v1'), so that the junction plugs the provider of lot C (or USR-01's) with
// setAndroidNoticeProvider and nothing else changes. The default provider: the text of lot C for a personal device
// (i18n.ts), version default-android_byod_link-personal-v1; the acknowledgement is kept on the invitation
// (notice_version_id, acknowledged_at, ack_locale, notice_ack_id) for want of USR-01's table.
// Since P0-13 T5 (USR-01) the generated notice of the tenant replaces it in every process (privacy/notice/provider.ts,
// installed by registerPrivacyModule; channels android_byod_invitation and android_signin of notice_acknowledgements).
import { createHash, randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import { byodTexts, fill, isByodLocale } from './i18n';

export interface AndroidNotice {
  /** Immutable version of the notice text (a UUID). */
  versionId: string;
  locale: string;
  title: string;
  /** Plain text only: rendered with escaping, never as HTML. */
  sections: Array<{ heading: string; paragraphs: string[] }>;
  consentSummary: string;
  contact: string | null;
}

/** The provider shape of lot C (EnrollmentNoticeProvider) for the ownership personal and the method android_byod_link. */
export interface AndroidNoticeProvider {
  noticeFor(trx: Knex | Knex.Transaction, tenantId: number, ownership: 'personal', locale: string,
    ctx: { method: 'android_byod_link'; organization: string }): Promise<AndroidNotice | null>;
  /** sessionId: the invitation (channel android_byod_invitation, by default) or the sign-in session (android_signin);
   *  endUserId: its end user when known. */
  recordAcknowledgement(trx: Knex.Transaction, tenantId: number,
    ack: { sessionId: string; versionId: string; locale: string; at: Date; channel?: 'android_byod_invitation' | 'android_signin';
      endUserId?: number | null }): Promise<string>;
}

/** A UUID derived from a name (SHA-256, version nibble 8): lot C's nameUuid. */
export function nameUuid(name: string): string {
  const h = createHash('sha256').update(name, 'utf8').digest();
  h[6] = (h[6] & 0x0f) | 0x80;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`;
}

/** The version id of the default notice of a personal Android device (lot C's defaultNoticeVersion). */
export const DEFAULT_BYOD_NOTICE_VERSION = nameUuid('default-android_byod_link-personal-v1');

const MAX_CONSENT = 500;

const defaultProvider: AndroidNoticeProvider = {
  async noticeFor(_trx, _tenantId, _ownership, locale, ctx) {
    const lang = isByodLocale(locale) ? locale : 'fr';
    const t = byodTexts(lang).notice;
    const v = { org: ctx.organization };
    return {
      versionId: DEFAULT_BYOD_NOTICE_VERSION,
      locale: lang,
      title: fill(t.title, v),
      sections: t.sections.map((s) => ({ heading: fill(s.heading, v), paragraphs: s.paragraphs.map((p) => fill(p, v)) })),
      consentSummary: fill(t.consentSummary, v).slice(0, MAX_CONSENT),
      contact: null,
    };
  },
  async recordAcknowledgement() {
    // The invitation keeps the acknowledgement; its id references nothing else.
    return randomUUID();
  },
};

let provider: AndroidNoticeProvider = defaultProvider;

/** The junction (AN-A2) plugs lot C's provider (or USR-01's), before anything starts. */
export function setAndroidNoticeProvider(p: AndroidNoticeProvider): void {
  provider = p;
}

/** Test hook and junction check: is the default (laboratory) notice in place? */
export function usesDefaultAndroidNotice(): boolean {
  return provider === defaultProvider;
}

/** Test hook: back to the default provider. */
export function resetAndroidNoticeProvider(): void {
  provider = defaultProvider;
}

export const androidNotice = (): AndroidNoticeProvider => provider;
