import { createHash, randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import type { EnrollmentProfileMethod, Ownership } from '@obligarth/shared';
import { fill, isSurfaceLocale, textsFor } from './i18n';

// =============================================================================
// Employee notice of an enrollment (docs: integration-apple-edge §10.7, I20):
// an interface whose default implementation (conception §10.3) is reserved to
// the laboratory; the specification of the notice (USR-01) replaces it before
// any pilot. The default notice: a generic translated text, version
// default-<method>-<ownership>-v1 (as a UUID: enrollment_sessions.
// notice_version_id is one), acknowledgement kept in enrollment_sessions
// (notice_version_id, acknowledged_at, notice_ack_id) for want of USR-01's
// table.
// =============================================================================

export interface EnrollmentNotice {
  versionId: string;                              // immutable version of the notice text (a UUID)
  locale: string;
  title: string;
  /** Plain text only: rendered with escaping, never as HTML. */
  sections: Array<{ heading: string; paragraphs: string[] }>;
  consentSummary: string;                         // ConsentText of the profile (≤ 500 characters)
  contact: string | null;
}

export interface EnrollmentNoticeProvider {
  noticeFor(trx: Knex | Knex.Transaction, tenantId: number, ownership: Ownership, locale: string,
    ctx: { method: EnrollmentProfileMethod; organization: string }): Promise<EnrollmentNotice | null>;
  recordAcknowledgement(trx: Knex.Transaction, tenantId: number,
    ack: { sessionId: string; versionId: string; locale: string; at: Date }): Promise<string>;   // acknowledgement id
}

/** A UUID derived from a name (SHA-256, version nibble 8): the stable version id of a default notice. */
export function nameUuid(name: string): string {
  const h = createHash('sha256').update(name, 'utf8').digest();
  h[6] = (h[6] & 0x0f) | 0x80;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`;
}

/** The version id of the default notice of a method and an ownership. */
export const defaultNoticeVersion = (method: EnrollmentProfileMethod, ownership: Ownership): string =>
  nameUuid(`default-${method}-${ownership}-v1`);

const MAX_CONSENT = 500;

const defaultProvider: EnrollmentNoticeProvider = {
  async noticeFor(_trx, _tenantId, ownership, locale, ctx) {
    const lang = isSurfaceLocale(locale) ? locale : 'fr';
    const t = textsFor(lang).notice[ownership];
    const v = { org: ctx.organization };
    return {
      versionId: defaultNoticeVersion(ctx.method, ownership),
      locale: lang,
      title: fill(t.title, v),
      sections: t.sections.map((s) => ({ heading: fill(s.heading, v), paragraphs: s.paragraphs.map((p) => fill(p, v)) })),
      consentSummary: fill(t.consentSummary, v).slice(0, MAX_CONSENT),
      contact: null,
    };
  },
  async recordAcknowledgement() {
    // The session keeps the acknowledgement (notice_version_id, acknowledged_at); its id references nothing else.
    return randomUUID();
  },
};

let provider: EnrollmentNoticeProvider = defaultProvider;

/** USR-01 replaces the default provider, before anything starts. */
export function setEnrollmentNoticeProvider(p: EnrollmentNoticeProvider): void {
  provider = p;
}

/** Is the default (laboratory) notice in place? */
export function usesDefaultNotice(): boolean {
  return provider === defaultProvider;
}

export const enrollmentNotice = (): EnrollmentNoticeProvider => provider;
