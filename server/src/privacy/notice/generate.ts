import type {
  NoticeLocale, NoticePlatform, NoticeSettings, Ownership, PrivacyCollectionScope, PrivacyProfileRules, RetentionCategory,
} from '@obligarth/shared';
import { unenrolledRetentionCategory } from '@obligarth/shared';
import { fill, noticeTexts, type NoticeTextSet } from './i18n';

// =============================================================================
// The generated notice of the employees (P0-13 T5, USR-01; conception §10.3): a pure function of what the organisation
// really collects (the privacy profile of the ownership as each channel applies it: noticeCollection), of the retention
// in force of the tenant, of the rotation of the backups and of the settings of the notice, per platform, ownership and
// language. Nine sections, in this order:
//   1. who manages (the data controller, its address, the paragraph of the organisation);
//   2. what the organisation sees, built from the rules (identifiers, applications, network, location in lost mode
//      only);
//   3. what it does not see (a fixed list, plus the data the profile refuses);
//   4. what it can do (erasure of the whole device or of the work data only, by ownership and platform; location only
//      with lostModeLocation);
//   5. purposes and legal basis (legitimate interest, articles 6.1.f and 32 of the GDPR);
//   6. recipients (the operator of the platform, Apple or Google, the other recipients of the settings);
//   7. durations (the categories of CNF-04 in force, the rotation of the backups);
//   8. rights and complaint to the CNIL;
//   9. contacts (data controller, DPO, other contact).
// consentSummary (the ConsentText of the enrollment profile) is 500 characters at most. Plain text only: every value is
// inserted as it is and escaped by the pages; the settings hold no markup (noticeSettingsErrors, CHECKs of the table).
// The same inputs give the same content, key for key (its SHA-256 names the version: obligarth.notice_ensure).
// No I/O, no import of the database: the unit tests load this file (npm run test:privacy).
// =============================================================================

/** The generation of the texts: moves with any change of i18n.ts or of the assembly below that changes a content. */
export const NOTICE_GENERATOR_VERSION = 1;

/** consentSummary at most (ConsentText of the enrollment profile; CHECK notice_versions_content_shape). */
export const MAX_CONSENT_SUMMARY = 500;

/** The content of a notice version (the EnrollmentNotice of the providers without its version id and language). */
export interface NoticeContent {
  title: string;
  sections: Array<{ heading: string; paragraphs: string[] }>;
  consentSummary: string;
  contact: string | null;
}

/** What the organisation really collects of a device of this platform and ownership. */
export interface NoticeCollection {
  serialNumber: boolean;
  hardwareIds: boolean;
  deviceName: boolean;
  phoneNumber: boolean;
  network: boolean;
  /** The location of the device in lost mode (never a personal device). */
  lostModeLocation: boolean;
  installedApps: PrivacyCollectionScope;
  /** null: the platform reports no certificate (Android). */
  certificates: PrivacyCollectionScope | null;
}

/** What the Android channel applies of a profile (privacy/profiles.ts AndroidProfileRules). */
export interface AndroidCollectionRules {
  networkInfo: boolean;
  imei: boolean;
  installedApps: PrivacyCollectionScope;
}

const isCompany = (o: Ownership): boolean => o === 'corporate' || o === 'corporate_personal';

/**
 * What the organisation collects, as each channel applies the rules of the profile in force:
 *   - Apple: the rules themselves (apple/devices/privacy.ts, the queries of the catalogue); never a location of a
 *     personal device;
 *   - Android: the serial number of a company device always (the ingestion keeps it: android/inventory/privacy.ts),
 *     the IMEI and the carrier as the channel's rules say (`android`: androidPrivacyRulesFor, the rules of before P0-13
 *     while the tenant has no version of the ownership), never the device name nor the phone number, no certificate;
 *     a personal device reports its work profile only.
 */
export function noticeCollection(platform: NoticePlatform, ownership: Ownership, rules: PrivacyProfileRules,
  android?: AndroidCollectionRules): NoticeCollection {
  const lost = ownership !== 'personal' && rules.lostModeLocation;
  if (platform === 'apple') {
    return {
      serialNumber: ownership !== 'personal' && rules.serialNumber,
      hardwareIds: rules.hardwareIds,
      deviceName: rules.deviceName,
      phoneNumber: rules.phoneNumber,
      network: rules.network,
      lostModeLocation: lost,
      installedApps: ownership === 'corporate' ? rules.installedApps : 'managed_only',
      certificates: rules.certificates,
    };
  }
  const company = isCompany(ownership);
  const a = android ?? { networkInfo: company && rules.network, imei: company && rules.network && rules.hardwareIds, installedApps: rules.installedApps };
  const network = company && a.networkInfo;
  return {
    serialNumber: company,
    hardwareIds: network && a.imei,
    deviceName: false,
    phoneNumber: false,
    network,
    lostModeLocation: company && lost,
    installedApps: ownership === 'corporate' ? a.installedApps : 'managed_only',
    certificates: null,
  };
}

/** Everything the generator reads. */
export interface NoticeInput {
  platform: NoticePlatform;
  ownership: Ownership;
  locale: NoticeLocale;
  /** The name of the tenant (the organisation the employees know). */
  organization: string;
  collection: NoticeCollection;
  /** The values in force of the retention of the tenant. */
  retention: Readonly<Record<RetentionCategory, number>>;
  /** The rotation of the backups of the platform, in days (BACKUP_RETENTION_DAYS). */
  backupDays: number;
  settings: Readonly<NoticeSettings>;
}

/** "a, b and c". */
export function joinList(items: readonly string[], and: string): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')}${and}${items[items.length - 1]}`;
}

const clean = (v: string | null | undefined): string | null => {
  const t = typeof v === 'string' ? v.trim() : '';
  return t === '' ? null : t;
};

/** The paragraphs of a multi-line setting (one per non-empty line). */
const paragraphsOf = (v: string | null): string[] => (v ? v.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '') : []);

/** A single-line value (a multi-line setting folded on one line, for a list or a contact). */
const oneLine = (v: string): string => v.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '').join(', ');

function duration(t: NoticeTextSet, unit: 'days' | 'months', n: number): string {
  const forms = unit === 'days' ? t.days : t.months;
  return fill(n === 1 ? forms.one : forms.other, { n: String(n) });
}

/** At most `max` characters, cut at the last space before the limit, with an ellipsis. */
export function clampText(text: string, max: number): string {
  const chars = [...text];
  if (chars.length <= max) return text;
  const head = chars.slice(0, max - 1).join('');
  const cut = head.lastIndexOf(' ');
  return `${(cut > max / 2 ? head.slice(0, cut) : head).replace(/[\s,;:]+$/, '')}…`;
}

/** The notice of a platform, ownership and language. */
export function generateNotice(i: NoticeInput): NoticeContent {
  const t = noticeTexts(i.locale);
  const c = i.collection;
  const o = i.ownership;
  const p = i.platform;
  const company = isCompany(o);
  const org = i.organization.trim() || '—';
  const v = { org };
  const s = i.settings;
  const controller = clean(s.controllerName);
  const address = clean(s.controllerAddress);
  const dpo = clean(s.dpoContact);
  const contact = clean(s.contact);
  const extra = clean(s.recipientsExtra);
  const intro = clean(i.locale === 'fr' ? s.introFr : s.introEn);
  const sections: NoticeContent['sections'] = [];

  // 1. Who manages.
  const who = [fill(t.who[p][o], v)];
  who.push(fill(t.controller, { name: controller ?? org }));
  if (address) who.push(fill(t.controllerAddress, { address: oneLine(address) }));
  who.push(...paragraphsOf(intro));
  sections.push({ heading: company ? t.headings.who : t.headings.whoPersonal, paragraphs: who });

  // 2. What it sees.
  const seen: string[] = [t.data.base[p][company ? 'company' : 'personal']];
  if (c.serialNumber) seen.push(t.data.serialNumber);
  if (c.hardwareIds) seen.push(t.data.hardwareIds[p]);
  if (c.deviceName) seen.push(t.data.deviceName);
  if (c.phoneNumber) seen.push(t.data.phoneNumber);
  if (c.network) seen.push(t.data.network[p]);
  seen.push(!company ? t.data.appsWork[p] : c.installedApps === 'all' ? t.data.appsAll : t.data.appsManaged);
  if (c.certificates) seen.push(c.certificates === 'all' ? t.data.certificatesAll : t.data.certificatesManaged);
  const sees = [fill(t.sees, { list: seen.join(t.listSep) })];
  if (c.lostModeLocation) sees.push(t.lostModeSees);
  sections.push({ heading: t.headings.sees, paragraphs: sees });

  // 3. What it does not see.
  const notSees = [t.notSeesFixed];
  if (!company) notSees.push(t.notSeesPersonal[p]);
  const refused: string[] = [];
  const n = t.notCollectedItems;
  if (!c.serialNumber) refused.push(n.serialNumber);
  if (!c.hardwareIds) refused.push(n.hardwareIds);
  if (!c.deviceName) refused.push(n.deviceName);
  if (!c.phoneNumber) refused.push(n.phoneNumber);
  if (!c.network) refused.push(n.network);
  if (company && c.installedApps === 'managed_only') refused.push(n.otherApps);
  if (c.certificates === 'managed_only') refused.push(n.certificates);
  if (!c.lostModeLocation) refused.push(n.location);
  if (refused.length) notSees.push(fill(t.notCollected, { list: refused.join(t.listSep) }));
  if (c.lostModeLocation) notSees.push(t.locationOnlyLost);
  sections.push({ heading: t.headings.notSees, paragraphs: notSees });

  // 4. What it can do.
  const canDo = [fill(t.canDo[p][o], v)];
  if (c.lostModeLocation) canDo.push(t.canDoLostMode);
  if (company) canDo.push(t.safeguards);
  sections.push({ heading: t.headings.canDo, paragraphs: canDo });

  // 5. Purposes and legal basis.
  sections.push({ heading: t.headings.purposes, paragraphs: t.purposes.map((x) => fill(x, v)) });

  // 6. Recipients.
  const recipients = [fill(t.recipientsOrg, v), t.recipientsPlatform[p][company ? 'company' : 'personal']];
  if (extra) recipients.push(`${fill(t.recipientsExtra, { list: oneLine(extra) })}${/[.!]$/.test(oneLine(extra)) ? '' : '.'}`);
  sections.push({ heading: t.headings.recipients, paragraphs: recipients });

  // 7. Durations.
  const r = i.retention;
  const d = t.durations;
  const durations = [
    fill(d.record, { n: duration(t, 'days', r[unenrolledRetentionCategory(o)]) }),
    fill(d.departed, { n: duration(t, 'days', r.departed_end_user_days) }),
    fill(d.logs, { n: duration(t, 'months', r.technical_log_months) }),
  ];
  if (p === 'apple') durations.push(fill(d.statusHistory, { n: duration(t, 'days', r.status_history_days) }));
  if (c.lostModeLocation) durations.push(fill(d.lostMode, { n: duration(t, 'days', r.lost_mode_location_days) }));
  durations.push(fill(d.ack, { n: duration(t, 'months', r.notice_ack_months) }));
  durations.push(fill(d.backups, { n: duration(t, 'days', i.backupDays) }));
  sections.push({ heading: t.headings.durations, paragraphs: durations });

  // 8. Rights.
  sections.push({ heading: t.headings.rights, paragraphs: [...t.rights] });

  // 9. Contacts.
  const contacts = [fill(t.contactController, { value: controller ?? org })];
  if (dpo) contacts.push(fill(t.contactDpo, { value: dpo }));
  if (contact) contacts.push(fill(t.contactOther, { value: contact }));
  if (!dpo && !contact) contacts.push(fill(t.contactFallback, v));
  sections.push({ heading: t.headings.contacts, paragraphs: contacts });

  return {
    title: company ? t.title.company : t.title.personal,
    sections,
    consentSummary: consentSummary(t, i),
    contact: null,
  };
}

/** The summary of the enrollment profile (500 characters at most). */
function consentSummary(t: NoticeTextSet, i: NoticeInput): string {
  const org = i.organization.trim() || '—';
  if (!isCompany(i.ownership)) return clampText(fill(t.consent.personal[i.platform], { org }), MAX_CONSENT_SUMMARY);
  const c = i.collection;
  const sees = [t.consent.seesModel, t.consent.seesOs];
  if (c.serialNumber) sees.push(t.consent.seesSerial);
  sees.push(c.installedApps === 'all' ? t.consent.seesAppsAll : t.consent.seesAppsManaged);
  const text = fill(t.consent.company, { org, sees: joinList(sees, t.and), locate: c.lostModeLocation ? t.consent.locate : '' });
  return clampText(text, MAX_CONSENT_SUMMARY);
}

/** Every text of a content, for the checks (no markup, lengths). */
export const noticeStrings = (c: NoticeContent): string[] =>
  [c.title, c.consentSummary, ...(c.contact ? [c.contact] : []), ...c.sections.flatMap((s) => [s.heading, ...s.paragraphs])];
