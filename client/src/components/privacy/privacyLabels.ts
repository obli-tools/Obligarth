import type { TFunction } from 'i18next';
import type {
  NoticeAckChannel, NoticeLocale, NoticeMissing, NoticePlatform, NoticeSettingsKey, ObligarthStage, PrivacyCollectionScope, PrivacyRuleKey,
  RetentionCategory, RetentionFixedKey, RetentionUnit,
} from '@obligarth/shared';
import { trCode } from '@/utils/apiError';

// The labels of the privacy console (page /privacy, P0-13 T7): the rules of a profile, the categories of the retention,
// the settings of the notice. Keys privacy.*; the English fallbacks below when a key is missing.

const RULE_FALLBACK: Record<PrivacyRuleKey, { label: string; hint: string }> = {
  serialNumber: { label: 'Serial number', hint: 'Identifies the device in the inventory.' },
  hardwareIds: { label: 'Hardware identifiers', hint: 'IMEI, MEID, EID and MAC addresses.' },
  deviceName: { label: 'Device name', hint: 'The name the user gave the device.' },
  phoneNumber: { label: 'Phone number', hint: 'Phone number, ICCID and subscriptions.' },
  network: { label: 'Network', hint: 'Carrier, roaming, Wi-Fi and Bluetooth addresses.' },
  lostModeLocation: { label: 'Location in lost mode', hint: 'The position of a lost device, only while the lost mode is on.' },
  installedApps: { label: 'Installed applications', hint: 'Every application, or only those the organisation manages.' },
  certificates: { label: 'Certificates', hint: 'Every certificate, or only those the organisation installed.' },
  remoteAssistance: {
    label: 'Remote assistance',
    hint: 'The support may see the screen, and control it, during an assistance session told on the device by notifications.',
  },
};

export const ruleLabel = (key: PrivacyRuleKey): string => trCode(`privacy.rules.${key}.label`, RULE_FALLBACK[key].label);
export const ruleHint = (key: PrivacyRuleKey): string => trCode(`privacy.rules.${key}.hint`, RULE_FALLBACK[key].hint);

const SCOPE_FALLBACK: Record<PrivacyCollectionScope, string> = { all: 'All', managed_only: 'Managed only' };
/** The choice of a rule with a scope, worded for that rule (French agrees with the noun: « Toutes », « Gérés seulement »). */
export const scopeLabel = (key: PrivacyRuleKey, s: PrivacyCollectionScope): string =>
  trCode(`privacy.rules.${key}.scope.${s}`, SCOPE_FALLBACK[s]);

/** Under a tab the reader cannot change: the capability needed, by its translated name (as the roles screen shows it). */
export const readOnlyNotice = (t: TFunction): string => {
  const capability = t('permissionSets.capabilities.mdm_privacy_manage') || 'Privacy · Profiles, notice and retention';
  return t('privacy.readOnly', { capability }) || `You can read these settings; changing them needs the capability "${capability}".`;
};

const CATEGORY_FALLBACK: Record<RetentionCategory, { label: string; hint: string }> = {
  unenrolled_corporate_days: { label: 'Corporate device out of management', hint: 'Its record, after the unenrollment.' },
  unenrolled_corporate_personal_days: { label: 'Corporate device, personally enabled, out of management', hint: 'Its record, after the unenrollment.' },
  unenrolled_personal_days: { label: 'Personal device out of management', hint: 'Its record, after the unenrollment.' },
  departed_end_user_days: { label: 'Departed employee', hint: 'The link between a device and an employee who left.' },
  lost_mode_location_days: { label: 'Positions in lost mode', hint: 'The positions of a lost device.' },
  technical_log_months: { label: 'Technical log', hint: 'The commands sent to the devices and their timeline.' },
  status_history_days: { label: 'Status history', hint: 'The history of the declarative status of the devices.' },
  notice_ack_months: { label: 'Acknowledgements of the notice', hint: 'The proof that an employee read the notice before an enrollment.' },
  remote_sessions_months: { label: 'Remote assistance sessions', hint: 'The journal of the sessions: who, when, which device, mode, duration and reason.' },
};

export const categoryLabel = (key: RetentionCategory): string =>
  trCode(`privacy.retention.categories.${key}.label`, CATEGORY_FALLBACK[key]?.label ?? key);
export const categoryHint = (key: RetentionCategory): string =>
  trCode(`privacy.retention.categories.${key}.hint`, CATEGORY_FALLBACK[key]?.hint ?? '');

const FIXED_FALLBACK: Record<RetentionFixedKey, string> = {
  enrollment_sessions: 'Enrollment sessions', enrollment_tokens: 'Enrollment links and tokens', inventory_commands: 'Inventory requests',
  ade_removed_devices: 'Devices removed from Apple Business', notification_log: 'Notification log', live_alerts: 'Live alerts',
  app_icons_orphaned: 'Icons of applications no longer installed', android_inbox: 'Android events applied', backups: 'Backups',
  smart_group_memberships: 'Entries and exits of the dynamic groups',
};
export const fixedLabel = (key: RetentionFixedKey): string => trCode(`privacy.retention.fixed.${key}`, FIXED_FALLBACK[key] ?? key);

/** '30 days', '6 months'. */
export function durationLabel(t: TFunction, value: number, unit: RetentionUnit): string {
  return unit === 'months'
    ? (t('privacy.units.months', { count: value }) || `${value} ${value === 1 ? 'month' : 'months'}`)
    : (t('privacy.units.days', { count: value }) || `${value} ${value === 1 ? 'day' : 'days'}`);
}

/** 'days' or 'months' alone (the suffix of an input). */
export const unitLabel = (t: TFunction, unit: RetentionUnit): string =>
  (unit === 'months' ? (t('privacy.units.monthsShort') || 'months') : (t('privacy.units.daysShort') || 'days'));

const SETTING_FALLBACK: Record<NoticeSettingsKey, { label: string; hint: string }> = {
  controllerName: { label: 'Data controller', hint: 'The employer, its legal name.' },
  controllerAddress: { label: 'Address of the data controller', hint: 'Its postal address.' },
  dpoContact: { label: 'Data protection officer', hint: 'Name, e-mail or address of the DPO.' },
  contact: { label: 'Other contact', hint: 'Who answers the employees\' questions, when there is no DPO.' },
  recipientsExtra: { label: 'Other recipients', hint: 'Who else receives the data, beyond the operator of the platform and Apple or Google.' },
  introFr: { label: 'Paragraph of the organisation (French)', hint: 'Shown after who manages the device, in the French notice.' },
  introEn: { label: 'Paragraph of the organisation (English)', hint: 'Shown after who manages the device, in the English notice.' },
};
export const settingLabel = (key: NoticeSettingsKey): string => trCode(`privacy.notice.fields.${key}.label`, SETTING_FALLBACK[key].label);
export const settingHint = (key: NoticeSettingsKey): string => trCode(`privacy.notice.fields.${key}.hint`, SETTING_FALLBACK[key].hint);

const MISSING_FALLBACK: Record<NoticeMissing, string> = { controllerName: 'the data controller', contact: 'a contact (the DPO or another)' };
export const missingLabel = (m: NoticeMissing): string => trCode(`privacy.notice.missing.${m}`, MISSING_FALLBACK[m]);

const STAGE_FALLBACK: Record<ObligarthStage, string> = { lab: 'Laboratory', pilot: 'Pilot', production: 'Production' };
export const stageLabel = (s: ObligarthStage): string => trCode(`privacy.notice.stage.${s}`, STAGE_FALLBACK[s] ?? s);

export const platformName = (p: NoticePlatform): string => (p === 'apple' ? 'Apple' : 'Android');
const LOCALE_FALLBACK: Record<NoticeLocale, string> = { fr: 'French', en: 'English' };
export const localeLabel = (l: NoticeLocale): string => trCode(`privacy.notice.locales.${l}`, LOCALE_FALLBACK[l]);

const CHANNEL_FALLBACK: Record<NoticeAckChannel, string> = {
  apple_session: 'Apple enrollment', android_byod_invitation: 'Android invitation', android_signin: 'Android sign-in',
};
export const ackChannelLabel = (c: NoticeAckChannel): string => trCode(`privacy.notice.channels.${c}`, CHANNEL_FALLBACK[c]);
