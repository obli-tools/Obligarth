// Texts of the Android BYOD pages of the device surface and of the invitation e-mail (lot AN-F1, section 10.5), in
// en and fr. The notice of a personal device is the text of the device surface of lot C (apple/enrollment/i18n.ts
// on main, notice.personal: the same words for the same ownership, whatever the platform); at the junction the
// provider of lot C (enrollmentNotice()) replaces the default provider of notice.ts and these texts with it. Plain
// text only: the pages escape every value; {org}, {code}, {url}, {expires} are replaced by values the caller escapes.

export const BYOD_LOCALES = ['fr', 'en'] as const;
export type ByodLocale = typeof BYOD_LOCALES[number];

export interface ByodNoticeTexts {
  title: string;
  sections: Array<{ heading: string; paragraphs: string[] }>;
  consentSummary: string;
}

export interface ByodTexts {
  lang: ByodLocale;
  ownershipLabel: string;
  personal: string;
  title: string;
  intro: string;
  code: string;
  codeHint: string;
  ack: string;
  enroll: string;
  wrongCode: string;
  noticeChanged: string;
  tooMany: string;
  retryTitle: string;
  retryBody: string;
  unavailableTitle: string;
  unavailableBody: string;
  requirement: string;
  notice: ByodNoticeTexts;
  mailSubject: string;
  mailBody: string[];
}

const EN: ByodTexts = {
  lang: 'en',
  ownershipLabel: 'Ownership',
  personal: 'Personal device',
  title: 'Enroll your personal device',
  intro: 'Enter the invitation code {org} gave you, after reading what enrolling means for your device. A work profile is then created on it by Google\'s Android Device Policy.',
  code: 'Invitation code',
  codeHint: 'Ten characters, for example abcde-fgh23.',
  ack: 'I have read this notice',
  enroll: 'Enroll',
  wrongCode: 'This code is not valid, or no longer. Check it, or ask your administrator for a new invitation.',
  noticeChanged: 'The notice changed meanwhile: please read it again.',
  tooMany: 'Too many attempts. Wait a moment, then try again.',
  retryTitle: 'Try again',
  retryBody: 'The enrollment could not be prepared. Try again in a moment.',
  unavailableTitle: 'Enrollment unavailable',
  unavailableBody: 'The enrollment of Android devices of {org} is not available at the moment. Contact your administrator.',
  requirement: 'Android 7 or later is required; open this page on the device to enroll.',
  notice: {
    title: 'Before you enroll your device',
    sections: [
      { heading: 'Who manages what', paragraphs: [
        'Your device stays yours. {org} manages only a separate space for its work apps and data, with Obligarth.'] },
      { heading: 'What your organisation can see', paragraphs: [
        'The model and the system version of the device, and the work apps it installs. Not the serial number nor any hardware identifier, not the device name, not your personal apps.',
        'It cannot see your messages, e-mails, photos, browsing history, calls, location or the content of your apps.'] },
      { heading: 'What your organisation can do', paragraphs: [
        'Install and remove work apps and settings, and remove its work data. It can never erase or lock your device.'] },
      { heading: 'Your data', paragraphs: [
        'The data collected about the device is kept 30 days after it leaves management, then erased.'] },
    ],
    consentSummary: '{org} will manage a separate work space on your device: it sees the model, the system version and its work apps only, and can remove its work data. It cannot see your personal data nor erase your device.',
  },
  mailSubject: 'Enroll your personal Android device for {org}',
  mailBody: [
    'Hello,',
    '{org} invites you to enroll your personal Android device: a separate work profile will be created on it.',
    'Your invitation code: {code}',
    'Open this page on the device: {url}',
    'The code expires on {expires} and can be used only once.',
  ],
};

const FR: ByodTexts = {
  lang: 'fr',
  ownershipLabel: 'Propriété',
  personal: 'Appareil personnel',
  title: 'Inscrire votre appareil personnel',
  intro: "Saisissez le code d'invitation que {org} vous a remis, après avoir lu ce que l'inscription implique pour votre appareil. Un profil professionnel y est ensuite créé par Android Device Policy, de Google.",
  code: "Code d'invitation",
  codeHint: 'Dix caractères, par exemple abcde-fgh23.',
  ack: "J'ai lu cette notice",
  enroll: "S'inscrire",
  wrongCode: "Ce code n'est pas ou plus valide. Vérifiez-le, ou demandez une nouvelle invitation à votre administrateur.",
  noticeChanged: 'La notice a changé entre-temps : relisez-la.',
  tooMany: 'Trop de tentatives. Attendez un moment, puis réessayez.',
  retryTitle: 'Réessayer',
  retryBody: "L'inscription n'a pas pu être préparée. Réessayez dans un instant.",
  unavailableTitle: 'Inscription indisponible',
  unavailableBody: "L'inscription des appareils Android de {org} n'est pas disponible pour le moment. Contactez votre administrateur.",
  requirement: "Android 7 ou ultérieur est nécessaire ; ouvrez cette page sur l'appareil à inscrire.",
  notice: {
    title: "Avant d'inscrire votre appareil",
    sections: [
      { heading: 'Qui gère quoi', paragraphs: [
        "Votre appareil reste le vôtre. {org} ne gère, avec Obligarth, qu'un espace séparé pour ses applications et ses données professionnelles."] },
      { heading: 'Ce que votre organisation voit', paragraphs: [
        "Le modèle et la version du système de l'appareil, et les applications professionnelles qu'elle installe. Ni le numéro de série, ni aucun identifiant matériel, ni le nom de l'appareil, ni vos applications personnelles.",
        'Elle ne voit ni vos messages, ni vos courriels, ni vos photos, ni votre historique de navigation, ni vos appels, ni votre position, ni le contenu de vos applications.'] },
      { heading: 'Ce que votre organisation peut faire', paragraphs: [
        'Installer et retirer des applications et des réglages professionnels, et retirer ses données professionnelles. Elle ne peut jamais effacer ni verrouiller votre appareil.'] },
      { heading: 'Vos données', paragraphs: [
        "Les données recueillies sur l'appareil sont conservées 30 jours après sa sortie de gestion, puis effacées."] },
    ],
    consentSummary: "{org} va gérer un espace professionnel séparé sur votre appareil : elle ne voit que son modèle, la version du système et ses applications professionnelles, et peut retirer ses données professionnelles. Elle ne voit pas vos données personnelles et ne peut pas effacer votre appareil.",
  },
  mailSubject: 'Inscrivez votre appareil Android personnel pour {org}',
  mailBody: [
    'Bonjour,',
    '{org} vous invite à inscrire votre appareil Android personnel : un profil professionnel séparé y sera créé.',
    "Votre code d'invitation : {code}",
    "Ouvrez cette page sur l'appareil : {url}",
    "Le code expire le {expires} et ne sert qu'une fois.",
  ],
};

const TEXTS: Record<ByodLocale, ByodTexts> = { en: EN, fr: FR };

export const isByodLocale = (v: unknown): v is ByodLocale => v === 'fr' || v === 'en';
export const byodTexts = (locale: ByodLocale): ByodTexts => TEXTS[locale];

/**
 * The language of a page: the first language of Accept-Language the surface speaks (q-values honoured), else the
 * fallback, else French (the parsing of lot C's pickLocale: 200 characters, 20 entries at most).
 */
export function pickByodLocale(acceptLanguage: unknown, fallback: unknown): ByodLocale {
  const header = typeof acceptLanguage === 'string' ? acceptLanguage.slice(0, 200) : '';
  const entries = header.split(',').slice(0, 20).map((part, i) => {
    const [tag, ...params] = part.trim().split(';');
    const q = params.map((p) => /^\s*q=([0-9.]{1,5})\s*$/.exec(p)).find(Boolean);
    return { lang: tag.trim().toLowerCase().split('-')[0], q: q ? Number(q[1]) : 1, i };
  }).filter((e) => e.lang && e.q > 0).sort((a, b) => b.q - a.q || a.i - b.i);
  for (const e of entries) if (isByodLocale(e.lang)) return e.lang;
  return isByodLocale(fallback) ? fallback : 'fr';
}

/** `text` with its {name} placeholders replaced (values used as they are: the caller escapes for HTML). */
export function fill(text: string, values: Record<string, string>): string {
  return text.replace(/\{([a-z]+)\}/g, (m, k: string) => (Object.prototype.hasOwnProperty.call(values, k) ? values[k] : m));
}
