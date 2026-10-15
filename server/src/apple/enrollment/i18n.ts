import type { Ownership } from '@obligarth/shared';

// =============================================================================
// Texts of the device surface (docs: integration-apple-edge §10.2, §10.7,
// §10.8): enrollment pages, profile names, default notice, e-mails, in en and
// fr. The language comes from Accept-Language, else from the profile (EX-28).
// Plain text only: the pages escape every value; {org} and the other
// placeholders are replaced by escaped values.
// =============================================================================

export const SURFACE_LOCALES = ['fr', 'en'] as const;
export type SurfaceLocale = typeof SURFACE_LOCALES[number];

export interface NoticeTexts {
  title: string;
  sections: Array<{ heading: string; paragraphs: string[] }>;
  consentSummary: string;
}

export interface SurfaceTexts {
  lang: SurfaceLocale;
  ownership: Record<Ownership, string>;
  pageTitle: string;
  ownershipLabel: string;
  ack: string;
  continue: string;
  invalidTitle: string;
  invalidBody: string;
  noticeChanged: string;
  retryTitle: string;
  retryBody: string;
  retryButton: string;
  notReadyTitle: string;
  notReadyBody: string;
  signingTitle: string;
  signingBody: string;
  expiredTitle: string;
  expiredBody: string;
  tooMany: string;
  profileName: string;
  profileDescription: string;
  scepName: string;
  mdmName: string;
  notice: Record<Ownership, NoticeTexts>;
  inviteTitle: string;
  inviteIntro: string;
  inviteSteps: string[];
  inviteRequirement: string;
  mailLinkSubject: string;
  mailLinkBody: string[];
  mailInviteSubject: string;
  mailInviteBody: string[];
}

const EN: SurfaceTexts = {
  lang: 'en',
  ownership: { corporate: 'Company device', corporate_personal: 'Company device for personal use', personal: 'Personal device' },
  pageTitle: 'Enroll this device',
  ownershipLabel: 'Ownership',
  ack: 'I have read this notice',
  continue: 'Continue',
  invalidTitle: 'Enrollment link not valid',
  invalidBody: 'This enrollment link is not valid, or no longer. Ask your administrator for a new one.',
  noticeChanged: 'The notice changed meanwhile: please read it again.',
  retryTitle: 'Try again',
  retryBody: 'The enrollment profile could not be prepared. Try again in a moment.',
  retryButton: 'Try again',
  notReadyTitle: 'Service not ready yet',
  notReadyBody: 'The device enrollment service of {org} is not ready yet. Contact your administrator.',
  signingTitle: 'Enrollment unavailable',
  signingBody: 'The enrollment profile cannot be signed at the moment. Contact your administrator.',
  expiredTitle: 'Enrollment expired',
  expiredBody: 'This enrollment has expired. Open your enrollment link again.',
  tooMany: 'Too many attempts. Wait a minute, then try again.',
  profileName: '{org} – device management',
  profileDescription: 'Lets {org} manage this device with Obligarth.',
  scepName: 'Device identity',
  mdmName: 'Device management',
  notice: {
    corporate: {
      title: 'Before you enroll this device',
      sections: [
        { heading: 'Who manages this device', paragraphs: [
          'This device belongs to {org}, which manages it with Obligarth. Enrolling installs a management profile on the device.'] },
        { heading: 'What your organisation can see', paragraphs: [
          'The model, serial number and other hardware identifiers, the system version, the device name, the storage and battery levels, the mobile network, and the installed apps.',
          'It cannot see your messages, e-mails, photos, browsing history, calls or the content of your apps.'] },
        { heading: 'What your organisation can do', paragraphs: [
          'Install and remove settings and apps, require a passcode, and lock, locate in lost mode or erase the device, with safeguards against mistakes.'] },
        { heading: 'Your data', paragraphs: [
          'The data collected about the device is kept 90 days after it leaves management, then erased.'] },
      ],
      consentSummary: '{org} will manage this company device: it can see its model, serial number, system version and installed apps, install settings and apps, and lock or erase it. It cannot see your messages, photos or browsing.',
    },
    corporate_personal: {
      title: 'Before you enroll this device',
      sections: [
        { heading: 'Who manages this device', paragraphs: [
          'This device belongs to {org}, which manages it with Obligarth and lets you use it personally.'] },
        { heading: 'What your organisation can see', paragraphs: [
          'The model, serial number and other hardware identifiers, the system version, the storage and battery levels, and the apps it manages. Not the device name, nor your own apps.',
          'It cannot see your messages, e-mails, photos, browsing history, calls or the content of your apps.'] },
        { heading: 'What your organisation can do', paragraphs: [
          'Install and remove the settings and apps it manages, require a passcode, and lock or erase the device, with safeguards against mistakes.'] },
        { heading: 'Your data', paragraphs: [
          'The data collected about the device is kept 90 days after it leaves management, then erased.'] },
      ],
      consentSummary: '{org} will manage this company device: it can see its model, serial number, system version and the apps it manages, install settings and apps, and lock or erase it. It cannot see your messages, photos, browsing or your own apps.',
    },
    personal: {
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
  },
  inviteTitle: 'Enroll your personal device',
  inviteIntro: 'Your organisation {org} invited you to enroll your iPhone or iPad. You need the Managed Apple Account and the invitation code you were given.',
  inviteSteps: [
    'Open Settings, then General, then VPN & Device Management.',
    'Tap Sign In to Work or School Account and enter your Managed Apple Account.',
    'When asked, read the notice and enter your invitation code.',
  ],
  inviteRequirement: 'iOS or iPadOS 18.2 or later is required.',
  mailLinkSubject: 'Enroll your device for {org}',
  mailLinkBody: [
    'Hello,',
    '{org} asks you to enroll a company device. Open this link on the device itself, with Safari:',
    '{url}',
    'The link expires on {expires}. It can be used only once unless your administrator said otherwise.',
  ],
  mailInviteSubject: 'Enroll your personal device for {org}',
  mailInviteBody: [
    'Hello,',
    '{org} invites you to enroll your personal iPhone or iPad with your Managed Apple Account {account}.',
    'Your invitation code: {code}',
    'The steps to follow: {url}',
    'The code expires on {expires} and can be used only once.',
  ],
};

const FR: SurfaceTexts = {
  lang: 'fr',
  ownership: { corporate: "Appareil de l'entreprise", corporate_personal: "Appareil de l'entreprise à usage personnel", personal: 'Appareil personnel' },
  pageTitle: 'Inscrire cet appareil',
  ownershipLabel: 'Propriété',
  ack: "J'ai lu cette notice",
  continue: 'Continuer',
  invalidTitle: "Lien d'inscription non valide",
  invalidBody: "Ce lien d'inscription n'est pas ou plus valide. Demandez-en un nouveau à votre administrateur.",
  noticeChanged: 'La notice a changé entre-temps : relisez-la.',
  retryTitle: 'Réessayer',
  retryBody: "Le profil d'inscription n'a pas pu être préparé. Réessayez dans un instant.",
  retryButton: 'Réessayer',
  notReadyTitle: 'Service pas encore prêt',
  notReadyBody: "Le service d'inscription des appareils de {org} n'est pas encore prêt. Contactez votre administrateur.",
  signingTitle: 'Inscription indisponible',
  signingBody: "Le profil d'inscription ne peut pas être signé pour le moment. Contactez votre administrateur.",
  expiredTitle: 'Inscription expirée',
  expiredBody: "Cette inscription a expiré. Ouvrez de nouveau votre lien d'inscription.",
  tooMany: 'Trop de tentatives. Attendez une minute, puis réessayez.',
  profileName: '{org} – gestion de l’appareil',
  profileDescription: 'Permet à {org} de gérer cet appareil avec Obligarth.',
  scepName: "Identité de l'appareil",
  mdmName: "Gestion de l'appareil",
  notice: {
    corporate: {
      title: "Avant d'inscrire cet appareil",
      sections: [
        { heading: 'Qui gère cet appareil', paragraphs: [
          "Cet appareil appartient à {org}, qui le gère avec Obligarth. L'inscription installe un profil de gestion sur l'appareil."] },
        { heading: 'Ce que votre organisation voit', paragraphs: [
          "Le modèle, le numéro de série et les autres identifiants matériels, la version du système, le nom de l'appareil, le stockage et la batterie, le réseau mobile et les applications installées.",
          "Elle ne voit ni vos messages, ni vos courriels, ni vos photos, ni votre historique de navigation, ni vos appels, ni le contenu de vos applications."] },
        { heading: 'Ce que votre organisation peut faire', paragraphs: [
          "Installer et retirer des réglages et des applications, exiger un code, verrouiller l'appareil, le localiser en mode perdu ou l'effacer, avec des garde-fous contre les erreurs."] },
        { heading: 'Vos données', paragraphs: [
          "Les données recueillies sur l'appareil sont conservées 90 jours après sa sortie de gestion, puis effacées."] },
      ],
      consentSummary: "{org} va gérer cet appareil de l'entreprise : elle peut voir son modèle, son numéro de série, la version du système et les applications installées, installer des réglages et des applications, le verrouiller ou l'effacer. Elle ne voit ni vos messages, ni vos photos, ni votre navigation.",
    },
    corporate_personal: {
      title: "Avant d'inscrire cet appareil",
      sections: [
        { heading: 'Qui gère cet appareil', paragraphs: [
          "Cet appareil appartient à {org}, qui le gère avec Obligarth et vous permet de l'utiliser à titre personnel."] },
        { heading: 'Ce que votre organisation voit', paragraphs: [
          "Le modèle, le numéro de série et les autres identifiants matériels, la version du système, le stockage et la batterie, et les applications qu'elle gère. Ni le nom de l'appareil, ni vos propres applications.",
          "Elle ne voit ni vos messages, ni vos courriels, ni vos photos, ni votre historique de navigation, ni vos appels, ni le contenu de vos applications."] },
        { heading: 'Ce que votre organisation peut faire', paragraphs: [
          "Installer et retirer les réglages et les applications qu'elle gère, exiger un code, verrouiller ou effacer l'appareil, avec des garde-fous contre les erreurs."] },
        { heading: 'Vos données', paragraphs: [
          "Les données recueillies sur l'appareil sont conservées 90 jours après sa sortie de gestion, puis effacées."] },
      ],
      consentSummary: "{org} va gérer cet appareil de l'entreprise : elle peut voir son modèle, son numéro de série, la version du système et les applications qu'elle gère, installer des réglages et des applications, le verrouiller ou l'effacer. Elle ne voit ni vos messages, ni vos photos, ni votre navigation, ni vos propres applications.",
    },
    personal: {
      title: "Avant d'inscrire votre appareil",
      sections: [
        { heading: 'Qui gère quoi', paragraphs: [
          'Votre appareil reste le vôtre. {org} ne gère, avec Obligarth, qu\'un espace séparé pour ses applications et ses données professionnelles.'] },
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
  },
  inviteTitle: 'Inscrire votre appareil personnel',
  inviteIntro: 'Votre organisation {org} vous invite à inscrire votre iPhone ou votre iPad. Il vous faut le compte Apple géré et le code d\'invitation qui vous ont été remis.',
  inviteSteps: [
    'Ouvrez Réglages, puis Général, puis VPN et gestion de l\'appareil.',
    'Touchez Se connecter à un compte professionnel ou scolaire et saisissez votre compte Apple géré.',
    "Quand c'est demandé, lisez la notice et saisissez votre code d'invitation.",
  ],
  inviteRequirement: 'iOS ou iPadOS 18.2 ou ultérieur est nécessaire.',
  mailLinkSubject: 'Inscrivez votre appareil pour {org}',
  mailLinkBody: [
    'Bonjour,',
    "{org} vous demande d'inscrire un appareil de l'entreprise. Ouvrez ce lien sur l'appareil lui-même, avec Safari :",
    '{url}',
    "Le lien expire le {expires}. Il ne sert qu'une fois, sauf indication contraire de votre administrateur.",
  ],
  mailInviteSubject: 'Inscrivez votre appareil personnel pour {org}',
  mailInviteBody: [
    'Bonjour,',
    '{org} vous invite à inscrire votre iPhone ou votre iPad personnel avec votre compte Apple géré {account}.',
    "Votre code d'invitation : {code}",
    'Les étapes à suivre : {url}',
    "Le code expire le {expires} et ne sert qu'une fois.",
  ],
};

const TEXTS: Record<SurfaceLocale, SurfaceTexts> = { en: EN, fr: FR };

export const isSurfaceLocale = (v: unknown): v is SurfaceLocale => v === 'fr' || v === 'en';

export const textsFor = (locale: SurfaceLocale): SurfaceTexts => TEXTS[locale];

/**
 * The language of a page: the first language of Accept-Language the surface speaks (q-values honoured), else
 * the profile's, else French. Bounded parsing (a header of 200 characters, 20 entries at most).
 */
export function pickLocale(acceptLanguage: unknown, fallback: unknown): SurfaceLocale {
  const header = typeof acceptLanguage === 'string' ? acceptLanguage.slice(0, 200) : '';
  const entries = header.split(',').slice(0, 20).map((part, i) => {
    const [tag, ...params] = part.trim().split(';');
    const q = params.map((p) => /^\s*q=([0-9.]{1,5})\s*$/.exec(p)).find(Boolean);
    return { lang: tag.trim().toLowerCase().split('-')[0], q: q ? Number(q[1]) : 1, i };
  }).filter((e) => e.lang && e.q > 0).sort((a, b) => b.q - a.q || a.i - b.i);
  for (const e of entries) if (isSurfaceLocale(e.lang)) return e.lang;
  return isSurfaceLocale(fallback) ? fallback : 'fr';
}

/** `text` with its {name} placeholders replaced (values used as they are: the caller escapes for HTML). */
export function fill(text: string, values: Record<string, string>): string {
  return text.replace(/\{([a-z]+)\}/g, (m, k: string) => (Object.prototype.hasOwnProperty.call(values, k) ? values[k] : m));
}
