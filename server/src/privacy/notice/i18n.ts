import type { NoticeLocale, NoticePlatform, Ownership } from '@obligarth/shared';

// =============================================================================
// Texts of the generated notice of the employees (P0-13 T5, USR-01; conception §10.3; D15: fr and en), assembled by
// generate.ts from the privacy profile, the retention and the settings of the tenant. Plain text only: the pages escape
// every value; {org}, {name}, {list}… are replaced by plain values (fill). These texts are not a legal opinion: a
// lawyer reviews them before the pilot (conception §10.9), with the retention of the acknowledgements (D5).
// A change of these texts changes the content of the notices, hence their versions: the employees acknowledge the new
// text at their next enrollment (NOTICE_GENERATOR_VERSION, generate.ts, names the generation).
// =============================================================================

type ByOwnership = Readonly<Record<Ownership, string>>;
type ByPlatform<T> = Readonly<Record<NoticePlatform, T>>;

export interface NoticeTextSet {
  lang: NoticeLocale;
  /** "a, b and c". */
  and: string;
  /** The separator of a list whose items may hold commas (what it sees, what it does not collect). */
  listSep: string;
  title: { company: string; personal: string };
  headings: {
    who: string; whoPersonal: string; sees: string; notSees: string; canDo: string; purposes: string; recipients: string;
    durations: string; rights: string; contacts: string;
  };
  // 1. Who manages the device.
  who: ByPlatform<ByOwnership>;
  controller: string;
  controllerAddress: string;
  // 2. What the organisation sees.
  sees: string;
  data: {
    base: ByPlatform<{ company: string; personal: string }>;
    serialNumber: string;
    hardwareIds: ByPlatform<string>;
    deviceName: string;
    phoneNumber: string;
    network: ByPlatform<string>;
    appsAll: string;
    appsManaged: string;
    appsWork: ByPlatform<string>;
    certificatesAll: string;
    certificatesManaged: string;
  };
  lostModeSees: string;
  // 3. What it does not see.
  notSeesFixed: string;
  notSeesPersonal: ByPlatform<string>;
  notCollected: string;
  notCollectedItems: {
    serialNumber: string; hardwareIds: string; deviceName: string; phoneNumber: string; network: string; otherApps: string;
    certificates: string; location: string;
  };
  locationOnlyLost: string;
  // 4. What it can do.
  canDo: ByPlatform<ByOwnership>;
  canDoLostMode: string;
  safeguards: string;
  // 5. Purposes and legal basis.
  purposes: string[];
  // 6. Recipients.
  recipientsOrg: string;
  recipientsPlatform: ByPlatform<{ company: string; personal: string }>;
  recipientsExtra: string;
  // 7. Durations.
  durations: {
    record: string; departed: string; logs: string; statusHistory: string; lostMode: string; ack: string; backups: string;
  };
  days: { one: string; other: string };
  months: { one: string; other: string };
  // 8. Rights.
  rights: string[];
  // 9. Contacts.
  contactController: string;
  contactDpo: string;
  contactOther: string;
  contactFallback: string;
  // The summary of the enrollment profile (ConsentText, 500 characters at most).
  consent: {
    company: string;
    personal: ByPlatform<string>;
    seesModel: string;
    seesOs: string;
    seesSerial: string;
    seesAppsAll: string;
    seesAppsManaged: string;
    locate: string;
  };
}

const FR: NoticeTextSet = {
  lang: 'fr',
  and: ' et ',
  listSep: ' ; ',
  title: { company: "Avant d'inscrire cet appareil", personal: "Avant d'inscrire votre appareil" },
  headings: {
    who: 'Qui gère cet appareil',
    whoPersonal: 'Qui gère quoi',
    sees: 'Ce que votre organisation voit',
    notSees: "Ce qu'elle ne voit pas",
    canDo: "Ce qu'elle peut faire",
    purposes: 'Pourquoi : finalités et base légale',
    recipients: 'Qui reçoit ces données',
    durations: 'Combien de temps elles sont conservées',
    rights: 'Vos droits',
    contacts: 'Contacts',
  },
  who: {
    apple: {
      corporate: "Cet appareil appartient à {org}, qui le gère avec Obligarth, une solution de gestion des appareils mobiles. L'inscription installe un profil de gestion sur l'appareil.",
      corporate_personal: "Cet appareil appartient à {org}, qui le gère avec Obligarth et vous permet aussi de l'utiliser à titre personnel. L'inscription installe un profil de gestion sur l'appareil.",
      personal: "Votre appareil reste le vôtre. {org} ne gère, avec Obligarth, qu'un espace séparé réservé à ses applications et à ses données professionnelles.",
    },
    android: {
      corporate: "Cet appareil appartient à {org}, qui le gère entièrement avec Obligarth, par l'intermédiaire de l'application Android Device Policy de Google.",
      corporate_personal: "Cet appareil appartient à {org}, qui le gère avec Obligarth. Un profil professionnel séparé y est créé ; vous pouvez utiliser le reste de l'appareil à titre personnel.",
      personal: "Votre appareil reste le vôtre. {org} ne gère, avec Obligarth, qu'un profil professionnel séparé, créé par l'application Android Device Policy de Google pour ses applications et ses données professionnelles.",
    },
  },
  controller: 'Responsable du traitement : {name}.',
  controllerAddress: 'Adresse : {address}.',
  sees: 'Elle voit : {list}.',
  data: {
    base: {
      apple: {
        company: "le modèle, la version du système, l'espace de stockage et le niveau de batterie, l'état de sécurité (code, chiffrement, supervision) et un identifiant technique de gestion",
        personal: "le modèle et la version du système de l'appareil, et un identifiant technique propre à l'inscription",
      },
      android: {
        company: "la marque, le modèle, la version du système et son niveau de correctifs de sécurité, l'espace de stockage et l'état de sécurité",
        personal: 'le modèle, la version du système et son niveau de correctifs de sécurité, et l\'état de sécurité du profil professionnel',
      },
    },
    serialNumber: 'le numéro de série',
    hardwareIds: { apple: 'les identifiants matériels (IMEI, MEID)', android: "l'IMEI" },
    deviceName: "le nom de l'appareil",
    phoneNumber: 'le numéro de téléphone et les identifiants de la carte SIM (ICCID, EID)',
    network: { apple: "l'opérateur mobile, l'itinérance et les adresses Wi-Fi et Bluetooth", android: "l'opérateur mobile" },
    appsAll: 'la liste des applications installées',
    appsManaged: "les applications qu'elle gère",
    appsWork: { apple: "les applications professionnelles qu'elle installe", android: 'les applications du profil professionnel' },
    certificatesAll: 'les certificats installés',
    certificatesManaged: "les certificats qu'elle installe",
  },
  lostModeSees: "Si l'appareil est perdu ou volé et que l'organisation le place en mode perdu, elle peut voir sa position, uniquement pendant ce mode.",
  notSeesFixed: "Elle ne voit ni vos messages, ni vos e-mails, ni vos photos, ni votre historique de navigation, ni vos appels, ni vos contacts, ni le contenu de vos applications.",
  notSeesPersonal: {
    apple: 'Elle ne voit rien de votre espace personnel : ni vos applications personnelles, ni leurs données.',
    android: 'Elle ne voit rien de votre espace personnel, en dehors du profil professionnel : ni vos applications personnelles, ni leurs données.',
  },
  notCollected: 'Elle ne recueille pas non plus : {list}.',
  notCollectedItems: {
    serialNumber: 'le numéro de série',
    hardwareIds: "les identifiants matériels de l'appareil (IMEI, adresses matérielles)",
    deviceName: "le nom de l'appareil",
    phoneNumber: 'le numéro de téléphone',
    network: "les informations du réseau mobile et de l'opérateur",
    otherApps: 'la liste de vos autres applications',
    certificates: "les certificats qu'elle n'a pas installés",
    location: "la position de l'appareil",
  },
  locationOnlyLost: "Elle ne suit jamais la position de l'appareil en dehors du mode perdu.",
  canDo: {
    apple: {
      corporate: "Installer et retirer des réglages et des applications, exiger un code, verrouiller l'appareil et l'effacer entièrement.",
      corporate_personal: "Installer et retirer des réglages et les applications qu'elle gère, exiger un code, verrouiller l'appareil et l'effacer entièrement.",
      personal: "Installer et retirer ses applications et ses réglages professionnels, et retirer ses données professionnelles. Elle ne peut jamais effacer, verrouiller ni localiser votre appareil.",
    },
    android: {
      corporate: "Installer et retirer des réglages et des applications, exiger un code, verrouiller, redémarrer et effacer entièrement l'appareil.",
      corporate_personal: "Installer et retirer des réglages et les applications du profil professionnel, exiger un code, verrouiller l'appareil et, l'appareil appartenant à {org}, l'effacer entièrement.",
      personal: "Installer et retirer ses applications et ses réglages professionnels, verrouiller le profil professionnel et le retirer avec ses données. Elle ne peut jamais effacer votre appareil, ni le localiser.",
    },
  },
  canDoLostMode: "Placer l'appareil en mode perdu et le localiser pendant ce mode.",
  safeguards: "Les actions les plus lourdes (effacement, retrait de la gestion) sont protégées par des garde-fous contre les erreurs : délais, confirmation et, lorsque l'organisation l'exige, validation par une seconde personne.",
  purposes: [
    "Ces données servent uniquement à gérer et à sécuriser les appareils utilisés pour le travail : configuration, mises à jour, inventaire, protection des données de votre organisation en cas de perte ou de vol, assistance.",
    "Base légale : l'intérêt légitime de votre organisation à gérer et à sécuriser son système d'information (article 6.1.f du RGPD) et son obligation d'assurer la sécurité des données qu'elle traite (article 32 du RGPD). Elles ne servent pas à surveiller votre activité.",
  ],
  recipientsOrg: "Les personnes habilitées de votre organisation et, le cas échéant, le prestataire qui exploite Obligarth pour son compte, en qualité de sous-traitant.",
  recipientsPlatform: {
    apple: {
      company: "Apple reçoit les informations techniques nécessaires à l'acheminement des commandes de gestion (service de notification d'Apple) et à l'attribution des appareils de l'entreprise (Apple Business Manager).",
      personal: "Apple reçoit les informations techniques nécessaires à l'acheminement des commandes de gestion (service de notification d'Apple).",
    },
    android: {
      company: "Google reçoit et traite les informations de l'appareil nécessaires à sa gestion (Android Management API).",
      personal: 'Google reçoit et traite les informations du profil professionnel nécessaires à sa gestion (Android Management API).',
    },
  },
  recipientsExtra: 'Autres destinataires : {list}',
  durations: {
    record: "Les données de l'appareil sont conservées tant qu'il est géré, puis {n} après sa sortie de la gestion, avant d'être effacées.",
    departed: "Le lien entre l'appareil et votre compte est supprimé {n} après votre départ de l'organisation.",
    logs: "L'historique des commandes et des événements techniques est conservé {n}.",
    statusHistory: "L'historique de l'état de l'appareil est conservé {n}.",
    lostMode: 'Les positions relevées en mode perdu sont effacées après {n}.',
    ack: 'La preuve de votre lecture de cette notice est conservée {n}.',
    backups: 'Les sauvegardes chiffrées de la plateforme sont renouvelées en {n} : une donnée effacée en disparaît dans ce délai.',
  },
  days: { one: '{n} jour', other: '{n} jours' },
  months: { one: '{n} mois', other: '{n} mois' },
  rights: [
    "Vous pouvez accéder aux données qui vous concernent, les faire rectifier ou effacer, en demander la limitation et vous opposer à leur traitement, dans les conditions prévues par le RGPD. Adressez-vous aux contacts ci-dessous.",
    'Vous pouvez aussi introduire une réclamation auprès de la CNIL (www.cnil.fr).',
  ],
  contactController: 'Responsable du traitement : {value}',
  contactDpo: 'Délégué à la protection des données : {value}',
  contactOther: 'Contact : {value}',
  contactFallback: 'Pour toute question, adressez-vous à {org}.',
  consent: {
    company: '{org} va gérer cet appareil de l\'entreprise : elle peut voir {sees}, installer des réglages et des applications, le verrouiller ou l\'effacer{locate}. Elle ne voit ni vos messages, ni vos photos, ni votre navigation.',
    personal: {
      apple: '{org} va gérer un espace professionnel séparé sur votre appareil : elle ne voit que son modèle, la version du système et ses applications professionnelles, et peut retirer ses données professionnelles. Elle ne voit pas vos données personnelles et ne peut pas effacer votre appareil.',
      android: '{org} va gérer un profil professionnel séparé sur votre appareil : elle ne voit que son modèle, la version du système et les applications de ce profil, et peut le retirer. Elle ne voit pas vos données personnelles et ne peut pas effacer votre appareil.',
    },
    seesModel: 'son modèle',
    seesOs: 'la version du système',
    seesSerial: 'son numéro de série',
    seesAppsAll: 'les applications installées',
    seesAppsManaged: "les applications qu'elle gère",
    locate: ', et le localiser en mode perdu',
  },
};

const EN: NoticeTextSet = {
  lang: 'en',
  and: ' and ',
  listSep: '; ',
  title: { company: 'Before you enroll this device', personal: 'Before you enroll your device' },
  headings: {
    who: 'Who manages this device',
    whoPersonal: 'Who manages what',
    sees: 'What your organisation can see',
    notSees: 'What it cannot see',
    canDo: 'What it can do',
    purposes: 'Why: purposes and legal basis',
    recipients: 'Who receives these data',
    durations: 'How long they are kept',
    rights: 'Your rights',
    contacts: 'Contacts',
  },
  who: {
    apple: {
      corporate: 'This device belongs to {org}, which manages it with Obligarth, a mobile device management solution. Enrolling installs a management profile on the device.',
      corporate_personal: 'This device belongs to {org}, which manages it with Obligarth and also lets you use it personally. Enrolling installs a management profile on the device.',
      personal: 'Your device stays yours. {org} manages only a separate space for its work apps and data, with Obligarth.',
    },
    android: {
      corporate: "This device belongs to {org}, which manages it fully with Obligarth, through Google's Android Device Policy app.",
      corporate_personal: 'This device belongs to {org}, which manages it with Obligarth. A separate work profile is created on it; you may use the rest of the device personally.',
      personal: "Your device stays yours. {org} manages only a separate work profile, created by Google's Android Device Policy app for its work apps and data, with Obligarth.",
    },
  },
  controller: 'Data controller: {name}.',
  controllerAddress: 'Address: {address}.',
  sees: 'It can see: {list}.',
  data: {
    base: {
      apple: {
        company: 'the model, the system version, the storage and battery levels, the security state (passcode, encryption, supervision) and a technical management identifier',
        personal: 'the model and the system version of the device, and a technical identifier of the enrollment',
      },
      android: {
        company: 'the brand, the model, the system version and its security patch level, the storage and the security state',
        personal: 'the model, the system version and its security patch level, and the security state of the work profile',
      },
    },
    serialNumber: 'the serial number',
    hardwareIds: { apple: 'the hardware identifiers (IMEI, MEID)', android: 'the IMEI' },
    deviceName: 'the device name',
    phoneNumber: 'the phone number and the identifiers of the SIM card (ICCID, EID)',
    network: { apple: 'the mobile carrier, the roaming state and the Wi-Fi and Bluetooth addresses', android: 'the mobile carrier' },
    appsAll: 'the list of the installed apps',
    appsManaged: 'the apps it manages',
    appsWork: { apple: 'the work apps it installs', android: 'the apps of the work profile' },
    certificatesAll: 'the installed certificates',
    certificatesManaged: 'the certificates it installs',
  },
  lostModeSees: 'If the device is lost or stolen and the organisation puts it in lost mode, it can see its location, during that mode only.',
  notSeesFixed: 'It cannot see your messages, e-mails, photos, browsing history, calls, contacts or the content of your apps.',
  notSeesPersonal: {
    apple: 'It sees nothing of your personal space: neither your personal apps nor their data.',
    android: 'It sees nothing of your personal space outside the work profile: neither your personal apps nor their data.',
  },
  notCollected: 'Nor does it collect: {list}.',
  notCollectedItems: {
    serialNumber: 'the serial number',
    hardwareIds: 'the hardware identifiers of the device (IMEI, hardware addresses)',
    deviceName: 'the device name',
    phoneNumber: 'the phone number',
    network: 'the information of the mobile network and carrier',
    otherApps: 'the list of your other apps',
    certificates: 'the certificates it did not install',
    location: 'the location of the device',
  },
  locationOnlyLost: 'It never follows the location of the device outside lost mode.',
  canDo: {
    apple: {
      corporate: 'Install and remove settings and apps, require a passcode, lock the device and erase it entirely.',
      corporate_personal: 'Install and remove settings and the apps it manages, require a passcode, lock the device and erase it entirely.',
      personal: 'Install and remove its work apps and settings, and remove its work data. It can never erase, lock or locate your device.',
    },
    android: {
      corporate: 'Install and remove settings and apps, require a passcode, lock, restart and erase the device entirely.',
      corporate_personal: 'Install and remove settings and the apps of the work profile, require a passcode, lock the device and, the device belonging to {org}, erase it entirely.',
      personal: 'Install and remove its work apps and settings, lock the work profile and remove it with its data. It can never erase your device nor locate it.',
    },
  },
  canDoLostMode: 'Put the device in lost mode and locate it during that mode.',
  safeguards: 'The heaviest actions (erasure, removal from management) are protected against mistakes: delays, confirmation and, when the organisation requires it, approval by a second person.',
  purposes: [
    'These data serve only to manage and secure the devices used for work: configuration, updates, inventory, protection of the data of your organisation when a device is lost or stolen, support.',
    'Legal basis: the legitimate interest of your organisation in managing and securing its information system (article 6.1.f of the GDPR) and its obligation to secure the data it processes (article 32 of the GDPR). They are not used to monitor your activity.',
  ],
  recipientsOrg: 'The authorised staff of your organisation and, where applicable, the provider that operates Obligarth on its behalf, as a processor.',
  recipientsPlatform: {
    apple: {
      company: "Apple receives the technical information needed to route the management commands (Apple's notification service) and to assign the company's devices (Apple Business Manager).",
      personal: "Apple receives the technical information needed to route the management commands (Apple's notification service).",
    },
    android: {
      company: 'Google receives and processes the information of the device needed to manage it (Android Management API).',
      personal: 'Google receives and processes the information of the work profile needed to manage it (Android Management API).',
    },
  },
  recipientsExtra: 'Other recipients: {list}',
  durations: {
    record: 'The data of the device are kept while it is managed, then {n} after it leaves management, before being erased.',
    departed: 'The link between the device and your account is removed {n} after you leave the organisation.',
    logs: 'The history of the commands and technical events is kept {n}.',
    statusHistory: 'The history of the state of the device is kept {n}.',
    lostMode: 'The locations recorded in lost mode are erased after {n}.',
    ack: 'The proof that you read this notice is kept {n}.',
    backups: 'The encrypted backups of the platform are renewed within {n}: an erased datum leaves them within that time.',
  },
  days: { one: '{n} day', other: '{n} days' },
  months: { one: '{n} month', other: '{n} months' },
  rights: [
    'You may access the data about you, have them corrected or erased, ask for their restriction and object to their processing, as the GDPR provides. Write to the contacts below.',
    'You may also lodge a complaint with the CNIL, the French data protection authority (www.cnil.fr), or with the supervisory authority of your country.',
  ],
  contactController: 'Data controller: {value}',
  contactDpo: 'Data protection officer: {value}',
  contactOther: 'Contact: {value}',
  contactFallback: 'For any question, write to {org}.',
  consent: {
    company: '{org} will manage this company device: it can see {sees}, install settings and apps, and lock or erase it{locate}. It cannot see your messages, photos or browsing.',
    personal: {
      apple: '{org} will manage a separate work space on your device: it sees the model, the system version and its work apps only, and can remove its work data. It cannot see your personal data nor erase your device.',
      android: '{org} will manage a separate work profile on your device: it sees the model, the system version and the apps of that profile only, and can remove it. It cannot see your personal data nor erase your device.',
    },
    seesModel: 'its model',
    seesOs: 'the system version',
    seesSerial: 'its serial number',
    seesAppsAll: 'the installed apps',
    seesAppsManaged: 'the apps it manages',
    locate: ', and locate it in lost mode',
  },
};

const TEXTS: Readonly<Record<NoticeLocale, NoticeTextSet>> = { fr: FR, en: EN };

export const noticeTexts = (locale: NoticeLocale): NoticeTextSet => TEXTS[locale];

/** Replaces {name} placeholders by plain values (an unknown placeholder stays as it is). */
export function fill(template: string, values: Readonly<Record<string, string>>): string {
  return template.replace(/\{([a-z]+)\}/g, (m, k: string) => (Object.prototype.hasOwnProperty.call(values, k) ? values[k] : m));
}
