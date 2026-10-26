import { createHash } from 'node:crypto';
import { NOTICE_LOCALES, OWNERSHIPS, noticeDisplayed, type NoticeLocale, type NoticePlatform, type Ownership } from '@obligarth/shared';
import { pickLocale } from '../../apple/enrollment/i18n';
import { fill } from './i18n';
import type { NoticeContent } from './generate';

// =============================================================================
// The public page of the notice of the employees (P0-13 T6, D6: GET /t/<key>/notice, surface.ts): server-rendered
// HTML, no script, no form, one embedded style sheet allowed by its SHA-256 in the CSP, every value escaped (plain text
// only, never HTML), as the pages of the enrollments (apple/enrollment/pages.ts). It shows the notice in force of one
// platform, ownership and language, and links to the other combinations shown at an enrollment and to the other
// language (the same page, another query). No personal data: the name of the organisation and the notice only.
// Pure: the unit tests load it.
// =============================================================================

const STYLE = [
  ':root{color-scheme:light dark}',
  'body{margin:0;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f4f5f7;color:#1c1e21}',
  'main{max-width:720px;margin:0 auto;padding:24px 16px 48px}',
  'h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:20px 0 6px}',
  '.org{color:#5f6672;margin:0 0 16px}',
  '.card{background:#fff;border-radius:12px;padding:16px 20px;box-shadow:0 1px 2px rgba(0,0,0,.08)}',
  '.tag{display:inline-block;background:#e7eefc;color:#1f4fbf;border-radius:999px;padding:2px 10px;font-size:.85rem;margin:8px 0}',
  'nav{margin:0 0 16px}nav p{margin:4px 0 6px;color:#5f6672;font-size:.9rem}',
  'nav ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:6px}',
  'nav a{display:inline-block;border:1px solid #c4c9d2;border-radius:999px;padding:4px 12px;color:#1f4fbf;text-decoration:none;font-size:.9rem}',
  'nav a[aria-current=page]{background:#1f4fbf;border-color:#1f4fbf;color:#fff}',
  '.meta{color:#5f6672;font-size:.85rem;margin-top:16px}',
  '@media (prefers-color-scheme:dark){body{background:#111316;color:#e8eaed}.card{background:#1c1f24;box-shadow:none}.org,nav p,.meta{color:#9aa0a6}'
    + '.tag{background:#22324f;color:#a8c3ff}nav a{border-color:#3c4250;color:#a8c3ff}nav a[aria-current=page]{background:#a8c3ff;border-color:#a8c3ff;color:#111316}}',
].join('');

/** The CSP of the page: its style sheet by hash, nothing else (no script, no form, no frame). */
export const NOTICE_PAGE_CSP = [
  "default-src 'none'",
  `style-src 'sha256-${createHash('sha256').update(STYLE, 'utf8').digest('base64')}'`,
  "form-action 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
].join('; ');

export interface NoticePageTexts {
  lang: NoticeLocale;
  pageTitle: string;
  /** {org}: the organisation. */
  intro: string;
  kindLabel: string;
  languageLabel: string;
  platform: Readonly<Record<NoticePlatform, string>>;
  ownership: Readonly<Record<Ownership, string>>;
  languageName: Readonly<Record<NoticeLocale, string>>;
  footer: string;
  unavailableTitle: string;
  /** {org}: the organisation. */
  unavailableBody: string;
  tooMany: string;
}

const FR: NoticePageTexts = {
  lang: 'fr',
  pageTitle: "Notice d'information des salariés",
  intro: "La notice que {org} présente avant l'inscription d'un appareil dans sa gestion de flotte.",
  kindLabel: "Type d'appareil",
  languageLabel: 'Langue',
  platform: { apple: 'Apple', android: 'Android' },
  ownership: { corporate: "Appareil de l'entreprise", corporate_personal: "Appareil de l'entreprise à usage personnel", personal: 'Appareil personnel' },
  languageName: { fr: 'Français', en: 'English' },
  footer: "Cette page présente la notice en vigueur. Elle est affichée de nouveau, et doit être lue, avant chaque inscription d'un appareil.",
  unavailableTitle: 'Notice indisponible',
  unavailableBody: "La notice d'information des salariés de {org} n'est pas encore complète. Contactez votre administrateur.",
  tooMany: 'Trop de requêtes. Attendez une minute, puis réessayez.',
};

const EN: NoticePageTexts = {
  lang: 'en',
  pageTitle: 'Employee privacy notice',
  intro: 'The notice {org} shows before a device is enrolled in its fleet management.',
  kindLabel: 'Kind of device',
  languageLabel: 'Language',
  platform: { apple: 'Apple', android: 'Android' },
  ownership: { corporate: 'Company device', corporate_personal: 'Company device for personal use', personal: 'Personal device' },
  languageName: { fr: 'Français', en: 'English' },
  footer: 'This page shows the notice in force. It is shown again, to be read, before each device enrollment.',
  unavailableTitle: 'Notice unavailable',
  unavailableBody: 'The employee notice of {org} is not complete yet. Contact your administrator.',
  tooMany: 'Too many requests. Wait a minute, then try again.',
};

const TEXTS: Readonly<Record<NoticeLocale, NoticePageTexts>> = { fr: FR, en: EN };
export const noticePageTexts = (locale: NoticeLocale): NoticePageTexts => TEXTS[locale];

/** HTML escaping of a text value (element content and quoted attributes). */
export function esc(v: unknown): string {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function page(lang: string, title: string, body: string): string {
  return `<!doctype html>\n<html lang="${esc(lang)}"><head><meta charset="utf-8">`
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="referrer" content="no-referrer">'
    + '<meta name="robots" content="noindex">'
    + `<title>${esc(title)}</title><style>${STYLE}</style></head>`
    + `<body><main>${body}</main></body></html>\n`;
}

/** A combination of the page. */
export interface NoticeChoice { platform: NoticePlatform; ownership: Ownership }

/** The combinations of the page, in their order: the platforms served, the ownerships shown at an enrollment. */
export function publicNoticeChoices(platforms: readonly NoticePlatform[]): NoticeChoice[] {
  return platforms.flatMap((platform) => OWNERSHIPS.filter((o) => noticeDisplayed(platform, o)).map((ownership) => ({ platform, ownership })));
}

const defaultOwnership = (p: NoticePlatform): Ownership => (p === 'apple' ? 'corporate' : 'personal');

/** The combination and language asked by a query, null when a value given is not one of them. */
export function noticeQueryOf(query: Record<string, unknown>, acceptLanguage: unknown, platforms: readonly NoticePlatform[]):
  { choice: NoticeChoice; locale: NoticeLocale } | null {
  const given = (k: string): string | undefined | null => {
    const v = query[k];
    if (v === undefined || v === '') return undefined;
    return typeof v === 'string' ? v : null;
  };
  const p = given('platform');
  const o = given('ownership');
  const l = given('lang');
  if (p === null || o === null || l === null || platforms.length === 0) return null;
  const platform = (p ?? platforms[0]) as NoticePlatform;
  if (!platforms.includes(platform)) return null;
  const ownership = (o ?? defaultOwnership(platform)) as Ownership;
  if (!(OWNERSHIPS as readonly string[]).includes(ownership) || !noticeDisplayed(platform, ownership)) return null;
  if (l !== undefined && !(NOTICE_LOCALES as readonly string[]).includes(l)) return null;
  const locale = (l ?? pickLocale(acceptLanguage, 'fr')) as NoticeLocale;
  return { choice: { platform, ownership }, locale };
}

/** The query of a combination (the page itself: a relative link). */
export const noticeQuery = (c: NoticeChoice, locale: NoticeLocale): string =>
  `?${new URLSearchParams({ platform: c.platform, ownership: c.ownership, lang: locale }).toString()}`;

export interface NoticePublicPageInput {
  t: NoticePageTexts;
  organization: string;
  current: NoticeChoice;
  /** Every combination shown at an enrollment on this instance (the current one among them). */
  choices: readonly NoticeChoice[];
  locales: readonly NoticeLocale[];
  notice: NoticeContent;
}

/** The page of a notice. */
export function noticePublicPage(i: NoticePublicPageInput): string {
  const { t, current } = i;
  const platforms = new Set(i.choices.map((c) => c.platform));
  const label = (c: NoticeChoice): string => (platforms.size > 1 ? `${t.platform[c.platform]} · ${t.ownership[c.ownership]}` : t.ownership[c.ownership]);
  const same = (c: NoticeChoice): boolean => c.platform === current.platform && c.ownership === current.ownership;
  const link = (href: string, text: string, on: boolean): string =>
    `<li><a href="${esc(href)}"${on ? ' aria-current="page"' : ''}>${esc(text)}</a></li>`;
  const kinds = i.choices.length > 1
    ? `<nav><p>${esc(t.kindLabel)}</p><ul>${i.choices.map((c) => link(noticeQuery(c, t.lang), label(c), same(c))).join('')}</ul></nav>` : '';
  const langs = i.locales.length > 1
    ? `<nav lang="${esc(t.lang)}"><p>${esc(t.languageLabel)}</p><ul>${i.locales.map((l) => link(noticeQuery(current, l), t.languageName[l], l === t.lang)).join('')}</ul></nav>`
    : '';
  const n = i.notice;
  const sections = n.sections.map((s) => `<h2>${esc(s.heading)}</h2>${s.paragraphs.map((p) => `<p>${esc(p)}</p>`).join('')}`).join('');
  const body = `<h1>${esc(t.pageTitle)}</h1><p class="org">${esc(fill(t.intro, { org: i.organization }))}</p>`
    + kinds + langs
    + `<div class="card"><span class="tag">${esc(`${t.platform[current.platform]} · ${t.ownership[current.ownership]}`)}</span>`
    + `<h2>${esc(n.title)}</h2>${sections}`
    + (n.contact ? `<p>${esc(n.contact)}</p>` : '')
    + '</div>'
    + `<p class="meta">${esc(t.footer)}</p>`;
  return page(t.lang, `${t.pageTitle} — ${i.organization}`, body);
}

/** A message page (the notice not complete outside the laboratory, too many requests). */
export function noticeMessagePage(t: NoticePageTexts, title: string, text: string): string {
  return page(t.lang, title, `<h1>${esc(title)}</h1><div class="card"><p>${esc(text)}</p></div>`);
}
