// Pages of the sign-in URL flow on the device surface (lot AN-F2, section 10.5), in the form of the BYOD pages
// (byod/pages.ts): server-rendered HTML, no script, one embedded style sheet allowed by its SHA-256 in the CSP, every
// value escaped (plain text only). Only a personal device sees a page before Obligate: the notice of a personal device
// (USR-01) and its acknowledgement, whose form posts to the page itself and is answered by a 303 to Obligate, which
// form-action admits (browsers apply form-action to the redirects of a form submission). A company device goes to
// Obligate at once; a refused sign-in goes to Google's invalid page; the message pages say why the flow cannot go on.
import { createHash } from 'node:crypto';
import type { ByodLocale, ByodTexts } from '../byod/i18n';
import type { AndroidNotice } from '../byod/notice';
import { esc } from '../byod/pages';

const STYLE = [
  ':root{color-scheme:light dark}',
  'body{margin:0;font:16px/1.5 Roboto,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f5f7;color:#1c1e21}',
  'main{max-width:640px;margin:0 auto;padding:24px 16px 48px}',
  'h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:20px 0 6px}',
  '.org{color:#5f6672;margin:0 0 16px}',
  '.card{background:#fff;border-radius:12px;padding:16px 20px;box-shadow:0 1px 2px rgba(0,0,0,.08)}',
  '.tag{display:inline-block;background:#e7eefc;color:#1f4fbf;border-radius:999px;padding:2px 10px;font-size:.85rem;margin:8px 0}',
  '.warn{color:#9a3b00}',
  'label{display:flex;gap:10px;align-items:flex-start;margin:20px 0 12px}',
  'input[type=checkbox]{width:22px;height:22px;margin-top:2px}',
  'button{display:inline-block;width:100%;border:0;border-radius:10px;padding:14px;font-size:1.05rem;background:#1f4fbf;color:#fff;text-align:center}',
  '@media (prefers-color-scheme:dark){body{background:#111316;color:#e8eaed}.card{background:#1c1f24;box-shadow:none}.org{color:#9aa0a6}.tag{background:#22324f;color:#a8c3ff}.warn{color:#ffb27a}}',
].join('');

const STYLE_HASH = createHash('sha256').update(STYLE, 'utf8').digest('base64');

const ORIGIN_RE = /^https?:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$/;

/** The CSP of the pages: their style sheet by hash; forms to the page itself and, after the acknowledgement, to the
 *  origin of Obligate's authorization page (and nowhere else). */
export function signinPageCsp(identityOrigin: string | null): string {
  const target = identityOrigin && ORIGIN_RE.test(identityOrigin) ? ` ${identityOrigin}` : '';
  return [
    "default-src 'none'",
    `style-src 'sha256-${STYLE_HASH}'`,
    `form-action 'self'${target}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}

export interface SigninTexts {
  title: string;
  intro: string;
  continue: string;
  invalidTitle: string;
  invalidBody: string;
}

const TEXTS: Record<ByodLocale, SigninTexts> = {
  en: {
    title: 'Sign in to enroll your device',
    intro: 'Read what enrolling means for your device. You then sign in with your {org} account; a work profile is created on the device by Google\'s Android Device Policy.',
    continue: 'Continue',
    invalidTitle: 'Sign-in not possible',
    invalidBody: 'This sign-in cannot go on. Start the setup of the device again, or contact your administrator.',
  },
  fr: {
    title: 'Connectez-vous pour inscrire votre appareil',
    intro: 'Lisez ce que l\'inscription signifie pour votre appareil. Vous vous connectez ensuite avec votre compte {org} ; un profil professionnel est créé sur l\'appareil par Android Device Policy de Google.',
    continue: 'Continuer',
    invalidTitle: 'Connexion impossible',
    invalidBody: 'Cette connexion ne peut pas aller plus loin. Recommencez la configuration de l\'appareil, ou contactez votre administrateur.',
  },
};

export const signinTexts = (locale: ByodLocale): SigninTexts => TEXTS[locale];

function page(lang: string, title: string, body: string): string {
  return `<!doctype html>\n<html lang="${esc(lang)}"><head><meta charset="utf-8">`
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="referrer" content="no-referrer">'
    + `<title>${esc(title)}</title><style>${STYLE}</style></head>`
    + `<body><main>${body}</main></body></html>\n`;
}

export interface SigninNoticePageInput {
  byod: ByodTexts;
  t: SigninTexts;
  organization: string;
  notice: AndroidNotice;
  /** The state of the session (the form's handle; it never reaches Obligate). */
  state: string;
  action: string;
  noticeChanged?: boolean;
}

/** The notice of a personal device before the sign-in (USR-01). */
export function signinNoticePage(i: SigninNoticePageInput): string {
  const n = i.notice;
  const sections = n.sections.map((s) => `<h2>${esc(s.heading)}</h2>${s.paragraphs.map((p) => `<p>${esc(p)}</p>`).join('')}`).join('');
  const body = `<h1>${esc(i.t.title)}</h1><p class="org">${esc(i.organization)}</p>`
    + `<div class="card"><span class="tag">${esc(i.byod.ownershipLabel)} : ${esc(i.byod.personal)}</span>`
    + `<p>${esc(i.t.intro.replace(/\{org\}/g, i.organization))}</p>`
    + `<h2>${esc(n.title)}</h2>${sections}`
    + (n.contact ? `<p>${esc(n.contact)}</p>` : '')
    + (i.noticeChanged ? `<p class="warn">${esc(i.byod.noticeChanged)}</p>` : '')
    + `<form method="post" action="${esc(i.action)}">`
    + `<input type="hidden" name="s" value="${esc(i.state)}">`
    + `<input type="hidden" name="notice_version_id" value="${esc(n.versionId)}">`
    + `<input type="hidden" name="lang" value="${esc(n.locale)}">`
    + `<label><input type="checkbox" name="ack" value="1" required><span>${esc(i.byod.ack)}</span></label>`
    + `<button type="submit">${esc(i.t.continue)}</button></form></div>`;
  return page(i.byod.lang, i.t.title, body);
}

/** A message page (too many attempts, unavailable). */
export function signinMessagePage(lang: ByodLocale, title: string, text: string): string {
  return page(lang, title, `<h1>${esc(title)}</h1><div class="card"><p>${esc(text)}</p></div>`);
}
