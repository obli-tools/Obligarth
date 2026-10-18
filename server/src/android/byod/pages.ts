// Pages of the Android BYOD flow on the device surface (lot AN-F1, section 10.5), in the form of the pages of lot C
// (apple/enrollment/pages.ts on main): server-rendered HTML, no script, one embedded style sheet allowed by its
// SHA-256 in the CSP, every value escaped (plain text only, never HTML). The form posts to the page itself; the answer
// of an acknowledged notice is a 303 to Google's enrollment page, which form-action admits (browsers apply form-action
// to the redirects of a form submission).
import { createHash } from 'node:crypto';
import type { ByodTexts } from './i18n';
import type { AndroidNotice } from './notice';

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
  '.field{display:block;margin:16px 0}.field span{display:block;font-weight:600;margin-bottom:4px}.field small{display:block;color:#5f6672;margin-top:4px}',
  '.field input{box-sizing:border-box;width:100%;font-size:1.05rem;padding:10px;border:1px solid #c4c9d2;border-radius:8px}',
  '@media (prefers-color-scheme:dark){body{background:#111316;color:#e8eaed}.card{background:#1c1f24;box-shadow:none}.org{color:#9aa0a6}.tag{background:#22324f;color:#a8c3ff}.warn{color:#ffb27a}}',
].join('');

/** Google's enrollment page, the only target of the redirect after the acknowledgement. */
export const GOOGLE_ENROLL_ORIGIN = 'https://enterprise.google.com';

/** The CSP of every page: its style sheet by hash, forms to itself and to Google's enrollment page. */
export const BYOD_PAGE_CSP = [
  "default-src 'none'",
  `style-src 'sha256-${createHash('sha256').update(STYLE, 'utf8').digest('base64')}'`,
  "form-action 'self' " + GOOGLE_ENROLL_ORIGIN,
  "frame-ancestors 'none'",
  "base-uri 'none'",
].join('; ');

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
    + `<title>${esc(title)}</title><style>${STYLE}</style></head>`
    + `<body><main>${body}</main></body></html>\n`;
}

export interface ByodPageInput {
  t: ByodTexts;
  organization: string;
  notice: AndroidNotice;
  /** The form posts here (the page itself). */
  action: string;
  wrongCode?: boolean;
  noticeChanged?: boolean;
}

/** The notice of a personal device, the invitation code and the acknowledgement (section 10.5). */
export function byodPage(i: ByodPageInput): string {
  const n = i.notice;
  const sections = n.sections.map((s) => `<h2>${esc(s.heading)}</h2>${s.paragraphs.map((p) => `<p>${esc(p)}</p>`).join('')}`).join('');
  const body = `<h1>${esc(i.t.title)}</h1><p class="org">${esc(i.organization)}</p>`
    + `<div class="card"><span class="tag">${esc(i.t.ownershipLabel)} : ${esc(i.t.personal)}</span>`
    + `<p>${esc(i.t.intro.replace(/\{org\}/g, i.organization))}</p>`
    + `<h2>${esc(n.title)}</h2>${sections}`
    + (n.contact ? `<p>${esc(n.contact)}</p>` : '')
    + (i.noticeChanged ? `<p class="warn">${esc(i.t.noticeChanged)}</p>` : '')
    + (i.wrongCode ? `<p class="warn">${esc(i.t.wrongCode)}</p>` : '')
    + `<form method="post" action="${esc(i.action)}">`
    + `<input type="hidden" name="notice_version_id" value="${esc(n.versionId)}">`
    + `<input type="hidden" name="lang" value="${esc(n.locale)}">`
    + `<label class="field"><span>${esc(i.t.code)}</span>`
    + '<input type="text" name="code" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" required maxlength="40">'
    + `<small>${esc(i.t.codeHint)}</small></label>`
    + `<label><input type="checkbox" name="ack" value="1" required><span>${esc(i.t.ack)}</span></label>`
    + `<button type="submit">${esc(i.t.enroll)}</button></form>`
    + `<p><small>${esc(i.t.requirement)}</small></p></div>`;
  return page(i.t.lang, i.t.title, body);
}

/** A message page (too many attempts, unavailable, retry). */
export function byodMessagePage(t: ByodTexts, title: string, text: string): string {
  const body = `<h1>${esc(title)}</h1><div class="card"><p>${esc(text)}</p></div>`;
  return page(t.lang, title, body);
}
