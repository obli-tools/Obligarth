import { createHash } from 'node:crypto';
import type { EnrollmentNotice } from './notice';
import type { SurfaceTexts } from './i18n';

// =============================================================================
// Pages of the device surface (docs: integration-apple-edge §10.3, §10.8):
// server-rendered HTML, no script, one embedded style sheet allowed by its
// SHA-256 in the CSP, every value escaped (plain text only, never HTML). The
// forms post to the page itself ('self').
// =============================================================================

const STYLE = [
  ':root{color-scheme:light dark}',
  'body{margin:0;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f4f5f7;color:#1c1e21}',
  'main{max-width:640px;margin:0 auto;padding:24px 16px 48px}',
  'h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:20px 0 6px}',
  '.org{color:#5f6672;margin:0 0 16px}',
  '.card{background:#fff;border-radius:12px;padding:16px 20px;box-shadow:0 1px 2px rgba(0,0,0,.08)}',
  '.tag{display:inline-block;background:#e7eefc;color:#1f4fbf;border-radius:999px;padding:2px 10px;font-size:.85rem;margin:8px 0}',
  '.warn{color:#9a3b00}',
  'label{display:flex;gap:10px;align-items:flex-start;margin:20px 0 12px}',
  'input[type=checkbox]{width:22px;height:22px;margin-top:2px}',
  'button,.button{display:inline-block;width:100%;border:0;border-radius:10px;padding:14px;font-size:1.05rem;background:#1f4fbf;color:#fff;text-align:center;text-decoration:none}',
  'ol{padding-left:22px}',
  '.field{display:block;margin:16px 0}.field span{display:block;font-weight:600;margin-bottom:4px}.field small{display:block;color:#5f6672;margin-top:4px}',
  '.field input{box-sizing:border-box;width:100%;font-size:1.05rem;padding:10px;border:1px solid #c4c9d2;border-radius:8px}',
  '@media (prefers-color-scheme:dark){body{background:#111316;color:#e8eaed}.card{background:#1c1f24;box-shadow:none}.org{color:#9aa0a6}.tag{background:#22324f;color:#a8c3ff}.warn{color:#ffb27a}}',
].join('');

/** The CSP of every page (§10.8): its style sheet by hash, forms to itself and the BYOD login scheme. */
export const PAGE_CSP = [
  "default-src 'none'",
  `style-src 'sha256-${createHash('sha256').update(STYLE, 'utf8').digest('base64')}'`,
  'img-src data:',
  "form-action 'self' apple-remotemanagement-user-login:",
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

export interface NoticePageInput {
  t: SurfaceTexts;
  organization: string;
  ownershipLabel: string;
  notice: EnrollmentNotice;
  /** The form posts here (a path of the page itself). */
  action: string;
  /** A notice of another version was acknowledged: read again. */
  noticeChanged?: boolean;
  /** Hidden fields of the form (the ADE web view: its session and its form token). */
  hidden?: Record<string, string>;
}

const hiddenFields = (h: Record<string, string> | undefined): string => Object.entries(h ?? {})
  .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join('');

/** The notice and its acknowledgement form (OTA, §10.3 step 1). */
export function noticePage(i: NoticePageInput): string {
  const n = i.notice;
  const sections = n.sections.map((s) => `<h2>${esc(s.heading)}</h2>${s.paragraphs.map((p) => `<p>${esc(p)}</p>`).join('')}`).join('');
  const body = `<h1>${esc(i.t.pageTitle)}</h1><p class="org">${esc(i.organization)}</p>`
    + `<div class="card"><span class="tag">${esc(i.t.ownershipLabel)} : ${esc(i.ownershipLabel)}</span>`
    + `<h2>${esc(n.title)}</h2>${sections}`
    + (n.contact ? `<p>${esc(n.contact)}</p>` : '')
    + (i.noticeChanged ? `<p class="warn">${esc(i.t.noticeChanged)}</p>` : '')
    + `<form method="post" action="${esc(i.action)}">`
    + `<input type="hidden" name="notice_version_id" value="${esc(n.versionId)}">`
    + `<input type="hidden" name="lang" value="${esc(n.locale)}">`
    + hiddenFields(i.hidden)
    + `<label><input type="checkbox" name="ack" value="1" required><span>${esc(i.t.ack)}</span></label>`
    + `<button type="submit">${esc(i.t.continue)}</button></form></div>`;
  return page(i.t.lang, i.t.pageTitle, body);
}

/** A message page (invalid link, not ready, failure), with an optional link (retry). */
export function messagePage(t: SurfaceTexts, title: string, text: string, link?: { href: string; label: string }): string {
  const body = `<h1>${esc(title)}</h1><div class="card"><p>${esc(text)}</p>`
    + (link ? `<p><a class="button" href="${esc(link.href)}">${esc(link.label)}</a></p>` : '')
    + '</div>';
  return page(t.lang, title, body);
}

/** The instructions of an account-driven enrollment (the link of an invitation). */
export function invitePage(t: SurfaceTexts, organization: string, texts: { intro: string }): string {
  const body = `<h1>${esc(t.inviteTitle)}</h1><p class="org">${esc(organization)}</p><div class="card">`
    + `<p>${esc(texts.intro)}</p><ol>${t.inviteSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`
    + `<p>${esc(t.inviteRequirement)}</p></div>`;
  return page(t.lang, t.inviteTitle, body);
}

export interface ByodAuthPageInput {
  t: SurfaceTexts;
  organization: string;
  ownershipLabel: string;
  notice: EnrollmentNotice;
  /** The form posts here (the page itself). */
  action: string;
  /** The Managed Apple Account of the web view (user-identifier); null: typed in the page [J1]. */
  account: string | null;
  formToken: string;
  /** The code typed was refused. */
  wrongCode?: boolean;
  noticeChanged?: boolean;
}

/** The web view of an account-driven enrollment (§10.5 step 3): the notice of a personal device, the invitation
 *  code and the acknowledgement. */
export function byodAuthPage(i: ByodAuthPageInput): string {
  const n = i.notice;
  const sections = n.sections.map((s) => `<h2>${esc(s.heading)}</h2>${s.paragraphs.map((p) => `<p>${esc(p)}</p>`).join('')}`).join('');
  const account = i.account
    ? `<p>${esc(i.t.byodAccount)} : <strong>${esc(i.account)}</strong></p><input type="hidden" name="user_identifier" value="${esc(i.account)}">`
    : `<label class="field"><span>${esc(i.t.byodAccount)}</span>`
      + '<input type="email" name="user_identifier" autocomplete="username" autocapitalize="off" spellcheck="false" required maxlength="320">'
      + `<small>${esc(i.t.byodAccountHint)}</small></label>`;
  const body = `<h1>${esc(i.t.byodTitle)}</h1><p class="org">${esc(i.organization)}</p>`
    + `<div class="card"><span class="tag">${esc(i.t.ownershipLabel)} : ${esc(i.ownershipLabel)}</span>`
    + `<p>${esc(i.t.byodIntro.replace(/\{org\}/g, i.organization))}</p>`
    + `<h2>${esc(n.title)}</h2>${sections}`
    + (n.contact ? `<p>${esc(n.contact)}</p>` : '')
    + (i.noticeChanged ? `<p class="warn">${esc(i.t.noticeChanged)}</p>` : '')
    + (i.wrongCode ? `<p class="warn">${esc(i.t.byodWrongCode)}</p>` : '')
    + `<form method="post" action="${esc(i.action)}">`
    + `<input type="hidden" name="notice_version_id" value="${esc(n.versionId)}">`
    + `<input type="hidden" name="lang" value="${esc(n.locale)}">`
    + `<input type="hidden" name="form_token" value="${esc(i.formToken)}">`
    + account
    + `<label class="field"><span>${esc(i.t.byodCode)}</span>`
    + '<input type="text" name="code" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" required maxlength="40">'
    + `<small>${esc(i.t.byodCodeHint)}</small></label>`
    + `<label><input type="checkbox" name="ack" value="1" required><span>${esc(i.t.ack)}</span></label>`
    + `<button type="submit">${esc(i.t.byodEnroll)}</button></form></div>`;
  return page(i.t.lang, i.t.byodTitle, body);
}
