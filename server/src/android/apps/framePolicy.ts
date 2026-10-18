// Content security policy of the console pages that host a Google iframe (android-amapi §12.3, AN22; lot AN-E1):
// frame-src https://play.google.com https://enterprise.google.com and script-src https://apis.google.com (gapi) are
// added to those pages only; every other page keeps its policy unchanged.
// Where the policy is set today (checked in the code at lot AN-E1): helmet in server/src/app.ts sets a strict policy on
// the API's answers (JSON: frames and scripts are moot there); the console is a single-page application served by
// client/nginx.conf, which sets no Content-Security-Policy at all. Junction AN-A2/AN-C2: when the console gets its
// policy (nginx or a header of the server), the pages of ANDROID_IFRAME_PAGES (and the zero-touch page of lot AN-F2)
// get androidFrameCsp(base) instead; androidFramePolicy is the middleware for a console served by Express.
// Pure apart from the middleware.
import type { NextFunction, Request, Response } from 'express';
import { ANDROID_FRAME_SOURCES, ANDROID_IFRAME_PAGES, ANDROID_SCRIPT_SOURCES } from '@obligarth/shared/dist/android/apps.js';

/** Pages hosting a Google iframe: those of ANDROID_IFRAME_PAGES and the zero-touch page (lot AN-F2). */
const ZERO_TOUCH_PAGE = /^\/enrollment\/android\/zero-touch$/;

export function isAndroidIframePage(path: unknown): boolean {
  if (typeof path !== 'string' || path.length > 200) return false;
  return ZERO_TOUCH_PAGE.test(path) || ANDROID_IFRAME_PAGES.some((p) => p.path.test(path));
}

/** Parses a Content-Security-Policy value into its directives (names lowercased, order kept). */
export function parseCsp(value: string): Array<[string, string[]]> {
  const out: Array<[string, string[]]> = [];
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (out.some(([n]) => n === name)) continue;       // the first occurrence of a directive is the one that applies
    out.push([name, tokens.slice(1)]);
  }
  return out;
}

/**
 * The policy of a page hosting a Google iframe: the base policy (the console's) with the Google sources added to
 * frame-src and script-src. A directive absent from the base falls back on default-src: it is created from
 * default-src's sources (never wider than the base), plus Google's. 'none' is replaced, never kept beside a source.
 */
export function androidFrameCsp(base: string | null | undefined): string {
  const directives = parseCsp(base ?? "default-src 'self'");
  const sourcesOf = (name: string): string[] | undefined => directives.find(([n]) => n === name)?.[1];
  const fallback = sourcesOf('default-src') ?? ["'self'"];
  // Review AN-E1: frame-src falls back on child-src before default-src (CSP level 3); a frame-src created from
  // default-src beside a narrower child-src would widen the base.
  const add = (name: string, sources: readonly string[], base: string[] = fallback): void => {
    const d = directives.find(([n]) => n === name);
    const current = d ? d[1] : [...base];
    const kept = current.filter((s) => s !== "'none'");
    const next = [...kept, ...sources.filter((s) => !kept.includes(s))];
    if (d) d[1] = next; else directives.push([name, next]);
  };
  add('frame-src', ANDROID_FRAME_SOURCES, sourcesOf('child-src') ?? fallback);
  add('script-src', ANDROID_SCRIPT_SOURCES);
  // script-src-elem, when the base sets it, governs <script> elements instead of script-src: gapi goes there too.
  if (sourcesOf('script-src-elem')) add('script-src-elem', ANDROID_SCRIPT_SOURCES);
  return directives.map(([n, s]) => [n, ...s].join(' ')).join('; ');
}

/** Express middleware: on a page hosting a Google iframe, the Content-Security-Policy set before it (helmet) gets the
 *  Google sources; any other request is untouched. */
export function androidFramePolicy() {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (isAndroidIframePage(req.path)) {
      const current = res.getHeader('Content-Security-Policy');
      res.setHeader('Content-Security-Policy', androidFrameCsp(typeof current === 'string' ? current : null));
    }
    next();
  };
}
