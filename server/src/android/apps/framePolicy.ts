// Content security policy of the console pages that host a Google iframe (android-amapi §12.3, AN22; lot AN-E1):
// frame-src https://play.google.com https://enterprise.google.com and script-src https://apis.google.com (gapi) are
// added to those pages only; every other page keeps its policy unchanged.
// Where the policy is set (lot AN-E): helmet in server/src/app.ts sets a strict policy on the API's answers (JSON:
// frames and scripts are moot there); the console is a single-page application served by client/nginx.conf, whose map
// $obligarth_csp gives every page CONSOLE_BASE_CSP and the pages of ANDROID_IFRAME_PAGES and the zero-touch page
// androidFrameCsp(CONSOLE_BASE_CSP) (the zero-touch page with its own sources); the testbed checks that the values
// written in nginx.conf are exactly these. androidFramePolicy is the middleware for a console served by Express.
// Pure apart from the middleware.
import type { NextFunction, Request, Response } from 'express';
import { ANDROID_FRAME_SOURCES, ANDROID_IFRAME_PAGES, ANDROID_SCRIPT_SOURCES, ANDROID_ZERO_TOUCH_FRAME_SOURCES } from '@obligarth/shared';

/** Pages hosting a Google iframe: those of ANDROID_IFRAME_PAGES and the zero-touch page (lot AN-F2). */
const ZERO_TOUCH_PAGE = /^\/enrollment\/android\/zero-touch$/;

export function isAndroidZeroTouchPage(path: unknown): boolean {
  return typeof path === 'string' && ZERO_TOUCH_PAGE.test(path);
}

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
 * frame-src and script-src. A directive absent from the base falls back on its fallback directive (frame-src on
 * child-src, then default-src; script-src on default-src): it is created from that directive's sources (never wider
 * than the base), plus Google's. When the base sets neither the directive nor any fallback, the base does not restrict
 * it at all, and nothing is added (lot AN-E: creating it would narrow the base, the console's inline theme script
 * blocked by a script-src made up here). 'none' is replaced, never kept beside a source. The zero-touch page
 * (o.zeroTouch) admits ANDROID_ZERO_TOUCH_FRAME_SOURCES.
 */
export function androidFrameCsp(base: string | null | undefined, o: { zeroTouch?: boolean } = {}): string {
  const directives = parseCsp(base ?? "default-src 'self'");
  const sourcesOf = (name: string): string[] | undefined => directives.find(([n]) => n === name)?.[1];
  const add = (name: string, sources: readonly string[], fallback: string[] | undefined): void => {
    const d = directives.find(([n]) => n === name);
    if (!d && !fallback) return;
    const current = d ? d[1] : [...fallback!];
    const kept = current.filter((s) => s !== "'none'");
    const next = [...kept, ...sources.filter((s) => !kept.includes(s))];
    if (d) d[1] = next; else directives.push([name, next]);
  };
  // Review AN-E1: frame-src falls back on child-src before default-src (CSP level 3); a frame-src created from
  // default-src beside a narrower child-src would widen the base.
  add('frame-src', o.zeroTouch ? ANDROID_ZERO_TOUCH_FRAME_SOURCES : ANDROID_FRAME_SOURCES, sourcesOf('child-src') ?? sourcesOf('default-src'));
  add('script-src', ANDROID_SCRIPT_SOURCES, sourcesOf('default-src'));
  // script-src-elem, when the base sets it, governs <script> elements instead of script-src: gapi goes there too.
  if (sourcesOf('script-src-elem')) add('script-src-elem', ANDROID_SCRIPT_SOURCES, undefined);
  return directives.map(([n, s]) => [n, ...s].join(' ')).join('; ');
}

/** Express middleware: on a page hosting a Google iframe, the Content-Security-Policy set before it (helmet) gets the
 *  Google sources; any other request is untouched. */
export function androidFramePolicy() {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (isAndroidIframePage(req.path)) {
      const current = res.getHeader('Content-Security-Policy');
      res.setHeader('Content-Security-Policy', androidFrameCsp(typeof current === 'string' ? current : null, { zeroTouch: isAndroidZeroTouchPage(req.path) }));
    }
    next();
  };
}
