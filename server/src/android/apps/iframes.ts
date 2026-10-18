// The screens of the managed Google Play iframes and the pages allowed to host them (android-amapi §9.6, §12.3; lot
// AN-E1). Pure (unit tests: appPolicy.test.ts); the token itself is webTokens.ts's.
import { ANDROID_IFRAME_PAGES, ANDROID_IFRAME_SCREENS, type AndroidIframeScreen } from '@obligarth/shared/dist/android/apps.js';
import type { IframeFeature } from '../gateway/types';

const PATH_MAX = 200;

/** The features of a screen, or null for an unknown one. */
export function featuresOfScreen(screen: unknown): IframeFeature[] | null {
  if (typeof screen !== 'string' || !Object.prototype.hasOwnProperty.call(ANDROID_IFRAME_SCREENS, screen)) return null;
  return [...ANDROID_IFRAME_SCREENS[screen as AndroidIframeScreen]] as IframeFeature[];
}

/**
 * The exact URL of the page hosting `screen`: the public origin of the console and an allowed path; null when the
 * path is not allowed for the screen (any query, fragment, encoded character, dot segment or double slash refused).
 */
export function parentFrameUrlOf(origin: string | null, screen: AndroidIframeScreen, path: unknown): string | null {
  if (!origin || !/^https:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$/.test(origin)) return null;
  if (typeof path !== 'string' || path.length === 0 || path.length > PATH_MAX || !/^\/[A-Za-z0-9/-]*$/.test(path)
    || path.includes('//') || path.endsWith('/')) return null;
  const page = ANDROID_IFRAME_PAGES.find((p) => p.screens.includes(screen) && p.path.test(path));
  if (!page) return null;
  const url = new URL(path, origin);
  if (url.origin !== origin || url.pathname !== path) return null;
  return `${origin}${path}`;
}
