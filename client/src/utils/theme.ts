import type { AppTheme } from '@obligarth/shared';

export type { AppTheme };

const STORAGE_KEY = 'obligarth:theme';
/** Key inherited from Obliance: read once (and moved) when the new one is
 *  still empty, so a saved choice survives the rename. index.html's
 *  anti-flash script reads it the same way. */
const LEGACY_STORAGE_KEY = 'oa-theme';

/** The saved theme id, moving a value still stored under the legacy key. */
function readStoredTheme(): string | null {
  const value = localStorage.getItem(STORAGE_KEY);
  if (value !== null) return value;
  const legacy = localStorage.getItem(LEGACY_STORAGE_KEY);
  if (legacy !== null) {
    localStorage.setItem(STORAGE_KEY, legacy);
    localStorage.removeItem(LEGACY_STORAGE_KEY);
  }
  return legacy;
}

/** Every theme id this app knows how to render. */
const KNOWN_THEMES = new Set<AppTheme>(['obli-operator', 'obli-daylight', 'obli-dim', 'modern', 'neon']);

/** True when `theme` is an id this app can render (see KNOWN_THEMES). */
export function isKnownTheme(theme: unknown): theme is AppTheme {
  return typeof theme === 'string' && KNOWN_THEMES.has(theme as AppTheme);
}

/**
 * Apply a theme by setting data-theme on <html> and persisting it. Unknown
 * ids (e.g. a future theme Obligate adds and pushes via SSO before this app
 * ships support for it) fall back to obli-operator rather than poisoning
 * data-theme with a value that has no token block — which would leave the UI
 * inheriting the dark :root defaults on an unstyled surface.
 */
export function applyTheme(theme: string): void {
  const safe: AppTheme = KNOWN_THEMES.has(theme as AppTheme) ? (theme as AppTheme) : 'obli-operator';
  document.documentElement.dataset.theme = safe;
  try {
    localStorage.setItem(STORAGE_KEY, safe);
  } catch {
    // localStorage unavailable
  }
}

/** Load the theme from localStorage (used before session check to avoid flash). */
export function loadSavedTheme(): AppTheme {
  try {
    const saved = readStoredTheme();
    if (saved && KNOWN_THEMES.has(saved as AppTheme)) return saved as AppTheme;
  } catch {
    // ignore
  }
  return 'obli-operator';
}

/** Called once on app boot in main.tsx to prevent flash of wrong theme. */
export function initTheme(): void {
  applyTheme(loadSavedTheme());
}
