import en from './i18n/en.json';
import fr from './i18n/fr.json';

/**
 * Obligarth bench station — the texts of the process itself (message boxes), in the language of Windows: the same
 * catalogs as the page. `t()` answers '' for a missing key, so a caller writes `t('bench.main.x') || 'Fallback'`.
 */
const CATALOGS: Record<string, Record<string, string>> = { en, fr };

export function systemLang(): 'en' | 'fr' {
  let loc = '';
  try { loc = Intl.DateTimeFormat().resolvedOptions().locale; } catch { /* none */ }
  return loc.toLowerCase().startsWith('fr') ? 'fr' : 'en';
}

export function t(key: string, params: Record<string, string | number> = {}, lang: 'en' | 'fr' = systemLang()): string {
  const s = CATALOGS[lang]?.[key] ?? CATALOGS.en[key] ?? '';
  return s.replace(/\{\{(\w+)\}\}/g, (_, k: string) => (params[k] !== undefined ? String(params[k]) : ''));
}
