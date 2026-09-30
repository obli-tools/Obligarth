import { AppError } from '../middleware/errorHandler';
import { appConfigService } from './appConfig.service';
import type { SettingsWriteDef } from './settingsWrite.service';

// ── File explorer: editable extensions (platform setting) ───────────────────
// Global, cross-tenant: GET / PUT /api/admin/config/editable-extensions
// (routes/fileExplorerSettings.routes.ts). The write is gated and replayed as
// a named settings write (settingsWrite.service), registered by
// modules/rmm.ts.

const EDITABLE_EXT_KEY        = 'file_explorer_editable_extensions';

const DEFAULT_EDITABLE_EXTENSIONS = [
  'txt', 'md', 'log', 'json', 'xml', 'yaml', 'yml', 'ini', 'conf', 'cfg',
  'env', 'properties', 'toml', 'csv', 'tsv',
  'js', 'ts', 'jsx', 'tsx', 'py', 'go', 'rs', 'java', 'c', 'cpp', 'h',
  'cs', 'rb', 'php', 'html', 'htm', 'css', 'scss', 'sass', 'less',
  'sh', 'bash', 'zsh', 'fish', 'bat', 'cmd', 'ps1', 'psm1', 'psd1',
  'sql', 'vue', 'svelte', 'astro', 'lua', 'pl', 'r', 'swift',
  'kt', 'scala', 'clj', 'cljs', 'ex', 'exs', 'erl', 'hs', 'dart', 'zig',
  'dockerfile', 'gitignore', 'editorconfig', 'htaccess',
];

export const fileExplorerSettings = {
  /** File explorer editable extensions (global, cross-tenant). */
  async getEditableExtensions(): Promise<string[]> {
    const raw = await appConfigService.get(EDITABLE_EXT_KEY);
    if (!raw) return DEFAULT_EDITABLE_EXTENSIONS;
    try {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr) && arr.every((x) => typeof x === 'string')) return arr;
    } catch {}
    return DEFAULT_EDITABLE_EXTENSIONS;
  },

  async setEditableExtensions(extensions: string[]): Promise<string[]> {
    // Normalise: lowercase, strip leading dots, dedupe, keep non-empty only.
    const cleaned = Array.from(new Set(
      extensions
        .map((e) => String(e).trim().toLowerCase().replace(/^\./, ''))
        .filter((e) => e.length > 0),
    ));
    await appConfigService.set(EDITABLE_EXT_KEY, JSON.stringify(cleaned));
    return cleaned;
  },

  getDefaultEditableExtensions(): string[] {
    return [...DEFAULT_EDITABLE_EXTENSIONS];
  },
};

/** PUT /editable-extensions */
export async function writeEditableExtensions(extensions: unknown): Promise<string[]> {
  if (!Array.isArray(extensions)) throw new AppError(400, 'extensions must be an array of strings');
  return fileExplorerSettings.setEditableExtensions(extensions as string[]);
}

/** The write as an approval keeps it, and its replay (registerSettingsWrite). */
export const editableExtensionsWrite: SettingsWriteDef = {
  method: 'PUT',
  path: '/editable-extensions',
  async prepare(raw) {
    const { short } = await import('./approvalDescribe');
    if (!Array.isArray(raw.extensions)) throw new AppError(400, 'extensions must be an array of strings');
    const exts = (raw.extensions as unknown[]).map(String);
    return {
      body: { extensions: exts }, carriesSecret: false, otherChanges: true,
      description: `File explorer editable extensions → ${short(exts, 400)} (${exts.length})`,
    };
  },
  async apply(body) {
    await writeEditableExtensions(body.extensions);
  },
};
