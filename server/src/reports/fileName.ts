import path from 'path';

/**
 * The name an output downloads under: `<report name>-<YYYY-MM-DD>.<ext>`, the
 * day it was generated (UTC) and the extension of the file produced (the
 * format of the report may have changed since). Characters a file system
 * refuses become spaces; never the name of the file on the server. null: no
 * file yet.
 */
export function outputFileName(reportName: unknown, generatedAt: unknown, filePath: unknown): string | null {
  if (!filePath) return null;
  const ext = path.extname(String(filePath)).slice(1).toLowerCase().replace(/[^a-z0-9]/g, '') || 'txt';
  const at = generatedAt instanceof Date ? generatedAt : generatedAt ? new Date(String(generatedAt)) : null;
  const day = at && !Number.isNaN(at.getTime()) ? at.toISOString().slice(0, 10) : 'undated';
  // eslint-disable-next-line no-control-regex
  const base = String(reportName ?? '').normalize('NFC').replace(/[\u0000-\u001f\u007f<>:"/\\|?*]+/g, ' ')
    .replace(/\s+/g, ' ').trim().replace(/^\.+/, '').slice(0, 120).trim() || 'report';
  return `${base}-${day}.${ext}`;
}
