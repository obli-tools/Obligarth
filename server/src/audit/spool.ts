// Local spool of the audit entries the database did not take (docs:
// audit-durci §5.5): standard and protective entries only (a critical entry
// that cannot be written refuses its action instead). One file per day,
// spool-YYYYMMDD.jsonl, mode 600, in AUDIT_SPOOL_DIR (mode 700); a line per
// entry: { tenant, body, firstError, spooledAt }, the body rebuilt with
// late: true (not chained yet, same id and instant). Written with
// appendFileSync and fsync. Bodies refused as malformed go to rejected/,
// never replayed. The spool holds personal data (addresses, usernames): it
// is never exported, it is in the backup of the custom volume, and emptied as
// soon as replayed.
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs';
import path from 'node:path';
import { config } from '../config';
import { auditMetrics } from './metrics';

export interface SpoolLine {
  tenant: number;
  body: string;
  firstError: string;
  spooledAt: string;
}

const FILE_RE = /^spool-[0-9]{8}\.jsonl$/;
const REJECTED_FILE_RE = /^rejected-[0-9]{8}\.jsonl$/;

export function spoolDir(): string {
  return path.resolve(config.audit.spoolDir);
}

function rejectedDir(): string {
  return path.join(spoolDir(), 'rejected');
}

function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function day(d = new Date()): string {
  return d.toISOString().slice(0, 10).replace(/-/g, '');
}

function appendLines(file: string, lines: readonly SpoolLine[]): void {
  if (!lines.length) return;
  const fd = openSync(file, 'a', 0o600);
  try {
    writeSync(fd, lines.map((l) => `${JSON.stringify(l)}\n`).join(''));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Entries kept for a later replay. Throws when the disk refuses them (the
 *  caller logs the loss). */
export function spoolEntries(lines: readonly SpoolLine[]): void {
  if (!lines.length) return;
  ensureDir(spoolDir());
  appendLines(path.join(spoolDir(), `spool-${day()}.jsonl`), lines);
  auditMetrics.inc('obligarth_audit_spooled_total', {}, lines.length);
}

/** Entries refused as malformed (or too old to be replayed): kept for the
 *  administration command, never replayed automatically. */
export function rejectEntries(lines: readonly SpoolLine[]): void {
  if (!lines.length) return;
  ensureDir(rejectedDir());
  appendLines(path.join(rejectedDir(), `rejected-${day()}.jsonl`), lines);
  auditMetrics.inc('obligarth_audit_spool_rejected', {}, lines.length);
}

/** The spool files, oldest first. */
export function spoolFiles(): string[] {
  const dir = spoolDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => FILE_RE.test(f)).sort().map((f) => path.join(dir, f));
}

export function rejectedFiles(dir = rejectedDir()): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => REJECTED_FILE_RE.test(f) || FILE_RE.test(f)).sort().map((f) => path.join(dir, f));
}

/** The lines of a spool file (unreadable lines are kept aside as rejected). */
export function readSpoolFile(file: string): { lines: SpoolLine[]; unreadable: number } {
  const lines: SpoolLine[] = [];
  let unreadable = 0;
  for (const raw of readFileSync(file, 'utf8').split('\n')) {
    if (!raw.trim()) continue;
    try {
      const l = JSON.parse(raw) as SpoolLine;
      if (typeof l.body === 'string' && Number.isSafeInteger(Number(l.tenant))) lines.push({ ...l, tenant: Number(l.tenant) });
      else unreadable++;
    } catch {
      unreadable++;
    }
  }
  return { lines, unreadable };
}

/** Rewrites a spool file with the lines still to replay (atomic rename), or
 *  removes it when none is left. */
export function rewriteSpoolFile(file: string, remaining: readonly SpoolLine[]): void {
  if (!remaining.length) {
    unlinkSync(file);
    return;
  }
  const tmp = `${file}.tmp`;
  const fd = openSync(tmp, 'w', 0o600);
  try {
    writeSync(fd, remaining.map((l) => `${JSON.stringify(l)}\n`).join(''));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
}

/** Lines waiting in the spool, the oldest instant, the rejected lines. */
export function spoolStatus(): { entries: number; oldestSpooledAt: string | null; rejected: number; files: number } {
  let entries = 0;
  let oldest: string | null = null;
  const files = spoolFiles();
  for (const f of files) {
    const { lines } = readSpoolFile(f);
    entries += lines.length;
    for (const l of lines) if (typeof l.spooledAt === 'string' && (oldest === null || l.spooledAt < oldest)) oldest = l.spooledAt;
  }
  let rejected = 0;
  for (const f of rejectedFiles()) {
    try {
      rejected += readFileSync(f, 'utf8').split('\n').filter((x) => x.trim()).length;
    } catch { /* unreadable: counted as none */ }
  }
  auditMetrics.set('obligarth_audit_spool_entries', entries);
  auditMetrics.set('obligarth_audit_spool_rejected', rejected);
  return { entries, oldestSpooledAt: oldest, rejected, files: files.length };
}

/** Size of a file, or 0. */
export function fileSize(file: string): number {
  try { return statSync(file).size; } catch { return 0; }
}
