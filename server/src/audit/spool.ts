// Local spool of the audit entries the database did not take (docs:
// audit-durci §5.5): standard and protective entries only (a critical entry
// that cannot be written refuses its action instead). One file per day,
// spool-YYYYMMDD.jsonl, mode 600, in AUDIT_SPOOL_DIR (mode 700); a line per
// entry: { tenant, body, firstError, spooledAt }, the body rebuilt with
// late: true (not chained yet, same id and instant). Written with
// appendFileSync and fsync. Bodies refused as malformed go to rejected/,
// never replayed; lines that do not even parse go there too, as they were
// (unreadable-YYYYMMDD.txt). A file being replayed is renamed first
// (.replaying), so that new entries never land in it. The spool holds personal data (addresses, usernames): it
// is never exported, it is in the backup of the custom volume, and emptied as
// soon as replayed.
import {
  closeSync, existsSync, fstatSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
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
/** A spool file taken by the replay (renamed before it is read: review F055); a leftover of a replay interrupted. */
const CLAIMED_SUFFIX = '.replaying';
const CLAIMED_RE = /^spool-[0-9]{8}\.jsonl\.replaying$/;
const REJECTED_FILE_RE = /^rejected-[0-9]{8}\.jsonl$/;
/** Lines of a spool file that could not be parsed, kept as they were (never replayed nor imported: review F058). */
const UNREADABLE_FILE_RE = /^unreadable-[0-9]{8}\.txt$/;

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

/** Appends text to a file; a file whose last line was cut (a full disk, a process killed during a write) first gets
 *  its line ended, so that the cut line never takes the next entry with it (review F058). */
function appendText(file: string, text: string): void {
  const fd = openSync(file, 'a+', 0o600);
  try {
    const size = fstatSync(fd).size;
    let guard = '';
    if (size > 0) {
      const last = Buffer.alloc(1);
      readSync(fd, last, 0, 1, size - 1);
      if (last[0] !== 0x0a) guard = '\n';
    }
    writeSync(fd, guard + text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function appendLines(file: string, lines: readonly SpoolLine[]): void {
  if (!lines.length) return;
  appendText(file, lines.map((l) => `${JSON.stringify(l)}\n`).join(''));
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

/** Lines of a spool file that do not parse: kept as they were in rejected/unreadable-<day>.txt, for a human (the
 *  spool-import command reads only rejected-<day>.jsonl). Throws when the disk refuses them. */
export function keepUnreadable(raw: readonly string[]): void {
  if (!raw.length) return;
  ensureDir(rejectedDir());
  appendText(path.join(rejectedDir(), `unreadable-${day()}.txt`), raw.map((l) => `${l.replace(/[\r\n]+/g, ' ')}\n`).join(''));
  auditMetrics.inc('obligarth_audit_spool_rejected', {}, raw.length);
}

/** The spool files, oldest first. */
export function spoolFiles(): string[] {
  const dir = spoolDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => FILE_RE.test(f)).sort().map((f) => path.join(dir, f));
}

/** Spool files taken by a replay that did not finish (a crash in between), oldest first. */
export function claimedSpoolFiles(): string[] {
  const dir = spoolDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => CLAIMED_RE.test(f)).sort().map((f) => path.join(dir, f));
}

/** The spool file a claimed file came from. */
export function spoolFileOf(claimed: string): string {
  return claimed.endsWith(CLAIMED_SUFFIX) ? claimed.slice(0, -CLAIMED_SUFFIX.length) : claimed;
}

/**
 * Takes a spool file for its replay (review F055): renamed (atomic) before it is read, so that the entries spooled
 * while it is replayed go to a new file of the same name, never into the one being replayed. Returns the claimed path,
 * or null when the file is gone or a claimed file of the same day is still there (replayed first).
 */
export function claimSpoolFile(file: string): string | null {
  const claimed = `${file}${CLAIMED_SUFFIX}`;
  if (existsSync(claimed)) return null;
  try {
    renameSync(file, claimed);
  } catch (err) {
    if ((err as { code?: string }).code === 'ENOENT') return null;
    throw err;
  }
  return claimed;
}

/**
 * Ends the replay of a claimed file: the lines still to replay (and any line another process appended to the claimed
 * file after it was read: `readLength`, the bytes read) go back in front of the spool file of the same day, which may
 * have received new entries meanwhile; then the claimed file is removed. Synchronous from the read of the spool file
 * to the rename: no entry of this process can come in between.
 */
export function releaseSpoolFile(claimed: string, remaining: readonly SpoolLine[], readLength: number): void {
  const target = spoolFileOf(claimed);
  let late: SpoolLine[] = [];
  let lateUnreadable: string[] = [];
  try {
    const now = readFileSync(claimed);
    if (now.length > readLength) {
      const parsed = parseSpoolText(now.subarray(readLength).toString('utf8'));
      late = parsed.lines;
      lateUnreadable = parsed.unreadableLines;
    }
  } catch { /* gone: nothing late */ }
  if (lateUnreadable.length) keepUnreadable(lateUnreadable);
  const back = [...remaining, ...late];
  if (back.length) {
    const head = back.map((l) => `${JSON.stringify(l)}\n`).join('');
    let tail = '';
    try { tail = readFileSync(target, 'utf8'); } catch { /* no new entry */ }
    if (tail && !tail.endsWith('\n')) tail += '\n';
    const tmp = `${target}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, head + tail);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, target);
  }
  unlinkSync(claimed);
}

export function rejectedFiles(dir = rejectedDir()): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => REJECTED_FILE_RE.test(f) || FILE_RE.test(f)).sort().map((f) => path.join(dir, f));
}

function parseSpoolText(text: string): { lines: SpoolLine[]; unreadableLines: string[] } {
  const lines: SpoolLine[] = [];
  const unreadableLines: string[] = [];
  for (const raw of text.split('\n')) {
    if (!raw.trim()) continue;
    try {
      const l = JSON.parse(raw) as SpoolLine;
      if (l && typeof l.body === 'string' && Number.isSafeInteger(Number(l.tenant))) lines.push({ ...l, tenant: Number(l.tenant) });
      else unreadableLines.push(raw);
    } catch {
      unreadableLines.push(raw);
    }
  }
  return { lines, unreadableLines };
}

/** The lines of a spool file; the lines that do not parse are returned as they were (unreadableLines), for the
 *  caller to keep aside (keepUnreadable); `length`: the bytes read. */
export function readSpoolFile(file: string): { lines: SpoolLine[]; unreadable: number; unreadableLines: string[]; length: number } {
  const buf = readFileSync(file);
  const { lines, unreadableLines } = parseSpoolText(buf.toString('utf8'));
  return { lines, unreadable: unreadableLines.length, unreadableLines, length: buf.length };
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
  const files = [...claimedSpoolFiles(), ...spoolFiles()];
  for (const f of files) {
    let lines: SpoolLine[] = [];
    try { ({ lines } = readSpoolFile(f)); } catch { /* removed meanwhile (a replay) */ }
    entries += lines.length;
    for (const l of lines) if (typeof l.spooledAt === 'string' && (oldest === null || l.spooledAt < oldest)) oldest = l.spooledAt;
  }
  let rejected = 0;
  const rdir = rejectedDir();
  const unreadableFiles = existsSync(rdir) ? readdirSync(rdir).filter((f) => UNREADABLE_FILE_RE.test(f)).map((f) => path.join(rdir, f)) : [];
  for (const f of [...rejectedFiles(), ...unreadableFiles]) {
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
