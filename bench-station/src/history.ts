import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { openJson, sealJson, type Protector } from './dpapi';

/**
 * Obligarth bench station — the local history (lot BANC §5.7): one line per provisioning that ENDED on this PC, kept in
 * %LOCALAPPDATA%\Obligarth\bench-history.json, 1000 lines, protected by DPAPI (CurrentUser).
 * What is kept: time, station, tenant and group (names), the serial CUT to its last four characters, model, Android,
 * role aimed at and obtained, outcome, error code, provisioningId, deviceUuid. Never a token, a configuration, an
 * account. Best effort: a history that cannot be read or written never stops a provisioning.
 */
export interface HistoryEntry {
  at: string;
  station: string | null;
  tenant: string | null;
  group: string | null;
  serial: string | null;
  model: string | null;
  android: string | null;
  roleTarget: string | null;
  roleObtained: string | null;
  outcome: 'completed' | 'failed' | 'abandoned';
  errorCode: string | null;
  provisioningId: string | null;
  deviceUuid: string | null;
}

export const HISTORY_KEEP = 1000;

const SERIAL_SAFE = /^…[A-Za-z0-9._:-]{1,4}$/;

export class HistoryStore {
  private chain: Promise<void> = Promise.resolve();

  constructor(readonly file: string, private readonly protector: Protector) {}

  async read(): Promise<HistoryEntry[]> {
    try {
      const v = await openJson(this.protector, readFileSync(this.file, 'utf8'));
      return Array.isArray(v) ? (v as HistoryEntry[]) : [];
    } catch {
      return [];
    }
  }

  /** Appends one entry (serialised: two cards finishing together do not lose one). */
  append(entry: HistoryEntry): Promise<void> {
    const safe: HistoryEntry = { ...entry, serial: entry.serial && SERIAL_SAFE.test(entry.serial) ? entry.serial : null };
    this.chain = this.chain.then(async () => {
      try {
        const all = [...(await this.read()), safe].slice(-HISTORY_KEEP);
        mkdirSync(dirname(this.file), { recursive: true });
        const tmp = `${this.file}.part`;
        writeFileSync(tmp, await sealJson(this.protector, all), 'utf8');
        renameSync(tmp, this.file);
      } catch { /* best effort */ }
    });
    return this.chain;
  }

  /** Today's entries (the PC's local date), newest first. */
  async today(now: Date = new Date()): Promise<HistoryEntry[]> {
    const day = now.toDateString();
    return (await this.read()).filter((e) => new Date(e.at).toDateString() === day).reverse();
  }
}
