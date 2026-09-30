/**
 * File transfers over the ObliReach stream (contract §1.6).
 *
 * Upload (operator → session user's Downloads):
 *   file_begin → file_accept{chunk,window} | file_error
 *   0x20 data frames [0x20][tid u32 LE][seq u32 LE][data], at most `window`
 *   unacknowledged (file_progress{seq} = everything up to seq received)
 *   file_end{sha256} → file_done{ok,path} | file_error
 * Download (a file the session user put on the clipboard):
 *   file_get{source:'clipboard',idx} → file_offer{name,size,chunk,window}
 *   0x21 data frames, acknowledged with file_progress{seq}
 *   file_done{dir:'down',sha256} — checked here before the file is saved.
 * Either side may send file_cancel. One transfer per direction at a time;
 * further uploads wait in a queue.
 */
import { Sha256 } from '@/utils/sha256';
import { FRAME } from './reachProtocol';

export type TransferDir = 'up' | 'down';
export type TransferStatus = 'queued' | 'waiting' | 'active' | 'verifying' | 'done' | 'error' | 'cancelled';

export interface TransferItem {
  tid: number;
  dir: TransferDir;
  name: string;
  size: number;
  /** Bytes acknowledged (up) / received (down). */
  bytes: number;
  status: TransferStatus;
  /** file_error code or local reason. */
  error?: string;
  errorMessage?: string;
  /** Where the agent wrote an upload. */
  path?: string;
}

export const DEFAULT_CHUNK = 262_144;
export const DEFAULT_WINDOW = 8;
export const DEFAULT_MAX_FILE = 2 * 1024 * 1024 * 1024;
const ACCEPT_TIMEOUT_MS = 30_000;
const HEADER = 9;

/** `[type][tid u32 LE][seq u32 LE][data]`. */
export function buildFileFrame(type: number, tid: number, seq: number, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(HEADER + data.length);
  const dv = new DataView(out.buffer);
  out[0] = type;
  dv.setUint32(1, tid >>> 0, true);
  dv.setUint32(5, seq >>> 0, true);
  out.set(data, HEADER);
  return out;
}

export function parseFileFrame(buf: ArrayBuffer): { type: number; tid: number; seq: number; data: Uint8Array } | null {
  if (buf.byteLength < HEADER) return null;
  const dv = new DataView(buf);
  return { type: dv.getUint8(0), tid: dv.getUint32(1, true), seq: dv.getUint32(5, true), data: new Uint8Array(buf, HEADER) };
}

interface Upload {
  item: TransferItem;
  file: Blob;
  chunk: number;
  window: number;
  offset: number;
  nextSeq: number;
  /** Highest acknowledged seq (-1 = none). */
  acked: number;
  hasher: Sha256;
  pumping: boolean;
  ended: boolean;
  acceptTimer: ReturnType<typeof setTimeout> | null;
}

interface Download {
  item: TransferItem;
  parts: Uint8Array[];
  hasher: Sha256;
  expectedSeq: number;
}

export interface ReachFileTransfersOptions {
  sendJson: (msg: object) => void;
  /** Sends a binary frame; false when the socket is gone. */
  sendBinary: (frame: Uint8Array) => boolean;
  onChange: (items: TransferItem[]) => void;
  /** Saves a finished download (returns false when the browser refused). */
  save: (blob: Blob, name: string) => Promise<boolean>;
}

export class ReachFileTransfers {
  private items: TransferItem[] = [];
  private queue: Array<{ item: TransferItem; file: Blob }> = [];
  private upload: Upload | null = null;
  private download: Download | null = null;
  private nextTid = (Math.floor(Math.random() * 0x7fff) << 8) + 1;
  private limits = { chunk: DEFAULT_CHUNK, window: DEFAULT_WINDOW, maxFile: DEFAULT_MAX_FILE };

  constructor(private readonly o: ReachFileTransfersOptions) {}

  /** Limits announced by init.files. */
  setLimits(l: { chunk?: number; window?: number; maxFile?: number } | undefined): void {
    if (!l) return;
    if (l.chunk && l.chunk > 0) this.limits.chunk = Math.min(l.chunk, 4 * 1024 * 1024);
    if (l.window && l.window > 0) this.limits.window = Math.min(l.window, 64);
    if (l.maxFile && l.maxFile > 0) this.limits.maxFile = l.maxFile;
  }

  list(): TransferItem[] { return this.items; }

  busyDownload(): boolean { return !!this.download; }

  /** Drop finished entries from the tray. */
  clearFinished(): void {
    this.items = this.items.filter((i) => !['done', 'error', 'cancelled'].includes(i.status));
    this.emit();
  }

  private emit(): void { this.o.onChange([...this.items.map((i) => ({ ...i }))]); }

  private tid(): number {
    this.nextTid = (this.nextTid + 1) >>> 0 || 1;
    return this.nextTid;
  }

  // ── Upload ────────────────────────────────────────────────────────────────

  /** Queue files for upload (sequentially). Returns the items created. */
  enqueueUploads(files: ArrayLike<File | (Blob & { name?: string })>): TransferItem[] {
    const created: TransferItem[] = [];
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const item: TransferItem = { tid: this.tid(), dir: 'up', name: (f as File).name || 'file', size: f.size, bytes: 0, status: 'queued' };
      created.push(item);
      this.items.push(item);
      if (f.size > this.limits.maxFile) {
        item.status = 'error';
        item.error = 'too_large';
        continue;
      }
      this.queue.push({ item, file: f });
    }
    this.emit();
    this.startNextUpload();
    return created;
  }

  private startNextUpload(): void {
    if (this.upload) return;
    const next = this.queue.shift();
    if (!next) return;
    const { item, file } = next;
    item.status = 'waiting';
    this.upload = {
      item, file, chunk: this.limits.chunk, window: this.limits.window,
      offset: 0, nextSeq: 0, acked: -1, hasher: new Sha256(), pumping: false, ended: false,
      acceptTimer: setTimeout(() => this.failUpload('timeout'), ACCEPT_TIMEOUT_MS),
    };
    this.o.sendJson({ type: 'file_begin', tid: item.tid, name: item.name, size: item.size, mime: (file as File).type || '', dest: 'downloads' });
    this.emit();
  }

  private finishUpload(status: TransferStatus, patch: Partial<TransferItem> = {}): void {
    const u = this.upload;
    if (!u) return;
    if (u.acceptTimer) clearTimeout(u.acceptTimer);
    Object.assign(u.item, patch, { status });
    this.upload = null;
    this.emit();
    this.startNextUpload();
  }

  private failUpload(code: string, message?: string): void {
    this.finishUpload('error', { error: code, errorMessage: message });
  }

  private async pump(): Promise<void> {
    const u = this.upload;
    if (!u || u.pumping || u.ended || u.item.status !== 'active') return;
    u.pumping = true;
    try {
      while (this.upload === u && u.item.status === 'active' && u.offset < u.item.size && u.nextSeq - (u.acked + 1) < u.window) {
        const end = Math.min(u.offset + u.chunk, u.item.size);
        const data = new Uint8Array(await u.file.slice(u.offset, end).arrayBuffer());
        if (this.upload !== u || u.item.status !== 'active') return;
        u.hasher.update(data);
        if (!this.o.sendBinary(buildFileFrame(FRAME.FILE_UP, u.item.tid, u.nextSeq, data))) {
          this.failUpload('disconnected');
          return;
        }
        u.nextSeq++;
        u.offset = end;
      }
      if (this.upload === u && u.item.status === 'active' && u.offset >= u.item.size && !u.ended) {
        u.ended = true;
        u.item.status = 'verifying';
        this.o.sendJson({ type: 'file_end', tid: u.item.tid, sha256: u.hasher.hex() });
        this.emit();
      }
    } catch (err) {
      this.failUpload('read_failed', String((err as Error)?.message ?? err));
    } finally {
      u.pumping = false;
    }
  }

  // ── Download ──────────────────────────────────────────────────────────────

  /** Ask for a file of the remote clipboard. False when a download is already running. */
  requestDownload(idx: number, name: string, size: number): boolean {
    if (this.download) return false;
    const item: TransferItem = { tid: this.tid(), dir: 'down', name, size, bytes: 0, status: 'waiting' };
    this.items.push(item);
    this.download = { item, parts: [], hasher: new Sha256(), expectedSeq: 0 };
    this.o.sendJson({ type: 'file_get', tid: item.tid, source: 'clipboard', idx });
    this.emit();
    return true;
  }

  private finishDownload(status: TransferStatus, patch: Partial<TransferItem> = {}): void {
    const d = this.download;
    if (!d) return;
    Object.assign(d.item, patch, { status });
    d.parts = [];
    this.download = null;
    this.emit();
  }

  // ── Common ────────────────────────────────────────────────────────────────

  cancel(tid: number): void {
    if (this.upload?.item.tid === tid) {
      this.o.sendJson({ type: 'file_cancel', tid });
      this.finishUpload('cancelled');
      return;
    }
    if (this.download?.item.tid === tid) {
      this.o.sendJson({ type: 'file_cancel', tid });
      this.finishDownload('cancelled');
      return;
    }
    const q = this.queue.findIndex((x) => x.item.tid === tid);
    if (q >= 0) {
      this.queue[q].item.status = 'cancelled';
      this.queue.splice(q, 1);
      this.emit();
    }
  }

  /** The stream is gone (close / reconnect / view respawn): everything in flight fails. */
  abortAll(code = 'disconnected'): void {
    if (this.upload) {
      if (this.upload.acceptTimer) clearTimeout(this.upload.acceptTimer);
      Object.assign(this.upload.item, { status: 'error', error: code });
      this.upload = null;
    }
    for (const q of this.queue) Object.assign(q.item, { status: 'error', error: code });
    this.queue = [];
    if (this.download) Object.assign(this.download.item, { status: 'error', error: code });
    this.download = null;
    this.emit();
  }

  /** A JSON control message; true when it was a file_* message. */
  handleMessage(msg: { type?: string; [k: string]: unknown }): boolean {
    const type = msg.type;
    if (typeof type !== 'string' || !type.startsWith('file_')) return false;
    const tid = typeof msg.tid === 'number' ? msg.tid : -1;
    const u = this.upload && this.upload.item.tid === tid ? this.upload : null;
    const d = this.download && this.download.item.tid === tid ? this.download : null;
    switch (type) {
      case 'file_accept': {
        if (!u || u.item.status !== 'waiting') return true;
        if (u.acceptTimer) { clearTimeout(u.acceptTimer); u.acceptTimer = null; }
        if (typeof msg.chunk === 'number' && msg.chunk > 0) u.chunk = Math.min(msg.chunk, 4 * 1024 * 1024);
        if (typeof msg.window === 'number' && msg.window > 0) u.window = Math.min(msg.window, 64);
        if (typeof msg.path === 'string') u.item.path = msg.path;
        u.item.status = 'active';
        this.emit();
        void this.pump();
        return true;
      }
      case 'file_progress': {
        if (u && typeof msg.seq === 'number') {
          u.acked = Math.max(u.acked, msg.seq);
          u.item.bytes = Math.min(u.item.size, (u.acked + 1) * u.chunk);
          this.emit();
          void this.pump();
        }
        return true;
      }
      case 'file_offer': {
        if (!d) return true;
        if (typeof msg.name === 'string' && msg.name) d.item.name = msg.name;
        if (typeof msg.size === 'number') d.item.size = msg.size;
        d.item.status = 'active';
        this.emit();
        return true;
      }
      case 'file_done': {
        if (u) {
          if (msg.ok === false) this.failUpload(typeof msg.code === 'string' ? msg.code : 'failed', typeof msg.message === 'string' ? msg.message : undefined);
          else this.finishUpload('done', { bytes: u.item.size, path: typeof msg.path === 'string' ? msg.path : u.item.path });
          return true;
        }
        if (d) {
          if (msg.ok === false) { this.finishDownload('error', { error: typeof msg.code === 'string' ? msg.code : 'failed' }); return true; }
          const expected = typeof msg.sha256 === 'string' ? msg.sha256.toLowerCase() : '';
          const got = d.hasher.hex();
          if (d.item.bytes !== d.item.size || (expected && expected !== got)) {
            this.finishDownload('error', { error: 'hash_mismatch' });
            return true;
          }
          const blob = new Blob(d.parts as BlobPart[]);
          const name = d.item.name;
          d.item.status = 'verifying';
          this.emit();
          this.o.save(blob, name)
            .then((ok) => (ok ? this.finishDownload('done') : this.finishDownload('error', { error: 'save_failed' })))
            .catch(() => this.finishDownload('error', { error: 'save_failed' }));
        }
        return true;
      }
      case 'file_error': {
        const code = typeof msg.code === 'string' ? msg.code : 'failed';
        const message = typeof msg.message === 'string' ? msg.message : undefined;
        if (u) this.failUpload(code, message);
        else if (d) this.finishDownload('error', { error: code, errorMessage: message });
        return true;
      }
      case 'file_cancel': {
        if (u) this.finishUpload('cancelled');
        else if (d) this.finishDownload('cancelled');
        return true;
      }
      default:
        return true;
    }
  }

  /** A 0x21 frame; true when consumed. */
  handleBinary(buf: ArrayBuffer): boolean {
    const f = parseFileFrame(buf);
    if (!f || f.type !== FRAME.FILE_DOWN) return false;
    const d = this.download;
    if (!d || d.item.tid !== f.tid || d.item.status !== 'active') return true;
    if (f.seq !== d.expectedSeq) {
      this.o.sendJson({ type: 'file_cancel', tid: f.tid });
      this.finishDownload('error', { error: 'out_of_order' });
      return true;
    }
    d.expectedSeq++;
    const copy = f.data.slice();
    d.parts.push(copy);
    d.hasher.update(copy);
    d.item.bytes += copy.length;
    if (d.item.bytes > d.item.size && d.item.size > 0) {
      this.o.sendJson({ type: 'file_cancel', tid: f.tid });
      this.finishDownload('error', { error: 'too_large' });
      return true;
    }
    this.o.sendJson({ type: 'file_progress', tid: f.tid, seq: f.seq });
    this.emit();
    return true;
  }
}
