/**
 * Remote audio playback for the ObliReach viewer (contract §1.7 / plan §2.4).
 *
 * The old player started every 50 ms chunk "now" (`source.start()`): network
 * jitter made chunks overlap or leave gaps — the crackle the owner heard.
 * Here chunks are queued back to back on a playhead:
 *
 *   underrun (playhead < now)  → t = now + 80 ms (everything queued has played)
 *   backlog > 300 ms           → the INCOMING chunk is dropped
 *   otherwise                  → t = max(playhead, now + 5 ms)
 *   source.start(t); playhead = t + duration
 *
 * A backlog (a burst after a network stall, e.g. behind a large keyframe)
 * used to re-anchor the new chunk at now + 80 ms while the chunks already
 * queued kept playing: ~250 ms of audio played on top of itself about once a
 * second (the "crunched" sound). Dropping the incoming chunk never overlaps,
 * loses less than flushing the queue, and keeps up to ~300 ms queued — a
 * cushion that absorbs the next stall instead of underrunning again; latency
 * stays bounded. Every started source is tracked: reset() (init, session
 * change), the audio toggle and close() stop them.
 *
 * The AudioContext is created only after `init` (at init.audioRate) and
 * recreated when the rate changes; chunks are dropped while the context is
 * not running (autoplay policy). Plays legacy 0x06 (PCM s16le mono) and 0x07
 * (header + PCM s16le, 1 or 2 channels).
 */

export const AUDIO_LEAD_S = 0.005;
export const AUDIO_RESET_LEAD_S = 0.08;
export const AUDIO_MAX_BACKLOG_S = 0.3;

/**
 * Where the next chunk starts, and the new playhead. `reset`: re-anchored
 * after an underrun. `drop`: too much audio already queued — the chunk is
 * not played (playhead unchanged).
 */
export function scheduleChunk(playhead: number, now: number, duration: number): { start: number; playhead: number; reset: boolean; drop: boolean } {
  if (playhead < now) {
    const start = now + AUDIO_RESET_LEAD_S;
    return { start, playhead: start + duration, reset: true, drop: false };
  }
  if (playhead - now > AUDIO_MAX_BACKLOG_S) return { start: playhead, playhead, reset: false, drop: true };
  const start = Math.max(playhead, now + AUDIO_LEAD_S);
  return { start, playhead: start + duration, reset: false, drop: false };
}

export interface PcmChunk {
  rate: number;
  channels: number;
  /** One Float32Array per channel, same length. */
  data: Float32Array[];
}

/** Legacy 0x06 frame: [0x06][PCM s16le mono]. */
export function parseAudioV1(buf: ArrayBuffer, rate: number): PcmChunk | null {
  const n = Math.floor((buf.byteLength - 1) / 2);
  if (n <= 0 || rate <= 0) return null;
  const dv = new DataView(buf, 1, n * 2);
  const ch = new Float32Array(n);
  for (let i = 0; i < n; i++) ch[i] = dv.getInt16(i * 2, true) / 32768;
  return { rate, channels: 1, data: [ch] };
}

export interface AudioV2Header {
  version: number;
  codec: number;
  channels: number;
  rate: number;
  seq: number;
  /** Sample position (u64, as a JS number — exact up to 2^53). */
  pos: number;
}

export const AUDIO_V2_HEADER = 20;

/** 0x07 header: [0x07][ver][codec][channels][rate u32 LE][seq u32 LE][pos u64 LE]. */
export function parseAudioV2Header(buf: ArrayBuffer): AudioV2Header | null {
  if (buf.byteLength < AUDIO_V2_HEADER) return null;
  const dv = new DataView(buf);
  if (dv.getUint8(0) !== 0x07) return null;
  const lo = dv.getUint32(12, true);
  const hi = dv.getUint32(16, true);
  return {
    version: dv.getUint8(1),
    codec: dv.getUint8(2),
    channels: dv.getUint8(3),
    rate: dv.getUint32(4, true),
    seq: dv.getUint32(8, true),
    pos: hi * 4294967296 + lo,
  };
}

/** 0x07 frame → PCM (codec 0 = s16le interleaved; other codecs unsupported → null). */
export function parseAudioV2(buf: ArrayBuffer): PcmChunk | null {
  const h = parseAudioV2Header(buf);
  if (!h || h.version !== 1 || h.codec !== 0) return null;
  const channels = h.channels === 2 ? 2 : h.channels === 1 ? 1 : 0;
  if (!channels || h.rate <= 0) return null;
  const frames = Math.floor((buf.byteLength - AUDIO_V2_HEADER) / (2 * channels));
  if (frames <= 0) return null;
  const dv = new DataView(buf, AUDIO_V2_HEADER, frames * 2 * channels);
  const data = Array.from({ length: channels }, () => new Float32Array(frames));
  for (let i = 0; i < frames; i++) {
    for (let c = 0; c < channels; c++) data[c][i] = dv.getInt16((i * channels + c) * 2, true) / 32768;
  }
  return { rate: h.rate, channels, data };
}

type Ctx = Pick<AudioContext, 'currentTime' | 'state' | 'destination' | 'createBuffer' | 'createBufferSource' | 'resume' | 'close'> & { sampleRate: number };

/** A started chunk: its source and when it plays (context time). */
interface ScheduledChunk {
  src: { stop: (when?: number) => void };
  start: number;
  end: number;
}

export interface ReachAudioPlayerOptions {
  /** AudioContext factory (tests inject a fake). */
  createContext?: (rate: number) => Ctx | null;
}

export class ReachAudioPlayer {
  private ctx: Ctx | null = null;
  private rate = 0;
  private playhead = 0;
  private enabled = false;
  /** Sources started and not known to be over (oldest first). */
  private queued: ScheduledChunk[] = [];
  private readonly create: (rate: number) => Ctx | null;
  /** Stats (debug / tests). */
  played = 0;
  dropped = 0;
  resets = 0;
  /** Chunks dropped because too much audio was queued (burst after a stall). */
  backlogDrops = 0;
  /** Queued sources stopped by reset / toggle / close. */
  trimmed = 0;

  constructor(opts: ReachAudioPlayerOptions = {}) {
    this.create = opts.createContext ?? ((rate) => {
      try { return new AudioContext({ sampleRate: rate }) as unknown as Ctx; } catch { return null; }
    });
  }

  /** Stream rate announced by init (0 / unknown keeps the current one). */
  setRate(rate: number): void {
    if (!rate || rate === this.rate) return;
    this.rate = rate;
    if (this.ctx && this.ctx.sampleRate !== rate) this.closeContext();
  }

  isEnabled(): boolean { return this.enabled; }

  /** Toggle playback; resets the queue. Call it from a user gesture to create / resume the context. */
  setEnabled(on: boolean): void {
    this.enabled = on;
    this.stopAll();
    if (on) this.ensureContext();
  }

  /** Create / resume the context (user gesture: autoplay policy). */
  ensureContext(): void {
    if (!this.enabled || !this.rate) return;
    if (!this.ctx) this.ctx = this.create(this.rate);
    if (this.ctx && this.ctx.state === 'suspended') this.ctx.resume().catch(() => { /* needs a gesture */ });
  }

  /** Drop the queue (reconnect, init, session change): queued chunks are stopped. */
  reset(): void { this.stopAll(); }

  /** Stop every tracked source and forget the playhead. */
  private stopAll(): void {
    for (const q of this.queued) {
      try { q.src.stop(); } catch { /* never started / already stopped */ }
    }
    this.trimmed += this.queued.length;
    this.queued = [];
    this.playhead = 0;
  }

  /** Close the context (viewer closed). */
  close(): void {
    this.closeContext();
    this.enabled = false;
  }

  private closeContext(): void {
    const c = this.ctx;
    this.stopAll();
    this.ctx = null;
    if (c) { try { void c.close(); } catch { /* already closed */ } }
  }

  /** A binary audio frame (0x06 or 0x07). Returns true when scheduled. */
  handleFrame(buf: ArrayBuffer): boolean {
    if (!this.enabled) return false;
    const type = new Uint8Array(buf, 0, 1)[0];
    const chunk = type === 0x07 ? parseAudioV2(buf) : type === 0x06 ? parseAudioV1(buf, this.rate || 48000) : null;
    if (!chunk) { this.dropped++; return false; }
    return this.play(chunk);
  }

  play(chunk: PcmChunk): boolean {
    if (!this.enabled) return false;
    if (chunk.rate !== this.rate) this.setRate(chunk.rate);
    if (!this.ctx) this.ctx = this.create(this.rate || chunk.rate);
    const ctx = this.ctx;
    if (!ctx || ctx.state !== 'running') {
      // Autoplay policy / suspended: dropping keeps the queue from piling up.
      this.dropped++;
      this.stopAll();
      return false;
    }
    const frames = chunk.data[0].length;
    const duration = frames / chunk.rate;
    const now = ctx.currentTime;
    // Chunks that finished playing are no longer tracked.
    if (this.queued.length) this.queued = this.queued.filter((q) => q.end > now);
    const s = scheduleChunk(this.playhead, now, duration);
    if (s.drop) {
      // Burst: never on top of what is queued (see the header).
      this.dropped++;
      this.backlogDrops++;
      return false;
    }
    let start = s.start;
    if (s.reset) {
      this.resets++;
      // Never on top of a chunk still playing (none normally: an underrun
      // means everything queued has played).
      for (const q of this.queued) if (q.end > start) start = q.end;
    }
    const buffer = ctx.createBuffer(chunk.channels, frames, chunk.rate);
    for (let c = 0; c < chunk.channels; c++) buffer.getChannelData(c).set(chunk.data[c]);
    const src = ctx.createBufferSource();
    src.buffer = buffer;
    src.connect(ctx.destination);
    this.playhead = start + duration;
    src.start(start);
    this.queued.push({ src, start, end: start + duration });
    this.played++;
    return true;
  }
}
