import { FRAME } from './reachProtocol';

// =============================================================================
// The picture of the remote viewer (P0-15 §5.1): H.264 Annex B decoded by WebCodecs (codec avc1 read from the SPS the
// agent puts before each IDR, optimizeForLatency), else JPEG decoded by createImageBitmap. Drawn on one canvas whose size
// follows each decoded picture: the coordinates of the inputs are pixels of that picture (the agent brings them back to
// its screen). Recopied in spirit from Obliance's reachVideo.ts (the canvas follows the decoded frame, a frame of another
// codec waits for its key frame), reduced to the two codecs of a phone. A delta frame never starts a decoder; a decoder
// that falls behind drops its deltas until the next key frame, asked by key_request.
// =============================================================================

/** H.264 Annex B: the NAL units of an access unit (start code 3 or 4 bytes), as [start, end) offsets of their payload. */
export function h264Units(au: Uint8Array): Array<[number, number]> {
  const starts: number[] = [];
  for (let i = 0; i + 2 < au.length; i++) {
    if (au[i] === 0 && au[i + 1] === 0 && au[i + 2] === 1) { starts.push(i + 3); i += 2; }
  }
  return starts.map((s, k) => {
    let end = k + 1 < starts.length ? starts[k + 1] - 3 : au.length;
    // A 4-byte start code leaves a zero before the next one.
    if (k + 1 < starts.length && end > s && au[end - 1] === 0) end--;
    return [s, end] as [number, number];
  });
}

/** An IDR slice (5) or a SPS (7) in the access unit: a key frame. */
export function isH264Key(au: Uint8Array): boolean {
  for (const [s, e] of h264Units(au)) {
    if (s >= e) continue;
    const type = au[s] & 0x1f;
    if (type === 5 || type === 7) return true;
  }
  return false;
}

/** The WebCodecs codec string of the SPS of an access unit (avc1.PPCCLL: profile, constraints, level), or null. */
export function h264CodecString(au: Uint8Array): string | null {
  for (const [s, e] of h264Units(au)) {
    if (e - s < 4 || (au[s] & 0x1f) !== 7) continue;
    const hex = (b: number) => b.toString(16).padStart(2, '0');
    return `avc1.${hex(au[s + 1])}${hex(au[s + 2])}${hex(au[s + 3])}`;
  }
  return null;
}

/** WebCodecs present (a secure context of a recent browser). */
export const webCodecsAvailable = (): boolean => typeof window !== 'undefined' && typeof window.VideoDecoder === 'function'
  && typeof window.EncodedVideoChunk === 'function';

export interface VideoSinkEvents {
  /** The decoded picture changed its size (the canvas followed). */
  onSize: (w: number, h: number) => void;
  /** A key frame is needed (a decoder started, fell behind or failed). */
  onKeyRequest: () => void;
  /** H.264 cannot be decoded here (no WebCodecs, a refused configuration): ask the agent for JPEG. */
  onH264Unsupported: () => void;
  /** A picture was drawn. */
  onFrame: () => void;
}

/** Deltas waiting in the decoder beyond which they are dropped until the next key frame (latency before smoothness). */
const MAX_DECODE_QUEUE = 8;

/** The decoder and the canvas of one viewer. */
export class RemoteVideoSink {
  private decoder: VideoDecoder | null = null;
  private codec: string | null = null;
  private waitKey = true;
  private ts = 0;
  private jpegBusy = false;
  private jpegNext: Uint8Array | null = null;
  private closed = false;
  private h264Refused = false;
  private w = 0;
  private h = 0;

  constructor(private readonly canvas: HTMLCanvasElement, private readonly ev: VideoSinkEvents) {}

  /** A binary frame of the tunnel (byte 0 its kind). */
  push(buf: ArrayBuffer): void {
    if (this.closed || buf.byteLength < 2) return;
    const all = new Uint8Array(buf);
    const data = all.subarray(1);
    if (all[0] === FRAME.h264) this.pushH264(data);
    else if (all[0] === FRAME.jpeg) this.pushJpeg(data);
  }

  /** Start again at the next key frame (a new init: rotation, resolution, codec). */
  reset(): void {
    this.waitKey = true;
    if (this.decoder && this.decoder.state !== 'closed') {
      try { this.decoder.reset(); } catch { /* closed */ }
    }
    this.codec = null;
  }

  close(): void {
    this.closed = true;
    if (this.decoder && this.decoder.state !== 'closed') {
      try { this.decoder.close(); } catch { /* closed */ }
    }
    this.decoder = null;
  }

  private draw(src: CanvasImageSource, w: number, h: number): void {
    if (!(w > 0 && h > 0)) return;
    if (w !== this.w || h !== this.h) {
      this.w = w; this.h = h;
      this.canvas.width = w;
      this.canvas.height = h;
      this.ev.onSize(w, h);
    }
    const ctx = this.canvas.getContext('2d');
    if (ctx) ctx.drawImage(src, 0, 0, w, h);
    this.ev.onFrame();
  }

  private ensureDecoder(): VideoDecoder | null {
    if (this.decoder && this.decoder.state !== 'closed') return this.decoder;
    try {
      this.decoder = new VideoDecoder({
        output: (frame) => {
          try {
            if (!this.closed) this.draw(frame, frame.displayWidth || frame.codedWidth, frame.displayHeight || frame.codedHeight);
          } finally {
            frame.close();
          }
        },
        error: () => {
          // A broken stream: a new decoder at the next key frame.
          this.decoder = null;
          this.codec = null;
          this.waitKey = true;
          if (!this.closed) this.ev.onKeyRequest();
        },
      });
    } catch {
      this.decoder = null;
    }
    return this.decoder;
  }

  private pushH264(au: Uint8Array): void {
    if (this.h264Refused) return;
    if (!webCodecsAvailable()) { this.h264Refused = true; this.ev.onH264Unsupported(); return; }
    const key = isH264Key(au);
    if (this.waitKey && !key) return;
    const d = this.ensureDecoder();
    if (!d) { this.h264Refused = true; this.ev.onH264Unsupported(); return; }
    if (key) {
      const codec = h264CodecString(au) ?? this.codec ?? 'avc1.42e01f';
      if (codec !== this.codec || d.state !== 'configured') {
        try {
          // Annex B without a description: the SPS and PPS travel in line before each IDR.
          d.configure({ codec, optimizeForLatency: true, hardwareAcceleration: 'no-preference' });
          this.codec = codec;
        } catch {
          this.h264Refused = true;
          this.ev.onH264Unsupported();
          return;
        }
      }
      this.waitKey = false;
    } else if (d.decodeQueueSize > MAX_DECODE_QUEUE) {
      // Behind: drop the deltas until a fresh key frame.
      this.waitKey = true;
      this.ev.onKeyRequest();
      return;
    }
    if (d.state !== 'configured') return;
    try {
      // Bytes copied: the chunk outlives the message buffer.
      d.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: this.ts, data: au.slice() }));
      this.ts += 33_333;
    } catch {
      this.waitKey = true;
      this.ev.onKeyRequest();
    }
  }

  /** One image at a time; while one decodes, only the latest that arrived waits (the others are stale). */
  private pushJpeg(data: Uint8Array): void {
    if (this.jpegBusy) { this.jpegNext = data.slice(); return; }
    this.jpegBusy = true;
    const blob = new Blob([data.slice()], { type: 'image/jpeg' });
    createImageBitmap(blob).then((bmp) => {
      if (!this.closed) this.draw(bmp, bmp.width, bmp.height);
      bmp.close();
    }).catch(() => { /* a broken image: the next one */ }).finally(() => {
      this.jpegBusy = false;
      const next = this.jpegNext;
      this.jpegNext = null;
      if (next && !this.closed) this.pushJpeg(next);
    });
  }
}
