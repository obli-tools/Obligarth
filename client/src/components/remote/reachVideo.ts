/**
 * Video frame helpers of the ObliReach web viewer (pure — unit-tested in node).
 *
 * The viewer never trusts its own idea of the stream for long:
 *   - the canvas (and the space mouse x,y are sent in) follows the size of
 *     each DECODED frame. Agents in the field restart the capture on another
 *     monitor after `set_monitor` without sending a new `init`: the canvas
 *     kept the previous monitor's size, the picture was stretched and every
 *     click landed at the wrong place (mixed-size multi-monitor offset);
 *   - the decoder follows the codec of the frames actually RECEIVED. The same
 *     restart falls back to H.264 while the viewer may be on VP9 / AV1 /
 *     JPEG: H.264 fed to a VP9 decoder froze the picture. A frame of another
 *     codec reconfigures the decoder at its next keyframe.
 */
import { FRAME } from './reachProtocol';

export type ReachVideoCodec = 'h264' | 'h265' | 'vp9' | 'av1';

/** Codec of an encoded video frame type (byte 0), null for anything else (JPEG, audio, files). */
export function codecOfFrame(type: number): ReachVideoCodec | null {
  switch (type) {
    case FRAME.H264: return 'h264';
    case FRAME.H265: return 'h265';
    case FRAME.VP9: return 'vp9';
    case FRAME.AV1: return 'av1';
    default: return null;
  }
}

/** H.264 Annex B: IDR slice (5) or SPS / PPS (7 / 8) present. */
export function isH264Keyframe(data: Uint8Array): boolean {
  let i = 0;
  while (i < data.length - 4) {
    if (data[i] === 0 && data[i + 1] === 0) {
      let nalStart = -1;
      if (data[i + 2] === 1) {
        nalStart = i + 3;
        i += 4;
      } else if (data[i + 2] === 0 && data[i + 3] === 1) {
        nalStart = i + 4;
        i += 5;
      } else {
        i++;
        continue;
      }
      if (nalStart < data.length) {
        const nalType = data[nalStart] & 0x1f;
        if (nalType === 5 || nalType === 7 || nalType === 8) return true;
      }
    } else {
      i++;
    }
  }
  return false;
}

/** H.265: IRAP NAL types 16..21, or VPS / SPS / PPS (32 / 33 / 34). */
export function isH265Keyframe(u8: Uint8Array): boolean {
  for (let j = 0; j < u8.length - 5; j++) {
    if (u8[j] === 0 && u8[j + 1] === 0 && ((u8[j + 2] === 1) || (u8[j + 2] === 0 && u8[j + 3] === 1))) {
      const off = u8[j + 2] === 1 ? j + 3 : j + 4;
      if (off < u8.length) {
        const nalType = (u8[off] >> 1) & 0x3f;
        if ((nalType >= 16 && nalType <= 21) || nalType === 32 || nalType === 33 || nalType === 34) return true;
      }
    }
  }
  return false;
}

/** Keyframe test for an encoded frame of `codec` (payload without the type byte). */
export function isKeyframe(codec: ReachVideoCodec, u8: Uint8Array): boolean {
  switch (codec) {
    case 'h264': return isH264Keyframe(u8);
    case 'h265': return isH265Keyframe(u8);
    // AV1: OBU_SEQUENCE_HEADER / temporal delimiter first — simple heuristic.
    case 'av1': return u8.length > 0 && ((u8[0] >> 3) & 0x0f) <= 6;
    // VP9: bit 0 of the first byte = 0 on a keyframe.
    case 'vp9': return u8.length > 0 && (u8[0] & 0x01) === 0;
    default: return false;
  }
}

export interface ReachDecoderState {
  /** Codec the current decoder was configured for (null: none). */
  codec: string | null;
  /** VideoDecoder.state (null: no decoder). */
  state: string | null;
  /** The stream restarted (e.g. set_monitor on an old agent): start over at the next keyframe. */
  stale: boolean;
}

export type ReachDecoderAction = 'decode' | 'reconfigure' | 'drop';

/**
 * What to do with an encoded frame: decode it with the current decoder,
 * reconfigure a decoder for its codec first (only on a keyframe: a delta
 * frame cannot start a stream), or drop it while waiting for that keyframe.
 */
export function decoderActionFor(d: ReachDecoderState, frameCodec: ReachVideoCodec, isKey: boolean): ReachDecoderAction {
  if (!d.stale && d.codec === frameCodec && d.state === 'configured') return 'decode';
  return isKey ? 'reconfigure' : 'drop';
}

/**
 * Size to adopt for a decoded frame, or null when it matches `current`.
 * displayWidth/Height is the visible picture (codedWidth may be padded to a
 * multiple of 16, e.g. 1088 for 1080).
 */
export function frameSizeChange(
  current: { w: number; h: number },
  frame: { displayWidth?: number; displayHeight?: number; codedWidth?: number; codedHeight?: number },
): { w: number; h: number } | null {
  const w = frame.displayWidth || frame.codedWidth || 0;
  const h = frame.displayHeight || frame.codedHeight || 0;
  if (!(w > 0 && h > 0)) return null;
  if (w === current.w && h === current.h) return null;
  return { w, h };
}
