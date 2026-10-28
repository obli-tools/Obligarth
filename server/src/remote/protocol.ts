import {
  REMOTE_AGENT_TO_VIEWER_TYPES, REMOTE_FRAME_TYPES, REMOTE_INPUT_TYPES, REMOTE_KEY_CODES, REMOTE_LIMITS, REMOTE_NAV_ACTIONS,
  REMOTE_VIEWER_TO_AGENT_TYPES, type RemoteKeyCode, type RemoteMode, type RemoteNavAction, type RemoteViewerToAgentMessage,
} from '@obligarth/shared';

// =============================================================================
// The messages of the remote stream as the relay filters them (P0-15 §5.2, §5.3, T5), without a database: types bound
// to their direction (a type is admitted only in the direction of §5.2, anything else dropped and counted), the bounds
// of each field (those of the agent's parser, core/RemoteProtocol.kt RemoteMessages.parse), the inputs dropped while the
// effective mode is view, the key frames of the video (the dropped video waits for the next one). The relay forwards
// the agent's texts as they came (once their type and size hold) and the viewer's messages rewritten with their known
// fields only. The unit tests load this file alone.
// =============================================================================

export type DropReason =
  | 'too_large' | 'malformed' | 'direction' | 'unknown_type' | 'out_of_bounds' | 'view_mode' | 'input_rate' | 'binary_from_viewer'
  | 'unknown_frame' | 'no_viewer' | 'no_agent' | 'backpressure';

const AGENT_TYPES = new Set<string>(REMOTE_AGENT_TO_VIEWER_TYPES);
const VIEWER_TYPES = new Set<string>(REMOTE_VIEWER_TO_AGENT_TYPES);
const INPUT_TYPES = new Set<string>(REMOTE_INPUT_TYPES);
/** Every type of §5.2 in any direction: a known type in the wrong direction is 'direction', not 'unknown_type'. */
const KNOWN_TYPES = new Set<string>([...REMOTE_AGENT_TO_VIEWER_TYPES, ...REMOTE_VIEWER_TO_AGENT_TYPES, 'hello', 'mode', 'session_end',
  // The dialect of before §0.1 (consent of the user): never admitted, in any direction.
  'consent_state', 'escalate', 'escalation', 'user_ended']);

const CODECS = new Set(['h264', 'jpeg']);
const QUALITIES = new Set([480, 720, 1080]);
const TOUCH_ACTIONS = new Set(['down', 'move', 'up', 'cancel']);
const NAV_ACTIONS = new Set<string>(REMOTE_NAV_ACTIONS);
const KEY_CODES = new Set<string>(REMOTE_KEY_CODES);
/** Coordinates are image pixels; far beyond any screen (the agent's bound). */
const MAX_COORDINATE = 16_384;
const MAX_KBPS = 100_000;
/** The agent's bound of a pointer id (it holds REMOTE_LIMITS.maxPointers pointers at once). */
const MAX_POINTER_ID = 255;

type Json = Record<string, unknown>;

function parseObject(text: string): Json | null {
  try {
    const v = JSON.parse(text) as unknown;
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Json : null;
  } catch {
    return null;
  }
}

const finite = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const int = (v: unknown, min: number, max: number): v is number => finite(v) && Number.isInteger(v) && v >= min && v <= max;
const coordinate = (v: unknown): v is number => finite(v) && v >= 0 && v <= MAX_COORDINATE;
const delta = (v: unknown): v is number => finite(v) && Math.abs(v) <= MAX_COORDINATE;
const generation = (v: unknown): v is number => int(v, 0, Number.MAX_SAFE_INTEGER);

export type AgentText = { ok: true; type: string } | { ok: false; reason: DropReason };

/** A text message of the agent (opened from its frame): its size, a JSON object, a type of agent → viewer (§5.2). */
export function checkAgentText(plain: Buffer): AgentText {
  if (plain.length > REMOTE_LIMITS.textFrameMaxBytes) return { ok: false, reason: 'too_large' };
  const m = parseObject(plain.toString('utf8'));
  if (!m || typeof m.type !== 'string') return { ok: false, reason: 'malformed' };
  if (!AGENT_TYPES.has(m.type)) return { ok: false, reason: KNOWN_TYPES.has(m.type) ? 'direction' : 'unknown_type' };
  return { ok: true, type: m.type };
}

export type AgentBinary = { ok: true; key: boolean } | { ok: false; reason: DropReason };

/** H.264 Annex B: an IDR slice (5) or the SPS (7) that precedes each IDR, among the first units of the access unit. */
export function h264HasKeyFrame(au: Buffer, from = 1): boolean {
  let units = 0;
  const end = Math.min(au.length - 3, from + 4096);
  for (let i = from; i < end && units < 8; i++) {
    if (au[i] === 0 && au[i + 1] === 0 && au[i + 2] === 1) {
      const type = au[i + 3] & 0x1f;
      if (type === 5 || type === 7) return true;
      units++;
      i += 3;
    }
  }
  return false;
}

/** A binary message of the agent (opened): byte 0 is its kind (§5.1: JPEG, H.264); a JPEG is a key frame by itself. */
export function checkAgentBinary(plain: Buffer): AgentBinary {
  if (plain.length < 2) return { ok: false, reason: 'malformed' };
  if (plain[0] === REMOTE_FRAME_TYPES.jpeg) return { ok: true, key: true };
  if (plain[0] === REMOTE_FRAME_TYPES.h264) return { ok: true, key: h264HasKeyFrame(plain) };
  return { ok: false, reason: 'unknown_frame' };
}

export type ViewerMessage = { ok: true; message: RemoteViewerToAgentMessage; input: boolean } | { ok: false; reason: DropReason };

/**
 * A text message of the viewer: its size, a JSON object, a type of viewer → agent (§5.2), its fields within their bounds;
 * an input (touch, scroll, nav, type_text, key) only while the effective mode is control (§5.3). The message returned
 * holds its known fields only.
 */
export function checkViewerText(text: string, effective: RemoteMode): ViewerMessage {
  if (Buffer.byteLength(text, 'utf8') > REMOTE_LIMITS.textFrameMaxBytes) return { ok: false, reason: 'too_large' };
  const m = parseObject(text);
  if (!m || typeof m.type !== 'string') return { ok: false, reason: 'malformed' };
  if (!VIEWER_TYPES.has(m.type)) return { ok: false, reason: KNOWN_TYPES.has(m.type) ? 'direction' : 'unknown_type' };
  const input = INPUT_TYPES.has(m.type);
  if (input && effective !== 'control') return { ok: false, reason: 'view_mode' };
  const message = viewerMessage(m);
  return message ? { ok: true, message, input } : { ok: false, reason: 'out_of_bounds' };
}

function viewerMessage(m: Json): RemoteViewerToAgentMessage | null {
  switch (m.type) {
    case 'keepalive': return { type: 'keepalive' };
    case 'key_request': return { type: 'key_request' };
    case 'set_bitrate': return int(m.kbps, 1, MAX_KBPS) ? { type: 'set_bitrate', kbps: m.kbps } : null;
    case 'set_codec': return typeof m.codec === 'string' && CODECS.has(m.codec) ? { type: 'set_codec', codec: m.codec as 'h264' | 'jpeg' } : null;
    case 'quality': return finite(m.maxHeight) && QUALITIES.has(m.maxHeight) ? { type: 'quality', maxHeight: m.maxHeight as 480 | 720 | 1080 } : null;
    case 'touch':
      return typeof m.action === 'string' && TOUCH_ACTIONS.has(m.action) && int(m.id, 0, MAX_POINTER_ID)
        && coordinate(m.x) && coordinate(m.y) && generation(m.gen)
        ? { type: 'touch', action: m.action as 'down' | 'move' | 'up' | 'cancel', id: m.id, x: m.x, y: m.y, gen: m.gen } : null;
    case 'scroll':
      return coordinate(m.x) && coordinate(m.y) && delta(m.dx) && delta(m.dy) && generation(m.gen)
        ? { type: 'scroll', x: m.x, y: m.y, dx: m.dx, dy: m.dy, gen: m.gen } : null;
    case 'nav': return typeof m.action === 'string' && NAV_ACTIONS.has(m.action) ? { type: 'nav', action: m.action as RemoteNavAction } : null;
    case 'type_text':
      return typeof m.text === 'string' && m.text.length > 0 && m.text.length <= REMOTE_LIMITS.typeTextMax ? { type: 'type_text', text: m.text } : null;
    case 'key': return typeof m.code === 'string' && KEY_CODES.has(m.code) ? { type: 'key', code: m.code as RemoteKeyCode } : null;
    default: return null;
  }
}

/** The inputs of one tunnel admitted per second (§5.3: 200 at most): a window of one second. */
export class InputRate {
  private start = 0;
  private n = 0;
  private readonly perSecond: number;
  constructor(perSecond: number = REMOTE_LIMITS.inputPerSecond) {
    this.perSecond = perSecond;
  }

  take(now: number = Date.now()): boolean {
    if (now - this.start >= 1000) { this.start = now; this.n = 0; }
    if (this.n >= this.perSecond) return false;
    this.n++;
    return true;
  }
}
