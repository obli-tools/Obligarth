import {
  REMOTE_AGENT_TO_VIEWER_TYPES, REMOTE_END_REASONS, REMOTE_FEATURES, REMOTE_FRAME_TYPES, REMOTE_LIMITS, REMOTE_MODES, REMOTE_VIEWER_PROTOCOL,
  REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX, remoteTunnelPath,
  type RemoteAgentToViewerMessage, type RemoteCodec, type RemoteEndReason, type RemoteFeature, type RemoteServerToViewerMessage,
  type RemoteViewerToAgentMessage,
} from '@obligarth/shared';

// =============================================================================
// The viewer's end of the remote stream (P0-15 §4.4, §5): the dialect of Obligarth written again on the frame format of
// Oblireach (not a copy of Obliance's reachProtocol.ts, whose desktop dialect has nothing to do with a phone). Text JSON
// frames in opcode 0x1, binary frames in 0x2 whose byte 0 tells their kind (0x01 JPEG, 0x02 H.264 Annex B). The tunnel
// is opened with the viewer's token as a WebSocket subprotocol, never in the URL (nor in a log). The messages are
// checked on arrival: a type of another direction, unknown or malformed is ignored (the relay filters too).
// =============================================================================

export const FRAME = REMOTE_FRAME_TYPES;

/** A message the viewer receives: from the agent (relayed) or from the server. */
export type ViewerInbound = RemoteAgentToViewerMessage | RemoteServerToViewerMessage;

const AGENT_TYPES = new Set<string>(REMOTE_AGENT_TO_VIEWER_TYPES);
const SERVER_TYPES = new Set<string>(['session_end', 'mode']);
const FEATURES = new Set<string>(REMOTE_FEATURES);
const CODECS = new Set<string>(['h264', 'jpeg']);

const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

/** The message of a text frame, or null when it is not one the viewer takes (§5.2). */
export function parseInbound(text: string): ViewerInbound | null {
  if (text.length > REMOTE_LIMITS.textFrameMaxBytes * 2) return null;
  let v: unknown;
  try { v = JSON.parse(text); } catch { return null; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const m = v as Record<string, unknown>;
  if (typeof m.type !== 'string' || !(AGENT_TYPES.has(m.type) || SERVER_TYPES.has(m.type))) return null;
  switch (m.type) {
    case 'init': {
      if (!num(m.gen) || !num(m.width) || !num(m.height) || m.width <= 0 || m.height <= 0) return null;
      const codecs = Array.isArray(m.codecs) ? m.codecs.filter((c): c is RemoteCodec => typeof c === 'string' && CODECS.has(c)) : [];
      const features = Array.isArray(m.features) ? m.features.filter((f): f is RemoteFeature => typeof f === 'string' && FEATURES.has(f)) : [];
      const codec = typeof m.codec === 'string' && CODECS.has(m.codec) ? m.codec as RemoteCodec : (codecs[0] ?? 'jpeg');
      return { type: 'init', gen: m.gen, width: m.width, height: m.height, rotation: num(m.rotation) ? m.rotation : 0, codecs, codec, features };
    }
    case 'keepalive': return { type: 'keepalive' };
    case 'error': return { type: 'error', code: typeof m.code === 'string' ? m.code.slice(0, 64) : 'error', retry: m.retry === true, ...(typeof m.message === 'string' ? { message: m.message.slice(0, 300) } : {}) };
    case 'display_state': return { type: 'display_state', rotation: num(m.rotation) ? m.rotation : 0, screenOn: m.screenOn !== false, locked: m.locked === true };
    case 'input_unavailable': return { type: 'input_unavailable', reason: typeof m.reason === 'string' ? m.reason.slice(0, 64) : 'unknown' };
    case 'bitrate': return num(m.kbps) ? { type: 'bitrate', kbps: m.kbps } : null;
    case 'inactivity_warning': return { type: 'inactivity_warning', seconds: num(m.seconds) ? m.seconds : REMOTE_LIMITS.idleWarningSeconds };
    case 'inactivity_timeout': return { type: 'inactivity_timeout' };
    case 'session_end': return typeof m.reason === 'string' && (REMOTE_END_REASONS as readonly string[]).includes(m.reason) ? { type: 'session_end', reason: m.reason as RemoteEndReason } : { type: 'session_end', reason: 'agent_error' };
    case 'mode': return typeof m.effective === 'string' && (REMOTE_MODES as readonly string[]).includes(m.effective) ? { type: 'mode', effective: m.effective as 'view' | 'control' } : null;
    default: return null;
  }
}

/** The text of a message of the viewer (its known fields only: the relay drops anything else). */
export function encodeOutbound(m: RemoteViewerToAgentMessage): string {
  return JSON.stringify(m);
}

/** The URL of the viewer's tunnel: same origin as the console (the server checks the Origin), no secret in it. */
export function tunnelUrl(sessionId: string): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${window.location.host}${remoteTunnelPath(sessionId)}`;
}

/** The subprotocols of the tunnel: the protocol, then the token (the server answers the protocol alone). */
export function tunnelProtocols(viewerToken: string): string[] {
  return [REMOTE_VIEWER_PROTOCOL, `${REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX}${viewerToken}`];
}

/** Close codes of the relay (server/src/remote/relay.ts). */
export const CLOSE = Object.freeze({ normal: 1000, policy: 1008, tryAgain: 1013, replaced: 4001 });

/** type_text holds REMOTE_LIMITS.typeTextMax characters at most: a longer text goes in pieces (never cutting a
 *  surrogate pair). */
export function textPieces(text: string, max: number = REMOTE_LIMITS.typeTextMax): string[] {
  const chars = Array.from(text);
  const out: string[] = [];
  let cur = '';
  for (const c of chars) {
    if (cur.length + c.length > max) { out.push(cur); cur = ''; }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}
