/**
 * ObliReach viewer ↔ agent protocol — TypeScript copy of the contract
 * (Go: Oblireach repo, agent/protocol.go; client-app: constants in ui.go).
 *
 * Feature detection, not versions: the viewer only uses a behaviour when the
 * agent lists it in `init.features`. An agent never sends a new frame type or
 * push the viewer did not ask for. Old agents send no `features` at all.
 */

// ── Binary frame types (byte 0) ───────────────────────────────────────────────
export const FRAME = {
  JPEG: 0x01,
  H264: 0x02,
  VP9: 0x03,
  H265: 0x04,
  AV1: 0x05,
  /** Legacy audio: PCM s16le mono, 50 ms chunks, at init.audioRate. */
  AUDIO_PCM: 0x06,
  /** Audio v2: 20-byte header (see reachAudioPlayer.parseAudioV2) + fixed 20 ms frames. */
  AUDIO_V2: 0x07,
  /** viewer → agent: upload data `[0x20][tid u32 LE][seq u32 LE][data]`. */
  FILE_UP: 0x20,
  /** agent → viewer: download data, same layout. */
  FILE_DOWN: 0x21,
} as const;

export type ReachFeature =
  | 'view_gen'
  | 'mosaic'
  | 'clipboard_text'
  | 'clipboard_push'
  | 'clipboard_files'
  | 'file_upload'
  | 'file_download'
  | 'audio_v2'
  | 'session_follow'
  | 'error_codes'
  /** Accepts `{"type":"keepalive"}`: resets the agent's 10-minute inactivity
   *  timer, injects nothing, no answer (see reachKeepalive). Never sent to an
   *  agent that does not list it. */
  | 'keepalive';

/** Viewer → agent: keeps a watched session open (agents with 'keepalive'). */
export const KEEPALIVE_MESSAGE = { type: 'keepalive' } as const;

export interface ReachMonitorInfo {
  /** Index after filtering (detached / clone-mode outputs removed). */
  index: number;
  name: string;
  /** Physical desktop pixels (the agent is per-monitor DPI aware). */
  x: number;
  y: number;
  width: number;
  height: number;
  primary?: boolean;
  dpi?: number;
  scale?: number;
  rotation?: number;
}

export interface ReachRect { x: number; y: number; w: number; h: number }

export interface ReachTile {
  index: number;
  /** In frame pixels — the space mouse x,y are sent in. */
  frame: ReachRect;
  /** In physical desktop coordinates. */
  desktop: ReachRect;
  rotation?: number;
  primary?: boolean;
}

export interface ReachView {
  mode: 'monitor' | 'mosaic';
  width: number;
  height: number;
  scale: number;
  tiles: ReachTile[];
}

export interface ReachSessionInfo {
  id?: number;
  state?: string;
  desktop?: string;
  user?: string;
}

export interface ReachInit {
  type: 'init';
  width: number;
  height: number;
  fps: number;
  /** Legacy "initial decoder" field: always 'h264' (a real switch follows as codec_switch). */
  codec?: string;
  codecActive?: string;
  codecs?: string[];
  extradata?: string;
  monitors?: ReachMonitorInfo[];
  /** Captured monitor, -1 in mosaic. */
  monitor?: number;
  audioRate?: number;
  audioAvail?: boolean;
  features?: string[];
  gen?: number;
  view?: ReachView;
  clipboard?: { text?: boolean; push?: boolean; files?: boolean; maxText?: number };
  files?: { upload?: boolean; download?: boolean; maxFile?: number; chunk?: number; window?: number };
  audio?: { codecs?: string[]; maxChannels?: number; rate?: number };
  session?: ReachSessionInfo;
  /** Added by the Obliance relay when the operator may not transfer files in
   *  this session (server reachFilesGate.ts): the file features are removed
   *  from `features` and this says why. Absent: nothing refused. */
  filesPolicy?: { allowed?: boolean; reason?: string };
}

/** Why file transfers are refused in this session ('restriction': the
 *  tenant's action restrictions on the file explorer's transfers). */
export type ReachFilesDenied = 'capability' | 'restriction' | 'privacy' | 'other';

/** The refusal the relay put in the init (reachFilesGate.ts), or null. */
export function filesDenied(init: Pick<ReachInit, 'filesPolicy'> | null | undefined): ReachFilesDenied | null {
  const p = init?.filesPolicy;
  if (!p || typeof p !== 'object' || p.allowed !== false) return null;
  return p.reason === 'capability' || p.reason === 'restriction' || p.reason === 'privacy' ? p.reason : 'other';
}

export type ReachErrorCode =
  // agent
  | 'helper_spawn_failed' | 'helper_timeout' | 'capture_init_failed' | 'encoder_init_failed'
  | 'session_not_found' | 'session_no_display' | 'session_logged_off' | 'session_switch_timeout' | 'privacy_mode' | 'internal'
  // relay (server)
  | 'agent_timeout' | 'agent_offline' | 'agent_error' | 'session_closed';

export interface ReachErrorMsg {
  type: 'error';
  code?: string;
  message?: string;
  retry?: boolean;
  /** Relay agent_error from a tunnel_failed: the agent's own code. */
  agentCode?: string;
}

export type ReachSessionStateName = 'starting' | 'switching' | 'live' | 'no_display';

export interface ReachSessionStateMsg {
  type: 'session_state';
  state: ReachSessionStateName;
  sessionId?: number;
  desktop?: string;
  user?: string;
  reason?: string;
  waitSec?: number;
}

export type ReachViewErrorCode = 'mosaic_unavailable' | 'monitor_not_found' | 'capture_failed' | 'too_large' | 'secure_desktop';

export interface ReachViewErrorMsg {
  type: 'view_error';
  code?: ReachViewErrorCode | string;
  message?: string;
  gen?: number;
}

export interface ReachClipboardContentMsg {
  type: 'clipboard_content';
  text?: string;
  origin?: 'request' | 'remote_change';
  id?: string;
  truncated?: boolean;
}

export interface ReachClipboardFile { idx: number; name: string; size: number; dir?: boolean }

/** Agent-side error codes after which no automatic retry makes sense (contract §1.4). */
export const NO_RETRY_CODES: ReadonlySet<string> = new Set([
  'session_not_found', 'session_no_display', 'session_logged_off', 'privacy_mode',
  'agent_timeout', 'agent_offline', 'agent_error', 'session_closed',
]);

/** Features the agent advertised (empty for old agents). */
export function featureSet(init: Pick<ReachInit, 'features'> | null | undefined): Set<string> {
  return new Set(Array.isArray(init?.features) ? init!.features.filter((f) => typeof f === 'string') : []);
}

/**
 * True when the agent speaks the feature-detected protocol at all. A list
 * with only 'keepalive' is the direct capture path (macOS, Linux, Windows
 * interactive), which sent no features before the keepalive and implements
 * none of the rest: it stays a legacy agent (clipboard: "update the agent").
 */
export function isModernAgent(init: Pick<ReachInit, 'features'> | null | undefined): boolean {
  const f = init?.features;
  if (!Array.isArray(f)) return false;
  return f.length === 0 || f.some((x) => x !== 'keepalive');
}

const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);

function rect(v: unknown): ReachRect | null {
  if (!v || typeof v !== 'object') return null;
  const r = v as Record<string, unknown>;
  const w = num(r.w);
  const h = num(r.h);
  if (w <= 0 || h <= 0) return null;
  return { x: num(r.x), y: num(r.y), w, h };
}

/** Validated view (tiles with a usable frame rect only), or null. */
export function parseView(v: unknown): ReachView | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const mode = o.mode === 'mosaic' ? 'mosaic' : o.mode === 'monitor' ? 'monitor' : null;
  if (!mode) return null;
  const tiles: ReachTile[] = [];
  if (Array.isArray(o.tiles)) {
    for (const t of o.tiles) {
      if (!t || typeof t !== 'object') continue;
      const tt = t as Record<string, unknown>;
      const frame = rect(tt.frame);
      if (!frame) continue;
      tiles.push({
        index: num(tt.index),
        frame,
        desktop: rect(tt.desktop) ?? frame,
        rotation: num(tt.rotation),
        primary: tt.primary === true,
      });
    }
  }
  return { mode, width: num(o.width), height: num(o.height), scale: num(o.scale, 1), tiles };
}

/** Monitor list with sane numbers (entries without a size dropped). */
export function parseMonitors(v: unknown): ReachMonitorInfo[] {
  if (!Array.isArray(v)) return [];
  const out: ReachMonitorInfo[] = [];
  for (const m of v) {
    if (!m || typeof m !== 'object') continue;
    const o = m as Record<string, unknown>;
    const width = num(o.width);
    const height = num(o.height);
    if (width <= 0 || height <= 0) continue;
    out.push({
      index: num(o.index, out.length),
      name: typeof o.name === 'string' ? o.name : '',
      x: num(o.x), y: num(o.y), width, height,
      primary: o.primary === true,
      dpi: typeof o.dpi === 'number' ? o.dpi : undefined,
      scale: typeof o.scale === 'number' ? o.scale : undefined,
      rotation: typeof o.rotation === 'number' ? o.rotation : undefined,
    });
  }
  return out;
}
