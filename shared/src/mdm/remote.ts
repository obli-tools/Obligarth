// =============================================================================
// Remote assistance (P0-15): a technician of the MSP sees the screen of a managed device, and controls it when
// allowed, from the console. The MSP model of Obliance/Oblireach (decision of the owners of 27/10, §0.1 of the spec):
// the technician is strongly authenticated (strict step-up at each opening and each move to the control) and traced;
// the user of the device accepts nothing and cannot stop the session, they are told by notifications (its opening, a
// permanent one all along, its end). The vocabulary shared by the server (server/src/remote/, the only writer of
// obligarth.remote_sessions: migration p015_remote_sessions), the console and the agents: the session (channel,
// mode, states, reasons of its end, reasons an action is unavailable), its view in the console, the limits, and the
// messages of the stream (§5: the frame format of Oblireach, its own dialect). The CHECKs of the table copy the lists
// below: both change together. No import: the client and the unit tests load it as is.
// =============================================================================

/** The fleets a session reaches: the bridge agent (first, T1 to T9), Android Enterprise through the companion app
 *  (T10, after P0-9), iOS/iPadOS in view only (T11, optional). */
export const REMOTE_CHANNELS = ['legacy_agent', 'android', 'apple'] as const;
export type RemoteChannel = typeof REMOTE_CHANNELS[number];

/** view: the screen only; control: the screen and the inputs (touch, navigation, text), which includes view. */
export const REMOTE_MODES = ['view', 'control'] as const;
export type RemoteMode = typeof REMOTE_MODES[number];

/** The effective mode of a session: the lower of the mode asked and the mode the agent took at /accept
 *  (consentedMode: the mode asked, view when the agent cannot inject; none yet: the mode asked). The relay and the
 *  agent filter by it, never by the mode asked. */
export function remoteEffectiveMode(mode: RemoteMode, consentedMode: RemoteMode | null): RemoteMode {
  return mode === 'control' && (consentedMode === null || consentedMode === 'control') ? 'control' : 'view';
}

/** The states of a session (§2), in their order of progress; the last four are final. No consent of the user (§0.1):
 *  awaiting_consent keeps its name for the step « delivered, awaiting /accept », which only the system dialog of the
 *  screen capture holds (60 s). */
export const REMOTE_SESSION_STATES = [
  'awaiting_approval',   // under the restriction 'restricted': an approval request is waiting (30 min)
  'queued',              // remote.open written in the queue of the device (10 min to be delivered)
  'awaiting_consent',    // delivered, awaiting /accept: the system dialog of the screen capture (60 s), never validated
                         // by an injection (§0.1 rule 8)
  'connecting',          // accepted, stream token handed over (60 s to attach)
  'live',                // both ends attached to the relay
  'ended', 'expired', 'cancelled', 'failed',
] as const;
export type RemoteSessionState = typeof REMOTE_SESSION_STATES[number];

export const REMOTE_FINAL_STATES = ['ended', 'expired', 'cancelled', 'failed'] as const satisfies readonly RemoteSessionState[];
export type RemoteFinalState = typeof REMOTE_FINAL_STATES[number];

export const isRemoteFinalState = (s: string): s is RemoteFinalState => (REMOTE_FINAL_STATES as readonly string[]).includes(s);

/** Why a session ended (§2, §0.1). revoked: capability withdrawn, privacy profile, unenrollment, ownership, console
 *  session revoked; projection_denied: the system dialog of the screen capture refused, or left 60 s without an answer
 *  (nobody before the device and « Ne plus afficher » never ticked: §0.1 rule 8); approval_denied, approval_expired: a
 *  session awaiting its approval whose request was denied or expired. No end by the user of the device (no consent,
 *  no Stop button) nor on the loss of its notification (§0.1 rules 1, 2). */
export const REMOTE_END_REASONS = [
  'operator', 'projection_denied', 'device_timeout', 'idle', 'max_duration', 'screen_off_timeout', 'freeze', 'revoked',
  'agent_error', 'server_restart', 'approval_denied', 'approval_expired',
] as const;
export type RemoteEndReason = typeof REMOTE_END_REASONS[number];

/** Who ended a session: the operator (or an administrator of the tenant, emergency end), the device's side (its system
 *  dialog of the screen capture refused or left unanswered, its screen off too long), the server. */
export const REMOTE_ENDED_BY = ['operator', 'user', 'system'] as const;
export type RemoteEndedBy = typeof REMOTE_ENDED_BY[number];

/** The side of the person who asked the session (shown to the user, approvals: requiredSide). */
export const REMOTE_REQUESTER_SIDES = ['msp', 'client'] as const;
export type RemoteRequesterSide = typeof REMOTE_REQUESTER_SIDES[number];

/** The control during a session (§0.1 rule 1): granted by the server after the checks of the technician (capability,
 *  restriction, strict step-up), never asked of the device (frame mode { effective: 'control' } to the agent);
 *  released when the technician goes back to the view (frame mode { effective: 'view' }). */
export const REMOTE_ESCALATION_STATES = ['granted', 'released'] as const;
export type RemoteEscalationState = typeof REMOTE_ESCALATION_STATES[number];

/** Why a session cannot be opened on a device now (server/src/remote/guard.ts checkOpenable; the menu of the device).
 *  policyConflict: the Android channel (T10), a policy disabling the screen capture. */
export const REMOTE_UNAVAILABLE_REASONS = [
  'privacyDisabled', 'personalDevice', 'platformUnsupported', 'agentTooOld', 'knoxRequired', 'injectUnavailable', 'frozen',
  'sessionOpen', 'capabilityMissing', 'revoked', 'notEnrolled', 'quota', 'policyConflict',
] as const;
export type RemoteUnavailableReason = typeof REMOTE_UNAVAILABLE_REASONS[number];

/** The bounds of the sessions (§4.1, D14). The tenant's settings move the maximum duration within its range. */
export const REMOTE_LIMITS = Object.freeze({
  /** The reason and the ticket are optional (§0.1 rule 3); given, a reason holds 1 to reasonMax characters. */
  reasonMax: 200,
  ticketMax: 100,
  /** Maximum duration of a session, minutes (tenant setting). */
  maxMinutesDefault: 60,
  maxMinutesMin: 15,
  maxMinutesMax: 240,
  idleSeconds: 600,
  idleWarningSeconds: 30,
  approvalMinutes: 30,
  deliverySeconds: 600,
  /** The system dialog of the screen capture (Android 7: « Commencer maintenant »), never validated by the agent. */
  projectionDialogSeconds: 60,
  connectingSeconds: 60,
  streamTokenSeconds: 60,
  openPerTenant: 5,
  openPerOperator: 2,
  openPerInstance: 40,
  agentUplinkKbps: 4000,
  bufferBytes: 2 * 1024 * 1024,
  textFrameMaxBytes: 4096,
  inputPerSecond: 200,
  typeTextMax: 256,
  maxPointers: 5,
  pingSeconds: 25,
  pongSeconds: 20,
  revalidateSeconds: 60,
  /** Size of agent_capabilities, compact JSON (the CHECK of the table). */
  agentCapabilitiesMaxBytes: 2048,
  /** Long wait of the bridge agent (/agent/v1/wait), and its armed window (D9). */
  waitSeconds: 50,
  armedWindowMinutes: 15,
  /** First version of the bridge agent that takes a session, and its versionCode (major × 10000 + minor × 100 + patch,
   *  agent-android/app/build.gradle.kts): the server reads the versionCode each interrogation announces (the name is the
   *  enrollment's, never updated by agent.update). */
  minAgentVersion: '1.1.0',
  minAgentVersionCode: 10100,
  /** Long waits held at once on the instance (/agent/v1/wait); beyond, 429 with a Retry-After. */
  waitPerInstance: 2000,
  /** Margin of the deadline of a session awaiting /accept, after the system dialog (seconds): the notification of the
   *  opening, the start of the capture, the network. */
  consentMarginSeconds: 30,
  /** Sessions one operator asks within an hour before the alert remote.burst (§4.6). */
  burstPerHour: 10,
  /** Android 15 (API 35) and later: no control in the device administrator mode (KBA Samsung 1674). */
  controlMaxApiLevel: 34,
});

/** The reasons an agent gives to POST /agent/v1/remote/<id>/end (§4.3, §0.1): the system dialog of the screen capture
 *  refused or left 60 s unanswered, the screen off too long, its error. No refusal nor Stop by the user (§0.1 rules 1,
 *  2); the inactivity and the maximum duration end at the server. */
export const REMOTE_AGENT_END_REASONS = ['projection_denied', 'screen_off_timeout', 'agent_error'] as const satisfies readonly RemoteEndReason[];
export type RemoteAgentEndReason = typeof REMOTE_AGENT_END_REASONS[number];

/** config.remote of the bridge agent (§4.3): given by /enroll and /poll, in the configuration signed with the answer,
 *  to an agent of minAgentVersionCode at least (an older one gets none: its configuration and its version are those of
 *  before P0-15, and an agent updated to 1.1.0 announces a version that no longer matches, so it gets it whole). */
export interface LegacyAgentRemoteConfig {
  /** The rule remoteAssistance of the corporate privacy profile of the tenant (true by default, §0.1 rule 5). */
  enabled: boolean;
  /** Permanent long wait (RemoteSettings.waitChannel, false by default, D9). */
  waitChannel: boolean;
  /** Server time (Unix seconds) until which the agent holds /agent/v1/wait: 15 min after the end of a session its
   *  device took (a quick return); null otherwise. */
  armedUntil: number | null;
  minAgentVersion: string;
}

/** What the agent measured when it accepted (§4.3 /accept; agent_capabilities of the session, 2 KiB at most). */
export interface RemoteAgentCapabilities {
  /** Inputs possible at all (control). */
  inject: boolean;
  /** Knox RemoteInjection held and instantiable (§8): the control rests on it, not on knox_state. */
  remoteInject: boolean;
  codecs: Array<'h264' | 'jpeg'>;
  width: number;
  height: number;
  /** The notifications of the agent are enabled: informative (§0.1 rule 2), never a refusal. */
  notificationsEnabled: boolean;
  overlay: boolean;
}

/** A session as the console sees it (never a token). */
export interface RemoteSessionDto {
  id: string;
  deviceId: number;
  channel: RemoteChannel;
  /** The mode asked. */
  mode: RemoteMode;
  /** The mode the agent took at /accept (null: not yet). */
  consentedMode: RemoteMode | null;
  /** remoteEffectiveMode(mode, consentedMode). */
  effectiveMode: RemoteMode;
  state: RemoteSessionState;
  requestedBy: number | null;
  requestedByName: string;
  requesterSide: RemoteRequesterSide;
  operatorOrg: string;
  /** The reason and the ticket are optional (§0.1 rule 3). */
  reason: string | null;
  ticket: string | null;
  approvalId: number | null;
  createdAt: string;
  deliveredAt: string | null;
  consentedAt: string | null;
  startedAt: string | null;
  endedAt: string | null;
  /** The deadline of the current state. */
  expiresAt: string;
  maxEndsAt: string | null;
  escalationState: RemoteEscalationState | null;
  endReason: RemoteEndReason | null;
  endedBy: RemoteEndedBy | null;
  bytesDown: number;
  bytesUp: number;
  inputEvents: number;
  /** From the start of the stream to its end (or now), seconds; null before the start. */
  durationSeconds: number | null;
}

// ── Stream (§5) ─────────────────────────────────────────────────────────────
// Text JSON frames (opcode 0x1) and binary frames (0x2); byte 0 of a binary frame tells its kind. On the agent's end
// every frame is also encrypted (AES-256-GCM, §4.4): the format below is the plain one.

/** Byte 0 of a binary frame: a JPEG image, an H.264 access unit (Annex B, SPS/PPS before each IDR). */
export const REMOTE_FRAME_TYPES = Object.freeze({ jpeg: 0x01, h264: 0x02 } as const);
export type RemoteStreamFrameType = typeof REMOTE_FRAME_TYPES[keyof typeof REMOTE_FRAME_TYPES];

/** The functions an agent announces in its init; the viewer enables only those. */
export const REMOTE_FEATURES = ['touch', 'nav', 'type_text', 'key', 'quality', 'display_state'] as const;
export type RemoteFeature = typeof REMOTE_FEATURES[number];

/** No power dialog, lock nor shutdown in v1 (§5.3): a power_dialog then a touch would bypass the guarded actions. */
export const REMOTE_NAV_ACTIONS = ['back', 'home', 'recents', 'notifications', 'volume_up', 'volume_down', 'wake'] as const;
export type RemoteNavAction = typeof REMOTE_NAV_ACTIONS[number];

export const REMOTE_KEY_CODES = ['enter', 'del', 'tab', 'left', 'right', 'up', 'down', 'escape'] as const;
export type RemoteKeyCode = typeof REMOTE_KEY_CODES[number];

export type RemoteCodec = 'h264' | 'jpeg';

/** Agent → viewer (relayed). */
export type RemoteAgentToViewerMessage =
  | { type: 'init'; gen: number; width: number; height: number; rotation: number; codecs: RemoteCodec[]; codec: RemoteCodec; features: RemoteFeature[] }
  | { type: 'keepalive' }
  | { type: 'error'; code: string; retry: boolean; message?: string }
  | { type: 'display_state'; rotation: number; screenOn: boolean; locked: boolean }
  | { type: 'input_unavailable'; reason: string }
  | { type: 'bitrate'; kbps: number }
  | { type: 'inactivity_warning'; seconds: number }
  | { type: 'inactivity_timeout' };

/** Viewer → agent (relayed; the inputs dropped by the relay while the effective mode is view). */
export type RemoteViewerToAgentMessage =
  | { type: 'keepalive' }
  | { type: 'key_request' }
  | { type: 'set_bitrate'; kbps: number }
  | { type: 'set_codec'; codec: RemoteCodec }
  | { type: 'quality'; maxHeight: 480 | 720 | 1080 }
  | { type: 'touch'; action: 'down' | 'move' | 'up' | 'cancel'; id: number; x: number; y: number; gen: number }
  | { type: 'scroll'; x: number; y: number; dx: number; dy: number; gen: number }
  | { type: 'nav'; action: RemoteNavAction }
  | { type: 'type_text'; text: string }
  | { type: 'key'; code: RemoteKeyCode };

/** Server → agent: hello (bound to the transport, §4.4), the effective mode the server granted (§0.1 rule 1: control
 *  after the checks of the technician, view to go back; the agent applies it, nothing is asked of the user), the end. */
export type RemoteServerToAgentMessage =
  | { type: 'hello'; sessionId: string; mode: RemoteMode; ts: number; serverEcdh: string; sig: string }
  | { type: 'mode'; effective: RemoteMode }
  | { type: 'session_end'; reason: RemoteEndReason };

/** Server → viewer. */
export type RemoteServerToViewerMessage =
  | { type: 'session_end'; reason: RemoteEndReason }
  | { type: 'mode'; effective: RemoteMode };

/** The message types admitted in each direction (§5.2): anything else is dropped and counted by the relay. */
export const REMOTE_AGENT_TO_VIEWER_TYPES = [
  'init', 'keepalive', 'error', 'display_state', 'input_unavailable', 'bitrate', 'inactivity_warning', 'inactivity_timeout',
] as const satisfies ReadonlyArray<RemoteAgentToViewerMessage['type']>;
export const REMOTE_VIEWER_TO_AGENT_TYPES = [
  'keepalive', 'key_request', 'set_bitrate', 'set_codec', 'quality', 'touch', 'scroll', 'nav', 'type_text', 'key',
] as const satisfies ReadonlyArray<RemoteViewerToAgentMessage['type']>;

/** The viewer's inputs: dropped by the relay (and refused by the agent) while the effective mode is view. */
export const REMOTE_INPUT_TYPES = ['touch', 'scroll', 'nav', 'type_text', 'key'] as const satisfies ReadonlyArray<RemoteViewerToAgentMessage['type']>;

/** The viewer's end of the relay (§4.4): GET /api/remote-sessions/<id>/tunnel, no secret in the URL. The console opens
 *  `new WebSocket(url, [REMOTE_VIEWER_PROTOCOL, REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX + viewerToken])` (the token in
 *  Sec-WebSocket-Protocol, never logged); the server answers REMOTE_VIEWER_PROTOCOL alone, never the element that carries
 *  the token. Refused before the handshake (an HTTP status, no reason beyond it): 401 no console session or no token, 403
 *  another Origin, a wrong token or the conditions lost, 404 unknown session, 409 its state. */
export const REMOTE_VIEWER_PROTOCOL = 'obl-remote.1';
export const REMOTE_VIEWER_TOKEN_PROTOCOL_PREFIX = 'obl-viewer.';
export const remoteTunnelPath = (sessionId: string): string => `/api/remote-sessions/${sessionId}/tunnel`;

/** The bounds of the relay (§4.1, §5.3). */
export const REMOTE_RELAY_LIMITS = Object.freeze({
  /** A message of the agent, once opened: an H.264 access unit of 1 MiB with its byte of type, with room. */
  agentMessageMaxBytes: 2 * 1024 * 1024,
  /** A WebSocket message of the viewer (its texts are 4 KiB at most: beyond, dropped; beyond this, the tunnel closes). */
  viewerMessageMaxBytes: 16 * 1024,
  /** A viewer gone (tab closed, network lost) may attach again within this delay; after it the session ends. */
  viewerReattachSeconds: 30,
  /** The agent's end gone without a reason: this delay for its /end to arrive (screen off, its error) before the relay
   *  ends the session itself. */
  agentGoneGraceSeconds: 5,
  /** Beyond this many bytes waiting for the viewer the tunnel of the viewer is closed (it attaches again). */
  viewerStallBytes: 8 * 1024 * 1024,
  /** At most one key_request of the relay per this delay, when the viewer catches up after dropped video. */
  keyRequestMs: 1000,
});

// ── Settings and console API (T3) ───────────────────────────────────────────

/** The settings of the remote assistance of a tenant (§4.1, §4.6, §0.1 rule 4; table remote_settings). A change is always an
 *  approval request (restriction remote.settings_change, floor 'restricted'); a request of the MSP that touches
 *  mspSessionsNeedClientApproval is reviewed by a client approver, never on the MSP side. */
export interface RemoteSettings {
  /** Every session asked by the MSP is approved by a client approver of the tenant (requiredSide 'client'). */
  mspSessionsNeedClientApproval: boolean;
  /** Maximum duration of a session, minutes (REMOTE_LIMITS.maxMinutesMin to maxMinutesMax). */
  maxMinutes: number;
  /** Permanent long wait of the bridge agents (/agent/v1/wait outside the armed window, D9): false by default, to
   *  enable only after the measure of the pilot. Read by the configuration of the agents (T4). */
  waitChannel: boolean;
}

export const DEFAULT_REMOTE_SETTINGS: Readonly<RemoteSettings> = Object.freeze({
  mspSessionsNeedClientApproval: false,
  maxMinutes: REMOTE_LIMITS.maxMinutesDefault,
  waitChannel: false,
});

/** GET /api/remote-sessions/settings: the settings in force and the change waiting for its approval. */
export interface RemoteSettingsDto extends RemoteSettings {
  updatedAt: string | null;
  pending: { approvalId: number; settings: Partial<RemoteSettings> } | null;
}

/** POST /api/remote-sessions: the session and the viewer's token, once (201); or the session awaiting its approval
 *  (202, no token: POST /:id/viewer-token once it is approved). */
export interface RemoteSessionCreated {
  session: RemoteSessionDto;
  viewerToken?: string;
  approvalId?: number;
}

/** Socket.io REMOTE_SESSION_CHANGED, to the requester and to the tenant's administrators (never a token). */
export interface RemoteSessionChanged {
  sessionId: string;
  deviceId: number;
  state: RemoteSessionState;
  endReason?: RemoteEndReason;
}

/** The status item of a bridge agent's device that carries the measured capability remoteInject (§8: Knox
 *  RemoteInjection held and instantiable), written from the agent's inventory and interrogation (T4, T8). The control
 *  is refused (injectUnavailable) while it is not true, whatever knox_state says. */
export const REMOTE_LEGACY_INJECT_ITEM = 'agent.remote.inject';
