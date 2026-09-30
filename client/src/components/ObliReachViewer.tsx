/**
 * ObliReachViewer — native screen-streaming viewer for the Oblireach protocol.
 *
 * Architecture
 * ────────────
 * Opens a single WebSocket to the built-in Obliance relay (or standalone relay).
 *
 * ● Binary frames → [1 byte type][payload]
 * 0x01 JPEG, 0x02 H.264, 0x03 VP9, 0x04 H.265, 0x05 AV1 → canvas
 * 0x06 / 0x07 audio → ReachAudioPlayer, 0x21 file data → ReachFileTransfers
 *
 * ● Text frames = JSON control messages (bidirectional). The contract lives in
 * components/remote/reachProtocol.ts: every newer behaviour (mosaic view,
 * clipboard push, file transfer, audio v2, session following, error codes)
 * is used only when the agent lists it in `init.features`.
 *
 * Codec: H.264 via the WebCodecs API (VideoDecoder).
 * Chrome 94+, Edge 94+, Firefox 130+ (hardware-accelerated decode).
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Monitor, X, Maximize2, Keyboard, RefreshCw, AlertTriangle, Wifi, Lock, Unlock, MessageCircle, Circle, Camera, Volume2, VolumeX, Command, ShieldAlert, MoreHorizontal, ClipboardPaste, ClipboardCopy, MousePointer2, Hand, Minimize2, ChevronDown, ChevronUp, LayoutGrid, Upload, MonitorOff, Users, FileText, Timer, TimerOff, Check } from 'lucide-react';
import { clsx } from 'clsx';
import type { RemoteDelivery } from '@obliance/shared';
import { useNativeTopOffset } from '@/hooks/useNativeTopOffset';
import { useIsCoarsePointer, matchesMedia, MEDIA } from '@/hooks/useMediaQuery';
import { useNativeBack } from '@/hooks/useNativeBack';
import { isAndroidApp } from '@/native/bridge';
import { saveBlob } from '@/utils/download';
import { copyText, readClipboardText } from '@/utils/clipboard';
import { useRemotePointer, type TouchInputMode } from '@/components/remote/useRemotePointer';
import { MousePointerOff } from '@/components/remote/reachIcons';
import { RemoteKeyBar, KeyChip } from '@/components/remote/RemoteKeyBar';
import { SoftKeyboardInput, type SoftKeyboardHandle } from '@/components/remote/SoftKeyboardInput';
import { ReachToolsSheet } from '@/components/remote/ReachToolsSheet';
import { useKeyboardInset } from '@/components/remote/useKeyboardInset';
import { ReachClipboardPanel, type ReachClipboardSupport } from '@/components/remote/ReachClipboardPanel';
import { ReachTransferTray } from '@/components/remote/ReachTransferTray';
import { ReachAudioPlayer } from '@/components/remote/reachAudioPlayer';
import { ReachFileTransfers, type TransferItem } from '@/components/remote/reachFileTransfer';
import { isMosaicGap, miniMapLayout, probeMosaicBudget, decoderCodecString, tilePercentBox } from '@/components/remote/reachMosaic';
import { codecOfFrame, decoderActionFor, frameSizeChange, isKeyframe } from '@/components/remote/reachVideo';
import {
 filesSignature, newClipSyncState, noteLocalSent, notePageLeft, noteRemoteCopy, pasteDecision, pasteFilesDecision,
} from '@/components/remote/reachClipboard';
import {
 KEEPALIVE_LABELS, KEEPALIVE_MODES, KEEPALIVE_STORAGE_KEY, KeepaliveScheduler,
 loadKeepaliveMode, parseKeepaliveMode, saveKeepaliveMode, type KeepaliveMode,
} from '@/components/remote/reachKeepalive';
import {
 FRAME, KEEPALIVE_MESSAGE, NO_RETRY_CODES, featureSet, filesDenied, isModernAgent, parseMonitors, parseView,
 type ReachClipboardContentMsg, type ReachClipboardFile, type ReachErrorMsg, type ReachFilesDenied, type ReachInit,
 type ReachMonitorInfo, type ReachSessionStateMsg, type ReachView, type ReachViewErrorMsg,
} from '@/components/remote/reachProtocol';
import {
 ESSENTIAL_KEYS, NAVIGATION_KEYS, KEY_TO_CODE, MODIFIER_CODES, NO_MODIFIERS,
 activeModifiers, codeForChar, hasModifier,
 type KeyBarKey, type ModifierKey, type Modifiers,
} from '@/components/remote/remoteKeys';

// System-key chords sendable from the viewer. Each entry is a list of
// physical key codes (DOM KeyboardEvent.code) pressed together. The agent
// maps these via codeToVK so they hit the remote by position. These are the
// browser-reserved combos a viewer can't type directly (the OS swallows Win+*
// / Alt+Tab / Ctrl+Shift+Esc before the page sees them).
// `id` keys the translated title (reach.chord.<id>); labels are key names.
const SYSTEM_KEY_CHORDS: Array<{ id: string; label: string; codes: string[]; title: string; group: 'win' | 'window' | 'misc' }> = [
 { id: 'win', label: 'Win', codes: ['MetaLeft'], title: 'Windows key — Start menu', group: 'win' },
 { id: 'winD', label: 'Win+D', codes: ['MetaLeft', 'KeyD'], title: 'Show / hide desktop', group: 'win' },
 { id: 'winE', label: 'Win+E', codes: ['MetaLeft', 'KeyE'], title: 'Open File Explorer', group: 'win' },
 { id: 'winR', label: 'Win+R', codes: ['MetaLeft', 'KeyR'], title: 'Run dialog', group: 'win' },
 { id: 'winI', label: 'Win+I', codes: ['MetaLeft', 'KeyI'], title: 'Settings', group: 'win' },
 { id: 'winL', label: 'Win+L', codes: ['MetaLeft', 'KeyL'], title: 'Lock the session', group: 'win' },
 { id: 'winTab', label: 'Win+Tab', codes: ['MetaLeft', 'Tab'], title: 'Task view', group: 'win' },
 { id: 'winUp', label: 'Win+↑', codes: ['MetaLeft', 'ArrowUp'], title: 'Maximize window', group: 'win' },
 { id: 'winDown', label: 'Win+↓', codes: ['MetaLeft', 'ArrowDown'], title: 'Restore / minimize window', group: 'win' },
 { id: 'altTab', label: 'Alt+Tab', codes: ['AltLeft', 'Tab'], title: 'Switch window', group: 'window' },
 { id: 'altF4', label: 'Alt+F4', codes: ['AltLeft', 'F4'], title: 'Close active window', group: 'window' },
 { id: 'taskMgr', label: 'Task Mgr', codes: ['ControlLeft', 'ShiftLeft', 'Escape'], title: 'Ctrl+Shift+Esc — Task Manager', group: 'window' },
 { id: 'ctrlEsc', label: 'Ctrl+Esc', codes: ['ControlLeft', 'Escape'], title: 'Start menu (Ctrl+Esc)', group: 'window' },
 { id: 'esc', label: 'Esc', codes: ['Escape'], title: 'Escape', group: 'misc' },
 { id: 'prtSc', label: 'PrtSc', codes: ['PrintScreen'], title: 'Print Screen (full screen capture on remote)', group: 'misc' },
 { id: 'menu', label: 'Menu', codes: ['ContextMenu'], title: 'Context-menu key', group: 'misc' },
 { id: 'pause', label: 'Pause', codes: ['Pause'], title: 'Pause / Break', group: 'misc' },
];

const CODECS: Array<{ id: string; label: string }> = [
 { id: 'h264', label: 'H.264' },
 { id: 'h265', label: 'H.265' },
 { id: 'vp9', label: 'VP9' },
 { id: 'av1', label: 'AV1' },
 { id: 'jpeg', label: 'JPEG' },
];

const TOUCH_MODE_KEY = 'obliance.reach.touchMode';
const CLIP_SYNC_KEY = 'obliance.reach.clipSync';
const VIEW_MODE_KEY = 'obliance.reach.viewMode';
/** View only (local): 'on' / 'off' — off by default. */
const VIEW_ONLY_KEY = 'obliance.reach.viewOnly';

/** Auto-reconnect delays (s) for agents that do not follow the session themselves. */
const RECONNECT_BACKOFF_S = [2, 2, 3, 5, 5, 8, 8, 10];
/** No `paired` / `session_state` / picture within this time: the launch failed. */
const CONNECT_TIMEOUT_MS = 45_000;
/** Command queued for an offline agent: it has 5 minutes to come back. */
const CONNECT_TIMEOUT_QUEUED_MS = 330_000;
/** VM console: the first start downloads the ~130 MB console helper on the
 *  host before it dials the relay. The server times a waiting session out
 *  after 6 min (agent_timeout notice): wait longer than that here. */
const CONNECT_TIMEOUT_VMCONSOLE_MS = 8 * 60_000;
/** `paired` (the agent's relay socket is up) but no init / session_state / picture yet. */
const NO_PICTURE_TIMEOUT_MS = 45_000;
const NO_PICTURE_TIMEOUT_VMCONSOLE_MS = 90_000;
/** A socket closed before the agent paired: the same session token is
 *  reopened (the relay keeps it 15 s) instead of starting a new session. */
const REOPEN_DELAY_MS = 1_500;
const REOPEN_MAX = 12;
/** Agent codes after which "Pick another session" is offered (the target Windows session is gone / has no display). */
const PICK_SESSION_CODES: ReadonlySet<string> = new Set(['session_not_found', 'session_no_display', 'session_logged_off', 'session_switch_timeout']);
/** Ctrl+V: time to wait for the browser's `paste` event (Safari never sends it). */
const PASTE_EVENT_WAIT_MS = 250;
/** Clipboard text cap (after JSON encoding) — contract §1.5. */
const CLIP_MAX_JSON = 1_048_576;

function loadTouchMode(): TouchInputMode {
 try { return localStorage.getItem(TOUCH_MODE_KEY) === 'trackpad' ? 'trackpad' : 'direct'; } catch { return 'direct'; }
}
function loadClipSync(): boolean {
 try { return localStorage.getItem(CLIP_SYNC_KEY) !== 'off'; } catch { return true; }
}
function loadViewMode(): 'mosaic' | 'monitor' {
 try { return localStorage.getItem(VIEW_MODE_KEY) === 'mosaic' ? 'mosaic' : 'monitor'; } catch { return 'monitor'; }
}
function loadViewOnly(): boolean {
 try { return localStorage.getItem(VIEW_ONLY_KEY) === 'on'; } catch { return false; }
}
function saveLocal(key: string, value: string) {
 try { localStorage.setItem(key, value); } catch { /* private mode */ }
}
const isMacPlatform = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || '');

const modifierFlags = (m: Modifiers) => ({ ctrl: m.ctrl, alt: m.alt, shift: m.shift, meta: m.meta });

// ── Types ─────────────────────────────────────────────────────────────────────

type ConnStatus = 'connecting' | 'waiting' | 'streaming' | 'disconnected' | 'error' | 'reconnecting';

export interface ObliReachViewerProps {
 /** Obliance session token (hex, 64 chars). Used to build the WS URL. */
 sessionToken: string | null;
 /** Human-readable device name shown in the toolbar. */
 deviceName: string;
 /** Short-lived HMAC viewer token — only required for standalone relay. */
 viewerToken?: string;
 /** Base URL of the standalone Oblireach relay server (e.g. "wss://relay.example.com").
 * If absent, falls back to the built-in Obliance WebSocket relay. */
 relayHost?: string;
 /** Called when the user clicks Disconnect. */
 onClose: () => void;
 /** User's preferred codec (from profile preferences). If the codec is
 * unavailable on the agent, falls back to JPEG automatically. */
 preferredCodec?: string;
 /** Called when the user clicks the Chat button in the toolbar. */
 onChatToggle?: () => void;
 /** Whether the chat panel is currently open (controls button highlight). */
 chatOpen?: boolean;
 /** Whether chat notification sound is enabled. */
 chatSoundEnabled?: boolean;
 /** Toggle chat sound on/off. */
 onChatSoundToggle?: () => void;
 /** Starts a NEW session on the same target (the parent ends the previous
 * one and updates `sessionToken`, which re-opens the WebSocket). Used for
 * the automatic reconnect after an unexpected close (older agents: the
 * Winlogon→user-session transition tears the tunnel down) and by the
 * Retry button. Throwing disables further retries. Absent prop disables
 * both (viewer just stays on 'disconnected'). */
 onReconnect?: () => Promise<void>;
 /** How the server delivered the open command ('queued' = agent offline). */
 delivery?: RemoteDelivery | null;
 /** "Pick another session" (shown when the target session has no display). */
 onPickSession?: () => void;
 /** OS of the target device (devices.os_type). A Mac operator's Cmd+C / X / V
 * become Ctrl+C / X / V only for a Windows target (unknown = Windows); a
 * macOS target keeps Cmd, a Linux one gets Super (Cmd+C must not send SIGINT). */
 remoteOs?: string | null;
 /** 'vmconsole': Hyper-V interactive console (longer launch wait, own texts). */
 kind?: 'oblireach' | 'vmconsole';
}

// ── Component ─────────────────────────────────────────────────────────────────

export function ObliReachViewer({
 sessionToken,
 deviceName,
 viewerToken,
 relayHost,
 onClose,
 preferredCodec,
 onChatToggle,
 chatOpen: chatOpenProp,
 chatSoundEnabled,
 onChatSoundToggle,
 onReconnect,
 delivery,
 onPickSession,
 remoteOs,
 kind = 'oblireach',
}: ObliReachViewerProps) {
 const canvasRef = useRef<HTMLCanvasElement>(null);
 const containerRef = useRef<HTMLDivElement>(null);
 const wsRef = useRef<WebSocket | null>(null);
 const decoderRef = useRef<VideoDecoder | null>(null);
 /** Codec the current decoder was configured for (null: none / closed). */
 const decoderCodecRef = useRef<string | null>(null);
 /** The stream restarts (set_monitor on an old agent): new decoder at the next keyframe. */
 const decoderStaleRef = useRef(false);
 const kindRef = useRef(kind);
 kindRef.current = kind;
 const remoteOsRef = useRef(remoteOs);
 remoteOsRef.current = remoteOs;
 const rafRef = useRef<number>(0);
 const fileInputRef = useRef<HTMLInputElement>(null);

 // Auto-reconnect state — survives re-renders and useEffect re-runs so a
 // burst of quick close→reconnect→close doesn't reset the counter. Reset
 // once the agent actually answers (init / first picture).
 const reconnectAttemptsRef = useRef(0);
 const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
 const onReconnectRef = useRef(onReconnect);
 onReconnectRef.current = onReconnect;
 const deliveryRef = useRef(delivery);
 deliveryRef.current = delivery;
 /** Sockets closed on purpose (timeout, Retry): their close is not an "unexpected" one. */
 const quietCloseRef = useRef(new WeakSet<WebSocket>());

 const [status, setStatusState] = useState<ConnStatus>('connecting');
 const statusRef = useRef<ConnStatus>('connecting');
 const setStatus = useCallback((s: ConnStatus | ((prev: ConnStatus) => ConnStatus)) => {
 setStatusState((prev) => {
 const next = typeof s === 'function' ? s(prev) : s;
 statusRef.current = next;
 return next;
 });
 }, []);
 const [errorMsg, setErrorMsg] = useState('');
 const [errorDetail, setErrorDetail] = useState('');
 // Machine code of the last error (agent code first): offers "Pick another
 // session" when the target Windows session is gone or has no display.
 const [errorCode, setErrorCode] = useState('');
 const [agentDims, setAgentDimsState] = useState({ w: 1920, h: 1080 });
 const agentDimsRef = useRef({ w: 1920, h: 1080 });
 const setAgentDims = useCallback((d: { w: number; h: number }) => {
 agentDimsRef.current = d;
 setAgentDimsState(d);
 }, []);
 const [fps, setFps] = useState(0);
 const [codecId, setCodecIdState] = useState('h264'); // technical id: h264, h265, vp9, jpeg
 const codecIdRef = useRef('h264');
 const setCodecId = useCallback((c: string) => { codecIdRef.current = c; setCodecIdState(c); }, []);
 const [bitrate, setBitrate] = useState(0);
 const [isFullscreen, setIsFullscreen] = useState(false);
 // True while the Keyboard Lock API holds the keyboard (fullscreen, Chromium).
 const keyboardLockedRef = useRef(false);
 const [monitors, setMonitors] = useState<ReachMonitorInfo[]>([]);
 const [activeMonitor, setActiveMonitor] = useState(0);
 const [inputBlocked, setInputBlocked] = useState(false);
 const [isRecording, setIsRecording] = useState(false);
 // Remote audio is OFF by default: the technician turns it on with the
 // speaker button when needed (owner decision, 27/09/2026).
 const [audioEnabled, setAudioEnabled] = useState(false);
 const [hasAudio, setHasAudio] = useState(false);
 const [sysKeysOpen, setSysKeysOpen] = useState(false);
 const audioRef = useRef<ReachAudioPlayer | null>(null);
 if (!audioRef.current) audioRef.current = new ReachAudioPlayer();
 const audioEnabledRef = useRef(audioEnabled);
 useEffect(() => { audioEnabledRef.current = audioEnabled; }, [audioEnabled]);
 const mediaRecorderRef = useRef<MediaRecorder | null>(null);
 const recordedChunks = useRef<Blob[]>([]);
 const codecLabel: Record<string, string> = { h264: 'H.264', h265: 'H.265', vp9: 'VP9', av1: 'AV1', jpeg: 'JPEG' };
 const codec = codecLabel[codecId] || codecId.toUpperCase();
 const nativeTop = useNativeTopOffset();
 const { t } = useTranslation();

 // ── Protocol state (contract: components/remote/reachProtocol.ts) ────────
 const [features, setFeatures] = useState<Set<string>>(() => new Set());
 const featuresRef = useRef<Set<string>>(new Set());
 /** File transfers refused in this session (init.filesPolicy, set by the relay:
 * no 'files' permission, or privacy mode without the 'files' unlock). */
 const [filesDeniedState, setFilesDeniedState] = useState<ReachFilesDenied | null>(null);
 const filesDeniedRef = useRef<ReachFilesDenied | null>(null);
 /** Local files already refused on a Ctrl+V (one message per copy). */
 const lastDeniedFilesRef = useRef<string | null>(null);
 /** The agent sent a `features` array (feature-detected protocol). */
 const [modernAgent, setModernAgent] = useState(false);
 const genRef = useRef<number | null>(null);
 const [view, setViewState] = useState<ReachView | null>(null);
 const viewRef = useRef<ReachView | null>(null);
 const [viewPending, setViewPending] = useState(false);
 const viewPendingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
 const [sessionState, setSessionStateState] = useState<ReachSessionStateMsg | null>(null);
 const sessionStateRef = useRef<ReachSessionStateMsg | null>(null);
 const setSessionState = useCallback((s: ReachSessionStateMsg | null) => { sessionStateRef.current = s; setSessionStateState(s); }, []);
 /** An error with retry:false (or an inactivity timeout) ends auto-reconnect for this connection. */
 const noRetryRef = useRef(false);
 /** The agent's relay socket paired on this connection (`paired`, or anything from the agent). */
 const pairedRef = useRef(false);
 /** The agent itself answered on this connection (init / session_state / picture / error). */
 const answeredRef = useRef(false);
 const connectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
 /** After `paired`: cleared by init / session_state / a picture ("no picture yet" otherwise). */
 const pictureTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
 /** Launch deadline of the current session token (survives same-token reopens). */
 const launchDeadlineRef = useRef<{ url: string; at: number } | null>(null);
 /** Same-token reopens (socket closed before pairing) — see REOPEN_MAX. */
 const [reopenTick, setReopenTick] = useState(0);
 const reopenCountRef = useRef(0);
 const preferredSentRef = useRef(false);
 const autoMosaicTriedRef = useRef(false);
 /** Mouse buttons whose `down` was dropped locally (black gap of the mosaic). */
 const droppedButtonsRef = useRef<Set<number>>(new Set());

 // ── Keepalive (agents with 'keepalive': components/remote/reachKeepalive) ──
 // A watched session sends no input: the agent would end it after 10 min.
 const [keepaliveMode, setKeepaliveModeState] = useState<KeepaliveMode>(loadKeepaliveMode);
 /** This connection's init listed 'keepalive' (reset with every new socket). */
 const [keepaliveOk, setKeepaliveOk] = useState(false);
 const [keepaliveMenuOpen, setKeepaliveMenuOpen] = useState(false);
 const keepaliveRef = useRef<KeepaliveScheduler | null>(null);

 // ── Touch / mobile state (docs/obli-mobile.md §5) ─────────────────────────
 const isCoarse = useIsCoarsePointer();
 const isCoarseRef = useRef(isCoarse);
 isCoarseRef.current = isCoarse;
 const inAndroidApp = isAndroidApp();
 const keyboardInset = useKeyboardInset(isCoarse);
 const rootRef = useRef<HTMLDivElement>(null);
 const softKbRef = useRef<SoftKeyboardHandle>(null);
 const [softKbOpen, setSoftKbOpen] = useState(false);
 const [keyBarOpen, setKeyBarOpen] = useState(true);
 const [toolsOpen, setToolsOpen] = useState(false);
 const [touchMode, setTouchModeState] = useState<TouchInputMode>(loadTouchMode);
 // View only (local): nothing goes to the remote — see setViewOnly. The ref
 // switches at once (input handlers), the state follows for the UI.
 const [viewOnly, setViewOnlyState] = useState(loadViewOnly);
 const viewOnlyRef = useRef(viewOnly);
 const setTouchMode = useCallback((m: TouchInputMode) => {
 setTouchModeState(m);
 saveLocal(TOUCH_MODE_KEY, m);
 }, []);
 // Modifiers latched from the key bar: applied to the next key, typed character or tap.
 const [latched, setLatchedState] = useState<Modifiers>(NO_MODIFIERS);
 const latchedRef = useRef<Modifiers>(NO_MODIFIERS);
 const setLatched = useCallback((m: Modifiers) => { latchedRef.current = m; setLatchedState(m); }, []);
 const touchModCodesRef = useRef<string[]>([]);
 const [inactivityWarn, setInactivityWarn] = useState(false);
 const inactivityWarnRef = useRef(false);
 useEffect(() => { inactivityWarnRef.current = inactivityWarn; }, [inactivityWarn]);
 const hasAudioRef = useRef(false);
 useEffect(() => { hasAudioRef.current = hasAudio; }, [hasAudio]);
 const lastMouseRef = useRef<{ x: number; y: number } | null>(null);

 // ── Clipboard state ───────────────────────────────────────────────────────
 const [clipSync, setClipSyncState] = useState(loadClipSync);
 const clipSyncRef = useRef(clipSync);
 const [clipPanelOpen, setClipPanelOpen] = useState(false);
 const [clipDraft, setClipDraft] = useState('');
 const [remoteClipText, setRemoteClipText] = useState<string | null>(null);
 const [remoteClipTruncated, setRemoteClipTruncated] = useState(false);
 const [clipRefreshing, setClipRefreshing] = useState(false);
 /** Remote text that could not be copied locally without a user gesture. */
 const [clipChip, setClipChip] = useState<string | null>(null);
 const [remoteFiles, setRemoteFiles] = useState<ReachClipboardFile[]>([]);
 const [filesChip, setFilesChip] = useState(false);
 const clipSeqRef = useRef(0);
 /** clipboard_get ids → what the answer is for. */
 const pendingGetRef = useRef<Map<string, 'panel' | 'copy'>>(new Map());
 const lastLocalCopyRef = useRef<string | null>(null);
 /** "Last copy wins" bookkeeping (components/remote/reachClipboard). */
 const clipTrackRef = useRef(newClipSyncState());
 /** Local files already uploaded by a Ctrl+V (same copy pasted twice → the remote pastes). */
 const lastUploadedFilesRef = useRef<string | null>(null);
 /** One hint per viewer when the browser refuses to read the local clipboard. */
 const readRefusedHintedRef = useRef(false);
 /** Local text already reported as too large (no toast on every Ctrl+V). */
 const tooLargeTextRef = useRef<string | null>(null);
 /** Ctrl+V / Shift+Insert whose keydown was held back, waiting for the browser's `paste`. */
 const pasteRef = useRef<{ code: string; key: string; ctrl: boolean; shift: boolean; alt: boolean; meta: boolean; viaMeta: boolean; done: boolean; timer: number } | null>(null);
 /** Codes whose keydown was not forwarded: their key-up is not either. */
 const suppressedUpRef = useRef<Set<string>>(new Set());
 /** Ctrl+C pressed (old agents: fetch the remote clipboard after the key-up). */
 const copyArmedRef = useRef(false);

 // ── File transfer state ───────────────────────────────────────────────────
 const [transfers, setTransfers] = useState<TransferItem[]>([]);
 const [dragOver, setDragOver] = useState(false);
 const transfersRef = useRef<ReachFileTransfers | null>(null);
 if (!transfersRef.current) {
 transfersRef.current = new ReachFileTransfers({
 sendJson: (m) => {
 const ws = wsRef.current;
 if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(m));
 },
 sendBinary: (frame) => {
 const ws = wsRef.current;
 if (ws?.readyState !== WebSocket.OPEN) return false;
 ws.send(frame);
 return true;
 },
 onChange: setTransfers,
 save: (blob, name) => saveBlob(blob, name),
 });
 }

 const fpsCountRef = useRef(0);
 const fpsTimerRef = useRef<ReturnType<typeof setInterval>>(null as any);

 // ── Build WS URL ─────────────────────────────────────────────────────────────
 const wsUrl = (() => {
 if (!sessionToken) return null;
 if (relayHost && viewerToken) {
 return `${relayHost.replace(/\/$/, '')}/relay/ws?role=viewer&token=${encodeURIComponent(viewerToken)}`;
 }
 const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
 return `${proto}//${window.location.host}/api/remote/tunnel/${sessionToken}`;
 })();

 // ── Raw send ──────────────────────────────────────────────────────────────
 const sendRaw = useCallback((obj: object) => {
 const ws = wsRef.current;
 if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
 }, []);

 const clearConnectTimer = useCallback(() => {
 if (connectTimerRef.current) {
 clearTimeout(connectTimerRef.current);
 connectTimerRef.current = null;
 }
 }, []);

 const clearPictureTimer = useCallback(() => {
 if (pictureTimerRef.current) {
 clearTimeout(pictureTimerRef.current);
 pictureTimerRef.current = null;
 }
 }, []);

 /** The agent's relay socket paired: stop the launch timeout. `paired` only
 * means the agent dialled the relay — the capture helper may still fail
 * to start in the session, so a second timer waits for init / a picture. */
 const markPaired = useCallback(() => {
 if (pairedRef.current) return;
 pairedRef.current = true;
 clearConnectTimer();
 if (answeredRef.current) return;
 clearPictureTimer();
 const ws = wsRef.current;
 const vm = kindRef.current === 'vmconsole';
 pictureTimerRef.current = setTimeout(() => {
 pictureTimerRef.current = null;
 if (!ws || wsRef.current !== ws || answeredRef.current) return;
 noRetryRef.current = true;
 setStatus('error');
 setErrorMsg(vm
 ? t('reach.vmConsole.noPicture', 'Connected to the host, but the VM console sent no picture.')
 : t('reach.err.noPicture', 'Connected to the agent, but no picture arrived: the capture did not start in the remote session.'));
 quietCloseRef.current.add(ws);
 try { ws.close(); } catch { /* ignore */ }
 }, vm ? NO_PICTURE_TIMEOUT_VMCONSOLE_MS : NO_PICTURE_TIMEOUT_MS);
 }, [clearConnectTimer, clearPictureTimer, setStatus, t]);

 /** The agent itself answered (init / session_state / picture / error): stop both timers. */
 const markAgentAlive = useCallback(() => {
 markPaired();
 if (answeredRef.current) return;
 answeredRef.current = true;
 clearPictureTimer();
 }, [markPaired, clearPictureTimer]);

 // ── VideoDecoder ──────────────────────────────────────────────────────────
 const configureDecoder = useCallback((codecName: string, width: number, height: number, extradata?: string) => {
 try { decoderRef.current?.close(); } catch { /* already closed */ }
 decoderRef.current = null;
 decoderCodecRef.current = null;
 decoderStaleRef.current = false;

 const canvas = canvasRef.current;
 if (!canvas) return;
 // Size the canvas to the agent frame so drawImage is 1:1.
 if (canvas.width !== width) canvas.width = width;
 if (canvas.height !== height) canvas.height = height;
 const ctx = canvas.getContext('2d');
 if (!ctx) return;

 if (typeof VideoDecoder === 'undefined') {
 setStatus('error');
 setErrorMsg(t('reach.err.webcodecs', 'WebCodecs not supported in this browser (Chrome/Edge 94+, Firefox 130+).'));
 return;
 }

 const decoder = new VideoDecoder({
 output: (frame: VideoFrame) => {
 fpsCountRef.current++;
 // Follow the DECODED size: older agents switch monitors (or the
 // remote resolution changes) without a new init. The canvas — and
 // the space mouse x,y are sent in — must be the picture's own size,
 // or the image is stretched and every click is offset.
 const size = frameSizeChange({ w: canvas.width, h: canvas.height }, frame);
 if (size) {
 canvas.width = size.w;
 canvas.height = size.h;
 }
 const d = agentDimsRef.current;
 if (d.w !== canvas.width || d.h !== canvas.height) setAgentDims({ w: canvas.width, h: canvas.height });
 ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
 frame.close();
 // Transition to streaming on first decoded frame
 setStatus((prev) => (prev !== 'streaming' ? 'streaming' : prev));
 },
 error: (err) => {
 console.error('[ObliReach] VideoDecoder error:', err);
 if (decoderRef.current === decoder) decoderCodecRef.current = null;
 // A switch in flight: the next keyframe of the codec actually
 // received configures a new decoder (see decoderActionFor).
 if (codecName !== 'h264') return;
 setStatus('error');
 setErrorMsg(t('reach.err.decoder', 'Decoder error: {{msg}}', { msg: String((err as Error).message ?? err) }));
 },
 });

 // H.264 High Profile Level 5.2 — up to 4096×2304 (mosaic) at 60 fps.
 // The agent sends Annex B with inline SPS/PPS; no AVCC description needed.
 let codecStr = decoderCodecString(codecName) ?? 'avc1.640034';
 if (codecName === 'h264' && extradata) {
 // extradata is legacy/reserved — only use it if it looks like a valid
 // AVCC DecoderConfigurationRecord (first byte = configurationVersion = 1).
 try {
 const raw = atob(extradata);
 const buf = new Uint8Array(raw.length);
 for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
 if (buf.length >= 4 && buf[0] === 0x01) {
 const p = buf[1].toString(16).padStart(2, '0');
 const c = buf[2].toString(16).padStart(2, '0');
 const l = buf[3].toString(16).padStart(2, '0');
 codecStr = `avc1.${p}${c}${l}`;
 }
 } catch { /* malformed extradata — ignore */ }
 }

 try {
 decoder.configure({ codec: codecStr, codedWidth: width, codedHeight: height, optimizeForLatency: true });
 decoderRef.current = decoder;
 decoderCodecRef.current = codecName;
 } catch (err) {
 console.error('[ObliReach] VideoDecoder.configure failed:', err);
 try { decoder.close(); } catch { /* ignore */ }
 }
 }, [setStatus, setAgentDims, t]);

 // ── Control messages (always the latest closure: props / state are fresh) ─
 const handleControlRef = useRef<(msg: { type: string; [k: string]: unknown }) => void>(() => {});

 // ── Connect / disconnect ──────────────────────────────────────────────────
 useEffect(() => {
 if (!wsUrl) return;

 let active = true;
 let tsMicros = 0;

 // Per-connection protocol state.
 pairedRef.current = false;
 answeredRef.current = false;
 noRetryRef.current = false;
 preferredSentRef.current = false;
 genRef.current = null;
 decoderStaleRef.current = false;
 droppedButtonsRef.current.clear();
 setSessionState(null);
 setErrorDetail('');
 setErrorCode('');
 // Keepalives only after THIS socket's init lists the feature.
 setKeepaliveOk(false);

 const ws = new WebSocket(wsUrl);
 ws.binaryType = 'arraybuffer';
 wsRef.current = ws;
 let opened = false;

 // Launch timeout: nothing from the agent in time → error with Retry. The
 // deadline belongs to the session token: a same-token reopen (socket cut
 // before pairing, see onclose) keeps the time already spent.
 const launchMs = kindRef.current === 'vmconsole' ? CONNECT_TIMEOUT_VMCONSOLE_MS
 : deliveryRef.current === 'queued' ? CONNECT_TIMEOUT_QUEUED_MS : CONNECT_TIMEOUT_MS;
 if (launchDeadlineRef.current?.url !== wsUrl) {
 launchDeadlineRef.current = { url: wsUrl, at: Date.now() + launchMs };
 reopenCountRef.current = 0;
 }
 const deadline = launchDeadlineRef.current.at;
 clearConnectTimer();
 clearPictureTimer();
 connectTimerRef.current = setTimeout(() => {
 connectTimerRef.current = null;
 if (!active || pairedRef.current) return;
 noRetryRef.current = true;
 setStatus('error');
 setErrorMsg(kindRef.current === 'vmconsole'
 ? t('reach.vmConsole.timeout', 'The host did not open the VM console in time.')
 : deliveryRef.current === 'queued'
 ? t('reach.err.agentOfflineTimeout', 'The ObliReach agent did not come back online in time.')
 : t('reach.err.agentNoAnswer', 'The ObliReach agent did not answer. It may be stopped, or blocked from reaching the server.'));
 quietCloseRef.current.add(ws);
 try { ws.close(); } catch { /* ignore */ }
 }, Math.max(0, deadline - Date.now()));

 ws.onopen = () => {
 if (!active) return;
 opened = true;
 setStatus((prev) => (prev === 'streaming' ? prev : 'waiting'));
 if (reconnectTimerRef.current) {
 clearTimeout(reconnectTimerRef.current);
 reconnectTimerRef.current = null;
 }
 };
 ws.onclose = (ev) => {
 transfersRef.current?.abortAll('disconnected');
 audioRef.current?.reset();
 if (!active) return;
 setKeepaliveOk(false);
 clearConnectTimer();
 clearPictureTimer();
 if (quietCloseRef.current.has(ws)) return;
 // Closed BEFORE the agent paired (a proxy cutting an idle socket while
 // the agent is still on its way, a network blip): the session is still
 // waiting for its agent — reopen the SAME token (the relay keeps it
 // 15 s) instead of ending it and queueing a new one. A refused upgrade
 // never opened: that one takes the normal path below.
 if (opened && !pairedRef.current && !noRetryRef.current
 && reopenCountRef.current < REOPEN_MAX && Date.now() + REOPEN_DELAY_MS < deadline) {
 reopenCountRef.current++;
 console.log(`[reach] ws closed before pairing (code=${ev.code}) — reopening the same session (${reopenCountRef.current}/${REOPEN_MAX})`);
 reconnectTimerRef.current = setTimeout(() => {
 reconnectTimerRef.current = null;
 setReopenTick((n) => n + 1);
 }, REOPEN_DELAY_MS);
 return;
 }
 const pendingState = sessionStateRef.current && sessionStateRef.current.state !== 'live';
 const followsSession = featuresRef.current.has('session_follow');
 const retryFn = onReconnectRef.current;
 const attempt = reconnectAttemptsRef.current;
 // Agents that follow the session themselves (session_follow) close the
 // stream only for good while a session change is pending; never after
 // an error that says retry:false.
 if (retryFn && !noRetryRef.current && !(followsSession && pendingState) && attempt < RECONNECT_BACKOFF_S.length) {
 reconnectAttemptsRef.current = attempt + 1;
 const n = attempt + 1;
 const delay = RECONNECT_BACKOFF_S[attempt] * 1000;
 console.log(`[reach] ws close code=${ev.code} wasClean=${ev.wasClean} — scheduling reconnect ${n}/${RECONNECT_BACKOFF_S.length} in ${delay} ms`);
 setStatus('reconnecting');
 setErrorMsg(t('reach.reconnectingN', 'Reconnecting ({{n}}/{{max}})...', { n, max: RECONNECT_BACKOFF_S.length }));
 reconnectTimerRef.current = setTimeout(() => {
 reconnectTimerRef.current = null;
 retryFn().catch((e) => {
 console.error('[reach] onReconnect threw, giving up:', e);
 if (active) {
 setStatus('disconnected');
 setErrorMsg('');
 }
 });
 }, delay);
 } else if (statusRef.current !== 'error') {
 setStatus('disconnected');
 }
 };
 ws.onerror = () => {
 if (!active) return;
 // Don't flip to 'error' if a reconnect is possible — onclose fires
 // right after and sets 'reconnecting', which is more informative.
 if (!onReconnectRef.current || noRetryRef.current || reconnectAttemptsRef.current >= RECONNECT_BACKOFF_S.length) {
 if (statusRef.current !== 'error') {
 setStatus('error');
 setErrorMsg(t('reach.err.ws', 'WebSocket connection failed'));
 }
 }
 };

 ws.onmessage = (ev) => {
 if (!active) return;

 if (typeof ev.data === 'string') {
 let msg: unknown;
 try { msg = JSON.parse(ev.data); } catch { return; }
 if (msg && typeof msg === 'object' && typeof (msg as { type?: unknown }).type === 'string') {
 try { handleControlRef.current(msg as { type: string }); } catch (err) { console.error('[reach] control message failed', err); }
 }
 return;
 }

 const buf = ev.data as ArrayBuffer;
 if (buf.byteLength < 2) return;
 const frameType = new Uint8Array(buf, 0, 1)[0];

 if (frameType === FRAME.AUDIO_PCM || frameType === FRAME.AUDIO_V2) {
 if (audioEnabledRef.current) audioRef.current?.handleFrame(buf);
 return;
 }
 if (frameType === FRAME.FILE_DOWN) {
 transfersRef.current?.handleBinary(buf);
 return;
 }

 if (frameType === FRAME.JPEG) {
 markAgentAlive();
 reconnectAttemptsRef.current = 0;
 // JPEG frame — decode with createImageBitmap (no WebCodecs needed)
 const blob = new Blob([buf.slice(1)], { type: 'image/jpeg' });
 createImageBitmap(blob).then((bmp) => {
 const canvas = canvasRef.current;
 if (!canvas) return;
 if (canvas.width !== bmp.width || canvas.height !== bmp.height) {
 canvas.width = bmp.width;
 canvas.height = bmp.height;
 setAgentDims({ w: bmp.width, h: bmp.height });
 }
 const ctx = canvas.getContext('2d');
 if (ctx) ctx.drawImage(bmp, 0, 0);
 bmp.close();
 fpsCountRef.current++;
 setStatus((prev) => (prev !== 'streaming' ? 'streaming' : prev));
 }).catch(() => {});
 return;
 }

 const frameCodec = codecOfFrame(frameType);
 if (frameCodec) {
 markAgentAlive();
 reconnectAttemptsRef.current = 0;
 const nalData = buf.slice(1);
 const u8 = new Uint8Array(nalData);
 const isKey = isKeyframe(frameCodec, u8);
 // Decode with the codec actually RECEIVED: an older agent restarts
 // on H.264 after set_monitor while the viewer may still be on VP9 /
 // AV1 / JPEG (the picture froze). A frame of another codec — or the
 // first one after a restart — configures a new decoder at its
 // keyframe; the deltas before it cannot be decoded and are dropped.
 const action = decoderActionFor({
 codec: decoderCodecRef.current,
 state: decoderRef.current?.state ?? null,
 stale: decoderStaleRef.current,
 }, frameCodec, isKey);
 if (action === 'drop') return;
 if (action === 'reconfigure') {
 const d = agentDimsRef.current;
 configureDecoder(frameCodec, d.w, d.h);
 if (codecIdRef.current !== frameCodec) setCodecId(frameCodec);
 }
 const decoder = decoderRef.current;
 if (!decoder || decoder.state !== 'configured') return;
 try {
 decoder.decode(new EncodedVideoChunk({ type: isKey ? 'key' : 'delta', data: nalData, timestamp: tsMicros }));
 tsMicros += Math.round(1_000_000 / 15);
 } catch { /* waiting for a keyframe */ }
 }
 };

 // FPS counter
 fpsTimerRef.current = setInterval(() => {
 setFps(fpsCountRef.current);
 fpsCountRef.current = 0;
 }, 1000);

 return () => {
 active = false;
 clearConnectTimer();
 clearPictureTimer();
 ws.close();
 wsRef.current = null;
 cancelAnimationFrame(rafRef.current);
 clearInterval(fpsTimerRef.current);
 try { decoderRef.current?.close(); } catch {}
 decoderRef.current = null;
 decoderCodecRef.current = null;
 transfersRef.current?.abortAll('disconnected');
 audioRef.current?.reset();
 // Cancel any pending auto-reconnect from the OLD effect run. The new
 // effect (triggered by sessionToken change) starts with a fresh
 // counter unless the reconnect itself scheduled this re-run.
 if (reconnectTimerRef.current) {
 clearTimeout(reconnectTimerRef.current);
 reconnectTimerRef.current = null;
 }
 };
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [wsUrl, reopenTick]);

 // ── Input forwarding ──────────────────────────────────────────────────────
 const sendJson = useCallback((obj: object) => {
 const ws = wsRef.current;
 let out = obj as { type?: string; action?: string; x?: number; y?: number; button?: number; [k: string]: unknown };
 if (out.type === 'mouse') {
 // Mosaic: a press in a black gap between screens never reaches the
 // remote (the agent drops it too), nor its matching release.
 if (out.action === 'down' || out.action === 'up') {
 const btn = typeof out.button === 'number' ? out.button : 0;
 if (out.action === 'down' && typeof out.x === 'number' && typeof out.y === 'number' && isMosaicGap(viewRef.current, out.x, out.y)) {
 droppedButtonsRef.current.add(btn);
 return;
 }
 if (out.action === 'up' && droppedButtonsRef.current.has(btn)) {
 droppedButtonsRef.current.delete(btn);
 return;
 }
 }
 // View generation: a move / press aimed at the previous layout is
 // dropped by the agent after a view change (a release never is).
 if (genRef.current != null && featuresRef.current.has('view_gen')) out = { ...out, gen: genRef.current };
 if (out.action !== 'scroll' && typeof out.x === 'number' && typeof out.y === 'number') {
 lastMouseRef.current = { x: out.x, y: out.y };
 }
 }
 if (ws?.readyState === WebSocket.OPEN) {
 ws.send(JSON.stringify(out));
 // Any input resets the relay's inactivity timer: drop the warning
 // banner shown over the screen (touch screens / narrow windows) instead
 // of leaving it over the remote's title bars for the rest of the session.
 if (inactivityWarnRef.current && (out.type === 'mouse' || out.type === 'key')
 && (isCoarseRef.current || !matchesMedia(MEDIA.sm))) {
 inactivityWarnRef.current = false;
 setInactivityWarn(false);
 setErrorMsg('');
 }
 }
 }, []);

 // ── Touch helpers ─────────────────────────────────────────────────────────
 // Take (and clear) the modifiers latched in the key bar.
 const consumeLatched = useCallback((): Modifiers => {
 const m = latchedRef.current;
 if (hasModifier(m)) setLatched(NO_MODIFIERS);
 return m;
 }, [setLatched]);

 // Remote audio needs an AudioContext created / resumed inside a user
 // gesture on mobile (autoplay policy): do it on the first taps and on the
 // audio toggle.
 const ensureAudio = useCallback(() => {
 if (!hasAudioRef.current || !audioEnabledRef.current) return;
 audioRef.current?.ensureContext();
 }, []);

 // Latched modifiers wrap a touch click (Ctrl+click, Shift+click…).
 const handleTouchButton = useCallback((phase: 'down' | 'up') => {
 if (phase === 'down') {
 const m = consumeLatched();
 const codes = activeModifiers(m).map((k) => MODIFIER_CODES[k]);
 touchModCodesRef.current = codes;
 for (const code of codes) sendJson({ type: 'key', action: 'down', code, key: '', ...modifierFlags(m) });
 } else {
 const codes = touchModCodesRef.current;
 touchModCodesRef.current = [];
 for (const code of [...codes].reverse()) sendJson({ type: 'key', action: 'up', code, key: '', ...modifierFlags(NO_MODIFIERS) });
 }
 }, [consumeLatched, sendJson]);

 const handleTouchStart = useCallback(() => {
 ensureAudio();
 // Keep hardware (Bluetooth) keyboards working after a tap, but never
 // steal the focus from the soft-keyboard field (that would close it).
 if (!softKbRef.current?.isFocused()) rootRef.current?.focus({ preventScroll: true });
 }, [ensureAudio]);

 // Mouse: unchanged forwarding. Touch: gestures (tap, long-press, two-finger
 // scroll, pinch zoom, trackpad mode) — see components/remote/useRemotePointer.
 // View only: no pointer message leaves (the hook's own guard follows the
 // next render; this one switches with the click).
 const sendPointer = useCallback((msg: object) => {
 if (!viewOnlyRef.current) sendJson(msg);
 }, [sendJson]);
 const pointer = useRemotePointer({
 canvasRef,
 agentDims,
 send: sendPointer,
 viewOnly,
 // Trackpad mode is a touch-screen option: a fine-pointer session (e.g. a
 // docked 2-in-1 that saved "trackpad" earlier) never gets its static cursor.
 touchMode: isCoarse ? touchMode : 'direct',
 onTouchButton: handleTouchButton,
 onTouchStart: handleTouchStart,
 });

 // Physical keys sent DOWN to the remote and not released yet. A key-up the
 // viewer never receives (focus leaves the page: clipboard permission prompt
 // on Ctrl+V, Ctrl+Tab, Alt+Tab, a click outside…) used to leave the key —
 // typically Ctrl — pressed on the remote, turning every later letter into a
 // shortcut. They are released when focus leaves, and a modifier the browser
 // reports as up is released before the next key goes out.
 const heldKeysRef = useRef<Set<string>>(new Set());
 // Windowed mode: a Windows-key press waiting for the key that goes with it.
 const pendingMetaRef = useRef<string | null>(null);
 const releaseHeldKeys = useCallback(() => {
 const held = [...heldKeysRef.current];
 if (held.length === 0) return;
 heldKeysRef.current.clear();
 pendingMetaRef.current = null;
 for (const code of held.reverse()) sendJson({ type: 'key', action: 'up', code, key: '', ...modifierFlags(NO_MODIFIERS) });
 }, [sendJson]);

 useEffect(() => {
 const root = rootRef.current;
 // Leaving the page is also when a local copy can happen (clipboard "last copy wins").
 const onBlur = () => { releaseHeldKeys(); notePageLeft(clipTrackRef.current); };
 const onVisibility = () => {
 if (document.visibilityState !== 'hidden') return;
 releaseHeldKeys();
 notePageLeft(clipTrackRef.current);
 };
 const onFocusOut = (ev: FocusEvent) => {
 const next = ev.relatedTarget as Node | null;
 if (!next || !root?.contains(next)) releaseHeldKeys();
 };
 window.addEventListener('blur', onBlur);
 document.addEventListener('visibilitychange', onVisibility);
 root?.addEventListener('focusout', onFocusOut);
 return () => {
 window.removeEventListener('blur', onBlur);
 document.removeEventListener('visibilitychange', onVisibility);
 root?.removeEventListener('focusout', onFocusOut);
 releaseHeldKeys();
 };
 }, [releaseHeldKeys]);

 // Ctrl + wheel over the viewer zooms the REMOTE, not the browser page.
 // React's onWheel listener is passive (its preventDefault is ignored), so a
 // native non-passive listener blocks the browser zoom here. When Ctrl is not
 // already held on the remote (keyboard focus elsewhere), it is pressed around
 // the scroll that useRemotePointer sends right after this listener.
 useEffect(() => {
 const root = rootRef.current;
 if (!root) return;
 const onWheel = (ev: WheelEvent) => {
 if (!ev.ctrlKey) return;
 ev.preventDefault();
 // View only: Ctrl+wheel zooms the picture locally (useRemotePointer), nothing is sent.
 if (viewOnlyRef.current) return;
 const held = heldKeysRef.current;
 if (held.has('ControlLeft') || held.has('ControlRight')) return;
 sendJson({ type: 'key', action: 'down', code: 'ControlLeft', key: '', ctrl: true, shift: ev.shiftKey, alt: ev.altKey, meta: false });
 // After React's wheel handler (root listener, runs once this dispatch ends).
 setTimeout(() => sendJson({ type: 'key', action: 'up', code: 'ControlLeft', key: '', ctrl: false, shift: false, alt: false, meta: false }), 0);
 };
 root.addEventListener('wheel', onWheel, { passive: false });
 return () => root.removeEventListener('wheel', onWheel);
 }, [sendJson]);

 // Send an arbitrary chord by physical key code. Presses every code down in
 // order, then releases in reverse — exactly how a real key combo fires.
 // `key:''` forces the agent's physical-code path (codeToVK) so combos map
 // by position, immune to the browser's keyboard layout (Win+R lands on the
 // remote's R regardless of AZERTY/QWERTZ). The modifier flags are derived
 // from the codes so the agent's SAS detection + any flag-based logic stay
 // consistent.
 const sendKeyChord = useCallback((codes: string[]) => {
 if (!codes.length) return;
 const mods = {
 ctrl: codes.some((c) => c.startsWith('Control')),
 alt: codes.some((c) => c.startsWith('Alt')),
 shift: codes.some((c) => c.startsWith('Shift')),
 meta: codes.some((c) => c.startsWith('Meta')),
 };
 for (const code of codes) {
 sendJson({ type: 'key', action: 'down', code, key: '', ...mods });
 }
 setTimeout(() => {
 for (const code of [...codes].reverse()) {
 sendJson({ type: 'key', action: 'up', code, key: '', ...mods });
 }
 }, 40);
 setSysKeysOpen(false);
 }, [sendJson]);

 // ── Clipboard ─────────────────────────────────────────────────────────────
 // Agents without `features` (every agent in the field before this
 // protocol) have NO working clipboard: on Windows the capture helper drops
 // clipboard_set / clipboard_get, and on Linux / macOS clipboardSet is a
 // no-op. 'legacy' therefore means "not supported, update the agent": no
 // text is sent and no Ctrl+V is ever injected after an unconfirmed set.
 const clipboardSupport: ReachClipboardSupport = !modernAgent
 ? 'legacy'
 : features.has('clipboard_text') ? 'full' : 'none';
 const clipboardSupportRef = useRef(clipboardSupport);
 clipboardSupportRef.current = clipboardSupport;
 /** A Mac operator's Cmd shortcuts become Ctrl ones only for a Windows target (unknown = Windows). */
 const cmdAsCtrl = () => isMacPlatform() && (!remoteOsRef.current || remoteOsRef.current === 'windows');

 /**
 * Local text → remote clipboard (agents with clipboard_text only). `paste`:
 * the agent pastes it itself once set — the viewer never injects a Ctrl+V
 * after a set. False when not sent (unsupported, too large).
 */
 const sendClipboardText = useCallback((text: string, paste: boolean, opts: { quiet?: boolean } = {}): boolean => {
 if (!featuresRef.current.has('clipboard_text')) return false;
 if (JSON.stringify(text).length > CLIP_MAX_JSON) {
 if (!opts.quiet) toast.error(t('reach.clip.tooLarge', 'Text too large for the remote clipboard (1 MB max)'));
 return false;
 }
 const id = `c${++clipSeqRef.current}`;
 sendJson(paste ? { type: 'clipboard_set', text, id, paste: true } : { type: 'clipboard_set', text, id });
 noteLocalSent(clipTrackRef.current, text);
 return true;
 }, [sendJson, t]);

 /** Ctrl+V is held back (to send the local clipboard first) only with sync on and an agent that can use it. */
 const pasteInterceptOn = () => clipSyncRef.current
 && (featuresRef.current.has('clipboard_text') || featuresRef.current.has('file_upload'));

 /** Ask the agent for its clipboard (answer: clipboard_content with this id). */
 const requestRemoteClipboard = useCallback((purpose: 'panel' | 'copy') => {
 const id = `g${++clipSeqRef.current}`;
 pendingGetRef.current.set(id, purpose);
 setTimeout(() => { if (pendingGetRef.current.delete(id)) setClipRefreshing(false); }, 5000);
 if (purpose === 'panel') setClipRefreshing(true);
 sendJson({ type: 'clipboard_get', id });
 }, [sendJson]);

 /** Remote text → local clipboard. Only the async Clipboard API is tried
 * here (secure context, focused page): the execCommand fallback moves the
 * focus to a hidden field, which would release the keys held on the remote.
 * Refused → a "Copy" chip (a click is the user gesture the browser wants). */
 const copyRemoteToLocal = useCallback((text: string) => {
 if (!text) return;
 const clip = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
 if (!window.isSecureContext || !clip?.writeText) { setClipChip(text); return; }
 clip.writeText(text).then(() => {
 lastLocalCopyRef.current = text;
 setClipChip(null);
 }, () => setClipChip(text));
 }, []);

 const setClipSync = useCallback((on: boolean) => {
 clipSyncRef.current = on;
 setClipSyncState(on);
 saveLocal(CLIP_SYNC_KEY, on ? 'on' : 'off');
 if (featuresRef.current.has('clipboard_push')) sendJson({ type: 'clipboard_sync', push: on });
 }, [sendJson]);

 /** Replays the paste keys once the remote clipboard holds the text (clipboard_set goes first, in order). */
 const sendPasteKeys = useCallback((p: NonNullable<typeof pasteRef.current>) => {
 const held = heldKeysRef.current;
 if (p.viaMeta) {
 // macOS Cmd+V: a Windows remote wants Ctrl+V (a Windows key held there
 // would make it Win+Ctrl+V); a macOS remote keeps Cmd+V.
 for (const code of [...held]) {
 if (code.startsWith('Meta')) {
 held.delete(code);
 sendJson({ type: 'key', action: 'up', code, key: '', ...modifierFlags(NO_MODIFIERS) });
 }
 }
 sendKeyChord(cmdAsCtrl() ? ['ControlLeft', 'KeyV'] : ['MetaLeft', 'KeyV']);
 return;
 }
 const modHeld = p.code === 'Insert'
 ? [...held].some((c) => c.startsWith('Shift'))
 : [...held].some((c) => c.startsWith('Control'));
 if (!modHeld) {
 // The modifier was released meanwhile (slow fallback path): full chord.
 sendKeyChord(p.code === 'Insert' ? ['ShiftLeft', 'Insert'] : ['ControlLeft', 'KeyV']);
 return;
 }
 const flags = { ctrl: p.ctrl, shift: p.shift, alt: p.alt, meta: false };
 sendJson({ type: 'key', action: 'down', code: p.code, key: p.key, ...flags });
 sendJson({ type: 'key', action: 'up', code: p.code, key: p.key, ...flags });
 }, [sendJson, sendKeyChord]);

 /** Why file transfers are refused in this session (init.filesPolicy). */
 const filesDeniedMessage = useCallback((r: ReachFilesDenied): string => {
 if (r === 'capability') {
 return t('reach.files.denied.capability', "File transfers are disabled: your account does not have the 'Files' permission on this device.");
 }
 if (r === 'restriction') {
 return t('reach.files.denied.restriction', 'File transfers are disabled: your organization restricts file transfers on this device, and a remote session cannot ask for the confirmation or approval they require.');
 }
 if (r === 'privacy') {
 return t('reach.files.denied.privacy', 'File transfers are disabled: privacy mode is on for this device. Unlock the file explorer (device password) on the device page, then reconnect.');
 }
 return t('reach.files.denied.other', 'File transfers are not permitted in this session.');
 }, [t]);

 const uploadFiles = useCallback((files: ArrayLike<File>) => {
 if (!files.length) return;
 if (filesDeniedRef.current) {
 toast.error(filesDeniedMessage(filesDeniedRef.current));
 return;
 }
 if (!featuresRef.current.has('file_upload')) {
 toast.error(t('reach.files.unsupported', 'This ObliReach agent cannot receive files (update it, and make sure a user is signed in).'));
 return;
 }
 transfersRef.current?.enqueueUploads(files);
 }, [t, filesDeniedMessage]);

 /**
 * The local clipboard was read (or not: `text` null) for a held-back Ctrl+V.
 * Its text goes to the remote clipboard only when sync is on, the agent
 * supports it and it is newer than what the remote has ("last copy wins",
 * see reachClipboard). The paste keys are ALWAYS forwarded afterwards —
 * read refused, too large or nothing to send: the remote then pastes its
 * own clipboard, as without the viewer's help.
 */
 const finishPaste = useCallback((p: NonNullable<typeof pasteRef.current>, text: string | null) => {
 // View only turned on meanwhile (setViewOnly cancels the pending paste): nothing more goes out.
 if (viewOnlyRef.current) return;
 const canSend = clipSyncRef.current && featuresRef.current.has('clipboard_text');
 if (text === null) {
 if (canSend && !readRefusedHintedRef.current) {
 readRefusedHintedRef.current = true;
 toast(t('reach.clip.readRefusedHint', 'The browser does not let the viewer read your clipboard here: the remote computer pasted its own clipboard. To send text, use the clipboard panel.'), { duration: 7000 });
 }
 } else if (canSend && pasteDecision(clipTrackRef.current, text) === 'send') {
 if (!sendClipboardText(text, false, { quiet: true }) && tooLargeTextRef.current !== text) {
 tooLargeTextRef.current = text;
 toast.error(t('reach.clip.tooLargePaste', 'Your clipboard is too large to be sent (1 MB max): the remote computer pasted its own clipboard.'));
 }
 }
 sendPasteKeys(p);
 }, [sendClipboardText, sendPasteKeys, t]);

 // Ctrl+V (sync on, agent that can use it): the keydown is held back and
 // NOT prevented, so the browser fires `paste` with the local clipboard —
 // readable without any permission, even on plain http. The text goes to
 // the remote clipboard first (when newer), then V.
 useEffect(() => {
 const onPaste = (ev: ClipboardEvent) => {
 const p = pasteRef.current;
 if (!p || p.done) return;
 // A paste into a field of a panel (portal) is not for the remote.
 const target = ev.target as Node | null;
 const root = rootRef.current;
 if (target && root && !root.contains(target) && target !== document.body && target !== document.documentElement) return;
 ev.preventDefault();
 p.done = true;
 window.clearTimeout(p.timer);
 pasteRef.current = null;
 const dt = ev.clipboardData;
 const files = dt?.files ? Array.from(dt.files) : [];
 const text = dt?.getData('text/plain') ?? '';
 if (files.length > 0 && featuresRef.current.has('file_upload')) {
 // Files copied locally go to the remote Downloads folder — once per
 // copy, and never over a newer copy made in the session.
 const sig = filesSignature(files);
 if (pasteFilesDecision(clipTrackRef.current, sig, lastUploadedFilesRef.current) === 'upload') {
 lastUploadedFilesRef.current = sig;
 uploadFiles(files);
 if (!text) return; // files only: nothing to paste as text
 }
 } else if (files.length > 0 && !text && filesDeniedRef.current) {
 // Files are not permitted in this session: said once per copy; the
 // remote then pastes its own clipboard, as without the viewer.
 const sig = filesSignature(files);
 if (lastDeniedFilesRef.current !== sig) {
 lastDeniedFilesRef.current = sig;
 toast.error(filesDeniedMessage(filesDeniedRef.current));
 }
 }
 finishPaste(p, text);
 };
 document.addEventListener('paste', onPaste);
 return () => document.removeEventListener('paste', onPaste);
 }, [finishPaste, uploadFiles, filesDeniedMessage]);

 const startPaste = useCallback((e: React.KeyboardEvent, viaMeta: boolean) => {
 const prev = pasteRef.current;
 if (prev) window.clearTimeout(prev.timer);
 const p = {
 code: e.code, key: e.key, ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey,
 viaMeta, done: false, timer: 0,
 };
 pasteRef.current = p;
 // No `paste` event (Safari, some WebViews): try the async API; the keys
 // go out whatever it answers.
 p.timer = window.setTimeout(() => {
 if (p.done) return;
 p.done = true;
 if (pasteRef.current === p) pasteRef.current = null;
 readClipboardText()
 .then((text) => finishPaste(p, text))
 .catch(() => finishPaste(p, null));
 }, PASTE_EVENT_WAIT_MS);
 }, [finishPaste]);

 // ── Keyboard ──────────────────────────────────────────────────────────────
 const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
 // Keys typed in portalled overlays (tools sheet) are not for the remote.
 if (!rootRef.current?.contains(e.target as Node)) return;
 // View only: the keyboard stays here (not prevented: local shortcuts work).
 if (viewOnlyRef.current) return;
 // Soft keyboards send keyCode 229 / 'Unidentified' while composing: the
 // hidden text field turns those into text (SoftKeyboardInput).
 if (e.key === 'Unidentified' || e.keyCode === 229 || e.nativeEvent.isComposing) return;

 // Paste: the LOCAL platform's shortcut only — Cmd+V on a Mac, Ctrl+V /
 // Shift+Insert elsewhere. (Win+V on Windows is the remote's clipboard
 // history, a Mac's Control+V is no paste: both go through untouched.)
 const mac = isMacPlatform();
 const isV = e.code === 'KeyV' || e.key.toLowerCase() === 'v';
 const pasteCombo = mac
 ? (e.metaKey && !e.ctrlKey && !e.altKey && isV)
 : ((e.ctrlKey && !e.altKey && !e.metaKey && isV)
 || (e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey && e.code === 'Insert'));
 if (pasteCombo && pasteInterceptOn()) {
 // Held back, NOT prevented: the browser fires `paste` (see startPaste).
 if (mac) pendingMetaRef.current = null; // Cmd is replayed by sendPasteKeys
 suppressedUpRef.current.add(e.code);
 if (!e.repeat) startPaste(e, mac);
 return;
 }

 e.preventDefault();
 // macOS operator on a Windows target: Cmd+C / X / V act as Ctrl+C / X / V
 // there (a macOS target keeps Cmd, a Linux one gets Super — never Ctrl+C,
 // which would interrupt the command running in a terminal).
 if (cmdAsCtrl() && e.metaKey && !e.ctrlKey && !e.altKey && pendingMetaRef.current
 && (e.code === 'KeyC' || e.code === 'KeyX' || e.code === 'KeyV')) {
 pendingMetaRef.current = null;
 suppressedUpRef.current.add(e.code);
 if (e.code === 'KeyC') copyArmedRef.current = true;
 if (e.code === 'KeyV') {
 // Paste without the clipboard sync: the remote pastes its own clipboard.
 if (!e.repeat) sendPasteKeys({ code: e.code, key: e.key, ctrl: false, shift: false, alt: false, meta: true, viaMeta: true, done: true, timer: 0 });
 return;
 }
 sendKeyChord(['ControlLeft', e.code]);
 return;
 }
 // The physical Windows key outside the keyboard lock (windowed mode): the
 // local OS keeps the shortcuts it owns (Win+R opens the LOCAL Run dialog)
 // and the key-up never reaches the page, so forwarding the press at once
 // left Win pressed on the remote (every later letter became a Win+letter
 // shortcut). The press is held back and only sent together with a key the
 // page does receive while Win is down; shortcuts the OS keeps stay local.
 // Fullscreen (keyboard lock) forwards it normally — except a Mac's Cmd
 // on a Windows target, whose Cmd+C / X / V become Ctrl ones (a Win press
 // released alone would open the remote Start menu); the toolbar's system
 // keys (Win, Win+R, Win+E…) always work.
 if (e.code.startsWith('Meta') && (!keyboardLockedRef.current || cmdAsCtrl())) {
 pendingMetaRef.current = e.code;
 return;
 }
 if (pendingMetaRef.current) {
 const meta = pendingMetaRef.current;
 pendingMetaRef.current = null;
 if (e.metaKey) {
 sendJson({ type: 'key', action: 'down', code: meta, key: '', ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: true });
 heldKeysRef.current.add(meta);
 }
 }
 // A modifier still held on the remote while the browser says it is up
 // lost its key-up: release it before this key goes out.
 for (const held of [...heldKeysRef.current]) {
 const stale = (held.startsWith('Control') && !e.ctrlKey) || (held.startsWith('Shift') && !e.shiftKey)
 || (held.startsWith('Alt') && !e.altKey) || (held.startsWith('Meta') && !e.metaKey);
 if (stale) {
 heldKeysRef.current.delete(held);
 sendJson({ type: 'key', action: 'up', code: held, key: '', ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey });
 }
 }
 // Ctrl+C: forwarded as is. Agents with clipboard push send the new
 // remote text by themselves; the others are asked after the key-up.
 if ((e.ctrlKey || e.metaKey) && e.code === 'KeyC') copyArmedRef.current = true;
 // Soft keyboards report named keys (Enter, Backspace…) without a code.
 const code = e.code || KEY_TO_CODE[e.key] || '';
 sendJson({ type: 'key', action: 'down', code, key: e.key,
 ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey });
 if (code) heldKeysRef.current.add(code);
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [sendJson, sendKeyChord, sendPasteKeys, startPaste]);

 /** After Ctrl+C in the session: agents without clipboard push are asked for the new text. */
 const afterRemoteCopy = useCallback(() => {
 if (!clipSyncRef.current || !featuresRef.current.has('clipboard_text') || featuresRef.current.has('clipboard_push')) return;
 setTimeout(() => requestRemoteClipboard('copy'), 300);
 }, [requestRemoteClipboard]);

 const handleKeyUp = useCallback((e: React.KeyboardEvent) => {
 if (!rootRef.current?.contains(e.target as Node)) return;
 // View only: what was held on the remote was released when it turned on.
 if (viewOnlyRef.current) return;
 if (e.key === 'Unidentified' || e.keyCode === 229 || e.nativeEvent.isComposing) return;
 const code = e.code || KEY_TO_CODE[e.key] || '';
 // The key-up of a key whose press was not forwarded (paste, Cmd+C).
 if (suppressedUpRef.current.delete(code)) {
 if (code === 'KeyC' && copyArmedRef.current) {
 copyArmedRef.current = false;
 afterRemoteCopy();
 }
 return;
 }
 e.preventDefault();
 // Windows key never forwarded down outside the keyboard lock: nothing to
 // release on the remote, only the keys typed while it was held (macOS).
 if (code.startsWith('Meta') && !heldKeysRef.current.has(code)) { pendingMetaRef.current = null; releaseHeldKeys(); return; }
 sendJson({ type: 'key', action: 'up', code, key: e.key,
 ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey });
 heldKeysRef.current.delete(code);
 if (code === 'KeyC' && copyArmedRef.current) {
 copyArmedRef.current = false;
 // Agents without clipboard push: fetch the remote clipboard.
 afterRemoteCopy();
 }
 // Browsers (macOS above all) do not deliver the key-ups of keys typed
 // while the Windows / Cmd key was held: release whatever is left.
 if (code.startsWith('Meta')) releaseHeldKeys();
 }, [sendJson, releaseHeldKeys, afterRemoteCopy]);

 const handleCtrlAltDel = useCallback(() => {
 const keys = [
 { code: 'ControlLeft', ctrl: true },
 { code: 'AltLeft', ctrl: true, alt: true },
 { code: 'Delete', ctrl: true, alt: true },
 ];
 for (const k of keys) sendJson({ type: 'key', action: 'down', ...k });
 setTimeout(() => {
 for (const k of [...keys].reverse()) sendJson({ type: 'key', action: 'up', ...k });
 }, 50);
 }, [sendJson]);

 const handleFullscreen = useCallback(() => {
 // Touch screens: a remote desktop is landscape — try to lock the
 // orientation once fullscreen (only allowed there; ignored elsewhere).
 const orientation = (typeof screen !== 'undefined' ? screen.orientation : undefined) as
 (ScreenOrientation & { lock?: (o: string) => Promise<void> }) | undefined;
 if (!isFullscreen) {
 const p = document.documentElement.requestFullscreen?.();
 p?.then?.(() => {
 if (isCoarseRef.current) orientation?.lock?.('landscape')?.catch?.(() => {});
 })?.catch?.(() => {});
 } else {
 try { if (isCoarseRef.current) orientation?.unlock?.(); } catch { /* not locked */ }
 document.exitFullscreen?.()?.catch?.(() => {});
 }
 setIsFullscreen(!isFullscreen);
 }, [isFullscreen]);

 // Keep the fullscreen state in sync when the browser leaves fullscreen by
 // itself (Esc, F11, WebView without fullscreen support).
 // In fullscreen, Chromium browsers can hand the Windows key, Alt+Tab, Esc…
 // to the page (Keyboard Lock API): only then is the physical Windows key
 // forwarded to the remote (see handleKeyDown).
 // View only: the system keys stay with this computer (no keyboard lock).
 const syncKeyboardLock = useCallback(() => {
 const kb = (navigator as Navigator & { keyboard?: { lock?: () => Promise<void>; unlock?: () => void } }).keyboard;
 if (document.fullscreenElement && !viewOnlyRef.current) {
 kb?.lock?.()?.then?.(() => { keyboardLockedRef.current = !viewOnlyRef.current; })?.catch?.(() => { keyboardLockedRef.current = false; });
 } else {
 keyboardLockedRef.current = false;
 try { kb?.unlock?.(); } catch { /* not locked */ }
 }
 }, []);
 useEffect(() => {
 const kb = (navigator as Navigator & { keyboard?: { lock?: () => Promise<void>; unlock?: () => void } }).keyboard;
 const onChange = () => {
 setIsFullscreen(!!document.fullscreenElement);
 syncKeyboardLock();
 };
 document.addEventListener('fullscreenchange', onChange);
 return () => {
 document.removeEventListener('fullscreenchange', onChange);
 keyboardLockedRef.current = false;
 try { kb?.unlock?.(); } catch { /* not locked */ }
 };
 }, [syncKeyboardLock]);

 // ── View only (local) ─────────────────────────────────────────────────────
 // Off by default, remembered per browser. While on, the picture is only
 // watched: no mouse move / click / wheel and no key (physical keyboard,
 // soft keyboard, key bar) reaches the remote, and fullscreen does not
 // capture the system keys; nothing at all is sent to the agent for it.
 // Ctrl+wheel / pinch zoom the picture locally (a drag / the wheel pan it),
 // the local cursor moves freely. Toolbar actions (Ctrl+Alt+Del, system
 // keys, clipboard panel, files) are explicit clicks and still work.
 // Turning it on first releases everything still pressed on the remote.
 const { releasePressed: releasePointer, resetView: resetPointerView } = pointer;
 const setViewOnly = useCallback((on: boolean) => {
 if (on === viewOnlyRef.current) return;
 if (on) {
 releasePointer();
 releaseHeldKeys();
 // A Ctrl+V waiting for the local clipboard is dropped.
 const p = pasteRef.current;
 if (p) { p.done = true; window.clearTimeout(p.timer); pasteRef.current = null; }
 suppressedUpRef.current.clear();
 copyArmedRef.current = false;
 } else if (!isCoarseRef.current) {
 // A mouse has no zoom / pan outside view only: back to the whole picture.
 resetPointerView();
 }
 viewOnlyRef.current = on;
 setViewOnlyState(on);
 saveLocal(VIEW_ONLY_KEY, on ? 'on' : 'off');
 syncKeyboardLock();
 toast.success(on
 ? t('reach.viewOnlyOn', 'View only: the mouse and keyboard stay on this computer.')
 : t('reach.viewOnlyOff', 'You control the remote again.'), { id: 'reach-view-only' });
 }, [releasePointer, releaseHeldKeys, resetPointerView, syncKeyboardLock, t]);

 const handleClose = useCallback(() => {
 if (mediaRecorderRef.current?.state === 'recording') {
 mediaRecorderRef.current.stop();
 }
 audioRef.current?.close();
 if (wsRef.current) quietCloseRef.current.add(wsRef.current);
 wsRef.current?.close();
 onClose();
 }, [onClose]);

 /** Retry = a NEW session on the same target (the parent ends the old one). */
 const retryNow = useCallback(() => {
 const fn = onReconnectRef.current;
 if (!fn) return;
 if (reconnectTimerRef.current) { clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = null; }
 reconnectAttemptsRef.current = 0;
 noRetryRef.current = false;
 const ws = wsRef.current;
 if (ws) { quietCloseRef.current.add(ws); try { ws.close(); } catch { /* ignore */ } }
 setSessionState(null);
 setErrorMsg('');
 setErrorDetail('');
 setErrorCode('');
 setStatus('connecting');
 fn().catch((err) => {
 console.error('[reach] retry failed:', err);
 setStatus('error');
 setErrorMsg(t('reach.err.retryFailed', 'Could not start a new session.'));
 });
 }, [setSessionState, setStatus, t]);

 const handleCodecSwitch = useCallback((newCodec: string) => {
 sendJson({ type: 'set_codec', codec: newCodec });
 }, [sendJson]);

 // ── View: one screen / mosaic ──────────────────────────────────────────────
 const canMosaic = features.has('mosaic') && monitors.length > 1;
 const inMosaic = view?.mode === 'mosaic';

 const armViewPending = useCallback(() => {
 setViewPending(true);
 if (viewPendingTimerRef.current) clearTimeout(viewPendingTimerRef.current);
 viewPendingTimerRef.current = setTimeout(() => setViewPending(false), 15_000);
 }, []);

 const handleMonitorSwitch = useCallback((idx: number) => {
 setActiveMonitor(idx);
 if (featuresRef.current.has('mosaic') || featuresRef.current.has('view_gen')) {
 armViewPending();
 sendJson({ type: 'set_view', mode: 'monitor', index: idx });
 } else {
 // Older agents restart the capture (and OpenH264) on the new screen
 // without a new init: start a fresh decoder at the next keyframe —
 // its decoded size then resizes the canvas (reachVideo).
 decoderStaleRef.current = true;
 sendJson({ type: 'set_monitor', index: idx });
 }
 saveLocal(VIEW_MODE_KEY, 'monitor');
 }, [armViewPending, sendJson]);

 const enterMosaic = useCallback(async () => {
 armViewPending();
 // The largest frame the local decoder accepts (H.264 first: every init
 // restarts on it, then the sticky codec comes back through codec_switch).
 const codecs = Array.from(new Set([decoderCodecString('h264'), decoderCodecString(codecIdRef.current)].filter((c): c is string => !!c)));
 const vd = typeof VideoDecoder !== 'undefined' && typeof VideoDecoder.isConfigSupported === 'function'
 ? (cfg: VideoDecoderConfig) => VideoDecoder.isConfigSupported(cfg)
 : null;
 const budget = await probeMosaicBudget(codecs, vd);
 sendJson({ type: 'set_view', mode: 'mosaic', ...budget });
 saveLocal(VIEW_MODE_KEY, 'mosaic');
 }, [armViewPending, sendJson]);

 const toggleMosaic = useCallback(() => {
 if (viewRef.current?.mode === 'mosaic') {
 const back = monitors.find((m) => m.primary)?.index ?? monitors[0]?.index ?? 0;
 handleMonitorSwitch(back);
 } else {
 void enterMosaic();
 }
 }, [enterMosaic, handleMonitorSwitch, monitors]);

 const handleInputBlock = useCallback(() => {
 sendJson({ type: 'set_input_block', block: !inputBlocked });
 }, [sendJson, inputBlocked]);

 const handleScreenshot = useCallback(() => {
 const canvas = canvasRef.current;
 if (!canvas) return;
 canvas.toBlob((blob) => {
 if (!blob) return;
 saveBlob(blob, `oblireach-screenshot-${new Date().toISOString().replace(/[:.]/g, '-')}.png`, 'image/png')
 .then((ok) => { if (!ok) toast.error(t('reach.saveFailed', 'Could not save the file')); });
 }, 'image/png');
 }, [t]);

 const handleToggleRecording = useCallback(() => {
 if (isRecording) {
 // Stop recording
 mediaRecorderRef.current?.stop();
 setIsRecording(false);
 } else {
 // Start recording
 const canvas = canvasRef.current;
 if (!canvas) return;
 try {
 const stream = canvas.captureStream(15);
 const mr = new MediaRecorder(stream, { mimeType: 'video/webm;codecs=vp9', videoBitsPerSecond: 5_000_000 });
 recordedChunks.current = [];
 mr.ondataavailable = (e) => { if (e.data.size > 0) recordedChunks.current.push(e.data); };
 mr.onstop = () => {
 const blob = new Blob(recordedChunks.current, { type: 'video/webm' });
 recordedChunks.current = [];
 saveBlob(blob, `oblireach-recording-${new Date().toISOString().replace(/[:.]/g, '-')}.webm`, 'video/webm')
 .then((ok) => { if (!ok) toast.error(t('reach.saveFailed', 'Could not save the file')); });
 };
 mr.start(1000); // collect data every second
 mediaRecorderRef.current = mr;
 setIsRecording(true);
 } catch (e) {
 console.error('Recording failed:', e);
 }
 }
 }, [isRecording, t]);

 // ── Soft keyboard / key bar (touch) ───────────────────────────────────────
 const pressKey = useCallback((code: string) => {
 if (viewOnlyRef.current) return;
 const m = consumeLatched();
 sendKeyChord([...activeModifiers(m).map((k) => MODIFIER_CODES[k]), code]);
 }, [consumeLatched, sendKeyChord]);

 const typePlain = useCallback((text: string) => {
 if (viewOnlyRef.current) return;
 const flags = modifierFlags(NO_MODIFIERS);
 for (const ch of Array.from(text)) {
 sendJson({ type: 'key', action: 'down', code: '', key: ch, ...flags });
 sendJson({ type: 'key', action: 'up', code: '', key: ch, ...flags });
 }
 }, [sendJson]);

 // Characters go through the agent's layout-aware `key` path; a latched
 // modifier applies to the first one (Ctrl+C, Alt+F…).
 const typeText = useCallback((text: string) => {
 if (viewOnlyRef.current) return;
 const m = consumeLatched();
 if (!hasModifier(m)) { typePlain(text); return; }
 const [first, ...rest] = Array.from(text);
 const modCodes = activeModifiers(m).map((k) => MODIFIER_CODES[k]);
 const code = codeForChar(first);
 if (code) {
 sendKeyChord([...modCodes, code]);
 } else {
 const flags = modifierFlags(m);
 for (const c of modCodes) sendJson({ type: 'key', action: 'down', code: c, key: '', ...flags });
 sendJson({ type: 'key', action: 'down', code: '', key: first, ...flags });
 sendJson({ type: 'key', action: 'up', code: '', key: first, ...flags });
 for (const c of [...modCodes].reverse()) sendJson({ type: 'key', action: 'up', code: c, key: '', ...modifierFlags(NO_MODIFIERS) });
 }
 // After the chord's release (sendKeyChord releases after 40 ms).
 if (rest.length) setTimeout(() => typePlain(rest.join('')), 60);
 }, [consumeLatched, sendJson, sendKeyChord, typePlain]);

 const handleBarKey = useCallback((k: KeyBarKey) => {
 if (k.code) pressKey(k.code);
 else if (k.text) typeText(k.text);
 }, [pressKey, typeText]);

 const toggleModifier = useCallback((m: ModifierKey) => {
 setLatched({ ...latchedRef.current, [m]: !latchedRef.current[m] });
 }, [setLatched]);

 const toggleSoftKeyboard = useCallback(() => {
 const kb = softKbRef.current;
 if (!kb) return;
 if (kb.isFocused()) {
 kb.blur();
 } else {
 setKeyBarOpen(true);
 kb.focus();
 }
 }, []);

 // ── Clipboard buttons (Ctrl+V / Ctrl+C need a hardware keyboard) ───────────
 const handlePasteToRemote = useCallback(async () => {
 if (clipboardSupportRef.current !== 'full') { setClipPanelOpen(true); return; }
 const text = await readClipboardText();
 if (text === null) {
 // Clipboard read refused (WebView / permission / plain http): the text box.
 setClipDraft('');
 setClipPanelOpen(true);
 return;
 }
 if (!text) return;
 if (sendClipboardText(text, true)) toast.success(t('reach.pasted', 'Clipboard sent to the remote'));
 }, [sendClipboardText, t]);

 const handleCopyFromRemote = useCallback(() => {
 if (clipboardSupportRef.current !== 'full') { setClipPanelOpen(true); return; }
 sendKeyChord(['ControlLeft', 'KeyC']);
 // The answer is shown in the panel: copying it locally needs a tap there
 // (mobile browsers / WebViews refuse a clipboard write from a socket callback).
 setTimeout(() => requestRemoteClipboard('panel'), 300);
 setClipPanelOpen(true);
 }, [requestRemoteClipboard, sendKeyChord]);

 const copyClipChip = useCallback(async () => {
 if (clipChip === null) return;
 const ok = await copyText(clipChip);
 if (ok) {
 lastLocalCopyRef.current = clipChip;
 toast.success(t('common.copied', 'Copied!'));
 setClipChip(null);
 } else {
 setClipPanelOpen(true);
 setClipChip(null);
 }
 }, [clipChip, t]);

 const handleDownloadRemoteFile = useCallback((f: ReachClipboardFile) => {
 if (!transfersRef.current?.requestDownload(f.idx, f.name, f.size)) {
 toast.error(t('reach.files.err.busy', 'Another transfer is already running'));
 }
 }, [t]);

 const openFilePicker = useCallback(() => fileInputRef.current?.click(), []);

 const stayConnected = useCallback(() => {
 if (keepaliveOk) {
 // Resets the agent's idle timer without touching the remote (View only too).
 sendRaw(KEEPALIVE_MESSAGE);
 } else {
 const p = lastMouseRef.current ?? { x: Math.round(agentDims.w / 2), y: Math.round(agentDims.h / 2) };
 sendJson({ type: 'mouse', action: 'move', x: p.x, y: p.y });
 }
 setInactivityWarn(false);
 setErrorMsg('');
 }, [agentDims, keepaliveOk, sendJson, sendRaw]);

 // ── Keepalive ─────────────────────────────────────────────────────────────
 // {"type":"keepalive"} every 60 s while the setting asks for it (always /
 // while the picture is on screen / never) and this connection's agent
 // listed 'keepalive'; one at once when the page comes back after more than
 // 60 s (reachKeepalive). Nothing is injected on the remote.
 if (!keepaliveRef.current) {
 keepaliveRef.current = new KeepaliveScheduler(() => {
 const ws = wsRef.current;
 if (ws?.readyState !== WebSocket.OPEN) return;
 ws.send(JSON.stringify(KEEPALIVE_MESSAGE));
 // The agent's idle timer restarted: a warning received meanwhile
 // (while the page was hidden) no longer applies.
 if (inactivityWarnRef.current) {
 inactivityWarnRef.current = false;
 setInactivityWarn(false);
 setErrorMsg('');
 }
 });
 }
 const setKeepaliveMode = useCallback((m: KeepaliveMode) => {
 setKeepaliveModeState(m);
 saveKeepaliveMode(m);
 }, []);
 const keepaliveLive = keepaliveOk && status !== 'error' && status !== 'disconnected';
 useEffect(() => {
 keepaliveRef.current?.update({ mode: keepaliveMode, supported: keepaliveOk, live: keepaliveLive });
 }, [keepaliveMode, keepaliveOk, keepaliveLive]);
 useEffect(() => {
 const k = keepaliveRef.current;
 const onVisibility = () => k?.update({ visible: document.visibilityState === 'visible' });
 // The setting changed in another viewer of this browser (another tab).
 const onStorage = (ev: StorageEvent) => {
 if (ev.key === KEEPALIVE_STORAGE_KEY) setKeepaliveModeState(parseKeepaliveMode(ev.newValue));
 };
 onVisibility();
 document.addEventListener('visibilitychange', onVisibility);
 window.addEventListener('storage', onStorage);
 return () => {
 document.removeEventListener('visibilitychange', onVisibility);
 window.removeEventListener('storage', onStorage);
 k?.stop();
 };
 }, []);

 // ── Control messages ──────────────────────────────────────────────────────
 const describeError = (e: ReachErrorMsg): string => {
 const code = e.agentCode || e.code || '';
 switch (code) {
 case 'helper_spawn_failed': return t('reach.errCode.helperSpawn', 'The capture could not start in the remote session.');
 case 'helper_timeout': return t('reach.errCode.helperTimeout', 'The capture in the remote session did not start in time.');
 case 'capture_init_failed': return t('reach.errCode.captureInit', 'The remote screen could not be captured.');
 case 'encoder_init_failed': return t('reach.errCode.encoderInit', 'The video encoder could not start on the remote.');
 case 'session_not_found': return t('reach.errCode.sessionNotFound', 'This Windows session no longer exists.');
 case 'session_no_display': return t('reach.errCode.sessionNoDisplay', 'This Windows session is disconnected: it has no screen until its user reconnects. Pick the console or an active session.');
 case 'session_logged_off': return t('reach.errCode.sessionLoggedOff', 'The user signed out of this session.');
 case 'session_switch_timeout': return t('reach.errCode.switchTimeout', 'The session did not come back (the user did not reconnect).');
 case 'privacy_mode': return t('reach.errCode.privacy', 'Privacy mode is on for this device: remote access is refused.');
 case 'relay_refused': return t('reach.errCode.relayRefused', 'The server refused the agent connection (API key or session).');
 case 'agent_timeout': return t('reach.errCode.agentTimeout', 'The agent did not open the session in time.');
 case 'agent_offline': return t('reach.errCode.agentOffline', 'The ObliReach agent is offline.');
 case 'session_closed': return t('reach.errCode.sessionClosed', 'The remote session was closed.');
 case 'agent_error': return t('reach.errCode.agentError', 'The agent could not open the session.');
 default: return e.message || t('reach.err.relay', 'Relay error');
 }
 };

 handleControlRef.current = (msg) => {
 switch (msg.type) {
 case 'waiting':
 setStatus((prev) => (prev === 'streaming' ? prev : 'waiting'));
 break;
 case 'paired':
 // The agent's relay socket is up — the decoder is initialised when
 // 'init' arrives (a second timer waits for it, see markPaired).
 markPaired();
 setStatus((prev) => (prev === 'streaming' ? prev : 'waiting'));
 break;
 case 'bitrate':
 setBitrate(typeof msg.bitrate === 'number' ? msg.bitrate : 0);
 break;
 case 'input_block_status':
 setInputBlocked(msg.blocked === true);
 break;
 case 'init': {
 const m = msg as unknown as ReachInit;
 markAgentAlive();
 reconnectAttemptsRef.current = 0;
 // A reconnect succeeded: drop its "Reconnecting (n/8)" message.
 if (!inactivityWarnRef.current) setErrorMsg('');
 const feats = featureSet(m);
 featuresRef.current = feats;
 setFeatures(feats);
 const denied = filesDenied(m);
 filesDeniedRef.current = denied;
 setFilesDeniedState(denied);
 if (denied) { setRemoteFiles([]); setFilesChip(false); }
 setKeepaliveOk(feats.has('keepalive'));
 setModernAgent(isModernAgent(m));
 genRef.current = typeof m.gen === 'number' ? m.gen : null;
 droppedButtonsRef.current.clear();
 const v = parseView(m.view);
 viewRef.current = v;
 setViewState(v);
 setViewPending(false);
 const mons = parseMonitors(m.monitors);
 if (Array.isArray(m.monitors)) setMonitors(mons);
 if (typeof m.monitor === 'number' && m.monitor >= 0) setActiveMonitor(m.monitor);
 const rate = m.audioRate || m.audio?.rate || 0;
 if (m.audioAvail) setHasAudio(true);
 if (rate) audioRef.current?.setRate(rate);
 audioRef.current?.reset();
 transfersRef.current?.setLimits(m.files);
 if (m.codec && m.codec !== 'h264') {
 setStatus('error');
 setErrorMsg(t('reach.err.codec', 'Unsupported codec: {{codec}}', { codec: m.codec }));
 break;
 }
 // Every init restarts on H.264; a sticky codec comes back as codec_switch.
 setCodecId('h264');
 configureDecoder('h264', m.width, m.height, m.extradata);
 setAgentDims({ w: m.width, h: m.height });
 // After EVERY init (helper respawn, view change): renegotiate.
 if (m.audioAvail || feats.has('audio_v2')) {
 sendRaw({ type: 'audio_caps', v: 2, codecs: ['pcm16'], channels: 2, enabled: audioEnabledRef.current });
 }
 if (feats.has('clipboard_push')) sendRaw({ type: 'clipboard_sync', push: clipSyncRef.current });
 // The user's preferred codec: once per connection.
 if (!preferredSentRef.current) {
 preferredSentRef.current = true;
 if (preferredCodec && preferredCodec !== 'h264' && m.codecActive !== preferredCodec) {
 sendRaw({ type: 'set_codec', codec: preferredCodec });
 }
 }
 // The last view mode used (mosaic): once per viewer.
 if (!autoMosaicTriedRef.current && feats.has('mosaic') && mons.length > 1) {
 autoMosaicTriedRef.current = true;
 if (loadViewMode() === 'mosaic' && v?.mode !== 'mosaic') void enterMosaic();
 }
 break;
 }
 case 'codec_switch': {
 const c = typeof msg.codec === 'string' ? msg.codec : 'h264';
 setCodecId(c);
 // Reconfigure the VideoDecoder for the new codec at the CURRENT frame
 // size (a ref: the old closure used the size of the first init).
 if (c === 'vp9' || c === 'h264' || c === 'h265' || c === 'av1') {
 // Already decoding that codec (its frames came first and configured
 // it at their keyframe): a new decoder would wait for the next one.
 if (decoderCodecRef.current !== c || decoderRef.current?.state !== 'configured') {
 const d = agentDimsRef.current;
 configureDecoder(c, d.w, d.h);
 }
 } else {
 try { decoderRef.current?.close(); } catch { /* ignore */ }
 decoderRef.current = null;
 decoderCodecRef.current = null;
 }
 break;
 }
 case 'resize': {
 const w = Number(msg.width);
 const h = Number(msg.height);
 if (!(w > 0 && h > 0)) break;
 setAgentDims({ w, h });
 // Reinitialise decoder at new resolution
 if (decoderRef.current) configureDecoder(codecIdRef.current === 'jpeg' ? 'h264' : codecIdRef.current, w, h);
 break;
 }
 case 'view_error': {
 const e = msg as unknown as ReachViewErrorMsg;
 setViewPending(false);
 const text = e.code === 'mosaic_unavailable' ? t('reach.viewErr.mosaicUnavailable', 'The mosaic view is not available on this computer.')
 : e.code === 'monitor_not_found' ? t('reach.viewErr.monitorNotFound', 'This screen is no longer connected.')
 : e.code === 'too_large' ? t('reach.viewErr.tooLarge', 'The screens are too large to be shown together.')
 : e.code === 'secure_desktop' ? t('reach.viewErr.secureDesktop', 'The mosaic cannot show the lock screen or a Windows security prompt: back to one screen.')
 : t('reach.viewErr.captureFailed', 'The view could not be changed; the previous view is kept.');
 toast.error(text);
 break;
 }
 case 'session_state': {
 const st = msg as unknown as ReachSessionStateMsg;
 markAgentAlive();
 setSessionState(st);
 if (st.state !== 'live') audioRef.current?.reset();
 break;
 }
 case 'clipboard_content': {
 const m = msg as unknown as ReachClipboardContentMsg;
 const text = typeof m.text === 'string' ? m.text : '';
 let purpose: 'panel' | 'copy' | undefined;
 if (m.id) {
 purpose = pendingGetRef.current.get(m.id);
 pendingGetRef.current.delete(m.id);
 } else if (!m.origin) {
 // Older agents do not echo the id: answers come in request order.
 const oldest = pendingGetRef.current.keys().next();
 if (!oldest.done) {
 purpose = pendingGetRef.current.get(oldest.value);
 pendingGetRef.current.delete(oldest.value);
 }
 }
 setRemoteClipText(text);
 setRemoteClipTruncated(m.truncated === true);
 setClipRefreshing(false);
 if (m.origin === 'remote_change') {
 // Copied in the session: newer than the local clipboard ("last copy wins").
 noteRemoteCopy(clipTrackRef.current, text);
 if (clipSyncRef.current && text && text !== lastLocalCopyRef.current) copyRemoteToLocal(text);
 } else if (purpose === 'copy') {
 // Ctrl+C on an agent without clipboard push (answer to our clipboard_get).
 noteRemoteCopy(clipTrackRef.current, text);
 if (isCoarseRef.current) setClipPanelOpen(true);
 else copyRemoteToLocal(text);
 } else {
 clipTrackRef.current.lastRemote = text;
 }
 break;
 }
 case 'clipboard_ack': {
 if (msg.ok === false) {
 const code = typeof msg.code === 'string' ? msg.code : '';
 toast.error(code === 'too_large'
 ? t('reach.clip.tooLarge', 'Text too large for the remote clipboard (1 MB max)')
 : code === 'busy'
 ? t('reach.clip.busy', 'The remote clipboard is busy — try again')
 : t('reach.clip.unavailableShort', 'The remote clipboard is not available'));
 }
 break;
 }
 case 'clipboard_files': {
 // File transfers refused in this session: the relay does not forward the list; ignored if one comes anyway.
 if (filesDeniedRef.current) break;
 const list = Array.isArray(msg.files) ? (msg.files as ReachClipboardFile[]).filter((f) => f && typeof f.name === 'string') : [];
 // Files copied in the session: Ctrl+V there must paste THEM, not local text.
 if (list.length > 0) noteRemoteCopy(clipTrackRef.current);
 setRemoteFiles(list);
 setFilesChip(list.length > 0 && featuresRef.current.has('file_download'));
 break;
 }
 case 'inactivity_warning':
 setErrorMsg(t('reach.inactivityWarning', 'Session will disconnect in {{seconds}}s due to inactivity', { seconds: typeof msg.seconds === 'number' ? msg.seconds : 30 }));
 setInactivityWarn(true);
 break;
 case 'inactivity_timeout':
 noRetryRef.current = true;
 setStatus('disconnected');
 setErrorMsg(t('reach.inactivityTimeout', 'Session disconnected due to inactivity'));
 setInactivityWarn(false);
 break;
 case 'peer_disconnected':
 setStatus('disconnected');
 break;
 case 'error': {
 const e = msg as unknown as ReachErrorMsg;
 const retry = typeof e.retry === 'boolean' ? e.retry : !(e.code && NO_RETRY_CODES.has(e.code));
 if (!retry) noRetryRef.current = true;
 markAgentAlive();
 setStatus('error');
 setErrorMsg(describeError(e));
 setErrorDetail(e.message && e.message !== describeError(e) ? e.message : '');
 setErrorCode(e.agentCode || e.code || '');
 break;
 }
 default:
 if (msg.type.startsWith('file_')) transfersRef.current?.handleMessage(msg);
 break;
 }
 };

 // Android back closes the viewer (and ends the session) instead of
 // navigating the page underneath. Stacked sheets close first.
 useNativeBack(() => { handleClose(); return true; }, true);

 // Mobile browsers (outside the Android app): the system back gesture would
 // change the route and unmount the viewer without ending the session. While
 // the viewer is open, keep a same-URL history entry on top and treat popping
 // it as Disconnect. Touch screens only — desktop history is untouched.
 const trapBrowserBack = isCoarse && !inAndroidApp;
 const handleCloseRef = useRef(handleClose);
 handleCloseRef.current = handleClose;
 useEffect(() => {
 if (!trapBrowserBack) return;
 const MARK = '__obliReachViewer';
 let pushed = false;
 let popped = false;
 // Deferred so a StrictMode mount → unmount → mount never pushes twice
 // (and never runs the history.back() below against the second entry).
 const timer = window.setTimeout(() => {
 const prev = window.history.state;
 window.history.pushState({ ...(prev && typeof prev === 'object' ? prev : {}), [MARK]: true }, '');
 pushed = true;
 }, 0);
 const onPop = () => {
 if (!pushed || popped) return;
 popped = true;
 handleCloseRef.current();
 };
 window.addEventListener('popstate', onPop);
 return () => {
 window.clearTimeout(timer);
 window.removeEventListener('popstate', onPop);
 // Closed from the UI: drop our entry — only while it is still the
 // current one (a route change has already replaced it).
 const cur = window.history.state as Record<string, unknown> | null;
 if (pushed && !popped && cur && cur[MARK]) window.history.back();
 };
 }, [trapBrowserBack]);

 // Unmounted without handleClose (route change, parent state): still
 // finalize an active recording — its onstop saves the file instead of
 // silently discarding it — and release the audio context.
 useEffect(() => () => {
 const mr = mediaRecorderRef.current;
 if (mr && mr.state === 'recording') {
 try { mr.stop(); } catch { /* already stopped */ }
 }
 audioRef.current?.close();
 if (viewPendingTimerRef.current) clearTimeout(viewPendingTimerRef.current);
 const p = pasteRef.current;
 if (p) window.clearTimeout(p.timer);
 }, []);

 // Lets the app shell hide its floating widgets while a remote screen is open.
 useEffect(() => {
 const root = document.documentElement;
 root.dataset.remoteViewer = 'open';
 return () => { delete root.dataset.remoteViewer; };
 }, []);

 // Canvas box (for the mosaic tile labels laid over it).
 const [canvasBox, setCanvasBox] = useState<{ left: number; top: number; width: number; height: number } | null>(null);
 useEffect(() => {
 const canvas = canvasRef.current;
 const container = containerRef.current;
 if (!canvas || !container || typeof ResizeObserver === 'undefined') return;
 const measure = () => setCanvasBox({ left: canvas.offsetLeft, top: canvas.offsetTop, width: canvas.offsetWidth, height: canvas.offsetHeight });
 const ro = new ResizeObserver(measure);
 ro.observe(canvas);
 ro.observe(container);
 measure();
 return () => ro.disconnect();
 }, [status, agentDims.w, agentDims.h]);

 // ── Status config ─────────────────────────────────────────────────────────
 const statusCfg: Record<ConnStatus, { label: string; color: string; spin?: boolean }> = {
 connecting: { label: t('reach.status.connecting', 'Connecting…'), color: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30', spin: true },
 waiting: { label: t('reach.status.waiting', 'Waiting…'), color: 'text-blue-400 bg-blue-400/10 border-blue-400/30', spin: true },
 streaming: { label: t('reach.status.streaming', 'Streaming'), color: 'text-green-400 bg-green-400/10 border-green-400/30' },
 reconnecting: { label: t('reach.status.reconnecting', 'Reconnecting…'), color: 'text-orange-400 bg-orange-400/10 border-orange-400/30', spin: true },
 disconnected: { label: t('reach.status.disconnected', 'Disconnected'), color: 'text-gray-400 bg-gray-400/10 border-gray-400/30' },
 error: { label: t('reach.status.error', 'Error'), color: 'text-red-400 bg-red-400/10 border-red-400/30' },
 };
 const sc = statusCfg[status];
 const streaming = status === 'streaming';
 const chordGroupLabel = (g: 'win' | 'window' | 'misc') =>
 g === 'win' ? t('reach.chordGroup.win', 'Windows') : g === 'window' ? t('reach.chordGroup.window', 'Windows & apps') : t('reach.chordGroup.misc', 'Misc');
 const chords = SYSTEM_KEY_CHORDS.map((k) => ({ ...k, title: t(`reach.chord.${k.id}`, k.title) }));
 const keepaliveLabel = (m: KeepaliveMode) => t(KEEPALIVE_LABELS[m].key, KEEPALIVE_LABELS[m].fallback);
 const touchKeys: KeyBarKey[] = [...ESSENTIAL_KEYS, ...NAVIGATION_KEYS];
 // 40 px targets on touch screens (desktop sizes unchanged).
 const TB = 'coarse:min-h-10 coarse:min-w-10 coarse:justify-center';
 const toggleAudio = () => {
 const next = !audioEnabled;
 setAudioEnabled(next);
 audioEnabledRef.current = next;
 // In the click: creates / resumes the AudioContext (autoplay policy).
 audioRef.current?.setEnabled(next);
 if (featuresRef.current.has('audio_v2')) sendJson({ type: 'set_audio', enabled: next });
 };
 // Toolbar buttons used while typing must not blur the soft-keyboard field.
 const keepFocus = {
 onPointerDown: (e: React.PointerEvent) => { if (e.pointerType !== 'mouse') e.preventDefault(); },
 onMouseDown: (e: React.MouseEvent) => { if (isCoarseRef.current) e.preventDefault(); },
 };
 const uploadSupported = features.has('file_upload') && !filesDeniedState;
 const downloadSupported = features.has('file_download') && !filesDeniedState;
 /** File transfers refused in this session: the reason, shown on the disabled actions. */
 const filesDeniedText = filesDeniedState ? filesDeniedMessage(filesDeniedState) : null;
 const sessionOverlay = sessionState && sessionState.state !== 'live' && status !== 'error' && status !== 'disconnected'
 ? sessionState : null;
 const waitMinutes = sessionOverlay?.waitSec ? Math.max(1, Math.round(sessionOverlay.waitSec / 60)) : null;
 const miniMap = monitors.length > 1 ? miniMapLayout(monitors, 100) : null;

 // ── Render ────────────────────────────────────────────────────────────────
 return (
 <div
 ref={rootRef}
 className="fixed inset-x-0 bottom-0 z-50 flex flex-col bg-black pt-safe px-safe"
 style={keyboardInset > 0 ? { top: nativeTop, bottom: keyboardInset } : { top: nativeTop }}
 onKeyDown={handleKeyDown}
 onKeyUp={handleKeyUp}
 tabIndex={-1}
 >
 {/* ── Toolbar ── */}
 <div className="flex items-center justify-between px-3 py-1.5 bg-bg-primary shrink-0 gap-3 max-lg:flex-wrap max-lg:gap-y-1 coarse:flex-wrap coarse:gap-y-1">
 <div className="flex items-center gap-2 min-w-0 max-md:flex-1 max-md:basis-0">
 <Monitor className="w-4 h-4 text-text-muted shrink-0" />
 <span className="text-sm font-medium text-text-primary truncate">{deviceName}</span>

 <span className={clsx('text-xs px-2 py-0.5 rounded-full border whitespace-nowrap flex items-center gap-1', sc.color)}>
 {sc.spin && <RefreshCw className="w-3 h-3 animate-spin" />}
 {status === 'error' && <AlertTriangle className="w-3 h-3" />}
 {status === 'streaming' && <Wifi className="w-3 h-3" />}
 {sc.label}
 </span>

 {status === 'streaming' && (
 <span className="text-xs text-text-muted hidden sm:block">
 {inMosaic ? `${t('reach.mosaic', 'Mosaic')} · ` : ''}{agentDims.w}×{agentDims.h} · {fps} fps · {codec}{bitrate > 0 ? ` · ${(bitrate / 1_000_000).toFixed(1)} Mbps` : ''}
 </span>
 )}

 {errorMsg && (
 <span className="text-xs text-red-400 truncate hidden sm:block">{errorMsg}</span>
 )}
 </div>

 {/* Right cluster: one row on desktop. Below lg (and on any touch
 screen) it may shrink to the toolbar width so its own flex-wrap
 applies — with shrink-0 it kept its max-content width and pushed
 Disconnect off-screen. On phones and touch tablets the secondary
 controls live in the "⋯" tools sheet. */}
 <div className="flex items-center gap-1 shrink-0 max-lg:flex-wrap max-lg:justify-end max-lg:ml-auto max-lg:shrink max-lg:min-w-0 coarse:flex-wrap coarse:justify-end coarse:ml-auto coarse:shrink coarse:min-w-0">
 {/* ── Mosaic toggle + monitor selector ── */}
 {status === 'streaming' && canMosaic && (
 <button
 onClick={toggleMosaic}
 disabled={viewPending}
 aria-pressed={inMosaic}
 title={inMosaic ? t('reach.mosaicExit', 'Back to one screen') : t('reach.mosaicHint', 'Show all the screens at once, at their real positions')}
 className={clsx(
 'flex items-center gap-1.5 px-2 py-1 text-xs border rounded transition-colors disabled:opacity-50 max-md:hidden max-lg:coarse:hidden', TB,
 inMosaic
 ? 'bg-accent/15 text-accent border-accent/40'
 : 'bg-bg-secondary text-text-muted border-transparent hover:text-text-primary hover:bg-bg-tertiary',
 )}
 >
 {viewPending ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <LayoutGrid className="w-3.5 h-3.5" />}
 <span className="hidden sm:inline">{t('reach.mosaic', 'Mosaic')}</span>
 </button>
 )}
 {status === 'streaming' && miniMap && (
 <div className="relative rounded bg-bg-tertiary max-md:hidden max-lg:coarse:hidden" style={{ width: miniMap.width, height: miniMap.height }} title={t('reach.selectMonitor', 'Select monitor')}>
 {miniMap.boxes.map((b) => {
 const m = monitors.find((x) => x.index === b.index);
 const highlighted = inMosaic || b.index === activeMonitor;
 return (
 <div
 key={b.index}
 onClick={() => handleMonitorSwitch(b.index)}
 className={clsx(
 'absolute border cursor-pointer flex items-center justify-center text-[8px] font-bold transition-colors',
 highlighted
 ? 'bg-accent/30 border-accent text-accent'
 : 'bg-bg-secondary/60 border-transparent/60 text-text-muted hover:bg-accent/10',
 )}
 style={{ left: `${b.left}%`, top: `${b.top}%`, width: `${b.width}%`, height: `${b.height}%` }}
 title={m ? `${m.name} (${m.width}×${m.height})` : undefined}
 >
 {b.index + 1}
 </div>
 );
 })}
 </div>
 )}

 {/* ── Codec selector ── */}
 {status === 'streaming' && (
 <select
 value={codecId}
 onChange={e => handleCodecSwitch(e.target.value)}
 title={t('reach.codec', 'Video codec')}
 aria-label={t('reach.codec', 'Video codec')}
 className="px-2 py-1 text-xs bg-bg-secondary text-text-muted rounded hover:text-text-primary transition-colors cursor-pointer max-md:hidden max-lg:coarse:hidden coarse:min-h-10"
 >
 {CODECS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
 </select>
 )}

 {/* ── Input block toggle ── */}
 {status === 'streaming' && (
 <button
 onClick={handleInputBlock}
 title={inputBlocked ? t('reach.unblockInput', 'Unblock remote user input') : t('reach.blockInput', 'Block remote user input')}
 className={clsx(
 'flex items-center gap-1.5 px-2 py-1 text-xs border rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB,
 inputBlocked
 ? 'bg-orange-500/20 text-orange-400 border-orange-500/30 hover:bg-orange-500/30'
 : 'bg-bg-secondary text-text-muted border-transparent hover:text-text-primary hover:bg-bg-tertiary'
 )}
 >
 {inputBlocked ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
 <span className="hidden sm:inline">{inputBlocked ? t('reach.blocked', 'Blocked') : t('reach.block', 'Block')}</span>
 </button>
 )}

 {/* ── View only (local: nothing is sent to the remote) ── */}
 {status === 'streaming' && (
 <button
 onClick={() => setViewOnly(!viewOnly)}
 aria-pressed={viewOnly}
 title={viewOnly
 ? t('reach.viewOnlyActive', 'View only is on: click to control the remote again')
 : t('reach.viewOnly', 'View only: the mouse and keyboard stay here')}
 aria-label={t('reach.viewOnly', 'View only: the mouse and keyboard stay here')}
 className={clsx(
 'p-1.5 border rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB,
 viewOnly
 ? 'bg-accent/15 text-accent border-accent/40 hover:bg-accent/25'
 : 'text-text-muted border-transparent hover:text-text-primary hover:bg-bg-secondary',
 )}
 >
 <MousePointerOff className="w-4 h-4" />
 </button>
 )}

 {/* ── Keep sessions alive (keepalive setting of this browser) ── */}
 {status === 'streaming' && (
 <div className="relative max-md:hidden max-lg:coarse:hidden">
 <button
 onClick={() => setKeepaliveMenuOpen((v) => !v)}
 aria-haspopup="menu"
 aria-expanded={keepaliveMenuOpen}
 title={t('reach.keepalive.button', 'Keep sessions alive: {{mode}}', { mode: keepaliveLabel(keepaliveMode) })}
 aria-label={t('reach.keepalive.button', 'Keep sessions alive: {{mode}}', { mode: keepaliveLabel(keepaliveMode) })}
 className={clsx(
 'p-1.5 rounded transition-colors', TB,
 keepaliveMenuOpen
 ? 'bg-accent/15 text-accent'
 : 'text-text-muted hover:text-text-primary hover:bg-bg-secondary',
 )}
 >
 {keepaliveMode === 'never' ? <TimerOff className="w-4 h-4" /> : <Timer className="w-4 h-4" />}
 </button>
 {keepaliveMenuOpen && (
 <>
 <div className="fixed inset-0 z-40" onClick={() => setKeepaliveMenuOpen(false)} />
 <div role="menu" aria-label={t('reach.keepalive.title', 'Keep sessions alive')} className="absolute right-0 top-full mt-1 z-50 w-72 max-w-[calc(100vw-1rem)] bg-bg-secondary rounded-lg shadow-2xl p-2 space-y-1">
 <div className="px-1 pb-1 text-[10px] font-mono uppercase tracking-wider text-text-muted">{t('reach.keepalive.title', 'Keep sessions alive')}</div>
 {KEEPALIVE_MODES.map((m) => (
 <button
 key={m}
 role="menuitemradio"
 aria-checked={keepaliveMode === m}
 onClick={() => { setKeepaliveMode(m); setKeepaliveMenuOpen(false); rootRef.current?.focus({ preventScroll: true }); }}
 className={clsx(
 'flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs transition-colors',
 keepaliveMode === m ? 'bg-accent/15 text-accent' : 'text-text-primary hover:bg-bg-tertiary',
 )}
 >
 <Check className={clsx('w-3.5 h-3.5 shrink-0', keepaliveMode !== m && 'invisible')} />
 {keepaliveLabel(m)}
 </button>
 ))}
 <p className="px-1 pt-1 text-[11px] leading-snug text-text-muted">{t('reach.keepalive.hint', 'The agent ends a session after 10 minutes without input; this keeps watched sessions open.')}</p>
 {!keepaliveOk && (
 <p className="px-1 text-[11px] leading-snug text-amber-400">{t('reach.keepalive.unsupported', 'This ObliReach agent cannot do it yet: update it to keep watched sessions open.')}</p>
 )}
 </div>
 </>
 )}
 </div>
 )}

 {/* ── Clipboard panel ── */}
 {status === 'streaming' && (
 <button
 onClick={() => { setClipDraft(''); setClipPanelOpen(true); }}
 title={t('reach.clip.open', 'Clipboard panel (text box)')}
 aria-label={t('reach.clip.open', 'Clipboard panel (text box)')}
 className={clsx('p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-secondary rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB)}
 >
 <ClipboardPaste className="w-4 h-4" />
 </button>
 )}

 {/* ── Send files ── */}
 {status === 'streaming' && uploadSupported && (
 <button
 onClick={openFilePicker}
 title={t('reach.files.sendHint', 'Send files to the remote Downloads folder (or drop them on the screen)')}
 aria-label={t('reach.files.send', 'Send files to the remote…')}
 className={clsx('p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-secondary rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB)}
 >
 <Upload className="w-4 h-4" />
 </button>
 )}
 {status === 'streaming' && !uploadSupported && filesDeniedText && (
 <button
 type="button"
 aria-disabled="true"
 onClick={() => toast.error(filesDeniedText)}
 title={filesDeniedText}
 aria-label={filesDeniedText}
 className={clsx('p-1.5 text-text-muted rounded opacity-40 cursor-not-allowed max-md:hidden max-lg:coarse:hidden', TB)}
 >
 <Upload className="w-4 h-4" />
 </button>
 )}

 {/* ── Chat toggle ── */}
 {onChatToggle && (
 <button
 onClick={onChatToggle}
 title={chatOpenProp ? t('reach.hideChat', 'Hide chat') : t('reach.chatWithUser', 'Chat with user')}
 className={clsx(
 'flex items-center gap-1.5 px-2 py-1 text-xs border rounded transition-colors max-md:hidden', TB,
 chatOpenProp
 ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
 : 'bg-bg-secondary text-text-muted border-transparent hover:text-text-primary hover:bg-bg-tertiary'
 )}
 >
 <MessageCircle className="w-3.5 h-3.5" />
 <span className="hidden sm:inline">{t('reach.chat', 'Chat')}</span>
 </button>
 )}

 {/* ── Chat sound toggle ── */}
 {onChatSoundToggle && (
 <button
 onClick={onChatSoundToggle}
 title={chatSoundEnabled ? t('reach.muteChat', 'Mute chat notifications') : t('reach.unmuteChat', 'Unmute chat notifications')}
 aria-label={chatSoundEnabled ? t('reach.muteChat', 'Mute chat notifications') : t('reach.unmuteChat', 'Unmute chat notifications')}
 className={clsx(
 'p-1.5 rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB,
 chatSoundEnabled
 ? 'text-text-muted hover:text-text-primary hover:bg-bg-secondary'
 : 'text-red-400 bg-red-500/10'
 )}
 >
 {chatSoundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
 </button>
 )}

 {/* ── Audio toggle ── */}
 {status === 'streaming' && hasAudio && (
 <button
 onClick={toggleAudio}
 title={audioEnabled ? t('reach.muteAudio', 'Mute remote audio') : t('reach.enableAudio', 'Enable remote audio')}
 aria-label={audioEnabled ? t('reach.muteAudio', 'Mute remote audio') : t('reach.enableAudio', 'Enable remote audio')}
 className={clsx(
 'p-1.5 rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB,
 audioEnabled
 ? 'text-accent hover:text-accent/70'
 : 'text-text-muted hover:text-text-primary hover:bg-bg-secondary'
 )}
 >
 {audioEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
 </button>
 )}

 {/* ── Screenshot ── */}
 {status === 'streaming' && (
 <button onClick={handleScreenshot} title={t('reach.screenshot', 'Take screenshot')} aria-label={t('reach.screenshot', 'Take screenshot')}
 className={clsx('p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-secondary rounded transition-colors max-md:hidden max-lg:coarse:hidden', TB)}>
 <Camera className="w-4 h-4" />
 </button>
 )}

 {/* ── Record toggle ── */}
 {status === 'streaming' && (
 <button
 onClick={handleToggleRecording}
 title={isRecording ? t('reach.stopRecording', 'Stop recording') : t('reach.record', 'Record session')}
 className={clsx(
 'flex items-center gap-1.5 px-2 py-1 text-xs border rounded transition-colors max-md:hidden', TB,
 // Touch tablets: in the tools sheet, but kept visible while recording.
 !isRecording && 'max-lg:coarse:hidden',
 isRecording
 ? 'bg-red-500/20 text-red-400 border-red-500/30 animate-pulse'
 : 'bg-bg-secondary text-text-muted border-transparent hover:text-text-primary hover:bg-bg-tertiary'
 )}
 >
 <Circle className={clsx('w-3.5 h-3.5', isRecording && 'fill-red-400')} />
 <span className="hidden sm:inline">{isRecording ? t('reach.stop', 'Stop') : t('reach.recordShort', 'Record')}</span>
 </button>
 )}

 {/* ── Soft keyboard (touch screens) ── */}
 {isCoarse && streaming && (
 <button
 {...keepFocus}
 onClick={toggleSoftKeyboard}
 aria-pressed={softKbOpen}
 aria-label={softKbOpen ? t('reach.hideKeyboard', 'Hide keyboard') : t('reach.showKeyboard', 'Show keyboard')}
 className={clsx(
 'flex items-center gap-1.5 px-2 py-1 text-xs rounded transition-colors', TB,
 softKbOpen ? 'bg-accent/15 text-accent' : 'bg-bg-secondary text-text-muted',
 )}
 >
 <Keyboard className="w-3.5 h-3.5" />
 <span className="hidden sm:inline">{t('reach.keyboard', 'Keyboard')}</span>
 </button>
 )}

 <button
 {...keepFocus}
 onClick={handleCtrlAltDel}
 disabled={status !== 'streaming'}
 title={t('reach.sendCad', 'Send Ctrl+Alt+Del')}
 aria-label={t('reach.sendCad', 'Send Ctrl+Alt+Del')}
 className={clsx('flex items-center gap-1.5 px-2 py-1 text-xs bg-bg-secondary text-text-muted rounded hover:text-text-primary hover:bg-bg-tertiary disabled:opacity-40 transition-colors', TB)}
 >
 <Keyboard className="w-3.5 h-3.5 coarse:hidden" />
 <ShieldAlert className="w-3.5 h-3.5 hidden coarse:block" />
 <span className="hidden sm:inline">Ctrl+Alt+Del</span>
 </button>

 {/* ── System keys — Windows/Alt/system combos the browser swallows ── */}
 <div className="relative max-md:hidden max-lg:coarse:hidden">
 <button
 onClick={() => setSysKeysOpen((v) => !v)}
 disabled={status !== 'streaming'}
 title={t('reach.systemKeysHint', 'Send system keys (Win, Alt+Tab, Task Manager…)')}
 className={clsx(
 'flex items-center gap-1.5 px-2 py-1 text-xs rounded transition-colors disabled:opacity-40', TB,
 sysKeysOpen
 ? 'bg-accent/15 text-accent'
 : 'bg-bg-secondary text-text-muted hover:text-text-primary hover:bg-bg-tertiary',
 )}
 >
 <Command className="w-3.5 h-3.5" />
 <span className="hidden sm:inline">{t('reach.systemKeys', 'System keys')}</span>
 </button>
 {sysKeysOpen && status === 'streaming' && (
 <>
 <div className="fixed inset-0 z-40" onClick={() => setSysKeysOpen(false)} />
 <div className="absolute right-0 top-full mt-1 z-50 w-72 max-w-[calc(100vw-1rem)] bg-bg-secondary rounded-lg shadow-2xl p-2 space-y-2 coarse:max-h-[70dvh] coarse:overflow-y-auto coarse:overscroll-contain">
 {(['win', 'window', 'misc'] as const).map((g) => {
 const keys = chords.filter((k) => k.group === g);
 if (keys.length === 0) return null;
 const heading = chordGroupLabel(g);
 return (
 <div key={g}>
 <div className="px-1 pb-1 text-[10px] font-mono uppercase tracking-wider text-text-muted">{heading}</div>
 <div className="flex flex-wrap gap-1">
 {keys.map((k) => (
 <button
 key={k.label}
 onClick={() => sendKeyChord(k.codes)}
 title={k.title}
 className="px-2 py-1 text-[11px] font-mono font-semibold bg-bg-tertiary rounded hover:bg-accent/10 hover:text-accent transition-colors coarse:min-h-10"
 >
 {k.label}
 </button>
 ))}
 </div>
 </div>
 );
 })}
 </div>
 </>
 )}
 </div>

 {/* Fullscreen: not offered in the Android app, where the viewer already fills the window. */}
 {!inAndroidApp && (
 <button
 onClick={handleFullscreen}
 title={isFullscreen ? t('reach.exitFullscreen', 'Exit fullscreen') : t('reach.fullscreen', 'Fullscreen')}
 aria-label={isFullscreen ? t('reach.exitFullscreen', 'Exit fullscreen') : t('reach.fullscreen', 'Fullscreen')}
 className={clsx('p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-secondary rounded transition-colors max-md:hidden', TB)}
 >
 <Maximize2 className="w-4 h-4" />
 </button>
 )}

 {/* ── Tools sheet trigger (phones; touch tablets too: labelled
 tools + zoom buttons, the toolbar icons only have a title) ── */}
 <button
 onClick={() => setToolsOpen(true)}
 aria-label={t('reach.tools', 'Session tools')}
 aria-haspopup="dialog"
 className={clsx(isCoarse ? 'lg:hidden' : 'md:hidden', 'flex items-center px-2 py-1 text-xs bg-bg-secondary text-text-muted rounded transition-colors', TB)}
 >
 <MoreHorizontal className="w-4 h-4" />
 </button>

 <button
 onClick={handleClose}
 title={t('reach.disconnect', 'Disconnect')}
 aria-label={t('reach.disconnect', 'Disconnect')}
 className={clsx('flex items-center gap-1.5 px-2 py-1 text-xs bg-red-500/10 text-red-400 border border-red-500/20 rounded hover:bg-red-500/20 transition-colors', TB)}
 >
 <X className="w-3.5 h-3.5" />
 <span className="hidden sm:inline">{t('reach.disconnect', 'Disconnect')}</span>
 </button>
 </div>
 </div>

 {/* ── Content area (flex-1, relative so overlays are scoped here) ── */}
 <div
 className="relative flex-1 overflow-hidden bg-black"
 onDragOver={(e) => {
 if ((!uploadSupported && !filesDeniedText) || !streaming || !Array.from(e.dataTransfer.types).includes('Files')) return;
 e.preventDefault();
 // Refused in this session: the overlay says why, the drop does nothing.
 e.dataTransfer.dropEffect = uploadSupported ? 'copy' : 'none';
 if (!dragOver) setDragOver(true);
 }}
 onDragLeave={(e) => {
 if (e.currentTarget.contains(e.relatedTarget as Node | null)) return;
 setDragOver(false);
 }}
 onDrop={(e) => {
 if (!uploadSupported && !filesDeniedText) return;
 e.preventDefault();
 setDragOver(false);
 uploadFiles(e.dataTransfer.files);
 }}
 >

 {/* Canvas is always mounted so canvasRef is valid when the decoder is
 configured during 'waiting' state (before the first frame arrives).
 Hidden via CSS until the decoder produces its first frame. */}
 <div
 ref={containerRef}
 className="absolute inset-0 flex items-center justify-center"
 style={{ display: status === 'streaming' ? 'flex' : 'none' }}
 >
 <canvas
 ref={canvasRef}
 className={clsx(
 'max-w-full max-h-full object-contain touch-none-canvas',
 !viewOnly ? 'cursor-crosshair' : pointer.isZoomed ? 'cursor-grab active:cursor-grabbing' : 'cursor-default',
 )}
 style={{ display: 'block', ...pointer.style }}
 {...pointer.handlers}
 // View only: a click on the picture keeps the keyboard where it was (e.g. the chat box).
 onMouseDown={(e) => { if (viewOnlyRef.current) e.preventDefault(); }}
 />
 {/* Mosaic: one numbered label per screen, over the canvas (same
 zoom transform); clicking it shows only that screen. */}
 {inMosaic && view && canvasBox && canvasBox.width > 0 && (
 <div
 className="pointer-events-none absolute"
 style={{
 left: canvasBox.left, top: canvasBox.top, width: canvasBox.width, height: canvasBox.height,
 transform: pointer.style.transform, transformOrigin: '0 0',
 }}
 >
 {view.tiles.map((tile) => {
 const b = tilePercentBox(tile, view.width || agentDims.w, view.height || agentDims.h);
 return (
 <div key={tile.index} className="absolute" style={{ left: `${b.left}%`, top: `${b.top}%`, width: `${b.width}%`, height: `${b.height}%` }}>
 <button
 type="button"
 onClick={() => handleMonitorSwitch(tile.index)}
 title={t('reach.mosaicShowOnly', 'Show only screen {{n}}', { n: tile.index + 1 })}
 className="pointer-events-auto absolute left-1 top-1 flex h-6 min-w-6 items-center justify-center rounded bg-black/60 px-1.5 text-[11px] font-bold text-white opacity-70 hover:opacity-100 hover:bg-accent transition coarse:h-9 coarse:min-w-9"
 >
 {tile.index + 1}
 </button>
 </div>
 );
 })}
 </div>
 )}
 {/* Trackpad mode: where the next tap will click. */}
 {pointer.cursorStyle && (
 <div style={pointer.cursorStyle} aria-hidden="true" className="z-10 drop-shadow">
 <MousePointer2 className="w-5 h-5 text-white fill-black/60" />
 </div>
 )}
 </div>

 {/* View only: always visible over the picture (a click gives the control back). */}
 {viewOnly && status === 'streaming' && (
 <button
 type="button"
 onClick={() => setViewOnly(false)}
 title={t('reach.viewOnlyActive', 'View only is on: click to control the remote again')}
 className="absolute left-2 top-2 z-20 flex items-center gap-1.5 rounded-full bg-black/60 px-2.5 py-1 text-[11px] font-medium text-white opacity-80 hover:opacity-100 transition-opacity coarse:min-h-10"
 >
 <MousePointerOff className="w-3.5 h-3.5" />
 {t('reach.viewOnlyShort', 'View only')}
 </button>
 )}

 {/* Drop target for files. */}
 {dragOver && (
 <div className={clsx(
 'pointer-events-none absolute inset-3 z-30 flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed bg-black/60 px-6 text-center text-sm text-white',
 filesDeniedText ? 'border-red-400' : 'border-accent',
 )}>
 <Upload className={clsx('w-8 h-8', filesDeniedText ? 'text-red-400' : 'text-accent')} />
 {filesDeniedText ?? t('reach.files.drop', 'Drop the files to send them to the remote Downloads folder')}
 </div>
 )}

 {/* Remote clipboard waiting for a gesture / remote files to download. */}
 {(clipChip !== null || filesChip) && streaming && (
 <div className="absolute top-2 left-1/2 z-20 flex -translate-x-1/2 flex-wrap justify-center gap-2 max-w-[calc(100%-1rem)]">
 {clipChip !== null && (
 <div className="flex items-center gap-2 rounded-full bg-bg-secondary/95 py-1 pl-3 pr-1 text-xs text-text-primary shadow-lg">
 <ClipboardCopy className="w-3.5 h-3.5 text-accent" />
 <span>{t('reach.clip.remoteUpdated', 'Remote clipboard updated')}</span>
 <button type="button" onClick={copyClipChip} className="rounded-full bg-accent px-3 py-1 font-medium text-white coarse:min-h-10">
 {t('common.copy', 'Copy')}
 </button>
 <button type="button" onClick={() => setClipChip(null)} aria-label={t('common.close', 'Close')} className="rounded-full p-1 text-text-muted hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
 <X className="w-3.5 h-3.5" />
 </button>
 </div>
 )}
 {filesChip && (
 <div className="flex items-center gap-2 rounded-full bg-bg-secondary/95 py-1 pl-3 pr-1 text-xs text-text-primary shadow-lg">
 <FileText className="w-3.5 h-3.5 text-accent" />
 <span>{t('reach.files.copiedOnRemote', '{{count}} file(s) copied on the remote', { count: remoteFiles.length })}</span>
 <button type="button" onClick={() => { setFilesChip(false); setClipPanelOpen(true); }} className="rounded-full bg-accent px-3 py-1 font-medium text-white coarse:min-h-10">
 {t('reach.files.download', 'Download')}
 </button>
 <button type="button" onClick={() => setFilesChip(false)} aria-label={t('common.close', 'Close')} className="rounded-full p-1 text-text-muted hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
 <X className="w-3.5 h-3.5" />
 </button>
 </div>
 )}
 </div>
 )}

 {/* Phones (and touch tablets): the toolbar hides / truncates status
 text — surface errors and the inactivity warning over the screen
 instead, with a "Stay connected" action. */}
 {errorMsg && streaming && !sessionOverlay && (
 <div role="status" className={clsx('absolute top-2 inset-x-2 z-10 flex items-center gap-2 rounded-lg bg-bg-secondary/95 px-3 py-2 text-xs text-red-400 shadow-lg', !isCoarse && 'sm:hidden')}>
 <AlertTriangle className="w-4 h-4 shrink-0" />
 <span className="min-w-0 flex-1">{errorMsg}</span>
 {inactivityWarn && (
 <button onClick={stayConnected} className="shrink-0 min-h-10 rounded-md bg-accent px-3 text-xs font-medium text-white">
 {t('reach.stayConnected', 'Stay connected')}
 </button>
 )}
 </div>
 )}

 {/* Session following (agents with session_follow): the stream stays
 up while the target session changes or has no display. */}
 {sessionOverlay && (
 <div className={clsx(
 'absolute inset-0 z-20 flex flex-col items-center justify-center gap-3 text-center p-8',
 streaming ? 'bg-black/70' : 'bg-[#0d0f14]',
 )}>
 {sessionOverlay.state === 'no_display'
 ? <MonitorOff className="w-10 h-10 text-text-muted" />
 : <RefreshCw className="w-10 h-10 text-accent animate-spin" />}
 <p className="text-text-primary font-medium">
 {sessionOverlay.state === 'no_display'
 ? t('reach.session.noDisplay', 'No display: the user of this session is disconnected')
 : sessionOverlay.state === 'switching'
 ? t('reach.session.switching', 'The remote session is changing (sign-in, lock, user switch)…')
 : t('reach.session.starting', 'Starting the capture in the session…')}
 </p>
 {sessionOverlay.state === 'no_display' && (
 <p className="text-sm text-text-muted max-w-md">
 {waitMinutes
 ? t('reach.session.noDisplayWait', 'The picture comes back as soon as the user reconnects (waiting up to {{min}} min). You can also pick another session.', { min: waitMinutes })
 : t('reach.session.noDisplayHint', 'The picture comes back as soon as the user reconnects. You can also pick another session.')}
 </p>
 )}
 {sessionOverlay.user && (
 <p className="text-xs text-text-muted">{t('reach.session.user', 'Session of {{user}}', { user: sessionOverlay.user })}</p>
 )}
 {sessionOverlay.state === 'no_display' && (
 <div className="mt-2 flex flex-wrap justify-center gap-2">
 {onPickSession && (
 <button onClick={onPickSession} className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg hover:bg-accent/90 transition-colors text-sm coarse:min-h-11">
 <Users className="w-4 h-4" />
 {t('reach.session.pickAnother', 'Pick another session')}
 </button>
 )}
 <button onClick={handleClose} className="px-4 py-2 bg-bg-secondary text-text-primary rounded-lg hover:bg-bg-tertiary transition-colors text-sm coarse:min-h-11">
 {t('reach.disconnect', 'Disconnect')}
 </button>
 </div>
 )}
 </div>
 )}

 {status === 'disconnected' && (
 <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-center p-8">
 <p className="text-text-primary font-medium">{sc.label}</p>
 {errorMsg && <p className="text-sm text-text-muted max-w-md">{errorMsg}</p>}
 <div className="mt-2 flex flex-wrap justify-center gap-2">
 {onReconnect && (
 <button onClick={retryNow} className="flex items-center gap-2 min-h-11 px-4 py-2 bg-accent text-white rounded-lg hover:bg-accent/90 transition-colors text-sm sm:min-h-0">
 <RefreshCw className="w-4 h-4" />
 {t('reach.retry', 'Retry')}
 </button>
 )}
 <button
 onClick={handleClose}
 className="min-h-11 px-4 py-2 bg-bg-secondary text-text-primary rounded-lg hover:bg-bg-tertiary transition-colors text-sm sm:min-h-0"
 >
 {t('common.close', 'Close')}
 </button>
 </div>
 </div>
 )}

 {status === 'error' && (
 <div className="absolute inset-0 z-20 flex flex-col items-center justify-center gap-3 text-center p-8 bg-black">
 <AlertTriangle className="w-12 h-12 text-red-400" />
 <p className="text-text-primary font-medium">{t('reach.connectionFailed', 'Connection failed')}</p>
 <p className="text-sm text-text-muted max-w-md">{errorMsg || t('reach.unknownError', 'An unknown error occurred.')}</p>
 {errorDetail && <p className="text-xs text-text-muted/80 max-w-md font-mono break-words">{errorDetail}</p>}
 <div className="mt-2 flex flex-wrap justify-center gap-2">
 {onPickSession && PICK_SESSION_CODES.has(errorCode) && (
 <button onClick={onPickSession} className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg hover:bg-accent/90 transition-colors text-sm coarse:min-h-11">
 <Users className="w-4 h-4" />
 {t('reach.session.pickAnother', 'Pick another session')}
 </button>
 )}
 {onReconnect && (
 <button onClick={retryNow} className="flex items-center gap-2 px-4 py-2 bg-accent text-white rounded-lg hover:bg-accent/90 transition-colors text-sm coarse:min-h-11">
 <RefreshCw className="w-4 h-4" />
 {t('reach.retry', 'Retry')}
 </button>
 )}
 <button
 onClick={handleClose}
 className="px-4 py-2 bg-bg-secondary text-text-primary rounded-lg hover:bg-bg-tertiary transition-colors text-sm coarse:min-h-11"
 >
 {t('common.close', 'Close')}
 </button>
 </div>
 </div>
 )}

 {(status === 'connecting' || status === 'waiting' || status === 'reconnecting') && !sessionOverlay && (
 <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 text-center p-8 bg-[#0d0f14]">
 <RefreshCw className="w-10 h-10 text-accent animate-spin" />
 <p className="text-text-primary font-medium">
 {status === 'reconnecting'
 ? t('reach.status.reconnecting', 'Reconnecting…')
 : kind === 'vmconsole'
 ? t('reach.vmConsole.waitingTitle', 'Opening the VM console…')
 : delivery === 'queued'
 ? t('reach.queuedTitle', 'ObliReach agent offline')
 : status === 'waiting'
 ? t('reach.waitingAgent', 'Waiting for agent to connect…')
 : t('reach.connectingRelay', 'Connecting to relay…')}
 </p>
 <p className="text-sm text-text-muted max-w-md">
 {status === 'reconnecting'
 ? (errorMsg || t('reach.reconnectingHint', 'The target session transitioned (e.g. after login) — redialling automatically.'))
 : kind === 'vmconsole'
 ? t('reach.vmConsole.waitingHint', 'The host prepares the console. The first time, it downloads the console component first, which can take a few minutes.')
 : delivery === 'queued'
 ? t('reach.queuedHint', 'The session starts as soon as the agent reconnects (up to 5 minutes).')
 : status === 'waiting'
 ? t('reach.waitingAgentHint', 'The wake-up command has been sent. The Oblireach agent will connect within 30 s.')
 : t('reach.connectingHint', 'Establishing encrypted tunnel…')}
 </p>
 </div>
 )}

 {/* File transfers. */}
 <ReachTransferTray
 items={transfers}
 onCancel={(tid) => transfersRef.current?.cancel(tid)}
 onClear={() => transfersRef.current?.clearFinished()}
 />

 {/* Hidden field that brings up the soft keyboard (touch screens). */}
 {isCoarse && (
 <SoftKeyboardInput
 ref={softKbRef}
 label={t('reach.keyboardInput', 'Remote keyboard input')}
 onText={typeText}
 onKey={pressKey}
 onFocusChange={setSoftKbOpen}
 />
 )}
 <input
 ref={fileInputRef}
 type="file"
 multiple
 className="hidden"
 aria-hidden="true"
 tabIndex={-1}
 onChange={(e) => {
 const files = e.currentTarget.files;
 if (files && files.length) uploadFiles(Array.from(files));
 e.currentTarget.value = '';
 }}
 />
 </div>

 {/* ── Touch key bar: modifiers, keys a soft keyboard lacks, clipboard ── */}
 {isCoarse && streaming && (keyBarOpen ? (
 <RemoteKeyBar
 modifiers={['ctrl', 'alt', 'shift', 'meta']}
 latched={latched}
 onToggleModifier={toggleModifier}
 keys={touchKeys}
 onKey={handleBarKey}
 letterRow
 ariaLabel={t('remoteKeys.bar', 'Keys')}
 leading={
 <KeyChip
 active={softKbOpen}
 onClick={toggleSoftKeyboard}
 aria-label={softKbOpen ? t('reach.hideKeyboard', 'Hide keyboard') : t('reach.showKeyboard', 'Show keyboard')}
 >
 <Keyboard className="w-4 h-4" />
 </KeyChip>
 }
 trailing={
 <>
 <KeyChip tone="accent" onClick={handleCtrlAltDel} aria-label={t('reach.sendCad', 'Send Ctrl+Alt+Del')}>
 <ShieldAlert className="w-4 h-4" />
 <span>Ctrl+Alt+Del</span>
 </KeyChip>
 <KeyChip onClick={handlePasteToRemote} aria-label={t('reach.pasteToRemote', 'Paste to remote')}>
 <ClipboardPaste className="w-4 h-4" />
 </KeyChip>
 <KeyChip onClick={handleCopyFromRemote} aria-label={t('reach.copyFromRemote', 'Copy from remote')}>
 <ClipboardCopy className="w-4 h-4" />
 </KeyChip>
 <KeyChip
 active={touchMode === 'trackpad'}
 onClick={() => setTouchMode(touchMode === 'trackpad' ? 'direct' : 'trackpad')}
 aria-label={touchMode === 'trackpad'
 ? t('reach.touchModeTrackpad', 'Touch: trackpad (relative cursor)')
 : t('reach.touchModeDirect', 'Touch: direct (tap where you click)')}
 >
 {touchMode === 'trackpad' ? <MousePointer2 className="w-4 h-4" /> : <Hand className="w-4 h-4" />}
 </KeyChip>
 {pointer.isZoomed && (
 <KeyChip onClick={pointer.resetView} aria-label={t('reach.fit', 'Fit')}>
 <Minimize2 className="w-4 h-4" />
 </KeyChip>
 )}
 <KeyChip onClick={() => setKeyBarOpen(false)} aria-label={t('remoteKeys.hide', 'Hide keys')}>
 <ChevronDown className="w-4 h-4" />
 </KeyChip>
 </>
 }
 />
 ) : (
 <div className="shrink-0 flex justify-end bg-bg-secondary px-2 py-1 pb-safe">
 <KeyChip onClick={() => setKeyBarOpen(true)} aria-label={t('remoteKeys.show', 'Show keys')}>
 <Keyboard className="w-4 h-4" />
 <ChevronUp className="w-4 h-4" />
 </KeyChip>
 </div>
 ))}

 {/* ── Phone tools sheet (everything the phone toolbar has no room for) ── */}
 <ReachToolsSheet
 open={toolsOpen}
 onClose={() => setToolsOpen(false)}
 streaming={streaming}
 monitors={monitors}
 activeMonitor={activeMonitor}
 onMonitor={handleMonitorSwitch}
 mosaic={canMosaic ? { active: inMosaic, pending: viewPending, onToggle: toggleMosaic } : null}
 codecId={codecId}
 codecs={CODECS}
 onCodec={handleCodecSwitch}
 zoom={isCoarse ? { zoomed: pointer.isZoomed, onZoomIn: () => pointer.zoomBy(1.5), onZoomOut: () => pointer.zoomBy(1 / 1.5), onReset: pointer.resetView } : null}
 inputBlocked={inputBlocked}
 onToggleInputBlock={handleInputBlock}
 viewOnly={{ active: viewOnly, onToggle: () => setViewOnly(!viewOnly) }}
 touchMode={isCoarse ? touchMode : null}
 onTouchMode={setTouchMode}
 onCtrlAltDel={handleCtrlAltDel}
 systemChords={chords}
 chordGroupLabel={chordGroupLabel}
 onChord={sendKeyChord}
 onPaste={handlePasteToRemote}
 onCopy={handleCopyFromRemote}
 onClipboardPanel={() => { setClipDraft(''); setClipPanelOpen(true); }}
 onSendFiles={uploadSupported ? openFilePicker : null}
 filesDenied={filesDeniedText}
 chat={onChatToggle ? { open: !!chatOpenProp, onToggle: onChatToggle } : null}
 chatSound={onChatSoundToggle ? { enabled: !!chatSoundEnabled, onToggle: onChatSoundToggle } : null}
 audio={hasAudio ? { enabled: audioEnabled, onToggle: toggleAudio } : null}
 keepalive={{ mode: keepaliveMode, supported: keepaliveOk, onChange: setKeepaliveMode }}
 onScreenshot={handleScreenshot}
 recording={isRecording}
 onToggleRecording={handleToggleRecording}
 fullscreen={inAndroidApp ? null : { active: isFullscreen, onToggle: handleFullscreen }}
 />

 {/* ── Clipboard panel: text box fallback, remote clipboard, files ── */}
 <ReachClipboardPanel
 open={clipPanelOpen}
 onClose={() => { setClipPanelOpen(false); rootRef.current?.focus({ preventScroll: true }); }}
 support={clipboardSupport}
 pushSupported={features.has('clipboard_push')}
 sync={clipSync}
 onSyncChange={setClipSync}
 remoteText={remoteClipText}
 remoteTruncated={remoteClipTruncated}
 refreshing={clipRefreshing}
 onRefresh={() => requestRemoteClipboard('panel')}
 onSend={(text, paste) => {
 if (sendClipboardText(text, paste)) toast.success(t('reach.pasted', 'Clipboard sent to the remote'));
 }}
 draft={clipDraft}
 remoteFiles={remoteFiles}
 downloadSupported={downloadSupported}
 onDownload={handleDownloadRemoteFile}
 onSendFiles={uploadSupported ? openFilePicker : null}
 filesDenied={filesDeniedText}
 />
 </div>
 );
}
