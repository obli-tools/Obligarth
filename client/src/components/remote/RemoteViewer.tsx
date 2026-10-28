import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Expand, Loader2, Lock, Minus, MoonStar, Plus, Scan, WifiOff } from 'lucide-react';
import {
  REMOTE_LIMITS,
  type RemoteCodec, type RemoteEndReason, type RemoteFeature, type RemoteKeyCode, type RemoteMode, type RemoteNavAction,
  type RemoteViewerToAgentMessage,
} from '@obligarth/shared';
import { CLOSE, encodeOutbound, parseInbound, textPieces, tunnelProtocols, tunnelUrl } from './reachProtocol';
import { RemoteVideoSink, webCodecsAvailable } from './reachVideo';
import { ReachKeepalive } from './reachKeepalive';
import { useTouchPointer } from './useTouchPointer';
import { AndroidNavBar } from './AndroidNavBar';
import { RemoteTextInput } from './RemoteTextInput';

// =============================================================================
// The viewer of a remote session (P0-15 §4.4, §5, T6): the tunnel /api/remote-sessions/<id>/tunnel opened with the
// viewer's token as a subprotocol (never in the URL), the picture (H.264 by WebCodecs, else JPEG), the inputs of the
// operator while the effective mode is control and the agent announced them (touch, navigation, text, keys), the
// quality, a local zoom whose coordinates stay right (useTouchPointer reads the rectangle on screen). A tab reloaded or
// a network lost attaches again within 30 s (the relay keeps the session); the server's session_end ends the viewer.
// The relay filters the inputs by the effective mode too: what this viewer sends in view is dropped.
// =============================================================================

type Link = 'connecting' | 'open' | 'retrying' | 'closed';

/** Attempts to attach again after a cut (the relay keeps a session 30 s without its viewer). */
const MAX_RETRIES = 8;
const QUALITIES = [480, 720, 1080] as const;
const ZOOMS = [1, 1.5, 2, 3] as const;
/** Printable keys of the operator's keyboard gathered this long before one type_text. */
const TYPE_BATCH_MS = 60;

export interface RemoteViewerProps {
  sessionId: string;
  token: string;
  effective: RemoteMode;
  /** The server's mode frame (the control granted or released). */
  onEffective: (m: RemoteMode) => void;
  /** The server's session_end. */
  onEnded: (reason: RemoteEndReason) => void;
  /** The tunnel closed and will not come back (refused, replaced, too many cuts): the page reads the session again. */
  onGone: (why: 'replaced' | 'refused') => void;
}

export function RemoteViewer({ sessionId, token, effective, onEffective, onEnded, onGone }: RemoteViewerProps) {
  const { t } = useTranslation();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const shellRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const sinkRef = useRef<RemoteVideoSink | null>(null);
  const endedRef = useRef(false);
  const cb = useRef({ onEffective, onEnded, onGone });
  useEffect(() => { cb.current = { onEffective, onEnded, onGone }; }, [onEffective, onEnded, onGone]);

  const [link, setLink] = useState<Link>('connecting');
  const [gen, setGen] = useState(0);
  const [features, setFeatures] = useState<RemoteFeature[]>([]);
  const [codecs, setCodecs] = useState<RemoteCodec[]>([]);
  const [codec, setCodec] = useState<RemoteCodec | null>(null);
  const [size, setSize] = useState<{ w: number; h: number } | null>(null);
  const [hasPicture, setHasPicture] = useState(false);
  const [display, setDisplay] = useState<{ screenOn: boolean; locked: boolean } | null>(null);
  const [kbps, setKbps] = useState<number | null>(null);
  const [quality, setQuality] = useState<number>(720);
  const [stalled, setStalled] = useState(false);
  const [idleWarning, setIdleWarning] = useState<number | null>(null);
  const [agentError, setAgentError] = useState<string | null>(null);
  const [inputNote, setInputNote] = useState<string | null>(null);
  const [zoom, setZoom] = useState<number>(1);
  const [box, setBox] = useState<{ w: number; h: number }>({ w: 0, h: 0 });

  const send = useCallback((m: RemoteViewerToAgentMessage) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(encodeOutbound(m));
  }, []);

  // ── The tunnel ─────────────────────────────────────────────────────────────
  useEffect(() => {
    endedRef.current = false;
    let retries = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const keepalive = new ReachKeepalive(() => send({ type: 'keepalive' }), setStalled);
    const sink = new RemoteVideoSink(canvas, {
      onSize: (w, h) => setSize({ w, h }),
      onKeyRequest: () => send({ type: 'key_request' }),
      onH264Unsupported: () => { send({ type: 'set_codec', codec: 'jpeg' }); setCodec('jpeg'); },
      onFrame: () => { setHasPicture(true); keepalive.seen(); },
    });
    sinkRef.current = sink;

    const connect = () => {
      if (disposed) return;
      setLink(retries === 0 ? 'connecting' : 'retrying');
      let ws: WebSocket;
      try {
        ws = new WebSocket(tunnelUrl(sessionId), tunnelProtocols(token));
      } catch {
        cb.current.onGone('refused');
        return;
      }
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;
      let opened = false;
      ws.onopen = () => {
        opened = true;
        retries = 0;
        setLink('open');
        keepalive.start();
        // A fresh picture for this viewer.
        ws.send(encodeOutbound({ type: 'key_request' }));
      };
      ws.onmessage = (ev) => {
        keepalive.seen();
        if (ev.data instanceof ArrayBuffer) { sink.push(ev.data); return; }
        if (typeof ev.data !== 'string') return;
        const m = parseInbound(ev.data);
        if (!m) return;
        switch (m.type) {
          case 'init':
            setGen(m.gen);
            setFeatures(m.features);
            setCodecs(m.codecs);
            sink.reset();
            if (m.codec === 'h264' && !webCodecsAvailable() && m.codecs.includes('jpeg')) {
              ws.send(encodeOutbound({ type: 'set_codec', codec: 'jpeg' }));
              setCodec('jpeg');
            } else {
              setCodec(m.codec);
            }
            ws.send(encodeOutbound({ type: 'key_request' }));
            break;
          case 'display_state': setDisplay({ screenOn: m.screenOn, locked: m.locked }); break;
          case 'bitrate': setKbps(m.kbps); break;
          case 'inactivity_warning': setIdleWarning(Math.max(1, Math.round(m.seconds))); break;
          case 'inactivity_timeout': setIdleWarning(0); break;
          case 'error': setAgentError(m.message || m.code); break;
          case 'input_unavailable': setInputNote(m.reason); break;
          case 'mode': cb.current.onEffective(m.effective); break;
          case 'session_end':
            endedRef.current = true;
            cb.current.onEnded(m.reason);
            break;
          default: break;
        }
      };
      ws.onclose = (ev) => {
        keepalive.stop();
        if (wsRef.current === ws) wsRef.current = null;
        if (disposed || endedRef.current) { setLink('closed'); return; }
        if (ev.code === CLOSE.replaced) { setLink('closed'); cb.current.onGone('replaced'); return; }
        // Refused before the handshake (never opened) twice in a row, or too many cuts: the page reads the session.
        retries++;
        if (retries > MAX_RETRIES || (!opened && retries > 2)) { setLink('closed'); cb.current.onGone('refused'); return; }
        setLink('retrying');
        timer = setTimeout(connect, Math.min(5_000, 800 * retries));
      };
    };
    connect();
    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      keepalive.stop();
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) ws.close(CLOSE.normal);
      sink.close();
      sinkRef.current = null;
    };
  }, [sessionId, token, send]);

  // The inactivity warning counts down (any input of the operator resets it at the agent).
  useEffect(() => {
    if (!idleWarning) return undefined;
    const id = setInterval(() => setIdleWarning((s) => (s && s > 1 ? s - 1 : s)), 1_000);
    return () => clearInterval(id);
  }, [idleWarning]);

  // ── Inputs ─────────────────────────────────────────────────────────────────
  const control = effective === 'control';
  const can = (f: RemoteFeature) => control && link === 'open' && features.includes(f);
  const sendInput = useCallback((m: RemoteViewerToAgentMessage) => { setIdleWarning(null); setInputNote(null); send(m); }, [send]);
  const pointer = useTouchPointer({ canvasRef, enabled: can('touch'), navEnabled: can('nav'), gen, send: sendInput });
  const nav = (action: RemoteNavAction) => sendInput({ type: 'nav', action });
  const typeText = (text: string) => sendInput({ type: 'type_text', text });
  const key = (code: RemoteKeyCode) => sendInput({ type: 'key', code });

  // The operator's keyboard while the picture has the focus: printable keys gathered into type_text, the others as keys.
  const typed = useRef('');
  const typedTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushTyped = () => {
    typedTimer.current = null;
    const s = typed.current;
    typed.current = '';
    for (const piece of textPieces(s)) typeText(piece);
  };
  const onKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (!control || e.ctrlKey || e.metaKey || e.altKey) return;
    const special: Record<string, RemoteKeyCode> = {
      Enter: 'enter', Backspace: 'del', Tab: 'tab', ArrowLeft: 'left', ArrowRight: 'right', ArrowUp: 'up', ArrowDown: 'down', Escape: 'escape',
    };
    const code = special[e.key];
    if (code && can('key')) {
      e.preventDefault();
      if (typedTimer.current) { clearTimeout(typedTimer.current); flushTyped(); }
      key(code);
      return;
    }
    if (e.key.length === 1 && can('type_text')) {
      e.preventDefault();
      typed.current += e.key;
      if (typed.current.length >= REMOTE_LIMITS.typeTextMax) { if (typedTimer.current) clearTimeout(typedTimer.current); flushTyped(); return; }
      if (!typedTimer.current) typedTimer.current = setTimeout(flushTyped, TYPE_BATCH_MS);
    }
  };

  // ── Layout: the picture fitted in its box, then the local zoom (the box scrolls) ─
  useEffect(() => {
    const el = boxRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver(() => setBox({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setBox({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);
  const style = useMemo(() => {
    if (!size || !box.w || !box.h) return { width: 1, height: 1 };
    const fit = Math.min(box.w / size.w, box.h / size.h);
    return { width: Math.max(1, Math.floor(size.w * fit * zoom)), height: Math.max(1, Math.floor(size.h * fit * zoom)) };
  }, [size, box, zoom]);

  const zoomBy = (dir: 1 | -1) => {
    const i = ZOOMS.indexOf(zoom as typeof ZOOMS[number]);
    const next = ZOOMS[Math.min(ZOOMS.length - 1, Math.max(0, (i < 0 ? 0 : i) + dir))];
    setZoom(next);
  };
  const fullscreen = () => {
    const el = shellRef.current;
    if (!el) return;
    if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
    else void el.requestFullscreen?.().catch(() => {});
  };
  const setQ = (q: number) => { setQuality(q); send({ type: 'quality', maxHeight: q as 480 | 720 | 1080 }); };
  const switchCodec = (c: RemoteCodec) => {
    if (c === 'h264' && !webCodecsAvailable()) return;
    setCodec(c);
    sinkRef.current?.reset();
    send({ type: 'set_codec', codec: c });
    send({ type: 'key_request' });
  };

  const toolBtn = 'flex h-8 w-8 items-center justify-center rounded bg-bg-tertiary text-text-secondary hover:text-text-primary disabled:opacity-40 coarse:h-10 coarse:w-10';
  const linkLabel = link === 'open'
    ? (stalled ? (t('remote.viewer.stalled') || 'No picture for a while…') : (t('remote.viewer.live') || 'Connected'))
    : link === 'retrying' ? (t('remote.viewer.retrying') || 'Connection lost, attaching again…')
      : link === 'closed' ? (t('remote.viewer.closed') || 'Disconnected') : (t('remote.viewer.connecting') || 'Connecting to the device…');

  return (
    <div ref={shellRef} className="flex flex-col gap-2 bg-bg-primary">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 ${link === 'open' && !stalled ? 'bg-green-400/10 text-green-400' : 'bg-amber-400/10 text-amber-400'}`}>
          {link === 'open' && !stalled ? <span className="h-1.5 w-1.5 rounded-full bg-green-400" /> : <WifiOff size={12} />}
          {linkLabel}
        </span>
        {codec && <span className="text-text-muted">{codec === 'h264' ? 'H.264' : 'JPEG'}{kbps ? ` · ${kbps} kbit/s` : ''}</span>}
        <div className="ml-auto flex items-center gap-1">
          {features.includes('quality') && (
            <select
              value={quality}
              onChange={(e) => setQ(Number(e.target.value))}
              aria-label={t('remote.viewer.quality') || 'Quality'}
              className="h-8 rounded border border-border bg-bg-secondary px-1 text-xs text-text-primary coarse:h-10"
            >
              {QUALITIES.map((q) => <option key={q} value={q}>{q}p</option>)}
            </select>
          )}
          {codecs.length > 1 && (
            <select
              value={codec ?? ''}
              onChange={(e) => switchCodec(e.target.value as RemoteCodec)}
              aria-label={t('remote.viewer.codec') || 'Video format'}
              className="h-8 rounded border border-border bg-bg-secondary px-1 text-xs text-text-primary coarse:h-10"
            >
              {codecs.map((c) => <option key={c} value={c} disabled={c === 'h264' && !webCodecsAvailable()}>{c === 'h264' ? 'H.264' : 'JPEG'}</option>)}
            </select>
          )}
          <button type="button" className={toolBtn} onClick={() => zoomBy(-1)} disabled={zoom <= ZOOMS[0]} title={t('remote.viewer.zoomOut') || 'Zoom out'} aria-label={t('remote.viewer.zoomOut') || 'Zoom out'}><Minus size={15} /></button>
          <button type="button" className={toolBtn} onClick={() => setZoom(1)} disabled={zoom === 1} title={t('remote.viewer.fit') || 'Fit'} aria-label={t('remote.viewer.fit') || 'Fit'}><Scan size={15} /></button>
          <button type="button" className={toolBtn} onClick={() => zoomBy(1)} disabled={zoom >= ZOOMS[ZOOMS.length - 1]} title={t('remote.viewer.zoomIn') || 'Zoom in'} aria-label={t('remote.viewer.zoomIn') || 'Zoom in'}><Plus size={15} /></button>
          <button type="button" className={toolBtn} onClick={fullscreen} title={t('remote.viewer.fullscreen') || 'Full screen'} aria-label={t('remote.viewer.fullscreen') || 'Full screen'}><Expand size={15} /></button>
        </div>
      </div>

      <div
        ref={boxRef}
        tabIndex={0}
        onKeyDown={onKeyDown}
        aria-label={t('remote.viewer.screen') || 'Screen of the device'}
        className="relative h-[calc(100dvh-20rem)] min-h-[16rem] overflow-auto rounded-lg bg-black outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <div className="flex min-h-full min-w-full items-center justify-center" style={{ width: zoom > 1 ? style.width : undefined, height: zoom > 1 ? style.height : undefined }}>
          <canvas
            ref={canvasRef}
            style={{ width: style.width, height: style.height, touchAction: control ? 'none' : 'auto', visibility: hasPicture ? 'visible' : 'hidden' }}
            className={control ? 'cursor-crosshair' : 'cursor-default'}
            {...pointer}
          />
        </div>
        {!hasPicture && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-sm text-gray-300">
            <Loader2 size={22} className="animate-spin" />
            {t('remote.viewer.waitingPicture') || 'Waiting for the picture of the device…'}
          </div>
        )}
        {display && (!display.screenOn || display.locked) && (
          <div className="pointer-events-none absolute left-2 top-2 flex flex-wrap gap-1 text-[11px]">
            {!display.screenOn && <span className="inline-flex items-center gap-1 rounded bg-black/70 px-2 py-0.5 text-amber-300"><MoonStar size={12} />{t('remote.viewer.screenOff') || 'Screen off'}</span>}
            {display.locked && <span className="inline-flex items-center gap-1 rounded bg-black/70 px-2 py-0.5 text-amber-300"><Lock size={12} />{t('remote.viewer.locked') || 'Locked screen'}</span>}
          </div>
        )}
        {idleWarning !== null && (
          <div className="absolute inset-x-2 bottom-2 rounded bg-amber-500/90 px-3 py-2 text-center text-xs text-black">
            {idleWarning > 0
              ? (t('remote.viewer.idleWarning', { seconds: idleWarning }) || `No activity: the session ends in ${idleWarning} s. Touch the screen to keep it.`)
              : (t('remote.viewer.idleTimeout') || 'The session ends for lack of activity.')}
          </div>
        )}
      </div>

      {(agentError || inputNote) && (
        <p className="text-xs text-amber-400">
          {agentError && <span>{t('remote.viewer.agentError', { message: agentError }) || `The device reports: ${agentError}`} </span>}
          {inputNote && <span>{t('remote.viewer.inputUnavailable', { reason: inputNote }) || `The device did not take the input (${inputNote}).`}</span>}
        </p>
      )}

      {control && (features.includes('nav') || features.includes('type_text')) && (
        <div className="space-y-2">
          {features.includes('nav') && <AndroidNavBar disabled={!can('nav')} onNav={nav} />}
          {features.includes('type_text') && <RemoteTextInput disabled={!can('type_text')} keysEnabled={features.includes('key')} onText={typeText} onKey={key} />}
        </div>
      )}
      <p className="text-[11px] text-text-muted">
        {control
          ? (t('remote.viewer.controlHelp') || 'Click or touch: a finger; drag: a swipe; Ctrl + drag: a pinch; right click: Back; middle click: Home; wheel: scroll. With the picture selected, the keyboard types on the device.')
          : (t('remote.viewer.viewHelp') || 'View only: nothing you do here reaches the device.')}
        {' '}
        {t('remote.viewer.secureHelp') || 'The screens an app protects (banking, passwords) show black: the device does not let them be captured.'}
      </p>
    </div>
  );
}
