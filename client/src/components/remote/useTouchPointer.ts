import { useCallback, useEffect, useRef, type MouseEvent as ReactMouseEvent, type PointerEvent as ReactPointerEvent, type RefObject, type WheelEvent as ReactWheelEvent } from 'react';
import { REMOTE_LIMITS, type RemoteViewerToAgentMessage } from '@obligarth/shared';

// =============================================================================
// The operator's mouse and fingers → the touches of the device (P0-15 §5.2): coordinates in pixels of the picture,
// computed on the rectangle the canvas really takes on screen (getBoundingClientRect: the local zoom and any transform
// included), clamped to the picture. The convention of scrcpy for a mouse: left button = a finger (drag = swipe),
// Ctrl + drag = a pinch around the point pressed, right click = Back, middle click = Home, wheel = scroll. A touch screen
// of the operator: up to five fingers. The moves are sent every 30 ms at most per finger (the relay admits 200 inputs a
// second), the down and up at once. Every touch carries the gen of the last init: the agent drops a stale one (except
// up/cancel). Inspired by Obliance's useRemotePointer.ts, reduced to a touch screen.
// =============================================================================

const MOVE_MS = 30;
const MAX_DELTA = 16_384;

type Send = (m: RemoteViewerToAgentMessage) => void;

interface Pointer { id: number; x: number; y: number; moved: boolean; pinch: { cx: number; cy: number } | null }

export interface TouchPointerHandlers {
  onPointerDown: (e: ReactPointerEvent<HTMLCanvasElement>) => void;
  onPointerMove: (e: ReactPointerEvent<HTMLCanvasElement>) => void;
  onPointerUp: (e: ReactPointerEvent<HTMLCanvasElement>) => void;
  onPointerCancel: (e: ReactPointerEvent<HTMLCanvasElement>) => void;
  onWheel: (e: ReactWheelEvent<HTMLCanvasElement>) => void;
  onContextMenu: (e: ReactMouseEvent<HTMLCanvasElement>) => void;
}

/** A point of the screen → pixels of the picture (null outside a drawn canvas). */
export function toPicture(canvas: HTMLCanvasElement, clientX: number, clientY: number): { x: number; y: number } | null {
  const r = canvas.getBoundingClientRect();
  if (!(r.width > 0 && r.height > 0 && canvas.width > 0 && canvas.height > 0)) return null;
  const x = Math.round(((clientX - r.left) / r.width) * canvas.width);
  const y = Math.round(((clientY - r.top) / r.height) * canvas.height);
  return { x: Math.min(canvas.width - 1, Math.max(0, x)), y: Math.min(canvas.height - 1, Math.max(0, y)) };
}

export function useTouchPointer({ canvasRef, enabled, navEnabled, gen, send }: {
  canvasRef: RefObject<HTMLCanvasElement>;
  /** The effective mode is control and the agent announced touch. */
  enabled: boolean;
  /** The agent announced nav (right and middle clicks). */
  navEnabled: boolean;
  gen: number;
  send: Send;
}): TouchPointerHandlers {
  const st = useRef({ enabled, navEnabled, gen, send });
  useEffect(() => { st.current = { enabled, navEnabled, gen, send }; }, [enabled, navEnabled, gen, send]);
  const pointers = useRef(new Map<number, Pointer>());
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastFlush = useRef(0);

  const freeId = (): number | null => {
    const used = new Set(Array.from(pointers.current.values()).flatMap((p) => (p.pinch ? [p.id, p.id + 1] : [p.id])));
    for (let i = 0; i < REMOTE_LIMITS.maxPointers; i++) if (!used.has(i)) return i;
    return null;
  };

  const touch = (action: 'down' | 'move' | 'up' | 'cancel', id: number, x: number, y: number) => {
    st.current.send({ type: 'touch', action, id, x, y, gen: st.current.gen });
  };

  /** The mirror of a point around the center of a pinch, clamped to the picture. */
  const mirror = (p: Pointer): { x: number; y: number } => {
    const c = canvasRef.current;
    const w = c?.width ?? 0;
    const h = c?.height ?? 0;
    const x = 2 * (p.pinch?.cx ?? p.x) - p.x;
    const y = 2 * (p.pinch?.cy ?? p.y) - p.y;
    return { x: Math.min(Math.max(0, w - 1), Math.max(0, x)), y: Math.min(Math.max(0, h - 1), Math.max(0, y)) };
  };

  const flush = useCallback(() => {
    flushTimer.current = null;
    lastFlush.current = Date.now();
    for (const p of pointers.current.values()) {
      if (!p.moved) continue;
      p.moved = false;
      touch('move', p.id, p.x, p.y);
      if (p.pinch) { const m = mirror(p); touch('move', p.id + 1, m.x, m.y); }
    }
  }, []);

  const scheduleFlush = () => {
    if (flushTimer.current) return;
    const wait = Math.max(0, MOVE_MS - (Date.now() - lastFlush.current));
    flushTimer.current = setTimeout(flush, wait);
  };

  useEffect(() => () => { if (flushTimer.current) clearTimeout(flushTimer.current); }, []);

  // Inputs no longer admitted (back to view, the session ended): the fingers held are released.
  useEffect(() => {
    if (enabled) return;
    for (const p of pointers.current.values()) {
      touch('cancel', p.id, p.x, p.y);
      if (p.pinch) { const m = mirror(p); touch('cancel', p.id + 1, m.x, m.y); }
    }
    pointers.current.clear();
  }, [enabled]);

  const end = (e: ReactPointerEvent<HTMLCanvasElement>, action: 'up' | 'cancel') => {
    const p = pointers.current.get(e.pointerId);
    if (!p) return;
    pointers.current.delete(e.pointerId);
    const c = canvasRef.current;
    const at = c ? toPicture(c, e.clientX, e.clientY) : null;
    if (at && action === 'up') { p.x = at.x; p.y = at.y; }
    if (p.pinch) { const m = mirror(p); touch(action, p.id + 1, m.x, m.y); }
    touch(action, p.id, p.x, p.y);
    try { e.currentTarget.releasePointerCapture(e.pointerId); } catch { /* not captured */ }
  };

  return {
    onPointerDown: (e) => {
      const c = canvasRef.current;
      if (!c) return;
      if (e.pointerType === 'mouse' && e.button !== 0) {
        // Right click: Back; middle click: Home (the nav of the agent).
        if (st.current.enabled && st.current.navEnabled && (e.button === 1 || e.button === 2)) {
          e.preventDefault();
          st.current.send({ type: 'nav', action: e.button === 2 ? 'back' : 'home' });
        }
        return;
      }
      if (!st.current.enabled) return;
      const at = toPicture(c, e.clientX, e.clientY);
      if (!at) return;
      const id = freeId();
      if (id === null) return;
      const pinch = e.pointerType === 'mouse' && e.ctrlKey && id + 1 < REMOTE_LIMITS.maxPointers ? { cx: at.x, cy: at.y } : null;
      e.preventDefault();
      try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* old browser */ }
      const p: Pointer = { id, x: at.x, y: at.y, moved: false, pinch };
      pointers.current.set(e.pointerId, p);
      touch('down', id, at.x, at.y);
      if (pinch) touch('down', id + 1, at.x, at.y);
    },
    onPointerMove: (e) => {
      const p = pointers.current.get(e.pointerId);
      const c = canvasRef.current;
      if (!p || !c) return;
      const at = toPicture(c, e.clientX, e.clientY);
      if (!at || (at.x === p.x && at.y === p.y)) return;
      p.x = at.x; p.y = at.y; p.moved = true;
      scheduleFlush();
    },
    onPointerUp: (e) => end(e, 'up'),
    onPointerCancel: (e) => end(e, 'cancel'),
    onWheel: (e) => {
      const c = canvasRef.current;
      if (!c || !st.current.enabled) return;
      const at = toPicture(c, e.clientX, e.clientY);
      if (!at) return;
      // Lines and pages brought to pixels; browser convention (dy > 0: the wheel turned down).
      const k = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? c.height : 1;
      const dx = Math.max(-MAX_DELTA, Math.min(MAX_DELTA, Math.round(e.deltaX * k)));
      const dy = Math.max(-MAX_DELTA, Math.min(MAX_DELTA, Math.round(e.deltaY * k)));
      if (dx === 0 && dy === 0) return;
      st.current.send({ type: 'scroll', x: at.x, y: at.y, dx, dy, gen: st.current.gen });
    },
    onContextMenu: (e) => { e.preventDefault(); },
  };
}
