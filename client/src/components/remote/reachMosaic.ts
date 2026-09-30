/**
 * Mosaic view helpers (contract §1.3). The AGENT maps a frame point to the
 * desktop per tile; the viewer keeps sending frame pixels (+ `gen`). This file
 * only tells the viewer where the tiles are, so it can:
 *   - drop a click that lands in a black gap between screens (the agent would
 *     drop the `down` anyway; the matching `up` is dropped here too),
 *   - draw one numbered label per tile, and
 *   - pick the largest mosaic frame the local decoder accepts.
 */
import type { ReachMonitorInfo, ReachTile, ReachView } from './reachProtocol';

/** The tile whose frame rectangle contains (x, y) (frame pixels), or null (gap / outside). */
export function tileAt(tiles: readonly ReachTile[], x: number, y: number): ReachTile | null {
  for (const t of tiles) {
    const f = t.frame;
    if (x >= f.x && x < f.x + f.w && y >= f.y && y < f.y + f.h) return t;
  }
  return null;
}

/** True when a press at (x, y) must not reach the remote: mosaic view, point in no tile. */
export function isMosaicGap(view: ReachView | null | undefined, x: number, y: number): boolean {
  if (!view || view.mode !== 'mosaic' || view.tiles.length === 0) return false;
  return tileAt(view.tiles, x, y) === null;
}

/** Tile label box in % of the frame (for an overlay laid over the canvas). */
export function tilePercentBox(tile: ReachTile, frameW: number, frameH: number): { left: number; top: number; width: number; height: number } {
  const W = frameW || 1;
  const H = frameH || 1;
  return {
    left: (tile.frame.x / W) * 100,
    top: (tile.frame.y / H) * 100,
    width: (tile.frame.w / W) * 100,
    height: (tile.frame.h / H) * 100,
  };
}

/** Mini-map geometry: every monitor as % boxes of the union rectangle. */
export function miniMapLayout(monitors: readonly ReachMonitorInfo[], boxW: number): {
  width: number; height: number;
  boxes: Array<{ index: number; left: number; top: number; width: number; height: number }>;
} {
  if (monitors.length === 0) return { width: boxW, height: 20, boxes: [] };
  const minX = Math.min(...monitors.map((m) => m.x));
  const minY = Math.min(...monitors.map((m) => m.y));
  const maxX = Math.max(...monitors.map((m) => m.x + m.width));
  const maxY = Math.max(...monitors.map((m) => m.y + m.height));
  const totalW = maxX - minX || 1;
  const totalH = maxY - minY || 1;
  const height = Math.max(20, Math.round((boxW * totalH) / totalW));
  return {
    width: boxW,
    height,
    boxes: monitors.map((m) => ({
      index: m.index,
      left: ((m.x - minX) / totalW) * 100,
      top: ((m.y - minY) / totalH) * 100,
      width: (m.width / totalW) * 100,
      height: (m.height / totalH) * 100,
    })),
  };
}

/** Agent defaults (the viewer's values are capped by these on the agent side too). */
export const MOSAIC_MAX = { width: 4096, height: 2304, pixels: 8_294_400 } as const;

/** Candidate mosaic frame budgets, largest first. */
export const MOSAIC_CANDIDATES: ReadonlyArray<{ width: number; height: number }> = [
  { width: 4096, height: 2304 },
  { width: 3840, height: 2160 },
  { width: 2560, height: 1440 },
];

export interface MosaicBudget { maxWidth: number; maxHeight: number; maxPixels: number }

/**
 * Largest candidate every given decoder config accepts. `isSupported` is
 * VideoDecoder.isConfigSupported (injected for tests). Falls back to the
 * smallest candidate when nothing answers true, and to the agent default
 * when WebCodecs is missing (JPEG needs no decoder).
 */
export async function probeMosaicBudget(
  codecs: readonly string[],
  isSupported: ((cfg: { codec: string; codedWidth: number; codedHeight: number }) => Promise<{ supported?: boolean }>) | null,
): Promise<MosaicBudget> {
  const budget = (w: number, h: number): MosaicBudget => ({ maxWidth: w, maxHeight: h, maxPixels: Math.min(w * h, MOSAIC_MAX.pixels) });
  if (!isSupported || codecs.length === 0) return budget(MOSAIC_MAX.width, MOSAIC_MAX.height);
  for (const c of MOSAIC_CANDIDATES) {
    let ok = true;
    for (const codec of codecs) {
      try {
        const r = await isSupported({ codec, codedWidth: c.width, codedHeight: c.height });
        if (!r?.supported) { ok = false; break; }
      } catch {
        ok = false;
        break;
      }
    }
    if (ok) return budget(c.width, c.height);
  }
  const last = MOSAIC_CANDIDATES[MOSAIC_CANDIDATES.length - 1];
  return budget(last.width, last.height);
}

/** WebCodecs codec string of a viewer codec id (same strings the decoder is configured with). */
export function decoderCodecString(codecId: string): string | null {
  switch (codecId) {
    case 'h264': return 'avc1.640034';
    case 'h265': return 'hev1.1.6.L93.B0';
    case 'vp9': return 'vp09.00.10.08';
    case 'av1': return 'av01.0.04M.08';
    default: return null; // jpeg: no decoder
  }
}
