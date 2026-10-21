import { ANDROID_GAPI_URL } from '@obligarth/shared';

// The managed Google Play iframes (android-amapi §9.6, §12.3; lot AN-E): Google's library of embedded iframes (gapi,
// ANDROID_GAPI_URL) opens the iframe whose URL the server built (it carries a short-lived token: kept in the page's
// memory only, never stored, never logged) and relays its events (onproductselect, onconfigupdated…). The library is
// loaded by the pages hosting such an iframe only, on demand. An event's payload comes from Google's frame: the
// console reads the few fields it needs, checks their shape, and the server checks them again (an app is read at
// Google for the tenant's enterprise before it enters the catalog).

interface GapiIframe {
  register(event: string, callback: (payload: unknown) => void, filter: unknown): void;
}

interface Gapi {
  load(name: string, o: { callback: () => void; onerror: () => void; timeout: number; ontimeout: () => void }): void;
  iframes: {
    getContext(): { openChild(o: { url: string; where: HTMLElement; attributes?: Record<string, string> }): GapiIframe };
    CROSS_ORIGIN_IFRAMES_FILTER: unknown;
  };
}

let loading: Promise<Gapi> | null = null;

/** Loads gapi and its iframes module once (a failed load is tried again at the next call). */
export function loadGapiIframes(): Promise<Gapi> {
  if (loading) return loading;
  const p = new Promise<Gapi>((resolve, reject) => {
    const w = window as unknown as { gapi?: Gapi };
    const ready = (): void => {
      if (!w.gapi) { reject(new Error('gapi')); return; }
      w.gapi.load('gapi.iframes', {
        callback: () => resolve(w.gapi as Gapi),
        onerror: () => reject(new Error('gapi.iframes')),
        timeout: 15_000,
        ontimeout: () => reject(new Error('gapi.iframes timeout')),
      });
    };
    if (w.gapi) { ready(); return; }
    const s = document.createElement('script');
    s.src = ANDROID_GAPI_URL;
    s.async = true;
    s.onload = ready;
    s.onerror = () => reject(new Error('gapi'));
    document.head.appendChild(s);
  });
  loading = p;
  p.catch(() => { if (loading === p) loading = null; });
  return p;
}

/** A string field of an event's payload, when it has the expected shape. */
export function eventField(payload: unknown, key: string, re: RegExp): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const v = (payload as Record<string, unknown>)[key];
  return typeof v === 'string' && v.length <= 255 && re.test(v) ? v : null;
}

/**
 * Opens a Google iframe in `container` (emptied first) and registers its events. Returns the function that removes
 * it (the token goes with the frame).
 */
export async function openGoogleFrame(container: HTMLElement, url: string, title: string,
  events: Record<string, (payload: unknown) => void>): Promise<() => void> {
  const gapi = await loadGapiIframes();
  container.replaceChildren();
  const frame = gapi.iframes.getContext().openChild({
    url, where: container, attributes: { style: 'width: 100%; height: 100%; border: 0;', scrolling: 'yes', title },
  });
  for (const [name, callback] of Object.entries(events)) frame.register(name, callback, gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER);
  return () => container.replaceChildren();
}
