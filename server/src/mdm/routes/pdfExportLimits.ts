import { AppError } from '../../middleware/errorHandler';

// =============================================================================
// Bounds of the PDF renders of the instance: the export of the device list (GET /api/mdm/devices/export?format=pdf)
// and the reports (services/report.service.ts, review F013). A PDF renders in its own Chromium, on the one instance of
// every tenant: bounded in rows (the device export), in simultaneous renders shared by both (beyond: 429 for a
// console request, a short wait for a report job), and in time (renderHtmlPdf: the browser always closed). The CSV and
// XLSX exports keep the limit of exportDevices.
// =============================================================================

export const PDF_MAX_ROWS = 2000;
export const PDF_MAX_RENDERS = 2;
export const PDF_RENDER_TIMEOUT_MS = 60_000;

let pdfRenders = 0;
/** Callers waiting for a slot (FIFO): each is handed the slot a render gives back. */
const waiters: Array<{ grant: () => void }> = [];

const busy = (): AppError => new AppError(429, 'Too many PDF exports in progress, retry shortly', 'exportBusy');

function release(): void {
  const next = waiters.shift();
  if (next) next.grant(); // the slot passes to the next caller as is: pdfRenders unchanged
  else pdfRenders--;
}

/** Why a wait or a render stops when its caller gives up (a report job aborted or past its deadline). */
const abortedError = (signal: AbortSignal): Error =>
  (signal.reason instanceof Error ? signal.reason : new AppError(503, 'PDF render abandoned', 'exportAborted'));

/** Takes a slot, waiting `waitMs` at most for one (0: none free, 429 at once); `signal` withdraws a waiting caller. */
function acquire(waitMs: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(abortedError(signal));
  if (pdfRenders < PDF_MAX_RENDERS) { pdfRenders++; return Promise.resolve(); }
  if (waitMs <= 0) return Promise.reject(busy());
  return new Promise<void>((resolve, reject) => {
    const withdraw = (): void => {
      const i = waiters.indexOf(entry);
      if (i >= 0) waiters.splice(i, 1);
    };
    const onAbort = (): void => { clearTimeout(timer); withdraw(); reject(abortedError(signal!)); };
    const entry = {
      grant: () => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); resolve(); },
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      withdraw();
      reject(busy());
    }, waitMs);
    timer.unref?.();
    signal?.addEventListener('abort', onAbort, { once: true });
    waiters.push(entry);
  });
}

/**
 * Runs `fn` in one of the PDF render slots of the instance. A console request answers 429 exportBusy when they are all
 * taken; `waitMs` lets a background caller (a report job) wait that long for one first, `signal` withdraws it from
 * the queue when it gives up (no render started for a job already abandoned).
 */
export async function inPdfSlot<T>(fn: () => Promise<T>, opts: { waitMs?: number; signal?: AbortSignal } = {}): Promise<T> {
  await acquire(Math.max(0, opts.waitMs ?? 0), opts.signal);
  try { return await fn(); } finally { release(); }
}

/** The rows of a PDF export, at most PDF_MAX_ROWS (413 beyond: the CSV and XLSX formats take the whole list). */
export function checkPdfRows(count: number): void {
  if (count > PDF_MAX_ROWS) {
    throw new AppError(413, `A PDF export is limited to ${PDF_MAX_ROWS} devices (${count} selected): narrow the filters or use CSV or XLSX`, 'exportTooLarge');
  }
}

/** What renderHtmlPdf needs of a browser (puppeteer's, or a fake in the tests). */
export interface PdfBrowser {
  newPage(): Promise<{
    setContent(html: string, o: { waitUntil: 'domcontentloaded'; timeout: number }): Promise<unknown>;
    pdf(o: Record<string, unknown>): Promise<Uint8Array>;
  }>;
  close(): Promise<void>;
}

const PDF_OPTIONS = { format: 'A4', landscape: true, margin: { top: '15mm', bottom: '15mm', left: '10mm', right: '10mm' }, printBackground: true };

/**
 * Renders an HTML document to an A4 landscape PDF in its own Chromium, PDF_RENDER_TIMEOUT_MS at most (503
 * exportTimeout beyond, or `timeoutMs`; `timeoutMessage` for a caller other than the console); `signal` stops it early
 * (a report job aborted). The browser is closed in every case. Call it inside inPdfSlot. `launch`: the tests' browser.
 */
export async function renderHtmlPdf(html: string, opts: {
  timeoutMs?: number; timeoutMessage?: string; signal?: AbortSignal; launch?: () => Promise<PdfBrowser>;
} = {}): Promise<Buffer> {
  const timeoutMs = opts.timeoutMs ?? PDF_RENDER_TIMEOUT_MS;
  const launch = opts.launch ?? (async () => (await import('../../utils/chromium')).launchChromium() as unknown as Promise<PdfBrowser>);
  const signal = opts.signal;
  if (signal?.aborted) throw abortedError(signal);
  const browser = await launch();
  let timer: NodeJS.Timeout | undefined;
  let onAbort: (() => void) | undefined;
  try {
    const render = (async () => {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
      return page.pdf(PDF_OPTIONS);
    })();
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new AppError(503, opts.timeoutMessage ?? 'The PDF export took too long, use CSV or XLSX', 'exportTimeout')), timeoutMs);
    });
    const stopped = new Promise<never>((_resolve, reject) => {
      if (!signal) return;
      onAbort = () => reject(abortedError(signal));
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    });
    render.catch(() => undefined); // settled after a timeout: the browser is closed below
    stopped.catch(() => undefined);
    return Buffer.from(await Promise.race([render, timeout, stopped]));
  } finally {
    if (timer) clearTimeout(timer);
    if (onAbort) signal?.removeEventListener('abort', onAbort);
    await browser.close().catch(() => undefined);
  }
}
