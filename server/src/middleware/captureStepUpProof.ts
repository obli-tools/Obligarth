import type { Request, Response, NextFunction } from 'express';

// P5 (docs/mobile/device-bound-2fa.md §6.0): step-up PROOFS never travel
// with the business body.
//
// Clients (web interceptor, Android app 0.3.x) replay the original JSON body
// with the proof fields added (`twoFactorCode`, `trustIp`, and later
// `stepUpPassword`, `deviceAssertion`, `deviceBulkId`). Left in req.body they
// were (a) stripped by validate() before the envelope could read them (users,
// teams, profile routes: the code was never seen), and (b) copied into
// approval payloads, error logs (`body: req.body`) and `...req.body` inserts.
//
// Mounted in app.ts right after express.json() and the session, before any
// router: when req.body is a plain object, the proof fields are MOVED to
// req.stepUpProof and deleted from the body. Every reader (checkSecondFactor
// in services/deviceKey/stepUpProof.ts) reads req.stepUpProof only.
// validate.ts is untouched.
//
// Raw-body routes (owners' decision INT-INTC-R1 A, 19/10): a file route (the
// exchange files of the Apple integrations) reads its body as bytes, so the
// proof cannot ride in it. The client sends the SAME bytes again with the
// proof in the header X-Obli-Step-Up-Proof (base64url of the JSON object of
// the proof fields). The header is always removed here (never logged, never
// seen by a router); it is kept aside and becomes req.stepUpProof only on a
// route that opts in with adoptHeaderStepUpProof (the raw parsers of the file
// routes). A JSON route ignores it: its proof travels in its body.

export interface StepUpProof {
  /** TOTP code as typed (trimmed string). */
  twoFactorCode?: string;
  /** Explicit "trust this IP" opt-in; honoured only when `=== true`. */
  trustIp?: boolean;
  /** Password fallback in a device-bound session (later lot). */
  stepUpPassword?: string;
  /** Device-key assertion (later lot) — raw, validated by its reader. */
  deviceAssertion?: unknown;
  /** Bulk step-up id (later lot) — raw, validated by its reader. */
  deviceBulkId?: unknown;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      stepUpProof?: StepUpProof;
    }
  }
}

export const STEP_UP_PROOF_FIELDS = ['twoFactorCode', 'trustIp', 'stepUpPassword', 'deviceAssertion', 'deviceBulkId'] as const;

/** The header of the proof of a raw-body route (lower case, as Node keys it). */
export const STEP_UP_PROOF_HEADER = 'x-obli-step-up-proof';
/** base64url of a small JSON object: a larger header is ignored. */
const HEADER_MAX_CHARS = 8192;

/** The proof of the header, kept aside until a raw-body route adopts it. */
const headerProofs = new WeakMap<Request, StepUpProof>();

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Moves the proof fields of `source` into a proof (they are deleted from `source`). */
function takeProof(source: Record<string, unknown>): StepUpProof {
  const proof: StepUpProof = {};
  for (const key of STEP_UP_PROOF_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    const v = source[key];
    delete source[key];
    switch (key) {
      case 'twoFactorCode':
        // The app and the web send a string; tolerate a JSON number.
        if (typeof v === 'string' || typeof v === 'number') {
          const s = String(v).trim();
          if (s) proof.twoFactorCode = s.slice(0, 32);
        }
        break;
      case 'trustIp':
        proof.trustIp = v === true;
        break;
      case 'stepUpPassword':
        if (typeof v === 'string' && v.length > 0) proof.stepUpPassword = v.slice(0, 1024);
        break;
      case 'deviceAssertion':
        proof.deviceAssertion = v;
        break;
      case 'deviceBulkId':
        proof.deviceBulkId = v;
        break;
    }
  }
  return proof;
}

/** The proof of the header (absent, malformed or too large: none). The header is always removed from the request. */
function takeHeaderProof(req: Request): StepUpProof | null {
  const raw = req.headers[STEP_UP_PROOF_HEADER];
  if (raw === undefined) return null;
  delete req.headers[STEP_UP_PROOF_HEADER];
  const text = Array.isArray(raw) ? raw[0] : raw;
  if (typeof text !== 'string' || text.length === 0 || text.length > HEADER_MAX_CHARS || !/^[A-Za-z0-9_-]+={0,2}$/.test(text)) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.from(text, 'base64url').toString('utf8')); } catch { return null; }
  if (!isPlainObject(parsed)) return null;
  const proof = takeProof(parsed);
  return Object.keys(proof).length > 0 ? proof : null;
}

export function captureStepUpProof(req: Request, _res: Response, next: NextFunction): void {
  const body = req.body as unknown;
  req.stepUpProof = isPlainObject(body) ? takeProof(body) : {};
  const fromHeader = takeHeaderProof(req);
  if (fromHeader) headerProofs.set(req, fromHeader);
  next();
}

/**
 * A raw-body route takes the proof of the header (INT-INTC-R1 A). Called by
 * the raw parsers of the file routes only; a proof already read from a JSON
 * body is never replaced.
 */
export function adoptHeaderStepUpProof(req: Request): void {
  const fromHeader = headerProofs.get(req);
  headerProofs.delete(req);
  if (!fromHeader) return;
  const current = req.stepUpProof;
  if (current && Object.keys(current).length > 0) return;
  req.stepUpProof = fromHeader;
}
