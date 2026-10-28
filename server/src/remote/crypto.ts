import { createCipheriv, createDecipheriv, createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject } from 'node:crypto';
import { b64url, p256PublicKey, signMessage, verifySignature } from '../legacyAgent/signature';

// =============================================================================
// The channel between the bridge agent and the server on the stream of a remote session (P0-15 §4.4, T5), in the
// format the agent chose (agent-android core/RemoteProtocol.kt, T7a), taken as is:
//   attach   GET /agent/v1/remote/<id>/stream signed OBL-AGENT-1 with seq 0 over
//            SHA-256(the 32 bytes of the stream token ‖ Obl-Nonce (16 bytes) ‖ Obl-Ecdh (SPKI DER of an ephemeral P-256
//            key)), both headers base64url without padding;
//   hello    the server's first frame, in clear (a text frame): { type: 'hello', sessionId, mode, ts, serverEcdh, sig },
//            serverEcdh the SPKI DER (base64url) of the server's ephemeral P-256 key, sig the ECDSA P-256 / SHA-256 DER
//            signature (base64url) by the instance key (legacy_agent_signing_key, the key the fleet pins) of the lines
//              OBL-REMOTE-HELLO-1 ‖ nonce ‖ agent's SPKI ‖ server's SPKI (all three base64url) ‖ sessionId ‖ mode ‖ ts
//            joined by '\n' (no final line feed): a hello made for another attach (another nonce, another key) or
//            changed on the way (the mode raised, another server key) never holds;
//   keys     ECDH P-256 (the X coordinate, 32 bytes), then HKDF-SHA256 (salt: the agent's nonce, info:
//            'obl-remote-1|<sessionId>') of 64 bytes: the first 32 the key of the agent → server direction, the last 32
//            the key of the server → agent direction (never the same key in both directions);
//   frames   every frame after the hello, text or binary, travels as a WebSocket binary frame:
//              kind (1 byte: 1 the plain is a JSON text message, 2 a binary message) ‖ counter (12 bytes, big endian,
//              the first 4 always zero) ‖ AES-256-GCM(plain) ‖ tag (16 bytes)
//            the counter is the GCM nonce (12 bytes), the 13 header bytes the additional data; each direction counts
//            from 0 and the receiver refuses any counter not above the last one it opened (replayed, reordered).
// Pure: no database, no project import but the signatures of the agent surface; the unit tests load it alone.
// =============================================================================

export const HELLO_TAG = 'OBL-REMOTE-HELLO-1';
export const HKDF_INFO_PREFIX = 'obl-remote-1|';
export const NONCE_BYTES = 16;
export const STREAM_TOKEN_BYTES = 32;
export const FRAME_KIND_TEXT = 0x01;
export const FRAME_KIND_BINARY = 0x02;
export const FRAME_HEADER_BYTES = 13;
export const FRAME_TAG_BYTES = 16;
const MAX_COUNTER = (1n << 63n) - 1n;

/** The hash the attach request is signed over: SHA-256 (hex) of token ‖ nonce ‖ the agent's SPKI. */
export function attachBodySha256(streamToken: Buffer, agentNonce: Buffer, agentEcdhSpki: Buffer): string {
  return createHash('sha256').update(streamToken).update(agentNonce).update(agentEcdhSpki).digest('hex');
}

/** The signed text of the hello (no final line feed). */
export function helloCanonical(h: { agentNonce: Buffer; agentEcdhSpki: Buffer; serverEcdhSpki: Buffer; sessionId: string; mode: string; ts: number }): string {
  return [HELLO_TAG, b64url(h.agentNonce), b64url(h.agentEcdhSpki), b64url(h.serverEcdhSpki), h.sessionId, h.mode, String(h.ts)].join('\n');
}

export interface ServerHello { type: 'hello'; sessionId: string; mode: string; ts: number; serverEcdh: string; sig: string }

/** The hello of an attach, signed by the instance key. */
export function signHello(instanceKey: KeyObject, h: { agentNonce: Buffer; agentEcdhSpki: Buffer; serverEcdhSpki: Buffer; sessionId: string; mode: string; ts: number }): ServerHello {
  return { type: 'hello', sessionId: h.sessionId, mode: h.mode, ts: h.ts, serverEcdh: b64url(h.serverEcdhSpki), sig: signMessage(instanceKey, helloCanonical(h)) };
}

/** Checks a hello as the agent does (tests, the vectors): the signature of `instanceSpki` over the agent's own nonce and key. */
export function helloHolds(hello: ServerHello, instanceSpki: Buffer, agentNonce: Buffer, agentEcdhSpki: Buffer): boolean {
  const key = p256PublicKey(instanceSpki);
  const serverEcdhSpki = Buffer.from(String(hello.serverEcdh ?? ''), 'base64url');
  if (!key || !p256PublicKey(serverEcdhSpki)) return false;
  return verifySignature(key, helloCanonical({ agentNonce, agentEcdhSpki, serverEcdhSpki, sessionId: hello.sessionId, mode: hello.mode, ts: hello.ts }), hello.sig);
}

/** The server's ephemeral P-256 pair of one attach. */
export interface EphemeralKey { privateKey: KeyObject; spki: Buffer }

export function ephemeralKey(): EphemeralKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { privateKey, spki: publicKey.export({ format: 'der', type: 'spki' }) as Buffer };
}

/** ECDH P-256 with the peer's SPKI (P-256 only, checked by p256PublicKey): the X coordinate, 32 bytes. null: not a key. */
export function sharedSecret(own: KeyObject, peerSpki: Buffer): Buffer | null {
  const peer = p256PublicKey(peerSpki);
  if (!peer) return null;
  return diffieHellman({ privateKey: own, publicKey: peer });
}

export interface SessionKeys { agentToServer: Buffer; serverToAgent: Buffer }

/** HKDF-SHA256 (salt = the agent's nonce, info = 'obl-remote-1|<sessionId>'), 64 bytes: agent → server, then server → agent. */
export function sessionKeys(secret: Buffer, agentNonce: Buffer, sessionId: string): SessionKeys {
  const okm = Buffer.from(hkdfSync('sha256', secret, agentNonce, Buffer.from(HKDF_INFO_PREFIX + sessionId, 'utf8'), 64));
  return { agentToServer: okm.subarray(0, 32), serverToAgent: okm.subarray(32, 64) };
}

/** The SPKI DER of a private key's public half (the vectors). */
export const spkiOfPrivate = (key: KeyObject): Buffer => createPublicKey(key).export({ format: 'der', type: 'spki' }) as Buffer;

export class FrameError extends Error {}

function header(kind: number, counter: bigint): Buffer {
  const h = Buffer.alloc(FRAME_HEADER_BYTES);
  h[0] = kind;
  h.writeBigUInt64BE(counter, 5);
  return h;
}

/** Seals the frames of one direction, counting from 0 (one sealer per direction and per attach). */
export class FrameSealer {
  private next = 0n;
  private readonly key: Buffer;
  constructor(key: Buffer) {
    if (key.length !== 32) throw new FrameError('AES-256 key expected');
    this.key = Buffer.from(key);
  }

  seal(kind: number, plain: Buffer): Buffer {
    if (kind !== FRAME_KIND_TEXT && kind !== FRAME_KIND_BINARY) throw new FrameError('unknown frame kind');
    if (this.next > MAX_COUNTER) throw new FrameError('counter exhausted');
    const h = header(kind, this.next++);
    const c = createCipheriv('aes-256-gcm', this.key, h.subarray(1, 13), { authTagLength: FRAME_TAG_BYTES });
    c.setAAD(h);
    return Buffer.concat([h, c.update(plain), c.final(), c.getAuthTag()]);
  }

  /** Tests: the counter of the next frame. */
  get counter(): bigint { return this.next; }
}

export interface OpenedFrame { kind: number; plain: Buffer; counter: bigint }

/** Opens the frames of one direction: throws FrameError on a short or malformed frame, a counter not above the last one,
 *  a frame that does not authenticate. The first failure closes the stream (the caller's policy). */
export class FrameOpener {
  private last = -1n;
  private readonly key: Buffer;
  constructor(key: Buffer) {
    if (key.length !== 32) throw new FrameError('AES-256 key expected');
    this.key = Buffer.from(key);
  }

  open(frame: Buffer): OpenedFrame {
    if (frame.length < FRAME_HEADER_BYTES + FRAME_TAG_BYTES) throw new FrameError('short frame');
    const kind = frame[0];
    if (kind !== FRAME_KIND_TEXT && kind !== FRAME_KIND_BINARY) throw new FrameError('unknown frame kind');
    if (frame.readUInt32BE(1) !== 0) throw new FrameError('counter out of range');
    const counter = frame.readBigUInt64BE(5);
    if (counter > MAX_COUNTER || counter <= this.last) throw new FrameError('counter not increasing');
    const h = frame.subarray(0, FRAME_HEADER_BYTES);
    const tag = frame.subarray(frame.length - FRAME_TAG_BYTES);
    let plain: Buffer;
    try {
      const d = createDecipheriv('aes-256-gcm', this.key, h.subarray(1, 13), { authTagLength: FRAME_TAG_BYTES });
      d.setAAD(h);
      d.setAuthTag(tag);
      plain = Buffer.concat([d.update(frame.subarray(FRAME_HEADER_BYTES, frame.length - FRAME_TAG_BYTES)), d.final()]);
    } catch {
      throw new FrameError('frame authentication failed');
    }
    this.last = counter;
    return { kind, plain, counter };
  }
}
