// RFC 3161 time stamps of the seals (docs: audit-durci §6.4): optional
// (AUDIT_TSA_URL). The request is DER encoded by hand (69 bytes); the
// response is read by the DER parser of the core (services/deviceKey/der.ts):
// status, the token's content type, the imprint (= seal_hash), the nonce,
// genTime, and the pinned certificate (AUDIT_TSA_CERT_SHA256). The full CMS
// signature is checked offline by OpenSSL (openssl ts -verify, §6.7): Node
// has no CMS verifier.
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  CLASS_CONTEXT, asInt, asOctetString, asOid, asSequence, children, explicitInner, parseDer, type Tlv,
} from '../services/deviceKey/der';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

export class TsaError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'TsaError';
    this.code = code;
  }
}

/** A positive nonce of 64 bits whose first byte is never 0 (minimal DER). */
export function newNonce(): Buffer {
  const n = randomBytes(8);
  n[0] = (n[0] & 0x7f) | 0x01;
  return n;
}

/** TimeStampReq v1: imprint SHA-256 = seal_hash, nonce, certReq TRUE, no policy. */
export function buildTimeStampReq(sealHash: Buffer, nonce: Buffer): Buffer {
  if (sealHash.length !== 32) throw new TsaError('format', 'the imprint is a SHA-256');
  if (nonce.length !== 8 || (nonce[0] & 0x80) !== 0 || nonce[0] === 0) throw new TsaError('format', 'invalid nonce');
  const algo = Buffer.from('300d06096086480165030402010500', 'hex');        // AlgorithmIdentifier sha256, NULL
  const imprint = Buffer.concat([Buffer.from([0x30, algo.length + 34]), algo, Buffer.from([0x04, 0x20]), sealHash]);
  const body = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01]),                                        // version 1
    imprint,
    Buffer.from([0x02, 0x08]), nonce,                                       // nonce
    Buffer.from([0x01, 0x01, 0xff]),                                        // certReq TRUE
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** GeneralizedTime "YYYYMMDDHHMMSS[.f*]Z" → ISO instant. */
function generalizedTime(t: Tlv): string {
  if (t.cls !== 0 || t.tag !== 24) throw new TsaError('format', 'genTime is not a GeneralizedTime');
  const s = t.value.toString('latin1');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d{1,9}))?Z$/.exec(s);
  if (!m) throw new TsaError('format', 'malformed genTime');
  const ms = m[7] ? m[7].padEnd(3, '0').slice(0, 3) : '000';
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${ms}Z`;
  if (Number.isNaN(new Date(iso).getTime())) throw new TsaError('format', 'invalid genTime');
  return iso;
}

function bigIntOf(t: Tlv): bigint {
  if (t.cls !== 0 || t.tag !== 2) throw new TsaError('format', 'expected an INTEGER');
  let n = 0n;
  for (const b of t.value) n = (n << 8n) | BigInt(b);
  if (t.value.length && (t.value[0] & 0x80)) n -= 1n << BigInt(t.value.length * 8);
  return n;
}

export interface ParsedTimeStamp {
  status: number;
  genTime: string;
  /** SHA-256 (hex) of each certificate the SignedData carries. */
  certificateSha256: string[];
}

/** Reads a TimeStampResp and checks it against the request: status granted
 *  (0 or 1), SignedData of id-ct-TSTInfo, imprint SHA-256 = sealHash, nonce
 *  = the request's; pinned certificate when `pinSha256` is given. */
export function parseTimeStampResp(der: Buffer, sealHash: Buffer, nonce: Buffer, pinSha256?: string): ParsedTimeStamp {
  let root: Tlv[];
  try {
    root = asSequence(parseDer(der));
  } catch (err) {
    throw new TsaError('format', `unreadable time-stamp response: ${(err as Error).message}`);
  }
  try {
    const statusInfo = asSequence(root[0]);
    const status = asInt(statusInfo[0]);
    if (status !== 0 && status !== 1) throw new TsaError('refused', `time-stamp refused (status ${status})`);
    if (!root[1]) throw new TsaError('format', 'no time-stamp token');
    const contentInfo = asSequence(root[1]);
    if (asOid(contentInfo[0]) !== OID_SIGNED_DATA) throw new TsaError('format', 'the token is not a SignedData');
    const signedData = asSequence(explicitInner(contentInfo[1]));
    const encap = asSequence(signedData[2]);
    if (asOid(encap[0]) !== OID_TST_INFO) throw new TsaError('format', 'the token does not hold a TSTInfo');
    const eContent = asOctetString(explicitInner(encap[1]));
    const tst = asSequence(parseDer(eContent));
    // TSTInfo: version, policy, messageImprint, serialNumber, genTime, [accuracy], [ordering], [nonce], …
    const imprint = asSequence(tst[2]);
    const algo = asSequence(imprint[0]);
    if (asOid(algo[0]) !== OID_SHA256) throw new TsaError('imprint', 'the imprint is not a SHA-256');
    if (!asOctetString(imprint[1]).equals(sealHash)) throw new TsaError('imprint', 'the imprint is not the seal hash');
    const genTime = generalizedTime(tst[4]);
    const nonceTlv = tst.slice(5).find((t) => t.cls === 0 && t.tag === 2);
    if (!nonceTlv) throw new TsaError('nonce', 'the response carries no nonce');
    let expected = 0n;
    for (const b of nonce) expected = (expected << 8n) | BigInt(b);
    if (bigIntOf(nonceTlv) !== expected) throw new TsaError('nonce', 'the nonce is not the request\'s');
    // certificates [0] IMPLICIT SET OF Certificate
    const certificateSha256: string[] = [];
    const certs = signedData.find((t, i) => i >= 3 && t.cls === CLASS_CONTEXT && t.tag === 0);
    if (certs) for (const c of children(certs)) certificateSha256.push(createHash('sha256').update(c.raw).digest('hex'));
    if (pinSha256 && !certificateSha256.includes(pinSha256)) {
      throw new TsaError('pin', 'no certificate of the response has the pinned SHA-256');
    }
    return { status, genTime, certificateSha256 };
  } catch (err) {
    if (err instanceof TsaError) throw err;
    throw new TsaError('format', `malformed time-stamp response: ${(err as Error).message}`);
  }
}

/** The imprint (hex) of a stored token, for the verification (§6.6). */
export function tokenImprint(der: Buffer): string | null {
  try {
    const root = asSequence(parseDer(der));
    const contentInfo = asSequence(root[1]);
    const signedData = asSequence(explicitInner(contentInfo[1]));
    const encap = asSequence(signedData[2]);
    const tst = asSequence(parseDer(asOctetString(explicitInner(encap[1]))));
    return asOctetString(asSequence(tst[2])[1]).toString('hex');
  } catch {
    return null;
  }
}

export interface TsaSettings {
  url: string;
  timeoutMs: number;
  authFile?: string;
  certSha256?: string;
}

/** Asks the authority for a time stamp of `sealHash`: the DER response and
 *  its genTime, or TsaError. Never in a transaction (§6.5). */
export async function requestTimeStamp(sealHash: Buffer, s: TsaSettings): Promise<{ token: Buffer; genTime: string }> {
  const nonce = newNonce();
  const body = buildTimeStampReq(sealHash, nonce);
  const headers: Record<string, string> = { 'Content-Type': 'application/timestamp-query', Accept: 'application/timestamp-reply' };
  if (s.authFile) headers.Authorization = readFileSync(s.authFile, 'utf8').trim();
  let res: Response;
  try {
    res = await fetch(s.url, { method: 'POST', headers, body, signal: AbortSignal.timeout(s.timeoutMs), redirect: 'error' });
  } catch (err) {
    throw new TsaError('network', `time-stamping authority unreachable: ${(err as Error).name}`);
  }
  if (!res.ok) throw new TsaError('http', `time-stamping authority answered ${res.status}`);
  const token = Buffer.from(await res.arrayBuffer());
  if (token.length === 0 || token.length > 256 * 1024) throw new TsaError('format', 'time-stamp response of an unexpected size');
  const parsed = parseTimeStampResp(token, sealHash, nonce, s.certSha256 || undefined);
  return { token, genTime: parsed.genTime };
}
