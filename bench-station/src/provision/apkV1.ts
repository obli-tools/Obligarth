import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { zipEntries, zipRead } from '../zip';

/**
 * Obligarth bench station — the signer of an APK from its JAR (v1) signature, the fallback when the archive carries no
 * v2/v3 block (lot BANC §6.3: « apkSigner (v2, repli v1) »). The certificate is read, not verified: Android verified
 * the package when it installed it, and the station only compares the certificate's SHA-256 to the pinned one.
 *
 * META-INF/<name>.RSA|.DSA|.EC is a PKCS#7 SignedData (DER): ContentInfo { contentType, [0] SignedData { version,
 * digestAlgorithms, contentInfo, [0] IMPLICIT certificates, … } }. The FIRST certificate of the set is taken, as
 * Android's PackageInfo.signatures does for a single signer.
 */

interface Tlv { tag: number; start: number; header: number; length: number }

function tlv(b: Buffer, at: number): Tlv {
  if (at + 2 > b.length) throw new Error('DER: truncated');
  const tag = b[at];
  let len = b[at + 1];
  let header = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || at + 2 + n > b.length) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    header += n;
  }
  if (at + header + len > b.length) throw new Error('DER: past the end');
  return { tag, start: at, header, length: len };
}

const children = (b: Buffer, t: Tlv): Tlv[] => {
  const out: Tlv[] = [];
  let at = t.start + t.header;
  const end = t.start + t.header + t.length;
  while (at < end) { const c = tlv(b, at); out.push(c); at = c.start + c.header + c.length; }
  return out;
};

/** The DER of the first certificate of a PKCS#7 SignedData. */
export function firstCertificateOfPkcs7(der: Buffer): Buffer {
  const ci = tlv(der, 0);
  if (ci.tag !== 0x30) throw new Error('PKCS#7: not a SEQUENCE');
  const [, explicit] = children(der, ci);
  if (!explicit || explicit.tag !== 0xa0) throw new Error('PKCS#7: no content');
  const [signedData] = children(der, explicit);
  if (!signedData || signedData.tag !== 0x30) throw new Error('PKCS#7: no SignedData');
  const certs = children(der, signedData).find((c) => c.tag === 0xa0);
  if (!certs) throw new Error('PKCS#7: no certificate');
  const [first] = children(der, certs);
  if (!first || first.tag !== 0x30) throw new Error('PKCS#7: no certificate');
  return der.subarray(first.start, first.start + first.header + first.length);
}

/** SHA-256 (hex) of the v1 signer's certificate of each META-INF signature block; [] when none. */
export async function v1SignersOfFile(file: string): Promise<string[]> {
  const buf = await readFile(file);
  const out: string[] = [];
  for (const e of zipEntries(buf)) {
    if (!/^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name)) continue;
    const cert = firstCertificateOfPkcs7(zipRead(buf, e, 1024 * 1024));
    out.push(createHash('sha256').update(cert).digest('hex'));
  }
  return [...new Set(out)];
}
