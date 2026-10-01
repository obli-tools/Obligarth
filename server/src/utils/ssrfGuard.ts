import { lookup } from 'dns/promises';
import { BlockList, isIP } from 'net';

// Reject any HTTP target that resolves to a private / loopback /
// link-local / metadata range. Used by the webhook notification
// channel so an admin (or compromised tenant admin) can't aim our
// outbound fetcher at internal services (Redis, Kubelet, AWS
// metadata 169.254.169.254, …).
//
// We resolve the hostname BEFORE the request fires and re-check the
// raw IP — `https://example.com` could otherwise CNAME-redirect onto
// an internal address. This is best-effort against an attacker who
// races DNS responses; for stronger isolation production should use
// an outbound HTTP proxy with allow-listed destinations.

const PRIVATE_V4_PREFIXES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,           // link-local + AWS metadata
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0 – 172.31.255.255
  /^0\./,                  // 0.0.0.0/8
  /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./, // CGNAT 100.64.0.0/10
];

export function isPrivateIPv4(ip: string): boolean {
  return PRIVATE_V4_PREFIXES.some((re) => re.test(ip));
}

export function isPrivateIPv6(ip: string): boolean {
  const lc = ip.toLowerCase();
  // ::1 (loopback), fc00::/7 (ULA), fe80::/10 (link-local),
  // ::ffff:<v4> (mapped — re-check the v4 portion).
  if (lc === '::1') return true;
  if (lc.startsWith('fc') || lc.startsWith('fd')) return true;
  if (lc.startsWith('fe8') || lc.startsWith('fe9') || lc.startsWith('fea') || lc.startsWith('feb')) return true;
  const mapped = lc.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}

export async function assertPublicHttpUrl(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Refused non-HTTP scheme: ${url.protocol}`);
  }
  const hostname = url.hostname;
  // Localhost + literal IPs handled directly.
  if (hostname === 'localhost' || hostname === 'localhost.localdomain') {
    throw new Error('Refused private destination (localhost)');
  }
  const v = isIP(hostname);
  if (v === 4 && isPrivateIPv4(hostname)) throw new Error(`Refused private destination (${hostname})`);
  if (v === 6 && isPrivateIPv6(hostname)) throw new Error(`Refused private destination (${hostname})`);
  if (v === 0) {
    // DNS hostname — resolve and screen. `lookup` returns the OS
    // resolver's first answer; we screen ALL answers when available.
    try {
      const all = await lookup(hostname, { all: true });
      for (const a of all) {
        if (a.family === 4 && isPrivateIPv4(a.address)) throw new Error(`Refused private destination (${hostname} → ${a.address})`);
        if (a.family === 6 && isPrivateIPv6(a.address)) throw new Error(`Refused private destination (${hostname} → ${a.address})`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Refused')) throw err;
      throw new Error(`Could not resolve ${hostname}: ${(err as Error).message}`);
    }
  }
  return url;
}

// ── SIEM destinations (audit-durci §8.1) ────────────────────────────────────
// A SIEM is often on the local network: the private ranges (RFC 1918, ULA,
// CGNAT) are admitted. Refused: loopback (unless the laboratory switch
// AUDIT_SIEM_ALLOW_LOOPBACK), link-local (169.254.0.0/16, fe80::/10, hence the
// cloud metadata services), 0.0.0.0/8, multicast, reserved and unspecified
// addresses, whatever their spelling: the ranges are BlockLists, which also
// check an IPv4-mapped IPv6 address (::ffff:7f00:1, the form a URL gives to
// [::ffff:127.0.0.1]) as the IPv4 address it carries; the deprecated
// IPv4-compatible range (::/96) is refused. The name is resolved at every
// connection; the caller connects to one of the addresses returned, never
// resolves again.

function blockListOf(subnets: ReadonlyArray<readonly [string, number, 'ipv4' | 'ipv6']>): BlockList {
  const b = new BlockList();
  for (const [net, prefix, type] of subnets) b.addSubnet(net, prefix, type);
  return b;
}

const SIEM_LOOPBACK = blockListOf([['127.0.0.0', 8, 'ipv4'], ['::1', 128, 'ipv6']]);
const SIEM_REFUSED: ReadonlyArray<readonly [string, BlockList]> = [
  ['link-local', blockListOf([['169.254.0.0', 16, 'ipv4'], ['fe80::', 10, 'ipv6']])],
  ['unspecified', blockListOf([['0.0.0.0', 8, 'ipv4'], ['::', 128, 'ipv6']])],
  ['multicast', blockListOf([['224.0.0.0', 4, 'ipv4'], ['ff00::', 8, 'ipv6']])],
  ['reserved', blockListOf([['240.0.0.0', 4, 'ipv4'], ['::', 96, 'ipv6']])],
];

/** Why a SIEM may not be reached at `ip`, or null. */
export function siemRefusal(ip: string, family: number, allowLoopback: boolean): string | null {
  const type = family === 6 ? 'ipv6' : 'ipv4';
  const address = String(ip ?? '').replace(/%.*$/, '');      // an IPv6 zone index is not part of the address
  if (isIP(address) !== (family === 6 ? 6 : 4)) return 'invalid address';
  if (SIEM_LOOPBACK.check(address, type)) return allowLoopback ? null : 'loopback';
  for (const [why, list] of SIEM_REFUSED) if (list.check(address, type)) return why;
  return null;
}

/** The addresses a SIEM destination `host` may be reached at, or an Error
 *  that says why not (no DNS answer, a refused range). */
export async function assertSiemTarget(host: string, o: { allowLoopback?: boolean } = {}): Promise<Array<{ address: string; family: number }>> {
  const allowLoopback = o.allowLoopback === true;
  const name = String(host ?? '').trim().replace(/^\[(.*)\]$/, '$1');
  if (!name || name.length > 253) throw new Error('Invalid SIEM host');
  if (!allowLoopback && /^(localhost|localhost\.localdomain)$/i.test(name)) throw new Error('Refused SIEM destination (loopback)');
  const v = isIP(name);
  let all: Array<{ address: string; family: number }>;
  if (v) {
    all = [{ address: name, family: v }];
  } else {
    try {
      all = await lookup(name, { all: true });
    } catch (err) {
      throw new Error(`Could not resolve ${name}: ${(err as Error).message}`);
    }
  }
  if (!all.length) throw new Error(`Could not resolve ${name}`);
  for (const a of all) {
    const why = siemRefusal(a.address, a.family, allowLoopback);
    if (why) throw new Error(`Refused SIEM destination (${why}: ${name}${v ? '' : ` → ${a.address}`})`);
  }
  return all;
}
