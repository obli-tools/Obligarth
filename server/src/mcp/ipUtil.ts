import { BlockList, isIP } from 'node:net';
import { normalizeIp } from '../utils/clientIp';

// =============================================================================
// Addresses and networks of the MCP server: allow-lists of the keys, the IP
// policy, the blocks. Pure functions (no database), in the canonical text form
// PostgreSQL gives an inet / cidr ('198.51.100.0/24', '2001:db8::/48').
// =============================================================================

export interface Cidr {
  family: 4 | 6;
  /** The network address (host bits cleared). */
  network: string;
  prefix: number;
  /** network/prefix. */
  text: string;
}

const MAX_V6 = (1n << 128n) - 1n;

/** An IPv6 address as a 128-bit integer (undefined: not an IPv6 address). */
export function v6ToBig(ip: string): bigint | undefined {
  if (isIP(ip) !== 6) return undefined;
  let s = ip;
  // A trailing dotted IPv4 (::ffff:1.2.3.4) becomes two groups.
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (dotted) {
    const parts = dotted[1].split('.').map(Number);
    s = s.slice(0, -dotted[1].length) + `${((parts[0] << 8) | parts[1]).toString(16)}:${((parts[2] << 8) | parts[3]).toString(16)}`;
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const missing = 8 - h.length - t.length;
  const groups = s.includes('::') ? [...h, ...Array(missing).fill('0'), ...t] : h;
  if (groups.length !== 8) return undefined;
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(parseInt(g || '0', 16));
  return n;
}

/** A 128-bit integer as a compressed IPv6 address. */
export function bigToV6(n: bigint): string {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) groups.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // The longest run of zero groups (2 or more) becomes '::'.
  let best = -1; let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return groups.join(':');
  return `${groups.slice(0, best).join(':')}::${groups.slice(best + bestLen).join(':')}`;
}

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, p) => ((acc << 8) >>> 0) + Number(p), 0) >>> 0;
}

function intToV4(n: number): string {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

/** A CIDR or a bare address ('203.0.113.7' = /32), host bits cleared; null when invalid. */
export function parseCidr(raw: unknown): Cidr | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s || s.length > 64) return null;
  const [addrRaw, bitsText, extra] = s.split('/');
  if (extra !== undefined) return null;
  const addr = normalizeIp(addrRaw);
  const family = isIP(addr);
  if (family === 0) return null;
  const max = family === 4 ? 32 : 128;
  if (bitsText !== undefined && !/^\d{1,3}$/.test(bitsText)) return null;
  const prefix = bitsText === undefined ? max : Number(bitsText);
  if (prefix < 0 || prefix > max) return null;
  if (family === 4) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = intToV4((v4ToInt(addr) & mask) >>> 0);
    return { family: 4, network, prefix, text: `${network}/${prefix}` };
  }
  const n = v6ToBig(addr);
  if (n === undefined) return null;
  const mask = prefix === 0 ? 0n : (MAX_V6 >> BigInt(128 - prefix)) << BigInt(128 - prefix);
  const network = bigToV6(n & mask);
  return { family: 6, network, prefix, text: `${network}/${prefix}` };
}

/** A matcher of a list of CIDRs (invalid entries are ignored: they never match). */
export function compileCidrs(list: readonly string[]): (ip: string) => boolean {
  const bl = new BlockList();
  let any = false;
  for (const raw of list) {
    const c = parseCidr(raw);
    if (!c) continue;
    any = true;
    bl.addSubnet(c.network, c.prefix, c.family === 4 ? 'ipv4' : 'ipv6');
  }
  return (ip: string) => {
    if (!any) return false;
    const a = normalizeIp(ip);
    const f = isIP(a);
    return f !== 0 && bl.check(a, f === 4 ? 'ipv4' : 'ipv6');
  };
}

/** The /64 of an IPv6 address ('2001:db8:1:2::/64'), or null for an IPv4 one. */
export function prefix64(ip: string): string | null {
  const a = normalizeIp(ip);
  if (isIP(a) !== 6) return null;
  return parseCidr(`${a}/64`)?.text ?? null;
}

/** Same network: the same /24 (IPv4) or /48 (IPv6). */
export function sameNetwork(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  const x = normalizeIp(a);
  const y = normalizeIp(b);
  const fx = isIP(x);
  if (fx === 0 || fx !== isIP(y)) return false;
  const bits = fx === 4 ? 24 : 48;
  return parseCidr(`${x}/${bits}`)?.text === parseCidr(`${y}/${bits}`)?.text;
}

/** A PostgreSQL array of inet / cidr as returned without a cast ('{a,b}'), or a text[] already parsed. */
export function pgTextArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v !== 'string') return [];
  const s = v.trim();
  if (s === '{}' || s === '') return [];
  return s.replace(/^\{|\}$/g, '').split(',').map((x) => x.replace(/^"|"$/g, '').trim()).filter(Boolean);
}

/** The text of an inet value without its /32 or /128 suffix. */
export function inetText(v: unknown): string | null {
  if (typeof v !== 'string' || !v) return null;
  return v.replace(/\/(32|128)$/, '');
}
