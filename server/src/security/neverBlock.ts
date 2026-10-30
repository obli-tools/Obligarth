import os from 'node:os';
import { isIP } from 'node:net';
import { compileTrustedProxies, isTrustedProxy, normalizeIp, type ResolvedClient } from '../utils/clientIp';
import { compileCidrs, parseCidr } from '../mcp/ipUtil';

// =============================================================================
// Guards of the MCP server's blocks (docs: specs mcp-server §3.6).
//   neverBlockReason   a local block is refused (the request only gets its
//                      401 / 403): a relay or an untrusted forwarder, loopback,
//                      a trusted proxy, an address of the instance itself or a
//                      Docker bridge subnet of the host, the settings'
//                      never_block list, and for a manual block the operator's
//                      own address. Other private addresses ARE blocked, so the
//                      strict mode keeps its meaning on a LAN or a VPN.
//   obliguardSkipReason the local block applies but Obliguard is not told (a
//                      network-wide ban): a non-public address, a /64 row, an
//                      address with a live web session or a trusted 2FA address.
// =============================================================================

const LOOPBACK = compileTrustedProxies('loopback');
const NON_PUBLIC = compileTrustedProxies(
  '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, '
  + '::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8',
);

/** The addresses of this process's interfaces, and the subnets of the Docker bridges of the host (docker*, br-*). */
function ownNetworks(): { addresses: Set<string>; bridges: (ip: string) => boolean } {
  const addresses = new Set<string>();
  const bridgeCidrs: string[] = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const a of list ?? []) {
      addresses.add(normalizeIp(a.address));
      if (/^(docker\d*|br-)/.test(name) && a.cidr) bridgeCidrs.push(a.cidr);
    }
  }
  return { addresses, bridges: compileCidrs(bridgeCidrs) };
}

let own: { at: number; value: ReturnType<typeof ownNetworks> } | null = null;
function ownNow(): ReturnType<typeof ownNetworks> {
  if (!own || Date.now() - own.at > 60_000) own = { at: Date.now(), value: ownNetworks() };
  return own.value;
}

/** Why the address must never be blocked locally, or null. */
export function neverBlockReason(client: Pick<ResolvedClient, 'ip' | 'relay' | 'untrustedForwarder'>, neverBlock: readonly string[],
  opts: { operatorIp?: string | null } = {}): string | null {
  if (client.relay || client.untrustedForwarder) return 'relay';
  const ip = normalizeIp(client.ip);
  if (!ip || isIP(ip) === 0) return 'invalid';
  if (LOOPBACK(ip)) return 'loopback';
  if (isTrustedProxy(ip)) return 'trusted_proxy';
  const o = ownNow();
  if (o.addresses.has(ip) || o.bridges(ip)) return 'instance';
  if (compileCidrs(neverBlock)(ip)) return 'never_block';
  if (opts.operatorIp && normalizeIp(opts.operatorIp) === ip) return 'operator';
  return null;
}

/** A non-public address (RFC 1918, CGNAT, loopback, link-local, ULA, multicast): never reported to Obliguard. */
export function isNonPublic(ip: string): boolean {
  const a = normalizeIp(ip);
  return isIP(a) === 0 || NON_PUBLIC(a);
}

/** True when the text is a /64 prefix (never reported: Obliguard receives plain addresses only). */
export function isPrefixRow(ip: string): boolean {
  const c = parseCidr(ip);
  return !!c && c.family === 6 && c.prefix === 64 && ip.includes('/');
}
