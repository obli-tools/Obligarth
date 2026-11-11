// Pure helpers of the rate limiters (middleware/rateLimiter.ts), without any
// import: unit-tested on their own.

/** The client as utils/clientIp.ts resolves it (the fields a key needs). */
export interface ResolvedForKey {
  ip: string;
  relay: boolean;
}

/** Key of an anonymous limiter: the client's real address, or the shared
 *  bucket of the nginx-seen address (req.ip) when the address is a relay. */
export function limiterKeyOf(resolved: ResolvedForKey | null, reqIp: string | undefined): string {
  if (resolved && resolved.ip && !resolved.relay) return `ip:${resolved.ip}`;
  return `relay:${reqIp ?? 'unknown'}`;
}

/** The username a login request names, normalised (key of the per-account bucket). */
export function loginUsernameOf(body: unknown): string {
  const raw = (body as { username?: unknown } | null | undefined)?.username;
  return typeof raw === 'string' ? raw.trim().toLowerCase().slice(0, 255) : '';
}

/** The e-mail address a password-reset request names, normalised (key of the per-account bucket). */
export function resetRequestEmail(body: unknown): string {
  const raw = (body as { email?: unknown } | null | undefined)?.email;
  return typeof raw === 'string' ? raw.trim().toLowerCase().slice(0, 255) : '';
}
