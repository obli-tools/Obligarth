// What a session without a second factor may still reach while "force 2FA" is
// on (middleware/force2fa.ts). No import: unit-tested on its own.

/** The request (paths under /api) is open to an account that has no second factor yet. */
export function exemptFromForce2fa(method: string, path: string): boolean {
  const p = path.replace(/\/+$/, '') || '/';
  // Sign-in state, sign-out, enrollment, SSO configuration: /api/auth/*.
  if (p === '/auth' || p.startsWith('/auth/')) return true;
  // The profile (read, language, theme, password) and the second factors themselves.
  if (p === '/profile' || p.startsWith('/profile/')) return true;
  // The profile page reads whether 2FA is allowed (GET only; the route guards itself).
  if (method === 'GET' && p === '/admin/config') return true;
  // The public endpoints (no session needed): app updates, script repository,
  // bridge agent download, bench stations, Android signup return.
  if (p.startsWith('/mobile/') || p.startsWith('/repo/') || p === '/legacy-agent/public' || p.startsWith('/legacy-agent/public/')
    || p === '/bench' || p.startsWith('/bench/') || p === '/android/signup' || p.startsWith('/android/signup/')) return true;
  return false;
}
