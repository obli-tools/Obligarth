// ── Secrets never sit in an approval ───────────────────────────────────────
//
// A two-step approval (pending_approvals) keeps its `payload` for up to 30
// minutes, returns it to every reviewer through GET /api/approvals and keeps
// it afterwards as history: a password, a token, an API key or a 2FA code
// must never be in it (P1 rule, extended).
//
//  - The routes decide, from what the SERVER knows to be secret, that an
//    action carries one (`carriesSecret` of restrictionService.enforce): the
//    secret fields a module declares for its device commands, the Obligate
//    API key / inbound secret, the own password change. Such an action asks
//    a fresh step-up (no trusted-IP shortcut) at the 'restricted' level
//    instead of a second administrator — the rule P1 applied to the admin
//    password reset. The name of a field the CALLER added never decides it:
//    a junk `token` key must not turn a two-person action into a one-person
//    one.
//  - approvalService.create strips any secret-named key that still reaches
//    it (and logs the key paths, never the values): a junk key is dropped,
//    the approval is filed as usual.
// Data only the executor needs and that is not a clear secret (a bcrypt hash
// of a new user's password, an avatar image) goes to `sealed_payload`
// instead: never returned, wiped when the request is resolved.
//
// Same rules as migration 129 (which cleaned the requests filed before).

const SECRET_KEY = /(password|passwd|passphrase|^pwd$|^pass$|secret|token|apikey|privatekey|credential|twofactorcode|^totp|^otp$|assertion)/;

/** Is this key name the name of a credential? Identifiers (`targetApiKeyId`,
 *  `keyId`, `tokenIds`…) are not. */
export function isSecretKey(key: string): boolean {
  // Dotted keys are map keys, not field names (restriction action keys such
  // as 'command.reboot'): never a credential.
  if (key.includes('.')) return false;
  const n = key.toLowerCase().replace(/[_\-\s]/g, '');
  if (/(id|ids)$/.test(n)) return false;
  return SECRET_KEY.test(n);
}

/** A value that actually carries something (booleans, null and '' do not:
 *  `privacyPasswordSet: true`, `apiKey: ''` "keep the current one"). */
export function hasValue(v: unknown): boolean {
  if (v === null || v === undefined || typeof v === 'boolean') return false;
  if (typeof v === 'string') return v.length > 0;
  if (typeof v === 'number') return true;
  if (Array.isArray(v)) return v.some(hasValue);
  if (typeof v === 'object') return Object.values(v as Record<string, unknown>).some(hasValue);
  return false;
}

/** Dotted paths of the secret-named keys that carry a value. */
export function findSecretPaths(value: unknown, path: string[] = [], out: string[] = [], depth = 0): string[] {
  if (depth > 12 || value === null || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    value.forEach((v, i) => findSecretPaths(v, [...path, String(i)], out, depth + 1));
    return out;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (isSecretKey(k) && hasValue(v)) out.push([...path, k].join('.'));
    else findSecretPaths(v, [...path, k], out, depth + 1);
  }
  return out;
}

/** Deep copy without the secret-named keys that carry a value. */
export function scrubSecrets<T>(value: T): { clean: T; removed: string[] } {
  const removed: string[] = [];
  const walk = (v: unknown, path: string[], depth: number): unknown => {
    if (depth > 12) return undefined;
    if (Array.isArray(v)) return v.map((x, i) => walk(x, [...path, String(i)], depth + 1));
    if (v && typeof v === 'object') {
      const o: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (isSecretKey(k) && hasValue(x)) { removed.push([...path, k].join('.')); continue; }
        o[k] = walk(x, [...path, k], depth + 1);
      }
      return o;
    }
    return v;
  };
  return { clean: walk(value, [], 0) as T, removed };
}

/** Command types whose payload carries a secret, and its fields: declared by
 *  the module that owns the command (registerSecretCommandFields; e.g. the
 *  agent reconfiguration key). Fixed by the server: never inferred from the
 *  caller's field names. */
const SECRET_COMMAND_FIELDS = new Map<string, readonly string[]>();

export function registerSecretCommandFields(type: string, fields: readonly string[]): void {
  if (SECRET_COMMAND_FIELDS.has(type)) throw new Error(`Secret fields of command '${type}' registered twice`);
  SECRET_COMMAND_FIELDS.set(type, Object.freeze([...fields]));
}

/** Does this command (type + payload) carry one of its secret fields? */
export function commandCarriesSecret(type: string, payload: unknown): boolean {
  const names = SECRET_COMMAND_FIELDS.get(type);
  if (!names || !payload || typeof payload !== 'object') return false;
  const p = payload as Record<string, unknown>;
  return names.some((n) => hasValue(p[n]));
}
