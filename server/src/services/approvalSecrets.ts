import { db } from '../db';

// ── Secrets never sit in an approval ───────────────────────────────────────
//
// A two-step approval (pending_approvals) keeps its `payload` for up to 30
// minutes, returns it to every reviewer through GET /api/approvals and keeps
// it afterwards as history: a password, a token, an API key, a secret script
// parameter or a 2FA code must never be in it (P1 rule, extended).
//
//  - The routes decide, from what the SERVER knows to be secret, that an
//    action carries one (`carriesSecret` of restrictionService.enforce): the
//    password fields of the privacy-password commands, the Obligate API key /
//    inbound secret, the own password change, the parameters a script
//    DECLARES secret. Such an action asks a fresh step-up (no trusted-IP
//    shortcut) at the 'restricted' level instead of a second administrator —
//    the rule P1 applied to the admin password reset. The name of a field
//    the CALLER added never decides it: a junk `token` key must not turn a
//    two-person action into a one-person one.
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
  // as 'command.set_privacy_password'): never a credential.
  if (key.includes('.')) return false;
  const n = key.toLowerCase().replace(/[_\-\s]/g, '');
  if (/(id|ids)$/.test(n)) return false;
  return SECRET_KEY.test(n);
}

/** A value that actually carries something (booleans, null and '' do not:
 *  `privacyPasswordSet: true`, `apiKey: ''` "keep the current one"). */
function hasValue(v: unknown): boolean {
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

/** Command types whose payload carries a secret, and its fields (the
 *  privacy-password commands of privacyGate.routes, the agent reconfiguration
 *  key). Fixed by the server: never inferred from the caller's field names. */
export const SECRET_COMMAND_FIELDS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  set_privacy_password: ['password'],
  change_privacy_password: ['oldPassword', 'newPassword'],
  remove_privacy_password: ['password'],
  verify_privacy_password: ['password'],
  reconfigure_agent: ['apiKey'],
});

/** Does this command (type + payload) carry one of its secret fields? */
export function commandCarriesSecret(type: string, payload: unknown): boolean {
  const names = SECRET_COMMAND_FIELDS[type];
  if (!names || !payload || typeof payload !== 'object') return false;
  const p = payload as Record<string, unknown>;
  return names.some((n) => hasValue(p[n]));
}

/**
 * A manual script run's parameter values, as an approval may keep them:
 *  - `declared`: only the parameters the SCRIPT declares (a value the caller
 *    adds under another name never reaches the request);
 *  - `secretNames`: the declared parameters that carry a value and are
 *    secret — type 'secret', or a credential name chosen by the script's
 *    author (e.g. `ApiToken` typed 'string'). A run with any of them cannot
 *    wait for an approval: the value would sit in it.
 */
export async function scriptParamsForApproval(scriptId: number, parameterValues: unknown): Promise<{ declared: Record<string, unknown>; secretNames: string[] }> {
  const declared: Record<string, unknown> = {};
  const secretNames: string[] = [];
  if (!parameterValues || typeof parameterValues !== 'object' || Array.isArray(parameterValues)) return { declared, secretNames };
  const params = await db('script_parameters').where({ script_id: scriptId }).select('name', 'type') as Array<{ name: string; type: string }>;
  const values = parameterValues as Record<string, unknown>;
  for (const p of params) {
    if (!Object.prototype.hasOwnProperty.call(values, p.name)) continue;
    const v = values[p.name];
    if ((p.type === 'secret' || isSecretKey(p.name)) && hasValue(v)) { secretNames.push(p.name); continue; }
    declared[p.name] = v;
  }
  return { declared, secretNames };
}
