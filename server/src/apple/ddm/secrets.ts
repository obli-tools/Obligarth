// =============================================================================
// No secret in a declaration (docs: integration-apple-edge I8, §8.8 rule 1,
// §9.4): a declaration is served to every device that cites it and lives in
// clear in apple_declarations; credentials will go through assets (v1). The
// closed rules of the command scanner, applied to a JSON payload:
//   1. a non-empty string whose key is a known secret key, as a whole key or
//      as the end of any key (CalDAVPassword, XAuthPassword…); booleans and
//      numbers are never secrets (PasswordRequired, MinPINLength);
//   2. a string that holds a PEM private key, under any key.
// Returns where (keys only, never a value). Self-contained: the unit tests run
// under node --test.
// =============================================================================

/** The keys that hold a secret in Apple's payloads: the same closed list as the scanner of the commands and as
 *  apple-edge's (queue/sensitive.go). */
export const SECRET_KEY_RE = /(Password|Passphrase|Secret|SharedSecret|Challenge|PIN|PrivateKey|AuthPassword|IncomingPassword|OutgoingPassword|UnlockToken|BootstrapToken)$/;
const PEM_PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const MAX_DEPTH = 64;

/**
 * The path (keys and indexes, 200 characters at most) of the first secret found in a declaration payload, or
 * null. A value nested deeper than the scanner reads counts as a secret: what cannot be examined is not served.
 */
export function findSecret(value: unknown, path: string[] = [], depth = 0): string | null {
  const where = (): string => path.join('.').slice(0, 200) || '(root)';
  if (depth > MAX_DEPTH) return where();
  if (typeof value === 'string') {
    if (PEM_PRIVATE_KEY_RE.test(value)) return where();
    // The key of the value; for an element of an array (of arrays), the key of that array: a list under a secret
    // key is that key's value as well.
    let i = path.length - 1;
    while (i > 0 && /^[0-9]+$/.test(path[i])) i--;
    return value !== '' && SECRET_KEY_RE.test(path[i] ?? '') ? where() : null;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const hit = findSecret(value[i], [...path, String(i)], depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const hit = findSecret(v, [...path, k], depth + 1);
      if (hit) return hit;
    }
  }
  return null;
}
