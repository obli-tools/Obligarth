/**
 * Obligarth bench station — the one output filter (lot BANC §5.7).
 *
 * Applied to every text this station writes to a log, keeps in a card's raw output, or exports: an enrollment token
 * (`OLE1.<public>.<secret>`), any base64url run longer than 200 characters (a configuration, which carries the token)
 * and any e-mail address become `[masqué]`. Applied as well to stdout and stderr of `adb shell -T` calls that carry a
 * configuration on their standard input (§5.6).
 */
export const MASK = '[masqué]';

const TOKEN_RE = /OLE1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const LONG_B64URL_RE = /[A-Za-z0-9_-]{201,}={0,2}/g;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export function redact(text: string): string {
  if (!text) return text;
  return text.replace(TOKEN_RE, MASK).replace(LONG_B64URL_RE, MASK).replace(EMAIL_RE, MASK);
}

/** A serial number cut to its last four characters (history, export, steps). */
export function truncateSerial(serial: string | null | undefined): string | null {
  if (typeof serial !== 'string' || !serial) return null;
  return serial.length <= 4 ? `…${serial}` : `…${serial.slice(-4)}`;
}

/**
 * The raw output of a card made fit for an export (« Exporter le journal brut », §5.7): `redact()`, then every serial
 * named in `serials` cut to its last four characters, then account names of `dumpsys account` (`Account {name=…,`)
 * removed — their type stays.
 */
export function anonymise(text: string, serials: Array<string | null | undefined>): string {
  let out = redact(text);
  for (const s of serials) {
    if (typeof s !== 'string' || s.length < 5) continue;
    out = out.split(s).join(truncateSerial(s) as string);
  }
  out = out.replace(/(Account \{name=)[^,}]*/g, `$1${MASK}`);
  return out;
}
