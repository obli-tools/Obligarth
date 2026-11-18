// =============================================================================
// Masks of the device identifiers (serial, IMEI, UDID, phone number, ICCID, EID, MAC addresses, Android id, Knox,
// location). Shared by the MCP server (mcp/tools/devices.ts: applied when the key lacks devices.identifiers, decision
// D10) and the Obliwatch read API (integrations/obliwatch/devices.ts: ALWAYS applied, whatever the scope, brief §3
// « Identifiants internes seulement »).
// =============================================================================

/** Status items of the bridge agent that carry a hardware or network identifier. */
export const IDENTIFIER_ITEM = /imei|meid|serial|android_?id|iccid|imsi|phone|msisdn|mac|knox/i;

/** A registry summary or record without its identifiers (serial, IMEI, UDID, phone number, ICCID, EID, MAC addresses). */
export function maskRegistryDevice<T extends object>(d: T): T {
  const out = { ...(d as Record<string, any>) };
  if ('serialNumber' in out) out.serialNumber = null;
  if (out.apple && typeof out.apple === 'object') {
    const apple = { ...out.apple };
    if ('imei' in apple) apple.imei = null;
    if ('udid' in apple) apple.udid = null;
    if (apple.info && typeof apple.info === 'object') {
      const info = { ...apple.info };
      for (const k of ['phoneNumber', 'iccid', 'eid', 'wifiMac', 'bluetoothMac']) if (k in info) info[k] = null;
      apple.info = info;
    }
    out.apple = apple;
  }
  out.identifiersMasked = true;
  return out as T;
}

/** A bridge agent's list row or record without its identifiers (serials, IMEIs, Android id, Knox, identifying status). */
export function maskLegacyDevice<T extends object>(d: T): T {
  const out = { ...(d as Record<string, any>) };
  if ('serialNumber' in out) out.serialNumber = null;
  for (const k of ['androidId', 'claimedSerial', 'samsungSerial', 'hints', 'knoxInfo']) if (k in out) out[k] = null;
  if ('imeis' in out) out.imeis = [];
  if (Array.isArray(out.status)) out.status = out.status.filter((s: { item?: unknown }) => !IDENTIFIER_ITEM.test(String(s.item ?? '')));
  out.identifiersMasked = true;
  return out as T;
}

/** The keys that name an identifier or a location, at any depth (the always-on mask of an outbound view). */
const IDENTIFIER_KEY = /^(serial(number)?|claimedserial|samsungserial|imeis?|meid|udid|androidid|iccid|eid|imsi|msisdn|phone(number)?|(wifi|bluetooth|ethernet)?mac(address)?|knoxinfo|hints|latitude|longitude|altitude|geo.*|ip(local|public)?|lastloggedinuser|hardwareinfo|networkinfo)$/i;

/**
 * A copy of `value` where every key that names an identifier or a location (IDENTIFIER_KEY, any depth) is dropped.
 * The last line of an outbound view built from a whitelist: a field added later by mistake never leaves.
 */
export function dropIdentifierKeys<T>(value: T): T {
  if (Array.isArray(value)) return value.map((v) => dropIdentifierKeys(v)) as unknown as T;
  if (!value || typeof value !== 'object' || value instanceof Date) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (IDENTIFIER_KEY.test(k.replace(/[_-]/g, ''))) continue;
    out[k] = dropIdentifierKeys(v);
  }
  return out as T;
}
