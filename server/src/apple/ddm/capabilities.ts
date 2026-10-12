// =============================================================================
// Client capabilities of a device (docs: integration-apple-edge §9.2, §9.3,
// §9.6, EX-12): what it announced in the status item
// management.client-capabilities, in the engine's view. The device's report
//   { "supported-versions": […], "supported-payloads": { "declarations":
//     { "activations": […], "assets": […], "configurations": […],
//       "management": […] }, "status-items": […] }, "supported-features": {…} }
// becomes DdmClientCapabilities, bounded (device data never size anything):
// that view is what apple_devices.ddm_client_capabilities stores. A device is
// never served a declaration type it did not announce. Self-contained: the
// unit tests run under node --test.
// =============================================================================

export type DeclarationFamily = 'activation' | 'asset' | 'configuration' | 'management';
export const DECLARATION_FAMILIES: readonly DeclarationFamily[] = ['activation', 'asset', 'configuration', 'management'];

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

export interface DdmClientCapabilities {
  supportedVersions: string[];
  /** supported-payloads.declarations, by family. */
  declarationTypes: Record<DeclarationFamily, string[]>;
  /** supported-payloads.status-items. */
  statusItems: string[];
  supportedFeatures: Record<string, JsonValue>;
}

/** A declaration type or a status item name as Apple writes them. */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_NAMES = 1000;
const MAX_FEATURES_BYTES = 8 * 1024;

const REPORT_FAMILY: Record<DeclarationFamily, string> = {
  activation: 'activations', asset: 'assets', configuration: 'configurations', management: 'management',
};

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

function names(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out = new Set<string>();
  for (const s of v) {
    if (typeof s === 'string' && NAME_RE.test(s)) out.add(s);
    if (out.size >= MAX_NAMES) break;
  }
  return [...out].sort();
}

function features(v: unknown): Record<string, JsonValue> {
  if (!isObject(v)) return {};
  try {
    const text = JSON.stringify(v);
    return Buffer.byteLength(text, 'utf8') <= MAX_FEATURES_BYTES ? JSON.parse(text) as Record<string, JsonValue> : {};
  } catch {
    return {};
  }
}

/**
 * The capabilities a device reported (the value of management.client-capabilities), or what the engine stored
 * of them (the same function reads both forms); null when the value announces nothing readable.
 */
export function parseClientCapabilities(raw: unknown): DdmClientCapabilities | null {
  let v = raw;
  if (typeof v === 'string') {
    try { v = JSON.parse(v); } catch { return null; }
  }
  if (!isObject(v)) return null;
  const stored = isObject(v.declarationTypes);
  const payloads = isObject(v['supported-payloads']) ? v['supported-payloads'] as Record<string, unknown> : null;
  if (!stored && !payloads) return null;
  const families = stored ? v.declarationTypes as Record<string, unknown> : isObject(payloads?.declarations) ? payloads?.declarations as Record<string, unknown> : {};
  const declarationTypes = {} as Record<DeclarationFamily, string[]>;
  for (const f of DECLARATION_FAMILIES) declarationTypes[f] = names(families[stored ? f : REPORT_FAMILY[f]]);
  return {
    supportedVersions: names(stored ? v.supportedVersions : v['supported-versions']).slice(0, 50),
    declarationTypes,
    statusItems: names(stored ? v.statusItems : payloads?.['status-items']),
    supportedFeatures: features(stored ? v.supportedFeatures : v['supported-features']),
  };
}

/** Do two capability sets announce the same things? (Both views are sorted and deduplicated.) */
export function sameCapabilities(a: DdmClientCapabilities | null, b: DdmClientCapabilities | null): boolean {
  if (a === null || b === null) return a === b;
  return JSON.stringify([a.supportedVersions, DECLARATION_FAMILIES.map((f) => a.declarationTypes[f]), a.statusItems, sortedJson(a.supportedFeatures)])
    === JSON.stringify([b.supportedVersions, DECLARATION_FAMILIES.map((f) => b.declarationTypes[f]), b.statusItems, sortedJson(b.supportedFeatures)]);
}

function sortedJson(v: JsonValue): JsonValue {
  if (Array.isArray(v)) return v.map(sortedJson);
  if (v && typeof v === 'object') {
    const out: Record<string, JsonValue> = {};
    for (const k of Object.keys(v).sort()) out[k] = sortedJson(v[k]);
    return out;
  }
  return v;
}
