// =============================================================================
// Sites (lot P1-SITE, spec P1-QR-SITES §2): where a device is ("this phone is at the store Exemple-Nord"), and the source
// of the per-site values its file templates read. A site of a tenant: a code (unique in the tenant), a name, a city,
// a contact, the group its devices may be filed in, and its values (key → text). The templates of the bridge agent
// read them two ways: {{device.custom.<key>}} takes the custom field of the device first, else the value of its site
// (the policies written for the MobiControl import keep working); {{site.code}}, {{site.name}}, {{site.city}} and
// {{site.<key>}} name the site directly. Shared by the server (validation, import, MCP) and the console.
// =============================================================================

import type { LegacyAgentTokenCreated } from './legacyAgent';

/** Bounds of a site, of its import and of a bulk attachment. */
export const SITE_LIMITS = {
  codeMax: 32,
  nameMax: 200,
  cityMax: 100,
  contactMax: 200,
  valuesMax: 50,
  valueMax: 500,
  /** The values of a site as stored (their JSON, in UTF-8 bytes): the bound of the table (sites_values_check). */
  valuesBytes: 65536,
  /** An import (CSV text): 2 MiB and 5 000 data lines at most. */
  importBytes: 2 * 1024 * 1024,
  importRows: 5000,
  /** Devices attached in one call. */
  bulkDevices: 500,
  /** Sites per tenant. */
  perTenant: 10_000,
} as const;

/** The key of a value of a site (a variable {{site.<key>}}, the fallback of {{device.custom.<key>}}). */
export const SITE_VALUE_KEY_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
/** The fields of a site a value never takes the name of (site.code, site.name, site.city; the contact is not a
 *  variable but a column of the import). */
export const SITE_RESERVED_KEYS = ['code', 'name', 'city', 'contact'] as const;
/** The prefix of the variables of a site in the templates of the bridge agent. */
export const SITE_VARIABLE_PREFIX = 'site.';

/** Is this a variable of a site: site.code, site.name, site.city or site.<key of a value>? */
export function isSiteVariable(name: string): boolean {
  if (!name.startsWith(SITE_VARIABLE_PREFIX)) return false;
  const k = name.slice(SITE_VARIABLE_PREFIX.length);
  return k === 'code' || k === 'name' || k === 'city' || (SITE_VALUE_KEY_RE.test(k) && !(SITE_RESERVED_KEYS as readonly string[]).includes(k));
}

/** A text of a site: no control character (a newline or a tab neither). */
export const isSiteText = (s: string): boolean => !/[\u0000-\u001f\u007f]/.test(s);

// ── The state of a device of a site (the rules of the inventory of 01/11) ─────

/** Without a contact for this long, a device no longer answers. */
export const SITE_STALE_HOURS = 24;
/** Below this free storage, a device is to look after (0.5 GiB). */
export const SITE_LOW_STORAGE_BYTES = 512 * 1024 * 1024;

/** Why a device of a site is not ready, in the order the console says them. */
export const SITE_DEVICE_REASONS = ['no_contact', 'agent_too_old', 'admin_inactive', 'low_storage', 'file_not_created',
  'appconfig_unresolved'] as const;
export type SiteDeviceReason = typeof SITE_DEVICE_REASONS[number];
/** Prêt / À faire / Ne répond plus. */
export const SITE_DEVICE_STATES = ['ready', 'todo', 'stale'] as const;
export type SiteDeviceState = typeof SITE_DEVICE_STATES[number];

/** The facts of a device the state reads (the server reads them; the rules are here, pure). */
export interface SiteDeviceFacts {
  lastCheckinAt: string | Date | null;
  /** The bridge agent only: its version code, null for another channel. */
  agentVersionCode: number | null;
  /** The bridge agent only: the device administration (or owner) is active; null for another channel. */
  adminActive: boolean | null;
  storageAvailableBytes: number | null;
  /** Agent settings of the device left out for a variable without a value (the file of the apps not deposited), the
   *  managed configurations of apps (agent:appconfig:<id>) apart. */
  unresolvedSettings: number;
  /** Managed configurations of apps of the device left out for a variable without a value (the app not configured). */
  unresolvedAppConfigs?: number;
}

/** The reasons of a device, in their order (an empty list: ready). `minAgentVersionCode`: the version the agent must
 *  reach (the instance's minimum, at least the one of the agent policies). */
export function siteDeviceReasons(f: SiteDeviceFacts, now: Date, minAgentVersionCode: number): SiteDeviceReason[] {
  const out: SiteDeviceReason[] = [];
  const seen = f.lastCheckinAt ? new Date(f.lastCheckinAt).getTime() : NaN;
  if (!Number.isFinite(seen) || now.getTime() - seen > SITE_STALE_HOURS * 3_600_000) out.push('no_contact');
  if (f.agentVersionCode !== null && f.agentVersionCode < minAgentVersionCode) out.push('agent_too_old');
  if (f.adminActive === false) out.push('admin_inactive');
  if (f.storageAvailableBytes !== null && f.storageAvailableBytes < SITE_LOW_STORAGE_BYTES) out.push('low_storage');
  if (f.unresolvedSettings > 0) out.push('file_not_created');
  if ((f.unresolvedAppConfigs ?? 0) > 0) out.push('appconfig_unresolved');
  return out;
}

/** The state of the reasons: no contact wins (nothing else can be fixed from afar), any other is to do. */
export const siteDeviceState = (reasons: readonly SiteDeviceReason[]): SiteDeviceState =>
  (reasons.includes('no_contact') ? 'stale' : reasons.length ? 'todo' : 'ready');

// ── Views ────────────────────────────────────────────────────────────────────

export interface SiteCounts {
  devices: number;
  ready: number;
  todo: number;
  stale: number;
  /** Devices whose file of the apps is not created (a variable of a template without a value). */
  fileNotCreated: number;
}

/** A site (GET /api/sites, /api/sites/:id). */
export interface SiteView {
  id: string;
  code: string;
  name: string;
  city: string | null;
  contact: string | null;
  groupId: number | null;
  groupName: string | null;
  values: Record<string, string>;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
  /** The devices of the site the caller sees, by state. */
  counts: SiteCounts;
}

/** A device of a site and what to do about it. */
export interface SiteDeviceView {
  id: number;
  label: string;
  platform: string;
  channel: string;
  groupId: number | null;
  lastCheckinAt: string | null;
  agentVersionName: string | null;
  storageAvailableBytes: number | null;
  state: SiteDeviceState;
  reasons: SiteDeviceReason[];
  /** The variables without a value of its file templates (device.custom.codeMag, site.city…): file_not_created only. */
  missingVariables: string[];
  /** The variables without a value of its managed configurations of apps: appconfig_unresolved only. */
  missingAppConfigVariables: string[];
}

export interface SiteDetail extends SiteView {
  devices: SiteDeviceView[];
}

/** What a device record says of its site (DeviceSummary.site). */
export interface DeviceSiteRef {
  id: string;
  code: string;
  name: string;
}

/** A site written by the console or the MCP (POST /api/sites, PATCH /api/sites/:id). */
export interface SiteWriteBody {
  code?: string;
  name?: string;
  city?: string | null;
  contact?: string | null;
  groupId?: number | null;
  values?: Record<string, string>;
}

// ── Import (CSV) and creation from the custom fields ─────────────────────────

/** Why a line of an import or a site is refused. */
export const SITE_ISSUE_CODES = [
  'code_missing', 'code_invalid', 'name_missing', 'name_invalid', 'city_invalid', 'contact_invalid', 'value_key_invalid',
  'value_key_reserved', 'value_invalid', 'too_many_values', 'duplicate_code', 'columns_mismatch', 'site_archived', 'group_not_found',
  'too_many_sites', 'values_too_large',
] as const;
export type SiteIssueCode = typeof SITE_ISSUE_CODES[number];

/** One line of an import, as the plan sees it. */
export interface SiteImportLine {
  /** The line of the file (the header is line 1). */
  line: number;
  code: string;
  action: 'create' | 'update' | 'unchanged' | 'error';
  /** The fields the update changes (name, city, contact, values.<key>). */
  changes: string[];
  issues: SiteIssueCode[];
}

/** The answer of an import: the plan (dryRun), or what was applied. */
export interface SiteImportResult {
  dryRun: boolean;
  applied: boolean;
  /** The columns read: the code, the name, and those that went to the values. */
  columns: { code: string; name: string; city: string | null; contact: string | null; values: string[] };
  created: number;
  updated: number;
  unchanged: number;
  errors: number;
  lines: SiteImportLine[];
  /** A digest of the plan: the MCP authorization compares it at approval, the console sends it back to apply (the plan
   *  made again under the lock is refused, planChanged, when it differs from the one shown). */
  digest: string;
  /** The console's dry run: how many devices' agent policy the plan changes (beyond the publication thresholds, a
   *  second person approves it). */
  policyImpact?: number;
}

/** The answer of a creation of the sites from the custom fields of the devices. */
export interface SitesFromDevicesResult {
  dryRun: boolean;
  applied: boolean;
  keys: { code: string; name: string; values: string[] };
  sites: Array<{ code: string; name: string; action: 'create' | 'update' | 'unchanged'; devices: number; changes: string[] }>;
  /** Devices attached (or to attach) to a site. */
  attached: number;
  /** Devices already on the site of their code. */
  alreadyAttached: number;
  /** Devices without the code field: left as they are. */
  withoutField: Array<{ id: number; label: string }>;
  /** Codes whose devices name the site differently (the most frequent name is kept), and devices on another site. */
  conflicts: Array<{ code: string; names: string[] }>;
  /** Devices attached to another site already: left there. */
  onOtherSite: Array<{ id: number; label: string; siteCode: string }>;
  digest: string;
  /** The console's dry run: how many devices' agent policy the plan changes. */
  policyImpact?: number;
}

/** A console write of the sites held for a second person (action sites.apply: beyond the publication thresholds, or
 *  'restricted' by the matrix), answered 202. */
export interface SiteWritePending {
  approvalId: number;
  status: 'pending_approval';
  code?: 'approvalRequired';
  policyImpact?: number;
}

/** Is this answer of a console write a request held for a second person? */
export const isSiteWritePending = (v: unknown): v is SiteWritePending =>
  !!v && typeof v === 'object' && (v as { status?: unknown }).status === 'pending_approval';

// ── The enrollment sheet of a site (lot P1-QR §3.2) ──────────────────────────

/** The sheet of a site ("Enroll a phone"): a token of the site, in its group, valid 30 days for 5 phones (decision D2:
 *  the values the console fills in, which the technician may change). */
export const SITE_SHEET_DEFAULTS = { days: 30, maxUses: 5 } as const;

/** POST /api/sites/:id/enrollment-sheet: the token of the sheet, its QR code, and the sheets of the site it replaced
 *  (revoked). Shown once, as the token (Cache-Control no-store). */
export interface SiteEnrollmentSheet {
  site: { id: string; code: string; name: string; city: string | null };
  token: LegacyAgentTokenCreated;
  /** The sheets of the site still active that this one revoked. */
  revokedPrevious: number;
  /** The public link of the agent's APK (step 1 of the sheet) and its QR code (a PNG data URL); null when the public
   *  base of the instance is not configured. */
  apkUrl: string | null;
  apkQrPng: string | null;
}
