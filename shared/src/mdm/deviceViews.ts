// =============================================================================
// Saved views of the device list (P0-5 §4.1, §5, D6): a view keeps the filters, the advanced filter (a rule of the
// rule language, rules.ts), the group, the sort and the columns of GET /api/mdm/devices. Private to its owner by
// default, or shared with every member of its tenant; one default view per user. GET /api/mdm/devices and its export
// take ?viewId=<id|uuid>: the server merges the view's definition, and the explicit parameters of the request win.
// =============================================================================

import type { ContactState } from './states';
import type { RuleNode } from './rules';

/** The sort keys of GET /api/mdm/devices (sortBy), the server's whitelist. */
export const DEVICE_LIST_SORT_KEYS = ['name', 'platform', 'os', 'lastCheckin', 'enrolledAt', 'group', 'state', 'compliance',
  'ownership', 'model', 'warranty'] as const;
export type DeviceListSortKey = typeof DEVICE_LIST_SORT_KEYS[number];

/** The values of the contact filter of the list. */
export const DEVICE_CONTACT_FILTERS = ['never', 'recent', 'quiet', 'stale'] as const satisfies readonly ContactState[];

export const DEVICE_VIEW_LIMITS = {
  /** Private views of a user in a tenant (D6). */
  privatePerUser: 50,
  /** Shared views of a tenant (D6). */
  sharedPerTenant: 100,
  nameMax: 100,
  descriptionMax: 500,
  /** Bytes of the definition as PostgreSQL stores it (jsonb text). */
  definitionMaxBytes: 16_384,
  /** Columns kept by a view. */
  columnsMax: 30,
  /** Characters of the JSON of ?rule= on the list and the export. */
  ruleParamMaxChars: 4_096,
  /** Characters of that JSON once encoded in the address (encodeURIComponent: 6 for an accented letter, 9 for a CJK
   *  character): the request line stays under the 8 KiB of the proxies, with the other parameters of the list. */
  ruleParamMaxEncodedChars: 6_000,
} as const;

/** Can the JSON of a rule go as ?rule= (both bounds of DEVICE_VIEW_LIMITS)? The console refuses a longer one: in the
 *  builder, and in a saved view (created through the API) whose rule goes beyond. */
export function ruleParamFits(json: string): boolean {
  return json.length <= DEVICE_VIEW_LIMITS.ruleParamMaxChars
    && encodeURIComponent(json).length <= DEVICE_VIEW_LIMITS.ruleParamMaxEncodedChars;
}

/** The filters of the list a view keeps (the query parameters of GET /api/mdm/devices, but the group, the rule and the
 *  global view's tenants): the keys of the server's filter registry, the later lots' included. */
export interface DeviceViewFilters {
  platform?: string[];
  ownership?: string[];
  enrollmentState?: string[];
  contact?: ContactState[];
  compliance?: string[];
  config?: string[];
  /** Devices whose OS version is below this one. */
  osBelow?: string;
  supervised?: boolean;
  tags?: string[];
  endUserId?: number;
  lostMode?: boolean;
  /** Free text. */
  q?: string;
  /** A filter of a later lot (registered on the server's registry). */
  [key: string]: unknown;
}

export interface DeviceViewDefinition {
  v: 1;
  filters: DeviceViewFilters;
  /** The advanced filter: every field of the catalog is permitted in a view (D2). */
  rule?: RuleNode;
  /** A static group, with its subgroups or not; or the devices of no group. */
  groupId?: number;
  includeSubgroups?: boolean;
  ungrouped?: boolean;
  sort?: { by: DeviceListSortKey; order: 'asc' | 'desc' };
  /** The optional columns shown (keys of the console's catalog). */
  columns?: string[];
}

export interface DeviceView {
  id: number;
  uuid: string;
  name: string;
  description: string | null;
  shared: boolean;
  /** name: null when the owner is no longer a member the caller can read. */
  owner: { id: number; name: string | null };
  /** The caller owns it. */
  mine: boolean;
  /** The caller may rename, change, share, unshare or delete it: its owner, or a tenant administrator for a shared view. */
  editable: boolean;
  /** The caller's default view. */
  isDefault: boolean;
  definition: DeviceViewDefinition;
  createdAt: string;
  updatedAt: string;
}

/** POST /api/mdm/device-views. */
export interface DeviceViewCreate {
  name: string;
  description?: string | null;
  shared?: boolean;
  definition: DeviceViewDefinition;
}

/** PATCH /api/mdm/device-views/:id (the fields to change). */
export type DeviceViewPatch = Partial<DeviceViewCreate>;
