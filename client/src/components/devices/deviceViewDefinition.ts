import {
  DEVICE_CONTACT_FILTERS, DEVICE_LIST_SORT_KEYS,
  type DeviceListSortKey, type DeviceViewDefinition, type DeviceViewFilters, type EnrollmentState, type RuleNode,
} from '@obligarth/shared';
import { ruleKey } from '@/components/rules/ruleModel';
import { LINE2_FIELDS } from '@/utils/deviceLine2Fields';

// =============================================================================
// A saved view of the inventory (P0-5 §6) as the console's list holds it: the state of the toolbar (enrollment tab,
// chips, search, advanced filter), the group of the side panel, the sort and the optional columns, to and from the
// definition the server keeps (shared DeviceViewDefinition). A view saved elsewhere (the API) may hold what the
// toolbar cannot show (an enrollment state set that is no tab, supervised = false, a group without its subgroups):
// fromDefinition takes the closest state.
// =============================================================================

/** The enrollment states the tabs of the toolbar group together. */
export type StateTab = 'managed' | 'enrolling' | 'enrolled' | 'unenrolled' | 'all';
export const STATE_TABS: Record<StateTab, EnrollmentState[] | undefined> = {
  managed: ['enrolling', 'awaiting_configuration', 'enrolled', 'unenrolling'],
  enrolling: ['enrolling', 'awaiting_configuration'],
  enrolled: ['enrolled'],
  unenrolled: ['unenrolled'],
  all: undefined,
};
export const isStateTab = (v: unknown): v is StateTab => typeof v === 'string' && v in STATE_TABS;

/** The state of the list a view keeps. groupId -1: the devices of no group; null: every group. */
export interface InventoryViewState {
  search: string;
  stateTab: StateTab;
  contact: ReadonlySet<string>;
  compliance: ReadonlySet<string>;
  config: ReadonlySet<string>;
  platform: ReadonlySet<string>;
  ownership: ReadonlySet<string>;
  supervisedOnly: boolean;
  osBelow: string;
  tags: ReadonlySet<string>;
  endUserId: number | undefined;
  lostOnly: boolean;
  rule: RuleNode | null;
  groupId: number | null;
  sortBy: '' | DeviceListSortKey;
  sortOrder: 'asc' | 'desc';
  columns: ReadonlySet<string>;
}

const sorted = (s: ReadonlySet<string>): string[] => [...s].sort();

/** The definition of the current state of the list (empty filters left out). */
export function definitionOf(s: InventoryViewState): DeviceViewDefinition {
  const filters: DeviceViewFilters = {};
  const list = (k: keyof DeviceViewFilters & string, v: ReadonlySet<string>) => { if (v.size > 0) (filters as Record<string, unknown>)[k] = sorted(v); };
  const states = STATE_TABS[s.stateTab];
  if (states) filters.enrollmentState = [...states];
  list('platform', s.platform);
  list('ownership', s.ownership);
  list('contact', s.contact);
  list('compliance', s.compliance);
  list('config', s.config);
  list('tags', s.tags);
  if (s.supervisedOnly) filters.supervised = true;
  if (s.osBelow) filters.osBelow = s.osBelow;
  if (s.endUserId !== undefined) filters.endUserId = s.endUserId;
  if (s.lostOnly) filters.lostMode = true;
  if (s.search.trim()) filters.q = s.search.trim();
  const def: DeviceViewDefinition = { v: 1, filters };
  if (s.rule) def.rule = s.rule;
  if (s.groupId === -1) def.ungrouped = true;
  else if (s.groupId !== null) { def.groupId = s.groupId; def.includeSubgroups = true; }
  if (s.sortBy) def.sort = { by: s.sortBy, order: s.sortOrder };
  def.columns = LINE2_FIELDS.map((f) => f.key).filter((k) => s.columns.has(k));
  return def;
}

const sameSet = (a: readonly string[] | undefined, b: readonly string[]): boolean => {
  const x = new Set(a ?? []);
  return x.size === b.length && b.every((v) => x.has(v));
};

/** The tab of a set of enrollment states: the one listing exactly these states ('all' for none or another set). */
function tabOf(states: readonly string[] | undefined): StateTab {
  if (!states || states.length === 0) return 'all';
  for (const [tab, list] of Object.entries(STATE_TABS) as Array<[StateTab, EnrollmentState[] | undefined]>) {
    if (list && sameSet(states, list)) return tab;
  }
  return 'all';
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

/** The state of the list a definition gives (the columns: undefined when the view keeps none). */
export function fromDefinition(def: DeviceViewDefinition): Omit<InventoryViewState, 'columns'> & { columns: Set<string> | undefined } {
  const f = def.filters ?? {};
  const contacts = strings(f.contact).filter((c) => (DEVICE_CONTACT_FILTERS as readonly string[]).includes(c));
  const known = new Set(LINE2_FIELDS.map((x) => x.key));
  const sortBy = def.sort && (DEVICE_LIST_SORT_KEYS as readonly string[]).includes(def.sort.by) ? def.sort.by : '';
  return {
    search: typeof f.q === 'string' ? f.q : '',
    stateTab: tabOf(strings(f.enrollmentState)),
    contact: new Set(contacts),
    compliance: new Set(strings(f.compliance)),
    config: new Set(strings(f.config)),
    platform: new Set(strings(f.platform)),
    ownership: new Set(strings(f.ownership)),
    supervisedOnly: f.supervised === true,
    osBelow: typeof f.osBelow === 'string' ? f.osBelow : '',
    tags: new Set(strings(f.tags)),
    endUserId: typeof f.endUserId === 'number' ? f.endUserId : undefined,
    lostOnly: f.lostMode === true,
    rule: def.rule ?? null,
    groupId: def.ungrouped ? -1 : (typeof def.groupId === 'number' ? def.groupId : null),
    sortBy,
    sortOrder: sortBy && def.sort?.order === 'desc' ? 'desc' : 'asc',
    columns: def.columns ? new Set(def.columns.filter((k) => known.has(k))) : undefined,
  };
}

/** A comparable form of a definition: the lists as sets, the rule canonical, the columns in catalog order (a view
 *  without columns leaves the current ones). */
function comparable(def: DeviceViewDefinition, columnsFallback?: readonly string[]): string {
  const filters: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(def.filters ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
    if (v === undefined || (Array.isArray(v) && v.length === 0)) continue;
    filters[k] = Array.isArray(v) ? [...v].map(String).sort() : v;
  }
  const columns = def.columns ?? columnsFallback ?? [];
  return JSON.stringify({
    filters,
    rule: ruleKey(def.rule),
    group: def.ungrouped ? 'none' : def.groupId ?? null,
    sort: def.sort ? `${def.sort.by}:${def.sort.order}` : '',
    columns: LINE2_FIELDS.map((f) => f.key).filter((k) => columns.includes(k)),
  });
}

/** Does the state of the list differ from the view's definition? */
export function differsFrom(current: DeviceViewDefinition, view: DeviceViewDefinition): boolean {
  return comparable(current) !== comparable(view, current.columns);
}
