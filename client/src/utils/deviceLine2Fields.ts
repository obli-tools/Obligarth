// Catalog of the optional fields shown on the second line of an inventory row
// (modele-donnees-mdm §11.3). Users toggle them through the "Columns" popover;
// the selection is kept in localStorage, per browser.

export interface Line2FieldDef {
  /** Stable key, also the value stored in localStorage. */
  key: string;
  /** Translation key of the label (devices.columns.<key>), with its English fallback. */
  label: string;
  /** Shown for a user who never opened the popover. */
  defaultVisible: boolean;
}

export const LINE2_FIELDS: Line2FieldDef[] = [
  { key: 'tenant',     label: 'Tenant',           defaultVisible: false },
  { key: 'platform',   label: 'Platform and OS',  defaultVisible: true  },
  { key: 'model',      label: 'Model',            defaultVisible: true  },
  { key: 'ownership',  label: 'Ownership',        defaultVisible: true  },
  { key: 'group',      label: 'Group',            defaultVisible: true  },
  { key: 'endUser',    label: 'End user',         defaultVisible: true  },
  { key: 'contact',    label: 'Last contact',     defaultVisible: false },
  { key: 'compliance', label: 'Compliance',       defaultVisible: false },
  { key: 'serial',     label: 'Serial number',    defaultVisible: false },
  { key: 'tags',       label: 'Tags',             defaultVisible: false },
];

// A new key: the catalog of the agent era (IP, MAC, last user, geolocation, reboot) no longer applies.
const STORAGE_KEY = 'obligarth:deviceLine2Fields:mdm';

/** The saved visibility, limited to the keys of the catalog; the defaults when nothing was saved. */
export function loadVisibleFields(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultVisibleFields();
    const arr = JSON.parse(raw) as string[];
    if (!Array.isArray(arr)) return defaultVisibleFields();
    const known = new Set(LINE2_FIELDS.map((f) => f.key));
    return new Set(arr.filter((k) => known.has(k)));
  } catch {
    return defaultVisibleFields();
  }
}

export function saveVisibleFields(visible: Set<string>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...visible]));
  } catch {
    // localStorage unavailable: the choice lasts for the session only.
  }
}

export function defaultVisibleFields(): Set<string> {
  return new Set(LINE2_FIELDS.filter((f) => f.defaultVisible).map((f) => f.key));
}
