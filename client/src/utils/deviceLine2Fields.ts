// Catalog of the optional fields shown on an inventory row (modele-donnees-mdm §11.3). Users toggle them through
// the "Columns" popover; the selection is kept in localStorage, per browser.

export interface Line2FieldDef {
  /** Stable key, also the value stored in localStorage. */
  key: string;
  /** Translation key of the label (devices.columns.<key>), with its English fallback. */
  label: string;
  /** Shown for a user who never opened the popover, and for a saved selection made before the field existed. */
  defaultVisible: boolean;
  /** Added after the first catalog: a selection saved in the legacy format (a bare array) never saw it. */
  addedLater?: boolean;
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
  { key: 'warranty',   label: 'Warranty',         defaultVisible: false },
  // On the first line, next to the last contact (Apple inventory, bridge agent; never an AMAPI device).
  { key: 'battery',    label: 'Battery',          defaultVisible: true, addedLater: true },
];

// A new key: the catalog of the agent era (IP, MAC, last user, geolocation, reboot) no longer applies.
const STORAGE_KEY = 'obligarth:deviceLine2Fields:mdm';

interface SavedFields { visible: string[]; known: string[] }

/**
 * The saved visibility, limited to the keys of the catalog; the defaults when nothing was saved. A field the saved
 * selection never knew (added to the catalog since) takes its default, so that a new field shows up for the users
 * who already picked their columns.
 */
export function loadVisibleFields(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultVisibleFields();
    const parsed = JSON.parse(raw) as unknown;
    let saved: SavedFields;
    if (Array.isArray(parsed)) {
      // Legacy format: the visible keys only, saved against the first catalog.
      saved = { visible: parsed.map(String), known: LINE2_FIELDS.filter((f) => !f.addedLater).map((f) => f.key) };
    } else if (parsed && typeof parsed === 'object' && Array.isArray((parsed as SavedFields).visible) && Array.isArray((parsed as SavedFields).known)) {
      saved = parsed as SavedFields;
    } else {
      return defaultVisibleFields();
    }
    const visible = new Set(saved.visible);
    const known = new Set(saved.known);
    return new Set(LINE2_FIELDS.filter((f) => (known.has(f.key) ? visible.has(f.key) : f.defaultVisible)).map((f) => f.key));
  } catch {
    return defaultVisibleFields();
  }
}

export function saveVisibleFields(visible: Set<string>): void {
  try {
    const saved: SavedFields = { visible: [...visible], known: LINE2_FIELDS.map((f) => f.key) };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
  } catch {
    // localStorage unavailable: the choice lasts for the session only.
  }
}

export function defaultVisibleFields(): Set<string> {
  return new Set(LINE2_FIELDS.filter((f) => f.defaultVisible).map((f) => f.key));
}
