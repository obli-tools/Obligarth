// Inventory of an Android device minimised at the ingestion (sections 8.1, 8.2; AN19, REQ-01, criterion 6): the
// compiler already asks Google for the least (statusReportingSettings by ownership), and the ingester filters again
// (a device may apply its policy late, a field not asked for is dropped). A personal device (work profile on a
// personal device) never has a serial number, an IMEI, a network datum, a memory datum nor a personal app in base:
// Google reports the apps of the work profile only, and nothing else is kept. Pure: unit tests U-A10.

export interface AndroidPrivacyRules {
  /** Network information of a company device (operator by default; IMEI only when the tenant's rule allows it). */
  networkInfo: boolean;
  imei: boolean;
}

export const DEFAULT_PRIVACY: Readonly<Record<'corporate' | 'corporate_personal' | 'personal', AndroidPrivacyRules>> = {
  corporate: { networkInfo: true, imei: false },
  corporate_personal: { networkInfo: false, imei: false },
  personal: { networkInfo: false, imei: false },
};

export interface FilteredInventory {
  serialNumber: string | null;
  brand: string | null;
  model: string | null;
  osVersion: string | null;
  osBuild: string | null;
  apiLevel: number | null;
  securityPatchLevel: string | null;
  storageTotal: number | null;
  storageAvailable: number | null;
  hardwareInfo: Record<string, string> | null;
  softwareInfo: Record<string, string>;
  networkInfo: Record<string, string> | null;
  apps: AndroidAppRow[];
}

export interface AndroidAppRow {
  identifier: string;
  name: string | null;
  version: string | null;
  shortVersion: string | null;
  state: string | null;
}

const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim() !== '' ? v.trim().slice(0, max) : null);
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
const PACKAGE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;
const PATCH_LEVEL = /^\d{4}-\d{2}-\d{2}$/;
const MAX_APPS = 2_000;

/** The inventory of a Device for its ownership and the tenant's rules. */
export function filterInventory(device: Record<string, unknown>, ownership: string, rules?: AndroidPrivacyRules): FilteredInventory {
  const company = ownership === 'corporate' || ownership === 'corporate_personal';
  const r = rules ?? DEFAULT_PRIVACY[company ? (ownership as 'corporate' | 'corporate_personal') : 'personal'];
  const hw = obj(device.hardwareInfo);
  const sw = obj(device.softwareInfo);
  const net = obj(device.networkInfo);
  const patch = str(sw.securityPatchLevel, 10);
  const softwareInfo: Record<string, string> = {};
  for (const k of ['androidVersion', 'androidBuildNumber', 'securityPatchLevel', 'primaryLanguageCode', 'androidDevicePolicyVersionName']) {
    const v = str(sw[k], 120);
    if (v) softwareInfo[k] = v;
  }
  let hardwareInfo: Record<string, string> | null = null;
  if (company) {
    hardwareInfo = {};
    for (const k of ['brand', 'manufacturer', 'model', 'hardware']) {
      const v = str(hw[k], 120);
      if (v) hardwareInfo[k] = v;
    }
  }
  let networkInfo: Record<string, string> | null = null;
  if (company && r.networkInfo) {
    networkInfo = {};
    const op = str(net.networkOperatorName, 120);
    if (op) networkInfo.networkOperatorName = op;
    if (r.imei) {
      const imei = str(net.imei, 32);
      if (imei) networkInfo.imei = imei;
    }
    // Never the phone number (v1), the MEID, the ICCID nor the Wi-Fi MAC address.
  }
  let storageTotal: number | null = null;
  let storageAvailable: number | null = null;
  if (company) {
    const mem = obj(device.memoryInfo);
    const total = Number(mem.totalInternalStorage);
    if (Number.isFinite(total) && total >= 0) storageTotal = Math.trunc(total);
    const events = Array.isArray(device.memoryEvents) ? device.memoryEvents as unknown[] : [];
    const last = events.map(obj).filter((e) => e.eventType === 'EXTERNAL_STORAGE_DETECTED' ? false : Number.isFinite(Number(e.byteCount)))
      .sort((a, b) => Date.parse(String(b.createTime ?? '')) - Date.parse(String(a.createTime ?? '')))[0];
    if (last) storageAvailable = Math.trunc(Number(last.byteCount));
  }
  const apps: AndroidAppRow[] = [];
  const seen = new Set<string>();
  for (const a of (Array.isArray(device.applicationReports) ? device.applicationReports as unknown[] : []).slice(0, MAX_APPS)) {
    const o = obj(a);
    const pkg = str(o.packageName, 255);
    if (!pkg || !PACKAGE.test(pkg) || seen.has(pkg)) continue;
    seen.add(pkg);
    apps.push({
      identifier: pkg, name: str(o.displayName, 255), version: str(o.versionName, 64),
      shortVersion: o.versionCode !== undefined && Number.isFinite(Number(o.versionCode)) ? String(Math.trunc(Number(o.versionCode))).slice(0, 64) : null,
      state: str(o.state, 32),
    });
  }
  return {
    serialNumber: company ? str(hw.serialNumber, 64) : null,
    brand: str(hw.brand, 64),
    model: str(hw.model, 64),
    osVersion: str(sw.androidVersion, 200),
    osBuild: str(sw.androidBuildNumber, 32),
    apiLevel: Number.isInteger(device.apiLevel) ? Number(device.apiLevel) : null,
    securityPatchLevel: patch && PATCH_LEVEL.test(patch) ? patch : null,
    storageTotal,
    storageAvailable,
    hardwareInfo,
    softwareInfo,
    networkInfo,
    apps,
  };
}

/** The ownership of the instance for the ownership Google reports (null: unknown). */
export const ownershipOfMode = (mode: string): 'corporate' | 'corporate_personal' | 'personal' | null =>
  mode === 'work_profile_personal' ? 'personal' : mode === 'work_profile_corporate' ? 'corporate_personal'
    : mode === 'fully_managed' || mode === 'dedicated' ? 'corporate' : null;
