import type { Knex } from 'knex';
import {
  DEVICE_USAGES, appleModeOfNanoType, ownershipAllows,
  type DeviceUsage, type EnrollmentMethod, type ManagementMode, type Ownership, type Platform,
} from '@obligarth/shared';
import type { AuthenticateFacts } from '../../apple/devices/lifecycle';
import type { PrivacyRules } from '../../apple/devices/privacy';

// =============================================================================
// Rules the data model imposes on an Authenticate (docs: modele-donnees-mdm
// §4.2, §4.3, §4.4, §4.5, §10.3; DM6, DM25, DM26; S10): the enrollment session
// (the ownership is never guessed), barrier 2 (the observed mode must be
// allowed for the session's ownership and method), the existing record (by
// enrollment id, else by serial number when it may be kept). Called by
// onAuthenticate (apple/devices/lifecycle.ts) in the transaction and the
// tenant context of the outbox consumer: no network.
// The serial number of the Authenticate message is device data: apple-edge
// verifies it only for an ADE enrollment (the SCEP challenge bound to the
// session's MachineInfo, signed by Apple). An unverified serial number finds
// a record that left management only (§4.4: unenrolled → enrolling); a
// record still under management is never taken by it.
// =============================================================================

export interface SessionFacts {
  sessionId: string;
  profileId: string;
  method: EnrollmentMethod;
  ownership: Ownership;
  /** Default group of the session's enrollment profile (a group of the tenant). */
  groupId: number | null;
  endUserId: number | null;
  /** Declared use of the devices of the profile (settings.deviceUsage), 'standard' by default. */
  usage: DeviceUsage;
  /** A re-enrolled device takes the profile's group again (settings.resetGroupOnReenroll). */
  resetGroupOnReenroll: boolean;
  /** ADE: the serial number of the session's MachineInfo (signed by Apple, checked by the ADE route). */
  serialNumber: string | null;
  /** ADE: the verified MachineInfo the session's SCEP challenge is bound to (apple-edge checks the UDID and
   *  the serial number of the Authenticate against it). */
  machineInfoId: string | null;
  state: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[0-9a-f]{64}$/;
const METHODS = new Set(['ade', 'ota', 'byod_account', 'configurator', 'account_device', 'migration']);
const OWNERSHIPS = new Set(['corporate', 'corporate_personal', 'personal']);

function sessionFactsOf(r: Record<string, any>): SessionFacts | null {
  if (!METHODS.has(r.method) || !OWNERSHIPS.has(r.ownership)) return null;
  const settings = r.settings && typeof r.settings === 'object' ? r.settings as Record<string, unknown> : {};
  const usage = (DEVICE_USAGES as readonly string[]).includes(String(settings.deviceUsage))
    ? settings.deviceUsage as DeviceUsage : 'standard';
  return {
    sessionId: r.id,
    profileId: r.profile_id,
    method: r.method,
    ownership: r.ownership,
    groupId: r.default_group_id === null || r.default_group_id === undefined ? null : Number(r.default_group_id),
    endUserId: r.end_user_id === null || r.end_user_id === undefined ? null : Number(r.end_user_id),
    usage,
    resetGroupOnReenroll: settings.resetGroupOnReenroll === true,
    serialNumber: typeof r.serial_number === 'string' && r.serial_number ? r.serial_number : null,
    machineInfoId: typeof r.machine_info_id === 'string' && r.machine_info_id ? r.machine_info_id : null,
    state: r.state,
  };
}

/**
 * The enrollment session of an Authenticate: by identity.session_ref, then by the SCEP challenge, then by
 * the fingerprint of the certificate (posed by scep.certificate_issued). Sessions of `tenantId` only; a
 * session marked failed (identity mismatch) never vouches for a device. null: no session (DM25: no record,
 * an alert, the enrollment stays at apple-edge until an operator decides).
 */
export async function findSessionForAuthenticate(trx: Knex.Transaction, tenantId: number,
  f: AuthenticateFacts): Promise<SessionFacts | null> {
  const lookups: Array<[string, string]> = [];
  if (f.sessionRef && UUID_RE.test(f.sessionRef)) lookups.push(['s.id', f.sessionRef.toLowerCase()]);
  if (f.challengeId && UUID_RE.test(f.challengeId)) lookups.push(['s.challenge_id', f.challengeId.toLowerCase()]);
  if (f.certSha256 && SHA256_RE.test(f.certSha256)) lookups.push(['s.cert_sha256', f.certSha256]);
  for (const [column, value] of lookups) {
    const row = await trx('enrollment_sessions as s')
      .join('enrollment_profiles as p', function joinProfile() {
        this.on('p.id', '=', 's.profile_id').andOn('p.tenant_id', '=', 's.tenant_id');
      })
      .where('s.tenant_id', tenantId)
      .where(column, value)
      .whereNot('s.state', 'failed')
      .orderBy('s.created_at', 'desc')
      .first('s.id', 's.profile_id', 's.method', 's.ownership', 's.end_user_id', 's.serial_number', 's.machine_info_id',
        's.state', 'p.default_group_id', 'p.settings') as Record<string, any> | undefined;
    if (row) return sessionFactsOf(row);
  }
  return null;
}

/**
 * Barrier 2 (§4.3): the management mode the NanoMDM type shows ('Device' → device, 'User Enrollment
 * (Device)' → user_enrollment), when the session's ownership and method allow it; null otherwise (no record,
 * alert enrollment.ownership_mismatch, audit, mdm.enrollment-release).
 */
export function managementModeFor(f: AuthenticateFacts, s: SessionFacts): ManagementMode | null {
  const mode = appleModeOfNanoType(f.enrollmentType);
  if (!mode) return null;
  return ownershipAllows(s.ownership, s.method, mode) ? mode : null;
}

/** A serial number in its stored form (upper case), when the value looks like one. */
export function normalizeSerial(v: unknown): string | null {
  return typeof v === 'string' && /^[A-Za-z0-9]{4,64}$/.test(v) ? v.toUpperCase() : null;
}

/** A serial number of the Authenticate message, when it looks like one (device data: verified by nothing). */
export function serialOf(f: AuthenticateFacts): string | null {
  return normalizeSerial(f.message?.SerialNumber);
}

/** The serial number an Authenticate presents (§4.5, S10). */
export interface SerialClaim {
  /** The serial number presented: the message's or the session's MachineInfo's (equal when both exist, unless
   *  contradicted); null: none. */
  serial: string | null;
  /** Verified: the serial number of the session's MachineInfo (signed by Apple), with apple-edge's ADE proof
   *  for this Authenticate (its SCEP challenge bound to that MachineInfo: apple-edge refuses an Authenticate
   *  whose UDID or serial number differs). Anything else is device data, which authorises nothing. */
  verified: boolean;
  /** The message announces another serial number than the session's MachineInfo: no record (apple-edge
   *  refuses such an Authenticate before it reaches the brain). */
  contradicted: boolean;
}

/**
 * The serial number of an Authenticate and its trust: verified only for an ADE session bound to its
 * MachineInfo whose Authenticate carries apple-edge's ADE proof; the message's SerialNumber is never verified
 * by itself (an OTA enrollment, a software MDM client, announces whatever it wants).
 */
export function serialClaimOf(f: AuthenticateFacts, s: SessionFacts): SerialClaim {
  const announced = serialOf(f);
  const machineInfo = s.method === 'ade' && s.machineInfoId ? normalizeSerial(s.serialNumber) : null;
  if (machineInfo && announced && announced !== machineInfo) return { serial: null, verified: false, contradicted: true };
  if (machineInfo && f.proof === 'ade') return { serial: machineInfo, verified: true, contradicted: false };
  return { serial: announced ?? machineInfo, verified: false, contradicted: false };
}

/** The record found for an Authenticate. */
export interface DeviceMatch {
  deviceId: number;
  enrollmentId: string | null;
  /** By its satellite; by the verified serial number (ADE, whatever its state: a device erased and enrolled
   *  again under a new enrollment); by the serial number of a record that left management (§4.4). */
  by: 'enrollment_id' | 'verified_serial' | 'serial';
}

/** The serial number of an Authenticate held by another record still under management: never taken. */
export interface SerialHeld {
  serialHeldBy: number;
}

/**
 * The existing record of the device: by enrollment id (the satellite), else by (tenant, apple_mdm, serial
 * number) when the rules of the session's ownership keep the serial number (never for a personal device):
 *   - a verified serial number (serialClaimOf) finds its record whatever its state;
 *   - an unverified one finds a record out of management only (unenrolled → enrolling, §4.4); held by a
 *     record still under management, it answers { serialHeldBy }: the Authenticate never takes that record
 *     (review of lot B2, MDM-B2-R1; DM6, S10).
 * The record found by its serial number is locked (FOR UPDATE): its state is read after any concurrent cycle.
 */
export async function findDeviceForAuthenticate(trx: Knex.Transaction, tenantId: number, f: AuthenticateFacts,
  rules: PrivacyRules, session: SessionFacts): Promise<DeviceMatch | SerialHeld | null> {
  const sat = await trx('apple_devices').where({ tenant_id: tenantId, enrollment_id: f.enrollmentId })
    .first('device_id', 'enrollment_id') as { device_id: number; enrollment_id: string } | undefined;
  if (sat) return { deviceId: Number(sat.device_id), enrollmentId: sat.enrollment_id, by: 'enrollment_id' };
  if (session.ownership === 'personal' || !rules.storeSerialNumber) return null;
  const claim = serialClaimOf(f, session);
  if (!claim.serial || claim.contradicted) return null;
  const row = await trx('devices as d')
    .leftJoin('apple_devices as a', function joinSat() {
      this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id');
    })
    .where({ 'd.tenant_id': tenantId, 'd.management_channel': 'apple_mdm', 'd.serial_number': claim.serial })
    // The record's row only (PostgreSQL refuses a lock on the nullable side of an outer join).
    .forUpdate('d')
    .first('d.id', 'd.enrollment_state', 'a.enrollment_id') as
    { id: number; enrollment_state: string; enrollment_id: string | null } | undefined;
  if (!row) return null;
  if (claim.verified) return { deviceId: Number(row.id), enrollmentId: row.enrollment_id ?? null, by: 'verified_serial' };
  if (row.enrollment_state === 'unenrolled') return { deviceId: Number(row.id), enrollmentId: row.enrollment_id ?? null, by: 'serial' };
  return { serialHeldBy: Number(row.id) };
}

/** Another Apple record of the tenant that holds `serial` (devices_serial_uq), or null. */
export async function serialHolderOf(trx: Knex.Transaction, tenantId: number, serial: string,
  exceptDeviceId: number | null): Promise<number | null> {
  const q = trx('devices').where({ tenant_id: tenantId, management_channel: 'apple_mdm', serial_number: serial });
  if (exceptDeviceId !== null) q.whereNot('id', exceptDeviceId);
  const row = await q.first('id') as { id: number } | undefined;
  return row ? Number(row.id) : null;
}

/** The platform of a ProductName (§4.2): iPhone, iPod → ios; iPad → ipados; AppleTV → tvos; Mac… → macos;
 *  RealityDevice → visionos; null when unknown (ios provisionally, corrected by DeviceInformation). */
export function platformFromProductName(productName: unknown): Platform | null {
  if (typeof productName !== 'string') return null;
  if (/^(iPhone|iPod)/.test(productName)) return 'ios';
  if (/^iPad/.test(productName)) return 'ipados';
  if (/^AppleTV/.test(productName)) return 'tvos';
  if (/^(Mac|MacBook|iMac|Macmini|MacPro)/.test(productName)) return 'macos';
  if (/^RealityDevice/.test(productName)) return 'visionos';
  return null;
}
