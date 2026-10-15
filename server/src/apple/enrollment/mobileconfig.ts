import { createHash, randomUUID } from 'node:crypto';
import type { EdgeEnrollmentConfig } from '../edge/wire';
import { PlistData, serializePlist, type PlistDict } from '../commands/plist';

// =============================================================================
// Composition of the enrollment profile (docs: integration-apple-edge §10.2):
// one profile per session (one single-use SCEP challenge per profile), from
// apple-edge's enrollment configuration (§6.4). Configuration → [SCEP, MDM];
// PayloadIdentifier tools.obli.obligarth.enroll.<key> stable per tenant (an
// enrollment again replaces the profile, the removal of management targets
// it); the SCEP subject never carries a personal value. Written by the plist
// serializer of §8.5 (1 MiB at most), then signed by apple-edge, which checks
// that every URL starts with MDM_PUBLIC_BASE/t/<key>/.
// =============================================================================

/** The largest profile apple-edge signs (signing.MaxProfile). */
export const MAX_PROFILE_BYTES = 1024 * 1024;

/** The file name and the media type of the answer to the device. */
export const PROFILE_CONTENT_TYPE = 'application/x-apple-aspen-config';
export const PROFILE_FILENAME = 'obligarth.mobileconfig';

export const enrollPayloadIdentifier = (key: string): string => `tools.obli.obligarth.enroll.${key}`;

export interface ComposeInput {
  key: string;
  config: EdgeEnrollmentConfig;
  challenge: string;
  sessionId: string;
  organization: string;
  displayName: string;
  description: string;
  scepName: string;
  mdmName: string;
  /** ConsentText: { default: English, fr: French, … }. */
  consent: Record<string, string>;
  /** Account-driven (BYOD): the Managed Apple Account of the invitation. */
  byod?: { managedAppleId: string };
  /** Tests: fixed payload UUIDs (profile, SCEP, MDM). */
  uuids?: { profile: string; scep: string; mdm: string };
}

export class ProfileCompositionError extends Error {
  readonly code: 'no_topic' | 'too_large' | 'invalid_ca';
  constructor(code: 'no_topic' | 'too_large' | 'invalid_ca', message: string) {
    super(message);
    this.code = code;
    this.name = 'ProfileCompositionError';
  }
}

/** SHA-1 of the DER of the first certificate of a PEM (CAFingerprint). */
export function caFingerprint(pem: string): Buffer {
  const m = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/.exec(String(pem));
  if (!m) throw new ProfileCompositionError('invalid_ca', 'the SCEP CA certificate is not a PEM certificate');
  const der = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
  if (der.length < 64) throw new ProfileCompositionError('invalid_ca', 'the SCEP CA certificate is too short');
  return createHash('sha1').update(der).digest();
}

const upper = (u: string): string => u.toUpperCase();

/** The profile as a plist dictionary (deterministic for given UUIDs). */
export function enrollmentProfileDict(i: ComposeInput): PlistDict {
  if (!i.config.topic) throw new ProfileCompositionError('no_topic', 'the tenant has no active push certificate');
  const ids = i.uuids ?? { profile: randomUUID(), scep: randomUUID(), mdm: randomUUID() };
  const root = enrollPayloadIdentifier(i.key);
  const scep: PlistDict = {
    PayloadType: 'com.apple.security.scep',
    PayloadVersion: 1,
    PayloadIdentifier: `${root}.scep`,
    PayloadUUID: upper(ids.scep),
    PayloadDisplayName: i.scepName,
    PayloadContent: {
      URL: i.config.scep_url,
      Name: 'obligarth',
      Challenge: i.challenge,
      Keysize: Math.trunc(Number(i.config.key_size) || 2048),
      'Key Type': 'RSA',
      'Key Usage': 5,
      Subject: [[['CN', `obligarth-${i.sessionId}`]]],
      CAFingerprint: new PlistData(caFingerprint(i.config.scep_ca_cert_pem)),
      Retries: 3,
      RetryDelay: 10,
      KeyIsExtractable: false,
      AllowAllAppsAccess: false,
    },
  };
  const mdm: PlistDict = {
    PayloadType: 'com.apple.mdm',
    PayloadVersion: 1,
    PayloadIdentifier: `${root}.mdm`,
    PayloadUUID: upper(ids.mdm),
    PayloadDisplayName: i.mdmName,
    ServerURL: i.config.server_url,
    CheckInURL: i.config.checkin_url,
    Topic: i.config.topic,
    IdentityCertificateUUID: upper(ids.scep),
    SignMessage: i.config.sign_message === true,
    CheckOutWhenRemoved: true,
    ...(i.byod
      ? { AssignedManagedAppleID: i.byod.managedAppleId, EnrollmentMode: 'BYOD' }
      : { AccessRights: 8191 }),
  };
  const consent: PlistDict = {};
  for (const [k, v] of Object.entries(i.consent)) if (v) consent[k] = v;
  return {
    PayloadType: 'Configuration',
    PayloadVersion: 1,
    PayloadIdentifier: root,
    PayloadUUID: upper(ids.profile),
    PayloadDisplayName: i.displayName,
    PayloadDescription: i.description,
    PayloadOrganization: i.organization,
    ...(Object.keys(consent).length ? { ConsentText: consent } : {}),
    PayloadContent: [scep, mdm],
  };
}

/** The unsigned profile (UTF-8 XML plist), 1 MiB at most. */
export function composeEnrollmentProfile(i: ComposeInput): Buffer {
  const bytes = Buffer.from(serializePlist(enrollmentProfileDict(i)), 'utf8');
  if (bytes.length > MAX_PROFILE_BYTES) throw new ProfileCompositionError('too_large', 'the enrollment profile exceeds 1 MiB');
  return bytes;
}
