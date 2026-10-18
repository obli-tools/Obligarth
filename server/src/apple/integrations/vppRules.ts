import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { VPP_LIMITS } from '@obligarth/shared';

// =============================================================================
// Pure rules of Apps and Books (docs: integration-apple-edge §11.3; lot C4):
// the .vpptoken file, the bearer of a notification, the platforms of an asset,
// whose mdmInfo a location holds. No database, no network: the unit tests
// load this module as it is (vpp.test.ts, U-17).
// =============================================================================

export type VppTokenFileErrorCode = 'vppTokenFileInvalid' | 'vppTokenExpired' | 'fileTooLarge';

export class VppTokenFileError extends Error {
  readonly code: VppTokenFileErrorCode;
  constructor(code: VppTokenFileErrorCode, message: string) {
    super(message);
    this.name = 'VppTokenFileError';
    this.code = code;
  }
}

export interface VppTokenFile { sToken: string; expDate: Date; orgName: string | null }

/** Decodes a .vpptoken file (base64 of {token, expDate, orgName}); the sToken presented to Apple is the file's content. */
export function decodeTokenFile(bytes: Buffer, now = new Date()): VppTokenFile {
  if (bytes.length > VPP_LIMITS.tokenFileBytes) throw new VppTokenFileError('fileTooLarge', 'The file is too large');
  const sToken = bytes.toString('utf8').replace(/^﻿/, '').trim();
  const bad = (): never => { throw new VppTokenFileError('vppTokenFileInvalid', 'This file is not a content token of Apps and Books (.vpptoken)'); };
  if (!sToken || !/^[A-Za-z0-9+/=_-]+$/.test(sToken)) bad();
  let doc: Record<string, unknown> | null = null;
  try {
    const v = JSON.parse(Buffer.from(sToken, 'base64').toString('utf8')) as unknown;
    doc = v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null;
  } catch { doc = null; }
  if (!doc || typeof doc.token !== 'string' || doc.token.length < 8 || typeof doc.expDate !== 'string') bad();
  const expDate = new Date(String(doc!.expDate));
  if (Number.isNaN(expDate.getTime())) bad();
  if (expDate.getTime() <= now.getTime()) throw new VppTokenFileError('vppTokenExpired', 'This content token is expired: download a new one from Apple Business');
  const orgName = typeof doc!.orgName === 'string' && doc!.orgName.trim() ? doc!.orgName.trim().slice(0, 200) : null;
  return { sToken, expDate, orgName };
}

/** Constant-time comparison of a presented bearer (Authorization header) with the stored SHA-256 of the secret. */
export function bearerMatches(authorization: string | undefined, storedHash: string): boolean {
  const m = /^Bearer\s+(\S{1,512})$/.exec(String(authorization ?? '').trim());
  const presented = createHash('sha256').update(m ? m[1] : randomBytes(16).toString('hex')).digest();
  const stored = /^[0-9a-f]{64}$/.test(storedHash) ? Buffer.from(storedHash, 'hex') : randomBytes(32);
  return timingSafeEqual(presented, stored) && m !== null;
}

/** Apple's platforms of an asset → the platforms of the catalog (iOS covers iPadOS). */
export function platformsOfAsset(list: string[]): string[] {
  const out = new Set<string>();
  for (const p of list.map((x) => x.toLowerCase())) {
    if (p === 'ios') { out.add('ios'); out.add('ipados'); } else if (p === 'ipados') out.add('ipados');
    else if (p === 'macos' || p === 'osx') out.add('macos');
    else if (p === 'tvos') out.add('tvos');
    else if (p === 'visionos' || p === 'xros') out.add('visionos');
  }
  return [...out].sort();
}

/**
 * Is the mdmInfo a location holds ours, or absent? The id names the instance; its metadata names the tenant
 * (tenants.uuid): a location another tenant of this instance configured is another MDM's for this tenant (review
 * of lot C4: never taken over in silence). A metadata Apple does not return is not held against us [J1].
 */
export const mdmInfoIsOurs = (c: { mdmInfo: { id: string | null; metadata?: string | null } | null }, ours: string, tenantUuid?: string | null): boolean =>
  !c.mdmInfo || !c.mdmInfo.id
  || (c.mdmInfo.id === ours && (!tenantUuid || !c.mdmInfo.metadata || c.mdmInfo.metadata === tenantUuid));
