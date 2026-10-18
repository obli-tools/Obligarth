import { config } from '../../config';
import { db } from '../../db';
import { asIdentity, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { recordInstanceDeadline, retireInstanceDeadlines } from './deadlines';
import type { SignedFileCheck } from './pushFiles';

// =============================================================================
// The vendor certificate's deadline (docs: integration-apple-edge §11.1 step
// 3, §11.4): an item of the instance (vendor_certificate), written in the
// identity context after the import (rls-tenant §5.3.1). Only a certificate
// the platform pinned (APPLE_MDM_VENDOR_CERT_SHA256, checkVendorTrust) sets it
// (review of lot C3, R2: an import by a tenant must never replace nor retire
// the instance's item with a certificate it made); the items of certificates
// no longer pinned are retired, those of the other pinned ones kept (a
// rotation). Best effort: a failure is logged, the import stands.
// =============================================================================

export async function recordVendorDeadline(actor: DbActor, check: SignedFileCheck): Promise<void> {
  const pins = config.apple.vendorCertPins ?? [];
  if (check.vendorTrusted !== true || !pins.includes(check.vendorCertSha256)) return;
  try {
    await asIdentity(actor, () => db.transaction(async (trx) => {
      await recordInstanceDeadline(trx, {
        kind: 'vendor_certificate', subjectRef: check.vendorCertSha256, label: `MDM Vendor certificate (${check.vendorCertLabel})`,
        notAfter: check.vendorCertNotAfter, source: 'brain', replace: true,
      });
      await retireInstanceDeadlines(trx, 'vendor_certificate', pins);
    }));
  } catch (err) {
    logger.warn({ code: (err as { code?: unknown })?.code ?? null }, 'the vendor certificate deadline was not recorded');
  }
}
