import { db } from '../../db';
import { asIdentity, type DbActor } from '../../db/context';
import { logger } from '../../utils/logger';
import { recordInstanceDeadline, retireInstanceDeadlines } from './deadlines';
import type { SignedFileCheck } from './pushFiles';

// =============================================================================
// The vendor certificate's deadline (docs: integration-apple-edge §11.1 step
// 3, §11.4): an item of the instance (vendor_certificate), the certificate of
// the last signed request imported (the previous ones retired), written in the
// identity context after the import (rls-tenant §5.3.1). Best effort: a
// failure is logged, the import stands.
// =============================================================================

export async function recordVendorDeadline(actor: DbActor, check: SignedFileCheck): Promise<void> {
  try {
    await asIdentity(actor, () => db.transaction(async (trx) => {
      await recordInstanceDeadline(trx, {
        kind: 'vendor_certificate', subjectRef: check.vendorCertSha256, label: `MDM Vendor certificate (${check.vendorCertLabel})`,
        notAfter: check.vendorCertNotAfter, source: 'brain', replace: true,
      });
      await retireInstanceDeadlines(trx, 'vendor_certificate', check.vendorCertSha256);
    }));
  } catch (err) {
    logger.warn({ code: (err as { code?: unknown })?.code ?? null }, 'the vendor certificate deadline was not recorded');
  }
}
