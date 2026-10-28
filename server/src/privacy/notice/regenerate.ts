import type { Knex } from 'knex';
import { z } from 'zod';
import { NOTICE_LOCALES, NOTICE_PLATFORMS, OWNERSHIPS } from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { privacyMetrics } from '../metrics';
import { invalidatePrivacyProfiles } from '../profiles';
import { ensureNotice, noticePublishedEntry, noticeSettingsOf } from './provider';

// =============================================================================
// privacy.notice-regenerate (P0-13 T5, USR-01): the notices of a tenant generated again from the inputs in force, the
// 2 × 3 × 2 combinations (platforms apple and android, the three ownerships, fr and en; the Android company devices
// too: their texts are generated, their display waits for the v1, D13). A content that changed becomes the current
// version and supersedes the previous one (obligarth.notice_ensure); each version published gets its audit entry
// privacy.notice_published (standard: hash and versions), in the transaction that published it.
// Queued, in the transaction of the change, by: the publication of a privacy profile (privacy/approvals.ts
// onProfilePublished), a change of the retention (privacy/retentionPolicy.ts onRetentionChanged), a change of the
// settings of the notice (routes.ts, P0-13 T6), and the daily retention of the tenant (modules/privacy.ts: a decrease of the
// retention reaching its date changes the durations). The enrollment pages publish a changed content by themselves
// (provider.ts): this job keeps the versions of the console and their audit up to date without waiting for one.
// Policy stately, key t:<tenant>: a change while a run is active queues one more run; more are folded into it.
// The cache of the profiles of the tenant is dropped first: the run reads what was just published in another process.
// Generation 2 (P0-15 T2, the remote assistance): the tenants concerned are those whose corporate profile allows it —
// by default every tenant (§0.1 rule 5) —; a publication queues this job by its hook, and the daily retention of every
// tenant queues it too, so no notice stays at generation 1 a day after an update. The other notices keep their content
// word for word: nothing is published for them (notice_ensure compares the contents), nothing to acknowledge again.
// =============================================================================

const JOB_NAME = 'privacy.notice-regenerate';

const RegeneratePayload = z.object({ tenantId: z.number().int().positive() }).strict();
type Regenerate = z.infer<typeof RegeneratePayload>;

let regenerateJob: JobHandle<Regenerate> | null = null;

/** Queues the regeneration of the notices of the tenant: in `trx` when given (sent at its commit only), else now. */
export async function requestNoticeRegeneration(trx: Knex.Transaction | null, tenantId: number): Promise<string | null> {
  if (!regenerateJob) throw new Error(`${JOB_NAME} is not registered (registerPrivacyModule)`);
  const o = { singletonKey: `t:${tenantId}`, tenantId };
  return trx ? regenerateJob.sendInTx(trx, { tenantId }, o) : regenerateJob.send({ tenantId }, o);
}

async function regenerate(ctx: JobContext<Regenerate>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  invalidatePrivacyProfiles(tenantId);
  const tenant = await ctx.inTenant(() => db('tenants').where({ id: tenantId }).first('name')) as { name: string } | undefined;
  if (!tenant) return { output: { published: 0, unchanged: 0, tenant: false } };
  const auditCtx = audit.fromJob({ name: ctx.name, requestId: ctx.requestId });
  let published = 0;
  let unchanged = 0;
  for (const platform of NOTICE_PLATFORMS) {
    for (const ownership of OWNERSHIPS) {
      for (const locale of NOTICE_LOCALES) {
        ctx.throwIfAborted();
        const done = await ctx.withTenant(async (trx) => {
          const settings = await noticeSettingsOf(trx, tenantId);
          const n = await ensureNotice(trx, tenantId, platform, ownership, locale, String(tenant.name), settings);
          if (n.published) await audit.appendInTx(trx, noticePublishedEntry(tenantId, platform, ownership, n, 'regeneration'), auditCtx);
          return n.published;
        });
        if (done) { published++; privacyMetrics.noticePublished('regeneration'); } else unchanged++;
      }
    }
  }
  return { output: { published, unchanged } };
}

let registered = false;

/** Registers privacy.notice-regenerate (registerPrivacyModule, before anything starts). */
export function registerNoticeRegenerationJob(): void {
  if (registered) return;
  registered = true;
  regenerateJob = registerJob({
    name: JOB_NAME,
    scope: 'tenant',
    description: 'Generate the employee notices of a tenant again from its privacy profiles, retention and notice settings; publish the changed ones',
    payload: RegeneratePayload,
    policy: 'stately',
    retry: { limit: 3, delaySeconds: 60, backoff: true, maxDelaySeconds: 1_800 },
    timeoutSeconds: 300,
    // Rare (a change of a profile, of the retention or of the settings, the daily retention): woken by NOTIFY, polled
    // by an idle queue (file-durable L3).
    notify: true,
    pollSeconds: 300,
    handler: regenerate,
  });
}
