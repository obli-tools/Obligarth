import { LEGACY_AGENT_PACKAGE } from '@obligarth/shared';
import { db } from '../db';
import { asTenant } from '../db/context';
import { forEachTenant } from '../db/tenantContext';
import { tenantFrozen } from '../guard/frozen';
import { JobError, type JobContext, type JobResult } from '../jobs';
import { restrictionFloor, restrictionService } from '../services/restriction.service';
import { legacyAgentCommands } from './commands';

// =============================================================================
// Harvest of the APKs of the fleet (agent 1.2.0): the job
// legacy-agent.apk-harvest (every 15 minutes) asks ONE device for the APK of
// each app of the fleet that the tenant has no package of (same package name,
// same versionCode), so that a migration keeps the apps it found installed:
//   what       the apps the agents inventoried (device_apps, agent_report),
//              not system, a numeric versionCode, never the agent itself;
//   who        an agent of the tenant, enrolled, not revoked, 1.2.0 or later
//              (app.pull), that interrogated in the last hour: the one that
//              interrogated last;
//   not again  none for a package with an open app.pull, nor one queued in
//              the last 24 hours (a failure is taken up the next day);
//   pace       HARVEST_PER_RUN commands per tenant and run at most;
//   guards     a frozen tenant gets nothing; a tenant whose restrictions
//              matrix puts a level on legacy_agent.apps (a person would be
//              asked) is left alone;
//   queue      legacyAgentCommands.enqueue, origin 'system', actor
//              j:legacy-agent.apk-harvest, its audit entry in the transaction.
// The APK comes back by POST /agent/v1/pull/<commandId> (pull.ts).
// =============================================================================

export const HARVEST_JOB = 'legacy-agent.apk-harvest';
export const HARVEST_ACTOR = `j:${HARVEST_JOB}`;
export const HARVEST_PER_RUN = 10;
export const PULL_MIN_VERSION_CODE = 10_200;
const RESTRICTION_KEY = 'legacy_agent.apps';

interface Wanted { identifier: string; version_code: string; device_id: number }

/** The apps of the tenant's fleet without a package, each with the device to ask. */
async function wantedOf(tenantId: number, limit: number): Promise<Wanted[]> {
  const res = await db.raw(`
    SELECT x.identifier, x.version_code, x.device_id FROM (
      SELECT da.identifier, da.short_version AS version_code, da.device_id,
             row_number() OVER (PARTITION BY da.identifier, da.short_version ORDER BY a.last_poll_at DESC, da.device_id) AS rn
        FROM obligarth.device_apps da
        JOIN obligarth.legacy_agent_devices a ON a.tenant_id = da.tenant_id AND a.device_id = da.device_id
        JOIN obligarth.devices d ON d.tenant_id = da.tenant_id AND d.id = da.device_id
       WHERE da.tenant_id = ? AND da.source = 'agent_report' AND da.is_system IS NOT TRUE
         AND da.short_version ~ '^[0-9]{1,15}$' AND da.identifier <> ? AND da.identifier NOT LIKE ?
         AND a.revoked_at IS NULL AND a.agent_version_code >= ? AND a.last_poll_at >= now() - interval '1 hour'
         AND d.enrollment_state = 'enrolled' AND d.management_channel = 'legacy_agent'
         AND NOT EXISTS (SELECT 1 FROM obligarth.legacy_agent_packages p
                          WHERE p.tenant_id = da.tenant_id AND p.package_name = da.identifier
                            AND p.version_code = da.short_version::bigint)
         AND NOT EXISTS (SELECT 1 FROM obligarth.legacy_agent_commands c
                          WHERE c.tenant_id = da.tenant_id AND c.request_type = 'app.pull'
                            AND c.params->>'packageName' = da.identifier
                            AND (c.state IN ('pending', 'sent') OR c.created_at > now() - interval '1 day'))
    ) x WHERE x.rn = 1
    ORDER BY x.identifier, x.version_code
    LIMIT ?`, [tenantId, LEGACY_AGENT_PACKAGE, `${LEGACY_AGENT_PACKAGE}.%`, PULL_MIN_VERSION_CODE, limit]) as { rows: Wanted[] };
  return res.rows;
}

/** A level on legacy_agent.apps anywhere in the tenant (a floor, or an entry): the harvest leaves the tenant alone. */
async function restricted(tenantId: number): Promise<boolean> {
  if (restrictionFloor(RESTRICTION_KEY)) return true;
  return !!(await restrictionService.getMap(tenantId))[RESTRICTION_KEY];
}

export async function harvestApks(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const out = { queued: 0, tenants: 0, frozenTenants: 0, restrictedTenants: 0 };
  let enqueueFailed = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const wanted = await wantedOf(tenantId, HARVEST_PER_RUN);
    if (wanted.length === 0) return;
    if (await tenantFrozen(null, tenantId, 'legacy_agent')) { out.frozenTenants++; return; }
    if (await restricted(tenantId)) { out.restrictedTenants++; return; }
    out.tenants++;
    for (const w of wanted) {
      ctx.throwIfAborted();
      try {
        const o = await asTenant(tenantId, ctx.dbActor, () => db.transaction((trx) => legacyAgentCommands.enqueue(trx, {
          tenantId, requestType: 'app.pull', deviceIds: [Number(w.device_id)], params: { packageName: w.identifier },
          origin: 'system', actor: HARVEST_ACTOR, reason: `Automatic harvest of the APK of ${w.identifier} (${w.version_code})`,
        })));
        out.queued += o.targets;
      } catch (err) {
        enqueueFailed++;
        ctx.log.warn({ tenantId, message: (err as Error)?.message?.slice(0, 200) }, 'legacy agent: APK harvest not queued');
      }
    }
  });
  if (failed + enqueueFailed > 0) throw new JobError('partial_failure', `${failed + enqueueFailed} failure(s)`);
  return { output: out };
}
