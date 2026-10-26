import type { Knex } from 'knex';
import { privacyRuleChanges, type Ownership, type PrivacyImpactDto, type PrivacyProfileRules } from '@obligarth/shared';
import { currentProfile, effectiveProfileRules } from './profiles';

// =============================================================================
// The impact of proposed rules on an ownership of the tenant (P0-13 T3; GET /api/privacy/profiles/:ownership/impact,
// and the description of a request): the keys narrowed and widened against the rules in force, the devices of the
// ownership per channel, and the rows the publication would remove (privacy.apply-profile, privacy/apply.ts): the
// applications that are not managed (Apple and the bridge agent: not managed; Android: outside the tenant's catalog)
// and the positions in lost mode. In the caller's connection or transaction, the tenant's context.
// =============================================================================

type Q = Knex | Knex.Transaction;

const count = async (q: Knex.QueryBuilder): Promise<number> => Number(((await q.count('* as n')) as Array<{ n: string | number }>)[0]?.n ?? 0);

export async function profileImpact(q: Q, tenantId: number, ownership: Ownership, rules: PrivacyProfileRules): Promise<PrivacyImpactDto> {
  const current = await currentProfile(q, tenantId, ownership);
  const changes = privacyRuleChanges(await effectiveProfileRules(q, tenantId, ownership), rules);
  const byChannel = await q('devices').where({ tenant_id: tenantId, ownership }).groupBy('management_channel')
    .select('management_channel').count('* as n') as Array<{ management_channel: string; n: string | number }>;
  const of = (c: string): number => Number(byChannel.find((r) => r.management_channel === c)?.n ?? 0);
  const devices = { total: byChannel.reduce((s, r) => s + Number(r.n), 0), apple: of('apple_mdm'), android: of('amapi'), legacyAgent: of('legacy_agent') };
  const appsOf = (): Knex.QueryBuilder => q('device_apps as da')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'da.device_id').andOn('d.tenant_id', '=', 'da.tenant_id'); })
    .where({ 'da.tenant_id': tenantId, 'd.ownership': ownership });
  let apps = 0;
  if (changes.narrowed.includes('installedApps')) {
    apps = await count(appsOf().whereIn('d.management_channel', ['apple_mdm', 'legacy_agent']).where('da.managed', false))
      + await count(appsOf().where('d.management_channel', 'amapi')
        .whereNotIn('da.identifier', q('apps').where({ tenant_id: tenantId, platform_family: 'android' }).whereNull('archived_at').select('identifier')));
  }
  const locations = changes.narrowed.includes('lostModeLocation')
    ? await count(q('lost_mode_locations as l')
      .join('devices as d', function joinDevice() { this.on('d.id', '=', 'l.device_id').andOn('d.tenant_id', '=', 'l.tenant_id'); })
      .where({ 'l.tenant_id': tenantId, 'd.ownership': ownership }))
    : 0;
  return {
    ownership, baseVersion: current?.version ?? null, firstVersion: !current, rules,
    narrowed: changes.narrowed, widened: changes.widened, devices, scrub: { apps, locations },
  };
}
