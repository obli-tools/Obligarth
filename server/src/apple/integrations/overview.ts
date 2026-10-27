import type { Knex } from 'knex';
import { OWNERSHIPS, noticeCompleteness, type Ownership } from '@obligarth/shared';
import type {
  DeadlineKind, DeadlineLevel, DeadlineView, IntegrationCardState, IntegrationsSummary, PushCertState, ReadinessItem,
} from '@obligarth/shared';
import { config } from '../../config';
import { ddmMetrics } from '../ddm/metrics';
import { edgeHealth } from '../edge/health';
import { usesDefaultNotice } from '../enrollment/notice';
import { usesDefaultPrivacyRules } from '../devices/privacy';
import { currentProfile } from '../../privacy/profiles';
import { noticeSettingsOf } from '../../privacy/notice/provider';
import { instanceStage, signingIdentityOf } from '../../ops/stage';

// =============================================================================
// What the Integrations tab shows (docs: integration-apple-edge §11.4, §11.5,
// §11.7; INT-04, INT-05): the readiness checklist of a tenant, computed
// without writing anything, the summary of the five cards, the deadlines of
// the view integration_deadlines. In the caller's context (the tenant's, or
// 'platform' for the cross-tenant view of the platform administrators). No
// device data on these cards: counts only.
// =============================================================================

const DAY = 86_400_000;
const iso = (v: Date | string | null | undefined): string | null => (v ? new Date(v).toISOString() : null);
const count = async (qb: Knex.QueryBuilder): Promise<number> => Number(((await qb.count({ n: '*' }).first()) as { n?: string | number } | undefined)?.n ?? 0);

export interface DeadlineRow {
  id: string;
  tenant_id: number | null;
  tenant_name?: string | null;
  kind: DeadlineKind;
  label: string;
  not_after: Date | null;
  source: DeadlineView['source'];
  last_alert_threshold: number | null;
  retired_at: Date | null;
  updated_at: Date;
  days_left: number | null;
  level: DeadlineLevel;
}

export function deadlineView(r: DeadlineRow, withTenant = false): DeadlineView {
  return {
    id: r.id, tenantId: r.tenant_id === null ? null : Number(r.tenant_id), ...(withTenant ? { tenantName: r.tenant_name ?? null } : {}),
    kind: r.kind, label: r.label, notAfter: iso(r.not_after), daysLeft: r.days_left === null ? null : Number(r.days_left), level: r.level,
    source: r.source, lastAlertThreshold: r.last_alert_threshold === null ? null : Number(r.last_alert_threshold), updatedAt: iso(r.updated_at)!,
  };
}

const DEADLINE_COLS = ['i.id', 'i.tenant_id', 'i.kind', 'i.label', 'i.not_after', 'i.source', 'i.last_alert_threshold', 'i.retired_at', 'i.updated_at',
  'i.days_left', 'i.level'];

/** The tenant's deadlines (its own items only: the instance's are the platform administrators'). */
export async function tenantDeadlines(q: Knex, tenantId: number, o: { retired?: boolean } = {}): Promise<DeadlineView[]> {
  let qb = q('integration_deadlines as i').where('i.tenant_id', tenantId);
  if (!o.retired) qb = qb.whereNull('i.retired_at');
  const rows = await qb.orderByRaw('i.not_after ASC NULLS LAST').limit(500).select(DEADLINE_COLS) as DeadlineRow[];
  return rows.map((r) => deadlineView(r));
}

/** Every deadline of the instance (context 'platform', under the administrator's grant): tenants' and instance's. */
export async function allDeadlines(q: Knex, o: { retired?: boolean } = {}): Promise<DeadlineView[]> {
  let qb = q('integration_deadlines as i').leftJoin('tenants as t', 't.id', 'i.tenant_id');
  if (!o.retired) qb = qb.whereNull('i.retired_at');
  const rows = await qb.orderByRaw('i.not_after ASC NULLS LAST').limit(2000).select([...DEADLINE_COLS, 't.name as tenant_name']) as DeadlineRow[];
  return rows.map((r) => deadlineView(r, true));
}

/** The readiness checklist of the tenant (§11.5). */
export async function readiness(q: Knex, tenantId: number): Promise<ReadinessItem[]> {
  const now = Date.now();
  const out: ReadinessItem[] = [];
  const t = await q('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null } | undefined;
  const mirror = await q('tenant_apple_edge').where({ tenant_id: tenantId }).first('edge_state', 'last_error_code') as
    { edge_state: string; last_error_code: string | null } | undefined;
  const edgeState = mirror?.edge_state ?? 'unprovisioned';
  if (config.apple.mode !== 'on') out.push({ key: 'tenant.provisioned', state: 'error', reason: 'integration_off' });
  else if (t?.mdm_key && edgeState === 'active') out.push({ key: 'tenant.provisioned', state: 'ready' });
  else if (['unprovisioned', 'provisioning'].includes(edgeState)) out.push({ key: 'tenant.provisioned', state: 'todo', reason: 'provisioning' });
  else out.push({ key: 'tenant.provisioned', state: 'error', reason: edgeState });

  const push = await q('tenant_apple_push').where({ tenant_id: tenantId, state: 'active' }).first('not_after') as { not_after: Date | null } | undefined;
  if (!push) out.push({ key: 'push.active', state: 'todo', reason: 'no_certificate' });
  else {
    const days = push.not_after ? Math.floor((new Date(push.not_after).getTime() - now) / DAY) : null;
    if (days !== null && days <= 30) out.push({ key: 'push.active', state: days <= 7 ? 'error' : 'warning', reason: 'expiring', params: { daysLeft: Math.max(0, days) } });
    else out.push({ key: 'push.active', state: 'ready' });
  }

  const profiles = await q('enrollment_profiles').where({ tenant_id: tenantId, platform: 'apple', enabled: true }).whereNull('archived_at')
    .groupBy('method').select('method').count({ n: '*' }) as Array<{ method: string; n: string | number }>;
  const byMethod = new Map(profiles.map((p) => [p.method, Number(p.n)]));
  const totalProfiles = [...byMethod.values()].reduce((a, b) => a + b, 0);
  out.push(totalProfiles > 0 ? { key: 'enrollment.profile', state: 'ready' } : { key: 'enrollment.profile', state: 'todo', reason: 'no_profile' });

  const servers = await q('tenant_apple_ade_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed')
    .select('state', 'byod_discovery') as Array<{ state: string; byod_discovery: boolean }>;
  if (!byMethod.get('ade')) out.push({ key: 'ade.server', state: 'not_applicable' });
  else if (servers.some((s) => s.state === 'active')) out.push({ key: 'ade.server', state: 'ready' });
  else if (servers.some((s) => s.state === 'terms_not_signed')) out.push({ key: 'ade.server', state: 'error', reason: 'terms_not_signed' });
  else if (servers.length > 0) out.push({ key: 'ade.server', state: 'error', reason: 'server_not_active' });
  else out.push({ key: 'ade.server', state: 'todo', reason: 'no_server' });

  if (!byMethod.get('byod_account')) out.push({ key: 'byod.discovery', state: 'not_applicable' });
  else out.push(servers.some((s) => s.state === 'active' && s.byod_discovery)
    ? { key: 'byod.discovery', state: 'ready' } : { key: 'byod.discovery', state: 'todo', reason: 'not_declared' });

  // Apps and Books comes with lot C4: applicable once a content token exists.
  const vpp = await q('tenant_apple_vpp_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').select('state') as Array<{ state: string }>;
  if (vpp.length === 0) out.push({ key: 'vpp.token', state: 'not_applicable' });
  else out.push(vpp.some((v) => v.state === 'active') ? { key: 'vpp.token', state: 'ready' } : { key: 'vpp.token', state: 'error', reason: 'no_active_token' });

  // The profile signing identity (D12): missing or expired, a warning in lab and an error beyond (P0-13 T11, D8: the
  // instance is then not ready), the profiles served unsigned or, when a signature is required, the enrollments
  // refused; not heard from apple-edge since the start, unknown (a warning, as the console of the operations says).
  const signing = signingIdentityOf(edgeHealth(), new Date(now));
  const required = config.apple.requireSignedProfiles;
  if (signing.state === 'ok') out.push({ key: 'signing.identity', state: 'ready' });
  else if (signing.state === 'expiring') {
    out.push({ key: 'signing.identity', state: 'warning', reason: 'expiring', params: { daysLeft: Math.max(0, signing.daysLeft ?? 0) } });
  } else if (signing.state === 'unknown') {
    out.push({ key: 'signing.identity', state: 'warning', reason: 'signing_unknown' });
  } else {
    const reason = signing.state === 'expired'
      ? (required ? 'signing_expired_refused' : 'signing_expired_unsigned')
      : (required ? 'signing_missing_refused' : 'unsigned_profiles');
    out.push({ key: 'signing.identity', state: instanceStage() === 'lab' ? 'warning' : 'error', reason });
  }
  out.push(await noticeReadiness(q, tenantId));
  out.push(await privacyProfileReadiness(q, tenantId));

  const ddmDevices = await count(q('apple_devices as a').join('devices as d', function on() { this.on('d.id', 'a.device_id').andOn('d.tenant_id', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.ddm_enabled': true }).whereNot('d.enrollment_state', 'unenrolled'));
  if (ddmDevices === 0) out.push({ key: 'ddm.relay', state: 'not_applicable' });
  else {
    const last = await q('apple_declaration_status').where({ tenant_id: tenantId }).max({ at: 'observed_at' }).first() as { at: Date | null } | undefined;
    const lastAt = Math.max(last?.at ? new Date(last.at).getTime() : 0, ddmMetrics.lastRelayOkAt() ?? 0);
    out.push(lastAt > now - DAY ? { key: 'ddm.relay', state: 'ready' } : { key: 'ddm.relay', state: 'warning', reason: 'relay_idle' });
  }
  return out;
}

/** The notice of the employees (P0-13 T6, USR-01): the default notice of the laboratory while no provider is installed;
 *  else the generated notice, ready once its settings are complete (D7: the data controller and a contact); not
 *  complete: a warning in the stage lab (served), an error beyond it (every enrollment of the tenant is refused). */
async function noticeReadiness(q: Knex, tenantId: number): Promise<ReadinessItem> {
  if (usesDefaultNotice()) return { key: 'notice.custom', state: 'warning', reason: 'default_notice' };
  const missing = noticeCompleteness((await noticeSettingsOf(q, tenantId)).settings);
  if (missing.length === 0) return { key: 'notice.custom', state: 'ready' };
  return { key: 'notice.custom', state: instanceStage() === 'lab' ? 'warning' : 'error', reason: 'notice_incomplete', params: { missing: missing.length } };
}

/** The tenant's own privacy profiles (P0-13, CNF-02) for the ownerships it enrolls (its enrollment profiles in use, of
 *  every platform): ready once each of them has a profile published, the default rules otherwise (params.ownerships:
 *  how many still have them). A tenant without an enrollment profile yet: ready once it published one profile. */
async function privacyProfileReadiness(q: Knex, tenantId: number): Promise<ReadinessItem> {
  if (usesDefaultPrivacyRules()) return { key: 'privacy.profile', state: 'warning', reason: 'default_rules' };
  const rows = await q('enrollment_profiles').where({ tenant_id: tenantId, enabled: true }).whereNull('archived_at')
    .distinct('ownership') as Array<{ ownership: string }>;
  const inUse = OWNERSHIPS.filter((o) => rows.some((r) => r.ownership === o));
  const published = new Set<Ownership>();
  for (const o of OWNERSHIPS) if (await currentProfile(q, tenantId, o)) published.add(o);
  if (inUse.length === 0) {
    return published.size ? { key: 'privacy.profile', state: 'ready' } : { key: 'privacy.profile', state: 'warning', reason: 'default_rules' };
  }
  const missing = inUse.filter((o) => !published.has(o)).length;
  return missing === 0 ? { key: 'privacy.profile', state: 'ready' }
    : { key: 'privacy.profile', state: 'warning', reason: 'default_rules', params: { ownerships: missing } };
}

const WORST: Record<string, number> = { ready: 0, todo: 1, attention: 2, error: 3 };
const worst = (...s: IntegrationCardState[]): IntegrationCardState => s.reduce((a, b) => (WORST[b] > WORST[a] ? b : a), 'ready' as IntegrationCardState);

/** The summary of the five cards (§11.7). */
export async function integrationsSummary(q: Knex, tenantId: number): Promise<IntegrationsSummary> {
  const t = await q('tenants').where({ id: tenantId }).first('mdm_key') as { mdm_key: string | null };
  const mirror = await q('tenant_apple_edge').where({ tenant_id: tenantId }).first('edge_state', 'commands_frozen') as
    { edge_state: string; commands_frozen: boolean } | undefined;
  const edgeState = mirror?.edge_state ?? 'unprovisioned';
  const reachable = config.apple.mode === 'on' ? edgeHealth().up : null;
  const edgeCard: IntegrationCardState = config.apple.mode !== 'on' || reachable === false ? 'error'
    : edgeState === 'active' ? (mirror?.commands_frozen ? 'attention' : 'ready') : ['unprovisioned', 'provisioning'].includes(edgeState) ? 'todo' : 'error';

  const pushRows = await q('tenant_apple_push').where({ tenant_id: tenantId }).whereIn('state', ['active', 'legacy', 'vendor_signature_pending', 'apple_upload_pending'])
    .select('state', 'topic', 'not_after', 'apple_account_hint') as Array<{ state: PushCertState; topic: string | null; not_after: Date | null; apple_account_hint: string | null }>;
  const active = pushRows.find((r) => r.state === 'active');
  const open = pushRows.find((r) => r.state === 'vendor_signature_pending' || r.state === 'apple_upload_pending');
  const legacyTopics = pushRows.filter((r) => r.state === 'legacy' && r.topic).map((r) => r.topic as string);
  const legacyDevices = legacyTopics.length ? await count(q('apple_devices as a').join('devices as d', function on() { this.on('d.id', 'a.device_id').andOn('d.tenant_id', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId).whereIn('a.topic', legacyTopics).whereNot('d.enrollment_state', 'unenrolled')) : 0;
  const pushDays = active?.not_after ? Math.floor((new Date(active.not_after).getTime() - Date.now()) / DAY) : null;
  const pushCard: IntegrationCardState = !active ? 'todo' : pushDays !== null && pushDays <= 7 ? 'error' : (pushDays !== null && pushDays <= 30) || legacyDevices > 0 ? 'attention' : 'ready';

  const servers = await q('tenant_apple_ade_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed')
    .select('state', 'byod_discovery', 'not_after') as Array<{ state: string; byod_discovery: boolean; not_after: Date | null }>;
  const adeDevices = await count(q('apple_ade_devices').where({ tenant_id: tenantId }).whereNull('removed_at'));
  const inError = servers.filter((s) => s.state === 'error' || s.state === 'expired').length;
  const terms = servers.filter((s) => s.state === 'terms_not_signed').length;
  const nextExpiry = servers.map((s) => s.not_after).filter((d): d is Date => !!d).sort((a, b) => new Date(a).getTime() - new Date(b).getTime())[0] ?? null;
  const adeCard: IntegrationCardState = servers.length === 0 ? 'todo' : inError + terms > 0 ? 'error'
    : servers.some((s) => s.state === 'awaiting_token') ? 'attention' : 'ready';

  const vpp = await q('tenant_apple_vpp_tokens').where({ tenant_id: tenantId }).whereNot('state', 'removed').select('state') as Array<{ state: string }>;
  const vppCard: IntegrationCardState = vpp.length === 0 ? 'todo' : vpp.every((v) => v.state === 'active') ? 'ready' : 'error';

  const deadlines = await tenantDeadlines(q, tenantId);
  const soon = deadlines.filter((d) => d.level !== 'ok').slice(0, 20);
  const deadlinesCard: IntegrationCardState = deadlines.some((d) => d.level === 'expired' || d.level === 'critical') ? 'error'
    : deadlines.some((d) => d.level === 'warning') ? 'attention' : 'ready';

  return {
    edge: { state: edgeCard, edgeState, mdmKey: t?.mdm_key ?? null, commandsFrozen: mirror?.commands_frozen === true, reachable },
    push: {
      state: pushCard, topic: active?.topic ?? null, notAfter: iso(active?.not_after), openRequestState: open?.state ?? null, legacyDevices,
      appleAccountHint: (open ?? active)?.apple_account_hint ?? null,
    },
    ade: {
      state: adeCard, servers: servers.length, active: servers.filter((s) => s.state === 'active').length, inError, termsToAccept: terms,
      byodDiscovery: servers.some((s) => s.byod_discovery), devices: adeDevices, nextExpiry: iso(nextExpiry),
    },
    vpp: { state: vppCard, tokens: vpp.length, active: vpp.filter((v) => v.state === 'active').length },
    deadlines: { state: worst(deadlinesCard), items: soon.length ? soon : deadlines.slice(0, 5) },
    readiness: await readiness(q, tenantId),
  };
}
