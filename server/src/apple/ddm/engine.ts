import type { Knex } from 'knex';
import type { NanoEnrollType, Ownership } from '@obligarth/shared';
import { logger } from '../../utils/logger';
import { privacyRulesFor, type PrivacyRules } from '../devices/privacy';
import { BASELINE_AFTER_SECONDS, baselineCapabilities } from './baseline';
import { EMPTY_DECLARATIONS_TOKEN } from './canonical';
import { parseClientCapabilities, type DdmClientCapabilities, type DeclarationFamily } from './capabilities';
import { ddmMetrics } from './metrics';
import { buildSet, type DeclarationSpec, type DroppedDeclaration, type SetDeclaration } from './validate';

// =============================================================================
// DDM engine (docs: integration-apple-edge §9.1 to §9.4, I7, I8, EX-12):
// generic, fed by declaration providers (the core provider serves the status
// subscriptions; the policies and the applications plug theirs in).
//   - a declaration is addressed by content in its tenant: (identifier,
//     ServerToken) unique in apple_declarations, never modified;
//   - the set of a device (apple_declaration_sets): its sorted items, its
//     DeclarationsToken, the time it was computed; the previous set stays
//     served for 24 h (a device in the middle of a synchronisation);
//   - a device is never served a declaration type it did not announce, and
//     nothing at all until it reported its capabilities (or, 15 minutes after
//     the DDM was activated, the reference capabilities of its OS).
// computeSet is deterministic: the same device, providers and capabilities
// give the same tokens, and a set that did not change writes nothing.
// In the caller's transaction and tenant context; no network.
// =============================================================================

export type { DeclarationFamily, DdmClientCapabilities } from './capabilities';
export type { DeclarationSpec } from './validate';
export type { JsonValue } from './canonical';

export interface DdmDeviceContext {
  tenantId: number;
  deviceId: number;
  platform: 'ios' | 'ipados' | null;
  osVersion: string | null;
  ownership: Ownership | null;
  supervised: boolean | null;
  enrollmentType: NanoEnrollType;
  /** Group of the device and its ancestors (policy inheritance), the nearest first. */
  groupIds: number[];
  /** null until the device reported management.client-capabilities (§9.3). */
  capabilities: DdmClientCapabilities | null;
  privacy: PrivacyRules;
}

export interface DeclarationProvider {
  /** 'core', 'policies', 'apps', 'updates'. */
  name: string;
  /** Identifiers this provider owns, e.g. /^obg\.(act|cfg|ast|mgt)\.pol-/. */
  owns: RegExp;
  /** Pure reads in trx, no network, 200 ms at most for one device. */
  declarationsFor(trx: Knex.Transaction, ctx: DdmDeviceContext): Promise<DeclarationSpec[]>;
}

const providers: DeclarationProvider[] = [];
let frozen = false;
const PROVIDER_NAME_RE = /^[a-z][a-z0-9_-]{0,47}$/;

/** Registers a provider, before jobs.start() (the registry is frozen with the jobs'); a name once. */
export function registerDeclarationProvider(p: DeclarationProvider): void {
  if (frozen) throw new Error('declaration providers are registered before the jobs start');
  if (!p || !PROVIDER_NAME_RE.test(String(p.name ?? ''))) throw new Error('declaration provider: invalid name');
  if (!(p.owns instanceof RegExp)) throw new Error(`declaration provider ${p.name}: owns must be a regular expression`);
  if (typeof p.declarationsFor !== 'function') throw new Error(`declaration provider ${p.name}: declarationsFor missing`);
  if (providers.some((x) => x.name === p.name)) throw new Error(`declaration provider ${p.name}: registered twice`);
  providers.push(p);
}

/** No provider may be added once the jobs run (registerAppleDdm's start task). */
export function freezeDeclarationProviders(): void {
  frozen = true;
}

export function declarationProviders(): readonly DeclarationProvider[] {
  return providers;
}

/** Tests: an empty registry again. */
export function resetDeclarationProvidersForTests(): void {
  providers.length = 0;
  frozen = false;
}

// ── Recomputation requests (the queues are the jobs module's) ───────────────────

export type RecomputeScope = { deviceIds: number[] } | { all: true };
type RecomputeSender = (trx: Knex.Transaction | null, tenantId: number, scope: RecomputeScope) => Promise<void>;
let recomputeSender: RecomputeSender | null = null;

/** ddm/jobs.ts hands over its queues at registration. */
export function setRecomputeSender(fn: RecomputeSender): void {
  recomputeSender = fn;
}

/**
 * Requests the recomputation (and the synchronisation) of the sets of devices of the tenant, or of all of them:
 * apple.ddm.device-sync per device, apple.ddm.recompute-tenant for the whole tenant or a large batch. Inside the
 * caller's transaction when given (the jobs exist if and only if it commits). The requests are grouped by the
 * queues (one waiting job per device or per tenant). Without the Apple module (a CLI, a test), nothing is sent.
 */
export async function requestDdmRecompute(trx: Knex.Transaction | null, tenantId: number, scope: RecomputeScope): Promise<void> {
  if (!recomputeSender) {
    logger.debug({ tenantId }, 'DDM recomputation not requested: the Apple module is not registered');
    return;
  }
  await recomputeSender(trx, tenantId, scope);
}

// ── Set of a device ────────────────────────────────────────────────────────────

export interface SetItem {
  family: DeclarationFamily;
  identifier: string;
  server_token: string;
  type: string;
}

export interface ComputedSet {
  deviceId: number;
  declarationsToken: string;
  computedAt: Date;
  items: SetItem[];
  /** The token differs from the one stored before (or no set was stored). */
  changed: boolean;
  /** Declarations a provider returned and the engine set aside (for the logs and the platform alerts). */
  dropped: DroppedDeclaration[];
  /** The reference capabilities of the OS served this computation (§9.3 fallback). */
  usedBaseline: boolean;
  /** No capabilities yet: the set is empty. */
  awaitingCapabilities: boolean;
}

interface DeviceRow {
  id: number;
  platform: string;
  os_version: string | null;
  ownership: Ownership | null;
  supervised: boolean | null;
  group_id: number | null;
  nano_enroll_type: NanoEnrollType;
  ddm_enabled_at: Date | null;
  ddm_client_capabilities: unknown;
}

/** How long the previous set of a device stays served. */
const PREVIOUS_SET_HOURS = 24;
/** last_used_at of a declaration cited again is refreshed at most this often (a hot row: thousands of devices
 *  cite the same declaration). */
const LAST_USED_REFRESH_MINUTES = 60;

const itemsOf = (declarations: SetDeclaration[]): SetItem[] =>
  declarations.map((d) => ({ family: d.family, identifier: d.identifier, server_token: d.serverToken, type: d.type }));

/** The capabilities the engine serves a device with: its own report; failing that, 15 minutes after the DDM was
 *  activated, the reference capabilities of its OS; null before. */
export function effectiveCapabilities(row: { platform: string | null; os_version: string | null; ddm_enabled_at: Date | null; ddm_client_capabilities: unknown },
  now: Date): { capabilities: DdmClientCapabilities | null; baseline: boolean } {
  const own = parseClientCapabilities(row.ddm_client_capabilities);
  if (own) return { capabilities: own, baseline: false };
  if (!row.ddm_enabled_at || now.getTime() - new Date(row.ddm_enabled_at).getTime() < BASELINE_AFTER_SECONDS * 1000) return { capabilities: null, baseline: false };
  const ref = baselineCapabilities(row.platform, row.os_version);
  return { capabilities: ref, baseline: ref !== null };
}

/**
 * Computes the declaration set of a device (§9.4 steps 1 to 6) and stores it when its token changed. The satellite
 * row is locked: one computation of a device at a time (a job and the relay may meet). Returns null when the
 * device has no Apple record in this tenant. The caller decides whether the device is under management.
 */
export async function computeSet(trx: Knex.Transaction, tenantId: number, deviceId: number, now = new Date()): Promise<ComputedSet | null> {
  const row = await trx('apple_devices as a')
    .join('devices as d', function joinDevice() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where({ 'a.tenant_id': tenantId, 'a.device_id': deviceId })
    .forUpdate('a')
    .first('d.id', 'd.platform', 'd.os_version', 'd.ownership', 'd.supervised', 'd.group_id', 'a.nano_enroll_type', 'a.ddm_enabled_at',
      'a.ddm_client_capabilities') as DeviceRow | undefined;
  if (!row) return null;

  const { capabilities, baseline } = effectiveCapabilities(row, now);
  let declarations: SetDeclaration[] = [];
  let dropped: DroppedDeclaration[] = [];
  let declarationsToken = EMPTY_DECLARATIONS_TOKEN;
  if (capabilities) {
    const groupIds = row.group_id === null ? [] : (await trx('device_group_closure')
      .where({ tenant_id: tenantId, descendant_id: row.group_id }).orderBy('depth').pluck('ancestor_id') as number[]).map(Number);
    const ctx: DdmDeviceContext = {
      tenantId, deviceId,
      platform: row.platform === 'ios' || row.platform === 'ipados' ? row.platform : null,
      osVersion: row.os_version ?? null,
      ownership: row.ownership ?? null,
      supervised: row.supervised ?? null,
      enrollmentType: row.nano_enroll_type,
      groupIds,
      capabilities,
      privacy: await privacyRulesFor(trx, tenantId, row.ownership ?? null, row.nano_enroll_type),
    };
    // A provider that fails fails the computation: a set without its declarations would remove them from the device.
    const sources = [];
    for (const p of providers) sources.push({ provider: p.name, owns: p.owns, declarations: await p.declarationsFor(trx, ctx) });
    const built = buildSet(sources, capabilities);
    declarations = built.declarations;
    dropped = built.dropped;
    declarationsToken = built.declarationsToken;
    if (baseline) {
      ddmMetrics.baselineUsed();
      logger.warn({ tenantId, deviceId }, 'DDM: no client capabilities reported, reference capabilities of the OS used');
    }
  }
  const items = itemsOf(declarations);

  // 4. The declarations of the set, addressed by content (in identifier order: two computations of one tenant
  //    never lock the same rows in opposite orders).
  for (const d of declarations) {
    await trx.raw(`
      INSERT INTO obligarth.apple_declarations AS x (tenant_id, identifier, family, type, server_token, payload, source)
      VALUES (?, ?, ?, ?, ?, ?::jsonb, ?)
      ON CONFLICT (tenant_id, identifier, server_token) DO UPDATE SET last_used_at = now()
        WHERE x.last_used_at < now() - make_interval(mins => ?::int)`,
    [tenantId, d.identifier, d.family, d.type, d.serverToken, JSON.stringify(d.payload), d.provider, LAST_USED_REFRESH_MINUTES]);
  }

  // 5 and 6. The set: nothing else when its token did not change.
  const current = await trx('apple_declaration_sets').where({ tenant_id: tenantId, device_id: deviceId })
    .first('declarations_token', 'computed_at') as { declarations_token: string; computed_at: Date } | undefined;
  if (current && current.declarations_token === declarationsToken) {
    return { deviceId, declarationsToken, computedAt: new Date(current.computed_at), items, changed: false, dropped, usedBaseline: baseline,
      awaitingCapabilities: capabilities === null };
  }
  // The Timestamp of the tokens has a resolution of one second: computed_at is stored at that resolution, so that
  // every reader derives the same bytes from it.
  const computedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  if (current) {
    await trx.raw(`
      UPDATE obligarth.apple_declaration_sets
         SET previous_items = items, previous_until = ?::timestamptz + make_interval(hours => ?::int),
             items = ?::jsonb, declarations_token = ?, computed_at = ?
       WHERE tenant_id = ? AND device_id = ?`,
    [now, PREVIOUS_SET_HOURS, JSON.stringify(items), declarationsToken, computedAt, tenantId, deviceId]);
  } else {
    await trx('apple_declaration_sets').insert({
      tenant_id: tenantId, device_id: deviceId, declarations_token: declarationsToken, items: JSON.stringify(items), computed_at: computedAt,
    });
  }
  ddmMetrics.setComputed();
  return { deviceId, declarationsToken, computedAt, items, changed: true, dropped, usedBaseline: baseline, awaitingCapabilities: capabilities === null };
}
