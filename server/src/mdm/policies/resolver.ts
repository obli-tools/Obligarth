import {
  ANDROID_MODES, APP_MANAGED_DECLARATION, appArtifactKey, availability, versionNum,
  type EffectiveSetting, type JsonValue, type PolicyVariable, type SettingAvailability, type SettingConflictEntry,
  type SettingKind, type SourceScope,
} from '@obligarth/shared';
import type { AppleCatalogView } from '../apple/catalog';
import { appContribution, type Contribution } from './contributions';

// =============================================================================
// The resolution (docs: modele-donnees-mdm §7.6), a pure function: for each
// device, the setting keys retained with their provenance, availability and
// conflicts. One rule of inheritance:
//   1. scopes of the device: the device (rank 0), each group of its group's
//      ancestry from the nearest (rank 1 + depth), the tenant (rank 10 000);
//   2. a resource excluded at any scope of the device does not contribute;
//   3. each remaining inclusion brings the keys of the resource (the published
//      version of a policy, an app);
//   4. by key, the first of (rank, priority, resource) ascending wins;
//      contributions of the winner's rank and priority with another value
//      hash are conflicts (refused at the write, broken here, listed);
//   5. a winning tombstone retains the key as removed;
//   6. the availability of the key for the device (section 7.8).
// The same function serves the writer (section 7.10) and the impact preview
// (section 7.11): both run it on what the loader read.
// =============================================================================

export const RANK = { device: 0, groupBase: 1, tenant: 10_000, library: 20_000 } as const;

export interface ResolutionDevice {
  id: number;
  uuid: string;
  label: string;
  groupId: number | null;
  platform: string;
  /** devices.management_channel (apple_mdm, amapi, legacy_agent): the artifact providers serve by channel (lot AN-P);
   *  absent for a fictitious device (the enrollment policy of a profile). */
  channel?: string;
  osVersion: string | null;
  mode: string;
  supervised: boolean;
  ownership: string;
  serialNumber: string | null;
  udid: string | null;
  modelName: string | null;
  ddmEnabled: boolean;
  /** Declaration types of management.client-capabilities; null until reported. */
  declarationTypes: string[] | null;
  endUser: { email: string | null; displayName: string | null; managedAppleAccount: string | null; externalId: string | null } | null;
}

export interface ResolutionAssignment {
  id: number;
  resourceType: 'policy' | 'app';
  resourceId: number;
  resourceTenantId: number;
  targetScope: 'tenant' | 'group' | 'device';
  targetId: number | null;
  mode: 'include' | 'exclude';
  priority: number;
  options: Record<string, JsonValue>;
}

export interface ResolvedResource {
  type: 'policy' | 'app';
  id: number;
  tenantId: number;
  /** The published version of a policy; null for an app. */
  versionId: number | null;
  name: string;
  /** A policy's contributions (an app's are built per assignment, its options being the value). */
  contributions: Contribution[];
  app?: { identifier: string; supportedPlatforms: string[]; storeId: string | null };
}

export interface ResolutionInput {
  tenantId: number;
  tenant: { name: string; slug: string };
  devices: ResolutionDevice[];
  /** For each group: its ancestors with their depth (the group itself at depth 0), from the closure. */
  groupAncestors: Map<number, Array<{ groupId: number; depth: number }>>;
  assignments: ResolutionAssignment[];
  /** Resources by resourceKey(type, tenantId, id). */
  resources: Map<string, ResolvedResource>;
  catalog: AppleCatalogView;
}

/** A retained setting, with what the writer and the impact preview need besides the stored row. */
export interface ResolvedSetting extends EffectiveSetting {
  type: string;
  kind: SettingKind | 'android';
  key: string | null;
  instance: string | null;
  /** The winning value (secrets as references, variables as templates); absent for a tombstone. For the
   *  compilation (section 7.9): never written with the effective state. */
  value?: JsonValue;
  /** An app: its App Store id (the compilation's iTunesStoreID / AppStoreID). */
  app?: { storeId: string | null };
}

export interface DeviceResolution { deviceId: number; settings: ResolvedSetting[] }
export interface ResolutionOutput { tenantId: number; devices: DeviceResolution[] }

export const resourceKey = (type: string, tenantId: number, id: number): string => `${type}:${tenantId}:${id}`;
const targetKey = (scope: string, id: number | null): string => `${scope}:${id ?? ''}`;

interface Candidate {
  c: Contribution;
  res: ResolvedResource;
  a: ResolutionAssignment;
  scope: SourceScope;
  scopeId: number | null;
  rank: number;
}

const compareCandidates = (x: Candidate, y: Candidate): number =>
  x.rank - y.rank || x.a.priority - y.a.priority
  || (x.res.type < y.res.type ? -1 : x.res.type > y.res.type ? 1 : 0)
  || x.res.tenantId - y.res.tenantId || x.res.id - y.res.id || x.a.id - y.a.id;

/** The value of a variable for a device; null when it has none (absent, or empty). */
export function variableValue(name: PolicyVariable, d: ResolutionDevice, tenant: { name: string; slug: string }): string | null {
  const v = ((): string | null | undefined => {
    switch (name) {
      case 'device.uuid': return d.uuid;
      case 'device.name': return d.label;
      case 'device.serial_number': return d.serialNumber;
      case 'device.udid': return d.udid;
      case 'device.model': return d.modelName;
      case 'user.email': return d.endUser?.email;
      case 'user.display_name': return d.endUser?.displayName;
      case 'user.managed_apple_account': return d.endUser?.managedAppleAccount;
      case 'user.external_id': return d.endUser?.externalId;
      case 'tenant.name': return tenant.name;
      case 'tenant.slug': return tenant.slug;
      default: return null;
    }
  })();
  return typeof v === 'string' && v.trim() !== '' ? v : null;
}

/** Does an app go to this device by the declaration app.managed (section 8.3, DM15)? iOS or iPadOS 17.2 and
 *  later, DDM active, no managed configuration, no takeover. */
export function appViaDeclaration(d: ResolutionDevice, app: NonNullable<Contribution['app']>): boolean {
  const v = versionNum(d.osVersion);
  return (d.platform === 'ios' || d.platform === 'ipados') && v !== null && v >= 17_002_000 && d.ddmEnabled
    && !app.config && !app.takeOver;
}

function availabilityOf(input: ResolutionInput, d: ResolutionDevice, c: Contribution): SettingAvailability {
  const unresolved = c.variables.find((v) => variableValue(v, d, input.tenant) === null) ?? null;
  // An Android key (lot AN-A2): the devices of the channel amapi only, known by their mode (the bridge agent,
  // channel legacy_agent, is 'device_admin' and has no policy in v0: agent-pont-android §2, review PONT-R); the
  // compilation of the Android module checks each field against the device (API level, mode, ownership:
  // mdm/android/availability.ts).
  if (c.kind === 'android') {
    if (d.platform !== 'android' || !(ANDROID_MODES as readonly string[]).includes(d.mode)) {
      return { status: 'not_applicable', reason: 'platform_unsupported' };
    }
    if (unresolved) return { status: 'not_applicable', reason: 'variable_unresolved', detail: unresolved };
    return { status: 'available' };
  }
  if (c.kind === 'app' && c.app) {
    if (c.app.supportedPlatforms.length > 0 && !c.app.supportedPlatforms.includes(d.platform)) {
      return { status: 'not_applicable', reason: 'platform_unsupported' };
    }
    if (appViaDeclaration(d, c.app)) {
      return availability(input.catalog.entry(APP_MANAGED_DECLARATION) ?? APP_MANAGED_FALLBACK, null, facts(d),
        { unresolvedVariable: unresolved });
    }
    if (unresolved) return { status: 'not_applicable', reason: 'variable_unresolved', detail: unresolved };
    return { status: 'available' };
  }
  const entry = input.catalog.entry(c.type);
  const key = c.key !== null ? input.catalog.key(c.type, c.key) ?? null : null;
  return availability(entry, key, facts(d), {
    forbiddenOwnerships: input.catalog.overlay(c.type).forbiddenOwnerships,
    requiresAsset: c.requiresAsset,
    unresolvedVariable: unresolved,
  });
}

/** The declaration app.managed when the catalog does not carry it: iOS 17.2, supervised or device enrollment, or
 *  User Enrollment (section 8.3). */
const APP_MANAGED_FALLBACK = {
  type: APP_MANAGED_DECLARATION, family: 'declaration' as const, title: 'Managed app', apply: 'multiple' as const, keys: [],
  os: { iOS: { introduced: '17.2', enrollments: ['supervised' as const, 'device' as const, 'user' as const] } },
};

const facts = (d: ResolutionDevice) => ({
  platform: d.platform, osVersion: d.osVersion, mode: d.mode, supervised: d.supervised, ownership: d.ownership,
  declarationTypes: d.declarationTypes,
});

/** The scopes of a device, from the nearest. */
export function scopesOf(d: ResolutionDevice, groupAncestors: ResolutionInput['groupAncestors']):
  Array<{ scope: SourceScope; scopeId: number | null; target: string; rank: number }> {
  const out: Array<{ scope: SourceScope; scopeId: number | null; target: string; rank: number }> = [
    { scope: 'device', scopeId: d.id, target: targetKey('device', d.id), rank: RANK.device },
  ];
  if (d.groupId !== null) {
    const ancestors = groupAncestors.get(d.groupId) ?? [{ groupId: d.groupId, depth: 0 }];
    for (const g of [...ancestors].sort((a, b) => a.depth - b.depth)) {
      out.push({ scope: 'group', scopeId: g.groupId, target: targetKey('group', g.groupId), rank: RANK.groupBase + g.depth });
    }
  }
  out.push({ scope: 'tenant', scopeId: null, target: targetKey('tenant', null), rank: RANK.tenant });
  return out;
}

/** Index of the assignments by target, built once for many devices. */
export function indexAssignments(assignments: ResolutionAssignment[]): Map<string, ResolutionAssignment[]> {
  const byTarget = new Map<string, ResolutionAssignment[]>();
  for (const a of assignments) {
    const k = targetKey(a.targetScope, a.targetScope === 'tenant' ? null : a.targetId);
    const list = byTarget.get(k);
    if (list) list.push(a); else byTarget.set(k, [a]);
  }
  return byTarget;
}

/** The resolution of one device. */
export function resolveDevice(input: ResolutionInput, d: ResolutionDevice, byTarget: Map<string, ResolutionAssignment[]>): DeviceResolution {
  const scopes = scopesOf(d, input.groupAncestors);
  const matched: Array<{ a: ResolutionAssignment; scope: SourceScope; scopeId: number | null; rank: number }> = [];
  for (const s of scopes) for (const a of byTarget.get(s.target) ?? []) matched.push({ a, scope: s.scope, scopeId: s.scopeId, rank: s.rank });
  // 2. Exclusion wins over inclusion, whatever the scope of either.
  const excluded = new Set(matched.filter((m) => m.a.mode === 'exclude').map((m) => resourceKey(m.a.resourceType, m.a.resourceTenantId, m.a.resourceId)));
  // 3. Contributions of the remaining inclusions.
  const byKey = new Map<string, Candidate[]>();
  for (const m of matched) {
    if (m.a.mode !== 'include') continue;
    const rk = resourceKey(m.a.resourceType, m.a.resourceTenantId, m.a.resourceId);
    if (excluded.has(rk)) continue;
    const res = input.resources.get(rk);
    if (!res) continue;
    const contributions = res.type === 'app' && res.app ? [appContributionOf(res, m.a)] : res.contributions;
    for (const c of contributions) {
      const cand: Candidate = { c, res, a: m.a, scope: m.scope, scopeId: m.scopeId, rank: m.rank };
      const list = byKey.get(c.settingKey);
      if (list) list.push(cand); else byKey.set(c.settingKey, [cand]);
    }
  }
  // 4 to 6. Winner, conflicts, removal, availability.
  const settings: ResolvedSetting[] = [];
  for (const [settingKey, list] of byKey) {
    list.sort(compareCandidates);
    const w = list[0];
    const conflict: SettingConflictEntry[] = [];
    for (const o of list.slice(1)) {
      if (o.rank !== w.rank || o.a.priority !== w.a.priority) break;
      if (o.c.valueHash !== w.c.valueHash || o.c.removed !== w.c.removed) {
        conflict.push({ type: o.res.type, id: o.res.id, tenantId: o.res.tenantId, assignmentId: o.a.id, valueHash: o.c.valueHash });
      }
    }
    const artifactKey = w.c.artifactKey ?? (w.c.app ? appArtifactKey(w.c.app.identifier, appViaDeclaration(d, w.c.app)) : null);
    settings.push({
      settingKey,
      artifactKey,
      valueHash: w.c.valueHash,
      removed: w.c.removed,
      source: {
        type: w.res.type, id: w.res.id, tenantId: w.res.tenantId, versionId: w.res.versionId, assignmentId: w.a.id,
        scope: w.scope, scopeId: w.scopeId, rank: w.rank, priority: w.a.priority,
      },
      availability: w.c.removed ? { status: 'available' } : availabilityOf(input, d, w.c),
      conflict: conflict.length ? conflict : null,
      type: w.c.type,
      kind: w.c.kind,
      key: w.c.key,
      instance: w.c.instance,
      ...(w.c.value !== undefined && !w.c.removed ? { value: w.c.value } : {}),
      ...(w.c.app ? { app: { storeId: w.c.app.storeId } } : {}),
    });
  }
  settings.sort((x, y) => (x.settingKey < y.settingKey ? -1 : x.settingKey > y.settingKey ? 1 : 0));
  return { deviceId: d.id, settings };
}

const appContributionCache = new WeakMap<ResolutionAssignment, Contribution>();

/** An app's contribution for one assignment (its options are the value). */
function appContributionOf(res: ResolvedResource, a: ResolutionAssignment): Contribution {
  const hit = appContributionCache.get(a);
  if (hit) return hit;
  const c = appContribution(res.app!, a.options ?? {});
  appContributionCache.set(a, c);
  return c;
}

/** resolveDevices(input): the resolution of every device of the input (section 7.6). */
export function resolveDevices(input: ResolutionInput): ResolutionOutput {
  const byTarget = indexAssignments(input.assignments);
  return { tenantId: input.tenantId, devices: input.devices.map((d) => resolveDevice(input, d, byTarget)) };
}
