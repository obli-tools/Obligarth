import {
  isSecretRef, parseSettingKey, settingKeysOf,
  type DeviceArtifactView, type DeviceConfigurationView, type EffectiveSettingView, type JsonValue, type PolicyContentV1,
  type SettingAvailability, type SettingConflictEntry, type SourceScope, type UnavailableReason,
} from '@obligarth/shared';
import { db } from '../../db';
import { appleCatalog } from '../apple/catalog';
import { loadDevices, loadPolicyState } from './loader';
import { indexAssignments, resolveDevice } from './resolver';

// =============================================================================
// The effective configuration of a device as the console shows it (docs:
// modele-donnees-mdm §10.6, criterion 9): for each stored key, its value read
// in the source version (never a secret: a reference shows as
// {"$secret": true}), its provenance (policy, version, scope), its
// availability with its reason, its conflicts; and the state of its artifacts
// (device_artifacts, written from the compilation on: lot B5c). In the
// device's tenant context.
// =============================================================================

const parse = <T>(v: unknown): T => (typeof v === 'string' ? JSON.parse(v) as T : v as T);

/** A value with its secret references masked. */
export function maskSecretRefs(v: JsonValue | undefined, depth = 0): JsonValue | undefined {
  if (v === undefined || depth > 64) return v;
  if (isSecretRef(v)) return { $secret: true };
  if (Array.isArray(v)) return v.map((x) => maskSecretRefs(x, depth + 1) as JsonValue);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, maskSecretRefs(x, depth + 1) as JsonValue]));
  }
  return v;
}

/** The value of a setting key in a version's content (keyed: the key's value; else the item's values). */
function valueOf(content: PolicyContentV1 | undefined, settingKey: string): JsonValue | undefined {
  if (!content) return undefined;
  const parsed = parseSettingKey(settingKey);
  if (!parsed) return undefined;
  const catalog = appleCatalog();
  for (const item of content.sections?.apple?.items ?? []) {
    if (item.type !== parsed.type) continue;
    const d = catalog.descriptor(item.type);
    if (!d) continue;
    const keys = settingKeysOf(item, d);
    if ('error' in keys) continue;
    const part = keys.parts.find((p) => p.settingKey === settingKey);
    if (part) return part.value;
  }
  return undefined;
}

export async function deviceConfiguration(tenantId: number, deviceId: number): Promise<DeviceConfigurationView> {
  const device = await db('devices').where({ tenant_id: tenantId, id: deviceId }).first('config_state') as { config_state: string } | undefined;
  const rows = await db('device_effective_settings').where({ tenant_id: tenantId, device_id: deviceId }).orderBy('setting_key')
    .select('*') as Array<Record<string, any>>;
  // Source versions (contents and numbers), names of the policies and apps, priorities of the assignments.
  const versionIds = [...new Set(rows.map((r) => r.source_version_id).filter((v) => v !== null).map(Number))];
  const versions = versionIds.length
    ? await db('policy_versions').whereIn('id', versionIds).select('id', 'version', 'content') as Array<{ id: number; version: number; content: unknown }>
    : [];
  const versionOf = new Map(versions.map((v) => [Number(v.id), { version: Number(v.version), content: parse<PolicyContentV1>(v.content) }]));
  const conflicts = rows.flatMap((r) => (r.conflict ? parse<SettingConflictEntry[]>(r.conflict) : []));
  const policyIds = [...new Set([...rows.filter((r) => r.source_type === 'policy').map((r) => Number(r.source_id)),
    ...conflicts.filter((c) => c.type === 'policy').map((c) => c.id)])];
  const appIds = [...new Set([...rows.filter((r) => r.source_type === 'app').map((r) => Number(r.source_id)),
    ...conflicts.filter((c) => c.type === 'app').map((c) => c.id)])];
  const policyNames = new Map((policyIds.length ? await db('policies').whereIn('id', policyIds).select('id', 'name') as Array<{ id: number; name: string }> : [])
    .map((p) => [Number(p.id), p.name]));
  const appNames = new Map((appIds.length ? await db('apps').whereIn('id', appIds).select('id', 'name') as Array<{ id: number; name: string }> : [])
    .map((a) => [Number(a.id), a.name]));
  const assignmentIds = [...new Set(rows.map((r) => Number(r.source_assignment_id)))];
  const priorities = new Map((assignmentIds.length ? await db('assignments').where({ tenant_id: tenantId }).whereIn('id', assignmentIds)
    .select('id', 'priority') as Array<{ id: number; priority: number }> : []).map((a) => [Number(a.id), Number(a.priority)]));
  // The details of the reasons (minimum version, variable…), from a resolution of the device in memory.
  const details = new Map<string, SettingAvailability>();
  if (rows.some((r) => r.availability === 'not_applicable')) {
    const state = await loadPolicyState(db, tenantId);
    const set = await loadDevices(db, tenantId, [deviceId]);
    if (set.devices.length) {
      const live = resolveDevice({ ...state, ...set, catalog: appleCatalog() }, set.devices[0], indexAssignments(state.assignments));
      for (const s of live.settings) details.set(s.settingKey, s.availability);
    }
  }
  const nameOf = (type: 'policy' | 'app', id: number): string | null => (type === 'policy' ? policyNames.get(id) : appNames.get(id)) ?? null;
  const settings: EffectiveSettingView[] = rows.map((r) => {
    const parsed = parseSettingKey(r.setting_key);
    const reason = r.unavailable_reason as UnavailableReason | null;
    const live = details.get(r.setting_key);
    const availability: SettingAvailability = r.availability === 'available' ? { status: 'available' }
      : { status: 'not_applicable', reason: reason as UnavailableReason,
        ...(live && live.status === 'not_applicable' && live.reason === reason && live.detail ? { detail: live.detail } : {}) };
    const v = r.source_version_id !== null ? versionOf.get(Number(r.source_version_id)) : undefined;
    const conflict = r.conflict ? parse<SettingConflictEntry[]>(r.conflict) : null;
    const value = r.source_type === 'policy' && !r.removed ? maskSecretRefs(valueOf(v?.content, r.setting_key)) : undefined;
    return {
      settingKey: r.setting_key,
      artifactKey: r.artifact_key ?? null,
      valueHash: String(r.value_hash).trim(),
      removed: !!r.removed,
      source: {
        type: r.source_type, id: Number(r.source_id), tenantId: Number(r.source_tenant_id),
        versionId: r.source_version_id === null ? null : Number(r.source_version_id), assignmentId: Number(r.source_assignment_id),
        scope: r.source_scope as SourceScope, scopeId: r.source_scope_id === null ? null : Number(r.source_scope_id),
        rank: Number(r.source_rank), priority: priorities.get(Number(r.source_assignment_id)) ?? 0,
      },
      availability,
      conflict,
      type: parsed?.type ?? '',
      key: parsed?.key ?? null,
      instance: parsed?.instance ?? null,
      ...(value !== undefined ? { value } : {}),
      sourceName: nameOf(r.source_type, Number(r.source_id)),
      sourceVersion: v?.version ?? null,
      conflictNames: (conflict ?? []).map((c) => ({ type: c.type, id: c.id, name: nameOf(c.type, c.id) })),
      computedAt: new Date(r.computed_at).toISOString(),
    };
  });
  const artifacts = (await db('device_artifacts').where({ tenant_id: tenantId, device_id: deviceId }).orderBy('artifact_key')
    .select('*') as Array<Record<string, any>>).map((a): DeviceArtifactView => ({
    artifactKey: a.artifact_key,
    channel: a.channel,
    state: a.state,
    stateReasons: parse<string[]>(a.state_reasons ?? []) ?? [],
    desiredAt: new Date(a.desired_at).toISOString(),
    deliveredAt: a.delivered_at ? new Date(a.delivered_at).toISOString() : null,
    stateAt: new Date(a.state_at).toISOString(),
    sources: parse<string[]>(a.sources ?? []) ?? [],
  }));
  return { deviceId, configState: (device?.config_state ?? 'unknown') as DeviceConfigurationView['configState'], settings, artifacts };
}
