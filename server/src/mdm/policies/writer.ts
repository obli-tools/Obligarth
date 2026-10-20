import type { Knex } from 'knex';
import { canonicalJson } from '../../audit/canonical';
import { writeArtifacts, type DeliveryContext } from './artifacts';
import { evaluateDevices } from '../compliance/evaluate';
import { requestComplianceEvaluation } from '../apple/requests';
import type { ResolutionOutput, ResolvedSetting } from './resolver';

// =============================================================================
// The writer of a resolution (docs: modele-donnees-mdm §7.10, step 1): the
// effective state of the devices of the output, in the caller's transaction
// (one per slice of 200 devices, motif M8). A row is written only when one of
// its columns changes (computed_at says when the effective value last
// changed), the keys no longer retained are deleted. With the delivery
// context of the resolution (its devices, the tenant), the same call has the
// providers of the channels compile the artifacts, writes their desired state
// per device and the aggregate configuration state, and requests their
// delivery (steps 2 to 6: the common store, policies/artifacts.ts, lot AN-P);
// the compliance of the devices that changed follows.
// Concurrent writers of a device (a resolution of the tenant and one of the
// device) are serialised by a transaction lock per device, taken in ascending
// order before reading what is stored.
// =============================================================================

export interface WriteSummary {
  devices: number;
  upserted: number;
  deleted: number;
  /** Devices whose effective state changed. */
  changedDeviceIds: number[];
  /** Devices one of whose artifacts changed (empty without a delivery context). */
  artifactDeviceIds: number[];
}

/** Beyond this many devices changed by one write, their compliance is evaluated in the transaction, in bulk,
 *  instead of one job per device. */
const COMPLIANCE_JOBS_MAX = 50;

const COLUMNS = ['artifact_key', 'value_hash', 'removed', 'source_type', 'source_id', 'source_tenant_id', 'source_version_id',
  'source_assignment_id', 'source_scope', 'source_scope_id', 'source_rank', 'availability', 'unavailable_reason', 'conflict'] as const;
type Row = Record<(typeof COLUMNS)[number], unknown> & { tenant_id: number; device_id: number; setting_key: string };

const BATCH = 500;

/** The stored row of a retained setting. */
export function rowOf(tenantId: number, deviceId: number, s: ResolvedSetting): Row {
  const notApplicable = s.availability.status === 'not_applicable';
  return {
    tenant_id: tenantId,
    device_id: deviceId,
    setting_key: s.settingKey,
    artifact_key: s.artifactKey,
    value_hash: s.valueHash,
    removed: s.removed,
    source_type: s.source.type,
    source_id: s.source.id,
    source_tenant_id: s.source.tenantId,
    source_version_id: s.source.versionId,
    source_assignment_id: s.source.assignmentId,
    source_scope: s.source.scope,
    source_scope_id: s.source.scopeId,
    source_rank: s.source.rank,
    availability: s.availability.status,
    unavailable_reason: notApplicable ? (s.availability as { reason: string }).reason : null,
    conflict: s.conflict ? JSON.stringify(s.conflict) : null,
  };
}

/** A comparable form of a column (bigint as number, jsonb in canonical form). */
function norm(column: string, v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (column === 'conflict') return canonicalJson(typeof v === 'string' ? JSON.parse(v) : v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number' || typeof v === 'bigint') return String(Number(v));
  if (/^(source_id|source_tenant_id|source_version_id|source_assignment_id|source_scope_id|source_rank)$/.test(column)) return String(Number(v));
  return String(v).trim();
}

function differs(stored: Record<string, unknown>, next: Row): boolean {
  return COLUMNS.some((c) => norm(c, stored[c]) !== norm(c, next[c]));
}

/** Namespace of the resolution's locks (two-key advisory locks: never confused with the single-key ones). */
const RESOLVE_LOCK_SPACE = 0x4d445052;   // 'MDPR'

/** A transaction lock on each device, in ascending order (concurrent resolutions of the same device wait). */
export async function lockDevices(trx: Knex.Transaction, deviceIds: number[]): Promise<void> {
  const ids = [...new Set(deviceIds)].sort((a, b) => a - b);
  if (!ids.length) return;
  await trx.raw(`SELECT pg_advisory_xact_lock(?::integer, s.d)
                   FROM (SELECT d FROM unnest(?::integer[]) AS d ORDER BY d) AS s`, [RESOLVE_LOCK_SPACE, ids]);
}

/**
 * writeResolution(trx, tenantId, out, delivery): the effective state of the output's devices (section 7.10, step
 * 1) and, with the delivery context, their artifacts and what delivers them (steps 2 to 6).
 */
export async function writeResolution(trx: Knex.Transaction, tenantId: number, out: ResolutionOutput, delivery?: DeliveryContext): Promise<WriteSummary> {
  const deviceIds = out.devices.map((d) => d.deviceId);
  const summary: WriteSummary = { devices: deviceIds.length, upserted: 0, deleted: 0, changedDeviceIds: [], artifactDeviceIds: [] };
  if (!deviceIds.length) return summary;
  const stored = await trx('device_effective_settings').where({ tenant_id: tenantId }).whereIn('device_id', deviceIds)
    .select('device_id', 'setting_key', ...COLUMNS) as Array<Record<string, unknown> & { device_id: number; setting_key: string }>;
  const byDevice = new Map<number, Map<string, Record<string, unknown>>>();
  for (const r of stored) {
    const m = byDevice.get(Number(r.device_id)) ?? new Map<string, Record<string, unknown>>();
    m.set(String(r.setting_key), r);
    byDevice.set(Number(r.device_id), m);
  }
  const upserts: Row[] = [];
  const deletes: Array<{ deviceId: number; settingKey: string }> = [];
  const changed = new Set<number>();
  for (const d of out.devices) {
    const before = byDevice.get(d.deviceId) ?? new Map<string, Record<string, unknown>>();
    const keep = new Set<string>();
    for (const s of d.settings) {
      keep.add(s.settingKey);
      const row = rowOf(tenantId, d.deviceId, s);
      const prev = before.get(s.settingKey);
      if (!prev || differs(prev, row)) {
        upserts.push(row);
        changed.add(d.deviceId);
      }
    }
    for (const key of before.keys()) {
      if (!keep.has(key)) {
        deletes.push({ deviceId: d.deviceId, settingKey: key });
        changed.add(d.deviceId);
      }
    }
  }
  const now = new Date();
  for (let i = 0; i < upserts.length; i += BATCH) {
    const rows = upserts.slice(i, i + BATCH).map((r) => ({ ...r, computed_at: now }));
    await trx('device_effective_settings').insert(rows)
      .onConflict(['tenant_id', 'device_id', 'setting_key'])
      .merge([...COLUMNS, 'computed_at']);
  }
  for (let i = 0; i < deletes.length; i += BATCH) {
    const slice = deletes.slice(i, i + BATCH);
    await trx.raw(`DELETE FROM obligarth.device_effective_settings e
                    USING unnest(?::integer[], ?::text[]) AS k(device_id, setting_key)
                    WHERE e.tenant_id = ? AND e.device_id = k.device_id AND e.setting_key = k.setting_key`,
    [slice.map((x) => x.deviceId), slice.map((x) => x.settingKey), tenantId]);
  }
  summary.upserted = upserts.length;
  summary.deleted = deletes.length;
  summary.changedDeviceIds = [...changed].sort((a, b) => a - b);
  if (delivery) {
    // Each channel compiles the settings it claims (the android:* keys are the channel amapi's: its own policy per
    // device, pushed by android.policies.push-device, lot AN-P), never another channel's.
    summary.artifactDeviceIds = (await writeArtifacts(trx, tenantId, out, delivery)).changedDeviceIds;
    // What applies to a device, or the state of its configuration, changed: its compliance is evaluated again.
    const touched = [...new Set([...summary.changedDeviceIds, ...summary.artifactDeviceIds])];
    if (touched.length > COMPLIANCE_JOBS_MAX) await evaluateDevices(trx, tenantId, touched);
    else if (touched.length > 0) await requestComplianceEvaluation(trx, tenantId, touched);
  }
  return summary;
}
