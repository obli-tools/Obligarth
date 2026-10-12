import type { Knex } from 'knex';
import { POLICY_VARIABLES, type ArtifactChannel, type ArtifactState, type JsonValue } from '@obligarth/shared';
import { requestDdmRecompute } from '../../apple/ddm/engine';
import { loadDevices } from '../policies/loader';
import { variableValue, type ResolutionDevice, type ResolutionOutput } from '../policies/resolver';
import type { AppleCatalogView } from './catalog';
import { compileApple, type CompiledArtifact } from './compile';
import { renderedHash, type StoredArtifact } from './render';
import { requestArtifactReconcile } from './requests';
import { RenderError, type VariableValues } from './variables';

// =============================================================================
// The compiled artifacts of the devices of a resolution and their desired
// state (docs: modele-donnees-mdm §7.10, steps 2 to 6), in the transaction
// that wrote their effective state:
//   2. mdm_artifacts: the bodies, addressed by content (one row serves every
//      device that wants it);
//   3. device_artifacts: an artifact whose desired version changes (its hash,
//      or its rendered hash: the value of a variable of the device) goes back
//      to 'pending'; one that is no longer desired is removed from the device
//      when it was delivered or is being delivered ('removing'), else its row
//      is deleted;
//   4. devices.config_state (obligarth.device_config_rollup);
//   5. the declarations of a device changed: its DDM set is computed again;
//   6. a profile or a setting changed: the reconciliation of the device.
// Order of the locks, for every writer of device_artifacts: the open targets
// of the device's policy commands (the reconciliation), the row of the device,
// then the rows of its artifacts. A status report, an inventory answer and a
// command result all hold the device's row before they reach an artifact.
// A setting has no removal (the Settings command sets a value, nothing unsets
// it): a setting no longer desired is simply 'removed'.
// =============================================================================

export interface DeliveryContext {
  devices: ResolutionDevice[];
  tenant: { name: string; slug: string };
  catalog: AppleCatalogView;
}

export interface ArtifactRow {
  tenant_id: number;
  device_id: number;
  artifact_key: string;
  channel: ArtifactChannel;
  desired_hash: string | null;
  rendered_hash: string | null;
  sources: unknown;
  desired_at: Date;
  delivered_hash: string | null;
  delivered_at: Date | null;
  state: ArtifactState;
  state_reasons: unknown;
  state_at: Date;
  last_command_id: string | null;
}

export interface ArtifactWriteSummary {
  /** Bodies compiled for the devices of the output (distinct hashes). */
  artifacts: number;
  /** Devices one of whose artifacts changed. */
  changedDeviceIds: number[];
  ddmDeviceIds: number[];
  commandDeviceIds: number[];
}

/** Reasons of an artifact that was never sent: what the compilation or the rendering refused. */
export const COMPILE_REASON_PREFIXES = ['compile:', 'render:'] as const;

const parseJson = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  if (typeof v !== 'string') return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};

export const reasonsOf = (row: Pick<ArtifactRow, 'state_reasons'>): string[] => {
  const r = parseJson<unknown>(row.state_reasons, []);
  return Array.isArray(r) ? r.filter((x): x is string => typeof x === 'string') : [];
};

export const sourcesOf = (row: Pick<ArtifactRow, 'sources'>): string[] => {
  const r = parseJson<unknown>(row.sources, []);
  return Array.isArray(r) ? r.filter((x): x is string => typeof x === 'string') : [];
};

/** An artifact in error because it could not be compiled or rendered: nothing to send again until it changes. */
export function isCompileError(row: Pick<ArtifactRow, 'state' | 'state_reasons'>): boolean {
  return row.state === 'error' && reasonsOf(row).some((r) => COMPILE_REASON_PREFIXES.some((p) => r.startsWith(p)));
}

export const hashOf = (v: string | null | undefined): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);

/** The columns of an artifact found removed from its device: nothing of it is delivered any more. */
export const REMOVED = { state: 'removed', state_reasons: '[]', delivered_hash: null, delivered_at: null } as const;

/** The values of the variables for a device (those that have one). */
export function variablesFor(d: ResolutionDevice, tenant: { name: string; slug: string }): VariableValues {
  const out: VariableValues = {};
  for (const name of POLICY_VARIABLES) {
    const v = variableValue(name, d, tenant);
    if (v !== null) out[name] = v;
  }
  return out;
}

/** The rows of devices of the tenant, locked in ascending order (before any of their artifacts). */
export async function lockDeviceRows(trx: Knex.Transaction, tenantId: number, deviceIds: number[]):
  Promise<Array<{ id: number; config_state: string; enrollment_state: string }>> {
  const ids = [...new Set(deviceIds)].sort((a, b) => a - b);
  if (ids.length === 0) return [];
  const rows = await trx('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [ids]).orderBy('id').forUpdate()
    .select('id', 'config_state', 'enrollment_state') as Array<{ id: number; config_state: string; enrollment_state: string }>;
  return rows.map((r) => ({ ...r, id: Number(r.id) }));
}

/** devices.config_state of devices from the state of their artifacts (every writer of device_artifacts calls it). */
export async function rollupConfigState(trx: Knex.Transaction, deviceIds: number[]): Promise<void> {
  const ids = [...new Set(deviceIds)];
  if (ids.length) await trx.raw('SELECT obligarth.device_config_rollup(?::integer[])', [ids]);
}

/** A stored artifact as the rendering reads it. */
export function storedArtifactOf(r: { channel: string; artifact_type: string; identifier: string; body: unknown; encrypt: boolean }): StoredArtifact {
  return {
    channel: r.channel as ArtifactChannel, artifactType: r.artifact_type, identifier: r.identifier,
    body: parseJson<Record<string, JsonValue>>(r.body, {}), encrypt: r.encrypt === true,
  };
}

/** What a delivery needs to render for one device: the device as the resolution reads it, the values of its
 *  variables. null: the device is not under management in the tenant. Reads only. */
export async function loadRenderContext(trx: Knex | Knex.Transaction, tenantId: number, deviceId: number):
  Promise<{ device: ResolutionDevice; vars: VariableValues } | null> {
  const set = await loadDevices(trx, tenantId, [deviceId]);
  const device = set.devices[0];
  if (!device) return null;
  const t = await trx('tenants').where({ id: tenantId }).first('name', 'slug') as { name: string; slug: string } | undefined;
  return { device, vars: variablesFor(device, { name: t?.name ?? '', slug: t?.slug ?? '' }) };
}

const sameList = (a: string[], b: string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
const BATCH = 500;

/**
 * Steps 2 to 6 of the writing of a resolution for the devices of `out` (already resolved and written in `trx`).
 * The devices' rows are locked here; the caller holds the resolution lock of each device.
 */
export async function writeArtifacts(trx: Knex.Transaction, tenantId: number, out: ResolutionOutput, ctx: DeliveryContext): Promise<ArtifactWriteSummary> {
  const summary: ArtifactWriteSummary = { artifacts: 0, changedDeviceIds: [], ddmDeviceIds: [], commandDeviceIds: [] };
  const deviceIds = out.devices.map((d) => d.deviceId);
  if (deviceIds.length === 0) return summary;
  const facts = new Map(ctx.devices.map((d) => [d.id, d]));

  // Compilation, in memory: the artifacts of each device, their rendered hash (one per artifact when it has no
  // variable, else one per device).
  const bodies = new Map<string, CompiledArtifact>();
  const plainRendered = new Map<string, string | RenderError>();
  const wanted = new Map<number, Map<string, { a: CompiledArtifact; rendered: string | null; problems: string[] }>>();
  for (const d of out.devices) {
    const device = facts.get(d.deviceId);
    // A device the context does not describe is left as it is (never emptied for lack of facts).
    if (!device) continue;
    const mine = new Map<string, { a: CompiledArtifact; rendered: string | null; problems: string[] }>();
    wanted.set(d.deviceId, mine);
    let vars: VariableValues | null = null;
    for (const a of compileApple(d.settings, ctx.catalog, { organization: ctx.tenant.name })) {
      if (!bodies.has(a.hash)) bodies.set(a.hash, a);
      const problems = [...a.problems];
      let rendered: string | null = null;
      if (problems.length === 0) {
        const stored: StoredArtifact = { channel: a.channel, artifactType: a.artifactType, identifier: a.identifier, body: a.body, encrypt: a.encrypt };
        let r: string | RenderError | undefined = a.hasVariables ? undefined : plainRendered.get(a.hash);
        if (r === undefined) {
          try {
            r = renderedHash(stored, a.hasVariables ? (vars ??= variablesFor(device, ctx.tenant)) : {});
          } catch (err) {
            if (!(err instanceof RenderError)) throw err;
            r = err;
          }
          if (!a.hasVariables) plainRendered.set(a.hash, r);
        }
        if (r instanceof RenderError) problems.push(`render:${r.code}`);
        else rendered = r;
      }
      mine.set(a.artifactKey, { a, rendered, problems });
    }
  }
  summary.artifacts = bodies.size;

  const locked = await lockDeviceRows(trx, tenantId, deviceIds);
  const existing = await trx('device_artifacts').where({ tenant_id: tenantId }).whereRaw('device_id = ANY (?::int[])', [deviceIds])
    .orderBy(['device_id', 'artifact_key']).forUpdate().select('*') as ArtifactRow[];
  const byDevice = new Map<number, Map<string, ArtifactRow>>();
  for (const r of existing) {
    const m = byDevice.get(Number(r.device_id)) ?? new Map<string, ArtifactRow>();
    m.set(r.artifact_key, r);
    byDevice.set(Number(r.device_id), m);
  }

  // 2. The bodies, addressed by content.
  const hashes = [...bodies.keys()];
  if (hashes.length) {
    const known = new Set((await trx('mdm_artifacts').where({ tenant_id: tenantId }).whereIn('hash', hashes).pluck('hash') as string[]).map((h) => h.trim()));
    const fresh = hashes.filter((h) => !known.has(h)).map((h) => bodies.get(h)!);
    for (let i = 0; i < fresh.length; i += 100) {
      await trx('mdm_artifacts').insert(fresh.slice(i, i + 100).map((a) => ({
        tenant_id: tenantId, hash: a.hash, channel: a.channel, artifact_type: a.artifactType, identifier: a.identifier,
        body: JSON.stringify(a.body), secret_refs: trx.raw('?::uuid[]', [a.secretRefs]), has_variables: a.hasVariables, encrypt: a.encrypt,
      }))).onConflict(['tenant_id', 'hash']).ignore();
    }
  }

  // 3. The desired state of each device.
  const now = new Date();
  const upserts: Array<Record<string, unknown>> = [];
  const sourcesOnly: Array<Record<string, unknown>> = [];
  const removing: Array<{ deviceId: number; key: string; state: 'removing' | 'removed' }> = [];
  const deleting: Array<{ deviceId: number; key: string }> = [];
  const changed = new Set<number>();
  const ddm = new Set<number>();
  const command = new Set<number>();
  const touch = (deviceId: number, channel: string): void => {
    changed.add(deviceId);
    if (channel === 'ddm') ddm.add(deviceId);
    else if (channel === 'profile' || channel === 'setting') command.add(deviceId);
  };
  for (const d of out.devices) {
    const mine = wanted.get(d.deviceId);
    if (!mine) continue;
    const before = byDevice.get(d.deviceId) ?? new Map<string, ArtifactRow>();
    for (const [key, w] of mine) {
      const row = before.get(key);
      const base = { tenant_id: tenantId, device_id: d.deviceId, artifact_key: key, channel: w.a.channel, desired_hash: w.a.hash,
        sources: JSON.stringify(w.a.sources) };
      if (w.problems.length > 0) {
        // Recorded, never sent: the artifact is in error until what it is made of changes.
        const same = row && row.state === 'error' && hashOf(row.desired_hash) === w.a.hash && sameList(reasonsOf(row), w.problems);
        if (!same) {
          upserts.push({ ...base, rendered_hash: null, desired_at: now, state: 'error', state_reasons: JSON.stringify(w.problems), state_at: now });
          touch(d.deviceId, w.a.channel);
        }
        continue;
      }
      const again = !row || hashOf(row.desired_hash) !== w.a.hash || hashOf(row.rendered_hash) !== w.rendered
        || row.state === 'removing' || row.state === 'removed' || isCompileError(row);
      if (again) {
        upserts.push({ ...base, rendered_hash: w.rendered, desired_at: now, state: 'pending', state_reasons: '[]', state_at: now });
        touch(d.deviceId, w.a.channel);
      } else if (!sameList(sourcesOf(row), w.a.sources)) {
        sourcesOnly.push({ ...base, rendered_hash: w.rendered });
      }
    }
    for (const [key, row] of before) {
      // The apps have their own writer (lot C4).
      if (mine.has(key) || row.channel === 'app' || row.state === 'removing' || row.state === 'removed') continue;
      if (row.desired_hash === null) continue;          // an error left by a removal: the reconciliation's
      const onDevice = row.delivered_hash !== null || row.state === 'delivering';
      if (!onDevice) deleting.push({ deviceId: d.deviceId, key });
      else removing.push({ deviceId: d.deviceId, key, state: row.channel === 'setting' ? 'removed' : 'removing' });
      touch(d.deviceId, row.channel);
    }
  }
  const mergeAll = ['channel', 'desired_hash', 'rendered_hash', 'sources', 'desired_at', 'state', 'state_reasons', 'state_at'];
  for (let i = 0; i < upserts.length; i += BATCH) {
    await trx('device_artifacts').insert(upserts.slice(i, i + BATCH)).onConflict(['tenant_id', 'device_id', 'artifact_key']).merge(mergeAll);
  }
  for (let i = 0; i < sourcesOnly.length; i += BATCH) {
    await trx('device_artifacts').insert(sourcesOnly.slice(i, i + BATCH)).onConflict(['tenant_id', 'device_id', 'artifact_key']).merge(['sources']);
  }
  for (let i = 0; i < removing.length; i += BATCH) {
    const s = removing.slice(i, i + BATCH);
    await trx.raw(`
      UPDATE obligarth.device_artifacts a
         SET desired_hash = NULL, rendered_hash = NULL, sources = '[]'::jsonb, state = k.state, state_reasons = '[]'::jsonb, state_at = ?,
             delivered_hash = CASE WHEN k.state = 'removed' THEN NULL ELSE a.delivered_hash END,
             delivered_at = CASE WHEN k.state = 'removed' THEN NULL ELSE a.delivered_at END
        FROM unnest(?::integer[], ?::text[], ?::text[]) AS k(device_id, artifact_key, state)
       WHERE a.tenant_id = ? AND a.device_id = k.device_id AND a.artifact_key = k.artifact_key`,
    [now, s.map((x) => x.deviceId), s.map((x) => x.key), s.map((x) => x.state), tenantId]);
  }
  for (let i = 0; i < deleting.length; i += BATCH) {
    const s = deleting.slice(i, i + BATCH);
    await trx.raw(`
      DELETE FROM obligarth.device_artifacts a
       USING unnest(?::integer[], ?::text[]) AS k(device_id, artifact_key)
       WHERE a.tenant_id = ? AND a.device_id = k.device_id AND a.artifact_key = k.artifact_key`,
    [s.map((x) => x.deviceId), s.map((x) => x.key), tenantId]);
  }

  // 4. The aggregate state: the devices whose artifacts changed, and those resolved for the first time.
  await rollupConfigState(trx, [...new Set([...changed, ...locked.filter((r) => r.config_state === 'unknown').map((r) => r.id)])]);

  // 5 and 6. What delivers the change.
  summary.changedDeviceIds = [...changed].sort((a, b) => a - b);
  summary.ddmDeviceIds = [...ddm].sort((a, b) => a - b);
  summary.commandDeviceIds = [...command].sort((a, b) => a - b);
  if (summary.ddmDeviceIds.length) await requestDdmRecompute(trx, tenantId, { deviceIds: summary.ddmDeviceIds });
  if (summary.commandDeviceIds.length) await requestArtifactReconcile(trx, tenantId, summary.commandDeviceIds);
  return summary;
}
