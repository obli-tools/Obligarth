import type { Knex } from 'knex';
import type { ArtifactState, JsonValue } from '@obligarth/shared';
import type { ResolutionDevice, ResolutionOutput, ResolvedSetting } from './resolver';

// =============================================================================
// The common store of the artifacts of a resolution (docs: modele-donnees-mdm
// §7.10, steps 2 to 6; android-amapi §22.6, COH-2, lot AN-P), in the
// transaction that wrote the effective state of the devices:
//   2. mdm_artifacts: the bodies, addressed by content (one row serves every
//      device that wants it);
//   3. device_artifacts: an artifact whose desired version changes (its hash,
//      or its rendered hash: the value of a variable of the device) goes back
//      to 'pending'; one that is no longer desired is removed from the device
//      when it was delivered or is being delivered ('removing', or 'removed'
//      for a channel without removal), else its row is deleted;
//   4. devices.config_state (obligarth.device_config_rollup);
//   5. what delivers the change: the hook of the provider of each channel
//      (onDesiredChanged), in the same transaction.
// The compilation belongs to the providers of the channels
// (registerArtifactChannel): Apple delivers the channels profile, ddm, app and
// setting (mdm/apple/artifacts.ts), Android the channel amapi (its own policy
// per device). A provider receives the settings it claims (claimsSetting; the
// provider without it takes every setting no other provider claims) of the
// devices it serves (servesDevice), and returns their artifacts. A setting goes
// to the provider of its artifact's channel (none when that channel's module is
// not loaded: an Android key never reaches the Apple compiler).
// Order of the locks, for every writer of device_artifacts: the open targets
// of the device's policy commands (the reconciliation), the row of the device,
// then the rows of its artifacts. A status report, an inventory answer and a
// command result all hold the device's row before they reach an artifact.
// =============================================================================

export interface ArtifactRow {
  tenant_id: number;
  device_id: number;
  artifact_key: string;
  channel: string;
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

/** What a delivery needs beyond the resolution: the devices as the resolution read them and the tenant. It carries
 *  no catalogue of a platform (COH-2): a provider reads its own. */
export interface DeliveryContext {
  devices: ResolutionDevice[];
  tenant: { name: string; slug: string };
  /** The tenant of the devices (set by writeArtifacts): a provider tells its own settings from a library's. */
  tenantId?: number;
}

/** One artifact a device wants, as a provider compiled it. */
export interface ChannelArtifact {
  artifactKey: string;
  channel: string;
  artifactType: string;
  identifier: string;
  body: Record<string, JsonValue>;
  /** SHA-256 (hex) of the body: the address of mdm_artifacts. */
  hash: string;
  secretRefs: string[];
  hasVariables: boolean;
  encrypt: boolean;
  /** Setting keys that produced the artifact (device_artifacts.sources). */
  sources: string[];
  /** The hash of the artifact as rendered for this device (null when it could not be rendered). */
  rendered: string | null;
  /** Why the artifact cannot be delivered as compiled or rendered (codes, never a value); empty: deliverable. */
  problems: string[];
}

/** A device given to a provider: its facts and the settings the provider claims. */
export interface ChannelDevice {
  device: ResolutionDevice;
  settings: ResolvedSetting[];
}

/** The change of the desired state of the devices, per channel (devices one of whose artifacts of that channel was
 *  written, removed or deleted). */
export interface DesiredChange {
  byChannel: ReadonlyMap<string, number[]>;
}

export interface ArtifactChannelProvider {
  /** Name of the provider (logs, registration). */
  name: string;
  /** The channels it delivers (the prefix of their artifact keys). */
  channels: readonly string[];
  /** The settings it compiles; absent: every setting no other provider claims (one such provider at most). */
  claimsSetting?(settingKey: string): boolean;
  /** The devices it serves; absent: every device. */
  servesDevice?(device: ResolutionDevice): boolean;
  /** The artifacts of each device given (in memory, no I/O). A device absent from the result wants nothing. */
  compile(devices: ChannelDevice[], ctx: DeliveryContext): Map<number, ChannelArtifact[]>;
  /** After the desired state is written and before the aggregate state: `wanted` lists, per device, the keys of
   *  the provider's artifacts it wants (the licence gate of the Apple apps). */
  beforeRollup?(trx: Knex.Transaction, tenantId: number, wanted: ReadonlyMap<number, string[]>): Promise<void>;
  /** What delivers the change, in the caller's transaction (jobs sent in it): called with the devices one of whose
   *  artifacts of the provider's channels changed, ascending. */
  onDesiredChanged(trx: Knex.Transaction, tenantId: number, deviceIds: number[], change: DesiredChange): Promise<void>;
  /** A channel whose artifact is never removed from a device (a setting has no removal: 'removed' at once). */
  removedAtOnce?(channel: string): boolean;
}

const providers: ArtifactChannelProvider[] = [];

/** Registers the provider of one or more channels (at the registration of a module, before anything runs). */
export function registerArtifactChannel(p: ArtifactChannelProvider): void {
  if (!/^[a-z][a-z0-9_.-]{0,40}$/.test(p.name)) throw new Error('artifact channel provider: invalid name');
  if (providers.some((x) => x.name === p.name)) throw new Error(`artifact channel provider ${p.name}: registered twice`);
  for (const c of p.channels) {
    if (!/^[a-z]{1,12}$/.test(c)) throw new Error(`artifact channel ${c}: invalid`);
    if (providers.some((x) => x.channels.includes(c))) throw new Error(`artifact channel ${c}: two providers`);
  }
  if (!p.claimsSetting && providers.some((x) => !x.claimsSetting)) throw new Error('artifact channel provider: one default provider at most');
  providers.push(p);
}

/** The registered providers, in registration order. */
export function artifactChannelProviders(): readonly ArtifactChannelProvider[] {
  return providers;
}

/** The provider of a channel, if any. */
export function providerOfChannel(channel: string): ArtifactChannelProvider | null {
  return providers.find((p) => p.channels.includes(channel)) ?? null;
}

/** Reasons of an artifact that was never sent: what the compilation or the rendering refused. */
export const COMPILE_REASON_PREFIXES = ['compile:', 'render:'] as const;

export const parseJson = <T>(v: unknown, fallback: T): T => {
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

export interface ArtifactWriteSummary {
  /** Bodies compiled for the devices of the output (distinct hashes). */
  artifacts: number;
  /** Devices one of whose artifacts changed. */
  changedDeviceIds: number[];
  /** Devices one of whose artifacts changed, per channel. */
  byChannel: Map<string, number[]>;
}

const sameList = (a: string[], b: string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
const BATCH = 500;
const sorted = (s: Iterable<number>): number[] => [...s].sort((a, b) => a - b);

/**
 * The settings of a device given to each provider: by the channel of their artifact (the provider of that channel; a
 * channel no provider delivers: nobody, as when its module is not loaded), else the provider that claims the setting,
 * else the default provider.
 */
function partition(settings: ResolvedSetting[]): Map<ArtifactChannelProvider, ResolvedSetting[]> {
  const out = new Map<ArtifactChannelProvider, ResolvedSetting[]>(providers.map((p) => [p, []]));
  const fallback = providers.find((p) => !p.claimsSetting) ?? null;
  for (const s of settings) {
    const sep = typeof s.artifactKey === 'string' ? s.artifactKey.indexOf(':') : -1;
    const owner = sep > 0 ? providerOfChannel(s.artifactKey!.slice(0, sep))
      : providers.find((p) => p.claimsSetting?.(s.settingKey)) ?? fallback;
    if (owner) out.get(owner)!.push(s);
  }
  return out;
}

/**
 * Steps 2 to 6 of the writing of a resolution for the devices of `out` (already resolved and written in `trx`).
 * The devices' rows are locked here; the caller holds the resolution lock of each device.
 */
export async function writeArtifacts(trx: Knex.Transaction, tenantId: number, out: ResolutionOutput, ctx: DeliveryContext): Promise<ArtifactWriteSummary> {
  const summary: ArtifactWriteSummary = { artifacts: 0, changedDeviceIds: [], byChannel: new Map() };
  const deviceIds = out.devices.map((d) => d.deviceId);
  if (deviceIds.length === 0) return summary;
  const facts = new Map(ctx.devices.map((d) => [d.id, d]));

  // Compilation, in memory, by each provider for the devices it serves.
  const inputs = new Map<ArtifactChannelProvider, ChannelDevice[]>(providers.map((p) => [p, []]));
  const described = new Set<number>();
  for (const d of out.devices) {
    const device = facts.get(d.deviceId);
    // A device the context does not describe is left as it is (never emptied for lack of facts).
    if (!device) continue;
    described.add(d.deviceId);
    for (const [p, settings] of partition(d.settings)) {
      if (!p.servesDevice || p.servesDevice(device)) inputs.get(p)!.push({ device, settings });
    }
  }
  const bodies = new Map<string, ChannelArtifact>();
  const wanted = new Map<number, Map<string, ChannelArtifact>>();
  for (const id of described) wanted.set(id, new Map());
  const wantedByProvider = new Map<ArtifactChannelProvider, Map<number, string[]>>();
  for (const p of providers) {
    const list = inputs.get(p)!;
    const keys = new Map<number, string[]>();
    wantedByProvider.set(p, keys);
    if (!list.length) continue;
    const compiled = p.compile(list, { ...ctx, tenantId });
    for (const [deviceId, artifacts] of compiled) {
      const mine = wanted.get(deviceId);
      if (!mine) continue;
      const k: string[] = [];
      for (const a of artifacts) {
        if (!p.channels.includes(a.channel) || !a.artifactKey.startsWith(`${a.channel}:`)) {
          throw new Error(`artifact channel provider ${p.name}: artifact ${a.artifactKey} out of its channels`);
        }
        if (!bodies.has(a.hash)) bodies.set(a.hash, a);
        mine.set(a.artifactKey, a);
        k.push(a.artifactKey);
      }
      keys.set(deviceId, k);
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
  const byChannel = new Map<string, Set<number>>();
  const touch = (deviceId: number, channel: string): void => {
    changed.add(deviceId);
    const s = byChannel.get(channel) ?? new Set<number>();
    s.add(deviceId);
    byChannel.set(channel, s);
  };
  for (const d of out.devices) {
    const mine = wanted.get(d.deviceId);
    if (!mine) continue;
    const before = byDevice.get(d.deviceId) ?? new Map<string, ArtifactRow>();
    for (const [key, w] of mine) {
      const row = before.get(key);
      const base = { tenant_id: tenantId, device_id: d.deviceId, artifact_key: key, channel: w.channel, desired_hash: w.hash,
        sources: JSON.stringify(w.sources) };
      if (w.problems.length > 0) {
        // Recorded, never sent: the artifact is in error until what it is made of changes.
        const same = row && row.state === 'error' && hashOf(row.desired_hash) === w.hash && sameList(reasonsOf(row), w.problems);
        if (!same) {
          upserts.push({ ...base, rendered_hash: null, desired_at: now, state: 'error', state_reasons: JSON.stringify(w.problems), state_at: now });
          touch(d.deviceId, w.channel);
        }
        continue;
      }
      const again = !row || hashOf(row.desired_hash) !== w.hash || hashOf(row.rendered_hash) !== w.rendered
        || row.state === 'removing' || row.state === 'removed' || isCompileError(row);
      if (again) {
        upserts.push({ ...base, rendered_hash: w.rendered, desired_at: now, state: 'pending', state_reasons: '[]', state_at: now });
        touch(d.deviceId, w.channel);
      } else if (!sameList(sourcesOf(row), w.sources)) {
        sourcesOnly.push({ ...base, rendered_hash: w.rendered });
      }
    }
    for (const [key, row] of before) {
      if (mine.has(key) || row.state === 'removing' || row.state === 'removed') continue;
      if (row.desired_hash === null) continue;          // an error left by a removal: the reconciliation's
      const onDevice = row.delivered_hash !== null || row.state === 'delivering';
      if (!onDevice) deleting.push({ deviceId: d.deviceId, key });
      else removing.push({ deviceId: d.deviceId, key, state: providerOfChannel(row.channel)?.removedAtOnce?.(row.channel) ? 'removed' : 'removing' });
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

  // What a provider does with the wanted state before the aggregate (the licences of the Apple apps, section 8.3).
  for (const p of providers) {
    const keys = wantedByProvider.get(p)!;
    if (p.beforeRollup && keys.size) await p.beforeRollup(trx, tenantId, keys);
  }

  // 4. The aggregate state: the devices whose artifacts changed, and those resolved for the first time.
  await rollupConfigState(trx, [...new Set([...changed, ...locked.filter((r) => r.config_state === 'unknown').map((r) => r.id)])]);

  // 5. What delivers the change: each provider for its channels.
  summary.changedDeviceIds = sorted(changed);
  for (const [c, s] of byChannel) summary.byChannel.set(c, sorted(s));
  for (const p of providers) {
    const mineByChannel = new Map<string, number[]>();
    const ids = new Set<number>();
    for (const c of p.channels) {
      const s = summary.byChannel.get(c);
      if (!s?.length) continue;
      mineByChannel.set(c, s);
      for (const id of s) ids.add(id);
    }
    if (ids.size) await p.onDesiredChanged(trx, tenantId, sorted(ids), { byChannel: mineByChannel });
  }
  return summary;
}
