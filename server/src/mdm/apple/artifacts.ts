import type { Knex } from 'knex';
import { POLICY_VARIABLES, type ArtifactChannel, type JsonValue } from '@obligarth/shared';
import { requestDdmRecompute } from '../../apple/ddm/engine';
import { loadDevices } from '../policies/loader';
import { variableValue, type ResolutionDevice } from '../policies/resolver';
import type { ArtifactChannelProvider, ChannelArtifact } from '../policies/artifacts';
import { appleCatalog } from './catalog';
import { compileApple } from './compile';
import { renderedHash, type StoredArtifact } from './render';
import { requestArtifactReconcile } from './requests';
import { RenderError, type VariableValues } from './variables';

// =============================================================================
// The provider of the Apple channels of the common artifact store (docs:
// modele-donnees-mdm §7.10; android-amapi §22.6, COH-2, lot AN-P): profile,
// ddm, app and setting, compiled by compileApple with the Apple catalogue it
// reads itself (the delivery context carries none), rendered per device (the
// values of its variables). The store (mdm/policies/artifacts.ts) writes the
// bodies, the desired state and the aggregate state; this provider then:
//   - before the aggregate: an app (lot C4) waits for its licence: the licence
//     gate registered by the delivery of the apps (mdm/apps/licensing.ts) puts
//     its artifact 'pending' with the reason license_pending (or
//     'not_applicable', license_unavailable) and asks Apps and Books for the
//     licence, in the same transaction;
//   - the declarations of a device changed: its DDM set is computed again;
//   - a profile, a setting or an app changed: the reconciliation of the device.
// A setting has no removal (the Settings command sets a value, nothing unsets
// it): a setting no longer desired is simply 'removed'.
// It is the default provider: it takes every setting no other provider claims
// (the android:* keys are the channel amapi's), for every device (unchanged
// since before the generalisation, lot AN-P).
// =============================================================================

// The common helpers, kept here for the Apple modules that import them.
export {
  COMPILE_REASON_PREFIXES, REMOVED, hashOf, isCompileError, lockDeviceRows, reasonsOf, rollupConfigState, sourcesOf,
  type ArtifactRow, type DeliveryContext,
} from '../policies/artifacts';

const parseJson = <T>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined) return fallback;
  if (typeof v !== 'string') return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};

/** The values of the variables for a device (those that have one). */
export function variablesFor(d: ResolutionDevice, tenant: { name: string; slug: string }): VariableValues {
  const out: VariableValues = {};
  for (const name of POLICY_VARIABLES) {
    const v = variableValue(name, d, tenant);
    if (v !== null) out[name] = v;
  }
  return out;
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

/** The licence gate of the apps (section 8.3): called with the devices one of whose app artifacts was written. */
export type AppLicenseGate = (trx: Knex.Transaction, tenantId: number, deviceIds: number[]) => Promise<void>;
let licenseGate: AppLicenseGate | null = null;
export function registerAppLicenseGate(fn: AppLicenseGate): void { licenseGate = fn; }

/** Is this artifact an app's (its command, or its declaration app.managed)? */
export const isAppArtifactKey = (key: string): boolean => key.startsWith('app:') || key.startsWith('ddm:obg.cfg.pol-app.managed.');

/** The channels of the Apple provider whose change the reconciliation of the device delivers (by commands). */
const COMMAND_CHANNELS = ['profile', 'setting', 'app'] as const;

/** The provider of the Apple channels (registered by registerMdmModule). */
export const appleArtifactProvider: ArtifactChannelProvider = {
  name: 'apple',
  channels: ['profile', 'ddm', 'app', 'setting'],
  // The devices of the channel apple_mdm only (review AN-P): an app without declared platforms, or any Apple
  // setting the resolution finds available, never becomes an Apple artifact of a device of the channel amapi or of
  // the bridge agent (its aggregate state, the licences of the apps, the reconciliation). A device without a channel
  // (the fictitious device of an enrollment profile) is Apple's.
  servesDevice: (d) => d.channel === undefined || d.channel === 'apple_mdm',
  removedAtOnce: (channel) => channel === 'setting',
  compile(devices, ctx) {
    const catalog = appleCatalog();
    const out = new Map<number, ChannelArtifact[]>();
    // The rendered hash: one per artifact when it has no variable, else one per device.
    const plainRendered = new Map<string, string | RenderError>();
    for (const { device, settings } of devices) {
      const mine: ChannelArtifact[] = [];
      out.set(device.id, mine);
      let vars: VariableValues | null = null;
      for (const a of compileApple(settings, catalog, { organization: ctx.tenant.name, device: { ownership: device.ownership, mode: device.mode } })) {
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
        mine.push({ ...a, rendered, problems });
      }
    }
    return out;
  },
  async beforeRollup(trx, tenantId, wanted) {
    const apps: number[] = [];
    for (const [deviceId, keys] of wanted) if (keys.some(isAppArtifactKey)) apps.push(deviceId);
    if (apps.length && licenseGate) await licenseGate(trx, tenantId, apps.sort((a, b) => a - b));
  },
  async onDesiredChanged(trx, tenantId, _deviceIds, change) {
    const ddm = change.byChannel.get('ddm') ?? [];
    const command = [...new Set(COMMAND_CHANNELS.flatMap((c) => change.byChannel.get(c) ?? []))].sort((a, b) => a - b);
    if (ddm.length) await requestDdmRecompute(trx, tenantId, { deviceIds: ddm });
    if (command.length) await requestArtifactReconcile(trx, tenantId, command);
  },
};
