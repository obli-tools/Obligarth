// Catalogue of the guarded actions (docs: audit-durci §10.2) and the
// providers the modules plug in: the size of a tenant's active fleet, the
// ownership of its devices, the freeze of its commands at apple-edge.
// Registered before anything starts (index.ts: the modules' registration),
// no I/O.
import { isActionKey, registerRestrictableActions } from '../services/restriction.service';
import type {
  EdgeFreezeHandler, FleetSizeProvider, GuardedActionDef, OwnershipProvider,
} from './types';

const FAMILIES = new Set(['device_records', 'device_destruction', 'device_control', 'device_privacy']);
const LEVELS = new Set(['sensitive', 'restricted']);
const OWNERSHIPS = new Set(['personal', 'corporate_personal', 'corporate']);

const actions = new Map<string, GuardedActionDef<any>>();
let fleetSizeProvider: FleetSizeProvider | null = null;
let ownershipProvider: OwnershipProvider | null = null;
let edgeFreezeHandler: EdgeFreezeHandler | null = null;

const isDelay = (n: unknown): boolean => Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 86_400;

/**
 * Declares a guarded action; also registers it as a restrictable action of
 * the matrix, with its single floor (never lowered by a tenant's matrix;
 * a batch is always 'restricted', computed per request). Throws on an
 * invalid definition or a duplicate: a defect of the code, at start.
 */
export function registerGuardedAction<P>(def: GuardedActionDef<P>): void {
  const key = String(def?.key ?? '');
  const fail = (m: string): never => { throw new Error(`guarded action ${JSON.stringify(key)}: ${m}`); };
  if (!isActionKey(key)) fail('invalid key');
  if (actions.has(key)) fail('registered twice');
  if (typeof def.label !== 'string' || !def.label.trim() || def.label.length > 200) fail('an English label is required');
  if (!FAMILIES.has(def.family)) fail(`unknown family ${String(def.family)}`);
  if (!LEVELS.has(def.singleFloor)) fail('singleFloor must be sensitive or restricted');
  if (def.defaultLevel !== undefined && !LEVELS.has(def.defaultLevel)) fail('defaultLevel must be sensitive or restricted');
  if (!Number.isInteger(def.bulkThreshold) || def.bulkThreshold < 2 || def.bulkThreshold > 3) {
    fail('bulkThreshold is 3 (D23), 2 at the strictest');
  }
  if (!isDelay(def.singleDelaySeconds) || !isDelay(def.bulkDelaySeconds)) fail('delays are integers from 0 to 86400 seconds');
  if (def.bulkDelaySeconds < def.singleDelaySeconds) fail('the bulk delay is never shorter than the single one');
  if (!Array.isArray(def.refuseOwnership) || !def.refuseOwnership.every((o) => OWNERSHIPS.has(o))) fail('invalid refuseOwnership');
  if (def.confirmation !== 'typed' && def.confirmation !== 'none') fail('confirmation is typed or none');
  if (def.hourlyCap && def.family !== 'device_destruction') fail('only the family device_destruction has an hourly cap (MVP)');
  if (!def.paramsSchema || typeof (def.paramsSchema as { safeParse?: unknown }).safeParse !== 'function') fail('paramsSchema (zod) is required');
  if (typeof def.revalidate !== 'function' || typeof def.execute !== 'function') fail('revalidate and execute are required');
  registerRestrictableActions(
    [{ key, label: def.label.trim(), category: def.category ?? 'Guarded actions' }],
    def.defaultLevel ? { [key]: def.defaultLevel } : {},
    { [key]: { level: def.singleFloor, strictStepUp: def.singleStrictStepUp === true } },
  );
  actions.set(key, Object.freeze({ ...def }) as GuardedActionDef<any>);
}

export function guardedActionDef(key: string): GuardedActionDef<any> | undefined {
  return actions.get(key);
}

export function guardedActionList(): GuardedActionDef<any>[] {
  return [...actions.values()];
}

/** The size of a tenant's active fleet: the managed devices of the tenant
 *  (lot B), until then every device (modules/devices.ts). One provider. */
export function registerFleetSizeProvider(fn: FleetSizeProvider): void {
  if (fleetSizeProvider) throw new Error('fleet size provider registered twice');
  fleetSizeProvider = fn;
}

export function fleetSizeOf(): FleetSizeProvider | null {
  return fleetSizeProvider;
}

/** The ownership of devices (lot B, devices.ownership). One provider. */
export function registerOwnershipProvider(fn: OwnershipProvider): void {
  if (ownershipProvider) throw new Error('ownership provider registered twice');
  ownershipProvider = fn;
}

export function ownershipOf(): OwnershipProvider | null {
  return ownershipProvider;
}

/** The freeze of a tenant's commands at apple-edge (lot B). One handler;
 *  without one (APPLE_EDGE_MODE=off, lot A), the freeze stays in the brain. */
export function registerEdgeFreezeHandler(fn: EdgeFreezeHandler): void {
  if (edgeFreezeHandler) throw new Error('edge freeze handler registered twice');
  edgeFreezeHandler = fn;
}

export function edgeFreezeOf(): EdgeFreezeHandler | null {
  return edgeFreezeHandler;
}
