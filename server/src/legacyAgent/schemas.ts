import { z } from 'zod';
import {
  LEGACY_AGENT_EVENT_TYPES, LEGACY_AGENT_KEY_STORAGES, LEGACY_AGENT_KNOX_STATES,
} from '@obligarth/shared';

// =============================================================================
// Strict schemas of the bodies of the agent surface (docs: agent-pont-android
// §4.4 to §4.6, §15.1 RC-7): every field bounded (sizes, counts, depth), no
// unknown key. A value the device cannot read is null, never an error (§8.7):
// most fields are nullable or optional.
// =============================================================================

const str = (max: number) => z.string().max(max);
const nstr = (max: number) => z.string().max(max).nullable().optional();
const int = (min: number, max: number) => z.number().int().min(min).max(max);
const nint = (min: number, max: number) => z.number().int().min(min).max(max).nullable().optional();
const UNIX = int(0, 4_102_444_800);                    // until 2100
const B64URL = z.string().regex(/^[A-Za-z0-9_-]+$/);

/** A small free object (detail of a result or an event): 20 keys, scalars or short strings, depth 1. */
const smallDetail = z.record(z.union([z.string().max(500), z.number(), z.boolean(), z.null()]))
  .refine((o) => Object.keys(o).length <= 20, 'detail: 20 keys at most');

export const DeviceFacts = z.object({
  manufacturer: nstr(64), brand: nstr(64), model: nstr(64), device: nstr(64),
  androidId: z.string().regex(/^[0-9a-fA-F]{1,32}$/).nullable().optional(),
  serial: nstr(64), samsungSerial: nstr(64),
  imeis: z.array(z.string().regex(/^[0-9]{14,16}$/)).max(4).optional(),
  apiLevel: nint(1, 100), osVersion: nstr(32),
  securityPatch: z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/).nullable().optional(),
  build: nstr(128), deviceName: nstr(255),
}).strict();

export const EnrollBody = z.object({
  token: str(80),
  publicKey: B64URL.max(200),
  keyStorage: z.enum(LEGACY_AGENT_KEY_STORAGES),
  attestation: z.array(z.string().max(8192)).max(6).optional(),
  agent: z.object({
    package: str(255), versionCode: int(1, 2_000_000_000), versionName: str(32),
    signerSha256: z.string().regex(/^[0-9a-fA-F]{64}$/).nullable().optional(),
  }).strict(),
  device: DeviceFacts,
  capabilities: z.object({
    adminActive: z.boolean(),
    knox: z.object({ state: z.enum(LEGACY_AGENT_KNOX_STATES), version: nstr(64), mdmApiLevel: nstr(64) }).strict(),
  }).strict(),
  hints: z.object({ deviceName: nstr(255), serial: nstr(64), imei: nstr(32) }).strict().nullable().optional(),
}).strict();
export type EnrollBody = z.infer<typeof EnrollBody>;

export const PollBody = z.object({
  agent: z.object({ versionCode: int(1, 2_000_000_000), configVersion: nint(0, 2_147_483_647) }).strict(),
  status: z.object({
    adminActive: z.boolean(),
    knoxState: z.enum(LEGACY_AGENT_KNOX_STATES),
    batteryLevel: nint(0, 100), charging: z.boolean().nullable().optional(),
    storageFreeBytes: nint(0, Number.MAX_SAFE_INTEGER),
    network: z.object({ type: nstr(16), ip: nstr(45) }).strict().nullable().optional(),
    uptimeSeconds: nint(0, Number.MAX_SAFE_INTEGER),
  }).strict(),
  results: z.array(z.object({
    commandId: z.string().uuid(),
    status: z.enum(['acknowledged', 'error', 'rejected']),
    code: z.string().regex(/^[a-z_]{1,48}$/),
    detail: smallDetail.optional(),
    at: UNIX,
  }).strict()).max(100).optional().default([]),
  events: z.array(z.object({
    type: z.enum(LEGACY_AGENT_EVENT_TYPES),
    at: UNIX,
    detail: smallDetail.optional(),
  }).strict()).max(20).optional().default([]),
}).strict();
export type PollBody = z.infer<typeof PollBody>;

export const InventoryBody = z.object({
  collectedAt: UNIX,
  device: DeviceFacts,
  storage: z.object({ totalBytes: nint(0, Number.MAX_SAFE_INTEGER), freeBytes: nint(0, Number.MAX_SAFE_INTEGER) }).strict().nullable().optional(),
  battery: z.object({ level: nint(0, 100), charging: z.boolean().nullable().optional(), health: nstr(32) }).strict().nullable().optional(),
  network: z.object({ type: nstr(16), ip: nstr(45), mac: nstr(32), ssid: nstr(64), operator: nstr(64) }).strict().nullable().optional(),
  knox: z.object({ state: z.enum(LEGACY_AGENT_KNOX_STATES), version: nstr(64), mdmApiLevel: nstr(64), error: nstr(200) }).strict(),
  admin: z.object({ active: z.boolean(), removable: z.boolean().nullable().optional() }).strict(),
  install: z.object({ unknownSources: z.boolean().nullable() }).strict().nullable().optional(),
  apps: z.array(z.object({
    package: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/).max(255),
    label: nstr(255), versionName: nstr(64), versionCode: nint(0, Number.MAX_SAFE_INTEGER),
    system: z.boolean().optional(), installer: nstr(255),
    firstInstallAt: nint(0, Number.MAX_SAFE_INTEGER), lastUpdateAt: nint(0, Number.MAX_SAFE_INTEGER),
  }).strict()).max(2000),
}).strict();
export type InventoryBody = z.infer<typeof InventoryBody>;
