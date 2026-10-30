import { z } from 'zod';
import {
  AGENT_POLICY_ITEM_STATES, AGENT_POLICY_REPORT_STATES, LEGACY_AGENT_EVENT_TYPES, LEGACY_AGENT_KEY_STORAGES, LEGACY_AGENT_KNOX_STATES, REMOTE_AGENT_END_REASONS, REMOTE_MODES,
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
  // A slot whose identifier is not a decimal IMEI (a CDMA MEID in hexadecimal, a placeholder) is dropped, never a
  // 400 that would stop the enrollment of the device for good (§8.7: an unreadable value is null, never an error).
  imeis: z.array(z.string().max(32)).max(4).transform((list) => list.filter((v) => /^[0-9]{14,16}$/.test(v))).optional(),
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
    // P0-15 §8 (agent 1.1.0 and later): the measured capability of the control, Knox RemoteInjection held and
    // instantiable (status item agent.remote.inject); absent: unchanged.
    remoteInject: z.boolean().nullable().optional(),
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
  // Agent 1.3.0 (lot PONT-POL §8.4): the compliance report of its policy, parsed apart (PolicyReport): a report the server
  // refuses never costs the poll.
  policy: z.unknown().optional(),
}).strict();
export type PollBody = z.infer<typeof PollBody>;

/** The compliance report of an agent policy (lot PONT-POL §8.4), in the poll body of an agent 1.3.0 or later. */
export const PolicyReport = z.object({
  /** null: the agent holds no policy. */
  hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  state: z.enum(AGENT_POLICY_REPORT_STATES),
  appliedAt: UNIX,
  knoxState: z.enum(LEGACY_AGENT_KNOX_STATES),
  items: z.array(z.object({
    // UTF-8 SSIDs and spaces admitted, no control character.
    key: z.string().max(160).regex(/^agent:[^\u0000-\u001f\u007f]{1,154}$/u),
    state: z.enum(AGENT_POLICY_ITEM_STATES),
    code: z.string().regex(/^[a-z_]{1,48}$/),
    detail: z.string().max(160).optional(),
  }).strict()).max(200),
}).strict();
export type PolicyReport = z.infer<typeof PolicyReport>;

export const InventoryBody = z.object({
  collectedAt: UNIX,
  device: DeviceFacts,
  storage: z.object({ totalBytes: nint(0, Number.MAX_SAFE_INTEGER), freeBytes: nint(0, Number.MAX_SAFE_INTEGER) }).strict().nullable().optional(),
  battery: z.object({ level: nint(0, 100), charging: z.boolean().nullable().optional(), health: nstr(32) }).strict().nullable().optional(),
  network: z.object({ type: nstr(16), ip: nstr(45), mac: nstr(32), ssid: nstr(64), operator: nstr(64) }).strict().nullable().optional(),
  knox: z.object({
    state: z.enum(LEGACY_AGENT_KNOX_STATES), version: nstr(64), mdmApiLevel: nstr(64), error: nstr(200),
    remoteInject: z.boolean().nullable().optional(),
  }).strict(),
  admin: z.object({ active: z.boolean(), removable: z.boolean().nullable().optional() }).strict(),
  install: z.object({ unknownSources: z.boolean().nullable() }).strict().nullable().optional(),
  apps: z.array(z.object({
    package: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/).max(255),
    label: nstr(255), versionName: nstr(64), versionCode: nint(0, Number.MAX_SAFE_INTEGER),
    system: z.boolean().optional(), launchable: z.boolean().optional(), installer: nstr(255),
    firstInstallAt: nint(0, Number.MAX_SAFE_INTEGER), lastUpdateAt: nint(0, Number.MAX_SAFE_INTEGER),
  }).strict()).max(2000),
}).strict();
export type InventoryBody = z.infer<typeof InventoryBody>;

/** The base64 (standard alphabet, padded) of a PNG of 32 KiB at most: 43 692 characters. */
const PNG_B64 = z.string().max(43_692).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);

/** POST /agent/v1/icons: the icons the server asked for (iconsWanted), 16 per request; exactly one of png (the
 *  rendered icon), none (the app has no icon) or failed (the agent cannot render it: the lease ends, this device is
 *  not asked again for a while). */
export const IconsBody = z.object({
  icons: z.array(z.object({
    package: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/).max(255),
    versionCode: int(0, Number.MAX_SAFE_INTEGER),
    png: PNG_B64.optional(),
    none: z.literal(true).optional(),
    failed: z.literal(true).optional(),
  }).strict().refine((i) => [i.png, i.none, i.failed].filter((v) => v !== undefined).length === 1, 'png, none or failed, exactly one'))
    .min(1).max(16),
}).strict();
export type IconsBody = z.infer<typeof IconsBody>;

// ── Remote assistance (P0-15 §4.3; §0.1: nothing is asked of the user of the device) ──

/** POST /agent/v1/remote/<id>/accept: the agent takes the session. consentedMode is the mode asked (view when it cannot
 *  inject), consentedAt the time it took it (the names of the contract); what it measured. */
export const RemoteAcceptBody = z.object({
  consentedAt: UNIX,
  consentedMode: z.enum(REMOTE_MODES),
  capabilities: z.object({
    inject: z.boolean(), remoteInject: z.boolean(),
    codecs: z.array(z.enum(['h264', 'jpeg'])).min(1).max(2).refine((c) => new Set(c).size === c.length, 'codecs: each once'),
    width: int(1, 16_384), height: int(1, 16_384),
    /** Informative (§0.1 rule 2): blocked notifications refuse nothing. */
    notificationsEnabled: z.boolean(),
    overlay: z.boolean(),
  }).strict(),
}).strict();
export type RemoteAcceptBody = z.infer<typeof RemoteAcceptBody>;

/** POST /agent/v1/remote/<id>/end: the end from the device's side. */
export const RemoteEndBody = z.object({ reason: z.enum(REMOTE_AGENT_END_REASONS) }).strict();
export type RemoteEndBody = z.infer<typeof RemoteEndBody>;

/** POST /agent/v1/wait: a random nonce, given back in the signed answer (16 bytes in base64url: 22 characters). */
export const WaitBody = z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/) }).strict();
export type WaitBody = z.infer<typeof WaitBody>;
