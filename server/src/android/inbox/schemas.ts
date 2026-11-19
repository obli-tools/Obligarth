// Schemas of the notification payloads (zod, NOT strict: AMAPI adds fields every month, but bounded: lengths, array
// sizes) and the classification of a Pub/Sub message: event type, enterprise, resource, best time. Pure (zod only):
// unit tests U-A04 under node --test.
import { z } from 'zod';

export const ANDROID_EVENT_TYPES = [
  'amapi.enrollment', 'amapi.status_report', 'amapi.command', 'amapi.usage_logs', 'amapi.enterprise_upgrade',
  'amapi.oversized', 'amapi.unknown',
] as const;
export type AndroidEventType = (typeof ANDROID_EVENT_TYPES)[number];

const NOTIFICATION_TO_EVENT: Record<string, AndroidEventType> = {
  ENROLLMENT: 'amapi.enrollment',
  STATUS_REPORT: 'amapi.status_report',
  COMMAND: 'amapi.command',
  USAGE_LOGS: 'amapi.usage_logs',
  ENTERPRISE_UPGRADE: 'amapi.enterprise_upgrade',
};

const str = (max: number) => z.string().max(max);
const time = z.string().max(40).refine((s) => Number.isFinite(Date.parse(s)), 'not a timestamp');
const deviceName = z.string().max(255).regex(/^enterprises\/[A-Za-z0-9_-]{1,100}\/devices\/[A-Za-z0-9_-]{1,100}$/);
const operationName = z.string().max(255)
  .regex(/^enterprises\/[A-Za-z0-9_-]{1,100}\/devices\/[A-Za-z0-9_-]{1,100}\/operations\/[A-Za-z0-9_-]{1,100}$/);

export const DeviceSchema = z.object({
  name: deviceName,
  managementMode: str(40).optional(),
  state: str(40).optional(),
  appliedState: str(40).optional(),
  ownership: str(40).optional(),
  policyName: str(255).optional(),
  appliedPolicyName: str(255).optional(),
  appliedPolicyVersion: str(40).optional(),
  enrollmentTime: time.optional(),
  lastStatusReportTime: time.optional(),
  lastPolicySyncTime: time.optional(),
  enrollmentTokenName: str(255).optional(),
  enrollmentTokenData: str(1024).optional(),
  previousDeviceNames: z.array(str(255)).max(100).optional(),
  apiLevel: z.number().int().min(0).max(1000).optional(),
  applicationReports: z.array(z.object({}).passthrough()).max(2000).optional(),
  nonComplianceDetails: z.array(z.object({}).passthrough()).max(2000).optional(),
}).passthrough();

export const OperationSchema = z.object({
  name: operationName,
  done: z.boolean().optional(),
  metadata: z.object({ type: str(40).optional(), createTime: time.optional() }).passthrough().optional(),
  error: z.object({ code: z.number().int().optional(), message: str(2000).optional() }).passthrough().optional(),
}).passthrough();

export const UsageLogsSchema = z.object({
  device: deviceName,
  usageLogEvents: z.array(z.object({ eventType: str(80).optional(), eventTime: time.optional() }).passthrough()).max(5000).optional(),
  /** Set by reduceUsageLogs: the events of the batch that were neither of the lost mode nor read by a detection. */
  otherEventCount: z.number().int().min(0).max(10_000_000).optional(),
}).passthrough();

// ── Reduction of the USAGE_LOGS batches before the inbox (Obliwatch lot L5, SEC-13) ──────────────────────────────
// Once the security logs are on (integrations/obliwatch/securityLogs.ts), a batch mixes the events of the lost mode with
// high-volume security events (process starts, shell commands, certificates…). The inbox never keeps those: a batch is
// reduced at intake, before it is written, whatever the switch of the integration says:
//   - the events of the lost mode are kept whole (their handler reads them; first, so no cap reaches them before the
//     others), 500 at most;
//   - the events a detection reads keep their type, their time and the one boolean the classifier reads
//     (certAuthorityInstalledEvent.success, keyguardDismissAuthAttemptEvent.success), 4,500 at most;
//   - every other event is only counted (otherEventCount): never its fields (no shell command, no certificate subject,
//     no package, no uid).
// The reduced batch is always within the schema's cap (5,000 events), so a large batch never goes dead for its size.
export const USAGE_LOG_LOST_MODE_TYPES: ReadonlySet<string> = new Set(['LOST_MODE_LOCATION', 'STOP_LOST_MODE_USER_ATTEMPT', 'LOST_MODE_OUTGOING_PHONE_CALL']);
const SECURITY_KEPT: Readonly<Record<string, string | null>> = {
  CERT_AUTHORITY_INSTALLED: 'certAuthorityInstalledEvent',
  KEYGUARD_DISMISS_AUTH_ATTEMPT: 'keyguardDismissAuthAttemptEvent',
  ADB_SHELL_COMMAND: null,
  ADB_SHELL_INTERACTIVE: null,
  KEY_INTEGRITY_VIOLATION: null,
  LOGGING_STOPPED: null,
};
const MAX_LOST_MODE_KEPT = 500;
const MAX_SECURITY_KEPT = 4_500;

/** A USAGE_LOGS payload reduced to what the handlers read (see above). Pure; any other shape is returned as is. */
export function reduceUsageLogs(decoded: unknown): unknown {
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) return decoded;
  const p = decoded as Record<string, unknown>;
  const events = Array.isArray(p.usageLogEvents) ? p.usageLogEvents : [];
  const lost: unknown[] = [];
  const kept: Array<Record<string, unknown>> = [];
  let other = typeof p.otherEventCount === 'number' && Number.isSafeInteger(p.otherEventCount) && p.otherEventCount >= 0 ? p.otherEventCount : 0;
  for (const raw of events) {
    const e = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
    const type = typeof e.eventType === 'string' ? e.eventType : '';
    if (USAGE_LOG_LOST_MODE_TYPES.has(type)) {
      if (lost.length < MAX_LOST_MODE_KEPT) lost.push(raw);
      continue;
    }
    if (type in SECURITY_KEPT && kept.length < MAX_SECURITY_KEPT) {
      const r: Record<string, unknown> = { eventType: type };
      if (typeof e.eventTime === 'string') r.eventTime = e.eventTime;
      const field = SECURITY_KEPT[type];
      if (field) {
        const inner = e[field];
        const success = inner && typeof inner === 'object' && (inner as Record<string, unknown>).success === true;
        r[field] = success ? { success: true } : {};
      }
      kept.push(r);
      continue;
    }
    other++;
  }
  return {
    ...(typeof p.device === 'string' ? { device: p.device } : {}),
    usageLogEvents: [...lost, ...kept],
    ...(other > 0 ? { otherEventCount: other } : {}),
  };
}

export const EnterpriseUpgradeSchema = z.object({
  enterprise: z.string().max(128).regex(/^enterprises\/[A-Za-z0-9_-]{1,100}$/),
  upgradeState: str(60).optional(),
}).passthrough();

export const OversizedSchema = z.object({ type: str(48), resource_name: str(255).nullable() }).strict();

export const PAYLOAD_SCHEMAS: Record<Exclude<AndroidEventType, 'amapi.unknown'>, z.ZodTypeAny> = {
  'amapi.enrollment': DeviceSchema,
  'amapi.status_report': DeviceSchema,
  'amapi.command': OperationSchema,
  'amapi.usage_logs': UsageLogsSchema,
  'amapi.enterprise_upgrade': EnterpriseUpgradeSchema,
  'amapi.oversized': OversizedSchema,
};

export interface ClassifiedMessage {
  /** 'test' messages are never written; 'unparsable': no enterprise could be extracted. */
  kind: 'test' | 'event' | 'unparsable';
  eventType: AndroidEventType;
  enterpriseName: string | null;
  resourceName: string | null;
  occurredAt: Date;
  payload: unknown;
}

const ENTERPRISE_HEAD = /^(enterprises\/[A-Za-z0-9_-]{1,100})(\/|$)/;
const head = (s: unknown): string | null => (typeof s === 'string' && s.length <= 400 ? ENTERPRISE_HEAD.exec(s)?.[1] ?? null : null);

function bestTime(type: AndroidEventType, p: Record<string, unknown>, publishTime: Date): Date {
  const pick = (v: unknown) => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? new Date(v) : null);
  if (type === 'amapi.status_report') return pick(p.lastStatusReportTime) ?? publishTime;
  if (type === 'amapi.enrollment') return pick(p.enrollmentTime) ?? publishTime;
  if (type === 'amapi.command') return pick((p.metadata as Record<string, unknown> | undefined)?.createTime) ?? publishTime;
  if (type === 'amapi.usage_logs' && Array.isArray(p.usageLogEvents)) {
    const ts = p.usageLogEvents.map((e) => pick((e as Record<string, unknown>)?.eventTime)?.getTime() ?? 0);
    const max = Math.max(0, ...ts);
    return max > 0 ? new Date(max) : publishTime;
  }
  return publishTime;
}

/**
 * Classifies a decoded message. `decoded`: the JSON of `data` (null when not JSON). The enterprise is extracted from
 * the resource (Device, Operation, BatchUsageLogEvents.device, EnterpriseUpgradeEvent.enterprise).
 */
export function classifyMessage(notificationType: string | undefined, decoded: unknown, publishTime: Date): ClassifiedMessage {
  if (notificationType === 'test') {
    return { kind: 'test', eventType: 'amapi.unknown', enterpriseName: null, resourceName: null, occurredAt: publishTime, payload: null };
  }
  const eventType: AndroidEventType = (notificationType && NOTIFICATION_TO_EVENT[notificationType]) || 'amapi.unknown';
  const p = (decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : {}) as Record<string, unknown>;
  let resource: string | null = null;
  let enterprise: string | null = null;
  if (typeof p.name === 'string') { resource = p.name; enterprise = head(p.name); }
  else if (typeof p.device === 'string') { resource = p.device; enterprise = head(p.device); }
  else if (typeof p.enterprise === 'string') { resource = p.enterprise; enterprise = head(p.enterprise); }
  if (!enterprise) {
    return { kind: 'unparsable', eventType, enterpriseName: null, resourceName: null, occurredAt: publishTime, payload: null };
  }
  return {
    kind: 'event', eventType, enterpriseName: enterprise, resourceName: resource && resource.length <= 255 ? resource : null,
    occurredAt: bestTime(eventType, p, publishTime), payload: eventType === 'amapi.usage_logs' ? reduceUsageLogs(decoded) : decoded,
  };
}
