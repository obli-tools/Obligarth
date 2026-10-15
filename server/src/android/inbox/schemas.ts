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
}).passthrough();

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
    occurredAt: bestTime(eventType, p, publishTime), payload: decoded,
  };
}
