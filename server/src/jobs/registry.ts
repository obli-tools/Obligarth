import { z } from 'zod';
import type { JobDefinition, JobPolicy, JobRetry, RegisteredJob } from './types';

// =============================================================================
// Registry of the jobs: each module declares its jobs (registerJob) before the
// start; the definitions are validated here (rules below), their defaults
// resolved, and the registry is frozen by jobs.start(). A rule that fails
// throws: the server does not start.
// =============================================================================

/** Owning modules: the first segment of a queue name. A new module is added here. */
export const JOB_MODULES: readonly string[] = [
  'core', 'jobs', 'devices', 'reports', 'apple-edge', 'apple', 'mdm', 'vpp', 'integrations', 'privacy', 'audit',
  'actions', 'enrollment', 'alerts', 'vault', 'tenants', 'restore', 'notifications', 'maintenance',
  // Lot AN-A2 (android-amapi §3.4): the queues of the Android module, registered only when ANDROID_MODE is not off.
  'android',
  // The Android bridge agent (agent-pont-android §6).
  'legacy-agent',
];

/** The shared dead letter queue (no worker). */
export const DEAD_LETTER_QUEUE = 'jobs.dead-letter';
/**
 * Polling of a scheduled housekeeping queue woken by NOTIFY (`notify: true`), in seconds. The budget of the server at
 * rest is 5 statements per second (file-durable L3), and a queue polled every 15 s (the default of a scheduled
 * job) costs a statement every 15 s whether it has work or not: with some sixty queues the budget was spent (review
 * of lot B4, INT-B4-R12). An occurrence is announced when the cron pass sends it and starts at once; the poll only
 * picks up what a notification missed (JOBS_LISTEN_NOTIFY=false, a connection cut) and the retries, a minute late
 * at most, for work no one waits for (hourly and daily sweeps, purges, snapshots).
 */
export const SCHEDULED_POLL_SECONDS = 60;

/** Queue names: `<module>.<name>[.<name>…]`, at most 62 characters (the
 *  database actor j:<queue> of the runs, db/context.ts). */
export const QUEUE_NAME_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+){1,3}$/;
export const QUEUE_NAME_MAX = 62;

/** singletonKey: internal identifiers only (never a UDID, a serial number,
 *  an e-mail nor a name). */
export const SINGLETON_KEY_RE = /^[A-Za-z0-9_.:/-]{1,100}$/;

/** Field names that suggest a secret, refused at any depth of a payload
 *  schema unless reviewed (reviewedFieldNames). */
export const SECRET_FIELD_RE = /(secret|passw|token|apikey|api_key|private|pem|p12|pkcs|unlock|bootstrap|credential|otp|totp|cookie|session)/i;

const POLICIES: ReadonlySet<string> = new Set(['standard', 'exclusive', 'stately', 'singleton', 'short', 'key_strict_fifo']);

export class JobRegistrationError extends Error {
  constructor(name: string, message: string) {
    super(`job ${JSON.stringify(name)}: ${message}`);
    this.name = 'JobRegistrationError';
  }
}

/** How often a 5-field cron expression fires, as far as the defaults care:
 *  every minute (minute field '*'), at most hourly (one fixed minute), or
 *  several times an hour. pg-boss checks the whole expression at the sync. */
export function cronCadence(cron: string): 'minute' | 'hourly_or_less' | 'sub_hourly' {
  const fields = cron.trim().split(/\s+/);
  if (fields.length !== 5) throw new Error('a schedule takes a 5-field cron expression');
  const minute = fields[0];
  if (minute === '*' || minute === '*/1') return 'minute';
  if (/^[0-9]{1,2}$/.test(minute)) return 'hourly_or_less';
  return 'sub_hourly';
}

/** Every object key of a zod schema, at any depth (objects, arrays,
 *  optionals, nullables, defaults, unions, records, effects). */
function fieldNames(schema: z.ZodTypeAny, out: string[] = [], seen = new Set<z.ZodTypeAny>()): string[] {
  if (!schema || seen.has(schema)) return out;
  seen.add(schema);
  const def = (schema as { _def?: Record<string, unknown> })._def ?? {};
  if (schema instanceof z.ZodObject) {
    for (const [k, v] of Object.entries(schema.shape as Record<string, z.ZodTypeAny>)) {
      out.push(k);
      fieldNames(v, out, seen);
    }
    return out;
  }
  for (const key of ['innerType', 'type', 'schema', 'valueType', 'keyType', 'left', 'right', 'in', 'out']) {
    const inner = def[key];
    if (inner && typeof inner === 'object' && '_def' in (inner as object)) fieldNames(inner as z.ZodTypeAny, out, seen);
  }
  const options = def.options;
  if (Array.isArray(options)) for (const o of options) fieldNames(o as z.ZodTypeAny, out, seen);
  if (options instanceof Map) for (const o of options.values()) fieldNames(o as z.ZodTypeAny, out, seen);
  const items = def.items;
  if (Array.isArray(items)) for (const o of items) fieldNames(o as z.ZodTypeAny, out, seen);
  return out;
}

/** Does `schema` accept exactly the positive integers as tenantId? */
function isTenantIdSchema(schema: z.ZodTypeAny | undefined): boolean {
  if (!schema) return false;
  return schema.safeParse(1).success && schema.safeParse(2_147_483_647).success
    && !schema.safeParse(0).success && !schema.safeParse(-1).success && !schema.safeParse(1.5).success
    && !schema.safeParse('1').success && !schema.safeParse(null).success && !schema.safeParse(undefined).success;
}

const isInt = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n);

/** Validates a definition and resolves its defaults (rules of the module
 *  header, docs: file-durable §5.3 and §5.4). Throws JobRegistrationError. */
export function resolveDefinition(def: JobDefinition<z.ZodTypeAny>): RegisteredJob {
  const name = String(def?.name ?? '');
  const fail = (message: string): never => { throw new JobRegistrationError(name, message); };

  // 1. name, module, reserved names
  if (!QUEUE_NAME_RE.test(name) || name.length > QUEUE_NAME_MAX) {
    fail(`invalid queue name (<module>.<name>, lower case, digits, hyphens, at most ${QUEUE_NAME_MAX} characters)`);
  }
  const module = name.split('.')[0];
  if (!JOB_MODULES.includes(module)) fail(`unknown module "${module}" (registry.ts JOB_MODULES)`);
  if (name === DEAD_LETTER_QUEUE || name.startsWith('__pgboss')) fail('reserved queue name');
  if (def.scope !== 'platform' && def.scope !== 'tenant') fail('scope must be "platform" or "tenant"');
  if (typeof def.description !== 'string' || def.description.trim() === '' || def.description.length > 200) {
    fail('a description of one line (200 characters at most) is required');
  }
  if (typeof def.handler !== 'function') fail('handler missing');

  // 2. strict object payload
  const schema = def.payload;
  if (!(schema instanceof z.ZodObject) || (schema._def as { unknownKeys?: string }).unknownKeys !== 'strict') {
    fail('payload must be a z.object({...}).strict() schema');
  }
  const shape = (schema as z.ZodObject<z.ZodRawShape>).shape as Record<string, z.ZodTypeAny>;

  // 3. tenantId and scope
  if (def.scope === 'tenant' && !isTenantIdSchema(shape.tenantId)) {
    fail('a tenant job has a tenantId field: z.number().int().positive()');
  }
  if (def.scope === 'platform' && 'tenantId' in shape) fail('a platform job has no tenantId field');

  // 6. no secret-looking field name, at any depth
  const reviewed = new Set((def.reviewedFieldNames ?? []).map(String));
  for (const field of fieldNames(schema)) {
    if (SECRET_FIELD_RE.test(field) && !reviewed.has(field)) {
      fail(`field "${field}" looks like a secret: a payload carries identifiers only (or list it in reviewedFieldNames once reviewed)`);
    }
  }

  // 4. schedule
  let cadence: ReturnType<typeof cronCadence> | null = null;
  if (def.schedule) {
    if (typeof def.schedule.cron !== 'string') fail('schedule.cron must be a cron expression');
    try {
      cadence = cronCadence(def.schedule.cron);
    } catch (err) {
      fail((err as Error).message);
    }
    if (def.schedule.missed !== undefined && def.schedule.missed !== 'once' && def.schedule.missed !== 'skip') {
      fail('schedule.missed must be "once" or "skip"');
    }
    if (def.schedule.tz !== undefined && (typeof def.schedule.tz !== 'string' || def.schedule.tz.trim() === '')) {
      fail('schedule.tz must be an IANA time zone');
    }
  }
  const scheduled = cadence !== null;
  const perMinute = cadence === 'minute';

  const policy: JobPolicy = def.policy ?? (scheduled ? 'exclusive' : 'standard');
  if (!POLICIES.has(policy)) fail(`unknown policy "${policy}"`);
  if (scheduled && !['exclusive', 'stately', 'singleton'].includes(policy)) {
    fail('a scheduled job needs the policy exclusive, stately or singleton');
  }
  const scheduleData = def.schedule?.data ?? {};
  if (scheduled && !schema.safeParse(scheduleData).success) fail('schedule.data is refused by the payload schema');

  // 5. runAtStart
  const runAtStart = def.runAtStart === true;
  if (runAtStart) {
    if (policy !== 'exclusive' && policy !== 'stately') fail('runAtStart needs the policy exclusive or stately');
    if (!schema.safeParse(scheduleData).success) fail('runAtStart: the start payload (schedule.data or {}) is refused by the schema');
  }

  // 7. bounds
  const retryDefaults: JobRetry = scheduled
    ? { limit: perMinute ? 0 : 2, delaySeconds: 60, backoff: true, maxDelaySeconds: 900 }
    : { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 3_600 };
  const retry: JobRetry = { ...retryDefaults, ...(def.retry ?? {}) };
  if (!isInt(retry.limit) || retry.limit < 0 || retry.limit > 10) fail('retry.limit must be an integer from 0 to 10');
  if (!isInt(retry.delaySeconds) || retry.delaySeconds < 0) fail('retry.delaySeconds must be an integer >= 0');
  if (typeof retry.backoff !== 'boolean') fail('retry.backoff must be a boolean');
  if (retry.maxDelaySeconds !== undefined && (!isInt(retry.maxDelaySeconds) || retry.maxDelaySeconds < 0)) {
    fail('retry.maxDelaySeconds must be an integer >= 0');
  }
  if (!retry.backoff) delete retry.maxDelaySeconds;

  const timeoutSeconds = def.timeoutSeconds ?? 300;
  if (!isInt(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 86_400) fail('timeoutSeconds must be an integer from 1 to 86400');
  const heartbeatSeconds = def.heartbeatSeconds ?? null;
  if (heartbeatSeconds !== null && (!isInt(heartbeatSeconds) || heartbeatSeconds < 10 || heartbeatSeconds >= timeoutSeconds)) {
    fail('heartbeatSeconds must be an integer >= 10 and below timeoutSeconds');
  }
  const pollSeconds = def.pollSeconds ?? (scheduled ? 15 : 2);
  if (typeof pollSeconds !== 'number' || !Number.isFinite(pollSeconds) || pollSeconds < 0.5) fail('pollSeconds must be >= 0.5');
  const local = def.concurrency?.local ?? 1;
  if (!isInt(local) || local < 1 || local > 8) fail('concurrency.local must be an integer from 1 to 8');
  const perTenant = def.concurrency?.perTenant ?? (def.scope === 'tenant' ? 1 : null);
  if (perTenant !== null && (!isInt(perTenant) || perTenant < 1 || perTenant > 8)) {
    fail('concurrency.perTenant must be an integer from 1 to 8');
  }
  const keepFinishedSeconds = def.keepFinishedSeconds ?? (scheduled ? (perMinute ? 86_400 : 172_800) : 604_800);
  const keepPendingSeconds = def.keepPendingSeconds ?? (scheduled ? 86_400 : 2_592_000);
  for (const [k, v, min] of [['keepFinishedSeconds', keepFinishedSeconds, 1], ['keepPendingSeconds', keepPendingSeconds, 1]] as const) {
    if (!isInt(v) || v < min || v > 31_536_000) fail(`${k} must be an integer from ${min} to 31536000`);
  }

  // 8. dead letters, redrive
  const deadLetter = def.deadLetter ?? !scheduled;
  const redrivable = def.redrivable ?? true;
  if (!redrivable && !deadLetter) fail('redrivable: false requires deadLetter: true (the job must stay visible)');

  const trackStatus = def.trackStatus ?? (scheduled ? 'queue' : 'none');
  if (!['queue', 'tenant', 'none'].includes(trackStatus)) fail('trackStatus must be "queue", "tenant" or "none"');
  if (trackStatus === 'tenant' && def.scope !== 'tenant') fail('trackStatus "tenant" needs a tenant job');
  const alertAfterFailures = def.alertAfterFailures ?? 3;
  if (!isInt(alertAfterFailures) || alertAfterFailures < 1 || alertAfterFailures > 100) {
    fail('alertAfterFailures must be an integer from 1 to 100');
  }

  return Object.freeze({
    name,
    module,
    scope: def.scope,
    description: def.description,
    payload: schema,
    policy,
    retry: Object.freeze(retry),
    timeoutSeconds,
    heartbeatSeconds,
    keepFinishedSeconds,
    keepPendingSeconds,
    schedule: def.schedule && cadence
      ? Object.freeze({
        cron: def.schedule.cron.trim(),
        tz: def.schedule.tz ?? 'UTC',
        missed: def.schedule.missed ?? (cadence === 'hourly_or_less' ? 'once' : 'skip'),
        data: scheduleData,
      })
      : null,
    runAtStart,
    pollSeconds,
    notify: def.notify === true,
    concurrency: Object.freeze({ local, perTenant }),
    deadLetter,
    redrivable,
    trackStatus,
    alertAfterFailures,
    manualRun: def.manualRun ?? scheduled,
    warningQueueSize: scheduled ? 10 : 1_000,
    handler: def.handler as RegisteredJob['handler'],
  });
}

/** The definitions of one runtime. */
export class JobRegistry {
  private readonly defs = new Map<string, RegisteredJob>();
  private frozen = false;

  register(def: JobDefinition<z.ZodTypeAny>): RegisteredJob {
    if (this.frozen) throw new JobRegistrationError(String(def?.name), 'registered after jobs.start(): register every job before the start');
    const job = resolveDefinition(def);
    if (this.defs.has(job.name)) throw new JobRegistrationError(job.name, 'registered twice');
    this.defs.set(job.name, job);
    return job;
  }

  get(name: string): RegisteredJob | undefined {
    return this.defs.get(name);
  }

  list(): RegisteredJob[] {
    return [...this.defs.values()];
  }

  freeze(): void {
    this.frozen = true;
  }

  isFrozen(): boolean {
    return this.frozen;
  }
}
