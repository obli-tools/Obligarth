import type { Knex } from 'knex';
import { z } from 'zod';
import { jobIdFor, registerJob, type JobContext, type JobHandle, type JobResult } from '../../jobs';
import { sanitizeError } from '../../jobs/errors';
import {
  ingestCertificateList, ingestDeviceInformation, ingestInstalledApplicationList, ingestManagedApplicationList, ingestProfileList,
  ingestSecurityInfo,
} from '../../mdm/inventory/ingestors';
import { logger } from '../../utils/logger';
import { resolveInTx } from '../alerts/service';
import { onTargetFinal as registerTargetFinalHook, type TargetFinalContext } from './targets';

// =============================================================================
// Ingestion of the results of the MDM commands (docs: integration-apple-edge
// §7.6; modele-donnees-mdm §5.3, §10.4): one ingestor per request type,
// registered before jobs.start() (the Apple module, the sister specifications:
// DeclarativeManagement by the DDM engine, DeviceLocation by the lost mode).
// The handler of mdm.command_result calls ingestCommandResult when a target of
// a command of the brain reaches 'acknowledged' (or 'error' for an ingestor
// that asks for it):
//   inline    in the event's savepoint (50 ms at most: one row);
//   deferred  the result copied to apple_command_results_inbox (personal data:
//             deleted once ingested) and the job apple.command-result-ingest
//             sent (id = event id), which applies it in the tenant's
//             transaction (large lists).
// A result older than the Authenticate of the device's current enrollment
// cycle (given before the device was erased and enrolled again, consumed late)
// is never ingested: its target only takes its state (§7.3).
// The ingestors write the tables of the data model through its contract
// (mdm/inventory/ingestors.ts: privacy rules, monotony by kind, a serial
// number never taken from another record). The MVP ingestors are registered
// here: DeviceInformation and SecurityInfo, ActivationLockBypassCode (a
// reference to the secret kept by apple-edge, never the code) and
// DeviceConfigured inline; the application, profile and certificate lists
// deferred. A non-personal summary of a result (counts) goes to
// mdm_command_targets.result_summary (summarizers, 4 KiB at most).
// =============================================================================

export type AppleCommandStatus = 'Acknowledged' | 'Error' | 'CommandFormatError' | 'NotNow';

export interface ResultIngestContext {
  trx: Knex.Transaction;                // tenant context already set
  tenantId: number;
  deviceId: number;
  commandId: string;
  status: AppleCommandStatus;
  /** apple-edge's converted result, envelope removed (CommandUUID, Status, UDID, ErrorChain…: outbox SplitResult). */
  result: Record<string, unknown>;
  occurredAt: Date;
}

export interface CommandResultIngestor {
  requestType: string;
  /** inline: in the event's savepoint (≤ 50 ms). deferred: copied to apple_command_results_inbox, applied by
   *  apple.command-result-ingest (large lists). */
  mode: 'inline' | 'deferred';
  /** Only Acknowledged results are ingested unless set. */
  alsoOnError?: boolean;
  apply(ctx: ResultIngestContext): Promise<void>;
}

export type ResultSummary = Record<string, string | number | boolean>;
export type ResultSummarizer = (result: Record<string, unknown>) => ResultSummary | null;

const ingestors = new Map<string, CommandResultIngestor>();
const summarizers = new Map<string, ResultSummarizer>();
const REQUEST_TYPE_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
/** Largest summary kept (bytes of its JSON). */
const MAX_SUMMARY_BYTES = 4096;

/** One per request type; registered before jobs.start() (registerAppleModule, sister specifications). */
export function registerCommandResultIngestor(i: CommandResultIngestor): void {
  if (!REQUEST_TYPE_RE.test(String(i?.requestType ?? ''))) throw new Error('result ingestor: invalid request type');
  if (i.mode !== 'inline' && i.mode !== 'deferred') throw new Error(`result ingestor ${i.requestType}: mode inline or deferred`);
  if (ingestors.has(i.requestType)) throw new Error(`result ingestor ${i.requestType}: registered twice`);
  ingestors.set(i.requestType, Object.freeze({ ...i }));
}

/** The summary of an Acknowledged result of a request type (the catalogue of the commands may register its own). */
export function registerResultSummarizer(requestType: string, fn: ResultSummarizer): void {
  if (!REQUEST_TYPE_RE.test(requestType)) throw new Error('result summarizer: invalid request type');
  summarizers.set(requestType, fn);
}

/** Hook run in the event's savepoint when a target reaches a final state (setup plans, DDM, VPP…). */
export function onTargetFinal(name: string, fn: (ctx: TargetFinalContext) => Promise<void>): void {
  registerTargetFinalHook(name, fn);
}

/** The ingestor of a request type, if any. */
export function ingestorOf(requestType: string): CommandResultIngestor | undefined {
  return ingestors.get(requestType);
}

/** The non-personal summary of a result (≤ 4 KiB), or null. */
export function summarizeResult(requestType: string, result: Record<string, unknown>): ResultSummary | null {
  const fn = summarizers.get(requestType);
  if (!fn) return null;
  try {
    const s = fn(result ?? {});
    if (!s) return null;
    const clean: ResultSummary = {};
    for (const [k, v] of Object.entries(s).slice(0, 32)) {
      if (!/^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(k)) continue;
      if (typeof v === 'string') clean[k] = v.slice(0, 200);
      else if ((typeof v === 'number' && Number.isFinite(v)) || typeof v === 'boolean') clean[k] = v;
    }
    return Buffer.byteLength(JSON.stringify(clean)) <= MAX_SUMMARY_BYTES ? clean : null;
  } catch {
    return null;
  }
}

const IngestPayload = z.object({
  tenantId: z.number().int().positive(),
  /** apple_command_results_inbox.event_id (the outbox event of the result). */
  eventId: z.string().uuid(),
}).strict();

let ingestJob: JobHandle<z.infer<typeof IngestPayload>> | null = null;

export type IngestionOutcome = 'none' | 'skipped' | 'previous_cycle' | 'inline' | 'deferred';

/**
 * Is a result of `occurredAt` of the device's current enrollment cycle (§7.3)? A result older than the cycle's
 * Authenticate was given before the device was erased and enrolled again (its event consumed late): its target takes
 * its state, but nothing of it describes the device of the current cycle (its inventory, its setup plan, its
 * secrets), possibly enrolled since under another ownership. No satellite: not an Apple record, nothing to compare.
 */
async function ofCurrentCycle(trx: Knex.Transaction, tenantId: number, deviceId: number, occurredAt: Date): Promise<boolean> {
  const sat = await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId }).first('authenticated_at') as
    { authenticated_at: Date | null } | undefined;
  return !sat?.authenticated_at || occurredAt.getTime() >= new Date(sat.authenticated_at).getTime();
}

/**
 * The ingestion of a result whose target just reached a final state (§7.6), in the event's savepoint: inline, or
 * copied to the inbox with its job (id derived from the event: a replay adds nothing). 'none': no ingestor for the
 * type; 'skipped': the status is not ingested; 'previous_cycle': the result is older than the device's current
 * enrollment cycle.
 */
export async function ingestCommandResult(trx: Knex.Transaction, c: Omit<ResultIngestContext, 'trx'> & { requestType: string; eventId: string }):
  Promise<IngestionOutcome> {
  const i = ingestors.get(c.requestType);
  if (!i) return 'none';
  const error = c.status === 'Error' || c.status === 'CommandFormatError';
  if (!(c.status === 'Acknowledged' || (error && i.alsoOnError))) return 'skipped';
  if (!(await ofCurrentCycle(trx, c.tenantId, c.deviceId, c.occurredAt))) return 'previous_cycle';
  if (i.mode === 'inline') {
    await i.apply({ trx, tenantId: c.tenantId, deviceId: c.deviceId, commandId: c.commandId, status: c.status, result: c.result,
      occurredAt: c.occurredAt });
    return 'inline';
  }
  if (!ingestJob) throw new Error('apple.command-result-ingest is not registered (registerAppleModule)');
  await trx.raw(`
    INSERT INTO obligarth.apple_command_results_inbox (event_id, tenant_id, command_id, device_id, request_type, status, occurred_at, result)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb)
    ON CONFLICT (event_id) DO NOTHING`,
  [c.eventId, c.tenantId, c.commandId, c.deviceId, c.requestType, c.status, c.occurredAt, JSON.stringify(c.result ?? {})]);
  await ingestJob.sendInTx(trx, { tenantId: c.tenantId, eventId: c.eventId },
    { id: jobIdFor('apple.command-result-ingest', c.eventId), tenantId: c.tenantId });
  return 'deferred';
}

interface InboxRow {
  event_id: string;
  command_id: string;
  device_id: number;
  request_type: string;
  status: AppleCommandStatus;
  occurred_at: Date;
  result: Record<string, unknown> | null;
}

/** apple.command-result-ingest: the result of the inbox applied by its ingestor and deleted, in one transaction of
 *  the tenant. A failure keeps the row (attempts, last_error_code) for the retries, then until the purge. */
async function ingestDeferred(ctx: JobContext<z.infer<typeof IngestPayload>>): Promise<JobResult> {
  const tenantId = ctx.tenantId as number;
  const eventId = ctx.payload.eventId;
  try {
    return await ctx.withTenant(async (trx) => {
      const row = await trx('apple_command_results_inbox').where({ tenant_id: tenantId, event_id: eventId }).forUpdate()
        .first('event_id', 'command_id', 'device_id', 'request_type', 'status', 'occurred_at', 'result') as InboxRow | undefined;
      if (!row) return { output: { skipped: 'not_in_inbox' } };
      const i = ingestors.get(row.request_type);
      // The device may have started a new enrollment cycle since the result was put aside.
      const current = i ? await ofCurrentCycle(trx, tenantId, Number(row.device_id), new Date(row.occurred_at)) : false;
      if (i && current) {
        await i.apply({ trx, tenantId, deviceId: Number(row.device_id), commandId: String(row.command_id), status: row.status,
          result: row.result ?? {}, occurredAt: new Date(row.occurred_at) });
      }
      await trx('apple_command_results_inbox').where({ tenant_id: tenantId, event_id: eventId }).del();
      const output: Record<string, string> = !i ? { skipped: 'no_ingestor' } : current ? { ingested: row.request_type } : { skipped: 'previous_cycle' };
      return { output };
    });
  } catch (err) {
    const code = sanitizeError(err).code.slice(0, 64);
    await ctx.withTenant((trx) => trx('apple_command_results_inbox').where({ tenant_id: tenantId, event_id: eventId })
      .update({ attempts: trx.raw('attempts + 1'), last_error_code: code })).catch((e) => {
      logger.warn({ code: sanitizeError(e).code }, 'apple.command-result-ingest: the failure could not be recorded');
    });
    throw err;
  }
}

// ── The MVP ingestors (§7.6) ───────────────────────────────────────────────────

const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null);
const arr = (v: unknown): Array<Record<string, unknown>> => (Array.isArray(v) ? v.filter((x) => obj(x)) as Array<Record<string, unknown>> : []);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** CertificateList items: { CommonName, Data (base64 of the DER), IsIdentity } → the DER, read and never kept. */
function certificatesOf(result: Record<string, unknown>): Array<{ data: Buffer; isIdentity?: boolean }> {
  const out: Array<{ data: Buffer; isIdentity?: boolean }> = [];
  for (const c of arr(result.CertificateList)) {
    if (typeof c.Data !== 'string' || c.Data.length > 96 * 1024 || !/^[A-Za-z0-9+/=\s]+$/.test(c.Data)) continue;
    out.push({ data: Buffer.from(c.Data, 'base64'), isIdentity: c.IsIdentity === true });
  }
  return out;
}

/** DeviceConfigured acknowledged (§8.9): the device left the setup assistant; its plan is configured. */
async function ingestDeviceConfigured(ctx: ResultIngestContext): Promise<void> {
  const { trx, tenantId, deviceId, occurredAt } = ctx;
  await trx('apple_devices').where({ tenant_id: tenantId, device_id: deviceId })
    .update({ device_configured_at: trx.raw('GREATEST(device_configured_at, ?::timestamptz)', [occurredAt]), updated_at: new Date() });
  await trx('apple_setup_plans').where({ tenant_id: tenantId, device_id: deviceId }).whereIn('state', ['running', 'timed_out'])
    .update({ state: 'configured', completed_at: occurredAt, outcome_code: 'configured' });
  await resolveInTx(trx, tenantId, 'enrollment.setup_timeout', deviceId);
}

let mvpRegistered = false;

/** The ingestors of the MVP whose writers the data model provides (registerAppleModule). DeclarativeManagement
 *  comes with the DDM engine (§9.4), DeviceLocation with the lost mode (SEC-05). */
export function registerMvpResultIngestors(): void {
  if (mvpRegistered) return;
  mvpRegistered = true;
  registerCommandResultIngestor({
    requestType: 'DeviceInformation', mode: 'inline',
    apply: async (c) => {
      const q = obj(c.result.QueryResponses);
      if (q) await ingestDeviceInformation(c.trx, c.tenantId, c.deviceId, q, c.occurredAt);
    },
  });
  registerCommandResultIngestor({
    requestType: 'SecurityInfo', mode: 'inline',
    apply: async (c) => {
      const s = obj(c.result.SecurityInfo);
      if (s) await ingestSecurityInfo(c.trx, c.tenantId, c.deviceId, s, c.occurredAt);
    },
  });
  registerCommandResultIngestor({
    requestType: 'InstalledApplicationList', mode: 'deferred',
    apply: async (c) => { await ingestInstalledApplicationList(c.trx, c.tenantId, c.deviceId, arr(c.result.InstalledApplicationList), c.occurredAt); },
  });
  registerCommandResultIngestor({
    requestType: 'ManagedApplicationList', mode: 'deferred',
    apply: async (c) => {
      const apps = obj(c.result.ManagedApplicationList) ?? {};
      const clean = Object.fromEntries(Object.entries(apps).filter(([, v]) => obj(v))) as Record<string, Record<string, unknown>>;
      await ingestManagedApplicationList(c.trx, c.tenantId, c.deviceId, clean, c.occurredAt);
    },
  });
  registerCommandResultIngestor({
    requestType: 'ProfileList', mode: 'deferred',
    apply: async (c) => { await ingestProfileList(c.trx, c.tenantId, c.deviceId, arr(c.result.ProfileList), c.occurredAt); },
  });
  registerCommandResultIngestor({
    requestType: 'CertificateList', mode: 'deferred',
    apply: async (c) => { await ingestCertificateList(c.trx, c.tenantId, c.deviceId, certificatesOf(c.result), c.occurredAt); },
  });
  registerCommandResultIngestor({
    requestType: 'ActivationLockBypassCode', mode: 'inline',
    apply: async (c) => {
      // apple-edge keeps the code and hands a reference (coffre-secrets §8.2): the code never reaches the brain.
      // The reference is what the device's answer became at apple-edge, which lets through a dictionary the device
      // wrote itself under this key ({ $secret_ref: … }): it is not proof that the secret is this device's. Whoever
      // reveals it (SEC-06, lot D) checks the kind and the enrollment apple-edge returns with the secret against
      // this record before showing anything (README §10, point 17).
      const ref = obj(c.result.ActivationLockBypassCode)?.$secret_ref;
      if (typeof ref !== 'string' || !UUID_RE.test(ref)) return;
      await c.trx('apple_devices').where({ tenant_id: c.tenantId, device_id: c.deviceId })
        .update({ activation_lock_bypass_ref: ref.toLowerCase(), updated_at: new Date() });
    },
  });
  registerCommandResultIngestor({ requestType: 'DeviceConfigured', mode: 'inline', apply: ingestDeviceConfigured });
  // Summaries: counts only (never a name, an identifier or a value of the inventory).
  registerResultSummarizer('InstalledApplicationList', (r) => ({ count: arr(r.InstalledApplicationList).length }));
  registerResultSummarizer('ManagedApplicationList', (r) => ({ count: Object.keys(obj(r.ManagedApplicationList) ?? {}).length }));
  registerResultSummarizer('ProfileList', (r) => ({ count: arr(r.ProfileList).length }));
  registerResultSummarizer('CertificateList', (r) => ({ count: arr(r.CertificateList).length }));
  registerResultSummarizer('DeviceInformation', (r) => ({ keys: Object.keys(obj(r.QueryResponses) ?? {}).length }));
}

let jobRegistered = false;

/** apple.command-result-ingest (annex B): tenant, standard, id per event, 3 retries, 120 s. */
export function registerResultJobs(): void {
  if (jobRegistered) return;
  jobRegistered = true;
  ingestJob = registerJob({
    name: 'apple.command-result-ingest',
    scope: 'tenant',
    description: 'Apply a large result of an MDM command (application, profile or certificate list) to the inventory',
    payload: IngestPayload,
    policy: 'standard',
    retry: { limit: 3, delaySeconds: 30, backoff: true, maxDelaySeconds: 600 },
    timeoutSeconds: 120,
    notify: true,
    pollSeconds: 60,                                   // woken by NOTIFY on send (file-durable L3)
    handler: ingestDeferred,
  });
}

