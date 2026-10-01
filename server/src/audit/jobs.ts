// The jobs of the journal (docs: audit-durci §13.2; file-durable annex B):
// seal (hourly), seal key (at start), retention (daily), verification
// (daily, then one job per chain), spool replay and clock (every minute and
// at start), export monitor (every minute). The SIEM exporter is not a job:
// a loop started by a start task (export/exporter.ts).
import { z } from 'zod';
import { config } from '../config';
import { db } from '../db';
import { defaultRuntime, registerJob, type JobHandle } from '../jobs';
import { logger } from '../utils/logger';
import { watchClock } from './clock';
import { exportLagSeconds } from './export/exporter';
import { listDestinationRows } from './export/destinations';
import { auditMetrics } from './metrics';
import { replaySpool } from './replay';
import { runRetention } from './retention';
import { runSeal } from './seal';
import { ensureSealKey } from './sealKeys';
import { verifyTenantChain, type VerificationKind } from './verify';

const empty = z.object({}).strict();

const VerifyTenantPayload = z.object({
  /** The chain (a tenant id; the chain of a deleted tenant is verified too). */
  chain: z.number().int().positive(),
  kind: z.enum(['incremental', 'full', 'on_demand']),
  verificationId: z.number().int().positive().optional(),
  requestedBy: z.number().int().positive().optional(),
}).strict();

let sealJob: JobHandle<Record<string, never>> | null = null;
let verifyTenantJob: JobHandle<z.infer<typeof VerifyTenantPayload>> | null = null;
let registered = false;

export function auditJobHandles(): { seal: JobHandle<Record<string, never>> | null; verifyTenant: JobHandle<z.infer<typeof VerifyTenantPayload>> | null } {
  return { seal: sealJob, verifyTenant: verifyTenantJob };
}

/** A job sent from the console (seal now, verify) is not left waiting for
 *  the next poll of this instance's workers. */
export function wakeAuditJob(name: 'audit.seal' | 'audit.verify-tenant'): void {
  defaultRuntime.wake(name);
}

/** Lag alerts already raised (destination id), until the lag clears. */
const lagging = new Set<number>();
let noDestinationAlerted = false;

export function registerAuditJobs(): void {
  if (registered) return;
  registered = true;

  // Polling (pollSeconds): none of these is waited for by a user beyond a few
  // seconds, and the queries of the server at rest stay low (file-durable L3).
  sealJob = registerJob({
    name: 'audit.seal',
    pollSeconds: 30,
    scope: 'platform',
    description: 'Seal the audit chains that moved: Merkle tree of the heads, Ed25519 signature, RFC 3161 time stamp',
    payload: empty,
    schedule: { cron: config.audit.sealCron },
    policy: 'exclusive',
    retry: { limit: 1, delaySeconds: 60 },
    timeoutSeconds: 300,
    deadLetter: false,
    trackStatus: 'queue',
    alertAfterFailures: 3,
    manualRun: true,
    handler: async (ctx) => {
      const r = await runSeal({ requestId: ctx.requestId });
      return { output: { seq: r.seq, leaves: r.leaves, tsa: r.tsaStatus, keyId: r.keyId } };
    },
  });

  registerJob({
    name: 'audit.seal-keys',
    pollSeconds: 60,
    scope: 'platform',
    description: 'Check that the seal key of the vault is the registered one (new key otherwise)',
    payload: empty,
    policy: 'exclusive',
    runAtStart: true,
    retry: { limit: 3, delaySeconds: 30 },
    timeoutSeconds: 120,
    handler: async (ctx) => {
      const k = await ensureSealKey({ requestId: ctx.requestId });
      return { output: { keyId: k.keyId, created: k.created } };
    },
  });

  registerJob({
    name: 'audit.retention-all',
    pollSeconds: 60,
    scope: 'platform',
    description: 'Purge the expired, sealed and exported prefixes of the audit chains; housekeeping of seal leaves and verifications',
    payload: empty,
    schedule: { cron: '20 3 * * *' },
    policy: 'exclusive',
    timeoutSeconds: 1_800,
    heartbeatSeconds: 60,
    handler: async (ctx) => {
      const r = await runRetention(ctx.signal);
      return { output: { chains: r.chains, purged: r.purged, leaves: r.leaves, verifications: r.verifications } };
    },
  });

  verifyTenantJob = registerJob({
    name: 'audit.verify-tenant',
    pollSeconds: 15,
    scope: 'platform',
    description: 'Verify one audit chain: links, head, seals (incremental, full, or on demand)',
    payload: VerifyTenantPayload,
    policy: 'exclusive',
    retry: { limit: 1, delaySeconds: 60 },
    timeoutSeconds: 1_800,
    heartbeatSeconds: 60,
    handler: async (ctx) => {
      const p = ctx.payload;
      const r = await verifyTenantChain(p.chain, p.kind as VerificationKind, {
        verificationId: p.verificationId, requestedBy: p.requestedBy ?? null, requestId: ctx.requestId,
      });
      return { output: { chain: p.chain, status: r.status, entries: r.entries, seals: r.seals } };
    },
  });

  registerJob({
    name: 'audit.verify-all',
    pollSeconds: 60,
    scope: 'platform',
    description: 'Queue the verification of every audit chain (incremental, full on Sundays)',
    payload: empty,
    schedule: { cron: '10 4 * * *' },
    policy: 'exclusive',
    timeoutSeconds: 300,
    handler: async () => {
      const kind: VerificationKind = new Date().getUTCDay() === 0 ? 'full' : 'incremental';
      const chains = (await db.raw('SELECT tenant_id FROM obligarth.audit_chains()') as { rows: Array<{ tenant_id: number }> }).rows;
      let queued = 0;
      for (const c of chains) {
        const id = await verifyTenantJob!.send({ chain: Number(c.tenant_id), kind }, { singletonKey: `t:${Number(c.tenant_id)}` });
        if (id) queued++;
      }
      return { output: { chains: chains.length, queued, kind } };
    },
  });

  registerJob({
    name: 'audit.spool-replay',
    pollSeconds: 30,
    scope: 'platform',
    description: 'Replay the local audit spool; measure the clock drift with the database',
    payload: empty,
    schedule: { cron: '* * * * *' },
    policy: 'exclusive',
    runAtStart: true,
    retry: { limit: 0 },
    timeoutSeconds: 120,
    handler: async (ctx) => {
      const skew = await watchClock().catch(() => null);
      const r = await replaySpool({ requestId: ctx.requestId });
      return { output: { replayed: r.replayed, rejected: r.rejected, remaining: r.remaining, skew: skew === null ? null : Math.round(skew * 10) / 10 } };
    },
  });

  registerJob({
    name: 'audit.export-monitor',
    pollSeconds: 60,
    scope: 'platform',
    description: 'Lag of every SIEM destination; alert when a destination lags or none is enabled in production',
    payload: empty,
    schedule: { cron: '* * * * *' },
    policy: 'exclusive',
    retry: { limit: 0 },
    timeoutSeconds: 120,
    handler: async () => {
      const dests = await listDestinationRows();
      const enabled = dests.filter((d) => d.enabled);
      auditMetrics.set('obligarth_audit_export_destinations', enabled.length, { state: 'enabled' });
      auditMetrics.set('obligarth_audit_export_destinations', dests.length - enabled.length, { state: 'disabled' });
      const { raiseJobAlert } = await import('../jobs/alerts');
      let maxLag = 0;
      for (const d of enabled) {
        const lag = await exportLagSeconds(d);
        auditMetrics.set('obligarth_audit_export_lag_seconds', lag ?? 0, { destination: d.id });
        maxLag = Math.max(maxLag, lag ?? 0);
        if (lag !== null && lag > 15 * 60) {
          if (!lagging.has(d.id)) {
            lagging.add(d.id);
            await raiseJobAlert({ type: 'job', name: 'audit.export-monitor' }, {
              stableKey: `audit:export-lag:${d.id}`, severity: 'warning',
              title: 'SIEM export behind',
              message: `The audit export to destination ${d.id} is ${Math.round(lag / 60)} min behind.`,
            });
          }
        } else {
          lagging.delete(d.id);
        }
      }
      if (!enabled.length && process.env.NODE_ENV === 'production' && config.audit.export !== 'off') {
        if (!noDestinationAlerted) {
          noDestinationAlerted = true;
          logger.warn({ code: 'AUDIT_NO_DESTINATION' }, 'audit: no SIEM destination enabled');
          await raiseJobAlert({ type: 'job', name: 'audit.export-monitor' }, {
            stableKey: 'audit:no-destination', severity: 'warning',
            title: 'No SIEM destination',
            message: 'No SIEM destination receives the audit log: configure one before the pilot (audit settings).',
          });
        }
      } else {
        noDestinationAlerted = false;
      }
      return { output: { destinations: enabled.length, maxLagSeconds: maxLag } };
    },
  });
}
