import type { Knex } from 'knex';
import {
  AGENT_REQUIRED_APP_KEY_PREFIX, AGENT_REQUIRED_APP_MODES, SITE_LOW_STORAGE_BYTES, parseAgentKey,
  type AgentRequiredApp, type LegacyAgentCommandState, type LegacyAgentRequiredAppReason, type LegacyAgentRequiredAppState,
  type LegacyAgentRequiredAppView, type LegacyAgentRequiredAppsTenantView, type LegacyAgentRequiredAppsView,
} from '@obligarth/shared';
import { db } from '../db';
import { asTenant, type DbActor } from '../db/context';
import { forEachTenant } from '../db/tenantContext';
import { tenantFrozen } from '../guard/frozen';
import { JobError, defaultRuntime, type JobContext, type JobHandle, type JobResult } from '../jobs';
import { raiseInTx, resolveInTx } from '../apple/alerts/service';
import { currentProfile, legacyAgentPrivacyRulesFor } from '../privacy/profiles';
import { restrictionFloor, restrictionService } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { LEGACY_AGENT_ACTOR } from './actor';
import { legacyAgentCommands, wakeAfterCommit } from './commands';

// =============================================================================
// Required apps of the bridge agent policies: the list requiredApps of the
// section legacyAgent (packages of the tenant's APK store, confirmed, F028),
// resolved like any agent:* setting (agent:requiredApp[<package>]: inheritance,
// priorities, exclusions, impact preview and publication thresholds) but never
// compiled for the agent (policyChannel.ts): the server installs them by the
// app.install every agent already knows, with the parameters of the console
// path (consoleCommand). Nothing in the agent nor in what it receives changes.
//   jobs       legacy-agent.required-apps (every 10 minutes, every tenant) and
//              legacy-agent.required-apps-tenant (one tenant or one device:
//              after an inventory is committed, after a tenant's resolution);
//   what       the effective settings agent:requiredApp[…] of the enrolled,
//              not revoked bridge devices, from a policy of the tenant,
//              available; the entry read in the policy version that is the
//              source; the last inventory (device_apps, agent_report);
//   decision   requiredAppDecision (pure), in this order: the package missing
//              or not confirmed (skipped); no inventory yet (skipped); the app
//              installed (mode install: present; minVersion: present and
//              versionCode >= the package's, a non-numeric one counts as
//              satisfied: never a loop of reinstalls); an app.install open
//              (pending, sent) for the device and the package name, whatever
//              its origin (queued); one acknowledged after the last inventory
//              (awaiting_inventory); the tenant's privacy profile limits the
//              apps to the managed ones and the app is absent (skipped: the
//              absence proves nothing); 3 failed installs of this job for
//              this package over the last 7 days (failed: no 4th before the
//              oldest of them is 7 days old; another package in the policy
//              starts the count again). A failure is an end error, rejected or
//              expired, or an install acknowledged that the next inventory
//              does not show; a cancellation (the operator's emergency stop)
//              never counts; the last install of this job for this package
//              queued less than 24 hours ago, whatever its end (backoff); a
//              frozen tenant, an inactive device administrator, no contact for
//              24 hours, a package whose recent installs fail (5 of the last
//              20 of this job within 24 hours end error or rejected: the
//              rollout stops for every device), a free storage unknown or
//              lower than the low-storage floor of the sites (512 MiB) plus
//              twice the APK, an inventory older than 6 hours or than the
//              current privacy profile (skipped; the job asks the device for an
//              inventory, inventory_requested_at, and the pass that follows its
//              ingestion decides on fresh facts); the restrictions matrix on
//              legacy_agent.apps for the device (skipped: a person would be
//              asked, as the harvest and the automatic update); otherwise due;
//   pace       REQUIRED_APPS_PER_RUN installs per tenant over a sliding window
//              of REQUIRED_APPS_WINDOW_MINUTES (a little shorter than the
//              10-minute period of the sweep), and at most REQUIRED_APPS_MAX_OPEN
//              installs of this job open (pending, sent) at once per tenant
//              (those queued in the last REQUIRED_APPS_OPEN_HOURS), both counted
//              in the queue itself under a per-tenant advisory lock (the
//              per-device triggers cannot go around them); silent installers
//              first (administrator active and Knox licensed), then the most
//              recent interrogation; the rest is deferred (logged) and taken by
//              a later pass;
//   queue      legacyAgentCommands.enqueue, origin 'system', actor
//              j:legacy-agent.required-apps, one device per call (one audit
//              entry legacy_agent.command_queued each, in the transaction), in
//              a savepoint, the devices by increasing id (the order of the
//              row locks of the resolution); the open installs are read again
//              under the lock; an idempotency key per device, package and UTC
//              day; the long waits of the devices woken after the commit;
//   alert      legacy_agent.required_app_failed: a full pass of the tenant
//              raises it while a pair is failed and resolves it otherwise; a
//              pass limited to a device only raises it.
// Never an uninstall. The guard setting legacyAgentCommandsSensitive concerns
// the HUMAN requests only (commandGuard.ts): these installs come from a
// published (approved) policy and only the matrix key legacy_agent.apps applies,
// per device, as for the harvest and the automatic update. Emergency stop:
// remove requiredApps from the policy (nothing at the next pass) or freeze the
// tenant; the pending commands are cancelled from the console (a cancellation
// holds the job back 24 hours for that app, never counts as a failure).
// =============================================================================

export const REQUIRED_APPS_JOB = 'legacy-agent.required-apps';
export const REQUIRED_APPS_TENANT_JOB = 'legacy-agent.required-apps-tenant';
export const REQUIRED_APPS_ACTOR = `j:${REQUIRED_APPS_JOB}`;
/** The installs this job queues at most per tenant over the window. */
export const REQUIRED_APPS_PER_RUN = 50;
/** A little shorter than the period of the sweep (10 minutes): the commands of the previous pass, created a few seconds
 *  after its start, are out of the window when the next pass starts. */
export const REQUIRED_APPS_WINDOW_MINUTES = 9;
/** The installs of this job open (pending, sent) at most per tenant: the next ones wait for the first results. */
export const REQUIRED_APPS_MAX_OPEN = REQUIRED_APPS_PER_RUN;
/** The open installs counted by REQUIRED_APPS_MAX_OPEN are those queued in the last hours (an install the user never
 *  answers, without Knox, holds no slot for its whole lifetime of 3 days). */
export const REQUIRED_APPS_OPEN_HOURS = 6;
export const REQUIRED_APPS_MAX_FAILURES = 3;
/** The failures count over this window: a failed state is never final. */
export const REQUIRED_APPS_FAILURE_WINDOW_DAYS = 7;
export const REQUIRED_APPS_RETRY_HOURS = 24;
export const REQUIRED_APPS_SILENCE_HOURS = 24;
/** An install is decided on an inventory of at most this age (otherwise the job asks the device for one). */
export const REQUIRED_APPS_INVENTORY_MAX_AGE_HOURS = 6;
export const REQUIRED_APPS_STORAGE_FLOOR = SITE_LOW_STORAGE_BYTES;
/** The breaker of a package: BREAKER_FAILURES failed among the last BREAKER_SAMPLE installs of this job ended in the
 *  last BREAKER_HOURS stop its rollout on every device of the tenant. */
export const REQUIRED_APPS_BREAKER_SAMPLE = 20;
export const REQUIRED_APPS_BREAKER_FAILURES = 5;
export const REQUIRED_APPS_BREAKER_HOURS = 24;

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const RESTRICTION_KEY = 'legacy_agent.apps';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERSION_CODE_RE = /^[0-9]{1,15}$/;
const OPEN_STATES: readonly LegacyAgentCommandState[] = ['pending', 'sent'];
/** The ends that count as a failed attempt ('cancelled' never: the operator's emergency stop). */
const FAILED_STATES: readonly LegacyAgentCommandState[] = ['error', 'rejected', 'expired'];
/** The ends that tell a defective package (the breaker): the device ran it and it failed. */
const BREAKER_STATES: readonly LegacyAgentCommandState[] = ['error', 'rejected'];

const ms = (v: unknown): number | null => (v ? new Date(v as string | Date).getTime() : null);
const iso = (v: number | null): string | null => (v === null ? null : new Date(v).toISOString());
const numOrNull = (v: unknown): number | null => (v === null || v === undefined || v === '' ? null : Number.isFinite(Number(v)) ? Number(v) : null);

/** The parameters of an app.install of a package row, exactly those of the console path (routes.ts consoleCommand). */
export function installParamsOf(p: Record<string, any>): Record<string, unknown> {
  return {
    packageId: String(p.id), packageName: p.package_name, versionCode: Number(p.version_code), sha256: String(p.sha256).trim(),
    size: Number(p.size_bytes), ...(p.signer_sha256 ? { signerSha256: String(p.signer_sha256).trim() } : {}),
  };
}

// ── The decision (pure) ──────────────────────────────────────────────────────

export interface RequiredAppCommandFact {
  id: string;
  packageId: string | null;
  versionCode: number | null;
  actor: string;
  state: LegacyAgentCommandState;
  resultCode?: string | null;
  createdAt: number;
  completedAt: number | null;
}

export interface RequiredAppFacts {
  now: number;
  entry: AgentRequiredApp;
  /** failing: the breaker of the package is open (its recent installs fail on the tenant's devices). */
  pkg: { id: string; packageName: string; versionCode: number; sizeBytes: number; confirmed: boolean; failing?: boolean } | null;
  device: {
    adminActive: boolean | null; lastPollAt: number | null; lastInventoryAt: number | null; storageAvailableBytes: number | null;
    frozen: boolean; appsLimited: boolean;
    /** The publication of the tenant's current privacy profile (an inventory before it was filtered by another rule). */
    privacySince?: number | null;
  };
  /** The app in the last inventory; versionCode null when it is not numeric. */
  installed: { versionCode: number | null } | null;
  /** The app.install of this device for this package name (any package id, any actor). */
  commands: RequiredAppCommandFact[];
}

export interface RequiredAppDecision {
  state: LegacyAgentRequiredAppState;
  reason: LegacyAgentRequiredAppReason | null;
  /** The failed installs of this job for the package of the entry. */
  attempts: number;
  openCommandId: string | null;
  nextAttemptAt: number | null;
  lastAttempt: { commandId: string; state: LegacyAgentCommandState; resultCode: string | null; at: number } | null;
}

/** Is the required app satisfied by what the inventory reports? */
export function requiredAppSatisfied(mode: AgentRequiredApp['mode'], installed: RequiredAppFacts['installed'], pkgVersionCode: number): boolean {
  if (!installed) return false;
  if (mode === 'install') return true;
  return installed.versionCode === null || installed.versionCode >= pkgVersionCode;
}

/** The state of one required app on one device (steps 1 to 9 of the design; the restriction is the caller's, on due and
 *  on skipped/stale_inventory). */
export function requiredAppDecision(f: RequiredAppFacts): RequiredAppDecision {
  const byNewest = [...f.commands].sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : -1));
  const last = byNewest[0];
  const lastAttempt = last ? { commandId: last.id, state: last.state, resultCode: last.resultCode ?? null, at: last.createdAt } : null;
  const target = (f.pkg?.id ?? f.entry.packageId).toLowerCase();
  const mine = byNewest.filter((c) => c.actor === REQUIRED_APPS_ACTOR && (c.packageId ?? '').toLowerCase() === target);
  const windowStart = f.now - REQUIRED_APPS_FAILURE_WINDOW_DAYS * DAY_MS;
  // The failed ends over the window (newest first); the futile acknowledgements are added once the app is known missing.
  let failures = mine.filter((c) => c.createdAt > windowStart && FAILED_STATES.includes(c.state));
  let attempts = failures.length;
  const out = (state: LegacyAgentRequiredAppState, reason: LegacyAgentRequiredAppReason | null = null,
    extra: Partial<RequiredAppDecision> = {}): RequiredAppDecision =>
    ({ state, reason, attempts, openCommandId: null, nextAttemptAt: null, lastAttempt, ...extra });

  // 1. The package of the policy.
  if (!f.pkg || f.pkg.packageName !== f.entry.packageName || f.pkg.id.toLowerCase() !== f.entry.packageId.toLowerCase()) {
    return out('skipped', 'package_unavailable');
  }
  if (!f.pkg.confirmed) return out('skipped', 'package_not_confirmed');
  // 2. Nothing is known of the device's apps yet.
  if (f.device.lastInventoryAt === null) return out('skipped', 'no_inventory');
  // 3. Installed.
  if (requiredAppSatisfied(f.entry.mode, f.installed, f.pkg.versionCode)) return out('installed');
  // 4. An install already open, whatever its origin.
  const open = byNewest.find((c) => OPEN_STATES.includes(c.state));
  if (open) return out('queued', null, { openCommandId: open.id });
  // 5. An install acknowledged after the last inventory: the next one tells.
  if (byNewest.some((c) => c.state === 'acknowledged' && c.completedAt !== null && c.completedAt > (f.device.lastInventoryAt as number))) {
    return out('awaiting_inventory');
  }
  // The installs of this job acknowledged, then an inventory where the app is still missing or older: failed attempts
  // too (never an endless loop of reinstalls every 24 hours).
  const lastInventoryAt = f.device.lastInventoryAt;
  const futile = mine.filter((c) => c.createdAt > windowStart && c.state === 'acknowledged' && c.completedAt !== null && c.completedAt <= lastInventoryAt);
  if (futile.length > 0) {
    failures = [...failures, ...futile].sort((a, b) => b.createdAt - a.createdAt);
    attempts = failures.length;
  }
  // 6. The inventory holds the managed apps only: an absent app proves nothing.
  if (f.device.appsLimited && !f.installed) return out('skipped', 'inventory_limited');
  // 7. Three failures of this job for this package over the window: no fourth until the oldest of them leaves it.
  if (attempts >= REQUIRED_APPS_MAX_FAILURES) {
    return out('failed', null, { nextAttemptAt: failures[REQUIRED_APPS_MAX_FAILURES - 1].createdAt + REQUIRED_APPS_FAILURE_WINDOW_DAYS * DAY_MS });
  }
  // 8. The last attempt of this job for this package, less than 24 hours ago (whatever its end, a cancellation included).
  if (mine[0] && mine[0].createdAt > f.now - REQUIRED_APPS_RETRY_HOURS * HOUR_MS) {
    return out('backoff', null, { nextAttemptAt: mine[0].createdAt + REQUIRED_APPS_RETRY_HOURS * HOUR_MS });
  }
  // 9. The device, the tenant and the package.
  if (f.device.frozen) return out('skipped', 'frozen');
  if (f.device.adminActive !== true) return out('skipped', 'admin_inactive');
  if (f.device.lastPollAt === null || f.device.lastPollAt < f.now - REQUIRED_APPS_SILENCE_HOURS * HOUR_MS) return out('skipped', 'no_contact');
  if (f.pkg.failing) return out('skipped', 'package_failing');
  // The storage of the last inventory (the agent always reports it; unknown: set aside, never a guess).
  if (f.device.storageAvailableBytes === null) return out('skipped', 'storage_unknown');
  if (f.device.storageAvailableBytes < REQUIRED_APPS_STORAGE_FLOOR + 2 * f.pkg.sizeBytes) return out('skipped', 'low_storage');
  // An inventory too old, or older than the current privacy profile: the app may be there since (another tool, the
  // user, the console) or filtered out by the former rule. The caller asks the device for an inventory.
  if (lastInventoryAt < f.now - REQUIRED_APPS_INVENTORY_MAX_AGE_HOURS * HOUR_MS
    || (f.device.privacySince != null && lastInventoryAt < f.device.privacySince)) {
    return out('skipped', 'stale_inventory');
  }
  return out('due');
}

// ── The facts ────────────────────────────────────────────────────────────────

interface PackageRow {
  id: string; package_name: string; version_code: string | number; version_name: string | null; label: string | null; sha256: string;
  size_bytes: string | number; signer_sha256: string | null; confirmed_at: Date | string | null;
}

interface Pair {
  deviceId: number;
  packageName: string;
  index: number;
  entry: AgentRequiredApp | null;
  availability: string;
  unavailableReason: string | null;
  policy: { id: number; name: string; version: number } | null;
  pkg: PackageRow | null;
  installed: { versionCode: string | null; versionName: string | null } | null;
  commands: RequiredAppCommandFact[];
  device: { adminActive: boolean | null; silent: boolean; lastPollAt: number | null; lastInventoryAt: number | null; storageAvailableBytes: number | null };
}

interface Facts {
  now: number; frozen: boolean; appsLimited: boolean; privacySince: number | null;
  /** The package ids (lower case) whose breaker is open. */
  failingPackages: Set<string>;
  pairs: Pair[];
}

/** Is the breaker of a package open? `ends`: the ends of its installs by this job over the breaker's window, newest
 *  first (pure). */
export function packageFailing(ends: readonly LegacyAgentCommandState[]): boolean {
  return ends.slice(0, REQUIRED_APPS_BREAKER_SAMPLE).filter((s) => BREAKER_STATES.includes(s)).length >= REQUIRED_APPS_BREAKER_FAILURES;
}

/** Everything the decisions need, read in `q` (the tenant's context), a handful of grouped queries. */
async function loadFacts(q: Knex.Transaction, tenantId: number, deviceIds?: number[]): Promise<Facts> {
  const now = Date.now();
  const sel = await q.raw(`
    SELECT e.device_id, e.setting_key, e.source_id AS policy_id, e.source_version_id, e.availability, e.unavailable_reason,
           a.admin_active, a.knox_state, a.last_poll_at, a.last_inventory_at, d.storage_available_bytes
      FROM obligarth.device_effective_settings e
      JOIN obligarth.legacy_agent_devices a ON a.tenant_id = e.tenant_id AND a.device_id = e.device_id
      JOIN obligarth.devices d ON d.tenant_id = e.tenant_id AND d.id = e.device_id
     WHERE e.tenant_id = ? AND e.setting_key LIKE ? AND NOT e.removed AND e.source_type = 'policy' AND e.source_tenant_id = e.tenant_id
       AND a.revoked_at IS NULL AND d.enrollment_state = 'enrolled' AND d.management_channel = 'legacy_agent'
       ${deviceIds ? 'AND e.device_id = ANY (?::int[])' : ''}
     ORDER BY e.device_id, e.setting_key`,
  [tenantId, `${AGENT_REQUIRED_APP_KEY_PREFIX}%`, ...(deviceIds ? [deviceIds] : [])]) as { rows: Array<Record<string, any>> };
  if (sel.rows.length === 0) return { now, frozen: false, appsLimited: false, privacySince: null, failingPackages: new Set(), pairs: [] };

  const versionIds = [...new Set(sel.rows.map((r) => Number(r.source_version_id)).filter((n) => Number.isSafeInteger(n)))];
  const versions = await q('policy_versions as v').join('policies as p', function j() { this.on('p.id', '=', 'v.policy_id').andOn('p.tenant_id', '=', 'v.tenant_id'); })
    .where('v.tenant_id', tenantId).whereIn('v.id', versionIds)
    .select('v.id', 'v.version', 'v.policy_id', 'p.name', q.raw("v.content->'sections'->'legacyAgent'->'requiredApps' AS required_apps")) as
    Array<{ id: number; version: number; policy_id: number; name: string; required_apps: unknown }>;
  const versionById = new Map(versions.map((v) => [Number(v.id), v]));

  const base = sel.rows.map((r) => {
    const packageName = parseAgentKey(String(r.setting_key))?.instance ?? '';
    const v = versionById.get(Number(r.source_version_id));
    const list = Array.isArray(v?.required_apps) ? v!.required_apps as unknown[] : [];
    const index = list.findIndex((x) => !!x && typeof x === 'object' && (x as AgentRequiredApp).packageName === packageName);
    const raw = index >= 0 ? list[index] as AgentRequiredApp : null;
    const entry = raw && typeof raw.packageId === 'string' && UUID_RE.test(raw.packageId) && (AGENT_REQUIRED_APP_MODES as readonly string[]).includes(raw.mode)
      ? { packageName, packageId: raw.packageId.toLowerCase(), mode: raw.mode } : null;
    return { r, packageName, index, entry, v };
  }).filter((x) => x.packageName !== '');

  const packageIds = [...new Set(base.flatMap((x) => (x.entry ? [x.entry.packageId] : [])))];
  const packages = packageIds.length
    ? await q('legacy_agent_packages').where({ tenant_id: tenantId }).whereIn('id', packageIds)
      .select('id', 'package_name', 'version_code', 'version_name', 'label', 'sha256', 'size_bytes', 'signer_sha256', 'confirmed_at') as PackageRow[]
    : [];
  const pkgById = new Map(packages.map((p) => [String(p.id).toLowerCase(), p]));

  const devIds = [...new Set(base.map((x) => Number(x.r.device_id)))];
  const names = [...new Set(base.map((x) => x.packageName))];
  const apps = await q('device_apps').where({ tenant_id: tenantId, source: 'agent_report' }).whereIn('device_id', devIds).whereIn('identifier', names)
    .select('device_id', 'identifier', 'short_version', 'version') as Array<{ device_id: number; identifier: string; short_version: string | null; version: string | null }>;
  const appOf = new Map(apps.map((a) => [`${Number(a.device_id)}|${a.identifier}`, a]));

  const cmds = await q('legacy_agent_commands').where({ tenant_id: tenantId, request_type: 'app.install' }).whereIn('device_id', devIds)
    .whereRaw("params->>'packageName' = ANY (?::text[])", [names])
    .select('id', 'device_id', 'actor', 'state', 'result_code', 'created_at', 'completed_at',
      q.raw("params->>'packageName' AS package_name"), q.raw("params->>'packageId' AS package_id"), q.raw("params->>'versionCode' AS version_code")) as
    Array<Record<string, any>>;
  const cmdsOf = new Map<string, RequiredAppCommandFact[]>();
  for (const c of cmds) {
    const k = `${Number(c.device_id)}|${c.package_name}`;
    const list = cmdsOf.get(k) ?? [];
    list.push({
      id: String(c.id).toLowerCase(), packageId: c.package_id ? String(c.package_id).toLowerCase() : null, versionCode: numOrNull(c.version_code),
      actor: String(c.actor), state: c.state, resultCode: c.result_code ?? null, createdAt: ms(c.created_at) as number, completedAt: ms(c.completed_at),
    });
    cmdsOf.set(k, list);
  }

  // The breaker of each package: the ends of this job's installs of the tenant (every device) over its window.
  const failingPackages = new Set<string>();
  if (packageIds.length > 0) {
    const ends = await q('legacy_agent_commands').where({ tenant_id: tenantId, request_type: 'app.install', actor: REQUIRED_APPS_ACTOR })
      .whereRaw("lower(params->>'packageId') = ANY (?::text[])", [packageIds]).whereNotIn('state', OPEN_STATES as string[])
      .where('created_at', '>', new Date(now - REQUIRED_APPS_BREAKER_HOURS * HOUR_MS))
      .orderBy('created_at', 'desc').limit(1000)
      .select(q.raw("lower(params->>'packageId') AS package_id"), 'state') as Array<{ package_id: string; state: LegacyAgentCommandState }>;
    const byPackage = new Map<string, LegacyAgentCommandState[]>();
    for (const e of ends) byPackage.set(e.package_id, [...(byPackage.get(e.package_id) ?? []), e.state]);
    for (const [id, list] of byPackage) if (packageFailing(list)) failingPackages.add(id);
  }

  const frozen = await tenantFrozen(q, tenantId, 'legacy_agent');
  const appsLimited = (await legacyAgentPrivacyRulesFor(q, tenantId)).installedApps === 'managed_only';
  const privacySince = (await currentProfile(q, tenantId, 'corporate'))?.createdAt.getTime() ?? null;

  const pairs: Pair[] = base.map(({ r, packageName, index, entry, v }) => {
    const deviceId = Number(r.device_id);
    const app = appOf.get(`${deviceId}|${packageName}`);
    return {
      deviceId, packageName, index, entry, availability: String(r.availability), unavailableReason: r.unavailable_reason ?? null,
      policy: v ? { id: Number(v.policy_id), name: String(v.name), version: Number(v.version) } : null,
      pkg: entry ? pkgById.get(entry.packageId) ?? null : null,
      installed: app ? { versionCode: app.short_version ?? null, versionName: app.version ?? null } : null,
      commands: cmdsOf.get(`${deviceId}|${packageName}`) ?? [],
      device: {
        adminActive: typeof r.admin_active === 'boolean' ? r.admin_active : null, silent: r.admin_active === true && r.knox_state === 'licensed',
        lastPollAt: ms(r.last_poll_at), lastInventoryAt: ms(r.last_inventory_at), storageAvailableBytes: numOrNull(r.storage_available_bytes),
      },
    };
  });
  return { now, frozen, appsLimited, privacySince, failingPackages, pairs };
}

function factsOf(f: Facts, p: Pair): RequiredAppFacts {
  const pkg = p.pkg;
  const vc = p.installed?.versionCode;
  const pkgId = pkg ? String(pkg.id).toLowerCase() : '';
  return {
    now: f.now, entry: p.entry as AgentRequiredApp,
    pkg: pkg ? {
      id: pkgId, packageName: pkg.package_name, versionCode: Number(pkg.version_code), sizeBytes: Number(pkg.size_bytes), confirmed: !!pkg.confirmed_at,
      failing: f.failingPackages.has(pkgId),
    } : null,
    device: { ...p.device, frozen: f.frozen, appsLimited: f.appsLimited, privacySince: f.privacySince },
    installed: p.installed ? { versionCode: vc && VERSION_CODE_RE.test(vc) ? Number(vc) : null } : null,
    commands: p.commands,
  };
}

interface Evaluated { pair: Pair; d: RequiredAppDecision }

/** A pair the restrictions matrix decides: due, or waiting for a fresh inventory (never ask one of a device the matrix
 *  holds anyway). */
const gatedByMatrix = (d: RequiredAppDecision): boolean => d.state === 'due' || (d.state === 'skipped' && d.reason === 'stale_inventory');

/**
 * The devices of `ids` the restrictions matrix holds for legacy_agent.apps (a level above 'none': a person would be
 * asked): a floor or an entry on the whole tenant holds all of them; a scope holds those it lists (include) or does not
 * list (exclude), a device being listed by its id or by its group or an ancestor of it, as restrictionService.getLevelFor
 * decides it for one device. One read of the matrix and at most one grouped query (autoUpdate.ts).
 */
async function restrictedDevices(tenantId: number, ids: number[]): Promise<Set<number>> {
  if (ids.length === 0) return new Set();
  if (restrictionFloor(RESTRICTION_KEY)) return new Set(ids);
  const entry = (await restrictionService.getMap(tenantId))[RESTRICTION_KEY];
  if (!entry || entry.level === 'none') return new Set();
  if (entry.scope.mode === 'all') return new Set(ids);
  const deviceIds = entry.scope.deviceIds ?? [];
  const groupIds = entry.scope.groupIds ?? [];
  const rows = await db('devices as d').where('d.tenant_id', tenantId).whereIn('d.id', ids)
    .where(function listed() {
      this.whereIn('d.id', deviceIds).orWhereExists(function viaGroup() {
        this.select(db.raw('1')).from('device_group_closure as gc').whereRaw('gc.descendant_id = d.group_id').whereIn('gc.ancestor_id', groupIds);
      });
    }).select('d.id') as Array<{ id: number }>;
  const listed = new Set(rows.map((r) => Number(r.id)));
  return new Set(ids.filter((id) => (entry.scope.mode === 'include' ? listed.has(id) : !listed.has(id))));
}

/** The decision of each available pair whose entry the source version holds, the restriction applied (gatedByMatrix). */
async function evaluate(tenantId: number, f: Facts): Promise<Evaluated[]> {
  const out: Evaluated[] = [];
  for (const p of f.pairs) {
    if (p.availability !== 'available' || !p.entry) continue;
    out.push({ pair: p, d: requiredAppDecision(factsOf(f, p)) });
  }
  const held = await restrictedDevices(tenantId, [...new Set(out.filter((e) => gatedByMatrix(e.d)).map((e) => e.pair.deviceId))]);
  for (const e of out) {
    if (gatedByMatrix(e.d) && held.has(e.pair.deviceId)) e.d = { ...e.d, state: 'skipped', reason: 'restricted' };
  }
  return out;
}

/** What of the tenant sets every required app aside (the head of the editor's tab). */
export async function requiredAppsTenantState(tenantId: number): Promise<LegacyAgentRequiredAppsTenantView> {
  const rank = { none: 0, sensitive: 1, restricted: 2 } as const;
  const floor = restrictionFloor(RESTRICTION_KEY);
  const entry = (await restrictionService.getMap(tenantId))[RESTRICTION_KEY];
  let restriction: LegacyAgentRequiredAppsTenantView['restriction'] = { level: 'none', scope: null };
  if (entry && entry.level !== 'none') restriction = { level: entry.level, scope: entry.scope.mode === 'all' ? 'all' : 'partial' };
  if (floor && rank[floor.level] >= rank[restriction.level]) restriction = { level: floor.level, scope: 'all' };
  const appsLimited = (await legacyAgentPrivacyRulesFor(db, tenantId)).installedApps === 'managed_only';
  return { appsLimited, restriction };
}

// ── The console view of a device ─────────────────────────────────────────────

function viewOf(p: Pair, d: RequiredAppDecision | null): LegacyAgentRequiredAppView {
  return {
    packageName: p.packageName, mode: p.entry?.mode ?? 'install', packageId: p.entry?.packageId ?? '',
    package: p.pkg ? {
      versionCode: String(p.pkg.version_code), versionName: p.pkg.version_name ?? null, label: p.pkg.label ?? null, sizeBytes: Number(p.pkg.size_bytes),
      confirmed: !!p.pkg.confirmed_at,
    } : null,
    policy: p.policy, installed: p.installed,
    state: d?.state ?? 'skipped', reason: d ? d.reason : 'not_applicable', detail: d ? null : p.unavailableReason,
    attempts: d?.attempts ?? 0, maxAttempts: REQUIRED_APPS_MAX_FAILURES,
    lastAttempt: d?.lastAttempt ? { ...d.lastAttempt, at: iso(d.lastAttempt.at) as string } : null,
    openCommandId: d?.openCommandId ?? null, nextAttemptAt: iso(d?.nextAttemptAt ?? null),
  };
}

/** The required apps of one bridge device and their state (the job's decisions). `dbActor` null: the caller's database
 *  context (a console request); 404 is the caller's for a device that is not a bridge device. */
export async function deviceRequiredApps(tenantId: number, deviceId: number, dbActor: DbActor | null): Promise<LegacyAgentRequiredAppsView> {
  const run = async (): Promise<LegacyAgentRequiredAppsView> => {
    const f = await db.transaction((trx) => loadFacts(trx, tenantId, [deviceId]));
    const evaluated = await evaluate(tenantId, f);
    const byPair = new Map(evaluated.map((e) => [e.pair, e.d]));
    const items = f.pairs.filter((p) => p.availability !== 'available' || p.entry)
      .map((p) => viewOf(p, p.availability === 'available' ? byPair.get(p) ?? null : null))
      .sort((a, b) => (a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0));
    return { deviceId, evaluatedAt: new Date(f.now).toISOString(), perRunLimit: REQUIRED_APPS_PER_RUN, items };
  };
  return dbActor ? asTenant(tenantId, dbActor, run) : run();
}

// ── The bench (lot BANC-A) ───────────────────────────────────────────────────

export type BenchAppSetAside = 'not_applicable' | 'package_unavailable' | 'package_not_confirmed' | 'frozen' | 'restricted' | 'installed'
  | 'inventory_limited';

/**
 * Does the bench install this required app (pure)? The station installs by ADB, at the device, with a technician: what
 * holds back the remote installs of the job (an install already open, the backoff, 3 failures, an inactive
 * administrator, no contact, the storage, the breaker, a stale inventory) does not apply; what SETS THE REQUIRED APPS
 * ASIDE does, as for the job: the package (missing, another one, not confirmed), a frozen tenant, the restrictions matrix
 * on legacy_agent.apps for the device (a person would be asked, whatever the state of the app), the app already
 * installed (minVersion: at the package's version or later; a non-numeric version counts as satisfied), the privacy
 * profile that limits the inventory to the managed apps (an absent app proves nothing). No inventory yet (a device just
 * enrolled): due (adb install -r of an app already there at that version is harmless; a later one fails as a downgrade,
 * told by the station).
 */
export function benchAppDecision(f: RequiredAppFacts, restricted: boolean): 'due' | BenchAppSetAside {
  if (!f.pkg || f.pkg.packageName !== f.entry.packageName || f.pkg.id.toLowerCase() !== f.entry.packageId.toLowerCase()) return 'package_unavailable';
  if (!f.pkg.confirmed) return 'package_not_confirmed';
  if (f.device.frozen) return 'frozen';
  if (restricted) return 'restricted';
  if (requiredAppSatisfied(f.entry.mode, f.installed, f.pkg.versionCode)) return 'installed';
  if (f.device.appsLimited && !f.installed) return 'inventory_limited';
  return 'due';
}

export interface BenchRequiredApp {
  packageId: string; packageName: string; versionCode: number; versionName: string | null; sha256: string; size: number;
  signerSha256: string | null; label: string | null; mode: AgentRequiredApp['mode'];
}

/** The required apps the bench installs on one bridge device (in the caller's database context: the tenant's), by
 *  package name; and the count of those set aside. */
export async function benchRequiredApps(tenantId: number, deviceId: number): Promise<{ items: BenchRequiredApp[]; setAside: number }> {
  const f = await db.transaction((trx) => loadFacts(trx, tenantId, [deviceId]));
  const restricted = f.pairs.length > 0 && (await restrictedDevices(tenantId, [deviceId])).has(deviceId);
  const items: BenchRequiredApp[] = [];
  let setAside = 0;
  for (const p of f.pairs) {
    if (p.availability !== 'available' || !p.entry) { setAside++; continue; }
    if (benchAppDecision(factsOf(f, p), restricted) !== 'due' || !p.pkg) { setAside++; continue; }
    items.push({
      packageId: String(p.pkg.id).toLowerCase(), packageName: p.pkg.package_name, versionCode: Number(p.pkg.version_code),
      versionName: p.pkg.version_name ?? null, sha256: String(p.pkg.sha256).trim(), size: Number(p.pkg.size_bytes),
      signerSha256: p.pkg.signer_sha256 ? String(p.pkg.signer_sha256).trim() : null, label: p.pkg.label ?? null, mode: p.entry.mode,
    });
  }
  items.sort((a, b) => (a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0));
  return { items, setAside };
}

// ── The reconciliation of a tenant ───────────────────────────────────────────

export interface ReconcileOutput {
  pairs: number;
  installed: number;
  queuedOpen: number;
  awaitingInventory: number;
  due: number;
  queued: number;
  deferred: number;
  backoff: number;
  failed: number;
  enqueueFailed: number;
  /** The devices asked for an inventory (skipped/stale_inventory, none asked yet). */
  inventoryRequested: number;
  skipped: Partial<Record<LegacyAgentRequiredAppReason, number>>;
  frozen: boolean;
}

type Log = Pick<typeof logger, 'info' | 'warn'>;

const emptyOutput = (): ReconcileOutput => ({
  pairs: 0, installed: 0, queuedOpen: 0, awaitingInventory: 0, due: 0, queued: 0, deferred: 0, backoff: 0, failed: 0, enqueueFailed: 0,
  inventoryRequested: 0, skipped: {}, frozen: false,
});

/** The budget of a pass (pure): the per-window limit less the installs of the window, and the open installs' cap less
 *  those open. */
export function installBudget(queuedInWindow: number, openOfJob: number): number {
  return Math.max(0, Math.min(REQUIRED_APPS_PER_RUN - queuedInWindow, REQUIRED_APPS_MAX_OPEN - openOfJob));
}

const ALERT = 'legacy_agent.required_app_failed' as const;

/**
 * The installs of a pass (pure): the due pairs in their order, without those an install already holds (`open`, keys
 * '<deviceId>|<packageName>'), the first `budget` chosen, the rest deferred to the next pass.
 */
export function planInstalls<T extends { deviceId: number; packageName: string }>(due: readonly T[], open: ReadonlySet<string>, budget: number):
  { chosen: T[]; deferred: T[]; alreadyOpen: T[] } {
  const out = { chosen: [] as T[], deferred: [] as T[], alreadyOpen: [] as T[] };
  for (const d of due) {
    if (open.has(`${d.deviceId}|${d.packageName}`)) out.alreadyOpen.push(d);
    else if (out.chosen.length < Math.max(0, budget)) out.chosen.push(d);
    else out.deferred.push(d);
  }
  return out;
}

/** The order of the due installs: silent installers first, then the most recent interrogation, the device, the list. */
export const byUrgency = (a: Pick<Evaluated, 'pair'>, b: Pick<Evaluated, 'pair'>): number =>
  Number(b.pair.device.silent) - Number(a.pair.device.silent) || (b.pair.device.lastPollAt ?? 0) - (a.pair.device.lastPollAt ?? 0)
  || a.pair.deviceId - b.pair.deviceId || a.pair.index - b.pair.index;

/**
 * One pass over a tenant (every device, or the devices given): the decisions, then the due installs queued within the
 * per-tenant budget, under the tenant's advisory lock. Never throws for one install (savepoint, counted enqueueFailed).
 */
export async function reconcileTenant(tenantId: number, dbActor: DbActor, opts: { deviceIds?: number[] }, log: Log = logger): Promise<ReconcileOutput> {
  const out = emptyOutput();
  const full = !opts.deviceIds;
  return asTenant(tenantId, dbActor, async () => {
    const f = await db.transaction((trx) => loadFacts(trx, tenantId, opts.deviceIds));
    out.frozen = f.frozen;
    if (f.pairs.length === 0) {
      if (full) await db.transaction((trx) => resolveInTx(trx, tenantId, ALERT));
      return out;
    }
    const evaluated = await evaluate(tenantId, f);
    out.pairs = evaluated.length;
    for (const e of evaluated) {
      switch (e.d.state) {
        case 'installed': out.installed++; break;
        case 'queued': out.queuedOpen++; break;
        case 'awaiting_inventory': out.awaitingInventory++; break;
        case 'due': out.due++; break;
        case 'backoff': out.backoff++; break;
        case 'failed': out.failed++; break;
        case 'skipped': if (e.d.reason) out.skipped[e.d.reason] = (out.skipped[e.d.reason] ?? 0) + 1; break;
      }
    }
    const due = evaluated.filter((e) => e.d.state === 'due').sort(byUrgency);
    const stale = [...new Set(evaluated.filter((e) => e.d.state === 'skipped' && e.d.reason === 'stale_inventory').map((e) => e.pair.deviceId))];
    let budget = 0;
    let considered = 0;
    await db.transaction(async (trx) => {
      await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [`legacy-agent.required-apps:${tenantId}`]);
      if (due.length > 0 && !f.frozen) {
        const recent = await trx('legacy_agent_commands')
          .where({ tenant_id: tenantId, request_type: 'app.install', origin: 'system', actor: REQUIRED_APPS_ACTOR })
          .where('created_at', '>', new Date(Date.now() - REQUIRED_APPS_WINDOW_MINUTES * 60_000)).count<{ n: string }[]>('* as n').first();
        // The installs of this job still open: the next ones wait for their results (a defective APK never reaches the
        // whole fleet before its first failures are known).
        const openOfJob = await trx('legacy_agent_commands')
          .where({ tenant_id: tenantId, request_type: 'app.install', origin: 'system', actor: REQUIRED_APPS_ACTOR })
          .whereIn('state', OPEN_STATES as string[]).where('created_at', '>', new Date(Date.now() - REQUIRED_APPS_OPEN_HOURS * HOUR_MS))
          .count<{ n: string }[]>('* as n').first();
        budget = installBudget(Number(recent?.n ?? 0), Number(openOfJob?.n ?? 0));
        // The installs opened since the read (another pass, a console request): never a second one.
        const open = await trx('legacy_agent_commands').where({ tenant_id: tenantId, request_type: 'app.install' })
          .whereIn('device_id', [...new Set(due.map((e) => e.pair.deviceId))]).whereIn('state', OPEN_STATES as string[])
          .select('device_id', trx.raw("params->>'packageName' AS package_name")) as Array<{ device_id: number; package_name: string }>;
        const plan = planInstalls(due.map((e) => ({ deviceId: e.pair.deviceId, packageName: e.pair.packageName, e })),
          new Set(open.map((o) => `${Number(o.device_id)}|${o.package_name}`)), budget);
        out.due -= plan.alreadyOpen.length;
        out.queuedOpen += plan.alreadyOpen.length;
        considered = plan.chosen.length + plan.deferred.length;
        const day = new Date().toISOString().slice(0, 10);
        // The budget applied by urgency, the queue by increasing device id: each enqueue locks the device's row (FOR
        // UPDATE) until the commit, in the order of the resolution's writer (lockDeviceRows), never a deadlock with it.
        const chosen = [...plan.chosen].sort((a, b) => a.deviceId - b.deviceId || a.e.pair.index - b.e.pair.index);
        const woken: number[] = [];
        for (const { e } of chosen) {
          const p = e.pair.pkg as PackageRow;
          const policy = e.pair.policy;
          const reason = `Required app ${p.package_name} ${p.version_name ?? String(p.version_code)} of the policy ${JSON.stringify(policy?.name ?? '')} (version ${policy?.version ?? '?'})`.slice(0, 500);
          try {
            const o = await trx.transaction((sp) => legacyAgentCommands.enqueue(sp, {
              tenantId, requestType: 'app.install', deviceIds: [e.pair.deviceId], params: installParamsOf(p), origin: 'system', actor: REQUIRED_APPS_ACTOR,
              reason, idempotencyKey: `required-app:${e.pair.deviceId}:${String(p.id).toLowerCase()}:${day}`,
            }));
            if (!o.replayed) {
              out.queued += o.targets;
              if (o.targets > 0 && !o.held) woken.push(e.pair.deviceId);
            }
          } catch (err) {
            out.enqueueFailed++;
            log.warn({ tenantId, deviceId: e.pair.deviceId, message: (err as Error)?.message?.slice(0, 200) }, 'legacy agent: required app not queued');
          }
        }
        // The long waits of these devices woken once the transaction committed (as a lock or an erase): the install
        // reaches a new device now, not at its next interrogation.
        if (woken.length > 0) wakeAfterCommit(trx, tenantId, [...new Set(woken)]);
      }
      // A full pass sets the count; a pass over one device raises it only when none is open (never a lower count) and
      // never resolves it.
      if (full) {
        if (out.failed > 0) await raiseInTx(trx, tenantId, ALERT, { params: { count: out.failed }, navigateTo: '/legacy-agent' });
        else await resolveInTx(trx, tenantId, ALERT);
      } else if (out.failed > 0) {
        const openAlert = await trx('live_alerts').where({ tenant_id: tenantId, kind: ALERT }).whereNull('resolved_at').first('id');
        if (!openAlert) await raiseInTx(trx, tenantId, ALERT, { params: { count: out.failed }, navigateTo: '/legacy-agent' });
      }
    });
    // An inventory asked of the devices whose last one is too old to decide (never twice: the ingestion clears it; the
    // pass that follows it decides on fresh facts). Its own transaction, after the queue's: no row of legacy_agent_devices
    // held while the enqueues lock the devices' rows.
    if (stale.length > 0 && !f.frozen) {
      out.inventoryRequested = await db.transaction((trx) => trx('legacy_agent_devices').where({ tenant_id: tenantId }).whereIn('device_id', stale)
        .whereNull('revoked_at').whereNull('inventory_requested_at').update({ inventory_requested_at: new Date() }));
      if (out.inventoryRequested > 0) log.info({ tenantId, devices: out.inventoryRequested }, 'legacy agent: inventory asked before a required app install');
    }
    out.deferred = Math.max(0, considered - budget);
    if (out.deferred > 0) log.info({ tenantId, deferred: out.deferred, budget }, 'legacy agent: required apps deferred by the per-run limit');
    if ((out.skipped.package_failing ?? 0) > 0) {
      log.warn({ tenantId, pairs: out.skipped.package_failing }, 'legacy agent: required apps held, the recent installs of their package fail');
    }
    // A tenant setting that sets every required app aside: said in the log (the device page and the editor show it too).
    const blocked = (out.skipped.inventory_limited ?? 0) + (out.skipped.restricted ?? 0);
    if (full && blocked > 0 && blocked === out.pairs - out.installed) {
      log.warn({ tenantId, inventoryLimited: out.skipped.inventory_limited ?? 0, restricted: out.skipped.restricted ?? 0 },
        'legacy agent: every missing required app of the tenant is set aside (privacy profile managed_only or restrictions matrix legacy_agent.apps)');
    }
    return out;
  });
}

// ── The jobs ─────────────────────────────────────────────────────────────────

/** The flat output of a job (the skipped pairs by reason as skipped_<reason>). */
function flat(o: ReconcileOutput, extra: Record<string, number | boolean> = {}): Record<string, number | boolean> {
  const { skipped, ...rest } = o;
  const out: Record<string, number | boolean> = { ...rest, ...extra };
  for (const [k, n] of Object.entries(skipped)) out[`skipped_${k}`] = n as number;
  return out;
}

export async function requiredAppsSweep(ctx: JobContext<Record<string, never>>): Promise<JobResult> {
  const total = emptyOutput();
  let tenants = 0;
  let frozenTenants = 0;
  const { failed } = await forEachTenant(ctx.dbActor, async (tenantId) => {
    ctx.throwIfAborted();
    const o = await reconcileTenant(tenantId, ctx.dbActor, {}, ctx.log);
    if (o.pairs === 0) return;
    tenants++;
    if (o.frozen) frozenTenants++;
    for (const k of ['pairs', 'installed', 'queuedOpen', 'awaitingInventory', 'due', 'queued', 'deferred', 'backoff', 'failed', 'enqueueFailed', 'inventoryRequested'] as const) {
      total[k] += o[k];
    }
    for (const [r, n] of Object.entries(o.skipped)) total.skipped[r as LegacyAgentRequiredAppReason] = (total.skipped[r as LegacyAgentRequiredAppReason] ?? 0) + (n as number);
  });
  const output = flat({ ...total, frozen: frozenTenants > 0 }, { tenants, frozenTenants });
  if (failed + total.enqueueFailed > 0) {
    ctx.log.warn(output, 'legacy agent: required apps partly done');
    throw new JobError('partial_failure', `${failed} tenant(s) and ${total.enqueueFailed} install(s) failed`);
  }
  return { output };
}

export type RequiredAppsTenantPayload = { tenantId: number; deviceId?: number };

export async function requiredAppsTenantRun(ctx: JobContext<RequiredAppsTenantPayload>): Promise<JobResult> {
  const o = await reconcileTenant(ctx.payload.tenantId, ctx.dbActor, { deviceIds: ctx.payload.deviceId ? [ctx.payload.deviceId] : undefined }, ctx.log);
  return { output: flat(o) };
}

// ── The triggers ─────────────────────────────────────────────────────────────

let tenantJob: JobHandle<RequiredAppsTenantPayload> | null = null;

/** The handle of legacy-agent.required-apps-tenant (registerLegacyAgentJobs). */
export function setRequiredAppsTenantJob(h: JobHandle<RequiredAppsTenantPayload>): void {
  tenantJob = h;
}

/**
 * A pass over one device once the outermost transaction committed (an inventory ingested), when the device has a
 * required app: no query in the caller's transaction, nothing on a rollback, never throws.
 */
export function requestRequiredAppsAfterCommit(trx: Knex.Transaction, tenantId: number, deviceId: number): void {
  try {
    let outer = trx as Knex.Transaction & { parentTransaction?: Knex.Transaction };
    while (outer.parentTransaction) outer = outer.parentTransaction as typeof outer;
    outer.executionPromise?.then(async () => {
      const job = tenantJob;
      if (!job || !defaultRuntime.isStarted()) return;
      const has = await asTenant(tenantId, LEGACY_AGENT_ACTOR, () => db('device_effective_settings')
        .where({ tenant_id: tenantId, device_id: deviceId, removed: false }).where('setting_key', 'like', `${AGENT_REQUIRED_APP_KEY_PREFIX}%`).first('device_id'));
      if (has) await job.send({ tenantId, deviceId }, { singletonKey: `t:${tenantId}:d:${deviceId}`, tenantId });
    }, () => undefined).catch((err) => logger.warn({ tenantId, deviceId, err: { message: (err as Error)?.message?.slice(0, 200) } },
      'legacy agent: required apps of a device not requested after its inventory'));
  } catch { /* never in the agent's way */ }
}

/** A pass over a tenant (after its resolution: a publication, an assignment, a group moved), when it has a required app. */
export async function requestRequiredAppsTenant(trx: Knex.Transaction, tenantId: number): Promise<string | null> {
  const job = tenantJob;
  if (!job || !defaultRuntime.isStarted()) return null;
  const has = await trx('device_effective_settings').where({ tenant_id: tenantId, removed: false })
    .where('setting_key', 'like', `${AGENT_REQUIRED_APP_KEY_PREFIX}%`).first('device_id');
  if (!has) return null;
  return job.sendInTx(trx, { tenantId }, { singletonKey: `t:${tenantId}`, tenantId });
}
