// The gateway of the google and fake modes (the same class: only the base URLs and the access token differ). Every
// operation passes, in order (section 5.4): ownership (the enterprise is the current tenant's, issued by the
// registry; identifiers validated; names built by names.ts), freeze lock, last-resort caps, limiter, call, removal of
// the sensitive fields of the answer. Never inside an open transaction of the caller (G-A1): the short transactions
// of the freeze lock and the caps are its own.
import type {
  AmapiApplication, AmapiCommand, AmapiDevice, AmapiEnrollmentToken, AmapiEnrollmentTokenPartial, AmapiEnterprise,
  AmapiEnterpriseBasic, AmapiOperation, AmapiPolicy, AmapiProvisioningInfoMin, Page, PubsubReceived,
} from '@obligarth/shared/dist/android/amapi';
import { db } from '../../db';
import { currentDbContext } from '../../db/context';
import { autoFreeze } from '../../guard/freeze';
import { readSettings } from '../../guard/settings';
import { policyHasWipeSettings } from '../../mdm/android/overlay';
import { logger } from '../../utils/logger';
import { raiseAndroidPlatformAlert, raiseAndroidTenantAlert } from '../alerts';
import { byodCommandRefusal, byodPolicyViolations } from '../byod/policy';
import type { AndroidConfig } from '../config';
import { amapiClient, type AmapiClient } from '../google/amapi';
import { GoogleHttp } from '../google/http';
import { pubsubClient, type PubsubClient } from '../google/pubsub';
import { GoogleTokenProvider, type SealedKeyLoader } from '../google/token';
import {
  AndroidDestructiveCapError, AndroidError, AndroidFrozenError, AndroidNotFoundError, AndroidOwnershipError,
  AndroidQuotaError, AndroidRequestError,
} from './errors';
import { commandEnterpriseStates } from './commandStates';
import { takeTokens } from './limiter';
import { checkId, checkPolicyId, enterpriseIdOf, names, parseOwnedName, type AndroidEnterpriseRef, type PolicyId } from './names';
import { redactEnterprise, redactProvisioningInfo, redactTokenListItem } from './redact';
import { isIssuedEnterpriseRef } from './refs';
import type {
  AndroidGateway, AndroidLinkHealth, CallClass, EnrollmentTokenRequest, EnterpriseCreateRequest, EnterprisePatch,
  EnterprisePatchField, IframeFeature, LimiterClass, SignupUrlRequest, UserFacingMessage,
} from './types';

/** Notification types every enterprise of the instance enables. */
export const NOTIFICATION_TYPES = ['ENROLLMENT', 'STATUS_REPORT', 'COMMAND', 'USAGE_LOGS', 'ENTERPRISE_UPGRADE'] as const;
/** Command types the freeze lock refuses (AN15). */
export const FROZEN_COMMANDS: ReadonlySet<string> = new Set(['WIPE', 'RESET_PASSWORD', 'LOCK', 'RELINQUISH_OWNERSHIP', 'START_LOST_MODE']);
const PATCH_FIELDS: ReadonlySet<string> = new Set(['enterpriseDisplayName', 'logo', 'primaryColor', 'termsAndConditions', 'signinDetails']);
const IFRAME_FEATURES: ReadonlySet<string> = new Set(['PLAY_SEARCH', 'PRIVATE_APPS', 'WEB_APPS', 'STORE_BUILDER', 'MANAGED_CONFIGURATIONS',
  'ZERO_TOUCH_CUSTOMER_MANAGEMENT']);
const CLEANUP_AGE_MS = 270 * 86_400_000;
const CLEANUP_CAP_PER_HOUR = 100;
const DURATION_RE = /^[0-9]{1,10}(\.[0-9]{1,9})?s$/;

type DestructiveKind = 'wipe' | 'relinquish' | 'delete' | 'disable' | 'cleanup';

/** Does a policy body carry a wipe-capable setting (section 22.4: the closed list of JSON paths of the overlay, one
 *  list for the validation and the freeze lock)? */
export { policyHasWipeSettings };

/** Quota of the project and limit of the tenant (AN49, section 13.3): the platform settings androidProjectDeviceQuota
 *  and androidDeviceLimit, read by the source the module installs (the platform settings arrive at the junction
 *  AN-A2: shared/src/settings is an existing file). null: no quota known, nothing refused. */
export interface AndroidQuota { projectQuota: number | null; tenantLimit: number | null }
let quotaOf: (tenantId: number) => Promise<AndroidQuota | null> = async () => null;
export function setAndroidQuotaSource(fn: (tenantId: number) => Promise<AndroidQuota | null>): void { quotaOf = fn; }

/** Android devices of the tenant not released (AN47 cap base). Replaced at lot AN-C1 (android_devices). */
let deviceCountOf: (tenantId: number) => Promise<number> = async () => 0;
export function setAndroidDeviceCounter(fn: (tenantId: number) => Promise<number>): void { deviceCountOf = fn; }

/**
 * Lot AN-F1 (EX-A7, criterion 6): is the device a personal one (work profile on a personal device)? The instance's
 * record (the device, or its quarantine), read in a short transaction of its own in the tenant's context; null when
 * the instance has no record of it (the caller then reads Google's resource).
 */
async function personalOfRecord(e: AndroidEnterpriseRef, name: string): Promise<boolean | null> {
  return db.transaction(async (trx) => {
    const r = await trx('android_devices as a').join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where({ 'a.tenant_id': e.tenantId, 'a.amapi_name': name }).first('d.ownership') as { ownership: string } | undefined;
    if (r) return r.ownership === 'personal';
    const q = await trx('android_quarantine').where({ tenant_id: e.tenantId, amapi_name: name }).first('amapi_ownership') as
      { amapi_ownership: string | null } | undefined;
    return q ? q.amapi_ownership === 'PERSONALLY_OWNED' : null;
  });
}

/** Lot AN-F1: does a policy id name the own policy of a personal device (d-<devices.uuid>) or the enrollment policy of a
 *  BYOD profile (e-<profile id>)? */
async function personalPolicyId(e: AndroidEnterpriseRef, policyId: string): Promise<boolean> {
  const m = /^([de])-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(policyId);
  if (!m) return false;
  return db.transaction(async (trx) => {
    const r = m[1] === 'd'
      ? await trx('devices').where({ tenant_id: e.tenantId, uuid: m[2] }).first('ownership')
      : await trx('enrollment_profiles').where({ tenant_id: e.tenantId, id: m[2] }).first('ownership');
    return (r as { ownership?: string } | undefined)?.ownership === 'personal';
  });
}

function personalRefusal(e: AndroidEnterpriseRef, reason: string, field?: string): AndroidRequestError {
  logger.warn({ android: { personal: reason, tenantId: e.tenantId } }, 'android: an operation on a personal device was refused');
  void raiseAndroidPlatformAlert('android.ownership_violation', { reason, tenantId: e.tenantId });
  return new AndroidRequestError(reason, { reason, ...(field ? { field } : {}) });
}

export class GoogleGateway implements AndroidGateway {
  readonly mode: 'google' | 'fake';
  readonly http: GoogleHttp;
  readonly tokens: GoogleTokenProvider;
  private readonly amapi: AmapiClient;
  private readonly pubsub: PubsubClient;

  constructor(private readonly cfg: AndroidConfig, loadKey: SealedKeyLoader) {
    if (cfg.mode === 'off') throw new Error('GoogleGateway: mode off');
    this.mode = cfg.mode;
    this.tokens = new GoogleTokenProvider(cfg, loadKey);
    this.http = new GoogleHttp(this.tokens, cfg.mode === 'fake');
    this.amapi = amapiClient(this.http, cfg.amapiBaseUrl);
    this.pubsub = pubsubClient(this.http, cfg.pubsubBaseUrl, String(cfg.subscription), cfg.pullMaxBytes);
  }

  // ── Checks ───────────────────────────────────────────────────────────────

  /** Lot AN-F1: personal by the instance's record, else by Google's resource (an own field, not a method of the
   *  prototype: the closed list of the gateway's operations is unchanged). */
  private readonly personalDevice = async (e: AndroidEnterpriseRef, deviceId: string): Promise<boolean> => {
    const name = names.device(e, deviceId);
    const known = await personalOfRecord(e, name);
    if (known !== null) return known;
    await this.limit('device', e, deviceId);
    const d = await this.amapi.getDevice(name);
    return d?.ownership === 'PERSONALLY_OWNED';
  };

  /** Step 1: the enterprise is the current tenant's, issued by the registry, in an allowed state. */
  private own(e: AndroidEnterpriseRef, states: ReadonlyArray<AndroidEnterpriseRef['state']> = ['linked']): AndroidEnterpriseRef {
    if (!isIssuedEnterpriseRef(e)) throw this.violation('enterprise not issued by the registry', null);
    const ctx = currentDbContext();
    if (!ctx || ctx.kind !== 'tenant' || ctx.tenantId !== e.tenantId) throw this.violation('enterprise of another context', e.tenantId);
    if (!states.includes(e.state)) throw new AndroidNotFoundError('enterprise not linked');
    enterpriseIdOf(e);
    return e;
  }

  private violation(reason: string, tenantId: number | null): AndroidOwnershipError {
    logger.warn({ android: { ownership: reason, tenantId } }, 'android: ownership check refused a call');
    void raiseAndroidPlatformAlert('android.ownership_violation', { reason, ...(tenantId ? { tenantId } : {}) });
    return new AndroidOwnershipError(reason);
  }

  /** A received full name must belong to the tenant's enterprise. */
  private owned(e: AndroidEnterpriseRef, full: string): ReturnType<typeof parseOwnedName> {
    try {
      return parseOwnedName(e, full);
    } catch (err) {
      if (err instanceof AndroidOwnershipError) throw this.violation(String(err.details.reason ?? 'name'), e.tenantId);
      throw err;
    }
  }

  /** Step 2: freeze lock (AN15), read in a short transaction of its own just before the call. */
  private async freezeLock(e: AndroidEnterpriseRef, op: string): Promise<void> {
    if (await this.frozen(e)) throw new AndroidFrozenError(op);
  }

  private frozen(e: AndroidEnterpriseRef): Promise<boolean> {
    return db.transaction(async (trx) => {
      const s = await readSettings(e.tenantId, trx);
      return !!s.frozen_at;
    });
  }

  /**
   * AN15 (contre-revue AN-C1a, REV-C1a-S2): under a freeze, attaching a device to a policy (devices.patch of
   * policyName) is refused when that policy carries a wipe-capable setting (policyHasWipeSettings, the list of the
   * validation and of putPolicy): otherwise a device would receive the wipe-capable settings of a policy already
   * published (another device's, an e-*) without any policies.patch. The policy is read at Google (the truth,
   * whoever wrote it); an unreadable or absent policy is refused too (fail closed). Not frozen: nothing read.
   */
  private async policyAttachLock(e: AndroidEnterpriseRef, policyName: string): Promise<void> {
    if (!(await this.frozen(e))) return;
    await this.limit('policy', e, policyName);
    let policy: AmapiPolicy | null;
    try {
      policy = await this.amapi.getPolicy(policyName);
    } catch {
      throw new AndroidFrozenError('devices.patch (policyName: policy unreadable under a freeze)');
    }
    if (!policy || policyHasWipeSettings(policy)) throw new AndroidFrozenError('devices.patch (policyName to a wipe-capable policy)');
  }

  /** Step 3: last-resort cap (AN47), counted and compared in one short transaction. */
  private async destructiveCap(e: AndroidEnterpriseRef, kind: DestructiveKind): Promise<void> {
    const devices = kind === 'cleanup' ? 0 : await deviceCountOf(e.tenantId);
    const cap = kind === 'cleanup' ? CLEANUP_CAP_PER_HOUR : Math.max(5, Math.floor(devices / 10));
    const count = await db.transaction(async (trx) => {
      await trx('android_enterprises').where({ id: e.id, tenant_id: e.tenantId }).forUpdate().first('id');
      const r = await trx('android_destructive_events')
        .where({ tenant_id: e.tenantId, enterprise_id: e.id, kind })
        .where('at', '>', trx.raw("now() - interval '1 hour'"))
        .count<{ n: string }[]>('* as n');
      const n = Number(r[0]?.n ?? 0);
      if (n >= cap) return n;
      await trx('android_destructive_events').insert({ tenant_id: e.tenantId, enterprise_id: e.id, kind });
      return -1;
    });
    if (count >= 0) {
      void raiseAndroidPlatformAlert('android.gateway_cap_reached', { tenantId: e.tenantId, kind, count }, `t${e.tenantId}:${kind}`);
      void raiseAndroidTenantAlert(e.tenantId, 'android.gateway_cap_reached', { kind, count });
      // AN47: the tenant is frozen by the anomaly rule A1 (the cleanups are spread, never a defect: no freeze). Awaited
      // before the refusal, so that the caller (and anything after it) sees the freeze; autoFreeze never throws.
      if (kind !== 'cleanup') await autoFreeze(e.tenantId, 'A1');
      throw new AndroidDestructiveCapError(kind, count, cap);
    }
  }

  /** Step 4: quota of the project (android_project_device_count, all tenants: a number only) and limit of the tenant. */
  private async quotaCheck(e: AndroidEnterpriseRef): Promise<void> {
    const q = await quotaOf(e.tenantId);
    if (!q || (q.projectQuota === null && q.tenantLimit === null)) return;
    const { project, tenant } = await db.transaction(async (trx) => {
      const r = await trx.raw('SELECT obligarth.android_project_device_count() AS n');
      const t = await trx('android_devices').where({ tenant_id: e.tenantId }).whereNull('released_at').count<{ n: string }[]>('* as n');
      return { project: Number(r.rows?.[0]?.n ?? 0), tenant: Number(t[0]?.n ?? 0) };
    });
    if (q.projectQuota !== null && project >= q.projectQuota) {
      void raiseAndroidPlatformAlert('android.quota_exhausted', { count: project }, 'project');
      throw new AndroidQuotaError();
    }
    if (q.projectQuota !== null && project >= Math.floor(q.projectQuota * 0.8)) void raiseAndroidPlatformAlert('android.quota_warning', { count: project }, 'project');
    if (q.tenantLimit !== null && tenant >= q.tenantLimit) throw new AndroidQuotaError('device limit of the tenant reached');
  }

  /** Step 5: limiter. */
  private limit(action: string, e: AndroidEnterpriseRef | null, resource: string | null, cls: LimiterClass = 'standard'): Promise<void> {
    const key = e ? `k:${action}:${enterpriseIdOf(e)}:${resource ?? '-'}` : null;
    return takeTokens({ projectPer100s: this.cfg.rateProjectPer100s }, key, cls);
  }

  private requireNone(op: string): void {
    const ctx = currentDbContext();
    if (!ctx || ctx.kind !== 'none') throw this.violation(`${op} outside the platform context`, ctx?.tenantId ?? null);
  }

  // ── Health ─────────────────────────────────────────────────────────────────

  async health(): Promise<AndroidLinkHealth> {
    let permission: boolean | null = null;
    try { permission = await this.checkSubscription(); } catch { permission = false; }
    return { mode: this.mode, identity: this.tokens.identity(), breaker: this.http.breaker(), subscriptionPermission: permission };
  }

  async checkSubscription(): Promise<boolean> {
    const perms = await this.pubsub.testIamPermissions(['pubsub.subscriptions.consume']);
    return perms.includes('pubsub.subscriptions.consume');
  }

  // ── Enterprises ────────────────────────────────────────────────────────────

  async createSignupUrl(req: SignupUrlRequest): Promise<{ name: string; url: string }> {
    if (!req.allowedDomains.length || req.allowedDomains.some((d) => !/^(\*\.)?[a-z0-9.-]{1,253}$/.test(d))) {
      throw new AndroidRequestError('invalid allowed domains');
    }
    await this.limit('signup', null, null, 'interactive');
    const r = await this.amapi.createSignupUrl(String(this.cfg.projectId), req.callbackUrl, req.adminEmail, req.allowedDomains);
    if (!r || typeof r.name !== 'string' || !/^signupUrls\/[A-Za-z0-9_-]{1,200}$/.test(r.name) || typeof r.url !== 'string' || !/^https:\/\//.test(r.url)) {
      throw new AndroidRequestError('unexpected signup URL answer');
    }
    return { name: r.name, url: r.url };
  }

  async createEnterprise(req: EnterpriseCreateRequest): Promise<AmapiEnterprise> {
    if (typeof req.enterpriseToken !== 'string' || !/^[A-Za-z0-9_.~-]{1,2048}$/.test(req.enterpriseToken)) {
      throw new AndroidRequestError('invalid enterprise token');
    }
    if (!/^signupUrls\/[A-Za-z0-9_-]{1,200}$/.test(req.signupUrlName)) throw new AndroidRequestError('invalid signup URL name');
    await this.limit('enterprise-create', null, null, 'interactive');
    // Without pubsubTopic: the topic is set by android.enterprise-setup once the enterprise is bound.
    const body: Partial<AmapiEnterprise> = {
      enterpriseDisplayName: req.enterpriseDisplayName.slice(0, 100),
      ...(req.primaryColor !== undefined ? { primaryColor: req.primaryColor } : {}),
      ...(req.logo ? { logo: req.logo } : {}),
    };
    const r = await this.amapi.createEnterprise(String(this.cfg.projectId), req.signupUrlName, req.enterpriseToken, body);
    if (!r || typeof r.name !== 'string' || !/^enterprises\/[A-Za-z0-9_-]{1,100}$/.test(r.name)) throw new AndroidRequestError('unexpected enterprise answer');
    return redactEnterprise(r);
  }

  async listProjectEnterprises(pageToken?: string): Promise<Page<AmapiEnterpriseBasic>> {
    this.requireNone('enterprises.list');
    await this.limit('enterprise-list', null, null, 'background');
    const r = await this.amapi.listEnterprises(String(this.cfg.projectId), pageToken);
    const items = (r?.enterprises ?? []).filter((x) => typeof x?.name === 'string')
      .map((x) => ({ name: x.name, ...(typeof x.enterpriseDisplayName === 'string' ? { enterpriseDisplayName: x.enterpriseDisplayName } : {}) }));
    return { items, ...(r?.nextPageToken ? { nextPageToken: r.nextPageToken } : {}) };
  }

  async getEnterprise(e: AndroidEnterpriseRef): Promise<AmapiEnterprise> {
    this.own(e, ['linked', 'unlinking', 'error']);
    await this.limit('enterprise-get', e, null);
    const r = await this.amapi.getEnterprise(names.enterprise(e));
    if (!r) throw new AndroidNotFoundError('enterprise not found');
    return redactEnterprise(r);
  }

  async patchEnterprise(e: AndroidEnterpriseRef, patch: EnterprisePatch, mask: EnterprisePatchField[]): Promise<AmapiEnterprise> {
    this.own(e);
    if (!mask.length || mask.some((m) => !PATCH_FIELDS.has(m))) throw new AndroidRequestError('field outside the enterprise patch mask');
    const body: Record<string, unknown> = {};
    for (const m of mask) body[m] = (patch as Record<string, unknown>)[m];
    await this.limit('enterprise-patch', e, null);
    const r = await this.amapi.patchEnterprise(names.enterprise(e), body, mask);
    return redactEnterprise(r ?? { name: e.name });
  }

  async setEnterpriseNotifications(e: AndroidEnterpriseRef, on: boolean): Promise<void> {
    this.own(e, ['linked', 'unlinking']);
    await this.limit('enterprise-patch', e, null);
    const body = on ? { pubsubTopic: String(this.cfg.topic), enabledNotificationTypes: [...NOTIFICATION_TYPES] }
      : { pubsubTopic: '', enabledNotificationTypes: [] };
    await this.amapi.patchEnterprise(names.enterprise(e), body, ['pubsubTopic', 'enabledNotificationTypes']);
  }

  async upgradeUrl(e: AndroidEnterpriseRef): Promise<{ url: string }> {
    this.own(e);
    await this.limit('enterprise-upgrade', e, null, 'interactive');
    const r = await this.amapi.upgradeUrl(names.enterprise(e));
    if (typeof r?.url !== 'string' || !/^https:\/\//.test(r.url)) throw new AndroidRequestError('unexpected upgrade answer');
    return { url: r.url };
  }

  // ── Policies ───────────────────────────────────────────────────────────────

  async putPolicy(e: AndroidEnterpriseRef, policyId: PolicyId, policy: AmapiPolicy): Promise<{ version: string }> {
    this.own(e);
    const name = names.policy(e, checkPolicyId(policyId));
    if (policyHasWipeSettings(policy)) await this.freezeLock(e, 'policies.patch (wipe-capable settings)');
    // Lot AN-F1: a policy of a personal device never carries a setting that acts on the whole device nor asks for a
    // report a personal device never sends (byod/policy.ts; policies/push.ts already withholds them).
    const violations = byodPolicyViolations((policy ?? {}) as Record<string, unknown>);
    if (violations.length && await personalPolicyId(e, String(policyId))) throw personalRefusal(e, 'byod_policy_refused', violations[0]);
    await this.limit('policy', e, policyId);
    const { name: _n, version: _v, ...body } = policy ?? {};
    const r = await this.amapi.patchPolicy(name, body);
    return { version: String(r?.version ?? '') };
  }

  async deletePolicy(e: AndroidEnterpriseRef, policyId: PolicyId): Promise<void> {
    this.own(e, ['linked', 'unlinking']);
    const name = names.policy(e, checkPolicyId(policyId));
    await this.limit('policy', e, policyId);
    await this.amapi.deletePolicy(name);
  }

  // ── Enrollment tokens ──────────────────────────────────────────────────────

  async createEnrollmentToken(e: AndroidEnterpriseRef, t: EnrollmentTokenRequest): Promise<AmapiEnrollmentToken> {
    this.own(e);
    if (!DURATION_RE.test(t.duration)) throw new AndroidRequestError('invalid duration');
    if (typeof t.additionalData !== 'string' || !/^obg1:[0-9a-f-]{36}$/.test(t.additionalData)) throw new AndroidRequestError('invalid additionalData');
    const policyName = t.policyId ? names.policy(e, checkPolicyId(t.policyId)) : undefined;
    await this.freezeLock(e, 'enrollmentTokens.create');
    await this.quotaCheck(e);
    await this.limit('token', e, null, 'interactive');
    const r = await this.amapi.createEnrollmentToken(names.enterprise(e), {
      duration: t.duration, additionalData: t.additionalData,
      ...(policyName ? { policyName } : {}),
      ...(t.oneTimeOnly !== undefined ? { oneTimeOnly: t.oneTimeOnly } : {}),
      ...(t.allowPersonalUsage ? { allowPersonalUsage: t.allowPersonalUsage } : {}),
    });
    if (!r?.name) throw new AndroidRequestError('unexpected enrollment token answer');
    this.owned(e, r.name);
    return r;
  }

  async deleteEnrollmentToken(e: AndroidEnterpriseRef, tokenId: string): Promise<void> {
    this.own(e, ['linked', 'unlinking']);
    const name = names.enrollmentToken(e, tokenId);
    await this.limit('token', e, tokenId);
    await this.amapi.deleteEnrollmentToken(name);
  }

  async listEnrollmentTokens(e: AndroidEnterpriseRef, pageToken?: string): Promise<Page<AmapiEnrollmentTokenPartial>> {
    this.own(e, ['linked', 'unlinking']);
    await this.limit('token-list', e, null, 'background');
    const r = await this.amapi.listEnrollmentTokens(names.enterprise(e), pageToken);
    const items = (r?.enrollmentTokens ?? []).map(redactTokenListItem).filter((x) => {
      try { this.owned(e, x.name); return true; } catch { return false; }
    });
    return { items, ...(r?.nextPageToken ? { nextPageToken: r.nextPageToken } : {}) };
  }

  async getEnrollmentToken(e: AndroidEnterpriseRef, tokenId: string): Promise<AmapiEnrollmentToken | null> {
    this.own(e, ['linked', 'unlinking']);
    const name = names.enrollmentToken(e, tokenId);
    await this.limit('token', e, tokenId);
    return this.amapi.getEnrollmentToken(name);
  }

  // ── Devices ────────────────────────────────────────────────────────────────

  async getDevice(e: AndroidEnterpriseRef, deviceId: string): Promise<AmapiDevice | null> {
    this.own(e, ['linked', 'unlinking', 'error']);
    const name = names.device(e, deviceId);
    await this.limit('device', e, deviceId);
    const r = await this.amapi.getDevice(name);
    if (r && r.policyName) this.owned(e, r.policyName);
    return r;
  }

  async listDevices(e: AndroidEnterpriseRef, pageToken?: string): Promise<Page<AmapiDevice>> {
    this.own(e, ['linked', 'unlinking', 'error']);
    await this.limit('device-list', e, null, 'background');
    const r = await this.amapi.listDevices(names.enterprise(e), pageToken);
    const items = (r?.devices ?? []).filter((d) => { try { this.owned(e, d.name); return true; } catch { return false; } });
    return { items, ...(r?.nextPageToken ? { nextPageToken: r.nextPageToken } : {}) };
  }

  async patchDevice(e: AndroidEnterpriseRef, deviceId: string,
    patch: { policyName?: PolicyId; state?: 'ACTIVE' | 'DISABLED'; disabledReason?: UserFacingMessage }): Promise<AmapiDevice> {
    this.own(e);
    const name = names.device(e, deviceId);
    const body: Record<string, unknown> = {};
    const mask: string[] = [];
    if (patch.policyName !== undefined) { body.policyName = names.policy(e, checkPolicyId(patch.policyName)); mask.push('policyName'); }
    if (patch.state !== undefined) {
      if (patch.state !== 'ACTIVE' && patch.state !== 'DISABLED') throw new AndroidRequestError('invalid device state');
      body.state = patch.state;
      mask.push('state');
      if (patch.disabledReason) { body.disabledReason = patch.disabledReason; mask.push('disabledReason'); }
    }
    if (!mask.length) throw new AndroidRequestError('empty device patch');
    if (patch.state !== undefined) await this.freezeLock(e, 'devices.patch (state)');
    if (patch.policyName !== undefined) await this.policyAttachLock(e, String(body.policyName));
    if (patch.state === 'DISABLED') await this.destructiveCap(e, 'disable');
    await this.limit('device', e, deviceId);
    const r = await this.amapi.patchDevice(name, body, mask);
    return r ?? { name };
  }

  async deleteDevice(e: AndroidEnterpriseRef, deviceId: string,
    o: { purpose: 'operator' | 'cleanup'; supersededBy?: string; wipeDataFlags?: string[]; wipeReasonMessage?: string }): Promise<void> {
    this.own(e, ['linked', 'unlinking']);
    const name = names.device(e, deviceId);
    if (o.wipeDataFlags?.some((f) => !/^[A-Z_]{1,64}$/.test(f))) throw new AndroidRequestError('invalid wipe flags');
    // Lot AN-F1: never a wipe data flag for a personal device (the deletion removes its work profile only).
    await this.freezeLock(e, 'devices.delete');
    if (o.wipeDataFlags?.length && await this.personalDevice(e, deviceId)) throw personalRefusal(e, 'personal_full_wipe');
    if (o.purpose === 'cleanup') {
      // The caller's label is not believed: devices.delete tries to wipe the device (RR-4).
      await this.limit('device', e, deviceId);
      const current = await this.amapi.getDevice(name);
      if (current) {
        let admitted = current.appliedState === 'DELETED';
        const last = Date.parse(String(current.lastStatusReportTime ?? current.enrollmentTime ?? ''));
        if (!admitted && Number.isFinite(last) && Date.now() - last > CLEANUP_AGE_MS) admitted = true;
        if (!admitted && o.supersededBy) {
          const successor = await this.amapi.getDevice(names.device(e, checkId(o.supersededBy, 'device')));
          if (successor && Array.isArray(successor.previousDeviceNames) && successor.previousDeviceNames.includes(name)) admitted = true;
        }
        if (!admitted) {
          void raiseAndroidPlatformAlert('android.ownership_violation', { reason: 'cleanup_refused', tenantId: e.tenantId });
          throw new AndroidRequestError('cleanup_refused', { reason: 'cleanup_refused' });
        }
      }
      await this.destructiveCap(e, 'cleanup');
    } else {
      await this.destructiveCap(e, 'delete');
    }
    await this.limit('device', e, deviceId);
    await this.amapi.deleteDevice(name, o.wipeDataFlags, o.wipeReasonMessage?.slice(0, 200));
  }

  // ── Commands and operations ────────────────────────────────────────────────

  async issueCommand(e: AndroidEnterpriseRef, deviceId: string, cmd: AmapiCommand): Promise<{ operation: string }> {
    // Review AN-H1 (H1R-1): WIPE and RELINQUISH_OWNERSHIP stay admitted while the enterprise is unlinking (§6.5 step 2).
    this.own(e, commandEnterpriseStates(cmd?.type));
    const name = names.device(e, deviceId);
    if (!cmd || typeof cmd.type !== 'string' || !/^[A-Z_]{1,40}$/.test(cmd.type)) throw new AndroidRequestError('invalid command type');
    if (typeof cmd.duration !== 'string' || !DURATION_RE.test(cmd.duration)) throw new AndroidRequestError('a command needs an explicit duration');
    if (FROZEN_COMMANDS.has(cmd.type)) await this.freezeLock(e, `issueCommand ${cmd.type}`);
    // Lot AN-F1 (EX-A7): a personal device takes LOCK, CLEAR_APP_DATA and the WIPE of its work profile only (no wipe
    // data flag), whatever the caller (the bus and the submission refused it already). Read only for a command a
    // personal device would not take.
    const byodWhy = byodCommandRefusal(cmd);
    if (byodWhy && await this.personalDevice(e, deviceId)) throw personalRefusal(e, byodWhy);
    if (cmd.type === 'WIPE') await this.destructiveCap(e, 'wipe');
    if (cmd.type === 'RELINQUISH_OWNERSHIP') await this.destructiveCap(e, 'relinquish');
    await this.limit('command', e, deviceId, 'interactive');
    const r = await this.amapi.issueCommand(name, cmd);
    if (!r?.name) throw new AndroidRequestError('unexpected command answer');
    const parsed = this.owned(e, r.name);
    if (parsed.kind !== 'operation' || parsed.deviceId !== deviceId) throw this.violation('operation of another device', e.tenantId);
    return { operation: r.name };
  }

  async listOperations(e: AndroidEnterpriseRef, deviceId: string, pageToken?: string): Promise<Page<AmapiOperation>> {
    this.own(e, ['linked', 'unlinking']);
    const name = names.device(e, deviceId);
    await this.limit('operation', e, deviceId, 'background');
    const r = await this.amapi.listOperations(name, pageToken);
    const items = (r?.operations ?? []).filter((op) => { try { this.owned(e, op.name); return true; } catch { return false; } });
    return { items, ...(r?.nextPageToken ? { nextPageToken: r.nextPageToken } : {}) };
  }

  async getOperation(e: AndroidEnterpriseRef, operationName: string): Promise<AmapiOperation | null> {
    this.own(e, ['linked', 'unlinking']);
    const p = this.owned(e, operationName);
    if (p.kind !== 'operation') throw this.violation('not an operation name', e.tenantId);
    await this.limit('operation', e, p.deviceId);
    return this.amapi.getOperation(names.operation(e, p.deviceId, p.operationId));
  }

  async cancelOperation(e: AndroidEnterpriseRef, operationName: string): Promise<'cancelled' | 'already_done'> {
    this.own(e, ['linked', 'unlinking']);
    const p = this.owned(e, operationName);
    if (p.kind !== 'operation') throw this.violation('not an operation name', e.tenantId);
    const name = names.operation(e, p.deviceId, p.operationId);
    await this.limit('operation', e, p.deviceId, 'interactive');
    try {
      await this.amapi.cancelOperation(name);
      return 'cancelled';
    } catch (err) {
      if (err instanceof AndroidError && err.kind === 'request' && err.details.conflict) return 'already_done';
      throw err;
    }
  }

  // ── Iframes, applications, provisioning ───────────────────────────────────

  async createWebToken(e: AndroidEnterpriseRef, w: { parentFrameUrl: string; enabledFeatures: IframeFeature[] }): Promise<{ value: string }> {
    this.own(e);
    // Lot AN-E1: in every mode (Google refuses another scheme: « The URL must use the https scheme »), and never a
    // token without features (Google opens them all, the zero-touch iframe included).
    if (!/^https:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?\/[A-Za-z0-9/-]{0,200}$/.test(w.parentFrameUrl)) throw new AndroidRequestError('parentFrameUrl must be an https page URL');
    if (!Array.isArray(w.enabledFeatures) || w.enabledFeatures.length === 0 || w.enabledFeatures.some((f) => !IFRAME_FEATURES.has(f))) {
      throw new AndroidRequestError('enabledFeatures must list known features');
    }
    await this.limit('webtoken', e, null, 'interactive');
    const r = await this.amapi.createWebToken(names.enterprise(e), { parentFrameUrl: w.parentFrameUrl, enabledFeatures: w.enabledFeatures });
    if (typeof r?.value !== 'string') throw new AndroidRequestError('unexpected web token answer');
    return { value: r.value };
  }

  async getApplication(e: AndroidEnterpriseRef, packageName: string, languageCode: string): Promise<AmapiApplication> {
    this.own(e);
    const name = names.application(e, packageName);
    if (!/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/.test(languageCode)) throw new AndroidRequestError('invalid language code');
    await this.limit('application', e, packageName, 'background');
    const r = await this.amapi.getApplication(name, languageCode);
    if (!r) throw new AndroidNotFoundError('application not found');
    return r;
  }

  async provisioningInfo(e: AndroidEnterpriseRef, id: string): Promise<AmapiProvisioningInfoMin> {
    this.own(e);
    checkId(id, 'provisioning info');
    await this.limit('provisioning', e, null, 'interactive');
    const r = await this.amapi.provisioningInfo(id);
    try {
      return redactProvisioningInfo(r, e.name);
    } catch (err) {
      if (r) void raiseAndroidPlatformAlert('android.ownership_violation', { reason: 'foreign_provisioning_info', tenantId: e.tenantId });
      throw err;
    }
  }

  // ── Pub/Sub (the project's subscription) ───────────────────────────────────

  async pull(o: { maxMessages: number; signal?: AbortSignal }): Promise<PubsubReceived[]> {
    this.requireNone('pubsub.pull');
    return this.pubsub.pull(Math.max(1, Math.min(1000, o.maxMessages)), o.signal);
  }

  async modifyAckDeadline(ackIds: string[], seconds: number): Promise<void> {
    await this.pubsub.modifyAckDeadline(ackIds, seconds);
  }

  async acknowledge(ackIds: string[]): Promise<void> {
    await this.pubsub.acknowledge(ackIds);
  }

  async seek(time: Date): Promise<void> {
    this.requireNone('pubsub.seek');
    await this.pubsub.seek(time);
  }
}
