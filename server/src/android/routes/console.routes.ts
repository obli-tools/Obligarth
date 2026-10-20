// /api/android (tenant router: requireAuth, requireTenant), the reads of the Android console (lot AN-C2, section 12):
//   GET /onboarding                    the Android part of the onboarding assistant (identifiers and booleans only)
//   GET /policy-catalog                the catalog the policy editor generates its forms from (any member reads policies)
//   GET /enrollment-tokens?profileId=  the tokens of the tenant (never a value), newest first
//   GET /devices/pending-approval      the devices held until approved (long tokens, AN17)
//   GET /devices/:id                   the Android facet of a device record (minimised inventory)
//   GET /devices/:id/actions           the menu of the Android commands and guarded actions of a device
// Capabilities: mdm.integrations.manage (onboarding), mdm.enrollment.manage (tokens, approvals); a device is read by
// whoever sees it (team scopes; 404 otherwise, rls-tenant §11.5). Mounted under /api/android by routes/index.ts.
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import type {
  AndroidDeviceAction, AndroidDeviceView, AndroidEnrollmentTokenView, AndroidPendingDeviceView, DeviceCapability,
} from '@obligarth/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { tenantFrozen } from '../../guard/frozen';
import { permissionService } from '../../services/permission.service';
import { androidFormCatalog } from '../../mdm/android/formCatalog';
import { ANDROID_COMMANDS, refusalOf, type AndroidCommandType } from '../commands/catalog';
import { ANDROID_COMMAND_CAPABILITY, ANDROID_COMMAND_RESTRICTION } from '../commands/console';
import { ANDROID_GUARDED_DEFAULTS, type AndroidGuardedKey } from '../commands/guarded';
import { androidOnboardStep } from '../operations/raccord';
import { androidDeviceOf } from './deviceAccess';

const wrap = (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction): void => { fn(req, res).catch(next); };

const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : v ? new Date(String(v)).toISOString() : null);
const day = (v: unknown): string | null => {
  if (!v) return null;
  if (v instanceof Date) return `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`;
  return String(v).slice(0, 10);
};
const json = (v: unknown): unknown => (typeof v === 'string' ? JSON.parse(v) : v);
const str = (v: unknown): string | null => (typeof v === 'string' && v ? v.slice(0, 200) : null);

/** The guarded action of each command type (guard engine) and the menu entries that are not a command type. */
const GUARDED_OF: Partial<Record<AndroidCommandType, AndroidGuardedKey>> = {
  LOCK: 'mdm.device_lock', RESET_PASSWORD: 'mdm.reset_password', START_LOST_MODE: 'mdm.lost_mode_enable', WIPE: 'mdm.erase_device',
  RELINQUISH_OWNERSHIP: 'mdm.relinquish_ownership',
};

const TokenQuery = z.object({ profileId: z.string().uuid().optional() });

export function createAndroidConsoleRouter(): Router {
  const router = Router();
  const integrations = requireTenantCapability('mdm.integrations.manage');
  const enrollment = requireTenantCapability('mdm.enrollment.manage');

  router.get('/onboarding', integrations, wrap(async (req, res) => {
    res.json({ success: true, data: await androidOnboardStep(Number(req.tenantId)) });
  }));

  router.get('/policy-catalog', wrap(async (_req, res) => {
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.json({ success: true, data: androidFormCatalog() });
  }));

  router.get('/enrollment-tokens', enrollment, wrap(async (req, res) => {
    const q = TokenQuery.safeParse(req.query);
    if (!q.success) throw new AppError(400, 'Invalid input', 'invalidInput');
    let query = db('android_enrollment_tokens').where({ tenant_id: Number(req.tenantId) }).orderBy('created_at', 'desc').limit(500)
      .select('id', 'profile_id', 'kind', 'state', 'one_time', 'expires_at', 'uses', 'max_uses', 'requires_approval', 'end_user_id', 'created_at',
        'last_used_at', 'revoked_at');
    if (q.data.profileId) query = query.where({ profile_id: q.data.profileId.toLowerCase() });
    const rows = await query as Array<Record<string, unknown>>;
    const data: AndroidEnrollmentTokenView[] = rows.map((r) => ({
      id: String(r.id), profileId: String(r.profile_id), kind: r.kind as AndroidEnrollmentTokenView['kind'],
      state: r.state as AndroidEnrollmentTokenView['state'], oneTime: r.one_time === true, expiresAt: iso(r.expires_at) as string,
      uses: Number(r.uses ?? 0), maxUses: r.max_uses === null || r.max_uses === undefined ? null : Number(r.max_uses),
      requiresApproval: r.requires_approval === true, endUserId: r.end_user_id === null || r.end_user_id === undefined ? null : Number(r.end_user_id),
      createdAt: iso(r.created_at) as string, lastUsedAt: iso(r.last_used_at), revokedAt: iso(r.revoked_at),
    }));
    res.json({ success: true, data });
  }));

  router.get('/devices/pending-approval', enrollment, wrap(async (req, res) => {
    const tenantId = Number(req.tenantId);
    const rows = await db('android_devices as a')
      .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .leftJoin('android_enrollment_tokens as t', function j() { this.on('t.id', '=', 'a.enrollment_token_id').andOn('t.tenant_id', '=', 'a.tenant_id'); })
      .where({ 'a.tenant_id': tenantId, 'a.approval_state': 'pending' }).whereNull('a.released_at')
      .orderBy('a.enrolled_at', 'asc').limit(500)
      .select('a.device_id', 'd.display_name', 'd.device_name', 'd.model', 'a.amapi_ownership', 'a.enrollment_token_id', 't.profile_id', 'a.enrolled_at') as
      Array<Record<string, unknown>>;
    // Only the devices the caller sees (team scopes): an administrator sees them all.
    const ids = req.session.role === 'admin' ? 'all' : await permissionService.getVisibleDeviceIds(Number(req.session.userId), false);
    const visible = ids === 'all' ? null : new Set(ids.map(Number));
    const data: AndroidPendingDeviceView[] = rows.filter((r) => visible === null || visible.has(Number(r.device_id))).map((r) => ({
      deviceId: Number(r.device_id), displayName: str(r.display_name) ?? str(r.device_name), model: str(r.model),
      ownership: r.amapi_ownership as AndroidPendingDeviceView['ownership'], tokenId: r.enrollment_token_id ? String(r.enrollment_token_id) : null,
      profileId: r.profile_id ? String(r.profile_id) : null, enrolledAt: iso(r.enrolled_at) as string,
    }));
    res.json({ success: true, data });
  }));

  router.get('/devices/:id', wrap(async (req, res) => {
    const deviceId = await androidDeviceOf(req, req.params.id);
    const tenantId = Number(req.tenantId);
    const r = await db('android_devices as a')
      .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
      .where({ 'a.tenant_id': tenantId, 'a.device_id': deviceId })
      .first('a.*', 'd.management_mode') as Record<string, unknown> | undefined;
    if (!r) throw new AppError(404, 'Not found', 'notFound');
    const posture = json(r.security_posture) as { devicePosture?: unknown; risks?: unknown[] } | null;
    const software = json(r.software_info) as Record<string, unknown> | null;
    const nonCompliance = json(r.non_compliance);
    const reasons = json(r.policy_state_reasons);
    const amapiName = String(r.amapi_name ?? '');
    const view: AndroidDeviceView = {
      deviceId,
      amapiId: amapiName.split('/').pop() ?? '',
      mode: (['fully_managed', 'dedicated', 'work_profile_corporate', 'work_profile_personal'] as const)
        .find((m) => m === r.management_mode) ?? null,
      managementMode: r.amapi_management_mode as AndroidDeviceView['managementMode'],
      ownership: r.amapi_ownership as AndroidDeviceView['ownership'],
      apiLevel: r.api_level === null || r.api_level === undefined ? null : Number(r.api_level),
      securityPatchLevel: day(r.security_patch_level),
      state: str(r.state), appliedState: str(r.applied_state),
      approvalState: r.approval_state as AndroidDeviceView['approvalState'],
      policy: {
        name: str(r.policy_name)?.split('/').pop() ?? null,
        pushedVersion: r.pushed_policy_version === null || r.pushed_policy_version === undefined ? null : String(r.pushed_policy_version),
        appliedVersion: r.applied_policy_version === null || r.applied_policy_version === undefined ? null : String(r.applied_policy_version),
        state: r.policy_state as AndroidDeviceView['policy']['state'],
        reasons: Array.isArray(reasons) ? reasons.filter((x): x is string => typeof x === 'string').slice(0, 50) : [],
        pushedAt: iso(r.pushed_at), lastSyncAt: iso(r.last_policy_sync_at),
        compliant: typeof r.policy_compliant === 'boolean' ? r.policy_compliant : null,
      },
      posture: posture ? {
        devicePosture: str(posture.devicePosture),
        risks: Array.isArray(posture.risks) ? posture.risks.map((x) => (typeof x === 'string' ? x : str((x as { risk?: unknown })?.risk) ?? '')).filter(Boolean).slice(0, 20) : [],
      } : null,
      nonCompliance: Array.isArray(nonCompliance) ? nonCompliance.slice(0, 200).map((x: Record<string, unknown>) => ({
        ...(str(x.settingName) ? { settingName: str(x.settingName)! } : {}),
        ...(str(x.nonComplianceReason) ? { nonComplianceReason: str(x.nonComplianceReason)! } : {}),
        ...(str(x.packageName) ? { packageName: str(x.packageName)! } : {}),
        ...(str(x.specificNonComplianceReason) ? { specificNonComplianceReason: str(x.specificNonComplianceReason)! } : {}),
      })) : [],
      software: software ? {
        androidVersion: str(software.androidVersion), androidBuildNumber: str(software.androidBuildNumber),
        deviceKernelVersion: str(software.deviceKernelVersion),
      } : null,
      lastStatusReportAt: iso(r.last_status_report_at),
      enrolledAt: iso(r.enrolled_at) as string,
      releasedAt: iso(r.released_at), releaseReason: str(r.release_reason),
    };
    res.json({ success: true, data: view });
  }));

  router.get('/devices/:id/actions', wrap(async (req, res) => {
    const deviceId = await androidDeviceOf(req, req.params.id);
    const tenantId = Number(req.tenantId);
    const t = await db('devices as d')
      .leftJoin('android_devices as a', function j() { this.on('a.device_id', '=', 'd.id').andOn('a.tenant_id', '=', 'd.tenant_id'); })
      .where({ 'd.tenant_id': tenantId, 'd.id': deviceId })
      .first('d.management_channel', 'd.enrollment_state', 'd.ownership', 'd.management_mode', 'a.api_level', 'a.released_at', 'a.amapi_name', 'a.state') as
      Record<string, unknown> | undefined;
    if (!t || t.management_channel !== 'amapi') throw new AppError(404, 'Not found', 'notFound');
    const frozen = await tenantFrozen(null, tenantId, 'amapi');
    const isAdmin = req.session.role === 'admin';
    const userId = Number(req.session.userId);
    const canWrite = isAdmin || await permissionService.canWriteDevice(userId, deviceId, false);
    const has = async (cap: DeviceCapability): Promise<boolean> => canWrite && (isAdmin || permissionService.canUseCapability(userId, deviceId, false, cap));
    const target = {
      managementChannel: String(t.management_channel), enrollmentState: String(t.enrollment_state), released: t.released_at !== null || !t.amapi_name,
      ownership: String(t.ownership), mode: String(t.management_mode), apiLevel: t.api_level === null || t.api_level === undefined ? null : Number(t.api_level),
    };
    const actions: AndroidDeviceAction[] = [];
    for (const type of Object.keys(ANDROID_COMMANDS) as AndroidCommandType[]) {
      const spec = ANDROID_COMMANDS[type];
      const guarded = GUARDED_OF[type];
      const refusal = refusalOf(type, target);
      const unavailable = !(await has(ANDROID_COMMAND_CAPABILITY[type])) ? 'capabilityMissing' : refusal ?? (frozen ? 'frozen' : null);
      actions.push({ type, actionKey: guarded ?? ANDROID_COMMAND_RESTRICTION[type] ?? spec.action, guarded: spec.guarded, available: unavailable === null, unavailable });
    }
    // The removal from management (WIPE of the profile for a personal device, RELINQUISH_OWNERSHIP for a company device
    // with a personal profile; a company device leaves by an erase) and the disabling of the device (devices.patch).
    const enrolled = target.enrollmentState === 'enrolled' && !target.released;
    const removal = target.ownership === 'corporate' ? 'use_erase' : null;
    const removeCap = await has(ANDROID_GUARDED_DEFAULTS['mdm.remove_management'].deviceCapability as DeviceCapability);
    actions.push({ type: 'REMOVE_MANAGEMENT', actionKey: 'mdm.remove_management', guarded: true,
      available: removeCap && enrolled && removal === null && !frozen,
      unavailable: !removeCap ? 'capabilityMissing' : !enrolled ? 'not_enrolled' : removal ?? (frozen ? 'frozen' : null) });
    const disableCap = await has(ANDROID_GUARDED_DEFAULTS['mdm.android_disable'].deviceCapability as DeviceCapability);
    const disabled = t.state === 'DISABLED';
    actions.push({ type: disabled ? 'ENABLE' : 'DISABLE', actionKey: 'mdm.android_disable', guarded: true,
      available: disableCap && enrolled && !frozen,
      unavailable: !disableCap ? 'capabilityMissing' : !enrolled ? 'not_enrolled' : frozen ? 'frozen' : null });
    res.json({ success: true, data: actions });
  }));

  return router;
}
