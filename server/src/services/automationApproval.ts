import { db } from '../db';
import { logger } from '../utils/logger';
import {
  activeRequester, auditAs, refuse, requireTenantCapability,
  type ApprovalExecution, type BatchCommandPayload,
} from './approval.service';
import { hasValue, isSecretKey } from './approvalSecrets';

// ── Approvals of the automations (scripts, schedules, scenarios) ────────────
// The manual script run and the privacy-bypass switch of a scenario or a
// schedule, executed AS THE REQUESTER once a second administrator approved
// them (approval.service), and what a script run request may keep.
// Executors registered by modules/rmm.ts.

/**
 * Manual script run (POST /api/scripts/:id/execute): the bare `run_script`
 * command would carry only {scriptId, parameterValues} — the agent needs the
 * script content, interpreter and timeout, and the run must appear as a
 * script execution. Such a request goes through the same path as the direct
 * (non-restricted) run, as the requester (executeManualScriptRun).
 */
export function isManualScriptRun(action: string, payload: BatchCommandPayload): boolean {
  const p = payload.params ?? {};
  return action === 'run_script' && p.scriptId != null && (
    p.source === 'script_execute'
    // Requests filed before the marker existed: script id + parameter
    // values and no inline content (a raw command approval carries content).
    || (p.source === undefined && p.parameterValues !== undefined && p.content === undefined)
  );
}

export async function executeManualScriptRun(x: ApprovalExecution): Promise<void> {
  const { tenantId, requesterId: userId } = x;
  const payload = x.payload as BatchCommandPayload;
  const scriptId = Number(payload.params?.scriptId);
  if (!Number.isInteger(scriptId) || scriptId <= 0) refuse('Script run request without a valid script id');
  const parameterValues = (payload.params?.parameterValues && typeof payload.params.parameterValues === 'object')
    ? payload.params.parameterValues as Record<string, unknown>
    : {};
  let deviceIds = (payload.deviceIds ?? []).map(Number).filter((n) => Number.isInteger(n) && n > 0);
  deviceIds = await db('devices').where({ tenant_id: tenantId }).whereIn('id', deviceIds).pluck('id');
  // Rights may have changed while the request waited for its approver: the
  // requester still needs `execute` on each device (admins are unrestricted).
  const requester = await activeRequester(userId);
  if (!requester.isPlatformAdmin) {
    const { permissionService } = await import('./permission.service');
    const lacking = new Set(await permissionService.devicesLackingCapability(userId, deviceIds, 'execute'));
    if (lacking.size) {
      logger.warn({ scriptId, lacking: [...lacking] }, 'approved script run: requester lost execute on some devices — skipped');
      deviceIds = deviceIds.filter((id) => !lacking.has(id));
    }
  }
  if (!deviceIds.length) refuse('Approved script run: no device left to run on');
  // The approver reviewed THIS content: refuse if the script changed since.
  if (typeof payload.params?.contentSha256 === 'string') {
    const script = await db('scripts').where({ id: scriptId }).first('content') as { content: string | null } | undefined;
    const { createHash } = await import('crypto');
    const now = createHash('sha256').update(String(script?.content ?? '')).digest('hex');
    if (now !== payload.params.contentSha256) {
      refuse('Approved script run refused: the script was modified after the request');
    }
  }
  const { scheduleService } = await import('./schedule.service');
  await scheduleService.executeNow(scriptId, deviceIds, tenantId, parameterValues, userId);
}

// Generic setting flip — used today for the scenario / schedule
// `bypass_privacy_mode` toggle. Targets a row by (entityType, entityId)
// in the requester's tenant and overwrites a single column when the
// second admin approves. Keep the field list narrow on the executor
// side so an attacker can't repurpose approvals to flip unrelated rows.
export interface SettingChangePayload {
  entityType: 'scenario' | 'schedule';
  entityId: number;
  field: 'bypassPrivacyMode';
  value: boolean;
}

/** Apply a single approved setting flip (request type 'setting_change').
 *  Strict allowlist on (entityType, field) so an attacker who plants a
 *  malformed approval payload can't repurpose this to write arbitrary
 *  columns. */
export async function executeSettingChange(x: ApprovalExecution): Promise<void> {
  const { tenantId, requesterId } = x;
  const payload = x.payload as SettingChangePayload;
  if (payload.field !== 'bypassPrivacyMode' || typeof payload.value !== 'boolean') {
    refuse('Unsupported setting change');
  }
  const table = payload.entityType === 'scenario' ? 'scenarios'
              : payload.entityType === 'schedule' ? 'script_schedules'
              : null;
  if (!table) refuse('Unsupported setting change');
  // Rights re-checked as the requester, as the routes do: scripts.manage
  // in the tenant (route guard of PUT /scenarios/:id, PATCH /schedules/:id),
  // then — not a platform admin — the automation's targets.
  const requester = await requireTenantCapability(requesterId, tenantId, 'scripts.manage');
  const entityId = Number(payload.entityId);
  const row = Number.isInteger(entityId) && entityId > 0
    ? await db(table).where({ id: entityId, tenant_id: tenantId }).first('id', 'tenant_id', 'target_type', 'target_ids')
    : undefined;
  if (!row) refuse(`The ${payload.entityType} no longer exists`);
  if (!requester.isPlatformAdmin && payload.value === true) {
    const { permissionService } = await import('./permission.service');
    let denied: number | null = null;
    if (payload.entityType === 'scenario') {
      const { scenarioService } = await import('./scenario.service');
      const { scenarioDenialFor } = await import('./scenarioPermission.service');
      const runIds = await scenarioService.resolveTargetDevices(entityId, tenantId);
      const denial = await scenarioDenialFor(requesterId, { id: entityId, tenant_id: tenantId }, runIds);
      if (denial) denied = denial.deviceId;
    } else {
      const { scheduleService } = await import('./schedule.service');
      const ids = await scheduleService.resolveTargetDeviceIdsForAuthz(tenantId, row.target_type, row.target_ids);
      const lacking = await permissionService.devicesLackingCapability(requesterId, ids, 'execute');
      if (lacking.length) denied = lacking[0];
    }
    if (denied !== null) refuse(`The requester can no longer run this ${payload.entityType} on device #${denied}`);
  }
  const n = await db(table)
    .where({ id: payload.entityId, tenant_id: tenantId })
    .update({ bypass_privacy_mode: payload.value, updated_at: new Date() });
  if (!n) refuse(`The ${payload.entityType} no longer exists`);
  await auditAs(tenantId, requesterId, `${payload.entityType}.bypass_privacy_mode_changed`, {
    resourceType: payload.entityType, resourcePath: String(payload.entityId), details: { value: payload.value },
  });
}

/**
 * A manual script run's parameter values, as an approval may keep them
 * (approvalSecrets.ts: no secret ever sits in an approval):
 *  - `declared`: only the parameters the SCRIPT declares (a value the caller
 *    adds under another name never reaches the request);
 *  - `secretNames`: the declared parameters that carry a value and are
 *    secret — type 'secret', or a credential name chosen by the script's
 *    author (e.g. `ApiToken` typed 'string'). A run with any of them cannot
 *    wait for an approval: the value would sit in it.
 */
export async function scriptParamsForApproval(scriptId: number, parameterValues: unknown): Promise<{ declared: Record<string, unknown>; secretNames: string[] }> {
  const declared: Record<string, unknown> = {};
  const secretNames: string[] = [];
  if (!parameterValues || typeof parameterValues !== 'object' || Array.isArray(parameterValues)) return { declared, secretNames };
  const params = await db('script_parameters').where({ script_id: scriptId }).select('name', 'type') as Array<{ name: string; type: string }>;
  const values = parameterValues as Record<string, unknown>;
  for (const p of params) {
    if (!Object.prototype.hasOwnProperty.call(values, p.name)) continue;
    const v = values[p.name];
    if ((p.type === 'secret' || isSecretKey(p.name)) && hasValue(v)) { secretNames.push(p.name); continue; }
    declared[p.name] = v;
  }
  return { declared, secretNames };
}
