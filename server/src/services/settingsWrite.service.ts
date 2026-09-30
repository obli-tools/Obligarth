import type { Request } from 'express';
import { DEVICE_KEY_SETTING_KEYS, type DeviceKeySettingKey, type MetricThresholds, type ObliReachWebView2Mode } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';
import { appConfigService } from './appConfig.service';
import { WEBVIEW2_MODES, WEBVIEW2_MODE_KEY, noteWebView2Mode } from './oblireachWebView2.service';

// ── Platform settings writes (/api/admin/config, tenant.manage_settings) ───
//
// ONE implementation for the routes (appConfig.controller.ts) and for an
// approved `settings_update` request (approval.service.ts, executed as the
// requester, who must still be an active platform administrator). The
// Obligate API key and inbound secret never reach an approval: such a write
// asks a step-up instead (restriction.service, approvalSecrets.ts).

export const CONFIG_KEYS = [
  'allow_2fa', 'force_2fa', 'otp_smtp_server_id',
  'obligate_enabled',
  // Device-bound 2FA platform settings (docs/mobile/device-bound-2fa.md §9, [D15]).
  ...DEVICE_KEY_SETTING_KEYS,
  // ObliReach automatic install / update by the Obliance agent (platform-wide;
  // absent = on). Tenant / group / device: settings key 'oblireachAutoInstall'.
  'oblireach_auto_install',
  // ObliReach: install of the Microsoft Edge WebView2 runtime of the chat
  // window (platform-wide; absent = 'proactive'; no per-tenant switch).
  'oblireach_webview2_install',
] as const;

const BOOLEAN_KEYS: ReadonlySet<string> = new Set<string>(DEVICE_KEY_SETTING_KEYS);
/** Plain 'true' / 'false' switches stored as is in app_config. */
const PLAIN_BOOLEAN_KEYS: ReadonlySet<string> = new Set<string>(['oblireach_auto_install']);
/** Keys with a fixed list of values (stored as is). */
const ENUM_KEYS: Readonly<Record<string, readonly string[]>> = {
  oblireach_webview2_install: WEBVIEW2_MODES,
};

export type SettingsWriteCtx = {
  byUserId?: number | null;
  req?: Request;
  /** Approval executor: the audit rows' tenant (no request). */
  auditTenantId?: number | null;
  viaApproval?: boolean;
};

/** PUT /:key */
export async function writeConfigKey(key: string, value: unknown, ctx: SettingsWriteCtx = {}): Promise<void> {
  if (!(CONFIG_KEYS as readonly string[]).includes(key)) throw new AppError(400, `Unknown config key: ${key}`);
  if (value === undefined) throw new AppError(400, 'Missing value');
  if (BOOLEAN_KEYS.has(key)) {
    // Device keys: read as === 'true' everywhere — only 'true' / 'false' are stored.
    const v = String(value);
    if (v !== 'true' && v !== 'false') throw new AppError(400, `${key} must be 'true' or 'false'`);
    // Write, policy cache dropped, unverified keys revoked when attestation
    // becomes required ('policy', §6.7), audited.
    const { deviceKeyService } = await import('./deviceKey/deviceKey.service');
    await deviceKeyService.setDeviceKeySetting(key as DeviceKeySettingKey, v, {
      byUserId: ctx.byUserId ?? null, req: ctx.req, auditTenantId: ctx.auditTenantId ?? null, viaApproval: ctx.viaApproval,
    });
    return;
  }
  if (PLAIN_BOOLEAN_KEYS.has(key)) {
    const v = String(value);
    if (v !== 'true' && v !== 'false') throw new AppError(400, `${key} must be 'true' or 'false'`);
    await appConfigService.set(key, v);
    return;
  }
  if (ENUM_KEYS[key]) {
    const v = String(value);
    if (!ENUM_KEYS[key].includes(v)) throw new AppError(400, `${key} must be one of: ${ENUM_KEYS[key].join(', ')}`);
    await appConfigService.set(key, v);
    // Applied at once by the ObliReach hub (no cache delay).
    if (key === WEBVIEW2_MODE_KEY) noteWebView2Mode(v as ObliReachWebView2Mode);
    return;
  }
  await appConfigService.set(key, String(value));
}

/** PATCH /agent-global: only the known fields, as sent. */
export function agentGlobalPatch(body: Record<string, unknown>): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const k of ['checkIntervalSeconds', 'scanIntervalSeconds', 'heartbeatMonitoring', 'maxMissedPushes', 'notificationTypes']) {
    if (k in body) patch[k] = body[k];
  }
  return patch;
}

export type ObligatePatch = {
  url?: string | null; apiKey?: string | null; enabled?: boolean;
  inboundSecret?: string | null;
};

/** PUT /obligate: validated patch (AppError 400). */
export function obligatePatch(body: Record<string, unknown>): ObligatePatch {
  const patch: ObligatePatch = {};
  if ('url' in body) patch.url = (typeof body.url === 'string' ? body.url.trim() : '') || null;
  if ('apiKey' in body) patch.apiKey = (typeof body.apiKey === 'string' ? body.apiKey.trim() : '') || null;
  if ('enabled' in body) patch.enabled = !!body.enabled;
  // The former client id form ('raw' | 'sha256') is gone: always the public
  // id. 'raw' is refused outright so an old client cannot believe it applied.
  if (body.clientIdMode === 'raw') throw new AppError(400, 'The raw API key can no longer be sent as client_id');
  // Distinct inbound secret (Obligate → this server): a non-empty string
  // sets it, null clears it (the API key is then expected again), an
  // empty string keeps it (same as the API key field).
  if ('inboundSecret' in body) {
    const s = body.inboundSecret;
    if (s !== null && typeof s !== 'string') throw new AppError(400, 'inboundSecret must be a string or null');
    if (s === null) {
      patch.inboundSecret = null;
    } else {
      const trimmed = s.trim();
      if (trimmed.length > 0 && trimmed.length < 16) throw new AppError(400, 'inboundSecret must be at least 16 characters');
      if (trimmed) patch.inboundSecret = trimmed;
    }
  }
  return patch;
}

/** PUT /editable-extensions */
export async function writeEditableExtensions(extensions: unknown): Promise<string[]> {
  if (!Array.isArray(extensions)) throw new AppError(400, 'extensions must be an array of strings');
  return appConfigService.setEditableExtensions(extensions as string[]);
}

/**
 * PUT /global-thresholds (cascade layer 2), stored as a JSON string under
 * app_config['metric_thresholds_global'], validated with the same Zod schema
 * as the group + tenant editors. null / {} clears it. Returns the stored value.
 */
export async function writeGlobalThresholds(thresholds: unknown): Promise<MetricThresholds | null> {
  const { metricThresholdsSchema } = await import('../validators/group.schema');
  // Previous value — a change of a per-metric alerts switch (`notify`)
  // triggers a silent re-baseline of every device (only the currently
  // alerting ones are actually re-evaluated).
  const beforeRaw = await appConfigService.get('metric_thresholds_global');
  let before: MetricThresholds | null = null;
  if (beforeRaw) {
    try { before = JSON.parse(beforeRaw) as MetricThresholds; } catch { before = null; }
  }
  const afterSave = async (after: MetricThresholds | null) => {
    const { invalidateGlobalThresholdCache } = await import('./threshold.service');
    invalidateGlobalThresholdCache();
    const { metricAlertRebaseline } = await import('./metricAlertRebaseline.service');
    if (metricAlertRebaseline.notifyChanged(before, after)) {
      metricAlertRebaseline.schedule({ kind: 'all' }, 'global notify switch');
    }
  };
  // Treat null/undefined/{} as "clear" — drop the row so the resolver falls
  // through to the system default below it.
  if (thresholds == null || (typeof thresholds === 'object' && Object.keys(thresholds as object).length === 0)) {
    await appConfigService.set('metric_thresholds_global', '');
    await afterSave(null);
    return null;
  }
  const parsed = metricThresholdsSchema.safeParse(thresholds);
  if (!parsed.success) {
    const issues = parsed.error.errors.map((e) => `${e.path.join('.') || '<root>'}: ${e.message}`).join('; ');
    throw new AppError(400, `Invalid thresholds — ${issues}`);
  }
  await appConfigService.set('metric_thresholds_global', JSON.stringify(parsed.data));
  await afterSave(parsed.data as MetricThresholds);
  return parsed.data as MetricThresholds;
}

/**
 * A settings write as a two-step approval may keep it (gateSettingsWrite),
 * validated BEFORE anything is filed (AppError 400, as the direct write):
 *  - `body`: only the fields the write reads — never the Obligate API key or
 *    inbound secret (an approval never keeps a secret), never a field the
 *    caller added;
 *  - `description`: what the approved write will change (before → after);
 *  - `carriesSecret`: an Obligate API key or inbound secret is being SET —
 *    decided from these known fields only, never from the caller's names;
 *  - `otherChanges`: a non-secret field actually changes (Obligate address,
 *    switch, client-id form, inbound secret cleared).
 */
export async function prepareSettingsApproval(method: string, path: string, rawBody: unknown): Promise<{
  body: Record<string, unknown>; description: string; carriesSecret: boolean; otherChanges: boolean;
}> {
  const { change, short } = await import('./approvalDescribe');
  const raw = (rawBody && typeof rawBody === 'object' && !Array.isArray(rawBody)) ? rawBody as Record<string, unknown> : {};
  const m = String(method).toUpperCase();
  const join = (title: string, parts: Array<string | null>) => {
    const p = parts.filter((x): x is string => !!x);
    return p.length ? `${title} — ${p.join('; ')}` : `${title} (no change)`;
  };

  if (m === 'PATCH' && path === '/agent-global') {
    const body = agentGlobalPatch(raw);
    const before = await appConfigService.getAgentGlobal() as unknown as Record<string, unknown>;
    return {
      body, carriesSecret: false, otherChanges: true,
      description: join('Agent global defaults', Object.keys(body).map((k) => change(k, before[k], body[k]))),
    };
  }
  if (m === 'PUT' && path === '/obligate') {
    const patch = obligatePatch(raw);
    const cur = await appConfigService.getObligateRaw();
    const enabledNow = (await appConfigService.get('obligate_enabled')) === 'true';
    const body: Record<string, unknown> = {};
    const parts: Array<string | null> = [];
    if ('url' in patch) { body.url = patch.url ?? null; parts.push(change('SSO gateway address', cur.url, patch.url ?? null)); }
    if ('enabled' in patch) { body.enabled = patch.enabled; parts.push(change('SSO enabled', enabledNow, patch.enabled)); }
    if (patch.inboundSecret === null) {
      body.inboundSecret = null;
      parts.push(cur.inboundSecret ? 'inbound secret cleared (the API key is expected again)' : null);
    }
    const carriesSecret = !!patch.apiKey || typeof patch.inboundSecret === 'string';
    const otherChanges = parts.some((x) => !!x);
    return { body, carriesSecret, otherChanges, description: join('Obligate SSO settings', parts) };
  }
  if (m === 'PUT' && path === '/editable-extensions') {
    if (!Array.isArray(raw.extensions)) throw new AppError(400, 'extensions must be an array of strings');
    const exts = (raw.extensions as unknown[]).map(String);
    return {
      body: { extensions: exts }, carriesSecret: false, otherChanges: true,
      description: `File explorer editable extensions → ${short(exts, 400)} (${exts.length})`,
    };
  }
  if (m === 'PUT' && path === '/global-thresholds') {
    const t = raw.thresholds;
    const clear = t == null || (typeof t === 'object' && Object.keys(t as object).length === 0);
    if (!clear) {
      const { metricThresholdsSchema } = await import('../validators/group.schema');
      const parsed = metricThresholdsSchema.safeParse(t);
      if (!parsed.success) {
        const issues = parsed.error.errors.map((e) => `${e.path.join('.') || '<root>'}: ${e.message}`).join('; ');
        throw new AppError(400, `Invalid thresholds — ${issues}`);
      }
    }
    return {
      body: { thresholds: clear ? null : t }, carriesSecret: false, otherChanges: true,
      description: clear ? 'Global metric thresholds cleared (system defaults apply)' : `Global metric thresholds → ${short(t, 600)}`,
    };
  }
  const key = /^\/([a-z0-9_]+)$/.exec(path);
  if (m === 'PUT' && key) {
    const k = key[1];
    if (!(CONFIG_KEYS as readonly string[]).includes(k)) throw new AppError(400, `Unknown config key: ${k}`);
    if (raw.value === undefined) throw new AppError(400, 'Missing value');
    const isBool = BOOLEAN_KEYS.has(k) || PLAIN_BOOLEAN_KEYS.has(k);
    if (isBool && String(raw.value) !== 'true' && String(raw.value) !== 'false') {
      throw new AppError(400, `${k} must be 'true' or 'false'`);
    }
    if (ENUM_KEYS[k] && !ENUM_KEYS[k].includes(String(raw.value))) {
      throw new AppError(400, `${k} must be one of: ${ENUM_KEYS[k].join(', ')}`);
    }
    const value = isBool || ENUM_KEYS[k] ? String(raw.value) : raw.value;
    const before = await appConfigService.get(k);
    return {
      body: { value }, carriesSecret: false, otherChanges: true,
      description: `Platform setting ${change(k, before ?? null, String(value)) ?? `${k}: ${short(String(value))} (unchanged)`}`,
    };
  }
  throw new AppError(400, `settings write ${m} ${path} is not supported`);
}

/**
 * Replays a settings write (method + path under /api/admin/config + body)
 * — the approval executor. Unknown writes fail with a clear error.
 */
export async function applySettingsRequest(method: string, path: string, body: unknown, ctx: SettingsWriteCtx = {}): Promise<void> {
  const b = (body && typeof body === 'object' && !Array.isArray(body)) ? body as Record<string, unknown> : {};
  const m = String(method).toUpperCase();
  if (m === 'PATCH' && path === '/agent-global') { await appConfigService.setAgentGlobal(agentGlobalPatch(b)); return; }
  if (m === 'PUT' && path === '/obligate') { await appConfigService.patchObligateConfig(obligatePatch(b)); return; }
  if (m === 'PUT' && path === '/editable-extensions') { await writeEditableExtensions(b.extensions); return; }
  if (m === 'PUT' && path === '/global-thresholds') { await writeGlobalThresholds(b.thresholds); return; }
  const key = /^\/([a-z0-9_]+)$/.exec(path);
  if (m === 'PUT' && key) { await writeConfigKey(key[1], b.value, ctx); return; }
  throw new AppError(400, `settings write ${m} ${path} cannot be replayed from an approval`);
}
