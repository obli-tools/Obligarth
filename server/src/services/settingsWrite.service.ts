import type { Request } from 'express';
import { DEVICE_KEY_SETTING_KEYS, type DeviceKeySettingKey } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';
import { appConfigService, moduleConfigKey } from './appConfig.service';

// ── Platform settings writes (/api/admin/config, tenant.manage_settings) ───
//
// ONE implementation for the routes (appConfig.controller.ts) and for an
// approved `settings_update` request (approval.service.ts, executed as the
// requester, who must still be an active platform administrator). The
// Obligate API key and inbound secret never reach an approval: such a write
// asks a step-up instead (restriction.service, approvalSecrets.ts).
//
// A module adds its own settings: plain keys through PUT /:key
// (appConfig.service registerConfigKey) and named writes on their own path
// (registerSettingsWrite, e.g. PUT /global-thresholds), both gated and
// replayed like the core's.

/** The core's keys of PUT /:key (a module's keys: appConfig.service registerConfigKey). */
export const CONFIG_KEYS = [
  'allow_2fa', 'force_2fa', 'otp_smtp_server_id',
  'obligate_enabled',
  // Device-bound 2FA platform settings (docs/mobile/device-bound-2fa.md §9, [D15]).
  ...DEVICE_KEY_SETTING_KEYS,
] as const;

const BOOLEAN_KEYS: ReadonlySet<string> = new Set<string>(DEVICE_KEY_SETTING_KEYS);

/** A key PUT /:key accepts: the core's, or a module's. */
function isConfigKey(key: string): boolean {
  return (CONFIG_KEYS as readonly string[]).includes(key) || !!moduleConfigKey(key);
}

export type SettingsWriteCtx = {
  byUserId?: number | null;
  req?: Request;
  /** Approval executor: the audit rows' tenant (no request). */
  auditTenantId?: number | null;
  viaApproval?: boolean;
};

/** What a settings write files in an approval (prepareSettingsApproval). */
export type PreparedSettingsWrite = {
  body: Record<string, unknown>; description: string; carriesSecret: boolean; otherChanges: boolean;
};

/**
 * A module's named settings write (its own path under /api/admin/config,
 * served by the module's router behind gateSettingsWrite): how an approval
 * keeps it (prepare: validated, AppError 400, before anything is filed) and
 * how an approved request replays it (apply).
 */
export interface SettingsWriteDef {
  method: 'PUT' | 'PATCH';
  path: string;
  prepare: (raw: Record<string, unknown>) => Promise<PreparedSettingsWrite>;
  apply: (body: Record<string, unknown>, ctx: SettingsWriteCtx) => Promise<void>;
}

const namedWrites: SettingsWriteDef[] = [];

export function registerSettingsWrite(def: SettingsWriteDef): void {
  if (!/^\/[a-z0-9-]+$/.test(def.path)) throw new Error(`Invalid settings write path: ${def.path}`);
  if (namedWrites.some((w) => w.method === def.method && w.path === def.path)) {
    throw new Error(`Settings write ${def.method} ${def.path} registered twice`);
  }
  namedWrites.push(def);
}

function namedWrite(method: string, path: string): SettingsWriteDef | undefined {
  return namedWrites.find((w) => w.method === method && w.path === path);
}

/** PUT /:key */
export async function writeConfigKey(key: string, value: unknown, ctx: SettingsWriteCtx = {}): Promise<void> {
  if (!isConfigKey(key)) throw new AppError(400, `Unknown config key: ${key}`);
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
  const mod = moduleConfigKey(key);
  if (mod?.type === 'boolean') {
    const v = String(value);
    if (v !== 'true' && v !== 'false') throw new AppError(400, `${key} must be 'true' or 'false'`);
    await appConfigService.set(key, v);
    mod.afterWrite?.(v);
    return;
  }
  if (mod?.type === 'enum') {
    const values = mod.values ?? [];
    const v = String(value);
    if (!values.includes(v)) throw new AppError(400, `${key} must be one of: ${values.join(', ')}`);
    await appConfigService.set(key, v);
    // Applied at once by the module (no cache delay).
    mod.afterWrite?.(v);
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
export async function prepareSettingsApproval(method: string, path: string, rawBody: unknown): Promise<PreparedSettingsWrite> {
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
  // A module's named write (registerSettingsWrite).
  const named = namedWrite(m, path);
  if (named) return named.prepare(raw);
  const key = /^\/([a-z0-9_]+)$/.exec(path);
  if (m === 'PUT' && key) {
    const k = key[1];
    if (!isConfigKey(k)) throw new AppError(400, `Unknown config key: ${k}`);
    if (raw.value === undefined) throw new AppError(400, 'Missing value');
    const mod = moduleConfigKey(k);
    const isBool = BOOLEAN_KEYS.has(k) || mod?.type === 'boolean';
    const enumValues = mod?.type === 'enum' ? (mod.values ?? []) : null;
    if (isBool && String(raw.value) !== 'true' && String(raw.value) !== 'false') {
      throw new AppError(400, `${k} must be 'true' or 'false'`);
    }
    if (enumValues && !enumValues.includes(String(raw.value))) {
      throw new AppError(400, `${k} must be one of: ${enumValues.join(', ')}`);
    }
    const value = isBool || enumValues ? String(raw.value) : raw.value;
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
  const named = namedWrite(m, path);
  if (named) { await named.apply(b, ctx); return; }
  const key = /^\/([a-z0-9_]+)$/.exec(path);
  if (m === 'PUT' && key) { await writeConfigKey(key[1], b.value, ctx); return; }
  throw new AppError(400, `settings write ${m} ${path} cannot be replayed from an approval`);
}
