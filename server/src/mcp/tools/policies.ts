import type { Request } from 'express';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ASSIGNMENT_PRIORITY, LEGACY_AGENT_POLICY_LIMITS as L, POLICY_PUBLISH_ACTION, POLICY_STATES, isAgentTemplateVariable, parseAgentKey,
  variablesInString, type AssignmentChange, type JsonValue, type LegacyAgentPolicySection, type PolicyContentV1, type PolicyImpact,
} from '@obligarth/shared';
import { audit } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { legacyAgentContributions } from '../../mdm/legacyAgent/contributions';
import { listAssignments } from '../../mdm/policies/assignments';
import { conflictsOf, describeKeys, type AssignmentDelta } from '../../mdm/policies/impact';
import { loadResolutionInput } from '../../mdm/policies/loader';
import { policyService, type PolicyActor } from '../../mdm/policies/policyService';
import {
  changeAssignments, emitPolicyChanged, previewAssignments, previewSubmission, requireWriteOnAssignedTargets, submitVersion, type PolicyBase,
  type RouteOutcome,
} from '../../mdm/policies/publish';
import { resolveDevices } from '../../mdm/policies/resolver';
import { hasSecretValue } from '../../mdm/policies/validate';
import { fileView, receiveBytes } from '../../legacyAgent/files';
import { customKeysOf, devicePolicyStatus, listStoreFiles, renderPreviewFor, renderPreviewsFor, storeReceivedFile } from '../../legacyAgent/policyRoutes';
import { accessKeyDetail, mcpAuditCtx } from '../audit';
import { createPending } from '../authorizations/service';
import { holdsTenantCapability, requireScope, targetIds, withTenant, type McpCaller } from '../caller';
import { deviceFilter, resolveCallerDevice } from '../perimeter';
import { AUTHORIZE_MESSAGE, deviceId, takeWrite, tenantId } from './common';
import { identifiersAllowed, notSupported } from './devices';
import { READ, js, page, registerTool } from './index';
import type { ExecContext, ExecResult } from './writes';

// =============================================================================
// The policies through the MCP server (lot P1-MCP-POL, spec P1-QR-SITES §3 bis): the console's own services
// (mdm/policies/policyService.ts, publish.ts, legacyAgent/policyRoutes.ts), the same validation, the same preview,
// the same thresholds of approval (PUBLISH_APPROVAL_THRESHOLDS) and the same audit; nothing here weakens the console.
//   reads (policies.read)      list_policies, get_policy, get_policy_version, list_policy_files, list_custom_keys,
//                              get_device_policy: as any member of the tenant, within the key's perimeter.
//   drafts (policies.write)    create_policy, create_policy_version, update_policy_version, validate_policy_version,
//                              render_policy_preview, policy_version_impact, upload_policy_file: mdm.policies.manage,
//                              no second factor (nothing reaches a device), journaled with the key's actor.
//   publication (policies.publish) submit_policy_version, change_policy_assignments: dry_run true by default answers
//                              the preview; dry_run false never publishes: ONE authorization the human approves with a
//                              second factor, then the console's submission runs as him (its step-up proven by that
//                              factor, mdm.policy_publish only), bound to the content and the digest of the impact he
//                              was shown (policyChanged otherwise, nothing written); beyond the thresholds it files the
//                              console's approval for another person (state 'filed'). A publication reaches every
//                              device the policy is assigned to: a key limited to groups or devices cannot ask it.
// Secrets: never read nor written. A content or a patch that holds a value typed in ({"$secretValue"}) is refused; a
// secret is only referenced by a reference already in the vault ({"$secret": "<uuid>"}), checked in the tenant.
// =============================================================================

const WRITE = { readOnlyHint: false, openWorldHint: false as const };
const POLICY_MANAGE = 'mdm.policies.manage' as const;
/** The bytes of one upload: the JSON parser of /mcp takes 256 kB a request (router.ts), the base64 text included. */
export const MCP_UPLOAD_BYTES = 180 * 1024;
/** The patches of one update_policy_version. */
const PATCHES_MAX = 50;

const POLICY_TOOLS = ['submit_policy_version', 'change_policy_assignments'] as const;
type PolicyTool = typeof POLICY_TOOLS[number];
export const isPolicyTool = (t: string): t is PolicyTool => (POLICY_TOOLS as readonly string[]).includes(t);

const policyId = z.number().int().positive().max(2147483647);
const versionNo = z.number().int().positive().max(1_000_000);
const sha = z.string().regex(/^[0-9a-f]{64}$/);

// ── Arguments ────────────────────────────────────────────────────────────────

const Patch = z.object({ key: z.string().min(7).max(400), value: z.unknown() }).strict();
/** A change of assignment of a policy (never an app: their options may hold secrets). */
const McpChange = z.object({
  op: z.enum(['create', 'update', 'delete']), id: z.number().int().positive().optional(), policy_id: policyId.optional(),
  policy_tenant_id: z.number().int().positive().optional(), target_scope: z.enum(['tenant', 'group', 'device', 'smart_group']).optional(),
  target_id: z.number().int().positive().nullable().optional(), mode: z.enum(['include', 'exclude']).optional(),
  priority: z.number().int().min(ASSIGNMENT_PRIORITY.min).max(ASSIGNMENT_PRIORITY.max).optional(),
}).strict();
/** The changes as an authorization stores them (the console's shape, resources of type policy only). */
const StoredChange = z.object({
  op: z.enum(['create', 'update', 'delete']), id: z.number().int().positive().optional(), resourceType: z.literal('policy').optional(),
  resourceId: z.number().int().positive().optional(), resourceTenantId: z.number().int().positive().optional(),
  targetScope: z.enum(['tenant', 'group', 'device', 'smart_group']).optional(), targetId: z.number().int().positive().nullable().optional(),
  mode: z.enum(['include', 'exclude']).optional(), priority: z.number().int().min(ASSIGNMENT_PRIORITY.min).max(ASSIGNMENT_PRIORITY.max).optional(),
}).strict();

const ARGS = {
  submit_policy_version: z.object({ tenant_id: tenantId, policy_id: policyId, version: versionNo, dry_run: z.boolean().optional() }).strict(),
  change_policy_assignments: z.object({ tenant_id: tenantId, changes: z.array(McpChange).min(1).max(100), dry_run: z.boolean().optional() }).strict(),
};

/** What an authorization of the policies stores as its arguments: the request and what the human was shown. */
export const POLICY_APPROVABLE_ARGS: Record<PolicyTool, z.ZodTypeAny> = {
  submit_policy_version: z.object({ tenant_id: tenantId, policy_id: policyId, version: versionNo, content_sha256: sha, digest: sha }).strict(),
  change_policy_assignments: z.object({ tenant_id: tenantId, changes: z.array(StoredChange).min(1).max(100), digest: sha }).strict(),
};

// ── Secrets, patches ─────────────────────────────────────────────────────────

/** 400 secretValueRefused: the MCP never writes a secret value, only a reference already in the vault. */
export function refuseSecretValues(v: unknown): void {
  if (hasSecretValue(v)) {
    throw new AppError(400, 'A secret value is never written through the MCP: reference a secret of the vault ({"$secret": "<id>"}) or type it in the console', 'secretValueRefused');
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const badPatch = (key: string, why: string): never => {
  throw new AppError(400, `Invalid setting ${key}: ${why}`, 'invalidSetting', { key });
};

/** The list with the item matching `match` replaced (in place), added at the end, or removed (item null). */
function upsertBy<T>(list: T[] | undefined, match: (x: T) => boolean, item: T | null): T[] {
  const out = [...(list ?? [])];
  const i = out.findIndex(match);
  if (item === null) { if (i >= 0) out.splice(i, 1); return out; }
  if (i >= 0) out[i] = item; else out.push(item);
  return out;
}

/**
 * One setting of the section of the bridge agent set or removed (value null) by its key, as the resolution names it
 * (agent:file[<id>], agent:wifi[<ssid>], agent:wifi.remove[<ssid>], agent:kiosk, agent:dpm.<field>, agent:knox.<field>,
 * agent:cert[<id>], agent:appconfig:<id>). The value is the setting as get_policy_version shows it (the id or the SSID of an instance comes
 * from the key). The section is then validated by the console's saving of the draft.
 */
export function patchAgentSection(section: LegacyAgentPolicySection | undefined | null, key: string, value: unknown): LegacyAgentPolicySection {
  const p = parseAgentKey(key);
  if (!p) badPatch(key, 'unknown setting key');
  const s = JSON.parse(JSON.stringify(section ?? {})) as LegacyAgentPolicySection & Record<string, unknown>;
  const remove = value === null;
  if (!remove && p!.family !== 'wifi.remove' && p!.family !== 'dpm' && p!.family !== 'knox' && !isObj(value)) badPatch(key, 'an object or null is expected');
  const v = value as Record<string, unknown>;
  const set = <K extends keyof LegacyAgentPolicySection>(k: K, list: unknown[]): void => {
    if (list.length) (s as Record<string, unknown>)[k] = list; else delete (s as Record<string, unknown>)[k];
  };
  switch (p!.family) {
    case 'file':
      set('files', upsertBy(s.files, (f) => f?.id === p!.instance, remove ? null : { ...v, id: p!.instance } as never));
      break;
    case 'appconfig':
      set('appConfigs', upsertBy(s.appConfigs, (a) => a?.id === p!.instance, remove ? null : { ...v, id: p!.instance } as never));
      break;
    case 'cert':
      set('certs', upsertBy(s.certs, (c) => c?.id === p!.instance, remove ? null : { ...v, id: p!.instance } as never));
      break;
    case 'wifi':
      set('wifi', upsertBy(s.wifi, (w) => w?.ssid === p!.instance, remove ? null : { ...v, ssid: p!.instance } as never));
      break;
    case 'wifi.remove':
      if (!remove && value !== true) badPatch(key, 'true or null is expected');
      set('wifiRemove', upsertBy(s.wifiRemove, (x) => x === p!.instance, remove ? null : p!.instance!));
      break;
    case 'kiosk':
      if (remove) delete s.kiosk; else s.kiosk = v as never;
      break;
    case 'dpm':
    case 'knox': {
      const rec = { ...((s[p!.family] as Record<string, JsonValue> | undefined) ?? {}) };
      if (remove) delete rec[p!.field!]; else rec[p!.field!] = value as JsonValue;
      if (Object.keys(rec).length) (s as Record<string, unknown>)[p!.family] = rec; else delete s[p!.family];
      break;
    }
    default:
      // A family parseAgentKey knows and this switch does not (a later family, until it is handled here): refused,
      // never a draft saved unchanged as if the patch had applied.
      badPatch(key, 'this setting is not patched here: change it with the whole content');
  }
  return s;
}

/** The content of a version with patches of the agent section applied (a copy; the stored version is not changed). */
export function patchedContent(content: PolicyContentV1, patches: Array<{ key: string; value: unknown }>): PolicyContentV1 {
  const out = JSON.parse(JSON.stringify(content)) as PolicyContentV1;
  let section = out.sections?.legacyAgent;
  for (const p of patches) section = patchAgentSection(section, p.key, p.value);
  out.sections = { ...(out.sections ?? {}), legacyAgent: section } as PolicyContentV1['sections'];
  return out;
}

/** The settings of the agent section as the resolution keys them (value as the version stores it: secrets as references). */
const agentSettingsOf = (content: PolicyContentV1 | null | undefined) =>
  legacyAgentContributions(content?.sections?.legacyAgent).map((c) => ({ key: c.settingKey, value: c.value, variables: c.variables }));

// ── Rights and perimeter ─────────────────────────────────────────────────────

/** A publication reaches every device the policy is assigned to: a key limited to groups or devices cannot. */
function requireWholeTenant(key: { groupMode: string; deviceMode: string }): void {
  if (key.groupMode !== 'all' || key.deviceMode !== 'all') {
    throw new AppError(403, 'Only a key that reaches every group and device of the tenant may publish policies or change their assignments', 'perimeterTooNarrow');
  }
}

/** Is the human an administrator of the tenant (as the console's assignment list asks)? */
async function isTenantAdmin(caller: Pick<McpCaller, 'userId' | 'isPlatformAdmin'>, tenant: number): Promise<boolean> {
  if (caller.isPlatformAdmin) return true;
  const ut = await db('user_tenants').where({ user_id: caller.userId, tenant_id: tenant }).first('role') as { role: string } | undefined;
  return ut?.role === 'admin';
}

const actorOf = async (caller: McpCaller, tenant: number, tool: string): Promise<PolicyActor> =>
  ({ userId: caller.userId, auditCtx: await mcpAuditCtx(caller, tenant, tool) });

/** A write refused for rights or perimeter is journaled (mcp.tool.denied), as the other write tools. */
async function denied(caller: McpCaller, tenant: number, tool: string, err: unknown): Promise<void> {
  const e = err as { statusCode?: number; code?: string };
  if (!(err instanceof AppError) || (e.statusCode !== 400 && e.statusCode !== 403 && e.statusCode !== 404)) return;
  if (e.statusCode === 400 && e.code !== 'secretValueRefused') return;
  try {
    await audit.append({
      tenantId: tenant, action: 'mcp.tool.denied', outcome: 'denied',
      details: { tool, code: e.code ?? null, status: e.statusCode, accessKey: accessKeyDetail(caller) },
    }, await mcpAuditCtx(caller, tenant, tool));
  } catch { /* spooled by the writer */ }
}

/** A draft or publication tool: the scope and its need, then the work; a refusal of rights is journaled. */
async function policyWrite<T>(caller: McpCaller, tool: string, tenant: number, scope: 'policies.write' | 'policies.publish', run: () => Promise<T>,
  counted = true): Promise<T> {
  if (counted) takeWrite(caller);
  try {
    return await withTenant(caller, tenant, async () => {
      await requireScope(caller, tenant, scope, POLICY_MANAGE);
      return run();
    });
  } catch (err) {
    await withTenant(caller, tenant, () => denied(caller, tenant, tool, err)).catch(() => undefined);
    throw err;
  }
}

const tenantLabel = async (tenant: number): Promise<string> => {
  const t = await db('tenants').where({ id: tenant }).first('name') as { name: string } | undefined;
  return t ? ` (tenant ${t.name})` : '';
};

const quotedName = (s: string): string => `"${s.replace(/[\u0000-\u001f\u007f"]/g, ' ').slice(0, 80)}"`;

/** The closed variables that carry a device identifier (decision D10): masked in a preview without devices.identifiers. */
const IDENTIFIER_VARIABLES: ReadonlySet<string> = new Set(['device.serial_number', 'device.udid']);

/** The identifier variables a template names that its preview renders masked: all of them unless `allowed` (the key
 *  carries devices.identifiers and the human holds devices.manage, as the device tools ask), asked only when needed. */
export async function previewMask(template: string, allowed: () => Promise<boolean>): Promise<Set<string>> {
  const named = variablesInString(template, isAgentTemplateVariable).known.filter((n) => IDENTIFIER_VARIABLES.has(n));
  return named.length && !(await allowed()) ? new Set(named) : new Set();
}

/** The summary of an authorization, 500 characters at most. */
const SUMMARY_MAX = 500;

/** One change of a batch in the words of the summary the human approves: the change, the policy, the target, the mode. */
export function describeDelta(d: AssignmentDelta, base: PolicyBase[]): string {
  const a = (d.after ?? d.before)!;
  const op = !d.before ? 'add' : !d.after ? 'remove' : 'change';
  const b = base.find((x) => x.policyId === a.resourceId && x.tenantId === a.resourceTenantId);
  const policy = `${b ? `${quotedName(b.name)} ` : ''}#${a.resourceId}`;
  const target = a.targetScope === 'tenant' ? 'the tenant' : `${a.targetScope === 'smart_group' ? 'dynamic group' : a.targetScope} #${a.targetId}`;
  const mode = d.before && d.after && (d.before.mode !== d.after.mode || d.before.priority !== d.after.priority)
    ? `${d.before.mode}/${d.before.priority} -> ${d.after.mode}/${d.after.priority}` : `${a.mode}, priority ${a.priority}`;
  return `${op} ${policy} on ${target} (${mode})`;
}

/**
 * The summary the human reads before approving with a second factor (the console's approval tells the same: the
 * policies, the counts, the keys): the head, then as many of the changes as fit ("+n more"), the counts, the setting
 * keys (describeKeys: never an instance), the thresholds and the tenant, within SUMMARY_MAX.
 */
export function fitSummary(head: string, items: string[], impact: PolicyImpact, tail: string): string {
  const counts = `${impact.devicesTouched} device(s) touched, ${impact.artifacts.removals} removal(s)`;
  const beyond = impact.approval.required ? `; beyond the thresholds (${impact.approval.reasons.join(', ')}): another person approves next` : '';
  const compose = (n: number, maxKeys: number): string => {
    const list = items.length ? ` [${items.slice(0, n).join('; ')}${items.length > n ? `${n ? '; ' : ''}+${items.length - n} more` : ''}]` : '';
    return `${head}${list}: ${counts}; keys: ${describeKeys(impact, maxKeys)}${beyond}${tail}`;
  };
  for (const maxKeys of [6, 3, 1]) {
    for (let n = items.length; n >= 0; n--) {
      const out = compose(n, maxKeys);
      if (out.length <= SUMMARY_MAX) return out;
    }
  }
  return compose(0, 1).slice(0, SUMMARY_MAX);
}

/** The preview as the agent reads it: the counters, the keys, the conflicts, the sample within the key. */
function impactAnswer(impact: PolicyImpact, level: string): Record<string, unknown> {
  const { devicesToken: _t, computedAt: _c, ...rest } = impact;
  return {
    ...rest, level, approvalBeyondThresholds: impact.approval.required,
    notApplicable: impact.keys.filter((k) => k.notApplicable > 0).map((k) => ({ settingKey: k.settingKey, devices: k.notApplicable })),
  };
}

/** The changes of the agent in the console's shape: policies only; an existing assignment changed must be a policy's. */
async function consoleChanges(q: Knex, tenant: number, changes: z.infer<typeof McpChange>[]): Promise<AssignmentChange[]> {
  const out: AssignmentChange[] = [];
  for (const [i, c] of changes.entries()) {
    if (c.op !== 'create') {
      if (!c.id) throw new AppError(400, 'id required', 'invalidRequest', { index: i, field: 'id' });
      const a = await q('assignments').where({ tenant_id: tenant, id: c.id }).first('resource_type') as { resource_type: string } | undefined;
      if (!a) throw new AppError(404, 'Assignment not found', 'notFound', { index: i });
      if (a.resource_type !== 'policy') throw new AppError(400, 'Only the assignments of policies are changed here', 'invalidRequest', { index: i });
    }
    out.push({
      op: c.op, ...(c.id !== undefined ? { id: c.id } : {}), ...(c.op === 'create' ? { resourceType: 'policy' as const } : {}),
      ...(c.policy_id !== undefined ? { resourceId: c.policy_id } : {}), ...(c.policy_tenant_id !== undefined ? { resourceTenantId: c.policy_tenant_id } : {}),
      ...(c.target_scope !== undefined ? { targetScope: c.target_scope } : {}), ...(c.target_id !== undefined ? { targetId: c.target_id } : {}),
      ...(c.mode !== undefined ? { mode: c.mode } : {}), ...(c.priority !== undefined ? { priority: c.priority } : {}),
    } as AssignmentChange);
  }
  return out;
}

// ── Tools ────────────────────────────────────────────────────────────────────

const PATCH_HELP = 'A patch sets one setting of the agent section by its key (agent:file[<id>], agent:wifi[<ssid>], agent:wifi.remove[<ssid>], agent:kiosk, agent:dpm.<field>, agent:knox.<field>, agent:cert[<id>], agent:appconfig:<id>); value null removes it; the value is the setting as get_policy_version shows it (a store file: {"paths": [...], "allowAppDataDir": true, "source": {"kind": "template", "text": "...", "encoding": "json"}}; the managed configuration of an app (agent 1.4.2, device owner only): {"package": "<package>", "entries": [{"key": "<key>", "template": "<text with {{variables}}>"}]}, 1 to 50 entries, strings only; the kiosk: {"enabled", "tiles": [...], "exitPin": {"$secret": "<id>"}, ...}, each tile {"id" (lower-case letters, digits, - and _, 48 at most), "label", "action": {"type": "app", "package"} | {"type": "intent", "uri"} | {"type": "url", "url"}}).';
const SECRET_HELP = 'Secrets (Wi-Fi password, kiosk PIN) are never written here: reference a secret of the vault {"$secret": "<id>"} (the one the version already holds); a value typed in is refused.';

export function registerPolicyTools(): void {
  // ── Reads ──

  registerTool({
    name: 'list_policies', title: 'List the policies', scope: 'policies.read',
    description: 'The policies of the tenant (name, category, state, sections, the published version, the open draft or version awaiting approval, the number of assignments). Archived ones only with state archived.',
    inputSchema: js.obj({
      tenant_id: js.tenant, state: js.enumOf(POLICY_STATES, 'Only this state.'), category: js.str('Only this category.', { maxLength: 32 }),
      q: js.str('Search on the name.', { maxLength: 200 }), limit: js.limit, offset: js.offset,
    }, ['tenant_id']),
    args: z.object({
      tenant_id: tenantId, state: z.enum(POLICY_STATES).optional(), category: z.string().max(32).optional(), q: z.string().trim().max(200).optional(),
      limit: z.number().int().min(1).max(200).optional(), offset: z.number().int().min(0).max(100_000).optional(),
    }).strict(),
    annotations: { title: 'List the policies', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'policies.read');
      const all = await policyService.list(a.tenant_id, { state: a.state, category: a.category, q: a.q });
      const o = a.offset ?? 0; const l = a.limit ?? 50;
      return page(all.slice(o, o + l), o, l, all.length);
    }),
  });

  registerTool({
    name: 'get_policy', title: 'Get a policy', scope: 'policies.read',
    description: 'One policy: its envelope, its versions (state, hash of the content, who and when; without their content) and its assignments within your rights and this key.',
    inputSchema: js.obj({ tenant_id: js.tenant, policy_id: js.int('The policy id.') }, ['tenant_id', 'policy_id']),
    args: z.object({ tenant_id: tenantId, policy_id: policyId }).strict(),
    annotations: { title: 'Get a policy', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'policies.read');
      const policy = await policyService.get(a.tenant_id, a.policy_id);
      const versions = await policyService.versions(a.tenant_id, a.policy_id);
      let assignments = await listAssignments(a.tenant_id, { resourceType: 'policy', resourceId: a.policy_id },
        { userId: caller.userId, isAdmin: await isTenantAdmin(caller, a.tenant_id) });
      // A key limited to groups or devices: the assignments to other groups and devices are left out.
      if (caller.key.groupMode === 'list' || caller.key.deviceMode === 'list') {
        const { ids } = await deviceFilter(caller, a.tenant_id);
        const groups = caller.key.groupMode === 'list' ? new Set(targetIds(caller, 'group', a.tenant_id)) : null;
        assignments = assignments.filter((x) => (x.targetScope === 'device' ? ids === 'all' || ids.includes(Number(x.targetId))
          : x.targetScope === 'group' ? !groups || groups.has(Number(x.targetId)) : true));
      }
      return { policy, versions, assignments };
    }),
  });

  registerTool({
    name: 'get_policy_version', title: 'Get a policy version', scope: 'policies.read',
    description: `One version of a policy: its state and the settings of the bridge agent section as the resolution keys them (agent:file[<id>], agent:kiosk…), their values as stored (templates as templates, secrets as references {"$secret": "<id>"}, never a secret value) and the variables of their templates. include_content true adds the whole content (Apple and Android sections too).`,
    inputSchema: js.obj({
      tenant_id: js.tenant, policy_id: js.int('The policy id.'), version: js.int('The version number.'), include_content: js.bool('Add the whole content (default false).'),
    }, ['tenant_id', 'policy_id', 'version']),
    args: z.object({ tenant_id: tenantId, policy_id: policyId, version: versionNo, include_content: z.boolean().optional() }).strict(),
    annotations: { title: 'Get a policy version', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'policies.read');
      const { content, impact: _i, ...v } = await policyService.version(a.tenant_id, a.policy_id, a.version);
      // A stored content never holds a value typed in (saveDraft): checked again before anything leaves.
      if (hasSecretValue(content)) throw new AppError(500, 'A secret value is stored in a version', 'internal');
      return { ...v, sections: Object.keys(content?.sections ?? {}), agentSettings: agentSettingsOf(content), ...(a.include_content ? { content } : {}) };
    }),
  });

  registerTool({
    name: 'list_policy_files', title: 'List the policy files', scope: 'policies.read',
    description: 'The file store of the agent policies (files, kiosk images, CA certificates): id, name, kind, size, SHA-256 and how many versions or deliveries use each one. Reference a store file in a file setting by its sha256, size and name.',
    inputSchema: js.obj({ tenant_id: js.tenant, limit: js.limit, offset: js.offset }, ['tenant_id']),
    args: z.object({ tenant_id: tenantId, limit: z.number().int().min(1).max(200).optional(), offset: z.number().int().min(0).max(100_000).optional() }).strict(),
    annotations: { title: 'List the policy files', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'policies.read');
      const all = await listStoreFiles(a.tenant_id);
      const o = a.offset ?? 0; const l = a.limit ?? 50;
      return page(all.slice(o, o + l), o, l, all.length);
    }),
  });

  registerTool({
    name: 'list_custom_keys', title: 'List the per-device value keys', scope: 'policies.read',
    description: 'The keys of the per-device values a template may use as {{device.custom.<key>}}: the custom fields of the bridge devices and the values of the sites (a device\'s own field first, then its site\'s).',
    inputSchema: js.obj({ tenant_id: js.tenant }, ['tenant_id']),
    args: z.object({ tenant_id: tenantId }).strict(),
    annotations: { title: 'List the per-device value keys', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'policies.read');
      return { keys: await customKeysOf(a.tenant_id) };
    }),
  });

  registerTool({
    name: 'get_device_policy', title: 'Get the agent policy of a device', scope: 'policies.read',
    description: 'What a bridge agent device received: the desired and delivered policy, its state, the settings dropped at compilation and their codes, the ones withheld by a freeze, the last compliance report of the agent (per item code), the settings whose template lacks a variable (the file is not deposited until the value exists), and the other settings it is not given with their reason (agent_too_old: the agent is below the version of the family).',
    inputSchema: js.obj({ tenant_id: js.tenant, device_id: js.int('The device id.') }, ['tenant_id', 'device_id']),
    args: z.object({ tenant_id: tenantId, device_id: deviceId }).strict(),
    annotations: { title: 'Get the agent policy of a device', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'policies.read');
      const d = await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      if (d.managementChannel !== 'legacy_agent') throw notSupported('The agent policy of this channel');
      const status = await devicePolicyStatus(a.tenant_id, a.device_id);
      const out = resolveDevices(await loadResolutionInput(db, a.tenant_id, [a.device_id]));
      const unresolved = (out.devices[0]?.settings ?? [])
        .filter((s) => s.kind === 'agent' && s.availability.status === 'not_applicable' && s.availability.reason === 'variable_unresolved')
        .map((s) => ({ settingKey: s.settingKey, variable: (s.availability as { detail?: string }).detail ?? null }));
      // The other settings the device is not given (an agent too old for the family, e.g. agent:appconfig:* below 1.4.2).
      const notApplicable = (out.devices[0]?.settings ?? [])
        .filter((s) => s.kind === 'agent' && s.availability.status === 'not_applicable' && s.availability.reason !== 'variable_unresolved')
        .map((s) => ({ settingKey: s.settingKey, reason: (s.availability as { reason?: string }).reason ?? null,
          detail: (s.availability as { detail?: string }).detail ?? null }));
      return { deviceId: a.device_id, label: d.label, ...status, unresolved, notApplicable };
    }),
  });

  // ── Drafts ──

  registerTool({
    name: 'create_policy', title: 'Create a policy', scope: 'policies.write',
    description: 'Creates a policy and its draft version 1: empty, or a copy of another policy of the tenant (copy_from). Nothing reaches a device before a submission.',
    inputSchema: js.obj({
      tenant_id: js.tenant, name: js.str('The name (unique in the tenant).', { maxLength: 200 }), description: js.str('A description.', { maxLength: 10_000 }),
      category: js.str('A category (default general).', { maxLength: 32 }), copy_from: js.int('A policy to copy (its published version, else its latest).'),
    }, ['tenant_id', 'name']),
    args: z.object({
      tenant_id: tenantId, name: z.string().trim().min(1).max(200), description: z.string().max(10_000).optional(), category: z.string().max(32).optional(),
      copy_from: policyId.optional(),
    }).strict(),
    annotations: { title: 'Create a policy', ...WRITE, destructiveHint: false, idempotentHint: false },
    run: (caller, a) => policyWrite(caller, 'create_policy', a.tenant_id, 'policies.write', async () => {
      const out = await policyService.create(a.tenant_id, { name: a.name, description: a.description, category: a.category, copyFrom: a.copy_from },
        await actorOf(caller, a.tenant_id, 'create_policy'));
      emitPolicyChanged(a.tenant_id, [out.policy.id]);
      return { policy: out.policy, version: { version: out.version.version, state: out.version.state, contentSha256: out.version.contentSha256 } };
    }),
  });

  registerTool({
    name: 'create_policy_version', title: 'Create a policy draft', scope: 'policies.write',
    description: 'A new draft of a policy: a copy of its published version (else of its latest), or of a rejected version taken up again (from). One open version per policy.',
    inputSchema: js.obj({ tenant_id: js.tenant, policy_id: js.int('The policy id.'), from: js.int('A rejected version to take up again.') }, ['tenant_id', 'policy_id']),
    args: z.object({ tenant_id: tenantId, policy_id: policyId, from: versionNo.optional() }).strict(),
    annotations: { title: 'Create a policy draft', ...WRITE, destructiveHint: false, idempotentHint: false },
    run: (caller, a) => policyWrite(caller, 'create_policy_version', a.tenant_id, 'policies.write', async () => {
      const v = await policyService.newVersion(a.tenant_id, a.policy_id, await actorOf(caller, a.tenant_id, 'create_policy_version'), { from: a.from });
      emitPolicyChanged(a.tenant_id, [a.policy_id]);
      return { policyId: a.policy_id, version: v.version, state: v.state, contentSha256: v.contentSha256, agentSettings: agentSettingsOf(v.content) };
    }),
  });

  registerTool({
    name: 'update_policy_version', title: 'Change a policy draft', scope: 'policies.write',
    description: `Saves a draft: either its whole content (content, as get_policy_version include_content shows it), or patches of settings of the bridge agent section (patches, ${PATCHES_MAX} at most, applied in order on the stored draft). ${PATCH_HELP} The console's validation applies (paths, files of the store, templates); an invalid draft is refused with its issues. ${SECRET_HELP}`,
    inputSchema: js.obj({
      tenant_id: js.tenant, policy_id: js.int('The policy id.'), version: js.int('The draft version number.'),
      content: { type: 'object', description: 'The whole content of the draft.' },
      patches: { type: 'array', maxItems: PATCHES_MAX, items: js.obj({ key: js.str('The setting key.'), value: { description: 'The setting, or null to remove it.' } }, ['key', 'value']), description: 'Settings of the agent section to set or remove.' },
      change_note: js.str('A note of the change.', { maxLength: 2000 }),
    }, ['tenant_id', 'policy_id', 'version']),
    args: z.object({
      tenant_id: tenantId, policy_id: policyId, version: versionNo, content: z.record(z.string(), z.unknown()).optional(),
      patches: z.array(Patch).min(1).max(PATCHES_MAX).optional(), change_note: z.string().max(2000).optional(),
    }).strict().refine((x) => (x.content === undefined) !== (x.patches === undefined), { message: 'Give content or patches, not both' }),
    annotations: { title: 'Change a policy draft', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => policyWrite(caller, 'update_policy_version', a.tenant_id, 'policies.write', async () => {
      let content: unknown;
      if (a.content !== undefined) content = a.content;
      else {
        const current = await policyService.version(a.tenant_id, a.policy_id, a.version);
        if (current.state !== 'draft') throw new AppError(409, 'Only a draft is edited', 'policyVersionNotDraft', { state: current.state });
        refuseSecretValues(a.patches);
        content = patchedContent(current.content, a.patches!.map((p) => ({ key: p.key, value: p.value })));
      }
      refuseSecretValues(content);
      const v = await policyService.saveDraft(a.tenant_id, a.policy_id, a.version, content, a.change_note ?? null,
        await actorOf(caller, a.tenant_id, 'update_policy_version'));
      emitPolicyChanged(a.tenant_id, [a.policy_id]);
      return { policyId: a.policy_id, version: v.version, state: v.state, contentSha256: v.contentSha256, summary: v.summary, agentSettings: agentSettingsOf(v.content) };
    }),
  });

  registerTool({
    name: 'validate_policy_version', title: 'Validate a policy version', scope: 'policies.write',
    description: 'The validation of a version for its submission (content, references to the store and the vault, the tenant binding) and its conflicts with the other policies at the same priority, without effect.',
    inputSchema: js.obj({ tenant_id: js.tenant, policy_id: js.int('The policy id.'), version: js.int('The version number.') }, ['tenant_id', 'policy_id', 'version']),
    args: z.object({ tenant_id: tenantId, policy_id: policyId, version: versionNo }).strict(),
    annotations: { title: 'Validate a policy version', ...READ },
    run: (caller, a) => policyWrite(caller, 'validate_policy_version', a.tenant_id, 'policies.write', async () => {
      const { issues } = await policyService.validate(a.tenant_id, a.policy_id, a.version);
      const row = await policyService.versionRow(db, a.tenant_id, a.policy_id, a.version);
      const conflicts = await conflictsOf(db, a.tenant_id, { kind: 'version', policyId: a.policy_id, versionId: Number(row.id) });
      return { valid: issues.length === 0 && conflicts.length === 0, issues, conflicts };
    }, false),
  });

  registerTool({
    name: 'render_policy_preview', title: 'Render a file template for a device', scope: 'policies.write',
    description: 'A file template rendered with the values of one device (its custom fields, then its site\'s; its own fields; the tenant): the text, the variables without a value (the file would not be deposited) and, for a JSON template, whether it parses. Give the template (template, encoding), a file setting of a version (policy_id, version, file_id), or a managed configuration of a version (policy_id, version, appconfig_id): each entry rendered as text (entries: key, text, missing; the whole configuration is left out of the device while one variable lacks a value). {{device.serial_number}} and {{device.udid}} render masked (listed in masked) unless this key carries devices.identifiers.',
    inputSchema: js.obj({
      tenant_id: js.tenant, device_id: js.int('The device id.'), template: js.str('The template text.', { maxLength: L.templateBytes }),
      encoding: js.enumOf(['text', 'json'], 'The encoding of the template (default text).'), policy_id: js.int('The policy id.'),
      version: js.int('The version number.'), file_id: js.str('The id of the file setting (agent:file[<id>]).', { maxLength: 200 }),
      appconfig_id: js.str('The id of the managed configuration (agent:appconfig:<id>).', { maxLength: 200 }),
    }, ['tenant_id', 'device_id']),
    args: z.object({
      tenant_id: tenantId, device_id: deviceId, template: z.string().max(L.templateBytes).optional(), encoding: z.enum(['text', 'json']).optional(),
      policy_id: policyId.optional(), version: versionNo.optional(), file_id: z.string().min(1).max(200).optional(),
      appconfig_id: z.string().min(1).max(200).optional(),
    }).strict().refine((x) => (x.template !== undefined
      ? x.file_id === undefined && x.appconfig_id === undefined
      : x.policy_id !== undefined && x.version !== undefined && (x.file_id !== undefined) !== (x.appconfig_id !== undefined)),
    { message: 'Give the template, or policy_id, version and file_id (or appconfig_id)' }),
    annotations: { title: 'Render a file template for a device', ...READ },
    run: (caller, a) => policyWrite(caller, 'render_policy_preview', a.tenant_id, 'policies.write', async () => {
      const d = await resolveCallerDevice(caller, a.tenant_id, a.device_id);
      if (a.appconfig_id !== undefined) {
        // A managed configuration (lot P1-QR §6 ter): each entry rendered as text, the variables of all masked alike.
        const v = await policyService.version(a.tenant_id, a.policy_id!, a.version!);
        const cfg = (v.content?.sections?.legacyAgent?.appConfigs ?? []).find((x) => x?.id === a.appconfig_id);
        if (!cfg) throw new AppError(404, 'Managed configuration not found', 'notFound');
        const masked = await previewMask(cfg.entries.map((e) => e.template).join(' '), () => identifiersAllowed(caller, a.tenant_id));
        const rendered = await renderPreviewsFor(a.tenant_id, d.id, cfg.entries.map((e) => ({ template: e.template, encoding: 'text' as const })), masked);
        const entries = cfg.entries.map((e, i) => ({ key: e.key, text: rendered[i].text, missing: rendered[i].missing }));
        return {
          deviceId: d.id, label: d.label, package: cfg.package, entries, missing: [...new Set(entries.flatMap((e) => e.missing))],
          ...(masked.size ? { masked: [...masked], maskedReason: 'devices.identifiers' } : {}),
        };
      }
      let template = a.template;
      let encoding: 'text' | 'json' = a.encoding ?? 'text';
      if (template === undefined) {
        const v = await policyService.version(a.tenant_id, a.policy_id!, a.version!);
        const f = (v.content?.sections?.legacyAgent?.files ?? []).find((x) => x?.id === a.file_id);
        if (!f) throw new AppError(404, 'File setting not found', 'notFound');
        if (f.source?.kind !== 'template') throw new AppError(400, 'This file setting is not a template', 'invalidRequest');
        template = f.source.text;
        encoding = f.source.encoding;
      }
      const masked = await previewMask(template, () => identifiersAllowed(caller, a.tenant_id));
      return {
        deviceId: d.id, label: d.label, ...(await renderPreviewFor(a.tenant_id, d.id, template, encoding, masked)),
        ...(masked.size ? { masked: [...masked], maskedReason: 'devices.identifiers' } : {}),
      };
    }, false),
  });

  registerTool({
    name: 'policy_version_impact', title: 'Preview the publication of a version', scope: 'policies.write',
    description: 'What publishing a version would do, nothing written: the devices touched, added and removed, per setting key the devices it adds, changes, removes and the ones where it would not apply (notApplicable: a variable without value, an agent too old…), the removals, the conflicts, a sample of devices within this key, the issues of its content, and the level its submission needs (sensitive: a second factor of the human; restricted / approvalBeyondThresholds: another person).',
    inputSchema: js.obj({ tenant_id: js.tenant, policy_id: js.int('The policy id.'), version: js.int('The version number.') }, ['tenant_id', 'policy_id', 'version']),
    args: z.object({ tenant_id: tenantId, policy_id: policyId, version: versionNo }).strict(),
    annotations: { title: 'Preview the publication of a version', ...READ },
    run: (caller, a) => policyWrite(caller, 'policy_version_impact', a.tenant_id, 'policies.write', async () => {
      const row = await policyService.versionRow(db, a.tenant_id, a.policy_id, a.version);
      const { ids } = await deviceFilter(caller, a.tenant_id);
      const p = await previewSubmission(a.tenant_id, a.policy_id, Number(row.id), ids);
      return { policyId: a.policy_id, version: a.version, state: row.state, issues: p.issues, impact: impactAnswer(p.impact, p.level) };
    }, false),
  });

  registerTool({
    name: 'upload_policy_file', title: 'Upload a policy file', scope: 'policies.write',
    description: `Adds a file to the store of the agent policies (a file to deposit that is not a template, a kiosk image PNG/JPEG/GIF/ICO of 256 KiB at most, a CA certificate), base64, ${MCP_UPLOAD_BYTES / 1024} KiB at most per call (the transport takes 256 kB a request). Idempotent by content: the same bytes answer the existing row. Never a secret in a file.`,
    inputSchema: js.obj({
      tenant_id: js.tenant, name: js.str('The name (1 to 200 characters, no slash).', { maxLength: 200 }), note: js.str('A note.', { maxLength: 500 }),
      media_type: js.str('The media type: application/octet-stream (JSON included), text/…, image/png, image/jpeg, image/gif, image/x-icon, application/x-x509-ca-cert.', { maxLength: 100 }),
      content_base64: js.str('The bytes, base64.', { maxLength: Math.ceil(MCP_UPLOAD_BYTES / 3) * 4 }),
    }, ['tenant_id', 'name', 'media_type', 'content_base64']),
    args: z.object({
      tenant_id: tenantId, name: z.string().trim().min(1).max(200).regex(/^[^\u0000-\u001f\u007f/\\]+$/), note: z.string().max(500).optional(),
      media_type: z.string().max(100), content_base64: z.string().min(1).max(Math.ceil(MCP_UPLOAD_BYTES / 3) * 4).regex(/^[A-Za-z0-9+/]+={0,2}$/),
    }).strict(),
    annotations: { title: 'Upload a policy file', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => policyWrite(caller, 'upload_policy_file', a.tenant_id, 'policies.write', async () => {
      const bytes = Buffer.from(a.content_base64, 'base64');
      const mediaType = a.media_type.toLowerCase().split(';')[0].trim();
      const max = Math.min(MCP_UPLOAD_BYTES, mediaType.startsWith('image/') ? L.imageBytes : L.storeFileBytes);
      const received = await receiveBytes(a.tenant_id, bytes, mediaType, max);
      const note = a.note ? a.note.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 500) || null : null;
      const { row, created } = await storeReceivedFile(a.tenant_id, received, { name: a.name, note, mediaType }, caller.userId,
        await mcpAuditCtx(caller, a.tenant_id, 'upload_policy_file'));
      return { created, file: fileView(row) };
    }),
  });

  // ── Publication ──

  registerTool({
    name: 'submit_policy_version', title: 'Submit a policy version', scope: 'policies.publish',
    description: 'Publishes a draft. dry_run (default true) answers the preview and the level it needs, nothing written. dry_run false NEVER publishes by itself: it asks ONE authorization the human approves with a second factor; the console\'s submission then runs as him, on the content and the impact he was shown (refused, nothing published, if either changed meanwhile), and beyond the thresholds (devices touched, share of the fleet, removals, a wipe setting) it files an approval for another person. Then call get_authorization_status.',
    inputSchema: js.obj({
      tenant_id: js.tenant, policy_id: js.int('The policy id.'), version: js.int('The draft version number.'), dry_run: js.bool('true (default): the preview only.'),
    }, ['tenant_id', 'policy_id', 'version']),
    args: ARGS.submit_policy_version,
    annotations: { title: 'Submit a policy version', ...WRITE, destructiveHint: false, idempotentHint: false },
    run: (caller, a) => policyWrite(caller, 'submit_policy_version', a.tenant_id, 'policies.publish', async () => {
      const row = await policyService.versionRow(db, a.tenant_id, a.policy_id, a.version);
      if (row.state !== 'draft') throw new AppError(409, 'Only a draft is submitted', 'policyVersionNotDraft', { state: row.state });
      const { ids } = await deviceFilter(caller, a.tenant_id);
      const p = await previewSubmission(a.tenant_id, a.policy_id, Number(row.id), ids);
      const answer = { policyId: a.policy_id, version: a.version, issues: p.issues, impact: impactAnswer(p.impact, p.level) };
      if (a.dry_run !== false) return { dryRun: true, ...answer };
      requireWholeTenant(caller.key);
      await requireWriteOnAssignedTargets(db, a.tenant_id, a.policy_id, caller);
      if (p.issues.length) throw new AppError(422, 'The content of the policy is not valid', 'validationFailed', { issues: p.issues });
      if (p.impact.conflicts.length) throw new AppError(422, 'The change would set a key to two values at the same priority', 'policyConflict', { conflicts: p.impact.conflicts });
      const policy = await policyService.policyRow(db, a.tenant_id, a.policy_id) as { name: string };
      const r = await createPending(caller, {
        tenantId: a.tenant_id, tool: 'submit_policy_version', actionKey: POLICY_PUBLISH_ACTION, level: 'always_human',
        summary: fitSummary(`Publish version ${a.version} of the policy ${quotedName(String(policy.name))} (#${a.policy_id})`, [], p.impact,
          await tenantLabel(a.tenant_id)),
        args: { tenant_id: a.tenant_id, policy_id: a.policy_id, version: a.version, content_sha256: p.contentSha256, digest: p.digest }, deviceIds: [],
      });
      return { ...answer, dryRun: false, status: 'authorization_required', authorizationId: String(r.id), expiresAt: new Date(r.expires_at).toISOString(), message: AUTHORIZE_MESSAGE };
    }, a.dry_run === false),
  });

  registerTool({
    name: 'change_policy_assignments', title: 'Change the assignments of policies', scope: 'policies.publish',
    description: 'A batch of changes of assignments of policies (1 to 100): create {policy_id, target_scope tenant|group|device|smart_group, target_id, mode include|exclude, priority (required for a dynamic group)}, update {id, mode?, priority?}, delete {id}. dry_run (default true) answers the preview; dry_run false asks ONE authorization (second factor of the human; beyond the thresholds another person approves next), bound to the impact shown. Assignments of apps are not changed here.',
    inputSchema: js.obj({
      tenant_id: js.tenant,
      changes: {
        type: 'array', minItems: 1, maxItems: 100, description: 'The changes.',
        items: js.obj({
          op: js.enumOf(['create', 'update', 'delete'], 'The change.'), id: js.int('The assignment (update, delete).'), policy_id: js.int('The policy (create).'),
          policy_tenant_id: js.int('The tenant of a shared policy of the library (default this tenant).'),
          target_scope: js.enumOf(['tenant', 'group', 'device', 'smart_group'], 'The target.'), target_id: { type: ['integer', 'null'], minimum: 1, description: 'The group or device (none for the tenant).' },
          mode: js.enumOf(['include', 'exclude'], 'Default include.'), priority: js.int('The priority.', { minimum: ASSIGNMENT_PRIORITY.min, maximum: ASSIGNMENT_PRIORITY.max }),
        }, ['op']),
      },
      dry_run: js.bool('true (default): the preview only.'),
    }, ['tenant_id', 'changes']),
    args: ARGS.change_policy_assignments,
    annotations: { title: 'Change the assignments of policies', ...WRITE, destructiveHint: false, idempotentHint: false },
    run: (caller, a) => policyWrite(caller, 'change_policy_assignments', a.tenant_id, 'policies.publish', async () => {
      const changes = await consoleChanges(db, a.tenant_id, a.changes);
      const { ids } = await deviceFilter(caller, a.tenant_id);
      if (a.dry_run === false) requireWholeTenant(caller.key);
      const p = await previewAssignments(a.tenant_id, changes, caller, ids);
      const answer = { changes: changes.length, impact: impactAnswer(p.impact, p.level) };
      if (a.dry_run !== false) return { dryRun: true, ...answer };
      if (p.impact.conflicts.length) throw new AppError(422, 'The change would set a key to two values at the same priority', 'policyConflict', { conflicts: p.impact.conflicts });
      const r = await createPending(caller, {
        tenantId: a.tenant_id, tool: 'change_policy_assignments', actionKey: POLICY_PUBLISH_ACTION, level: 'always_human',
        summary: fitSummary(`Change ${changes.length} assignment(s) of policies`, p.deltas.map((d) => describeDelta(d, p.base)), p.impact,
          await tenantLabel(a.tenant_id)),
        args: { tenant_id: a.tenant_id, changes, digest: p.digest }, deviceIds: [],
      });
      return { ...answer, dryRun: false, status: 'authorization_required', authorizationId: String(r.id), expiresAt: new Date(r.expires_at).toISOString(), message: AUTHORIZE_MESSAGE };
    }, a.dry_run === false),
  });
}

// ── Execution of an approved authorization (in the human's request, rights re-checked) ─

/** The answer of a console submission as the state of the authorization. */
export function outcomeOf(out: RouteOutcome, done: Record<string, unknown>): ExecResult {
  const data = (out.body as { data?: { outcome?: string; approvalId?: number } }).data;
  if (out.status === 202 && data?.approvalId) return { state: 'filed', outcome: { approvalId: Number(data.approvalId) } };
  if (out.status === 200) return { state: 'executed', outcome: done };
  const body = (out.body ?? {}) as { twoFactorRequired?: unknown };
  return { state: 'failed', errorCode: body.twoFactorRequired ? 'stepUpRequired' : `refused${out.status}` };
}

/** What the executor reaches beyond its arguments (an object, so that the unit tests replace them: no database there). */
export const policyExec = {
  keyModes: async (keyId: unknown, userId: number) => await db('access_keys').where({ id: keyId as string, user_id: userId })
    .first('group_mode', 'device_mode') as { group_mode: string; device_mode: string } | undefined,
  holdsTenantCapability, submitVersion, changeAssignments,
};

/**
 * Runs an approved submission or batch of assignments as its human: the key still reaching the whole tenant, his
 * mdm.policies.manage, then the console's own function in his request (its step-up proven by the approval's factor
 * for mdm.policy_publish only), bound to what he was shown (expectContentSha, expectDigest: policyChanged otherwise,
 * nothing written); a direct write closes the authorization in its transaction, with the entry of the key
 * (mcp.tool.write); a request beyond the thresholds is filed for another person (state 'filed').
 */
export async function executePolicyWrite(x: ExecContext): Promise<ExecResult> {
  const tool = String(x.row.tool);
  const tenant = Number(x.row.tenant_id);
  if (!isPolicyTool(tool)) return { state: 'failed', errorCode: 'unknownTool' };
  const parsed = POLICY_APPROVABLE_ARGS[tool].safeParse(x.args);
  if (!parsed.success) return { state: 'failed', errorCode: 'perimeterLost' };
  const key = await policyExec.keyModes(x.row.key_id, x.consoleCaller.userId);
  if (!key || key.group_mode !== 'all' || key.device_mode !== 'all') return { state: 'failed', errorCode: 'perimeterLost' };
  const who = { userId: x.consoleCaller.userId, isPlatformAdmin: x.consoleCaller.isPlatformAdmin };
  if (!(await policyExec.holdsTenantCapability(who, tenant, POLICY_MANAGE))) return { state: 'failed', errorCode: 'capabilityMissing' };
  const req: Request = x.req;
  try {
    if (tool === 'submit_policy_version') {
      const a = parsed.data as { policy_id: number; version: number; content_sha256: string; digest: string };
      const done = { policyId: a.policy_id, version: a.version, published: true };
      const out = await policyExec.submitVersion(req, tenant, a.policy_id, a.version, {
        expectContentSha: a.content_sha256, expectDigest: a.digest, descriptionPrefix: x.descriptionPrefix,
        inTx: (trx) => x.finishInTx(trx, { tool, ...done }),
      });
      return outcomeOf(out, done);
    }
    const a = parsed.data as { changes: AssignmentChange[]; digest: string };
    const done = { changes: a.changes.length, applied: true };
    const out = await policyExec.changeAssignments(req, tenant, { changes: a.changes }, false, {
      expectDigest: a.digest, descriptionPrefix: x.descriptionPrefix, inTx: (trx) => x.finishInTx(trx, { tool, ...done }),
    });
    return outcomeOf(out, done);
  } catch (err) {
    if (err instanceof AppError && (err.code === 'impactChanged' || err.code === 'policyVersionChanged' || err.code === 'policyVersionNotDraft')) {
      return { state: 'failed', errorCode: 'policyChanged' };
    }
    if (err instanceof AppError && err.statusCode < 500) return { state: 'failed', errorCode: err.code ?? `refused${err.statusCode}` };
    throw err;
  }
}
