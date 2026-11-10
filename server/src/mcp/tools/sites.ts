import { createHash } from 'node:crypto';
import type { Knex } from 'knex';
import { z } from 'zod';
import { SITE_LIMITS as L, SITE_VALUE_KEY_RE } from '@obligarth/shared';
import { audit, canonicalJson } from '../../audit';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { approvalService } from '../../services/approval.service';
import { permissionService } from '../../services/permission.service';
import { beyondThresholds } from '../../legacyAgent/policyRoutes';
import { consumeBatch, insertBatch, purgeTenantBatches, usableBatch } from '../../sites/batches';
import { POLICY_MANAGE, SITES_APPLY, SITE_WRITE_APPROVAL, prevDigestOf, type SiteWriteSealed } from '../../sites/guard';
import { checkSite, type SiteRow } from '../../sites/model';
import {
  applyFromDevices, applyImport, archiveSite, createSite, existingSites, fromDevicesImpact, fromDevicesUpdatedSites, importImpactChange,
  importPlanNow, importUpdatedSites, listSites, managedDevicesOfSites, managedOnSite, planChanged, previewFromDevices, previewImport,
  requireSiteReach, setDevicesSite, siteAfter, siteChanges, siteDetail, siteNotFound, sitePolicyImpact, updateSite, type SiteWho, type Visible,
} from '../../sites/service';
import { accessKeyDetail, mcpAuditCtx } from '../audit';
import { createPending } from '../authorizations/service';
import { holdsTenantCapability, requireScope, withTenant, type McpCaller } from '../caller';
import { assertDevicesInPerimeter, deviceFilter } from '../perimeter';
import { AUTHORIZE_MESSAGE, takeWrite, tenantId } from './common';
import { READ, js, page, registerTool } from './index';
import type { ExecContext, ExecResult } from './writes';

// =============================================================================
// The sites through the MCP server (lot P1-SITE §2.5): the population of the sites can be done entirely here.
//   reads (devices.read)   list_sites, get_site: the sites, the state of their devices within the key's perimeter.
//   writes (sites.write)   import_sites, sites_from_devices, upsert_site, archive_site, set_device_site. dry_run is
//                          true by default and answers the plan at once; dry_run false never applies: the request is
//                          kept as a batch (site_batches) and ONE authorization is asked for the whole batch, its
//                          summary built by the server from the plan; the human approves it with a second factor, the
//                          plan is made again as him, refused when it changed (planChanged), then applied once.
// A site and its values reach every device of the site: the writes of the sites themselves (import, upsert, archive,
// the sites from the custom fields) need a key that reaches the whole tenant (groups and devices 'all'), and a change
// of what the templates read (values, code, name, city; an import that updates sites; the sites from the custom fields)
// needs, as in the console (sites/guard.ts), mdm.policies.manage and the human's rights on every device of the sites
// changed, then at approval the restrictable action sites.apply and, beyond the publication thresholds of its policy
// impact, a second person (the console's approval site_write, filed by the approval: state 'filed').
// set_device_site needs every device inside the key and the human's write access on it. Attaching a device to a site
// never moves it between groups (move_devices_to_group, always a human, does). The values of a site are customer data:
// stored in the batch, never in a summary nor an audit entry (keys only).
// =============================================================================

const WRITE = { readOnlyHint: false, openWorldHint: false as const };
/** The CSV text of one call of import_sites: the JSON parser of /mcp takes 256 kB a request (router.ts), escaping
 *  included; a larger file is split in several imports (each its own authorization). */
const MCP_IMPORT_BYTES = 200 * 1024;
const SITE_TOOLS = ['import_sites', 'sites_from_devices', 'upsert_site', 'archive_site', 'set_device_site'] as const;
type SiteTool = typeof SITE_TOOLS[number];
export const isSiteTool = (t: string): t is SiteTool => (SITE_TOOLS as readonly string[]).includes(t);

const sha256 = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
const keyName = z.string().regex(SITE_VALUE_KEY_RE);
const siteText = (max: number) => z.string().max(max * 2);

// ── Arguments ────────────────────────────────────────────────────────────────

const ARGS = {
  import_sites: z.object({
    tenant_id: tenantId, csv: z.string().min(1).max(MCP_IMPORT_BYTES), dry_run: z.boolean().optional(),
  }).strict(),
  sites_from_devices: z.object({
    tenant_id: tenantId, code_key: keyName.optional(), name_key: keyName.optional(), values_keys: z.array(keyName).max(L.valuesMax).optional(),
    dry_run: z.boolean().optional(),
  }).strict(),
  upsert_site: z.object({
    tenant_id: tenantId, code: siteText(L.codeMax), name: siteText(L.nameMax).optional(), city: siteText(L.cityMax).nullable().optional(),
    contact: siteText(L.contactMax).nullable().optional(), group_id: z.number().int().positive().nullable().optional(),
    values: z.record(z.string().max(L.valueMax * 2)).optional(), values_mode: z.enum(['merge', 'replace']).optional(), dry_run: z.boolean().optional(),
  }).strict(),
  archive_site: z.object({ tenant_id: tenantId, site_id: z.string().uuid(), dry_run: z.boolean().optional() }).strict(),
  set_device_site: z.object({
    tenant_id: tenantId, device_ids: z.array(z.number().int().positive().max(2147483647)).min(1).max(L.bulkDevices),
    site_id: z.string().uuid().nullable(), dry_run: z.boolean().optional(),
  }).strict(),
};

/** What an authorization of a site batch stores as its arguments (the request lives in site_batches). */
const BatchArgs = z.object({ tenant_id: tenantId, batch_id: z.string().uuid(), digest: z.string().regex(/^[0-9a-f]{64}$/) }).strict();
export const SITE_APPROVABLE_ARGS: Record<SiteTool, z.ZodTypeAny> = {
  import_sites: BatchArgs, sites_from_devices: BatchArgs, upsert_site: BatchArgs, archive_site: BatchArgs, set_device_site: BatchArgs,
};

// ── Rights and perimeter ─────────────────────────────────────────────────────

interface Who { userId: number; isPlatformAdmin: boolean }

/** The writes of the sites themselves reach every device of a site: a key limited to groups or devices cannot. */
function requireWholeTenant(key: { groupMode: string; deviceMode: string }): void {
  if (key.groupMode !== 'all' || key.deviceMode !== 'all') {
    throw new AppError(403, 'Only a key that reaches every group and device of the tenant may write its sites', 'perimeterTooNarrow');
  }
}

/** The devices the human sees ('all': a platform administrator). */
const visibleOf = (who: Who): Promise<Visible> => (who.isPlatformAdmin ? Promise.resolve('all' as const) : permissionService.getVisibleDeviceIds(who.userId, false));
const siteWho = (who: Who): SiteWho => ({ userId: who.userId, admin: who.isPlatformAdmin });

/** A change of what the templates of a site's devices read: mdm.policies.manage, as the console. */
async function requirePolicyManage(who: Who, tenant: number): Promise<void> {
  if (!(await holdsTenantCapability(who, tenant, POLICY_MANAGE))) {
    throw new AppError(403, 'Changing the values of sites needs the right to manage the policies', 'capabilityMissing');
  }
}

/** Write access of the human on the group a site names (the group must be of the tenant: 404 otherwise). */
async function requireGroupOf(who: Who, tenant: number, groupId: number | null | undefined): Promise<void> {
  if (!groupId) return;
  const found = await db('device_groups').where({ tenant_id: tenant, id: groupId }).first('id');
  if (!found || (!who.isPlatformAdmin && !(await permissionService.canReadGroup(who.userId, groupId, false)))) throw new AppError(404, 'Group not found', 'notFound');
  if (!who.isPlatformAdmin && !(await permissionService.canWriteGroup(who.userId, groupId, false))) throw new AppError(403, 'No write permission on target group', 'capabilityMissing');
}

/** devices.manage, and write access on each device (as the console's routes). */
async function requireDeviceWrites(who: Who, tenant: number, ids: number[]): Promise<void> {
  if (!(await holdsTenantCapability(who, tenant, 'devices.manage'))) throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  if (who.isPlatformAdmin) return;
  for (const id of ids) {
    if (!(await permissionService.canWriteDevice(who.userId, id, false))) throw new AppError(403, 'Insufficient permissions', 'capabilityMissing');
  }
}

// ── Plans of the small writes (their digest: the request and the state it reads) ─

type UpsertArgs = z.infer<typeof ARGS.upsert_site>;
type SetArgs = z.infer<typeof ARGS.set_device_site>;
type ArchiveArgs = z.infer<typeof ARGS.archive_site>;

interface SmallPlan { digest: string; answer: Record<string, unknown>; summary: string }
type Q = Knex | Knex.Transaction;

const digestOf = (tool: string, request: unknown, state: unknown): string => sha256(canonicalJson({ tool, request, state } as never));
const strip = <T extends { dry_run?: boolean }>(a: T): Omit<T, 'dry_run'> => { const { dry_run: _d, ...rest } = a; return rest; };

async function planUpsert(q: Q, tenant: number, a: UpsertArgs): Promise<SmallPlan & { prev: SiteRow | null; body: Parameters<typeof checkSite>[0] }> {
  const code = a.code.trim();
  const prev = (await existingSites(q, tenant)).find((s) => s.code.toLowerCase() === code.toLowerCase()) ?? null;
  if (prev?.archived) throw new AppError(409, 'This site is archived', 'siteArchived');
  const values = a.values === undefined ? undefined
    : (a.values_mode === 'replace' || !prev ? a.values : { ...prev.values, ...a.values });
  const body = {
    ...(prev ? {} : { code }), ...(a.name !== undefined ? { name: a.name } : {}), ...(a.city !== undefined ? { city: a.city } : {}),
    ...(a.contact !== undefined ? { contact: a.contact } : {}), ...(a.group_id !== undefined ? { groupId: a.group_id } : {}),
    ...(values !== undefined ? { values } : {}),
  };
  const { site, issues } = checkSite(body, !prev);
  if (issues.length) throw new AppError(400, `Invalid site: ${issues.join(', ')}`, 'invalidSite', { issues });
  const changes: string[] = [];
  if (prev) {
    if (site.name !== undefined && site.name !== prev.name) changes.push('name');
    if (site.city !== undefined && site.city !== prev.city) changes.push('city');
    if (site.contact !== undefined && site.contact !== prev.contact) changes.push('contact');
    if (site.groupId !== undefined && site.groupId !== prev.groupId) changes.push('groupId');
    if (site.values !== undefined) {
      for (const k of new Set([...Object.keys(prev.values), ...Object.keys(site.values)])) if (prev.values[k] !== site.values[k]) changes.push(`values.${k}`);
    }
  }
  const action = prev ? (changes.length ? 'update' : 'unchanged') : 'create';
  return {
    prev, body, digest: digestOf('upsert_site', strip(a), prev),
    answer: { action, code: prev?.code ?? code, siteId: prev?.id ?? null, changes },
    summary: action === 'create' ? `Create the site ${code}` : `Change the site ${prev!.code}: ${changes.slice(0, 10).join(', ') || 'nothing'}`,
  };
}

async function planArchive(q: Q, tenant: number, a: ArchiveArgs): Promise<SmallPlan & { site: SiteRow }> {
  const site = (await existingSites(q, tenant)).find((s) => s.id === a.site_id.toLowerCase());
  if (!site) throw siteNotFound();
  // The devices under management, as the site page and archiveSite count them (an unenrolled one is detached).
  const n = await managedOnSite(q, tenant, site.id);
  if (n > 0) throw new AppError(409, 'Detach the devices of the site before archiving it', 'siteNotEmpty', { devices: n });
  return {
    site, digest: digestOf('archive_site', strip(a), site),
    answer: { action: site.archived ? 'unchanged' : 'archive', siteId: site.id, code: site.code }, summary: `Archive the site ${site.code}`,
  };
}

async function planSet(q: Q, tenant: number, a: SetArgs): Promise<SmallPlan & { ids: number[] }> {
  const ids = [...new Set(a.device_ids)].sort((x, y) => x - y);
  const site = a.site_id === null ? null : (await existingSites(q, tenant)).find((s) => s.id === a.site_id!.toLowerCase());
  if (a.site_id !== null && !site) throw siteNotFound();
  if (site?.archived) throw new AppError(409, 'This site is archived', 'siteArchived');
  const rows = await q('devices').where({ tenant_id: tenant }).whereRaw('id = ANY (?::int[])', [ids]).orderBy('id')
    .select('id', 'label', 'site_id', 'group_id') as Array<{ id: number; label: string | null; site_id: string | null; group_id: number | null }>;
  const target = site?.id ?? null;
  const change = rows.filter((r) => (r.site_id ?? null) !== target).map((r) => Number(r.id));
  const outsideGroup = site?.groupId ? rows.filter((r) => Number(r.group_id) !== site.groupId).map((r) => Number(r.id)) : [];
  return {
    ids, digest: digestOf('set_device_site', { ...strip(a), device_ids: ids }, { target, current: rows.map((r) => [Number(r.id), r.site_id ?? null]) }),
    answer: {
      action: change.length ? 'attach' : 'unchanged', siteId: target, code: site?.code ?? null, changed: change, unchanged: ids.filter((i) => !change.includes(i)),
      siteGroupId: site?.groupId ?? null, outsideGroup,
      ...(outsideGroup.length ? { note: 'These devices are not in the group of the site: move_devices_to_group files them there (always approved by the human).' } : {}),
    },
    summary: site ? `Attach ${change.length} device(s) to the site ${site.code}` : `Detach ${change.length} device(s) from their site`,
  };
}

// ── Staging and authorization ────────────────────────────────────────────────

const tenantLabel = async (tenant: number): Promise<string> => {
  const t = await db('tenants').where({ id: tenant }).first('name') as { name: string } | undefined;
  return t ? ` (tenant ${t.name})` : '';
};

/** Keeps the request of an applied batch and asks its ONE authorization (inside withTenant). A batch whose
 *  authorization is refused (the cap of the pending ones, any error) goes at once: nothing is kept without a human to
 *  approve it. */
async function stage(caller: McpCaller, tenant: number, tool: SiteTool, request: Record<string, unknown>, digest: string, summary: string,
  deviceIds: number[]): Promise<Record<string, unknown>> {
  const batchId = await db.transaction(async (trx) => {
    // The batches done with go (approved, refused or forgotten alike); the hourly purge does it for every tenant too.
    await purgeTenantBatches(trx, tenant);
    return insertBatch(trx, { tenantId: tenant, userId: caller.userId, tool, request, digest });
  });
  let row: Awaited<ReturnType<typeof createPending>>;
  try {
    row = await createPending(caller, {
      tenantId: tenant, tool, actionKey: SITES_APPLY, level: 'always_human', summary: (summary + await tenantLabel(tenant)).slice(0, 500),
      args: { tenant_id: tenant, batch_id: batchId, digest }, deviceIds,
    });
  } catch (err) {
    await db('site_batches').where({ tenant_id: tenant, id: batchId }).delete().catch(() => undefined);
    throw err;
  }
  return { status: 'authorization_required', authorizationId: String(row.id), expiresAt: new Date(row.expires_at).toISOString(), message: AUTHORIZE_MESSAGE };
}

/** A write refused for rights or perimeter is journaled (mcp.tool.denied), as the other write tools. */
async function denied(caller: McpCaller, tenant: number, tool: string, err: unknown): Promise<void> {
  const e = err as { statusCode?: number; code?: string };
  if (!(err instanceof AppError) || (e.statusCode !== 403 && e.statusCode !== 404)) return;
  try {
    await audit.append({
      tenantId: tenant, action: 'mcp.tool.denied', outcome: 'denied',
      details: { tool, code: e.code ?? null, status: e.statusCode, accessKey: accessKeyDetail(caller) },
    }, await mcpAuditCtx(caller, tenant, tool));
  } catch { /* spooled by the writer */ }
}

/** A write tool of the sites: the scope and the rights, then the plan (dry run) or the batch and its authorization. */
async function siteWrite(caller: McpCaller, tool: SiteTool, a: { tenant_id: number; dry_run?: boolean }, run: () => Promise<unknown>): Promise<unknown> {
  if (a.dry_run === false) takeWrite(caller);
  try {
    return await withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'sites.write', 'devices.manage');
      return run();
    });
  } catch (err) {
    await withTenant(caller, a.tenant_id, () => denied(caller, a.tenant_id, tool, err)).catch(() => undefined);
    throw err;
  }
}

const IMPORT_HELP = 'CSV text with a header line, separator ";" or ",". Column code (or codeMag) and name (or nameMag) required; city (or ville) and contact optional; every other column goes to the values of the site (a column used as the code or the name that is not literally "code" or "name" goes there too, so that {{device.custom.codeMag}} finds it).';

export function registerSiteTools(): void {
  registerTool({
    name: 'list_sites', title: 'List the sites', scope: 'devices.read',
    description: 'The sites of the tenant (code, name, city, contact, group, values) with the counts of their devices within this key: ready, todo, stale (no contact for 24 h) and fileNotCreated (a variable of a file template of the agent has no value: the file of the store apps is not deposited).',
    inputSchema: js.obj({
      tenant_id: js.tenant, q: js.str('Search on the code, the name and the city.', { maxLength: 100 }),
      archived: js.bool('Include the archived sites.'), limit: js.limit, offset: js.offset,
    }, ['tenant_id']),
    args: z.object({ tenant_id: tenantId, q: z.string().trim().max(100).optional(), archived: z.boolean().optional(),
      limit: z.number().int().min(1).max(200).optional(), offset: z.number().int().min(0).max(100_000).optional() }).strict(),
    annotations: { title: 'List the sites', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      const { ids } = await deviceFilter(caller, a.tenant_id);
      const all = await listSites(a.tenant_id, { q: a.q, archived: a.archived, visible: ids });
      const o = a.offset ?? 0; const l = a.limit ?? 50;
      return page(all.slice(o, o + l), o, l, all.length);
    }),
  });

  registerTool({
    name: 'get_site', title: 'Get a site', scope: 'devices.read',
    description: 'One site: its fields and values, its devices within this key with their state (ready, todo, stale), the reasons (no_contact, agent_too_old, admin_inactive, low_storage, file_not_created: a file template lacks a value, appconfig_unresolved: a managed configuration of an app lacks one) and the variables their templates lack (missingVariables for the files, missingAppConfigVariables for the managed configurations).',
    inputSchema: js.obj({ tenant_id: js.tenant, site_id: js.str('The site id (uuid).', { format: 'uuid' }) }, ['tenant_id', 'site_id']),
    args: z.object({ tenant_id: tenantId, site_id: z.string().uuid() }).strict(),
    annotations: { title: 'Get a site', ...READ },
    run: (caller, a) => withTenant(caller, a.tenant_id, async () => {
      await requireScope(caller, a.tenant_id, 'devices.read');
      const { ids } = await deviceFilter(caller, a.tenant_id);
      return siteDetail(a.tenant_id, a.site_id, ids);
    }),
  });

  registerTool({
    name: 'import_sites', title: 'Import sites from a CSV text', scope: 'sites.write',
    description: `Creates and updates sites from a CSV text (200 KiB per call: the transport takes 256 kB a request; split a larger file in several calls by lines, each with its header; 5 000 lines at most; an empty cell keeps the value of the site). ${IMPORT_HELP} dry_run (default true) answers the creations, updates and errors per line; dry_run false asks ONE authorization for the whole batch: the human approves it with a second factor, then call get_authorization_status.`,
    inputSchema: js.obj({
      tenant_id: js.tenant, csv: js.str('The CSV text (200 KiB at most).', { maxLength: MCP_IMPORT_BYTES }), dry_run: js.bool('true (default): the plan only.'),
    }, ['tenant_id', 'csv']),
    args: ARGS.import_sites,
    annotations: { title: 'Import sites from a CSV text', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => siteWrite(caller, 'import_sites', a, async () => {
      requireWholeTenant(caller.key);
      if (a.csv.split(/\r?\n/).filter((x) => x.trim()).length - 1 > L.importRows) throw new AppError(413, `At most ${L.importRows} lines per import`, 'importTooLarge');
      const plan = await previewImport(a.tenant_id, a.csv);
      if (a.dry_run !== false) return { ...plan, dryRun: true };
      if (plan.created + plan.updated === 0) return { ...plan, dryRun: false, status: 'nothing_to_apply' };
      const updated = importUpdatedSites((await importPlanNow(a.tenant_id, a.csv)).plan);
      if (updated.length) {
        await requirePolicyManage(caller, a.tenant_id);
        await requireSiteReach(db, a.tenant_id, siteWho(caller), updated);
      }
      return stage(caller, a.tenant_id, 'import_sites', strip(a), plan.digest,
        `Import sites: ${plan.created} to create, ${plan.updated} to update, ${plan.errors} line(s) refused`, []);
    }),
  });

  registerTool({
    name: 'sites_from_devices', title: 'Create the sites from the custom fields', scope: 'sites.write',
    description: 'Creates the sites from the custom fields of the devices (code_key default codeMag, name_key default nameMag; values_keys: other fields copied into the values of the site, e.g. codeEns) and attaches the devices to them. An existing site keeps its name and values (only the keys it lacks are added). Lists the devices without the code field and the conflicts (same code, different names). Never moves a device between groups. dry_run (default true) answers the plan; dry_run false asks ONE authorization for the whole batch.',
    inputSchema: js.obj({
      tenant_id: js.tenant, code_key: js.str('The custom field of the code (default codeMag).'), name_key: js.str('The custom field of the name (default nameMag).'),
      values_keys: { type: 'array', items: { type: 'string' }, maxItems: L.valuesMax, description: 'Other custom fields copied into the values of the site.' },
      dry_run: js.bool('true (default): the plan only.'),
    }, ['tenant_id']),
    args: ARGS.sites_from_devices,
    annotations: { title: 'Create the sites from the custom fields', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => siteWrite(caller, 'sites_from_devices', a, async () => {
      requireWholeTenant(caller.key);
      const keys = { code: a.code_key ?? 'codeMag', name: a.name_key ?? 'nameMag', values: a.values_keys ?? [] };
      const { ids } = await deviceFilter(caller, a.tenant_id);
      const plan = await previewFromDevices(a.tenant_id, keys, ids);
      if (a.dry_run !== false) return plan.result;
      const attach = plan.attach.map((x) => x.deviceId);
      if (!plan.writes.length && !attach.length) return { ...plan.result, dryRun: false, status: 'nothing_to_apply' };
      await requireDeviceWrites(caller, a.tenant_id, attach);
      await requirePolicyManage(caller, a.tenant_id);
      await requireSiteReach(db, a.tenant_id, siteWho(caller), fromDevicesUpdatedSites(plan));
      const created = plan.writes.filter((w) => w.kind === 'create').length;
      return stage(caller, a.tenant_id, 'sites_from_devices', strip(a), plan.result.digest,
        `Sites from the custom fields ${keys.code} / ${keys.name}: ${created} site(s) to create, ${plan.writes.length - created} to complete, ${attach.length} device(s) to attach`, attach);
    }),
  });

  registerTool({
    name: 'upsert_site', title: 'Create or change a site', scope: 'sites.write',
    description: 'Creates the site of this code, or changes it (name, city, contact, group_id: the group its devices may be filed in, values: merged by default, values_mode replace replaces them). dry_run (default true) answers the change; dry_run false asks an authorization.',
    inputSchema: js.obj({
      tenant_id: js.tenant, code: js.str('The code of the site (unique in the tenant, case-blind).', { maxLength: L.codeMax }),
      name: js.str('The name (required to create).', { maxLength: L.nameMax }), city: { type: ['string', 'null'], maxLength: L.cityMax, description: 'The city.' },
      contact: { type: ['string', 'null'], maxLength: L.contactMax, description: 'A contact.' },
      group_id: { type: ['integer', 'null'], minimum: 1, description: 'The group the devices of the site may be filed in.' },
      values: { type: 'object', additionalProperties: { type: 'string', maxLength: L.valueMax }, description: 'Values key → text (keys: letters, digits, _; 50 at most).' },
      values_mode: js.enumOf(['merge', 'replace'], 'merge (default) or replace the values.'), dry_run: js.bool('true (default): the change only.'),
    }, ['tenant_id', 'code']),
    args: ARGS.upsert_site,
    annotations: { title: 'Create or change a site', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => siteWrite(caller, 'upsert_site', a, async () => {
      requireWholeTenant(caller.key);
      const plan = await planUpsert(db, a.tenant_id, a);
      await requireGroupOf(caller, a.tenant_id, a.group_id);
      if (a.dry_run !== false) return { dryRun: true, ...plan.answer, digest: plan.digest };
      if (plan.answer.action === 'unchanged') return { dryRun: false, status: 'nothing_to_apply', ...plan.answer };
      if (plan.prev && siteChanges(plan.prev, checkSite(plan.body, false).site).rendered) {
        await requirePolicyManage(caller, a.tenant_id);
        await requireSiteReach(db, a.tenant_id, siteWho(caller), [plan.prev.id]);
      }
      return stage(caller, a.tenant_id, 'upsert_site', strip(a), plan.digest, plan.summary, []);
    }),
  });

  registerTool({
    name: 'archive_site', title: 'Archive a site', scope: 'sites.write',
    description: 'Archives a site that has no device any more (detach them first with set_device_site). dry_run (default true); dry_run false asks an authorization.',
    inputSchema: js.obj({ tenant_id: js.tenant, site_id: js.str('The site id (uuid).', { format: 'uuid' }), dry_run: js.bool('true (default): the check only.') }, ['tenant_id', 'site_id']),
    args: ARGS.archive_site,
    annotations: { title: 'Archive a site', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => siteWrite(caller, 'archive_site', a, async () => {
      requireWholeTenant(caller.key);
      const plan = await planArchive(db, a.tenant_id, a);
      if (a.dry_run !== false || plan.answer.action === 'unchanged') return { dryRun: a.dry_run !== false, ...plan.answer };
      return stage(caller, a.tenant_id, 'archive_site', strip(a), plan.digest, plan.summary, []);
    }),
  });

  registerTool({
    name: 'set_device_site', title: 'Attach devices to a site', scope: 'sites.write',
    description: `Attaches devices (1 to ${L.bulkDevices}) to a site, or detaches them (site_id null). Their file templates are rendered again with the values of the site. Never moves a device between groups: the answer lists the devices outside the group of the site (move_devices_to_group files them there). dry_run (default true); dry_run false asks ONE authorization for the batch.`,
    inputSchema: js.obj({
      tenant_id: js.tenant, device_ids: js.ids(`Device ids, 1 to ${L.bulkDevices}.`, L.bulkDevices),
      site_id: { type: ['string', 'null'], format: 'uuid', description: 'The site, or null for none.' }, dry_run: js.bool('true (default): the change only.'),
    }, ['tenant_id', 'device_ids', 'site_id']),
    args: ARGS.set_device_site,
    annotations: { title: 'Attach devices to a site', ...WRITE, destructiveHint: false, idempotentHint: true },
    run: (caller, a) => siteWrite(caller, 'set_device_site', a, async () => {
      const ids = [...new Set(a.device_ids)];
      await assertDevicesInPerimeter(caller, a.tenant_id, ids);
      await requireDeviceWrites(caller, a.tenant_id, ids);
      const plan = await planSet(db, a.tenant_id, a);
      if (a.dry_run !== false) return { dryRun: true, ...plan.answer, digest: plan.digest };
      if (plan.answer.action === 'unchanged') return { dryRun: false, status: 'nothing_to_apply', ...plan.answer };
      return stage(caller, a.tenant_id, 'set_device_site', strip(a), plan.digest, plan.summary, ids);
    }),
  });
}

// ── Execution of an approved batch (in the human's request, rights re-checked) ─

interface ApprovedGuard {
  deviceIds: number[];
  impact: number;
  description: string;
  payload: Record<string, unknown>;
  sealed: SiteWriteSealed;
}

/**
 * The console's guard of a write that changes what the templates read (sites/guard.ts), at the approval: the
 * restrictable action sites.apply (its 'sensitive' step stands proven by the fresh factor of the approval; 'restricted'
 * files the console's approval), then, beyond the publication thresholds of its policy impact, the approval site_write
 * filed as the human (a second person). null: the write may run now.
 */
async function guardApproved(x: ExecContext, tenant: number, g: ApprovedGuard): Promise<ExecResult | null> {
  const payload = { action: SITES_APPLY, ...g.payload, policyImpact: g.impact, deviceIds: g.deviceIds.slice(0, 500), source: 'mcp' };
  const description = (x.descriptionPrefix ?? '') + g.description;
  const gate = await x.gate.check({
    tenantId: tenant, actionKey: SITES_APPLY, deviceIds: g.deviceIds, approvalRequestType: SITE_WRITE_APPROVAL,
    approvalDescription: g.description, approvalPayload: payload, approvalSealed: g.sealed,
  });
  if (!gate.ok) {
    if (gate.kind === 'approval') return { state: 'filed', outcome: { approvalId: gate.approvalId } };
    const body = (gate.kind === 'refused' ? gate.body : {}) as { twoFactorRequired?: unknown };
    return { state: 'failed', errorCode: body.twoFactorRequired ? 'stepUpRequired' : gate.kind === 'refused' ? `refused${gate.status}` : 'refused' };
  }
  if (await beyondThresholds(db, tenant, g.impact)) {
    const approval = await approvalService.create({
      tenantId: tenant, userId: x.consoleCaller.userId, requestType: SITE_WRITE_APPROVAL, description, payload, sealed: g.sealed,
    });
    return { state: 'filed', outcome: { approvalId: approval.id, policyImpact: g.impact } };
  }
  return null;
}

/**
 * Runs an approved site batch as its human: the batch read (his, of this tenant, not consumed nor expired), the key
 * still reaching the whole tenant for the writes of the sites, his rights again (mdm.policies.manage and every device
 * of the sites changed for a change of what the templates read), the plan made again and compared with the approved
 * digest (planChanged otherwise: nothing applied), outside then again under the sites lock, the console's guard of the
 * values (guardApproved), then applied once; the authorization closes in the transaction of the write, with the entry
 * of the key (mcp.tool.write), and the batch is consumed there.
 */
export async function executeSiteBatch(x: ExecContext): Promise<ExecResult> {
  const tool = String(x.row.tool) as SiteTool;
  const tenant = Number(x.row.tenant_id);
  const who: Who = { userId: x.consoleCaller.userId, isPlatformAdmin: x.consoleCaller.isPlatformAdmin };
  const sw = siteWho(who);
  const args = BatchArgs.safeParse(x.args);
  if (!args.success || !isSiteTool(tool)) return { state: 'failed', errorCode: 'unknownTool' };
  const batch = await usableBatch(db, tenant, args.data.batch_id, who.userId, [tool], args.data.digest);
  if (!batch) return { state: 'failed', errorCode: 'batchGone' };
  const key = await db('access_keys').where({ id: x.row.key_id, user_id: who.userId }).first('group_mode', 'device_mode') as { group_mode: string; device_mode: string } | undefined;
  if (!key) return { state: 'failed', errorCode: 'perimeterLost' };
  if (!(await holdsTenantCapability(who, tenant, 'devices.manage'))) return { state: 'failed', errorCode: 'perimeterLost' };
  const parsed = ARGS[tool].safeParse(typeof batch.request === 'string' ? JSON.parse(batch.request) : batch.request);
  if (!parsed.success) return { state: 'failed', errorCode: 'batchGone' };
  const digest = args.data.digest;
  const ctx = x.consoleCaller.auditCtx;
  const close = async (trx: Knex.Transaction, outcome: Record<string, unknown>): Promise<void> => {
    await consumeBatch(trx, tenant, String(batch.id));
    await x.finishInTx(trx, { tool, ...outcome });
  };
  const changed = (): ExecResult => ({ state: 'failed', errorCode: 'planChanged' });
  const policyRights = async (): Promise<boolean> => holdsTenantCapability(who, tenant, POLICY_MANAGE);
  try {
    if (tool !== 'set_device_site' && (key.group_mode !== 'all' || key.device_mode !== 'all')) return { state: 'failed', errorCode: 'perimeterLost' };
    switch (tool) {
      case 'import_sites': {
        const a = parsed.data as z.infer<typeof ARGS.import_sites>;
        const { plan, existing } = await importPlanNow(tenant, a.csv);
        if (plan.result.digest !== digest) return changed();
        const updated = importUpdatedSites(plan);
        if (updated.length) {
          if (!(await policyRights())) return { state: 'failed', errorCode: 'capabilityMissing' };
          await requireSiteReach(db, tenant, sw, updated);
          const held = await guardApproved(x, tenant, {
            deviceIds: await managedDevicesOfSites(db, tenant, updated), impact: await sitePolicyImpact(db, tenant, importImpactChange(plan, existing)),
            description: `Import sites: ${plan.result.created} to create, ${plan.result.updated} to update`,
            payload: { op: 'import', created: plan.result.created, updated: plan.result.updated, codes: plan.writes.map((w) => w.site.code).slice(0, 100) },
            sealed: { op: 'import', batchId: String(batch.id), digest, source: 'mcp' },
          });
          if (held) return held;
        }
        const r = await applyImport(tenant, a.csv, ctx, { expectDigest: digest, source: 'mcp', who: sw },
          (trx, res) => close(trx, { created: res.created, updated: res.updated, errors: res.errors }));
        return { state: 'executed', outcome: { created: r.created, updated: r.updated, errors: r.errors } };
      }
      case 'sites_from_devices': {
        const a = parsed.data as z.infer<typeof ARGS.sites_from_devices>;
        const keys = { code: a.code_key ?? 'codeMag', name: a.name_key ?? 'nameMag', values: a.values_keys ?? [] };
        const visible = await visibleOf(who);
        const plan = await previewFromDevices(tenant, keys, visible);
        if (plan.result.digest !== digest) return changed();
        if (!(await policyRights())) return { state: 'failed', errorCode: 'capabilityMissing' };
        const attach = plan.attach.map((d) => d.deviceId);
        await requireDeviceWrites(who, tenant, attach);
        const updated = fromDevicesUpdatedSites(plan);
        await requireSiteReach(db, tenant, sw, updated);
        const created = plan.writes.filter((w) => w.kind === 'create').length;
        const held = await guardApproved(x, tenant, {
          deviceIds: [...new Set([...attach, ...(await managedDevicesOfSites(db, tenant, updated))])], impact: await fromDevicesImpact(tenant, plan),
          description: `Sites from the custom fields ${keys.code} / ${keys.name}: ${created} site(s) to create, ${updated.length} to complete, ${attach.length} device(s) to attach`,
          payload: { op: 'from_devices', keys, created, completed: updated.length, attach: attach.length },
          sealed: { op: 'from_devices', keys, digest, source: 'mcp' },
        });
        if (held) return held;
        const r = await applyFromDevices(tenant, keys, visible, ctx, {
          expectDigest: digest, source: 'mcp', canWrite: (ids) => requireDeviceWrites(who, tenant, ids), who: sw,
        }, (trx, res) => close(trx, { sites: res.sites.length, attached: res.attached }));
        return { state: 'executed', outcome: { sites: r.sites.length, attached: r.attached } };
      }
      case 'upsert_site': {
        const a = parsed.data as UpsertArgs;
        const plan = await planUpsert(db, tenant, a);
        if (plan.digest !== digest) return changed();
        // The group named: the human's rights on it again (a group he lost meanwhile is refused).
        await requireGroupOf(who, tenant, a.group_id);
        // The plan is made again under the sites lock: a write landing in between is never overwritten.
        const again = async (trx: Knex.Transaction): Promise<void> => { if ((await planUpsert(trx, tenant, a)).digest !== digest) throw planChanged(); };
        const done = (trx: Knex.Transaction, s: SiteRow) => close(trx, { siteId: s.id, code: s.code });
        if (!plan.prev) {
          const s = await createSite(tenant, plan.body, ctx, done, { before: again });
          return { state: 'executed', outcome: { siteId: s.id, code: s.code } };
        }
        const site = checkSite(plan.body, false).site;
        const diff = siteChanges(plan.prev, site);
        if (diff.rendered) {
          if (!(await policyRights())) return { state: 'failed', errorCode: 'capabilityMissing' };
          await requireSiteReach(db, tenant, sw, [plan.prev.id]);
          const held = await guardApproved(x, tenant, {
            deviceIds: await managedDevicesOfSites(db, tenant, [plan.prev.id]),
            impact: await sitePolicyImpact(db, tenant, { sites: [siteAfter(plan.prev, site)] }),
            description: `Change the site ${plan.prev.code}: ${diff.fields.join(', ')}`,
            payload: { op: 'update', siteId: plan.prev.id, code: plan.prev.code, fields: diff.fields, valueKeys: diff.valueKeys },
            sealed: { op: 'update', siteId: plan.prev.id, body: plan.body, prevDigest: prevDigestOf(plan.prev), source: 'mcp' },
          });
          if (held) return held;
        }
        const s = await updateSite(tenant, plan.prev.id, plan.body, ctx, done, { who: sw, before: (trx) => again(trx) });
        return { state: 'executed', outcome: { siteId: s.id, code: s.code } };
      }
      case 'archive_site': {
        const a = parsed.data as ArchiveArgs;
        const plan = await planArchive(db, tenant, a);
        if (plan.digest !== digest) return changed();
        const s = await archiveSite(tenant, plan.site.id, ctx, true, (trx, r) => close(trx, { siteId: r.id, code: r.code }), {
          before: async (trx) => { if ((await planArchive(trx, tenant, a)).digest !== digest) throw planChanged(); },
        });
        return { state: 'executed', outcome: { siteId: s.id, code: s.code } };
      }
      case 'set_device_site': {
        const a = parsed.data as SetArgs;
        const visible = await visibleOf(who);
        if (visible !== 'all' && a.device_ids.some((id) => !visible.includes(id))) return { state: 'failed', errorCode: 'perimeterLost' };
        await requireDeviceWrites(who, tenant, a.device_ids);
        const plan = await planSet(db, tenant, a);
        if (plan.digest !== digest) return changed();
        const r = await setDevicesSite(tenant, plan.ids, a.site_id, ctx, (trx, o) => close(trx, { changed: o.changed.length }), {
          before: async (trx) => { if ((await planSet(trx, tenant, a)).digest !== digest) throw planChanged(); },
        });
        return { state: 'executed', outcome: { changed: r.changed.length, outsideGroup: r.outsideGroup } };
      }
    }
  } catch (err) {
    if (err instanceof AppError && err.code === 'planChanged') return changed();
    if (err instanceof AppError && err.statusCode < 500) return { state: 'failed', errorCode: err.code ?? `refused${err.statusCode}` };
    throw err;
  }
  return { state: 'failed', errorCode: 'unknownTool' };
}
