import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { Router, type Request, type Response } from 'express';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  AGENT_POLICY_ITEM_STATES, LEGACY_AGENT_DEVICE_VALUES_LIMITS as DV, deviceCodePattern, LEGACY_AGENT_POLICY_ARTIFACT_KEY, LEGACY_AGENT_POLICY_LIMITS as L,
  LEGACY_AGENT_POLICY_MIN_VERSION_CODE, PUBLISH_APPROVAL_THRESHOLDS, isAgentTemplateVariable, variablesInString,
  type AgentPolicyReportItem, type AgentPolicyReportState, type LegacyAgentDeviceValuesImportResult, type LegacyAgentDeviceValuesPreviewRow,
  type LegacyAgentPolicyStatusView,
} from '@obligarth/shared';
import { audit } from '../audit';
import { db } from '../db';
import { userActor } from '../db/context';
import { tenantFrozen } from '../guard/frozen';
import { AppError } from '../middleware/errorHandler';
import { requireTenantCapability } from '../middleware/rbac';
import { approvalService, activeRequester, refuse, requireTenantCapability as requesterHolds, type ApprovalExecution } from '../services/approval.service';
import { deviceService } from '../services/device.service';
import { permissionService } from '../services/permission.service';
import { applyRestriction } from '../services/restriction.service';
import { logger } from '../utils/logger';
import { deviceFactsEffect } from '../mdm/groups/governance';
import type { DevicePatch } from '../mdm/registry/devicePatch';
import { requestGroupEvaluation } from '../mdm/groups/triggers';
import { withConfigurationLock } from '../mdm/policies/configLock';
import { loadResolutionInput, loadDevices } from '../mdm/policies/loader';
import { resolveDevices, variableValue } from '../mdm/policies/resolver';
import { requestDeviceResolution } from '../mdm/policies/triggers';
import { fleetShareFloor } from '../mdm/settings';
import { fileUsage, fileView, mediaTypeOf, receiveFile, settleKind, storedFilePath } from './files';
import { compileAgentPolicy, renderTemplate } from './policyChannel';
import { frozenWithhold } from './policyDelivery';
import { body, deviceOf, uploadLimiter, visible, wrap } from './routes';

// =============================================================================
// Console API of the agent policies (lot PONT-POL §9.2), mounted with the
// bridge agent's routes at /api/legacy-agent (createLegacyAgentRouter):
//   GET    /files                      the tenant's store (any member), with what uses each file
//   POST   /files?name=&note=          raw upload (mdm.policies.manage): kind inferred, idempotent by content
//   PATCH  /files/:id                  name, note
//   DELETE /files/:id                  under the configuration lock; 409 fileInUse while referenced
//   GET    /files/:id/content          preview (mdm.policies.manage): images and files of 64 KiB at most
//   POST   /policy/render-preview      a template rendered with a device's values (never logged)
//   GET    /policy/custom-keys         the custom fields of the bridge devices (variable picker)
//   POST   /policy/import-images       the store images of a MobiControl import marked origin 'import'
//   GET    /devices/:id/policy         the state of a device's agent policy
//   POST   /device-values              import of per-device values (devices.manage and mdm.policies.manage): preview,
//                                      or apply (restrictable action legacy_agent.device_values_import; beyond the
//                                      publication thresholds of its policy impact, a request for approval: D18)
// The values of the devices are customer data: never in a log nor an audit entry (keys only).
// =============================================================================

const POLICY_MANAGE = 'mdm.policies.manage' as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const jsonOf = (v: unknown): any => { if (typeof v !== 'string') return v ?? null; try { return JSON.parse(v); } catch { return null; } };
const NAME_RE = /^[^\u0000-\u001f\u007f/\\]{1,200}$/;

const cleanName = (v: unknown): string | null => {
  const s = typeof v === 'string' ? v.trim() : '';
  return s && NAME_RE.test(s) ? s : null;
};
const cleanNote = (v: unknown): string | null | undefined => {
  if (v === undefined) return undefined;
  if (v === null || v === '') return null;
  const s = String(v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 500);
  return s || null;
};

async function fileRow(tenantId: number, id: string): Promise<Record<string, any>> {
  if (!UUID_RE.test(id)) throw new AppError(404, 'File not found');
  const r = await db('legacy_agent_files').where({ tenant_id: tenantId, id: id.toLowerCase() }).first() as Record<string, any> | undefined;
  if (!r) throw new AppError(404, 'File not found');
  return r;
}

/** usedBy of every file of a list at once, counted by the database (never the texts in this process): the versions and
 *  the distinct desired bodies that name each SHA-256 (fileUsage per file, grouped). */
async function usageOf(tenantId: number, shas: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>(shas.map((s) => [s, 0]));
  if (!shas.length) return out;
  const versions = await db.raw(`
    SELECT s.sha, count(v.id)::int AS n
      FROM unnest(?::text[]) AS s(sha)
      JOIN policy_versions v ON v.tenant_id = ? AND v.state IN ('draft', 'pending_approval', 'published')
       AND jsonb_typeof(v.content -> 'sections' -> 'legacyAgent') = 'object'
       AND strpos(v.content::text, s.sha) > 0
     GROUP BY s.sha`, [shas, tenantId]) as { rows: Array<{ sha: string; n: number }> };
  const bodies = await db.raw(`
    WITH b AS (
      SELECT m.hash, m.body
        FROM (SELECT DISTINCT x.tenant_id, x.desired_hash FROM device_artifacts x
               WHERE x.tenant_id = ? AND x.artifact_key = ? AND x.desired_hash IS NOT NULL) d
        JOIN mdm_artifacts m ON m.tenant_id = d.tenant_id AND m.hash = d.desired_hash)
    SELECT s.sha, count(b.hash)::int AS n
      FROM unnest(?::text[]) AS s(sha)
      JOIN b ON b.body -> 'blobs' @> jsonb_build_array(s.sha) OR strpos(b.body::text, s.sha) > 0
     GROUP BY s.sha`, [tenantId, LEGACY_AGENT_POLICY_ARTIFACT_KEY, shas]) as { rows: Array<{ sha: string; n: number }> };
  for (const r of [...versions.rows, ...bodies.rows]) out.set(r.sha, (out.get(r.sha) ?? 0) + Number(r.n));
  return out;
}

export function policyRouter(): Router {
  const router = Router();

  // ── File store ─────────────────────────────────────────────────────────────

  router.get('/files', wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const rows = await db('legacy_agent_files').where({ tenant_id: tenantId }).orderBy('created_at', 'desc').limit(1000).select('*') as Array<Record<string, any>>;
    const usage = await usageOf(tenantId, rows.map((r) => String(r.sha256).trim()));
    res.json({ success: true, data: rows.map((r) => fileView(r, usage.get(String(r.sha256).trim()) ?? 0)) });
  }));

  // POST /api/legacy-agent/files?name=&note= (body: the file)
  router.post('/files', requireTenantCapability(POLICY_MANAGE), uploadLimiter, wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const name = cleanName(req.query.name);
    if (!name) throw new AppError(400, 'A name of 1 to 200 characters is required', 'invalidRequest', { field: 'name' });
    const note = cleanNote(req.query.note) ?? null;
    const mediaType = mediaTypeOf(req);
    const max = mediaType.startsWith('image/') ? L.imageBytes : L.storeFileBytes;
    const received = await receiveFile(req, tenantId, max);
    const file = await settleKind(tenantId, received, { name, mediaType });
    const auditCtx = await audit.fromRequest(req, tenantId);
    const { row, created } = await db.transaction(async (trx) => {
      const existing = await trx('legacy_agent_files').where({ tenant_id: tenantId, sha256: file.sha256 }).first() as Record<string, any> | undefined;
      if (existing) return { row: existing, created: false };
      const used = await trx('legacy_agent_files').where({ tenant_id: tenantId }).sum<{ n: string | null }[]>('size_bytes as n').first();
      if (Number(used?.n ?? 0) + file.size > L.storeTenantBytes) throw new AppError(413, 'The file store of the tenant is full (2 GiB)', 'quotaExceeded');
      const [r] = await trx('legacy_agent_files').insert({
        tenant_id: tenantId, sha256: file.sha256, size_bytes: file.size, name, content_type: file.contentType, kind: file.kind, origin: 'upload',
        note, created_by: req.session.userId ?? null,
      }).returning('*') as Array<Record<string, any>>;
      await audit.appendInTx(trx, {
        tenantId, action: 'legacy_agent.file_uploaded', target: { type: 'legacy_agent_file', id: String(r.id) },
        details: { sha256: file.sha256, size: file.size, name, kind: file.kind },
      }, auditCtx);
      return { row: r, created: true };
    });
    res.status(created ? 201 : 200).json({ success: true, data: fileView(row) });
  }));

  const PatchBody = z.object({ name: z.string().max(200).optional(), note: z.string().max(500).nullable().optional() }).strict();

  router.patch('/files/:id', requireTenantCapability(POLICY_MANAGE), wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const b = body(PatchBody, req);
    const r = await fileRow(tenantId, String(req.params.id));
    const changes: Record<string, unknown> = {};
    if (b.name !== undefined) {
      const name = cleanName(b.name);
      if (!name) throw new AppError(400, 'A name of 1 to 200 characters is required', 'invalidRequest', { field: 'name' });
      changes.name = name;
    }
    if (b.note !== undefined) changes.note = cleanNote(b.note);
    if (!Object.keys(changes).length) { res.json({ success: true, data: fileView(r) }); return; }
    const auditCtx = await audit.fromRequest(req, tenantId);
    const row = await db.transaction(async (trx) => {
      const [u] = await trx('legacy_agent_files').where({ tenant_id: tenantId, id: r.id }).update(changes).returning('*') as Array<Record<string, any>>;
      await audit.appendInTx(trx, {
        tenantId, action: 'legacy_agent.file_renamed', target: { type: 'legacy_agent_file', id: String(r.id) },
        details: { fields: Object.keys(changes), ...(changes.name ? { name: changes.name } : {}) },
      }, auditCtx);
      return u;
    });
    res.json({ success: true, data: fileView(row) });
  }));

  // A file is deleted under the configuration lock, which a publication takes too: either the publication sees the row,
  // or it answers file_not_found (B6).
  router.delete('/files/:id', requireTenantCapability(POLICY_MANAGE), wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const r = await fileRow(tenantId, String(req.params.id));
    const auditCtx = await audit.fromRequest(req, tenantId);
    await withConfigurationLock(tenantId, async (trx) => {
      const used = await fileUsage(trx, tenantId, String(r.sha256).trim());
      if (used > 0) throw new AppError(409, 'The file is used by a policy', 'fileInUse', { usedBy: used });
      await trx('legacy_agent_files').where({ tenant_id: tenantId, id: r.id }).delete();
      await audit.appendInTx(trx, {
        tenantId, action: 'legacy_agent.file_deleted', target: { type: 'legacy_agent_file', id: String(r.id) },
        details: { sha256: String(r.sha256).trim(), name: r.name, kind: r.kind },
      }, auditCtx);
    });
    // The bytes are left to the collection (24 hours): an upload of the same content meanwhile keeps them.
    res.json({ success: true, data: { deleted: true } });
  }));

  router.get('/files/:id/content', requireTenantCapability(POLICY_MANAGE), wrap(async (req, res) => {
    const tenantId = req.tenantId!;
    const r = await fileRow(tenantId, String(req.params.id));
    const sha = String(r.sha256).trim();
    const size = Number(r.size_bytes);
    if (r.kind === 'file' && size > 64 * 1024) throw new AppError(422, 'Only files of 64 KiB at most are previewed', 'previewTooLarge');
    const file = storedFilePath(tenantId, sha);
    const st = await stat(file).catch(() => null);
    if (!st || !st.isFile() || st.size !== size) {
      logger.error({ tenantId }, 'agent files: a stored file is missing');
      throw new AppError(404, 'File not found');
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    if (r.kind === 'image') res.setHeader('Content-Type', r.content_type);
    else {
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', 'attachment');
    }
    res.setHeader('Content-Length', String(size));
    createReadStream(file).pipe(res);
  }));

  // ── Templates ──────────────────────────────────────────────────────────────

  const PreviewBody = z.object({
    template: z.string().max(L.templateBytes), encoding: z.enum(['text', 'json']), deviceId: z.union([z.number(), z.string()]),
  }).strict();

  router.post('/policy/render-preview', requireTenantCapability(POLICY_MANAGE), wrap(async (req, res) => {
    const b = body(PreviewBody, req);
    req.params.id = String(b.deviceId);
    const id = await deviceOf(req);
    const tenantId = req.tenantId!;
    const t = await db('tenants').where({ id: tenantId }).first('name', 'slug') as { name: string; slug: string } | undefined;
    const tenant = { name: t?.name ?? '', slug: t?.slug ?? '' };
    const set = await loadDevices(db, tenantId, [id]);
    const device = set.devices[0];
    if (!device) throw new AppError(404, 'Device not found');
    const vars = variablesInString(b.template, isAgentTemplateVariable);
    const missing = [...vars.unknown, ...vars.known.filter((v) => variableValue(v, device, tenant, 'agent') === null)];
    const text = renderTemplate(b.template, b.encoding, (n) => variableValue(n as never, device, tenant, 'agent') ?? '') ?? '';
    let jsonValid: boolean | null = null;
    if (b.encoding === 'json') { try { JSON.parse(text); jsonValid = true; } catch { jsonValid = false; } }
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, data: { text, missing, jsonValid } });
  }));

  router.get('/policy/custom-keys', wrap(async (req, res) => {
    const rows = await db('devices').where({ tenant_id: req.tenantId!, management_channel: 'legacy_agent' })
      .whereRaw("jsonb_typeof(custom_fields) = 'object'")
      .distinct(db.raw('jsonb_object_keys(custom_fields) AS k')).limit(200) as Array<{ k: string }>;
    res.json({ success: true, data: rows.map((r) => r.k).filter((k) => L.customKeyRe.test(k)).sort() });
  }));

  const ImportImagesBody = z.object({
    names: z.array(z.object({ name: z.string().max(200), sha256: z.string().regex(/^[0-9a-f]{64}$/) }).strict()).min(1).max(L.tiles + 1),
  }).strict();

  router.post('/policy/import-images', requireTenantCapability(POLICY_MANAGE), wrap(async (req, res) => {
    const b = body(ImportImagesBody, req);
    const tenantId = req.tenantId!;
    let marked = 0;
    await db.transaction(async (trx) => {
      for (const x of b.names) {
        const name = cleanName(x.name);
        marked += await trx('legacy_agent_files').where({ tenant_id: tenantId, sha256: x.sha256, kind: 'image' })
          .update({ origin: 'import', ...(name ? { name } : {}) });
      }
    });
    res.json({ success: true, data: { marked } });
  }));

  // ── The state of a device's policy ─────────────────────────────────────────

  router.get('/devices/:id/policy', wrap(async (req, res) => {
    const id = await deviceOf(req);
    const tenantId = req.tenantId!;
    const sat = await db('legacy_agent_devices').where({ tenant_id: tenantId, device_id: id }).first('agent_version_code') as { agent_version_code: number } | undefined;
    if (!sat) throw new AppError(404, 'Device not found');
    const art = await db('device_artifacts').where({ tenant_id: tenantId, device_id: id, artifact_key: LEGACY_AGENT_POLICY_ARTIFACT_KEY }).first() as Record<string, any> | undefined;
    const desired = art?.desired_hash ? String(art.desired_hash).trim() : null;
    let dropped: Array<{ key: string; code: string }> = [];
    let withheld: string[] = [];
    if (desired) {
      const m = await db('mdm_artifacts').where({ tenant_id: tenantId, hash: desired }).first('body') as { body: unknown } | undefined;
      const b = jsonOf(m?.body);
      if (b && Array.isArray(b.dropped)) dropped = b.dropped.filter((d: any) => d && typeof d.key === 'string' && typeof d.code === 'string');
      if (b) {
        withheld = await db.transaction(async (trx) => (await tenantFrozen(trx, tenantId, 'legacy_agent')
          ? frozenWithhold(trx, tenantId, id, b, { delivered_hash: art?.delivered_hash ?? null, desired_hash: desired }) : []));
      }
    }
    const rep = await db('legacy_agent_policy_reports').where({ tenant_id: tenantId, device_id: id }).first() as Record<string, any> | undefined;
    const reasons = jsonOf(art?.state_reasons);
    const view: LegacyAgentPolicyStatusView = {
      supported: Number(sat.agent_version_code) >= LEGACY_AGENT_POLICY_MIN_VERSION_CODE, agentVersionCode: Number(sat.agent_version_code),
      desiredHash: desired, deliveredHash: art?.delivered_hash ? String(art.delivered_hash).trim() : null, artifactState: art?.state ?? null,
      reasons: Array.isArray(reasons) ? reasons.filter((r: unknown) => typeof r === 'string') : [], dropped, withheld,
      report: rep ? {
        hash: rep.policy_hash ? String(rep.policy_hash).trim() : null, state: rep.state as AgentPolicyReportState, reportedAt: iso(rep.received_at) as string,
        appliedAt: iso(rep.applied_at), knoxState: rep.knox_state ?? null,
        counts: { compliant: rep.compliant, nonCompliant: rep.non_compliant, pending: rep.pending, pendingLicence: rep.pending_licence,
          unsupported: rep.unsupported, errors: rep.errors },
        items: (jsonOf(rep.items) ?? []).filter((i: any) => i && typeof i.key === 'string' && (AGENT_POLICY_ITEM_STATES as readonly string[]).includes(i.state)) as AgentPolicyReportItem[],
      } : null,
    };
    res.json({ success: true, data: view });
  }));

  // ── Per-device values ──────────────────────────────────────────────────────

  router.post('/device-values', requireTenantCapability('devices.manage'), requireTenantCapability(POLICY_MANAGE), wrap(async (req, res) => {
    const b = body(DeviceValuesBody, req);
    const tenantId = req.tenantId!;
    const userId = req.session.userId!;
    const isAdmin = req.session.role === 'admin';
    const seen = await visible(req);
    const plan = await planDeviceValues(db, tenantId, b, { visible: seen, canWrite: (id) => (isAdmin ? Promise.resolve(true) : permissionService.canWriteDevice(userId, id, false)) });
    if (!b.apply) { res.json({ success: true, data: plan.result }); return; }
    const changedIds = [...plan.changes.keys()];
    if (!changedIds.length) { res.json({ success: true, data: { ...plan.result, applied: true } }); return; }
    const keys = [...new Set([...plan.changes.values()].flatMap((v) => Object.keys(v)))].sort();
    const payload = { action: 'legacy_agent.device_values', devices: changedIds.length, keys, deviceIds: changedIds.slice(0, 500) };
    const sealed = { rows: b.rows, match: b.match };
    const description = `Import per-device values on ${changedIds.length} Android agent device(s) — keys: ${keys.slice(0, 10).join(', ')}`;
    const ok = await applyRestriction(res, {
      req, actionKey: 'legacy_agent.device_values_import', deviceIds: changedIds, approvalRequestType: 'legacy_agent_device_values',
      approvalDescription: description, approvalPayload: payload, approvalSealed: sealed,
    });
    if (!ok) return;
    // D18: beyond the publication thresholds of its policy impact, a second person approves the import.
    if (await beyondThresholds(db, tenantId, plan.result.policyImpact)) {
      const approval = await approvalService.create({ tenantId, userId, requestType: 'legacy_agent_device_values', description, payload, sealed });
      res.status(202).json({ success: true, data: { approvalId: approval.id, status: 'pending_approval', code: 'approvalRequired', policyImpact: plan.result.policyImpact } });
      return;
    }
    const auditCtx = await audit.fromRequest(req, tenantId);
    const out = await applyDeviceValues(tenantId, b, { visible: seen, canWrite: (id) => (isAdmin ? Promise.resolve(true) : permissionService.canWriteDevice(userId, id, false)) }, auditCtx);
    res.json({ success: true, data: out });
  }));

  return router;
}

// ── Per-device values: matching, preview, apply (§12.1) ─────────────────────

const KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;

const DeviceValuesBody = z.object({
  rows: z.array(z.object({
    deviceKey: z.string().trim().min(1).max(200),
    values: z.record(z.string().max(DV.valueMax)).refine((v) => Object.keys(v).length <= DV.valuesPerRow && Object.keys(v).every((k) => KEY_RE.test(k)),
      'values: 16 keys at most, names of letters, digits, _ and -'),
    source: z.string().max(300).optional(),
  }).strict()).min(1).max(DV.rows),
  match: z.object({
    byName: z.boolean(),
    byCode: z.object({ nameRegex: z.string().min(1).max(DV.nameRegexMax), field: z.string().regex(KEY_RE), pad: z.number().int().min(1).max(12) }).strict().optional(),
  }).strict(),
  apply: z.boolean().optional(),
}).strict();
type DeviceValuesBody = z.infer<typeof DeviceValuesBody>;

interface PlanScope { visible: number[] | 'all'; canWrite: (deviceId: number) => Promise<boolean> }

const codeOf = (s: string, pad: number): string | null => {
  const t = s.trim();
  if (!/^[0-9]{1,24}$/.test(t)) return null;
  return t.replace(/^0+/, '').padStart(pad, '0');
};

interface Plan {
  result: LegacyAgentDeviceValuesImportResult;
  /** Device → the values that change (merged into its custom fields). */
  changes: Map<number, Record<string, string>>;
}

/** The matching and the preview of an import, as `q` reads the tenant (§12.1). */
async function planDeviceValues(q: Knex | Knex.Transaction, tenantId: number, b: DeviceValuesBody, scope: PlanScope): Promise<Plan> {
  let query = q('legacy_agent_devices as a')
    .join('devices as d', function j() { this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', 'a.tenant_id'); })
    .where('a.tenant_id', tenantId).whereNull('a.revoked_at').whereNot('d.enrollment_state', 'unenrolled');
  if (scope.visible !== 'all') query = query.whereRaw('d.id = ANY (?::int[])', [scope.visible]);
  const devices = (await query.select('d.id', 'd.label', 'd.custom_fields') as Array<{ id: number; label: string | null; custom_fields: unknown }>)
    .map((d) => {
      const f = jsonOf(d.custom_fields);
      return { id: Number(d.id), name: String(d.label ?? '').trim(), fields: (f && typeof f === 'object' && !Array.isArray(f) ? f : {}) as Record<string, unknown> };
    });
  const byName = new Map<string, number[]>();
  for (const d of devices) {
    const k = d.name.toLowerCase();
    if (k) byName.set(k, [...(byName.get(k) ?? []), d.id]);
  }
  // Never an arbitrary pattern on the shared event loop: only the restricted form of deviceCodePattern (a literal
  // prefix, one digit group, a literal suffix), which cannot backtrack. The executor of an approval replays it too.
  let re: RegExp | null = null;
  if (b.match.byCode) {
    re = deviceCodePattern(b.match.byCode.nameRegex);
    if (!re) {
      throw new AppError(400, 'nameRegex: only a literal prefix, one digit group such as (\\d{5}) and a literal suffix are accepted',
        'invalidRequest', { field: 'nameRegex' });
    }
  }
  const byCode = new Map<string, number[]>();
  if (re && b.match.byCode) {
    for (const d of devices) {
      if (d.name.length > 200) continue;
      const m = re.exec(d.name);
      const code = m?.[1] !== undefined ? codeOf(m[1], b.match.byCode.pad) : null;
      if (code) byCode.set(code, [...(byCode.get(code) ?? []), d.id]);
    }
  }
  const byId = new Map(devices.map((d) => [d.id, d]));
  // 1. The devices of each row.
  const matched = b.rows.map((r, index) => {
    const exact = b.match.byName ? byName.get(r.deviceKey.trim().toLowerCase()) ?? [] : [];
    if (exact.length === 1) return { index, kind: 'exact' as const, ids: exact };
    if (exact.length > 1) return { index, kind: 'conflict' as const, ids: exact };
    if (b.match.byCode) {
      const v = r.values[b.match.byCode.field];
      const code = typeof v === 'string' ? codeOf(v, b.match.byCode.pad) : null;
      const ids = code ? byCode.get(code) ?? [] : [];
      if (ids.length) return { index, kind: 'code' as const, ids };
    }
    return { index, kind: 'unmatched' as const, ids: [] as number[] };
  });
  // 2. A device several rows reach is a conflict for each of them.
  const rowsOf = new Map<number, number>();
  for (const m of matched) for (const id of m.ids) rowsOf.set(id, (rowsOf.get(id) ?? 0) + 1);

  const result: LegacyAgentDeviceValuesImportResult = {
    applied: false, rows: [], updated: 0, unchanged: 0, skipped: { unmatched: 0, conflict: 0, governed: 0, outOfScope: 0 }, policyImpact: 0,
  };
  const changes = new Map<number, Record<string, string>>();
  for (const m of matched) {
    const r = b.rows[m.index];
    const row: LegacyAgentDeviceValuesPreviewRow = { index: m.index, deviceKey: r.deviceKey, match: m.kind, devices: [] };
    result.rows.push(row);
    if (m.kind === 'unmatched') { result.skipped.unmatched++; continue; }
    for (const id of m.ids) {
      const d = byId.get(id)!;
      const diff = Object.entries(r.values).filter(([k, v]) => d.fields[k] !== v).map(([k, v]) => ({ key: k, from: typeof d.fields[k] === 'string' ? d.fields[k] as string : null, to: v }));
      const entry: LegacyAgentDeviceValuesPreviewRow['devices'][number] = { deviceId: id, name: d.name, changes: diff, status: 'change' };
      row.devices.push(entry);
      if (m.kind === 'conflict' || (rowsOf.get(id) ?? 0) > 1) { entry.status = 'conflict'; result.skipped.conflict++; continue; }
      if (!diff.length) { entry.status = 'unchanged'; result.unchanged++; continue; }
      if (!(await scope.canWrite(id))) { entry.status = 'outOfScope'; result.skipped.outOfScope++; continue; }
      const merged = { ...d.fields, ...Object.fromEntries(diff.map((c) => [c.key, c.to])) };
      const effect = await deviceFactsEffect(q, tenantId, id, { customFields: merged } as DevicePatch);
      if (effect.entered.length || effect.left.length) { entry.status = 'governed'; result.skipped.governed++; continue; }
      changes.set(id, Object.fromEntries(diff.map((c) => [c.key, c.to])));
    }
    if (row.devices.every((x) => x.status === 'conflict')) row.match = 'conflict';
  }
  result.updated = changes.size;
  result.policyImpact = await policyImpactOf(q, tenantId, changes);
  return { result, changes };
}

/** How many devices' agent:policy the changes would change: their resolution compiled before and after, in memory. */
async function policyImpactOf(q: Knex | Knex.Transaction, tenantId: number, changes: Map<number, Record<string, string>>): Promise<number> {
  if (!changes.size) return 0;
  const ids = [...changes.keys()];
  const input = await loadResolutionInput(q, tenantId, ids);
  const before = resolveDevices(input);
  const patched = input.devices.map((d) => ({ ...d, customFields: { ...(d.customFields ?? {}), ...(changes.get(d.id) ?? {}) } }));
  const after = resolveDevices({ ...input, devices: patched });
  let n = 0;
  input.devices.forEach((d, i) => {
    const a = compileAgentPolicy(d, before.devices[i].settings, input.tenant, tenantId)?.hash ?? null;
    const b = compileAgentPolicy(patched[i], after.devices[i].settings, input.tenant, tenantId)?.hash ?? null;
    if (a !== b) n++;
  });
  return n;
}

/** Does a policy impact reach the publication thresholds of the tenant (D18)? */
async function beyondThresholds(q: Knex | Knex.Transaction, tenantId: number, impact: number): Promise<boolean> {
  if (impact <= 0) return false;
  const T = PUBLISH_APPROVAL_THRESHOLDS;
  if (impact >= T.devicesTouched) return true;
  const fleet = await q('devices').where({ tenant_id: tenantId }).whereNot('enrollment_state', 'unenrolled').count({ n: '*' }).first() as { n: string | number };
  const size = Number(fleet?.n ?? 0);
  const floor = await fleetShareFloor(q, tenantId);
  return impact >= floor && size > 0 && impact >= T.fleetShare * size;
}

/** The apply of an import, in one transaction under the configuration lock: the plan made again (governed checked
 *  again), the values merged into the devices' custom fields (never a key removed), one audit entry per device (keys
 *  only), their resolution requested. */
async function applyDeviceValues(tenantId: number, b: DeviceValuesBody, scope: PlanScope,
  auditCtx: Awaited<ReturnType<typeof audit.fromRequest>>): Promise<LegacyAgentDeviceValuesImportResult> {
  const out = await withConfigurationLock(tenantId, async (trx) => {
    const plan = await planDeviceValues(trx, tenantId, b, scope);
    const ids = [...plan.changes.keys()].sort((x, y) => x - y);
    if (ids.length) await trx('devices').where({ tenant_id: tenantId }).whereRaw('id = ANY (?::int[])', [ids]).orderBy('id').forUpdate().select('id');
    const now = new Date();
    for (const id of ids) {
      const values = plan.changes.get(id)!;
      await trx('devices').where({ tenant_id: tenantId, id })
        .update({ custom_fields: trx.raw("COALESCE(CASE WHEN jsonb_typeof(custom_fields) = 'object' THEN custom_fields END, '{}'::jsonb) || ?::jsonb", [JSON.stringify(values)]), updated_at: now });
      await audit.appendInTx(trx, {
        tenantId, action: 'legacy_agent.device_values_imported', target: { type: 'device', id: String(id), device: id },
        details: { keys: Object.keys(values).sort() },
      }, auditCtx);
    }
    if (ids.length) {
      await requestDeviceResolution(trx, tenantId, ids);
      await requestGroupEvaluation(trx, tenantId, ids);
    }
    return { ...plan.result, applied: true };
  });
  if (out.updated) deviceService.emitChanged(tenantId, out.rows.flatMap((r) => r.devices.filter((d) => d.status === 'change').map((d) => d.deviceId)));
  return out;
}

/** The executor of an approved import of per-device values (D18): as the requester, whose capabilities and devices are
 *  read again; the rows come from the sealed part of the request. */
export async function executeDeviceValuesImport(x: ApprovalExecution): Promise<string | void> {
  const parsed = DeviceValuesBody.safeParse({ ...(x.sealed ?? {}), apply: true });
  if (!parsed.success) refuse('This request carries no values any more: import the file again');
  const requester = await activeRequester(x.requesterId);
  await requesterHolds(x.requesterId, x.tenantId, 'devices.manage');
  await requesterHolds(x.requesterId, x.tenantId, POLICY_MANAGE);
  const seen = requester.isPlatformAdmin ? 'all' as const : await permissionService.getVisibleDeviceIds(x.requesterId, false);
  const auditCtx = await audit.fromDbActor(userActor(x.requesterId), x.tenantId);
  const out = await applyDeviceValues(x.tenantId, parsed.data!, {
    visible: seen, canWrite: (id) => (requester.isPlatformAdmin ? Promise.resolve(true) : permissionService.canWriteDevice(x.requesterId, id, false)),
  }, auditCtx);
  const skipped = out.skipped.conflict + out.skipped.governed + out.skipped.outOfScope + out.skipped.unmatched;
  return skipped ? `${out.updated} device(s) updated, ${skipped} row(s) or device(s) set aside` : undefined;
}
