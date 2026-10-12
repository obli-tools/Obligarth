import { Router, type NextFunction, type Request, type Response } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { POLICY_STATES, type ImpactDevicesPage } from '@obligarth/shared';
import { db } from '../../db';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { requireTenantCapability } from '../../middleware/rbac';
import { permissionService } from '../../services/permission.service';
import { appleCatalog } from '../apple/catalog';
import { listAssignments } from '../policies/assignments';
import { computeImpact, conflictsOf } from '../policies/impact';
import { cacheTouched, cachedTouched, verifyImpactToken } from '../policies/impactToken';
import { policyService, type PolicyActor } from '../policies/policyService';
import { changeAssignments, emitPolicyChanged, submitVersion, versionImpact, type RouteOutcome } from '../policies/publish';

// =============================================================================
// Console API of the policies (docs: modele-donnees-mdm §7, §10.6): mounted at
// /api/mdm, in the tenant of the session. Reads: any member (the assignments
// and the samples of a preview are limited to the caller's scopes); writes:
// mdm.policies.manage, plus write access on the target of an assignment (the
// whole tenant: a tenant administrator). A publication and a change of
// assignments go through the preview and the restriction mdm.policy_publish
// (a step-up, a second approver beyond the thresholds). Secrets typed in
// ({"$secretValue"}) never come back, nor go to a log.
// =============================================================================

const router = Router();
const manage = requireTenantCapability('mdm.policies.manage');
/** A .mobileconfig, in memory: 1 MiB at most, one file. */
const profileUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024, files: 1, fields: 4, parts: 6 } }).single('file');
const uploadProfile = (req: Request, res: Response, next: NextFunction): void => {
  profileUpload(req, res, (err: unknown) => {
    if (!err) { next(); return; }
    const code = (err as { code?: string }).code;
    next(new AppError(code === 'LIMIT_FILE_SIZE' ? 413 : 400, code === 'LIMIT_FILE_SIZE' ? 'The profile is larger than 1 MiB' : 'Invalid upload', 'rawProfileInvalid',
      { reason: code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'invalid_upload' }));
  });
};

const CreateBody = z.object({
  name: z.string().max(200),
  description: z.string().max(10_000).nullable().optional(),
  category: z.string().max(32).optional(),
  copyFrom: z.number().int().positive().nullable().optional(),
}).strict();
const PatchBody = z.object({
  name: z.string().max(200).optional(),
  description: z.string().max(10_000).nullable().optional(),
  category: z.string().max(32).optional(),
}).strict();
const DraftBody = z.object({
  content: z.record(z.string(), z.unknown()),
  changeNote: z.string().max(2000).nullable().optional(),
}).strict();
const NewVersionBody = z.object({
  /** Number of a rejected version to take up again (default: a copy of the published version). */
  from: z.number().int().positive().optional(),
}).strict();
const ListQuery = z.object({
  state: z.enum(POLICY_STATES).optional(),
  category: z.string().max(32).optional(),
  q: z.string().max(200).optional(),
}).passthrough();
const AssignmentQuery = z.object({
  resourceType: z.enum(['policy', 'app']).optional(),
  resourceId: z.coerce.number().int().positive().optional(),
  targetScope: z.enum(['tenant', 'group', 'device']).optional(),
  targetId: z.coerce.number().int().positive().optional(),
}).passthrough();
const PageQuery = z.object({
  page: z.coerce.number().int().positive().max(100_000).optional(),
  pageSize: z.coerce.number().int().positive().max(500).optional(),
}).passthrough();

function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

const idParam = (raw: string, what = 'Policy'): number => {
  if (!/^[1-9][0-9]{0,9}$/.test(raw)) throw new AppError(404, `${what} not found`);
  return Number(raw);
};

async function actorOf(req: Request): Promise<PolicyActor> {
  return { userId: req.session.userId ?? null, auditCtx: await audit.fromRequest(req, req.tenantId!) };
}

function send(res: Response, out: RouteOutcome): void {
  for (const [k, v] of Object.entries(out.headers ?? {})) res.setHeader(k, v);
  res.status(out.status).json(out.body);
}

/** Is the caller an administrator of the tenant (platform administrator, or tenant role admin)? */
async function isTenantAdmin(req: Request): Promise<boolean> {
  if (req.session.role === 'admin') return true;
  const ut = await db('user_tenants').where({ user_id: req.session.userId, tenant_id: req.tenantId }).first('role') as { role: string } | undefined;
  return ut?.role === 'admin';
}

// ── Policies ───────────────────────────────────────────────────────────────

// GET /api/mdm/policies?state=&category=&q=
router.get('/policies', async (req, res, next) => {
  try {
    const q = parse(ListQuery, req.query);
    res.json({ data: await policyService.list(req.tenantId!, { state: q.state, category: q.category, q: q.q }) });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies — { name, description?, category?, copyFrom? }: the envelope and its draft 1.
router.post('/policies', manage, async (req, res, next) => {
  try {
    const b = parse(CreateBody, req.body);
    const out = await policyService.create(req.tenantId!, b, await actorOf(req));
    emitPolicyChanged(req.tenantId!, [out.policy.id]);
    res.status(201).json({ data: out });
  } catch (err) { next(err); }
});

// GET /api/mdm/policies/:id
router.get('/policies/:id', async (req, res, next) => {
  try {
    res.json({ data: await policyService.get(req.tenantId!, idParam(req.params.id)) });
  } catch (err) { next(err); }
});

// PATCH /api/mdm/policies/:id — { name?, description?, category? }
router.patch('/policies/:id', manage, async (req, res, next) => {
  try {
    const b = parse(PatchBody, req.body);
    const id = idParam(req.params.id);
    const policy = await policyService.update(req.tenantId!, id, b, await actorOf(req));
    emitPolicyChanged(req.tenantId!, [id]);
    res.json({ data: policy });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies/:id/archive — refused while assignments remain (409 policyHasAssignments).
router.post('/policies/:id/archive', manage, async (req, res, next) => {
  try {
    const id = idParam(req.params.id);
    const policy = await policyService.archive(req.tenantId!, id, await actorOf(req));
    emitPolicyChanged(req.tenantId!, [id]);
    res.json({ data: policy });
  } catch (err) { next(err); }
});

// GET /api/mdm/policies/:id/versions — without their content.
router.get('/policies/:id/versions', async (req, res, next) => {
  try {
    res.json({ data: await policyService.versions(req.tenantId!, idParam(req.params.id)) });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies/:id/versions — { from? }: a new draft from the published version, or from a rejected
// version taken up again (409 policyHasOpenVersion, policyVersionNotRejected).
router.post('/policies/:id/versions', manage, async (req, res, next) => {
  try {
    const b = parse(NewVersionBody, req.body);
    const id = idParam(req.params.id);
    const v = await policyService.newVersion(req.tenantId!, id, await actorOf(req), { from: b.from });
    emitPolicyChanged(req.tenantId!, [id]);
    res.status(201).json({ data: v });
  } catch (err) { next(err); }
});

// GET /api/mdm/policies/:id/versions/:v — the secret references stay references.
router.get('/policies/:id/versions/:v', async (req, res, next) => {
  try {
    res.json({ data: await policyService.version(req.tenantId!, idParam(req.params.id), idParam(req.params.v, 'Policy version')) });
  } catch (err) { next(err); }
});

// PUT /api/mdm/policies/:id/versions/:v — { content, changeNote? }: the draft (validation, secrets moved to the vault).
router.put('/policies/:id/versions/:v', manage, async (req, res, next) => {
  try {
    const b = parse(DraftBody, req.body);
    const id = idParam(req.params.id);
    const v = await policyService.saveDraft(req.tenantId!, id, idParam(req.params.v, 'Policy version'), b.content, b.changeNote ?? null, await actorOf(req));
    emitPolicyChanged(req.tenantId!, [id]);
    res.json({ data: v });
  } catch (err) { next(err); }
});

// DELETE /api/mdm/policies/:id/versions/:v — a draft or a rejected version.
router.delete('/policies/:id/versions/:v', manage, async (req, res, next) => {
  try {
    const id = idParam(req.params.id);
    await policyService.discardDraft(req.tenantId!, id, idParam(req.params.v, 'Policy version'), await actorOf(req));
    emitPolicyChanged(req.tenantId!, [id]);
    res.json({ data: { discarded: true } });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies/:id/raw-profiles — multipart, field "file": a .mobileconfig (1 MiB at most) imported as a
// raw.profile item of the draft. Answers the draft as a reader sees it, the names of the keys moved to the vault.
/** The policy of the route exists in the tenant of the session (404 before anything of the upload is read). */
const knownPolicy = (req: Request, _res: Response, next: NextFunction): void => {
  Promise.resolve().then(() => policyService.policyRow(db, req.tenantId!, idParam(req.params.id))).then(() => next(), next);
};

router.post('/policies/:id/raw-profiles', manage, knownPolicy, uploadProfile, async (req, res, next) => {
  try {
    const id = idParam(req.params.id);
    const file = (req as Request & { file?: { buffer: Buffer } }).file;
    if (!file || !Buffer.isBuffer(file.buffer) || file.buffer.length === 0) throw new AppError(400, 'A profile file is required', 'invalidRequest');
    const out = await policyService.importRawProfile(req.tenantId!, id, file.buffer, await actorOf(req));
    emitPolicyChanged(req.tenantId!, [id]);
    res.status(201).json({ data: out });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies/:id/versions/:v/validate — validation and conflicts, without effect.
router.post('/policies/:id/versions/:v/validate', async (req, res, next) => {
  try {
    const id = idParam(req.params.id);
    const v = idParam(req.params.v, 'Policy version');
    const { issues } = await policyService.validate(req.tenantId!, id, v);
    const row = await policyService.versionRow(db, req.tenantId!, id, v);
    const conflicts = await conflictsOf(db, req.tenantId!, { kind: 'version', policyId: id, versionId: Number(row.id) });
    res.json({ data: { valid: issues.length === 0 && conflicts.length === 0, issues, conflicts } });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies/:id/versions/:v/impact — the preview of its publication (nothing written).
router.post('/policies/:id/versions/:v/impact', async (req, res, next) => {
  try {
    res.json({ data: await versionImpact(req, req.tenantId!, idParam(req.params.id), idParam(req.params.v, 'Policy version')) });
  } catch (err) { next(err); }
});

// POST /api/mdm/policies/:id/versions/:v/submit — publication (step-up) or approval request (202).
router.post('/policies/:id/versions/:v/submit', manage, async (req, res, next) => {
  try {
    send(res, await submitVersion(req, req.tenantId!, idParam(req.params.id), idParam(req.params.v, 'Policy version')));
  } catch (err) { next(err); }
});

// ── Assignments ────────────────────────────────────────────────────────────

// GET /api/mdm/assignments?resourceType=&resourceId= | ?targetScope=&targetId=
router.get('/assignments', async (req, res, next) => {
  try {
    const q = parse(AssignmentQuery, req.query);
    res.json({ data: await listAssignments(req.tenantId!, q, { userId: req.session.userId!, isAdmin: await isTenantAdmin(req) }) });
  } catch (err) { next(err); }
});

// POST /api/mdm/assignments/changes?dryRun=true — { changes: [...] }: a batch (preview, step-up, or approval).
router.post('/assignments/changes', manage, async (req, res, next) => {
  try {
    const dryRun = req.query.dryRun === 'true' || req.query.dryRun === '1';
    send(res, await changeAssignments(req, req.tenantId!, req.body, dryRun));
  } catch (err) { next(err); }
});

// ── Schema and previews ────────────────────────────────────────────────────

// GET /api/mdm/schema/apple?type= — the catalog of the editor: schema, merge, instance key, secret keys, offered or not.
router.get('/schema/apple', async (req, res, next) => {
  try {
    const catalog = appleCatalog();
    const only = typeof req.query.type === 'string' ? req.query.type : null;
    const types = (only ? [only] : catalog.types()).filter((t) => catalog.entry(t));
    if (only && !types.length) throw new AppError(404, 'Unknown type');
    res.json({
      data: {
        release: catalog.release,
        types: types.map((t) => {
          const o = catalog.overlay(t);
          return { ...catalog.entry(t)!, descriptor: catalog.descriptor(t), secretKeys: o.secretKeys ?? {},
            forbiddenOwnerships: o.forbiddenOwnerships ?? [], enabled: catalog.enabled(t) };
        }),
      },
    });
  } catch (err) { next(err); }
});

// GET /api/mdm/impact/:token/devices?page=&pageSize= — the touched devices of a preview (token of 15 minutes, bound
// to the tenant and to the user), within the caller's scopes.
router.get('/impact/:token/devices', async (req, res, next) => {
  try {
    const q = parse(PageQuery, req.query);
    const token = String(req.params.token);
    const change = verifyImpactToken(token, req.tenantId!, req.session.userId!);
    if (!change) throw new AppError(404, 'Unknown or expired preview');
    let touched = cachedTouched(token);
    if (!touched) {
      touched = (await computeImpact(db, req.tenantId!, change)).touched;
      cacheTouched(token, touched);
    }
    if (!(await isTenantAdmin(req))) {
      const visible = await permissionService.getVisibleDeviceIds(req.session.userId!, false);
      if (visible !== 'all') {
        const set = new Set(visible.map(Number));
        touched = touched.filter((t) => set.has(t.deviceId));
      }
    }
    const pageSize = q.pageSize ?? 100;
    const page = q.page ?? 1;
    const body: ImpactDevicesPage = { total: touched.length, page, pageSize, devices: touched.slice((page - 1) * pageSize, page * pageSize) };
    res.json({ data: body });
  } catch (err) { next(err); }
});

export default router;
