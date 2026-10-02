import { Router, text, type Request } from 'express';
import { z } from 'zod';
import { audit } from '../../audit';
import { AppError } from '../../middleware/errorHandler';
import { requireAnyTenantCapability, requireTenantCapability } from '../../middleware/rbac';
import { endUserService } from '../registry/endUsers';

// =============================================================================
// End users of the tenant (docs: modele-donnees-mdm §4.8, §10.6, PLT-28):
// mounted at /api/mdm/end-users, in the tenant of the session. Writes:
// users.manage; reads: users.manage or devices.manage (assigning a device's
// end user needs the list). Personal data (name, e-mail, Managed Apple
// Account): never in a log line, never in the details of an audit entry
// (identifiers and counters only, audit-durci §3.5).
// =============================================================================

const router = Router();

const Fields = z.object({
  email: z.string().max(320).nullable().optional(),
  displayName: z.string().max(200).nullable().optional(),
  managedAppleAccount: z.string().max(320).nullable().optional(),
  externalId: z.string().max(255).nullable().optional(),
}).strict();
const ListQuery = z.object({
  status: z.enum(['active', 'departed']).optional(),
  q: z.string().max(200).optional(),
  page: z.coerce.number().int().positive().optional(),
  pageSize: z.coerce.number().int().positive().max(500).optional(),
}).passthrough();

function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  const parsed = schema.safeParse(value ?? {});
  if (!parsed.success) throw new AppError(400, parsed.error.issues[0]?.message ?? 'Invalid request', 'invalidRequest');
  return parsed.data;
}

const idOf = (req: Request): number => {
  const id = /^[1-9][0-9]{0,9}$/.test(req.params.id) ? Number(req.params.id) : NaN;
  if (!Number.isSafeInteger(id)) throw new AppError(404, 'End user not found');
  return id;
};

const reader = requireAnyTenantCapability('users.manage', 'devices.manage');

// GET /api/mdm/end-users?status=&q=&page=&pageSize=
router.get('/', reader, async (req, res, next) => {
  try {
    const q = parse(ListQuery, req.query);
    res.json({ data: await endUserService.list(req.tenantId!, { status: q.status, search: q.q, page: q.page, pageSize: q.pageSize }) });
  } catch (err) { next(err); }
});

// POST /api/mdm/end-users/import — CSV (text/csv body, or JSON { csv }), 1 MiB at most: a report line by line.
router.post('/import', requireTenantCapability('users.manage'), text({ type: ['text/csv', 'text/plain'], limit: '1mb' }), async (req, res, next) => {
  try {
    const csv = typeof req.body === 'string' ? req.body : typeof (req.body as { csv?: unknown })?.csv === 'string' ? (req.body as { csv: string }).csv : null;
    if (csv === null) throw new AppError(400, 'A CSV file is required', 'invalidRequest');
    const report = await endUserService.importCsv(req.tenantId!, csv, { createdBy: req.session.userId ?? null });
    await audit.append({
      tenantId: req.tenantId!, action: 'end_user.imported', target: { type: 'end_user', id: 'import' },
      details: { created: report.created, updated: report.updated, unchanged: report.unchanged, rejected: report.rejected },
    }, await audit.fromRequest(req, req.tenantId!));
    res.json({ data: report });
  } catch (err) { next(err); }
});

// POST /api/mdm/end-users
router.post('/', requireTenantCapability('users.manage'), async (req, res, next) => {
  try {
    const f = parse(Fields, req.body);
    const user = await endUserService.create(req.tenantId!, f, { createdBy: req.session.userId ?? null });
    await audit.append({
      tenantId: req.tenantId!, action: 'end_user.created', target: { type: 'end_user', id: String(user.id) },
      details: { fields: Object.keys(f).filter((k) => (f as Record<string, unknown>)[k] != null) },
    }, await audit.fromRequest(req, req.tenantId!));
    res.status(201).json({ data: user });
  } catch (err) { next(err); }
});

// GET /api/mdm/end-users/:id
router.get('/:id', reader, async (req, res, next) => {
  try {
    const user = await endUserService.get(req.tenantId!, idOf(req));
    if (!user) throw new AppError(404, 'End user not found');
    res.json({ data: user });
  } catch (err) { next(err); }
});

// PATCH /api/mdm/end-users/:id
router.patch('/:id', requireTenantCapability('users.manage'), async (req, res, next) => {
  try {
    const id = idOf(req);
    const f = parse(Fields, req.body);
    const user = await endUserService.update(req.tenantId!, id, f);
    if (!user) throw new AppError(404, 'End user not found');
    await audit.append({
      tenantId: req.tenantId!, action: 'end_user.updated', target: { type: 'end_user', id: String(id) },
      details: { fields: Object.keys(f) },
    }, await audit.fromRequest(req, req.tenantId!));
    res.json({ data: user });
  } catch (err) { next(err); }
});

// POST /api/mdm/end-users/:id/depart — the employee left (links kept 90 days, then purged).
router.post('/:id/depart', requireTenantCapability('users.manage'), async (req, res, next) => {
  try {
    const id = idOf(req);
    const user = await endUserService.depart(req.tenantId!, id);
    if (!user) throw new AppError(404, 'End user not found');
    await audit.append({
      tenantId: req.tenantId!, action: 'end_user.departed', target: { type: 'end_user', id: String(id) },
    }, await audit.fromRequest(req, req.tenantId!));
    res.json({ data: user });
  } catch (err) { next(err); }
});

export default router;
