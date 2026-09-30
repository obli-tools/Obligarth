import { Router, type Request, type Response, type NextFunction } from 'express';
import type { MetricThresholds } from '@obliance/shared';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { requireTenant } from '../middleware/tenant';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import { appConfigService } from '../services/appConfig.service';
import { writeGlobalThresholds } from '../services/thresholdSettings.service';
import { gateSettingsWrite } from './appConfig.routes';

// Metric-threshold defaults of the platform and of the current tenant,
// served on their former paths (mounted in routes/index.ts):
//  - globalThresholdRoutes under /api/admin/config, before the core settings
//    router (whose PUT /:key would otherwise take the path);
//  - tenantThresholdRoutes under /api/tenants and /api/tenant, after the core
//    tenant router.

// ── Global metric-threshold default (cascade layer 2) ─────────────────────
// Cross-tenant — only the platform admin sitting on the master tenant can
// edit. Read is admin-only because the response shape is for the editor;
// the resolver inside threshold.service.ts reads it directly without going
// through this endpoint. Stored as a JSON-encoded string under
// app_config['metric_thresholds_global']. The endpoint validates the shape
// with the same Zod schema the group + tenant editors use so all three
// surfaces accept the same input — no surprise where one layer rejects a
// payload another would accept.

export const globalThresholdRoutes = Router();

globalThresholdRoutes.get('/global-thresholds', requireAuth, requireRole('admin'), async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const raw = await appConfigService.get('metric_thresholds_global');
    let value: unknown = null;
    if (raw) {
      try { value = JSON.parse(raw); } catch { value = null; }
    }
    res.json({ success: true, data: { thresholds: value } });
  } catch (err) { next(err); }
});

globalThresholdRoutes.put('/global-thresholds', requireAuth, requireRole('admin'), gateSettingsWrite, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const thresholds = await writeGlobalThresholds((req.body as { thresholds?: unknown })?.thresholds);
    res.json({ success: true, data: { thresholds } });
  } catch (err) { next(err); }
});

// ── Tenant metric-threshold default (cascade layer 3) ────────────────
// Scope: a tenant admin may edit only their own current tenant. The
// platform admin sitting on the master tenant may edit any tenant
// (their `currentTenantId` is the one being edited and the master
// god-view is implicit). We don't accept `:id` from the URL so a child
// tenant admin can't aim a payload at a sibling tenant — the row
// being edited is always `req.tenantId`.
//
// `requireTenant` is applied per-handler here because the router is
// mounted as just `requireAuth` in routes/index.ts, next to the core
// tenant router (its /tenants endpoints don't need a tenant context to
// resolve — locate-device walks all of them).

export const tenantThresholdRoutes = Router();

// All tenant routes require auth
tenantThresholdRoutes.use(requireAuth);

tenantThresholdRoutes.get('/current/thresholds', requireTenant, async (req, res, next) => {
  try {
    const tenantId = req.tenantId!;
    const row = await db('tenants').where({ id: tenantId }).first('metric_thresholds_default') as { metric_thresholds_default: unknown } | undefined;
    let value: unknown = row?.metric_thresholds_default ?? null;
    if (typeof value === 'string') {
      try { value = JSON.parse(value); } catch { value = null; }
    }
    res.json({ success: true, data: { thresholds: value } });
  } catch (err) { next(err); }
});

tenantThresholdRoutes.put('/current/thresholds', requireTenant, async (req, res, next) => {
  try {
    if (req.session.role !== 'admin') throw new AppError(403, 'Admin only');
    const tenantId = req.tenantId!;
    const { metricThresholdsSchema } = await import('../validators/group.schema');
    const { thresholds } = req.body as { thresholds?: unknown };
    // Previous value — a change of a per-metric alerts switch (`notify`)
    // triggers a silent re-baseline of the tenant's devices.
    const beforeRow = await db('tenants').where({ id: tenantId }).first('metric_thresholds_default') as { metric_thresholds_default: unknown } | undefined;
    let before: MetricThresholds | null = null;
    if (typeof beforeRow?.metric_thresholds_default === 'string') {
      try { before = JSON.parse(beforeRow.metric_thresholds_default) as MetricThresholds; } catch { before = null; }
    } else if (beforeRow?.metric_thresholds_default && typeof beforeRow.metric_thresholds_default === 'object') {
      before = beforeRow.metric_thresholds_default as MetricThresholds;
    }
    const afterSave = async (after: MetricThresholds | null) => {
      const { invalidateTenantThresholdCache } = await import('../services/threshold.service');
      invalidateTenantThresholdCache(tenantId);
      const { metricAlertRebaseline } = await import('../services/metricAlertRebaseline.service');
      if (metricAlertRebaseline.notifyChanged(before, after)) {
        metricAlertRebaseline.schedule({ kind: 'tenant', tenantId }, 'tenant notify switch');
      }
    };
    if (thresholds == null || (typeof thresholds === 'object' && Object.keys(thresholds as object).length === 0)) {
      await db('tenants').where({ id: tenantId }).update({ metric_thresholds_default: null });
      await afterSave(null);
      res.json({ success: true, data: { thresholds: null } });
      return;
    }
    const parsed = metricThresholdsSchema.safeParse(thresholds);
    if (!parsed.success) {
      const issues = parsed.error.errors.map((e) => `${e.path.join('.') || '<root>'}: ${e.message}`).join('; ');
      throw new AppError(400, `Invalid thresholds — ${issues}`);
    }
    await db('tenants').where({ id: tenantId }).update({ metric_thresholds_default: JSON.stringify(parsed.data) });
    await afterSave(parsed.data);
    res.json({ success: true, data: { thresholds: parsed.data } });
  } catch (err) { next(err); }
});

// ── Resolved tenant defaults (read-only) ────────────────────────────
// Effective values (with the origin of each value) resolved up to and
// including the tenant layer. `?scope=parent` stops above the tenant:
// what the tenant itself inherits (global + system) — used by the tenant
// thresholds tab so its placeholders / greyed alerts switches never echo
// the tenant's own saved values.
tenantThresholdRoutes.get('/current/thresholds-resolved', requireTenant, async (req, res, next) => {
  try {
    const { thresholdService } = await import('../services/threshold.service');
    const resolved = req.query.scope === 'parent'
      ? await thresholdService.resolveGlobal()
      : await thresholdService.resolveForTenant(req.tenantId!);
    res.json({ success: true, data: resolved });
  } catch (err) { next(err); }
});
