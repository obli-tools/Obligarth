import type { MetricThresholds } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';
import { appConfigService } from './appConfig.service';
import type { SettingsWriteDef } from './settingsWrite.service';

// ── Metric thresholds: global default (cascade layer 2) ─────────────────────
// Stored as a JSON-encoded string under app_config['metric_thresholds_global']:
// GET / PUT /api/admin/config/global-thresholds
// (routes/thresholdSettings.routes.ts). The write is gated and replayed as a
// named settings write (settingsWrite.service), registered by modules/rmm.ts.

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

/** The write as an approval keeps it, and its replay (registerSettingsWrite). */
export const globalThresholdsWrite: SettingsWriteDef = {
  method: 'PUT',
  path: '/global-thresholds',
  async prepare(raw) {
    const { short } = await import('./approvalDescribe');
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
  },
  async apply(body) {
    await writeGlobalThresholds(body.thresholds);
  },
};
