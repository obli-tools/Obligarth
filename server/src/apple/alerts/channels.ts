import { config } from '../../config';
import { db } from '../../db';
import type { JobContext } from '../../jobs';
import { getPlugin } from '../../notifications/registry';
import type { NotificationPayload } from '../../notifications/types';
import { notificationService } from '../../services/notification.service';
import { logger } from '../../utils/logger';
import { APPLE_ALERTS, isAppleAlertKind, render, type AlertParams, type AppleAlertKind } from './catalog';
import { APPLE_ALERTS_FR } from './catalog.fr';

// =============================================================================
// External channels of an alert of the Apple integration (docs: integration-
// apple-edge §12.3), sent by alerts.deliver for a raised alert of severity
// warning or critical:
//   - the channels bound to the tenant at the global level
//     (notification_bindings, scope 'global'; 'exclude' removes, 'replace'
//     keeps only its own), enabled;
//   - the text rendered in the tenant's language (en or fr: the instance's
//     default_language when it is one of them, French otherwise), from the
//     closed catalogue (never a device name, a serial number, a UDID…: I11);
//   - at most one send per kind and per tenant every 15 minutes, except a
//     critical alert (job_once on the kind's quarter of an hour), and the
//     sends of one alert done once (job_once 'alerts.deliver:<id>');
//   - the network calls outside any transaction; a channel that fails is
//     logged (no URL, no secret: channelErrorText) and does not fail the job
//     (the alert is in the bell already).
// =============================================================================

/** Throttle window of the external sends of a kind in a tenant (non-critical alerts). */
export const CHANNEL_THROTTLE_SECONDS = 15 * 60;

export type AlertLanguage = 'en' | 'fr';

/** The language of a tenant's external notifications. */
export async function tenantLanguage(): Promise<AlertLanguage> {
  const row = await db('app_config').where({ key: 'default_language' }).first('value') as { value: string | null } | undefined;
  const v = String(row?.value ?? '').trim().toLowerCase();
  return v === 'en' ? 'en' : 'fr';
}

/** Title and message of an alert of the catalogue in `language`. */
export function renderAlert(kind: AppleAlertKind, params: AlertParams, language: AlertLanguage): { title: string; message: string } {
  const def = language === 'fr' ? APPLE_ALERTS_FR[kind] : APPLE_ALERTS[kind];
  return { title: render(def.title, params).slice(0, 500), message: render(def.message, params).slice(0, 2000) };
}

/** The channels bound to the tenant at the global level (merge, replace, exclude), enabled. */
export async function globalChannelsOf(tenantId: number): Promise<Array<{ id: number; name: string; type: string }>> {
  const bindings = await db('notification_bindings').where({ tenant_id: tenantId, scope: 'global' }).whereNull('scope_id')
    .select('channel_id', 'override_mode') as Array<{ channel_id: number; override_mode: string }>;
  if (bindings.length === 0) return [];
  let ids = new Set<number>();
  if (bindings.some((b) => b.override_mode === 'replace')) ids = new Set();
  for (const b of bindings) if (b.override_mode !== 'exclude') ids.add(Number(b.channel_id));
  for (const b of bindings) if (b.override_mode === 'exclude') ids.delete(Number(b.channel_id));
  if (ids.size === 0) return [];
  return db('notification_channels').whereIn('id', [...ids]).where({ is_enabled: true }).orderBy('id')
    .select('id', 'name', 'type') as Promise<Array<{ id: number; name: string; type: string }>>;
}

export interface ChannelOutcome { sent: number; failed: number; skipped: 'not_external' | 'no_channel' | 'throttled' | 'done' | null }

/**
 * The external sends of a raised alert (in the job's tenant context, no transaction). `row` is the live_alerts row.
 */
export async function deliverToChannels(ctx: Pick<JobContext<unknown>, 'once'>, tenantId: number, row: Record<string, unknown>): Promise<ChannelOutcome> {
  const kind = String(row.kind ?? '');
  const severity = String(row.severity ?? '');
  if (!isAppleAlertKind(kind) || (severity !== 'warning' && severity !== 'critical')) return { sent: 0, failed: 0, skipped: 'not_external' };
  const channels = await globalChannelsOf(tenantId);
  if (channels.length === 0) return { sent: 0, failed: 0, skipped: 'no_channel' };
  const alertId = Number(row.id);
  const out: ChannelOutcome = { sent: 0, failed: 0, skipped: null };
  const send = async (): Promise<void> => {
    const language = await tenantLanguage();
    const params = (row.i18n_params && typeof row.i18n_params === 'object' ? row.i18n_params : {}) as AlertParams;
    const text = renderAlert(kind, params, language);
    const at = row.created_at instanceof Date ? row.created_at : new Date(String(row.created_at ?? Date.now()));
    const navigate = typeof row.navigate_to === 'string' && row.navigate_to.startsWith('/') && config.publicUrl
      ? `${config.publicUrl}${row.navigate_to}` : undefined;
    const payload: NotificationPayload = {
      monitorName: text.title, oldStatus: 'ok', newStatus: severity, message: text.message,
      timestamp: (Number.isNaN(at.getTime()) ? new Date() : at).toISOString(), appName: config.appName,
      ...(navigate ? { monitorUrl: navigate } : {}),
    };
    for (const ch of channels) {
      const plugin = getPlugin(ch.type);
      if (!plugin) continue;
      try {
        const resolved = await notificationService.resolveChannelConfig({ id: ch.id });
        await plugin.send(resolved, payload);
        out.sent += 1;
        await notificationService.logNotification(ch.id, `apple.${kind}`, true);
      } catch {
        out.failed += 1;
        await notificationService.logNotification(ch.id, `apple.${kind}`, false, 'send failed');
        logger.warn({ tenantId, alertId, channelId: ch.id, channelType: ch.type }, 'apple alert: external channel failed');
      }
    }
  };
  // One alert sent once; a kind at most once per quarter of an hour in the tenant, a critical alert always.
  const sendOnce = (): Promise<'done' | 'skipped'> => ctx.once(`alerts.deliver:${alertId}`, 7 * 86_400, send);
  if (severity === 'critical') {
    const r = await sendOnce();
    if (r === 'skipped') out.skipped = 'done';
    return out;
  }
  const slot = Math.floor(Date.now() / (CHANNEL_THROTTLE_SECONDS * 1000));
  let inner: 'done' | 'skipped' | null = null;
  const r = await ctx.once(`alerts.notify:${tenantId}:${kind}:${slot}`, 2 * CHANNEL_THROTTLE_SECONDS, async () => { inner = await sendOnce(); });
  if (r === 'skipped') out.skipped = 'throttled';
  else if (inner === 'skipped') out.skipped = 'done';
  return out;
}
