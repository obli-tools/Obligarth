import type { TFunction } from 'i18next';
import type { GuardSettingsDto } from '@obligarth/shared';
import type { PendingApproval } from '@/api/approval.api';

// The changes of the guard settings waiting for their second person (approval guard_settings_change, filed by
// PUT /api/guard/settings with the asked settings in payload.settings), shown under the settings form.

type SettingsPayload = Partial<{
  hourlyCapPercent: number; hourlyCapMin: number; massApproverSide: string; publishFleetShareFloor: number;
  legacyAgentCommandsSensitive: boolean;
}>;

/** The pending guard_settings_change requests of a tenant, the most recent first. */
export function pendingSettingsChanges(list: PendingApproval[], tenantId: number): PendingApproval[] {
  return list
    .filter((a) => a.requestType === 'guard_settings_change' && a.status === 'pending' && Number(a.tenantId) === Number(tenantId))
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

function settingsOf(a: PendingApproval): SettingsPayload {
  const s = (a.payload as { settings?: unknown } | null | undefined)?.settings;
  return s && typeof s === 'object' && !Array.isArray(s) ? (s as SettingsPayload) : {};
}

/** What a request changes against the current settings, in the words of the form ("label: value" joined), or the
 *  server's description when nothing can be told apart (a payload of another shape). */
export function pendingSettingsSummary(t: TFunction, a: PendingApproval, current: GuardSettingsDto): string {
  const s = settingsOf(a);
  const on = t('guard.settings.on') || 'on';
  const off = t('guard.settings.off') || 'off';
  const parts: string[] = [];
  if (typeof s.legacyAgentCommandsSensitive === 'boolean' && s.legacyAgentCommandsSensitive !== (current.legacyAgentCommandsSensitive === true)) {
    parts.push(`${t('guard.settings.legacyAgentCommandsSensitive') || 'Second factor on the Android agent commands'}: ${s.legacyAgentCommandsSensitive ? on : off}`);
  }
  if (typeof s.hourlyCapPercent === 'number' && s.hourlyCapPercent !== current.hourlyCapPercent) parts.push(`${t('guard.settings.percent') || 'Hourly cap (% of the fleet)'}: ${s.hourlyCapPercent}`);
  if (typeof s.hourlyCapMin === 'number' && s.hourlyCapMin !== current.hourlyCapMin) parts.push(`${t('guard.settings.min') || 'Minimum (devices)'}: ${s.hourlyCapMin}`);
  if ((s.massApproverSide === 'client' || s.massApproverSide === 'msp') && s.massApproverSide !== current.massApproverSide) {
    parts.push(`${t('guard.settings.side') || 'Approver of the mass actions of the MSP'}: ${s.massApproverSide === 'msp' ? (t('guard.side.msp') || 'MSP') : (t('guard.side.client') || 'client')}`);
  }
  if (typeof s.publishFleetShareFloor === 'number' && s.publishFleetShareFloor !== current.publishFleetShareFloor) parts.push(`${t('guard.settings.fleetShareFloor') || 'Second approver: 10 % of the fleet counted from (devices)'}: ${s.publishFleetShareFloor}`);
  return parts.length > 0 ? parts.join(' · ') : (a.description ?? '');
}
