import i18n from 'i18next';
import type { TFunction } from 'i18next';
import {
  MCP_SCOPES, type AccessKeyView, type McpAuthorizationState, type McpKeyRevokeReason, type McpKeyState, type McpScope,
} from '@obligarth/shared';
import { trCode } from '@/utils/apiError';

// Labels and small formatters of the access keys pages (docs: specs mcp-server §6.5).

export type Tone = 'green' | 'gray' | 'blue' | 'amber' | 'red' | 'violet';

/** The shared English label of a scope, translated when the console has it (accessKeys.scopes.<a_b>). */
export function scopeLabel(scope: McpScope): string {
  return trCode(`accessKeys.scopes.${scope.replace('.', '_')}`, MCP_SCOPES[scope]?.label ?? scope);
}

export const KEY_STATE_TONE: Record<McpKeyState, Tone> = { active: 'green', expired: 'gray', revoked: 'red' };
const KEY_STATE_FALLBACK: Record<McpKeyState, string> = { active: 'Active', expired: 'Expired', revoked: 'Revoked' };
export const keyStateLabel = (s: McpKeyState): string => trCode(`accessKeys.state.${s}`, KEY_STATE_FALLBACK[s] ?? s);

const REVOKE_FALLBACK: Record<McpKeyRevokeReason, string> = {
  user: 'Revoked by you',
  admin: 'Revoked by a platform administrator',
  user_disabled: 'Account disabled',
  credentials_changed: 'Password or second factor changed',
  sessions_killed: 'Sessions of the account ended',
  owner_removed: 'Account removed',
};
export const revokeReasonLabel = (r: McpKeyRevokeReason): string => trCode(`accessKeys.revokeReason.${r}`, REVOKE_FALLBACK[r] ?? r);

export const AUTH_STATE_TONE: Record<McpAuthorizationState, Tone> = {
  pending: 'amber', executing: 'blue', executed: 'green', failed: 'red', denied: 'gray', expired: 'gray',
  cancelled: 'gray', filed: 'violet', interrupted: 'red',
};
const AUTH_STATE_FALLBACK: Record<McpAuthorizationState, string> = {
  pending: 'Waiting for you', executing: 'Running', executed: 'Done', failed: 'Failed', denied: 'Denied', expired: 'Expired',
  cancelled: 'Cancelled', filed: 'Sent for approval', interrupted: 'Interrupted',
};
export const authStateLabel = (s: McpAuthorizationState): string => trCode(`mcpAuthorizations.state.${s}`, AUTH_STATE_FALLBACK[s] ?? s);

/** A date relative to now ("in 3 days", "2 hours ago"), the full date in the title. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): { text: string; full: string } | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const lang = i18n.language || undefined;
  const full = d.toLocaleString(lang, { dateStyle: 'short', timeStyle: 'short' });
  const diff = d.getTime() - now;
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  const sign = diff < 0 ? -1 : 1;
  let text: string;
  if (abs < 60_000) text = rtf.format(0, 'minute');
  else if (abs < 3_600_000) text = rtf.format(sign * Math.round(abs / 60_000), 'minute');
  else if (abs < 86_400_000) text = rtf.format(sign * Math.round(abs / 3_600_000), 'hour');
  else text = rtf.format(sign * Math.round(abs / 86_400_000), 'day');
  return { text, full };
}

/** The masked form of a key: its public part only, the secret never comes back. */
export const maskedToken = (publicId: string): string => `obg_${publicId}_…`;

/** One line per perimeter kind of a key: tenants, groups, devices (names resolved by the server when readable). */
export function perimeterLines(t: TFunction, k: AccessKeyView): { tenants: string; groups: string; devices: string } {
  const name = (n: string | null, id: number) => n ?? `#${id}`;
  const tenants = k.tenants.mode === 'all'
    ? (t('accessKeys.perimeter.allTenants') || 'All my tenants')
    : k.tenants.items.map((x) => name(x.name, x.tenantId)).join(', ');
  const groups = k.groups.mode === 'all'
    ? (t('accessKeys.perimeter.allGroups') || 'All groups')
    : k.groups.items.map((x) => name(x.name, x.groupId)).join(', ');
  const devices = k.devices.mode === 'all'
    ? (t('accessKeys.perimeter.allDevices') || 'All devices')
    : k.devices.items.map((x) => name(x.name, x.deviceId)).join(', ');
  return { tenants, groups, devices };
}
