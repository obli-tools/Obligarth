// Deadlines of the Android integration (lot AN-H1; android-amapi §6.2 step 6, §10.3, §22.3, REV-2, annex E):
//   - long enrollment tokens (zero-touch, KME, kiosk: several uses, up to a year): a rotation proposed 90 days after
//     their creation (AN17), and their end; tenant alert android.token_expiring (low) while one is within 14 days of
//     either, resolved once none is;
//   - the « Google backup administrators » of the enterprise: a yearly reminder from its link (INT-05);
//   - the service account key of the instance (vault_key mode): 90 days of age at most (organisation policy, REV-2),
//     platform alert android.google_key_expiring 14 days before, resolved once a new key is deposited.
// The items are computed (no table): listAndroidDeadlines() for the tenant's console, platformKeyDeadline() for the
// platform screen; the échéancier of the core (lot C3) takes them through its provider at the junction AN-P.
// Identifiers and dates only.
import {
  ANDROID_KEY_MAX_AGE_DAYS, ANDROID_KEY_WARNING_DAYS, ANDROID_LONG_TOKEN_ROTATION_DAYS, ANDROID_TOKEN_WARNING_DAYS,
  type AndroidDeadline,
} from '@obligarth/shared';
import { db } from '../../db';
import { asNone, asTenant, type DbActor } from '../../db/context';
import { raiseAndroidPlatformAlert, raiseAndroidTenantAlert, resolveAndroidPlatformAlert, resolveAndroidTenantAlert } from '../alerts';
import { androidConfig } from '../config';
import { MAINTENANCE_ACTOR } from '../enterprises/orphans';
import { readPlatformState } from '../enterprises/registry';

const DAY_MS = 86_400_000;

/** Status of a deadline at `now` with its warning period. Pure (unit tests). */
export function deadlineStatus(due: Date, now: Date, warningDays: number): AndroidDeadline['status'] {
  const left = due.getTime() - now.getTime();
  if (left <= 0) return 'overdue';
  if (left <= warningDays * DAY_MS) return 'warning';
  return 'ok';
}

/** The next yearly anniversary of `from` after `now` (29 February → 28 February of a common year). */
export function nextAnniversary(from: Date, now: Date): Date {
  for (let y = now.getUTCFullYear(); y <= now.getUTCFullYear() + 1; y++) {
    const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
    const day = from.getUTCMonth() === 1 && from.getUTCDate() === 29 && !leap ? 28 : from.getUTCDate();
    const d = new Date(Date.UTC(y, from.getUTCMonth(), day, from.getUTCHours(), from.getUTCMinutes()));
    if (d.getTime() > now.getTime() && y > from.getUTCFullYear()) return d;
  }
  return new Date(Date.UTC(now.getUTCFullYear() + 1, from.getUTCMonth(), from.getUTCDate()));
}

interface TokenRow { id: string; created_at: Date; expires_at: Date }

/** The deadlines of a tenant (its console; the échéancier at the junction). Tenant context of the caller. */
export async function tenantDeadlines(tenantId: number, now: Date = new Date()): Promise<AndroidDeadline[]> {
  const out: AndroidDeadline[] = [];
  const tokens = await db('android_enrollment_tokens').where({ tenant_id: tenantId, state: 'active', one_time: false })
    .select('id', 'created_at', 'expires_at') as TokenRow[];
  for (const t of tokens) {
    const rotation = new Date(new Date(t.created_at).getTime() + ANDROID_LONG_TOKEN_ROTATION_DAYS * DAY_MS);
    const end = new Date(t.expires_at);
    if (rotation.getTime() < end.getTime()) {
      out.push({ kind: 'long_token_rotation', ref: String(t.id), dueAt: rotation.toISOString(), status: deadlineStatus(rotation, now, ANDROID_TOKEN_WARNING_DAYS) });
    }
    out.push({ kind: 'token_expiry', ref: String(t.id), dueAt: end.toISOString(), status: deadlineStatus(end, now, ANDROID_TOKEN_WARNING_DAYS) });
  }
  const e = await db('android_enterprises').where({ tenant_id: tenantId, state: 'linked' }).whereNotNull('linked_at').first('id', 'linked_at') as
    { id: number; linked_at: Date } | undefined;
  if (e) {
    const due = nextAnniversary(new Date(e.linked_at), now);
    out.push({ kind: 'google_backup_admins', ref: String(e.id), dueAt: due.toISOString(), status: deadlineStatus(due, now, ANDROID_TOKEN_WARNING_DAYS) });
  }
  return out.sort((a, b) => a.dueAt.localeCompare(b.dueAt));
}

/** The deadlines of a tenant as a user reads them (route of the console). */
export async function listAndroidDeadlines(tenantId: number, userId: number, now: Date = new Date()): Promise<AndroidDeadline[]> {
  return asTenant(tenantId, { type: 'user', userId }, () => tenantDeadlines(tenantId, now));
}

/** The token alert of a tenant: raised while a long token is due within 14 days (rotation or end), resolved otherwise. */
export async function tenantDeadlineAlerts(tenantId: number, actor: DbActor, now: Date = new Date()): Promise<number> {
  const items = await asTenant(tenantId, actor, () => tenantDeadlines(tenantId, now));
  const due = items.filter((d) => (d.kind === 'long_token_rotation' || d.kind === 'token_expiry') && d.status !== 'ok');
  const tokens = new Set(due.map((d) => d.ref)).size;
  if (tokens) await raiseAndroidTenantAlert(tenantId, 'android.token_expiring', { count: tokens });
  else await resolveAndroidTenantAlert(tenantId, 'android.token_expiring');
  return tokens;
}

/** The deadline of the service account key (vault_key mode, a key deposited), or null. */
export async function platformKeyDeadline(now: Date = new Date()): Promise<AndroidDeadline | null> {
  if (androidConfig().auth !== 'vault_key') return null;
  const state = await asNone(MAINTENANCE_ACTOR, () => readPlatformState());
  if (!state.credential_set_at) return null;
  const due = new Date(new Date(state.credential_set_at).getTime() + ANDROID_KEY_MAX_AGE_DAYS * DAY_MS);
  return { kind: 'service_account_key', ref: null, dueAt: due.toISOString(), status: deadlineStatus(due, now, ANDROID_KEY_WARNING_DAYS) };
}

/** The daily key check of android.maintenance: android.google_key_expiring raised or resolved. */
export async function checkKeyDeadline(now: Date = new Date()): Promise<AndroidDeadline | null> {
  const d = await platformKeyDeadline(now);
  if (d && d.status !== 'ok') {
    const days = Math.max(0, Math.ceil((Date.parse(d.dueAt) - now.getTime()) / DAY_MS));
    await raiseAndroidPlatformAlert('android.google_key_expiring', { days }, 'key');
  } else {
    await resolveAndroidPlatformAlert('android.google_key_expiring', 'key');
  }
  return d;
}
