// Assignments of Android apps (android-amapi §4.6, §9.6; lot AN-E1): what the common batch of assignment changes
// (POST /api/mdm/assignments/changes, mdm/policies/publish.ts) calls for an app of the family android, at the junction
// AN-A2/AN-P. An assignment is never written here: it goes through the batch, its impact preview, its step-up or
// second approver and the lock of the tenant's configuration (writing it from this module would bypass the guard).
//   - checkAndroidAppAssignment (normalizeChanges, each look of the batch): the app is a live Android app of the
//     tenant's own catalog, its options are checked (apps/appPolicy.ts), the secret references they hold belong to
//     the tenant with the purpose of a managed configuration;
//   - sealAndroidAppOptions (once, before anything stores the batch: the approval request's payload included): the
//     secrets typed in ({"$secretValue"}) move to the tenant's vault and are replaced by their reference; no value in
//     clear ever reaches assignments.options, pending_approvals nor a log (assignments.options is a declared holder
//     of references: mdm/index.ts);
//   - androidAppContribution (appPolicy.ts) is what the resolver takes from such an assignment.
import type { Knex } from 'knex';
import { isSecretRef, isSecretValue, type JsonValue } from '@obligarth/shared';
import { vault } from '../../vault';
import { APP_CONFIG_SECRET_PURPOSE } from '../../mdm/android/overlay';
import { checkAndroidAppOptions, type AndroidAppOptionIssue, type AndroidAppOptionsCheck, type AndroidAppSecretSite } from './appPolicy';
import { AndroidAppError, readAndroidApp, type AndroidAppRow } from './catalog';
import { metadataOf } from './metadata';

export type AndroidAppAssignmentIssue = AndroidAppOptionIssue | { path: string; code: 'secret_not_found' };

export class AndroidAppOptionsError extends Error {
  readonly status = 422;
  readonly code = 'androidAppOptionsInvalid';
  readonly issues: AndroidAppAssignmentIssue[];
  constructor(issues: AndroidAppAssignmentIssue[]) {
    super('invalid options of an Android app assignment');
    this.name = 'AndroidAppOptionsError';
    this.issues = issues;
  }
}

export interface AndroidAppAssignmentCheck extends Omit<AndroidAppOptionsCheck, 'issues'> {
  app: AndroidAppRow;
  issues: AndroidAppAssignmentIssue[];
}

const isObject = (v: unknown): v is Record<string, JsonValue> => !!v && typeof v === 'object' && !Array.isArray(v);

function at(root: unknown, path: Array<string | number>): unknown {
  let node = root;
  for (const p of path) node = isObject(node) || Array.isArray(node) ? (node as Record<string | number, unknown>)[p as string] : undefined;
  return node;
}

function replaceAt(root: Record<string, JsonValue>, path: Array<string | number>, value: JsonValue): Record<string, JsonValue> {
  const copy = structuredClone(root);
  let node: unknown = copy;
  for (const p of path.slice(0, -1)) node = (node as Record<string | number, unknown>)[p as string];
  (node as Record<string | number, unknown>)[path[path.length - 1] as string] = value;
  return copy;
}

/** Does a value still hold a secret in clear? */
export function holdsSecretValue(v: unknown, depth = 0): boolean {
  if (depth > 40) return true;
  if (isSecretValue(v)) return true;
  if (Array.isArray(v)) return v.some((x) => holdsSecretValue(x, depth + 1));
  if (isObject(v)) return Object.values(v).some((x) => holdsSecretValue(x, depth + 1));
  return false;
}

/** The checks of an assignment of the Android app `appId` of the tenant (the app of another tenant: not found). */
export async function checkAndroidAppAssignment(q: Knex | Knex.Transaction, tenantId: number, appId: number, options: unknown): Promise<AndroidAppAssignmentCheck | null> {
  const app = await readAndroidApp(q, tenantId, appId);
  if (!app) return null;
  const check = checkAndroidAppOptions({ packageName: app.identifier, kind: app.kind, metadata: metadataOf(app.metadata) }, options);
  const issues: AndroidAppAssignmentIssue[] = [...check.issues];
  const refs = check.secrets.filter((s) => s.kind === 'ref');
  if (refs.length) {
    const ids = [...new Set(refs.map((s) => String((at(options, s.path) as { $secret: string }).$secret)))];
    const rows = await q('tenant_secrets').where({ tenant_id: tenantId, purpose: APP_CONFIG_SECRET_PURPOSE }).whereIn('id', ids).pluck('id') as string[];
    const known = new Set(rows.map(String));
    for (const s of refs) {
      const id = String((at(options, s.path) as { $secret: string }).$secret);
      if (!known.has(id)) issues.push({ path: s.path.join('.'), code: 'secret_not_found' });
    }
  }
  return { ...check, issues, app };
}

/**
 * The options with every secret typed in moved to the tenant's vault (in the caller's transaction) and replaced by
 * its reference. Called once per batch, before the batch or its approval request is stored.
 */
export async function sealAndroidAppOptions(trx: Knex.Transaction, tenantId: number, options: Record<string, JsonValue>,
  sites: AndroidAppSecretSite[], actor: { userId: number | null }): Promise<Record<string, JsonValue>> {
  let out = options;
  for (const s of sites) {
    if (s.kind !== 'value') continue;
    const v = at(out, s.path);
    if (!isSecretValue(v)) continue;
    const id = await vault.createTenantSecret(tenantId, s.purpose, v.$secretValue, { userId: actor.userId }, { trx });
    out = replaceAt(out, s.path, { $secret: id });
  }
  if (holdsSecretValue(out)) throw new Error('a secret value would be stored');
  for (const s of sites) if (s.kind === 'ref' && !isSecretRef(at(out, s.path))) throw new Error('a secret reference was lost');
  return out;
}

/**
 * Both steps for a single assignment (the batch of the junction, and the testbed): the options checked, refused
 * with their issues, then sealed. Returns what the batch writes in assignments (resource_type 'app').
 */
export async function prepareAndroidAppAssignment(trx: Knex.Transaction, tenantId: number, appId: number, options: unknown,
  actor: { userId: number | null }): Promise<{ resourceType: 'app'; resourceId: number; resourceTenantId: number; options: Record<string, JsonValue> }> {
  const c = await checkAndroidAppAssignment(trx, tenantId, appId, options);
  if (!c) throw new AndroidAppError(404, 'notFound', 'app not found');
  if (c.issues.length) throw new AndroidAppOptionsError(c.issues);
  const sealed = await sealAndroidAppOptions(trx, tenantId, options as Record<string, JsonValue>, c.secrets, actor);
  return { resourceType: 'app', resourceId: Number(c.app.id), resourceTenantId: tenantId, options: sealed };
}
