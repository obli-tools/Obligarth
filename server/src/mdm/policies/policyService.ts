import { createHash, randomUUID } from 'node:crypto';
import type { Knex } from 'knex';
import {
  emptyPolicyContent, POLICY_CATEGORY_RE, RAW_PROFILE_TYPE,
  type Policy, type PolicyContentV1, type PolicyImpact, type PolicyValidationIssue, type PolicyVersion, type PolicyVersionSummary,
  type PolicyVersionState,
} from '@obligarth/shared';
import { db } from '../../db';
import { audit, type AuditWriteContext } from '../../audit';
import { canonicalJson } from '../../audit/canonical';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { vault } from '../../vault';
import { appleCatalog } from '../apple/catalog';
import {
  RawProfileError, type RawProfile, rawSecretSites, rawSuspectKeys, readRawProfile, redactRawProfileItem, redactRawProfileValues, withRawSecretRefs,
} from '../apple/plistRead';
import { withConfigurationLock } from './configLock';
import { requestTenantResolution } from './triggers';
import { androidContributions } from '../android/contributions';
import { legacyAgentContributions } from '../legacyAgent/contributions';
import { legacyAgentNodeAt, type LegacyAgentStoreRef } from '../legacyAgent/validate';
import { FAILED_PASSWORDS_FOR_WIPE } from '../android/overlay';
import type { AndroidValidationOptions } from '../android/validate';
import {
  ANDROID_SECTION_ITEM, androidNodeAt, androidPathText, contentBytes, hasSecretValue, LEGACY_AGENT_SECTION_ITEM, POLICY_MAX_CONTENT_BYTES, RAW_SECRET_PURPOSE,
  rawProfilesOf, validatePolicyContent, withSecretRefs,
  type SecretRefSite,
} from './validate';

// =============================================================================
// The envelope and the versions of a policy (docs: modele-donnees-mdm §7.1,
// §7.2, §10.3): create (an empty draft, or a copy), edit the envelope, save
// the draft (validation, secrets typed in moved to the tenant's vault before
// any storage), new version (a copy of the published one), discard a draft or
// a rejected version, archive (refused while assignments remain). The
// submission and the publication (guards, approval) are in publish.ts. In the
// tenant's database context (the request's). One open version at most per
// policy (policy_versions_one_open); a submitted or published version is
// immutable (policy_versions_guard). Writers lock the policy, then its
// version; those that change the effective configuration (publication,
// archival) take the lock of the tenant's configuration first
// (configLock.ts). A version left 'pending_approval' by a request that is
// over is settled before any change (settleOrphanedPending).
// =============================================================================

export interface PolicyActor { userId: number | null; auditCtx: AuditWriteContext }

/** SHA-256 of the canonical JSON of a content (policy_versions.content_sha256). */
export function contentSha(content: unknown): string {
  return createHash('sha256').update(canonicalJson(content)).digest('hex');
}

const iso = (d: unknown): string | null => (d ? new Date(d as string).toISOString() : null);
const parse = <T>(v: unknown): T => (typeof v === 'string' ? JSON.parse(v) as T : v as T);

/** The content of a version as a reader sees it: a raw profile shows its name, its identifier and the types of its
 *  payloads, never their content (review of lot B5b, MDM-B5b-C9). */
export function contentForReaders(content: PolicyContentV1): PolicyContentV1 {
  const items = content?.sections?.apple?.items;
  if (!Array.isArray(items) || !items.some((i) => i?.type === RAW_PROFILE_TYPE)) return content;
  return { ...content, sections: { ...content.sections, apple: { items: items.map((i) => redactRawProfileItem(i)) } } };
}

/**
 * The raw profiles an editor sends back are those it was shown (contentForReaders): each one that is, value for
 * value, the reduced form of the raw profile the stored draft holds under the same id takes the stored values back.
 * Anything else is left as it came (the validation refuses a raw profile the draft does not hold).
 */
function withStoredRawProfiles(raw: unknown, stored: PolicyContentV1): unknown {
  const items = (raw as PolicyContentV1 | null)?.sections?.apple?.items;
  const kept = new Map((stored?.sections?.apple?.items ?? []).filter((i) => i.type === RAW_PROFILE_TYPE).map((i) => [i.id, i]));
  if (!Array.isArray(items) || kept.size === 0) return raw;
  const restored = items.map((i) => {
    const mine = i && typeof i === 'object' && i.type === RAW_PROFILE_TYPE && typeof i.id === 'string' ? kept.get(i.id.toLowerCase()) : undefined;
    if (!mine || !i.values) return i;
    try {
      return canonicalJson(i.values) === canonicalJson(redactRawProfileValues(mine.values)) ? { ...i, values: mine.values } : i;
    } catch {
      return i;
    }
  });
  const r = raw as PolicyContentV1;
  return { ...r, sections: { ...r.sections, apple: { ...r.sections.apple, items: restored } } };
}

export function rowToVersion(r: Record<string, any>, withContent = true): PolicyVersion {
  return {
    id: Number(r.id),
    policyId: Number(r.policy_id),
    version: Number(r.version),
    state: r.state as PolicyVersionState,
    content: withContent ? contentForReaders(parse<PolicyContentV1>(r.content)) : emptyPolicyContent(),
    contentSha256: String(r.content_sha256).trim(),
    schemaRelease: parse<Record<string, string>>(r.schema_release ?? {}) ?? {},
    summary: parse<PolicyVersionSummary>(r.summary ?? {}) ?? {},
    changeNote: r.change_note ?? null,
    impact: r.impact ? parse<PolicyImpact>(r.impact) : null,
    approvalId: r.approval_id === null || r.approval_id === undefined ? null : Number(r.approval_id),
    createdBy: r.created_by ?? null,
    createdAt: iso(r.created_at) as string,
    submittedBy: r.submitted_by ?? null,
    submittedAt: iso(r.submitted_at),
    publishedBy: r.published_by ?? null,
    publishedAt: iso(r.published_at),
    supersededAt: iso(r.superseded_at),
  };
}

function rowToPolicy(r: Record<string, any>, extra: { currentVersion: number | null; open: PolicyVersion | null; assignments: number }): Policy {
  return {
    id: Number(r.id),
    uuid: r.uuid,
    tenantId: Number(r.tenant_id),
    name: r.name,
    description: r.description ?? null,
    category: r.category,
    state: r.state,
    sections: Array.isArray(r.sections) ? r.sections : [],
    currentVersionId: r.current_version_id === null ? null : Number(r.current_version_id),
    currentVersion: extra.currentVersion,
    versionCounter: Number(r.version_counter),
    openVersion: extra.open ? { id: extra.open.id, version: extra.open.version, state: extra.open.state } : null,
    assignmentCount: extra.assignments,
    shared: Array.isArray(r.target_tenant_ids) && r.target_tenant_ids.length > 0,
    createdBy: r.created_by ?? null,
    updatedBy: r.updated_by ?? null,
    createdAt: iso(r.created_at) as string,
    updatedAt: iso(r.updated_at) as string,
    archivedAt: iso(r.archived_at),
  };
}

const notFound = (): never => { throw new AppError(404, 'Policy not found'); };

/** A unique violation of the name (policies_name_uq) answers 409 policyNameTaken. */
function nameTaken(err: unknown): boolean {
  const e = err as { code?: string; constraint?: string };
  return e?.code === '23505' && e.constraint === 'policies_name_uq';
}

function cleanName(name: unknown): string {
  const n = typeof name === 'string' ? name.trim() : '';
  if (!n || n.length > 200) throw new AppError(400, 'A name of 1 to 200 characters is required', 'invalidRequest', { field: 'name' });
  return n;
}

function cleanCategory(category: unknown): string {
  const c = category === undefined || category === null ? 'configuration' : String(category);
  if (!POLICY_CATEGORY_RE.test(c)) throw new AppError(400, 'Invalid category', 'invalidRequest', { field: 'category' });
  return c;
}

/** The policy row of the tenant (or a policy the master shares with it, read only), locked when asked. */
async function policyRow(q: Knex | Knex.Transaction, tenantId: number, policyId: number, opts: { forUpdate?: boolean; own?: boolean } = {}): Promise<Record<string, any>> {
  if (!Number.isSafeInteger(policyId) || policyId <= 0) notFound();
  const query = q('policies').where({ id: policyId });
  if (opts.own !== false) query.where({ tenant_id: tenantId });
  if (opts.forUpdate) query.forUpdate();
  const row = await query.first() as Record<string, any> | undefined;
  if (!row) notFound();
  return row!;
}

async function versionRow(q: Knex | Knex.Transaction, tenantId: number, policyId: number, version: number, forUpdate = false): Promise<Record<string, any>> {
  if (!Number.isSafeInteger(version) || version <= 0) throw new AppError(404, 'Policy version not found');
  const query = q('policy_versions').where({ tenant_id: tenantId, policy_id: policyId, version });
  if (forUpdate) query.forUpdate();
  const row = await query.first() as Record<string, any> | undefined;
  if (!row) throw new AppError(404, 'Policy version not found');
  return row;
}

/** The purposes of the secrets a policy may refer to (section 7.2): those its own editor and import create. */
const POLICY_SECRET_PURPOSE_PREFIX = 'policy.';

/**
 * The references of a content that designate no secret of the policies of the tenant stored for the key that refers
 * to it: unknown, of another tenant, of a purpose that is not a policy's (tenant_secrets holds the secrets of every
 * document of the tenant: a policy never delivers to devices a secret stored for something else), or of another
 * purpose than its key's (the password of a Wi-Fi is not the identity of a PKCS #12, nor the typed value of a raw
 * profile a password: the rendering reads a secret by the purpose of its key; MDM-B5b-C8). One answer for all:
 * secret_not_found.
 */
export async function missingSecrets(q: Knex | Knex.Transaction, tenantId: number, refs: SecretRefSite[]): Promise<PolicyValidationIssue[]> {
  if (!refs.length) return [];
  const ids = [...new Set(refs.map((r) => r.id))];
  const rows = await q('tenant_secrets').where({ tenant_id: tenantId }).whereIn('id', ids).select('id', 'purpose') as Array<{ id: string; purpose: string }>;
  const purposes = new Map(rows.filter((r) => String(r.purpose).startsWith(POLICY_SECRET_PURPOSE_PREFIX)).map((r) => [String(r.id), String(r.purpose)]));
  return refs.filter((r) => purposes.get(r.id) !== r.purpose).map((r) => ({ itemId: r.itemId, path: r.path, code: 'secret_not_found' as const }));
}

/** Minutes an approved request may take to execute before its version is held to be left behind. */
const EXECUTION_GRACE_MINUTES = 10;

/**
 * A version 'pending_approval' whose request neither waits nor executes any more (a process stopped between the
 * decision and the execution, a closing hook that failed, a request deleted) would block its policy for ever: one
 * open version at most, and a version under approval is never discarded. It is settled the way its request ended:
 * rejected after a refusal or an expiry, back to the draft of its author otherwise. Called before every change of
 * the versions of a policy, in the tenant's context. Returns the number of versions settled.
 */
export async function settleOrphanedPending(q: Knex | Knex.Transaction, tenantId: number, policyId: number): Promise<number> {
  const rows = await q('policy_versions as v')
    .leftJoin('pending_approvals as a', function joinApproval() { this.on('a.id', '=', 'v.approval_id').andOn('a.tenant_id', '=', 'v.tenant_id'); })
    .where({ 'v.tenant_id': tenantId, 'v.policy_id': policyId, 'v.state': 'pending_approval' })
    .select('v.id', 'v.version', 'v.approval_id', 'a.status', 'a.reviewed_at', 'a.execution_error') as
    Array<{ id: number; version: number; approval_id: number | null; status: string | null; reviewed_at: Date | null; execution_error: string | null }>;
  let settled = 0;
  for (const r of rows) {
    if (r.status === 'pending') continue;
    const executing = r.status === 'approved' && !r.execution_error && r.reviewed_at
      && Date.now() - new Date(r.reviewed_at).getTime() < EXECUTION_GRACE_MINUTES * 60_000;
    if (executing) continue;
    const to = r.status === 'denied' || r.status === 'expired' ? 'rejected' : 'draft';
    const n = await q('policy_versions').where({ tenant_id: tenantId, id: r.id, state: 'pending_approval', approval_id: r.approval_id })
      .update(to === 'draft' ? { state: 'draft', approval_id: null } : { state: 'rejected' });
    if (!n) continue;
    settled++;
    logger.warn({ tenantId, policyId, version: Number(r.version), approvalId: r.approval_id, approval: r.status ?? 'missing', to },
      'policy version left behind by its approval request: settled');
  }
  return settled;
}

/** 422 validationFailed, details: the issues ({ itemId, path, code }). */
export function validationFailed(issues: PolicyValidationIssue[]): never {
  throw new AppError(422, 'The content of the policy is not valid', 'validationFailed', issues as unknown as Record<string, unknown>);
}

/** The sections a content holds (policies.sections): apple with items, android with at least one setting key, legacy_agent
 *  (the content key legacyAgent, lot PONT-POL) with at least one setting key. */
export function sectionsOf(content: PolicyContentV1 | null | undefined): string[] {
  const out: string[] = [];
  if (content?.sections?.apple?.items.length) out.push('apple');
  if (content?.sections?.android && androidContributions(content.sections.android).length) out.push('android');
  if (content?.sections?.legacyAgent && legacyAgentContributions(content.sections.legacyAgent).length) out.push('legacy_agent');
  return out;
}

/**
 * The store files a section of the bridge agent references that the tenant's store does not hold as referenced (lot
 * PONT-POL §4.4): no row, another size (file_not_found), or another kind (file_kind_mismatch: an image for a tile or
 * the logo, a certificate for a CA, a file for a deposit). In the caller's transaction: the publication runs it under
 * the configuration lock, which the deletion of a store file takes too (B6).
 */
export async function missingFiles(q: Knex | Knex.Transaction, tenantId: number, refs: LegacyAgentStoreRef[]): Promise<PolicyValidationIssue[]> {
  if (!refs.length) return [];
  const shas = [...new Set(refs.map((r) => r.sha256))];
  const rows = await q('legacy_agent_files').where({ tenant_id: tenantId }).whereIn('sha256', shas).select('sha256', 'size_bytes', 'kind') as
    Array<{ sha256: string; size_bytes: string | number; kind: string }>;
  const bySha = new Map(rows.map((r) => [String(r.sha256).trim(), r]));
  const out: PolicyValidationIssue[] = [];
  for (const r of refs) {
    const row = bySha.get(r.sha256);
    if (!row || Number(row.size_bytes) !== r.size) out.push({ itemId: LEGACY_AGENT_SECTION_ITEM, path: r.path, code: 'file_not_found' });
    else if (row.kind !== r.kind) out.push({ itemId: LEGACY_AGENT_SECTION_ITEM, path: r.path, code: 'file_kind_mismatch' });
  }
  return out;
}

/** The guards of the Android validation of a tenant (android-amapi §22.4; lot AN-A2): the domain of its live
 *  enterprise (FRP administrators) and the floor of maximumFailedPasswordsForWipe (the default floor until the tenant
 *  setting androidMinFailedPasswordsForWipe exists). In the tenant's context of the caller. */
export async function androidValidationOptions(q: Knex | Knex.Transaction, tenantId: number): Promise<AndroidValidationOptions> {
  const e = await q('android_enterprises').where({ tenant_id: tenantId }).whereNot('state', 'unlinked').first('admin_domain') as
    { admin_domain: string | null } | undefined;
  return { adminDomain: e?.admin_domain ?? null, minFailedPasswordsForWipe: FAILED_PASSWORDS_FOR_WIPE.defaultFloor };
}

/** Validates a content for a submission or a publication (no secret typed in; references must exist). */
export async function validateForSubmission(q: Knex | Knex.Transaction, tenantId: number, policyUuid: string, content: unknown):
  Promise<{ issues: PolicyValidationIssue[]; content: PolicyContentV1 | null; androidWipeRules: string[]; legacyAgentWipeRules: string[];
    legacyAgentTenantBound: boolean }> {
  const v = validatePolicyContent(content, { catalog: appleCatalog(), policyUuid, allowSecretValues: false, allowRawProfiles: true,
    android: await androidValidationOptions(q, tenantId) });
  const issues = [...v.issues, ...(await missingSecrets(q, tenantId, v.secretRefs)), ...(await missingFiles(q, tenantId, v.legacyAgentStoreRefs))];
  if (!sectionsOf(v.content).length && !issues.length) issues.push({ itemId: null, path: 'sections.apple.items', code: 'invalid_content' });
  return { issues, content: v.content, androidWipeRules: v.androidWipeRules, legacyAgentWipeRules: v.legacyAgentWipeRules,
    legacyAgentTenantBound: v.legacyAgentTenantBound };
}

export const policyService = {
  async list(tenantId: number, opts: { state?: string; category?: string; q?: string } = {}): Promise<Policy[]> {
    const query = db('policies').where({ tenant_id: tenantId }).orderBy([{ column: 'name' }, { column: 'id' }]);
    if (opts.state) query.where({ state: opts.state });
    else query.whereNot({ state: 'archived' });
    if (opts.category) query.where({ category: opts.category });
    if (opts.q) query.whereRaw('lower(name) LIKE ?', [`%${opts.q.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`)}%`]);
    const rows = await query.select('*') as Array<Record<string, any>>;
    return this.decorate(tenantId, rows);
  },

  async decorate(tenantId: number, rows: Array<Record<string, any>>): Promise<Policy[]> {
    if (!rows.length) return [];
    const ids = rows.map((r) => Number(r.id));
    const versions = await db('policy_versions').where({ tenant_id: tenantId }).whereIn('policy_id', ids)
      .where((w) => w.whereIn('state', ['draft', 'pending_approval', 'published']))
      .select('id', 'policy_id', 'version', 'state') as Array<{ id: number; policy_id: number; version: number; state: PolicyVersionState }>;
    const counts = await db('assignments').where({ tenant_id: tenantId, resource_type: 'policy', resource_tenant_id: tenantId })
      .whereIn('resource_id', ids).groupBy('resource_id').select('resource_id').count({ n: '*' }) as Array<{ resource_id: number; n: string | number }>;
    const countOf = new Map(counts.map((c) => [Number(c.resource_id), Number(c.n)]));
    return rows.map((r) => {
      const mine = versions.filter((v) => Number(v.policy_id) === Number(r.id));
      const published = mine.find((v) => v.state === 'published');
      const open = mine.find((v) => v.state === 'draft' || v.state === 'pending_approval');
      return rowToPolicy(r, {
        currentVersion: published ? Number(published.version) : null,
        open: open ? { id: Number(open.id), version: Number(open.version), state: open.state } as PolicyVersion : null,
        assignments: countOf.get(Number(r.id)) ?? 0,
      });
    });
  },

  async get(tenantId: number, policyId: number): Promise<Policy> {
    const row = await policyRow(db, tenantId, policyId);
    return (await this.decorate(tenantId, [row]))[0];
  },

  /** Creates a policy: its envelope and version 1 (empty, or a copy of another policy of the tenant). */
  async create(tenantId: number, input: { name: unknown; description?: unknown; category?: unknown; copyFrom?: unknown },
    actor: PolicyActor): Promise<{ policy: Policy; version: PolicyVersion }> {
    const name = cleanName(input.name);
    const category = cleanCategory(input.category);
    const description = typeof input.description === 'string' ? input.description.slice(0, 10_000) : null;
    let content: PolicyContentV1 = emptyPolicyContent();
    let copyFrom: number | null = null;
    if (input.copyFrom !== undefined && input.copyFrom !== null) {
      copyFrom = Number(input.copyFrom);
      const src = await policyRow(db, tenantId, copyFrom);
      const v = await db('policy_versions').where({ tenant_id: tenantId, policy_id: src.id })
        .orderByRaw("CASE WHEN state = 'published' THEN 0 ELSE 1 END").orderBy('version', 'desc').first('content') as { content: unknown } | undefined;
      if (v) content = parse<PolicyContentV1>(v.content);
    }
    const summary = validatePolicyContent(content, { catalog: appleCatalog(), policyUuid: '00000000-0000-0000-0000-000000000000', allowSecretValues: false, allowRawProfiles: true }).summary;
    let created: { policy: Record<string, any>; version: Record<string, any> };
    try {
      created = await db.transaction(async (trx) => {
        const [policy] = await trx('policies').insert({
          tenant_id: tenantId, name, description, category, state: 'draft',
          sections: sectionsOf(content), version_counter: 1,
          created_by: actor.userId, updated_by: actor.userId,
        }).returning('*') as Array<Record<string, any>>;
        const [version] = await trx('policy_versions').insert({
          tenant_id: tenantId, policy_id: policy.id, version: 1, state: 'draft', content: JSON.stringify(content),
          content_sha256: contentSha(content), schema_release: JSON.stringify({ apple: appleCatalog().release.commit }),
          summary: JSON.stringify(summary), created_by: actor.userId,
        }).returning('*') as Array<Record<string, any>>;
        return { policy, version };
      });
    } catch (err) {
      if (nameTaken(err)) throw new AppError(409, 'A policy of this name exists in the tenant', 'policyNameTaken');
      throw err;
    }
    await audit.append({
      tenantId, action: 'policy.created', target: { type: 'policy', id: String(created.policy.id) },
      details: { category, copyFrom, items: summary.items },
    }, actor.auditCtx);
    return { policy: await this.get(tenantId, Number(created.policy.id)), version: rowToVersion(created.version) };
  },

  /** Name, description, category of the envelope. */
  async update(tenantId: number, policyId: number, patch: { name?: unknown; description?: unknown; category?: unknown },
    actor: PolicyActor): Promise<Policy> {
    const row = await policyRow(db, tenantId, policyId);
    if (row.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
    const changes: Record<string, unknown> = {};
    if (patch.name !== undefined) changes.name = cleanName(patch.name);
    if (patch.description !== undefined) changes.description = typeof patch.description === 'string' ? patch.description.slice(0, 10_000) : null;
    if (patch.category !== undefined) changes.category = cleanCategory(patch.category);
    if (Object.keys(changes).length) {
      try {
        await db('policies').where({ tenant_id: tenantId, id: policyId }).update({ ...changes, updated_by: actor.userId, updated_at: new Date() });
      } catch (err) {
        if (nameTaken(err)) throw new AppError(409, 'A policy of this name exists in the tenant', 'policyNameTaken');
        throw err;
      }
      await audit.append({
        tenantId, action: 'policy.updated', target: { type: 'policy', id: String(policyId) }, details: { fields: Object.keys(changes) },
      }, actor.auditCtx);
    }
    return this.get(tenantId, policyId);
  },

  async versions(tenantId: number, policyId: number): Promise<PolicyVersion[]> {
    await policyRow(db, tenantId, policyId);
    const rows = await db('policy_versions').where({ tenant_id: tenantId, policy_id: policyId }).orderBy('version', 'desc')
      .select('id', 'policy_id', 'version', 'state', 'content_sha256', 'schema_release', 'summary', 'change_note', 'approval_id',
        'created_by', 'created_at', 'submitted_by', 'submitted_at', 'published_by', 'published_at', 'superseded_at') as Array<Record<string, any>>;
    return rows.map((r) => rowToVersion(r, false));
  },

  async version(tenantId: number, policyId: number, version: number): Promise<PolicyVersion> {
    await policyRow(db, tenantId, policyId);
    return rowToVersion(await versionRow(db, tenantId, policyId, version));
  },

  /**
   * Saves the content of a draft: validation (section 7.2) against the stored draft (its raw profiles are kept as
   * they are), references checked in the tenant, secrets typed in ({"$secretValue"}) moved to the vault
   * (vault.createTenantSecret, purposes policy.*) and replaced by their reference before any storage, in one
   * transaction. A version other than a draft answers 409.
   */
  async saveDraft(tenantId: number, policyId: number, version: number, rawContent: unknown, changeNote: unknown,
    actor: PolicyActor): Promise<PolicyVersion> {
    await policyRow(db, tenantId, policyId);
    await settleOrphanedPending(db, tenantId, policyId);
    const note = typeof changeNote === 'string' && changeNote.trim() ? changeNote.trim().slice(0, 2000) : null;
    const saved = await db.transaction(async (trx) => {
      // The policy, then its version: the order of every writer of the versions.
      const policy = await policyRow(trx, tenantId, policyId, { forUpdate: true });
      if (policy.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
      const row = await versionRow(trx, tenantId, policyId, version, true);
      if (row.state !== 'draft') throw new AppError(409, 'Only a draft is edited', 'policyVersionNotDraft', { state: row.state });
      // Validated against the draft as it is stored (locked): the raw profiles it holds are kept as they are (the
      // editor sends back what it was shown of them).
      const stored = parse<PolicyContentV1>(row.content);
      const v = validatePolicyContent(withStoredRawProfiles(rawContent, stored), {
        catalog: appleCatalog(), policyUuid: policy.uuid, allowSecretValues: true, keptRawProfiles: rawProfilesOf(stored),
        android: await androidValidationOptions(trx, tenantId),
      });
      const issues = [...v.issues, ...(await missingSecrets(trx, tenantId, v.secretRefs)), ...(await missingFiles(trx, tenantId, v.legacyAgentStoreRefs))];
      if (issues.length || !v.content) validationFailed(issues);
      const sites: Array<(typeof v.secretValues)[number] & { id: string }> = [];
      for (const s of v.secretValues) {
        const value = valueAt(v.content!, s.itemId, s.path);
        const id = await vault.createTenantSecret(tenantId, s.purpose, value, { userId: actor.userId }, { trx });
        sites.push({ ...s, id });
      }
      const content = sites.length ? withSecretRefs(v.content!, sites) : v.content!;
      if (hasSecretValue(content)) throw new Error('a secret value would be stored');
      if (contentBytes(content) > POLICY_MAX_CONTENT_BYTES) validationFailed([{ itemId: null, path: '', code: 'content_too_large' }]);
      const [updated] = await trx('policy_versions').where({ tenant_id: tenantId, id: row.id }).update({
        content: JSON.stringify(content), content_sha256: contentSha(content), summary: JSON.stringify(v.summary),
        schema_release: JSON.stringify({ apple: appleCatalog().release.commit }), change_note: note,
        // A content that changes invalidates a stored preview.
        impact: null,
      }).returning('*') as Array<Record<string, any>>;
      await trx('policies').where({ tenant_id: tenantId, id: policyId }).update({
        sections: sectionsOf(content), updated_by: actor.userId, updated_at: new Date(),
      });
      return { row: updated, secrets: sites.length, summary: v.summary };
    });
    await audit.append({
      tenantId, action: 'policy.draft_saved', target: { type: 'policy', id: String(policyId) },
      details: { version, items: saved.summary.items, removals: saved.summary.removals, referencesCreated: saved.secrets,
        contentSha256: String(saved.row.content_sha256).slice(0, 16) },
    }, actor.auditCtx);
    return rowToVersion(saved.row);
  },

  /**
   * A new draft, numbered version_counter + 1: a copy of the published version (else of the latest one) or, with
   * `from`, of a rejected version of the policy (the draft a refusal or an expiry set aside is made again; the copy
   * of a superseded version is the rollback of the v1).
   */
  async newVersion(tenantId: number, policyId: number, actor: PolicyActor, opts: { from?: number } = {}): Promise<PolicyVersion> {
    await policyRow(db, tenantId, policyId);
    await settleOrphanedPending(db, tenantId, policyId);
    const created = await db.transaction(async (trx) => {
      const policy = await policyRow(trx, tenantId, policyId, { forUpdate: true });
      if (policy.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
      const open = await trx('policy_versions').where({ tenant_id: tenantId, policy_id: policyId })
        .whereIn('state', ['draft', 'pending_approval']).first('version', 'state') as { version: number; state: string } | undefined;
      if (open) throw new AppError(409, 'The policy has an open version', 'policyHasOpenVersion', { version: Number(open.version), state: open.state });
      let src: { content: unknown; summary: unknown } | undefined;
      if (opts.from !== undefined) {
        const from = await versionRow(trx, tenantId, policyId, opts.from);
        if (from.state !== 'rejected') {
          throw new AppError(409, 'Only a rejected version is taken up again', 'policyVersionNotRejected', { state: from.state });
        }
        src = { content: from.content, summary: from.summary };
      } else {
        src = await trx('policy_versions').where({ tenant_id: tenantId, policy_id: policyId })
          .orderByRaw("CASE WHEN state = 'published' THEN 0 ELSE 1 END").orderBy('version', 'desc')
          .first('content', 'summary') as { content: unknown; summary: unknown } | undefined;
      }
      const content = src ? parse<PolicyContentV1>(src.content) : emptyPolicyContent();
      const number = Number(policy.version_counter) + 1;
      const [row] = await trx('policy_versions').insert({
        tenant_id: tenantId, policy_id: policyId, version: number, state: 'draft', content: JSON.stringify(content),
        content_sha256: contentSha(content), schema_release: JSON.stringify({ apple: appleCatalog().release.commit }),
        summary: JSON.stringify(src ? parse(src.summary) ?? {} : {}), created_by: actor.userId,
      }).returning('*') as Array<Record<string, any>>;
      await trx('policies').where({ tenant_id: tenantId, id: policyId })
        .update({ version_counter: number, updated_by: actor.userId, updated_at: new Date() });
      return row;
    });
    await audit.append({
      tenantId, action: 'policy.draft_saved', target: { type: 'policy', id: String(policyId) },
      details: { version: Number(created.version), created: true, ...(opts.from !== undefined ? { from: opts.from } : {}) },
    }, actor.auditCtx);
    return rowToVersion(created);
  },

  /** Discards a draft or a rejected version (a version under approval or published is never deleted). */
  async discardDraft(tenantId: number, policyId: number, version: number, actor: PolicyActor): Promise<void> {
    await policyRow(db, tenantId, policyId);
    await settleOrphanedPending(db, tenantId, policyId);
    await db.transaction(async (trx) => {
      await policyRow(trx, tenantId, policyId, { forUpdate: true });
      const row = await versionRow(trx, tenantId, policyId, version, true);
      if (row.state !== 'draft' && row.state !== 'rejected') {
        throw new AppError(409, 'Only a draft or a rejected version is discarded', 'policyVersionNotDraft', { state: row.state });
      }
      await trx('policy_versions').where({ tenant_id: tenantId, id: row.id }).delete();
    });
    await audit.append({
      tenantId, action: 'policy.draft_discarded', target: { type: 'policy', id: String(policyId) }, details: { version },
    }, actor.auditCtx);
  },

  /** Archives a policy: refused while it has assignments (removing them is a change published like any other) or
   *  a version awaiting approval. Under the lock of the tenant's configuration: a batch of assignments written at
   *  the same time either sees the policy archived, or is seen here. */
  async archive(tenantId: number, policyId: number, actor: PolicyActor): Promise<Policy> {
    await policyRow(db, tenantId, policyId);
    await settleOrphanedPending(db, tenantId, policyId);
    await withConfigurationLock(tenantId, async (trx) => {
      const policy = await policyRow(trx, tenantId, policyId, { forUpdate: true });
      if (policy.state === 'archived') return;
      const n = await trx('assignments').where({ resource_type: 'policy', resource_tenant_id: tenantId, resource_id: policyId }).first('id');
      if (n) throw new AppError(409, 'Remove the assignments of the policy first', 'policyHasAssignments');
      const pending = await trx('policy_versions').where({ tenant_id: tenantId, policy_id: policyId, state: 'pending_approval' }).first('version');
      if (pending) throw new AppError(409, 'A version of the policy awaits an approval', 'policyHasOpenVersion', { version: Number(pending.version), state: 'pending_approval' });
      await trx('policies').where({ tenant_id: tenantId, id: policyId })
        .update({ state: 'archived', archived_at: new Date(), updated_by: actor.userId, updated_at: new Date() });
      await requestTenantResolution(trx, tenantId);
    });
    await audit.append({ tenantId, action: 'policy.archived', target: { type: 'policy', id: String(policyId) } }, actor.auditCtx);
    return this.get(tenantId, policyId);
  },

  /**
   * Imports a configuration profile (.mobileconfig, CFG-06) as a raw.profile item of the open draft of the policy:
   * read by the strict reader (a signature removed, a binary or encrypted profile and the forbidden payloads
   * refused), its secrets moved to the tenant's vault (purpose policy.raw_secret, the typed value as JSON) before
   * anything is stored, in one transaction. Answers what a reader sees of the item, and the names of the keys moved
   * (never a value). 422 rawProfileInvalid; 409 when the policy has no draft.
   */
  async importRawProfile(tenantId: number, policyId: number, bytes: Buffer, actor: PolicyActor):
    Promise<{ version: PolicyVersion; itemId: string; movedSecrets: string[]; suspectKeys: string[]; payloadTypes: string[]; signed: boolean;
      signature: RawProfile['signature'] }> {
    await policyRow(db, tenantId, policyId);
    await settleOrphanedPending(db, tenantId, policyId);
    let profile: ReturnType<typeof readRawProfile>;
    try {
      profile = readRawProfile(bytes);
    } catch (err) {
      if (err instanceof RawProfileError) {
        throw new AppError(422, 'The profile cannot be imported', 'rawProfileInvalid', { reason: err.code, ...(err.detail ? { at: err.detail } : {}) });
      }
      throw err;
    }
    const catalog = appleCatalog();
    const sites = rawSecretSites(profile.payloads, (type, path) => catalog.secretPurpose(type, path) !== null);
    const itemId = randomUUID();
    const saved = await db.transaction(async (trx) => {
      const policy = await policyRow(trx, tenantId, policyId, { forUpdate: true });
      if (policy.state === 'archived') throw new AppError(409, 'An archived policy does not change', 'policyArchived');
      const row = await trx('policy_versions').where({ tenant_id: tenantId, policy_id: policyId, state: 'draft' }).forUpdate().first() as
        Record<string, any> | undefined;
      if (!row) throw new AppError(409, 'The policy has no draft to import into', 'policyVersionNotDraft');
      const ids: string[] = [];
      for (const s of sites) ids.push(await vault.createTenantSecret(tenantId, RAW_SECRET_PURPOSE, JSON.stringify(s.value), { userId: actor.userId }, { trx }));
      const stored = parse<PolicyContentV1>(row.content);
      const item = { id: itemId, type: RAW_PROFILE_TYPE, values: {
        displayName: profile.displayName, originalIdentifier: profile.originalIdentifier, payloads: withRawSecretRefs(profile.payloads, sites, ids),
      } };
      const next: PolicyContentV1 = { format: 1, sections: { ...stored.sections, apple: { items: [...(stored.sections?.apple?.items ?? []), item] } } };
      const v = validatePolicyContent(next, { catalog, policyUuid: policy.uuid, allowSecretValues: false, allowRawProfiles: true,
        android: await androidValidationOptions(trx, tenantId) });
      const issues = [...v.issues, ...(await missingSecrets(trx, tenantId, v.secretRefs))];
      if (issues.length || !v.content) validationFailed(issues);
      if (hasSecretValue(v.content)) throw new Error('a secret value would be stored');
      if (contentBytes(v.content) > POLICY_MAX_CONTENT_BYTES) validationFailed([{ itemId: null, path: '', code: 'content_too_large' }]);
      const [updated] = await trx('policy_versions').where({ tenant_id: tenantId, id: row.id }).update({
        content: JSON.stringify(v.content), content_sha256: contentSha(v.content), summary: JSON.stringify(v.summary),
        schema_release: JSON.stringify({ apple: catalog.release.commit }), impact: null,
      }).returning('*') as Array<Record<string, any>>;
      await trx('policies').where({ tenant_id: tenantId, id: policyId }).update({ sections: sectionsOf(v.content), updated_by: actor.userId, updated_at: new Date() });
      return updated;
    });
    const payloadTypes = [...new Set(profile.payloads.map((p) => String(p.PayloadType)))].sort();
    // Key names only: the last name of each path, never a value.
    const movedSecrets = [...new Set(sites.map((s) => s.path.filter((p) => typeof p === 'string').join('.')))].sort();
    await audit.append({
      tenantId, action: 'policy.raw_profile_imported', target: { type: 'policy', id: String(policyId) },
      details: { version: Number(saved.version), payloads: profile.payloads.length, payloadTypes: payloadTypes.slice(0, 20), movedToVault: sites.length, signed: profile.signed,
        signature: profile.signature ? { status: profile.signature.status, trusted: profile.signature.trusted ?? false, signerSha256: profile.signature.signer?.sha256 ?? null } : null },
    }, actor.auditCtx);
    // Keys that look like secrets and stay in clear (no rule moved them): shown to the editor (MDM-B5c-R9).
    const suspectKeys = rawSuspectKeys(profile.payloads, sites);
    return { version: rowToVersion(saved), itemId, movedSecrets, suspectKeys, payloadTypes, signed: profile.signed, signature: profile.signature };
  },

  /** Validation and conflicts of a version, without effect (POST …/validate). */
  async validate(tenantId: number, policyId: number, version: number): Promise<{ issues: PolicyValidationIssue[] }> {
    const policy = await policyRow(db, tenantId, policyId);
    const row = await versionRow(db, tenantId, policyId, version);
    const { issues } = await validateForSubmission(db, tenantId, policy.uuid, parse(row.content));
    return { issues };
  },

  policyRow,
  versionRow,
};

/** The value at a path of an item (a secret typed in). */
function valueAt(content: PolicyContentV1, itemId: string, path: Array<string | number>): string {
  let node: unknown;
  if (itemId === ANDROID_SECTION_ITEM) {
    const at = androidNodeAt(content.sections.android, androidPathText(path));
    node = at ? at.parent[at.key] : undefined;
  } else if (itemId === LEGACY_AGENT_SECTION_ITEM) {
    const at = legacyAgentNodeAt(content.sections.legacyAgent, path);
    node = at ? at.parent[at.key] : undefined;
  } else {
    node = content.sections.apple?.items.find((i) => i.id === itemId);
    for (const p of path) node = (node as Record<string | number, unknown>)?.[p as string];
  }
  const v = (node as { $secretValue?: unknown })?.$secretValue;
  if (typeof v !== 'string') throw new Error('secret value not found at its site');
  return v;
}
