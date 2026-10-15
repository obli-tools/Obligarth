// Registry of the Android enterprises of the tenants (android_enterprises, under RLS) and the platform state of the
// link (android_platform_state, technical: one row, no tenant data). The only issuer of the AndroidEnterpriseRef the
// gateway accepts. The project is pinned at the first enterprise linked (EX-A13): an instance pointed at another
// project afterwards refuses to start its Android link.
import type { Knex } from 'knex';
import { db } from '../../db';
import { issueEnterpriseRef } from '../gateway/refs';
import type { AndroidEnterpriseRef } from '../gateway/names';

export interface EnterpriseRow {
  id: number;
  tenant_id: number;
  enterprise_name: string | null;
  project_id: string | null;
  state: 'pending' | 'linked' | 'unlinking' | 'unlinked' | 'error';
  enterprise_type: string | null;
  domain_type: string | null;
  admin_domain: string | null;
  display_name: string;
  mgpa_exception: boolean;
  topic_set_at: Date | null;
  test_message_at: Date | null;
  linked_at: Date | null;
}

const LIVE = ['pending', 'linked', 'unlinking', 'error'];

/** The live enterprise row of the current tenant (context 'tenant'), or null. */
export async function readEnterpriseRow(q: Knex | Knex.Transaction = db, o: { forUpdate?: boolean } = {}): Promise<EnterpriseRow | null> {
  const b = q('android_enterprises').whereIn('state', LIVE).first<EnterpriseRow | undefined>(
    'id', 'tenant_id', 'enterprise_name', 'project_id', 'state', 'enterprise_type', 'domain_type', 'admin_domain', 'display_name',
    'mgpa_exception', 'topic_set_at', 'test_message_at', 'linked_at');
  if (o.forUpdate) b.forUpdate();
  return (await b) ?? null;
}

/** The enterprise of the current tenant as the gateway takes it (linked, unlinking or error), or null. */
export async function readEnterprise(q: Knex | Knex.Transaction = db): Promise<AndroidEnterpriseRef | null> {
  const row = await readEnterpriseRow(q);
  if (!row || !row.enterprise_name || row.state === 'pending') return null;
  return issueEnterpriseRef({ id: row.id, tenant_id: row.tenant_id, enterprise_name: row.enterprise_name, state: row.state });
}

export interface PlatformState {
  pinned_project_id: string | null;
  credential_fingerprint: string | null;
  credential_set_at: Date | null;
  last_pull_at: Date | null;
  last_applied_publish_at: Date | null;
  last_test_message_at: Date | null;
}

export async function readPlatformState(q: Knex | Knex.Transaction = db): Promise<PlatformState> {
  const row = await q('android_platform_state').where({ id: 1 }).first<PlatformState | undefined>(
    'pinned_project_id', 'credential_fingerprint', 'credential_set_at', 'last_pull_at', 'last_applied_publish_at', 'last_test_message_at');
  return row ?? {
    pinned_project_id: null, credential_fingerprint: null, credential_set_at: null, last_pull_at: null,
    last_applied_publish_at: null, last_test_message_at: null,
  };
}

/** Updates the platform state row (created at first use). Only the gateway, the loop and the maintenance call it. */
export async function updatePlatformState(q: Knex | Knex.Transaction, patch: Partial<PlatformState>): Promise<void> {
  await q('android_platform_state').insert({ id: 1, ...patch, updated_at: q.fn.now() })
    .onConflict('id').merge({ ...patch, updated_at: q.fn.now() });
}

/**
 * Pins `projectId` at the first link (returns 'pinned'); 'same' when already pinned to it; throws when the instance is
 * pinned to another project.
 */
export async function pinProject(trx: Knex.Transaction, projectId: string): Promise<'pinned' | 'same'> {
  await trx('android_platform_state').insert({ id: 1 }).onConflict('id').ignore();
  const row = await trx('android_platform_state').where({ id: 1 }).forUpdate().first<{ pinned_project_id: string | null }>('pinned_project_id');
  if (row?.pinned_project_id === projectId) return 'same';
  if (row?.pinned_project_id) throw new ProjectMismatchError();
  await trx('android_platform_state').where({ id: 1 }).update({ pinned_project_id: projectId, updated_at: trx.fn.now() });
  return 'pinned';
}

export class ProjectMismatchError extends Error {
  constructor() {
    super('the instance is pinned to another Google Cloud project (ANDROID_GCP_PROJECT_ID changed)');
    this.name = 'ProjectMismatchError';
  }
}

/** Refuses to start when the configured project differs from the pinned one (EX-A13). */
export async function checkPinnedProject(projectId: string | null): Promise<void> {
  const state = await readPlatformState();
  if (state.pinned_project_id && state.pinned_project_id !== projectId) throw new ProjectMismatchError();
}
