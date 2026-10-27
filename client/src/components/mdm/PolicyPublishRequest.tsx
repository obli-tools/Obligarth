import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { ImpactApprovalReason } from '@obligarth/shared';
import { approvalReasonLabel, settingKeyLabel } from '@/components/mdm/ImpactPreview';
import { trCode } from '@/utils/apiError';

// What a request of the type mdm_policy_publish will execute, for its reviewer (modele-donnees-mdm §11.3,
// MDM-B5b-C16): the change itself first (a publication, a batch of assignments, a group moved or deleted, a change of
// a dynamic group an assignment targets or of the facts of a device that moves it in such a group: P0-5 T7), then
// the counters of the preview the request was filed with, then its keys. The generic table of a payload stopped
// at 80 lines, and the keys of the preview (five lines each) came first: beyond some fifteen keys the counters
// and the changes could no longer be read.

interface StoredImpact {
  devicesInScope?: number; devicesTouched?: number; devicesAdded?: number; devicesRemoved?: number;
  artifacts?: { installs?: number; removals?: number; kioskLockChanges?: number; appRemovals?: number };
  removalDevices?: number; fleetSize?: number; conflicts?: number; reasons?: string[];
  keys?: Array<{ settingKey: string; added?: number; changed?: number; removed?: number; notApplicable?: number }>;
  keysTotal?: number; digest?: string;
}
interface StoredChange {
  op?: string; id?: number; resourceType?: string; resourceId?: number; targetScope?: string; targetId?: number | null;
  mode?: string; priority?: number;
}
export interface PolicyPublishPayload {
  kind?: 'version' | 'assignments' | 'group_move' | 'group_delete' | 'smart_group_rule' | 'smart_group_delete' | 'smart_group_release'
    | 'device_facts' | string;
  policyId?: number; version?: number;
  changes?: StoredChange[];
  base?: Array<{ policyId?: number; version?: number }>;
  groupId?: number; newParentId?: number | null;
  /** A dynamic group (P0-5 T7): the version of its rule the request was filed on, its new name, its entries and exits. */
  smartGroupId?: number; ruleVersion?: number; name?: string;
  membership?: { added?: number; removed?: number; total?: number };
  /** The facts of a device (P0-5 D11): its fields changed (their names only are shown), the targeted groups it enters and leaves. */
  deviceId?: number; patch?: Record<string, unknown>;
  smartGroups?: { entered?: number[]; left?: number[] };
  impact?: StoredImpact;
}

export const POLICY_PUBLISH_REQUEST_TYPE = 'mdm_policy_publish';

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const ids = (v: unknown): number[] => (Array.isArray(v) ? v.filter((x): x is number => typeof x === 'number' && Number.isFinite(x)) : []);

function Counter({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <span className="inline-flex items-baseline gap-1 rounded bg-bg-secondary px-1.5 py-0.5">
      <span className={`font-semibold tabular-nums ${value > 0 && tone ? tone : 'text-text-primary'}`}>{value}</span>
      <span className="text-text-muted">{label}</span>
    </span>
  );
}

export function PolicyPublishSummary({ payload }: { payload: unknown }) {
  const { t } = useTranslation();
  const p = (payload && typeof payload === 'object' ? payload : {}) as PolicyPublishPayload;
  const impact = p.impact ?? {};
  const keys = Array.isArray(impact.keys) ? impact.keys : [];
  const changes = Array.isArray(p.changes) ? p.changes : [];
  const reasons = Array.isArray(impact.reasons) ? impact.reasons : [];
  const target = (c: StoredChange): string => (c.targetScope === 'tenant' ? (t('mdm.assignments.wholeTenant') || 'Whole tenant')
    : `${trCode(`mdm.assignments.scope.${c.targetScope}`, String(c.targetScope ?? ''))} #${c.targetId}`);

  return (
    <div className="mt-1 rounded bg-bg-tertiary p-2 text-left text-[11px] space-y-2">
      <p className="text-[10px] uppercase text-text-muted">{t('approvals.details', 'What will be executed')}</p>

      {/* 1. The change */}
      {p.kind === 'version' && (
        <p className="text-text-primary">
          {t('approvals.publish.version', { version: p.version }) || `Publication of version ${p.version} of the policy`}{' '}
          <Link to={`/policies/${p.policyId}`} className="text-accent hover:underline">#{p.policyId}</Link>
        </p>
      )}
      {p.kind === 'group_move' && (
        <p className="text-text-primary">
          {t('approvals.publish.groupMove') || 'Move of the group'}{' '}
          <Link to={`/group/${p.groupId}`} className="text-accent hover:underline">#{p.groupId}</Link>{' → '}
          {p.newParentId === null || p.newParentId === undefined
            ? (t('groupPanel.rootLevel') || 'Root level (no parent)')
            : <Link to={`/group/${p.newParentId}`} className="text-accent hover:underline">#{p.newParentId}</Link>}
        </p>
      )}
      {p.kind === 'group_delete' && (
        <p className="text-text-primary">
          {t('approvals.publish.groupDelete') || 'Deletion of the group'}{' '}
          <Link to={`/group/${p.groupId}`} className="text-accent hover:underline">#{p.groupId}</Link>
        </p>
      )}
      {(p.kind === 'smart_group_rule' || p.kind === 'smart_group_delete' || p.kind === 'smart_group_release') && (
        <div className="text-text-primary">
          <p>
            {p.kind === 'smart_group_rule'
              ? (t('approvals.publish.smartGroupRule', { version: num(p.ruleVersion) }) || `New rule for the dynamic group (its version ${num(p.ruleVersion)} replaced)`)
              : p.kind === 'smart_group_delete'
                ? (t('approvals.publish.smartGroupDelete') || 'Deletion of the dynamic group, with its assignments')
                : (t('approvals.publish.smartGroupRelease') || 'Release of the dynamic group held by the mass guard')}
            {' '}<span className="font-mono">#{p.smartGroupId}</span>
            {p.kind === 'smart_group_rule' && typeof p.name === 'string' && <> · {t('approvals.publish.smartGroupName') || 'new name'}: {p.name}</>}
          </p>
          {p.membership && (
            <p className="text-text-secondary">
              {t('approvals.publish.smartGroupMembership', { added: num(p.membership.added), removed: num(p.membership.removed), total: num(p.membership.total) })
                || `${num(p.membership.added)} device(s) enter, ${num(p.membership.removed)} leave; ${num(p.membership.total)} member(s) afterwards`}
            </p>
          )}
        </div>
      )}
      {p.kind === 'device_facts' && (
        <div className="text-text-primary">
          <p>
            {t('approvals.publish.deviceFacts') || 'Change of the record of the device'}{' '}
            <Link to={`/devices/${p.deviceId}`} className="text-accent hover:underline">#{p.deviceId}</Link>
          </p>
          {/* The names of the fields only: never their values (tags, custom fields). */}
          {p.patch && typeof p.patch === 'object' && (
            <p className="text-text-secondary">
              {t('approvals.publish.deviceFactsFields') || 'Fields'}: <span className="font-mono">{Object.keys(p.patch).slice(0, 20).join(', ')}</span>
            </p>
          )}
          {p.smartGroups && (
            <p className="text-text-secondary">
              {t('approvals.publish.deviceFactsGroups', {
                entered: ids(p.smartGroups.entered).map((x) => `#${x}`).join(', ') || '—',
                left: ids(p.smartGroups.left).map((x) => `#${x}`).join(', ') || '—',
              }) || `Dynamic groups entered: ${ids(p.smartGroups.entered).map((x) => `#${x}`).join(', ') || '—'}; left: ${ids(p.smartGroups.left).map((x) => `#${x}`).join(', ') || '—'}`}
            </p>
          )}
        </div>
      )}
      {changes.length > 0 && (
        <div>
          <p className="text-text-primary">{t('approvals.publish.assignments', { count: changes.length }) || `${changes.length} change(s) of assignments`}</p>
          <ul className="mt-0.5 max-h-32 overflow-auto font-mono text-text-secondary">
            {changes.slice(0, 100).map((c, i) => (
              <li key={i}>
                {trCode(`approvals.publish.op.${c.op}`, String(c.op ?? ''))}
                {c.op === 'create' || c.resourceId !== undefined ? <> · <Link to={`/policies/${c.resourceId}`} className="text-accent hover:underline">{c.resourceType ?? 'policy'} #{c.resourceId}</Link></> : null}
                {c.targetScope ? ` → ${target(c)}` : c.id !== undefined ? ` · ${t('approvals.publish.assignment') || 'assignment'} #${c.id}` : ''}
                {c.mode ? ` · ${c.mode}` : ''}{c.priority !== undefined ? ` · P${c.priority}` : ''}
              </li>
            ))}
          </ul>
          {changes.length > 100 && (
            <p className="mt-0.5 text-text-muted">{t('approvals.publish.moreChanges', { count: changes.length - 100, defaultValue: '+{{count}} more changes' })}</p>
          )}
          {Array.isArray(p.base) && p.base.length > 0 && (
            <p className="mt-0.5 text-text-muted">
              {t('approvals.publish.base') || 'Versions the request was filed with'}: {p.base.map((b) => `#${b.policyId} v${b.version}`).join(', ')}
            </p>
          )}
        </div>
      )}

      {/* 2. The counters of the preview the request was filed with */}
      <div className="flex flex-wrap gap-1.5">
        <Counter label={t('mdm.impact.devicesTouched') || 'Devices touched'} value={num(impact.devicesTouched)} />
        <Counter label={t('mdm.impact.devicesInScope') || 'Devices in scope'} value={num(impact.devicesInScope)} />
        <Counter label={t('mdm.impact.devicesAdded') || 'Start receiving it'} value={num(impact.devicesAdded)} />
        <Counter label={t('mdm.impact.devicesRemoved') || 'Stop receiving it'} value={num(impact.devicesRemoved)} tone="text-amber-400" />
        <Counter label={t('mdm.impact.installs') || 'Installations'} value={num(impact.artifacts?.installs)} />
        <Counter label={t('mdm.impact.removals') || 'Removals'} value={num(impact.artifacts?.removals) + num(impact.artifacts?.appRemovals)} tone="text-red-400" />
        <Counter label={t('mdm.impact.kioskLockChanges') || 'Kiosk lock changes'} value={num(impact.artifacts?.kioskLockChanges)} tone="text-red-400" />
        <Counter label={t('mdm.impact.fleetSize') || 'Enrolled fleet'} value={num(impact.fleetSize)} />
        {num(impact.conflicts) > 0 && <Counter label={t('approvals.publish.conflicts') || 'Conflicts'} value={num(impact.conflicts)} tone="text-red-400" />}
      </div>
      {reasons.length > 0 && (
        <p className="text-text-secondary">
          {t('approvals.publish.why') || 'A second approver is required because'}: {reasons.map((r) => approvalReasonLabel(t, r as ImpactApprovalReason)).join('; ')}
        </p>
      )}
      <p className="text-text-muted">{t('approvals.publish.recheck') || 'At the approval, the preview is computed again: the request is refused if its content or its reach changed.'}</p>

      {/* 3. The keys, last: however many, they never push the rest out */}
      {keys.length > 0 && (
        <details>
          <summary className="cursor-pointer text-accent hover:underline coarse:min-h-9">
            {t('approvals.publish.keys', { count: num(impact.keysTotal) || keys.length }) || `${num(impact.keysTotal) || keys.length} setting(s) touched`}
          </summary>
          <div className="mt-1 max-h-48 overflow-auto">
            <table className="w-full font-mono">
              <thead className="text-text-muted">
                <tr>
                  <th className="text-left font-normal">{t('mdm.impact.key') || 'Setting'}</th>
                  <th className="text-right font-normal px-1">+</th>
                  <th className="text-right font-normal px-1">~</th>
                  <th className="text-right font-normal px-1">−</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.settingKey}>
                    <td className="break-all text-text-primary">{settingKeyLabel(String(k.settingKey))}</td>
                    <td className="text-right px-1 tabular-nums">{num(k.added) || ''}</td>
                    <td className="text-right px-1 tabular-nums">{num(k.changed) || ''}</td>
                    <td className={`text-right px-1 tabular-nums ${num(k.removed) ? 'text-red-400' : ''}`}>{num(k.removed) || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {num(impact.keysTotal) > keys.length && (
              <p className="mt-1 text-text-muted">{t('approvals.moreRows', { count: num(impact.keysTotal) - keys.length, defaultValue: '+{{count}} more fields' })}</p>
            )}
          </div>
        </details>
      )}
    </div>
  );
}
