import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import toast from 'react-hot-toast';
import { Building2, FolderOpen, Minus, Plus, Smartphone, Trash2 } from 'lucide-react';
import type { AppleAppOptions, Assignment, AssignmentChange, AssignmentMode, AssignmentTargetScope, DeviceSummary, JsonValue, Policy, SubmitOutcome } from '@obligarth/shared';
import { APPLE_APP_OPTION_DEFAULTS, ASSIGNMENT_PRIORITY } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { isStepUpHandled } from '@/api/client';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { GroupTreePicker } from '@/components/devices/GroupTreePicker';
import { ImpactConfirmDialog } from '@/components/mdm/ImpactPreview';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';

// Assignments of the policies (modele-donnees-mdm §7.5): a policy applies to the whole tenant, to a group (and its
// subgroups) or to a device, as an inclusion or an exclusion, with a priority that breaks ties (smaller is
// stronger). Every change goes through the impact preview, then the second factor or a second approver.
// An app (lot C4, modele §8.2) is assigned the same way, with its options (removable, removed with the management,
// no backup, takeover of an app the user installed, managed configuration without secret).

export type AssignableResource = { id: number; tenantId: number; name: string; type?: 'policy' | 'app' };

/** The options of an app assignment (AppleAppOptions), edited in place. */
export function AppOptionsFields({ value, onChange, configText, onConfigText }: {
  value: AppleAppOptions; onChange: (v: AppleAppOptions) => void; configText: string; onConfigText: (s: string) => void;
}) {
  const { t } = useTranslation();
  const box = (key: 'removable' | 'removeOnUnenroll' | 'preventBackup' | 'takeOver', label: string, hint: string) => (
    <label className="flex items-start gap-2">
      <input type="checkbox" className="mt-1" checked={value[key]} onChange={(e) => onChange({ ...value, [key]: e.target.checked })} />
      <span><span className="text-text-primary">{label}</span><span className="block text-[11px] text-text-muted">{hint}</span></span>
    </label>
  );
  return (
    <div className="space-y-2 rounded border border-border p-2">
      <p className="text-xs font-semibold text-text-secondary">{t('apps.options.title') || 'Options of the app'}</p>
      {box('removable', t('apps.options.removable') || 'The user may delete the app', t('apps.options.removableHint') || 'Always allowed on a personal device.')}
      {box('removeOnUnenroll', t('apps.options.removeOnUnenroll') || 'Removed with the management', t('apps.options.removeOnUnenrollHint') || 'The app leaves the device when it leaves management.')}
      {box('preventBackup', t('apps.options.preventBackup') || 'No backup of its data', t('apps.options.preventBackupHint') || 'The data of the app are not saved in the backups of the device.')}
      {box('takeOver', t('apps.options.takeOver') || 'Take over the app if the user installed it', t('apps.options.takeOverHint') || 'Never on a personal device enrolled with User Enrollment.')}
      <label className="block">
        <span className="text-xs text-text-muted">{t('apps.options.config') || 'Managed configuration (JSON, optional, no secret)'}</span>
        <textarea value={configText} onChange={(e) => onConfigText(e.target.value)} spellCheck={false}
          className="mt-1 w-full h-24 rounded border border-border bg-bg-secondary px-2 py-1.5 font-mono text-xs text-text-primary" placeholder='{"ServerURL": "https://example.net"}' />
      </label>
    </div>
  );
}

/** The managed configuration typed as JSON: an object, or nothing; undefined when it is not valid JSON. */
export function parseAppConfig(text: string): Record<string, JsonValue> | null | undefined {
  if (!text.trim()) return null;
  try {
    const v = JSON.parse(text) as unknown;
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, JsonValue> : undefined;
  } catch { return undefined; }
}

/** Tells the user what a guarded write of the configuration did. */
export function announceSubmitOutcome(t: TFunction, outcome: SubmitOutcome): void {
  if (outcome.outcome === 'awaiting_approval') {
    toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
  } else if (outcome.outcome === 'published') {
    toast.success(t('mdm.outcome.published') || 'Published');
  } else if (outcome.outcome === 'applied') {
    toast.success(t('mdm.outcome.applied') || 'Applied');
  }
}

export interface AssignmentTarget { scope: AssignmentTargetScope; id: number | null; name?: string | null }

const scopeIcon = (scope: AssignmentTargetScope) => (scope === 'tenant' ? <Building2 className="w-3.5 h-3.5" />
  : scope === 'group' ? <FolderOpen className="w-3.5 h-3.5" /> : <Smartphone className="w-3.5 h-3.5" />);

export function targetLabel(t: TFunction, a: Pick<Assignment, 'targetScope' | 'targetId' | 'targetName'>): string {
  if (a.targetScope === 'tenant') return t('mdm.assignments.wholeTenant') || 'Whole tenant';
  return anonymize(a.targetName) || `#${a.targetId}`;
}

/** A device of the tenant, found by typing (label, name, serial number, model, end user). */
function DevicePicker({ value, onChange }: { value: DeviceSummary | null; onChange: (d: DeviceSummary | null) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [results, setResults] = useState<DeviceSummary[]>([]);
  useEffect(() => {
    if (value || q.trim().length < 2) { setResults([]); return; }
    let cancelled = false;
    const timer = setTimeout(() => {
      mdmApi.listDevices({ q: q.trim(), pageSize: 12, sortBy: 'name' })
        .then((r) => { if (!cancelled) setResults(r.items); })
        .catch(() => { if (!cancelled) setResults([]); });
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [q, value]);
  if (value) {
    return (
      <div className="flex items-center gap-2 rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm">
        <Smartphone className="w-3.5 h-3.5 text-text-muted" />
        <span className="flex-1 truncate text-text-primary">{anonymize(value.label)}</span>
        <button type="button" onClick={() => onChange(null)} className="text-xs text-accent hover:underline coarse:min-h-9">{t('common.edit') || 'Edit'}</button>
      </div>
    );
  }
  return (
    <div>
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder={t('mdm.assignments.searchDevice') || 'Search a device…'}
        autoCapitalize="off"
        spellCheck={false}
        className="w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary"
      />
      {results.length > 0 && (
        <ul className="mt-1 max-h-40 overflow-auto rounded border border-border bg-bg-secondary text-sm">
          {results.map((d) => (
            <li key={d.id}>
              <button type="button" onClick={() => onChange(d)} className="w-full text-left px-2 py-1.5 hover:bg-bg-tertiary coarse:py-2.5">
                {anonymize(d.label)}
                {d.groupName && <span className="ml-2 text-xs text-text-muted">{anonymize(d.groupName)}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Composes assignments (one policy on one or several targets), previews them, then applies them.
 * `resource` fixed: the user picks the target; `targets` fixed: the user picks the policy.
 */
export function AssignmentCreateDialog({ open, onClose, resource, targets, onDone }: {
  open: boolean;
  onClose: () => void;
  resource?: AssignableResource;
  targets?: AssignmentTarget[];
  onDone?: (outcome: SubmitOutcome) => void;
}) {
  const { t } = useTranslation();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policyId, setPolicyId] = useState<number | ''>('');
  const [scope, setScope] = useState<AssignmentTargetScope>('group');
  const [groupId, setGroupId] = useState<number | null>(null);
  const [device, setDevice] = useState<DeviceSummary | null>(null);
  const [mode, setMode] = useState<AssignmentMode>('include');
  const [priority, setPriority] = useState<number>(ASSIGNMENT_PRIORITY.default);
  const [previewing, setPreviewing] = useState(false);
  const [appOptions, setAppOptions] = useState<AppleAppOptions>({ ...APPLE_APP_OPTION_DEFAULTS });
  const [configText, setConfigText] = useState('');
  const isApp = resource?.type === 'app';

  useEffect(() => {
    if (!open) return;
    setPolicyId(''); setScope('group'); setGroupId(null); setDevice(null); setMode('include');
    setPriority(ASSIGNMENT_PRIORITY.default); setPreviewing(false); setAppOptions({ ...APPLE_APP_OPTION_DEFAULTS }); setConfigText('');
    if (!resource) mdmApi.listPolicies({ state: 'published' }).then(setPolicies).catch(() => setPolicies([]));
  }, [open, resource]);

  const chosen = resource ?? (() => {
    const p = policies.find((x) => x.id === policyId);
    return p ? { id: p.id, tenantId: p.tenantId, name: p.name } : undefined;
  })();
  const chosenTargets: AssignmentTarget[] = useMemo(() => {
    if (targets) return targets;
    if (scope === 'tenant') return [{ scope, id: null }];
    if (scope === 'group') return groupId ? [{ scope, id: groupId }] : [];
    return device ? [{ scope, id: device.id, name: device.label }] : [];
  }, [targets, scope, groupId, device]);
  const config = isApp ? parseAppConfig(configText) : null;
  // An exclusion of the whole tenant is refused by the model (assignments_no_tenant_exclude).
  const invalid = !chosen || chosenTargets.length === 0 || (mode === 'exclude' && chosenTargets.some((x) => x.scope === 'tenant'))
    || !Number.isInteger(priority) || priority < ASSIGNMENT_PRIORITY.min || priority > ASSIGNMENT_PRIORITY.max
    || (isApp && mode === 'include' && config === undefined);
  const options = isApp && mode === 'include' ? { ...appOptions, ...(config ? { config } : {}) } as unknown as Record<string, JsonValue> : undefined;
  const changes: AssignmentChange[] = chosen ? chosenTargets.map((x) => ({
    op: 'create', resourceType: isApp ? 'app' : 'policy', resourceId: chosen.id, resourceTenantId: chosen.tenantId,
    targetScope: x.scope, targetId: x.id, mode, priority, ...(options ? { options } : {}),
  })) : [];

  const field = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
  return (
    <>
      <Modal
        open={open && !previewing}
        onClose={onClose}
        size="md"
        title={isApp ? (t('apps.assignTitle') || 'Assign an app') : (t('mdm.assignments.addTitle') || 'Assign a policy')}
        footer={(
          <>
            <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
            <Button onClick={() => setPreviewing(true)} disabled={invalid}>{t('mdm.assignments.preview') || 'Preview the impact'}</Button>
          </>
        )}
      >
        <div className="space-y-3 text-sm">
          {resource ? (
            <p className="text-text-secondary">{isApp ? (t('apps.app') || 'App') : (t('mdm.assignments.policy') || 'Policy')}: <span className="font-medium text-text-primary">{resource.name}</span></p>
          ) : (
            <label className="block">
              <span className="text-xs text-text-muted">{t('mdm.assignments.policy') || 'Policy'}</span>
              <select value={policyId} onChange={(e) => setPolicyId(e.target.value ? Number(e.target.value) : '')} className={field}>
                <option value="">{t('mdm.assignments.pickPolicy') || 'Pick a published policy…'}</option>
                {policies.map((p) => <option key={`${p.tenantId}-${p.id}`} value={p.id}>{p.name}{p.currentVersion ? ` (v${p.currentVersion})` : ''}</option>)}
              </select>
              {policies.length === 0 && <span className="mt-1 block text-xs text-text-muted">{t('mdm.assignments.noPublishedPolicy') || 'No published policy yet.'}</span>}
            </label>
          )}

          {targets ? (
            <p className="text-text-secondary">
              {t('mdm.assignments.targetsCount', { count: targets.length }) || `${targets.length} target(s)`}
              {targets.length <= 3 && targets.some((x) => x.name) && <span className="text-text-primary">: {targets.map((x) => anonymize(x.name) || `#${x.id}`).join(', ')}</span>}
            </p>
          ) : (
            <>
              <div>
                <span className="text-xs text-text-muted">{t('mdm.assignments.target') || 'Target'}</span>
                <div className="mt-1 flex gap-1.5">
                  {(['tenant', 'group', 'device'] as const).map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setScope(s)}
                      className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg coarse:min-h-10 ${scope === s ? 'bg-accent text-white' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'}`}
                    >
                      {scopeIcon(s)}
                      {t(`mdm.assignments.scope.${s}`) || s}
                    </button>
                  ))}
                </div>
              </div>
              {scope === 'group' && <GroupTreePicker value={groupId} onChange={(id) => setGroupId(id)} />}
              {scope === 'device' && <DevicePicker value={device} onChange={setDevice} />}
            </>
          )}

          <div className="flex gap-3">
            <label className="block flex-1">
              <span className="text-xs text-text-muted">{t('mdm.assignments.mode') || 'Mode'}</span>
              <select value={mode} onChange={(e) => setMode(e.target.value as AssignmentMode)} className={field}>
                <option value="include">{t('mdm.assignments.include') || 'Include'}</option>
                <option value="exclude">{t('mdm.assignments.exclude') || 'Exclude'}</option>
              </select>
            </label>
            <label className="block w-32">
              <span className="text-xs text-text-muted">{t('mdm.assignments.priority') || 'Priority'}</span>
              <input type="number" min={ASSIGNMENT_PRIORITY.min} max={ASSIGNMENT_PRIORITY.max} value={priority}
                onChange={(e) => setPriority(Number(e.target.value))} className={field} />
            </label>
          </div>
          <p className="text-[11px] text-text-muted">{t('mdm.assignments.priorityHint') || 'Priority: 0 to 1000, smaller is stronger; it only breaks ties between policies assigned at the same level.'}</p>
          {isApp && mode === 'include' && (
            <>
              <AppOptionsFields value={appOptions} onChange={setAppOptions} configText={configText} onConfigText={setConfigText} />
              {config === undefined && <p className="text-xs text-red-400">{t('apps.options.configInvalid') || 'The managed configuration must be a JSON object.'}</p>}
            </>
          )}
          {mode === 'exclude' && chosenTargets.some((x) => x.scope === 'tenant') && (
            <p className="text-xs text-red-400">{t('mdm.assignments.noTenantExclude') || 'A policy cannot be excluded from the whole tenant: remove its assignment instead.'}</p>
          )}
        </div>
      </Modal>
      <ImpactConfirmDialog
        open={open && previewing}
        onClose={() => setPreviewing(false)}
        title={t('mdm.assignments.previewTitle') || 'Impact of the assignment'}
        load={() => mdmApi.previewAssignments(changes)}
        apply={async () => {
          try {
            const outcome = await mdmApi.changeAssignments(changes);
            announceSubmitOutcome(t, outcome);
            onDone?.(outcome);
            onClose();
          } catch (err) {
            if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
            throw err;
          }
        }}
      />
    </>
  );
}

/** The assignments of a policy (`resource`) or those that target a group or a device (`target`). */
export function AssignmentsPanel({ resource, target, canManage, onChanged }: {
  resource?: AssignableResource & { published: boolean };
  target?: AssignmentTarget;
  canManage: boolean;
  onChanged?: () => void;
}) {
  const { t } = useTranslation();
  const [items, setItems] = useState<Assignment[] | null>(null);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Assignment | null>(null);

  const load = useCallback(() => {
    const params = resource
      ? { resourceType: (resource.type ?? 'policy') as 'policy' | 'app', resourceId: resource.id }
      : target && target.scope !== 'tenant' && target.id !== null
        ? { targetScope: target.scope, targetId: target.id }
        : { targetScope: 'tenant' as const };
    mdmApi.listAssignments(params).then((list) => {
      setItems(target?.scope === 'tenant' ? list.filter((a) => a.targetScope === 'tenant') : list);
    }).catch(() => setItems([]));
  }, [resource, target]);
  useEffect(() => { load(); }, [load]);

  const removal: AssignmentChange[] = removing ? [{ op: 'delete', id: removing.id }] : [];
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-text-primary">{t('mdm.assignments.title') || 'Assignments'}</h3>
        {canManage && (!resource || resource.published) && (
          <Button size="sm" variant="secondary" onClick={() => setAdding(true)}>
            <Plus className="w-3.5 h-3.5 mr-1" />{t('mdm.assignments.add') || 'Assign'}
          </Button>
        )}
      </div>
      {resource && !resource.published && resource.type !== 'app' && (
        <p className="text-xs text-text-muted">{t('mdm.assignments.publishFirst') || 'A policy is assigned once it has a published version.'}</p>
      )}
      {items === null ? (
        <p className="text-xs text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
      ) : items.length === 0 ? (
        <p className="text-xs text-text-muted">{t('mdm.assignments.none') || 'No assignment.'}</p>
      ) : (
        <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
          {items.map((a) => (
            <li key={a.id} className="flex items-center gap-2 px-3 py-2 text-sm">
              {resource ? (
                <span className="flex min-w-0 flex-1 items-center gap-1.5 text-text-primary">
                  <span className="text-text-muted">{scopeIcon(a.targetScope)}</span>
                  {a.targetScope === 'group' && a.targetId ? (
                    <Link to={`/group/${a.targetId}`} className="truncate hover:text-accent">{targetLabel(t, a)}</Link>
                  ) : a.targetScope === 'device' && a.targetId ? (
                    <Link to={`/devices/${a.targetId}`} className="truncate hover:text-accent">{targetLabel(t, a)}</Link>
                  ) : <span className="truncate">{targetLabel(t, a)}</span>}
                </span>
              ) : (
                <Link to={a.resourceType === 'app' ? `/apps?app=${a.resourceId}` : `/policies/${a.resourceId}`} className="min-w-0 flex-1 truncate text-text-primary hover:text-accent">
                  {a.resourceType === 'app' && <span className="mr-1 text-[10px] uppercase px-1 py-0.5 rounded bg-blue-400/10 text-blue-400">{t('apps.app') || 'App'}</span>}
                  {a.resourceName || `#${a.resourceId}`}
                </Link>
              )}
              <span className={`shrink-0 inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded ${a.mode === 'exclude' ? 'bg-red-400/10 text-red-400' : 'bg-green-400/10 text-green-400'}`}>
                {a.mode === 'exclude' ? <Minus className="w-3 h-3" /> : <Plus className="w-3 h-3" />}
                {a.mode === 'exclude' ? (t('mdm.assignments.exclude') || 'Exclude') : (t('mdm.assignments.include') || 'Include')}
              </span>
              <span className="shrink-0 text-[11px] text-text-muted tabular-nums" title={t('mdm.assignments.priority') || 'Priority'}>P{a.priority}</span>
              {canManage && (
                <button
                  type="button"
                  onClick={() => setRemoving(a)}
                  aria-label={t('mdm.assignments.remove') || 'Remove the assignment'}
                  title={t('mdm.assignments.remove') || 'Remove the assignment'}
                  className="shrink-0 p-1 rounded text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      <AssignmentCreateDialog
        open={adding}
        onClose={() => setAdding(false)}
        resource={resource ? { id: resource.id, tenantId: resource.tenantId, name: resource.name, type: resource.type } : undefined}
        targets={target ? [target] : undefined}
        onDone={() => { load(); onChanged?.(); }}
      />
      <ImpactConfirmDialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        danger
        title={t('mdm.assignments.removeTitle') || 'Remove the assignment'}
        intro={removing ? `${removing.resourceName ?? `#${removing.resourceId}`} → ${targetLabel(t, removing)}` : undefined}
        confirmLabel={t('mdm.assignments.remove') || 'Remove the assignment'}
        load={() => mdmApi.previewAssignments(removal)}
        apply={async () => {
          try {
            const outcome = await mdmApi.changeAssignments(removal);
            announceSubmitOutcome(t, outcome);
            load();
            onChanged?.();
          } catch (err) {
            if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
            throw err;
          }
        }}
      />
    </div>
  );
}
