import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Package, Pencil, Plus, Trash2 } from 'lucide-react';
import type {
  AgentRequiredApp, AgentRequiredAppMode, LegacyAgentRequiredAppPackageView, LegacyAgentRequiredAppsTenantView, PolicyValidationIssue,
} from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS as L } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage } from '@/utils/apiError';
import { ChipChoice, IssueList, fieldCls, humanSize, issuesUnder } from './ui';

// The required apps of the bridge policy (agent:requiredApp[<package>]): server-side only, never sent to the agent. Each
// entry names a package of the tenant's APK store (legacy_agent_packages, confirmed, F028) and a mode; the job
// legacy-agent.required-apps queues app.install where the app is missing (or older, mode minVersion), at most 50 per
// tenant every 10 minutes, and never uninstalls anything. No write here: the list is saved with the draft of the policy.

const versionOf = (p: { versionName: string | null; versionCode: string }): string => `v${p.versionName ?? p.versionCode}`;
const codeNum = (s: string): number => { const n = Number(s); return Number.isFinite(n) ? n : 0; };

export function RequiredAppsPanel({ items, editable, issues, onChange }: {
  items: AgentRequiredApp[]; editable: boolean; issues: PolicyValidationIssue[]; onChange: (next: AgentRequiredApp[]) => void;
}) {
  const { t } = useTranslation();
  // null: not loaded (or not readable by this member: mdm.policies.manage); never taken for « no package ».
  const [packages, setPackages] = useState<LegacyAgentRequiredAppPackageView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tenant, setTenant] = useState<LegacyAgentRequiredAppsTenantView | null>(null);
  // null: closed; index null: add an app; index n: change the version of entry n.
  const [picking, setPicking] = useState<{ index: number | null } | null>(null);
  useEffect(() => {
    let live = true;
    legacyAgentApi.requiredAppPackages().then((p) => { if (live) { setPackages(p); setError(null); } })
      .catch((err) => { if (live) { setPackages(null); setError(apiErrorMessage(err)); } });
    legacyAgentApi.requiredAppsTenant().then((v) => { if (live) setTenant(v); }).catch(() => { /* the banner only */ });
    return () => { live = false; };
  }, []);
  const byId = useMemo(() => new Map((packages ?? []).map((p) => [p.id.toLowerCase(), p])), [packages]);
  const modeOptions = [
    { id: 'install' as const, label: t('legacyAgentPolicy.requiredApps.modes.install') || 'Install if missing' },
    { id: 'minVersion' as const, label: t('legacyAgentPolicy.requiredApps.modes.minVersion') || 'Install or update to this version' },
  ];
  const modeLabel = (m: AgentRequiredAppMode) => modeOptions.find((o) => o.id === m)?.label ?? m;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <p className="text-xs text-text-muted">
          {t('legacyAgentPolicy.requiredApps.intro') || 'The server installs these apps on the devices of the policy where they are missing (app.install), from a recent inventory, at most 50 per tenant every 10 minutes and 50 in progress at once; a package whose installs fail is stopped. Nothing is ever uninstalled. Silent with Knox, otherwise Android asks the user.'}
        </p>
        {editable && items.length < L.requiredApps && (
          <Button size="sm" variant="secondary" className="ml-auto shrink-0" onClick={() => setPicking({ index: null })}>
            <Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.requiredApps.add') || 'Add a required app'}
          </Button>
        )}
      </div>
      {editable && error && <p className="text-xs text-red-400">{error}</p>}
      {tenant?.appsLimited && (
        <p role="status" className="rounded-lg bg-amber-400/10 px-3 py-2 text-xs text-amber-400">
          {t('legacyAgentPolicy.requiredApps.tenant.appsLimited') || 'The privacy profile of this tenant limits the apps inventory to the managed apps: an absent app proves nothing, so nothing is installed while it is set to « managed apps only ».'}
        </p>
      )}
      {tenant && tenant.restriction.level !== 'none' && (
        <p role="status" className="rounded-lg bg-amber-400/10 px-3 py-2 text-xs text-amber-400">
          {tenant.restriction.scope === 'all'
            ? (t('legacyAgentPolicy.requiredApps.tenant.restrictedAll') || 'The restrictions matrix of this tenant asks for a person on legacy_agent.apps: no required app is installed automatically.')
            : (t('legacyAgentPolicy.requiredApps.tenant.restrictedPartial') || 'The restrictions matrix of this tenant asks for a person on legacy_agent.apps for some devices or groups: the required apps are not installed automatically on them.')}
        </p>
      )}
      <IssueList issues={issues.filter((i) => i.path === 'requiredApps')} />
      {items.length === 0 ? <p className="text-sm text-text-muted">{t('legacyAgentPolicy.requiredApps.none') || 'No required app.'}</p> : (
        <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
          {items.map((a, i) => {
            const p = byId.get(a.packageId.toLowerCase());
            return (
              <li key={`${a.packageName}-${i}`} className="px-3 py-2 text-sm hover:bg-bg-tertiary">
                <div className="flex flex-wrap items-center gap-2">
                  <Package className="h-4 w-4 text-text-muted" />
                  <span className="text-text-primary">{p?.label ?? a.packageName}</span>
                  <span className="font-mono text-[11px] text-text-muted">{a.packageName}</span>
                  {p && <span className="rounded-full bg-accent/10 px-2 py-0.5 text-[11px] text-accent">{versionOf(p)}</span>}
                  {packages && !p && (
                    <span className="rounded-full bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-400">{t('legacyAgentPolicy.requiredApps.packageMissing') || 'Package not found'}</span>
                  )}
                  {p && !p.confirmed && (
                    <span className="rounded-full bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-400">{t('legacyAgentPolicy.requiredApps.toConfirm') || 'To confirm'}</span>
                  )}
                  <span className="ml-auto flex flex-wrap items-center gap-1">
                    {editable
                      ? <ChipChoice value={a.mode} options={modeOptions} onChange={(mode) => onChange(items.map((x, j) => (j === i ? { ...x, mode } : x)))} />
                      : <span className="text-xs text-text-secondary">{modeLabel(a.mode)}</span>}
                    {editable && (
                      <>
                        <button type="button" className="rounded p-1.5 text-text-muted hover:text-text-primary" aria-label={t('common.edit') || 'Edit'}
                          title={t('legacyAgentPolicy.requiredApps.changeVersion') || 'Change the version'} onClick={() => setPicking({ index: i })}><Pencil className="h-4 w-4" /></button>
                        <button type="button" className="rounded p-1.5 text-text-muted hover:text-red-400" aria-label={t('common.delete') || 'Delete'}
                          onClick={() => onChange(items.filter((_, j) => j !== i))}><Trash2 className="h-4 w-4" /></button>
                      </>
                    )}
                  </span>
                </div>
                <IssueList issues={issuesUnder(issues, `requiredApps[${i}]`)} />
              </li>
            );
          })}
        </ul>
      )}
      <PackagePicker open={picking !== null} packages={packages ?? []} modeOptions={modeOptions}
        current={picking?.index != null ? items[picking.index] ?? null : null}
        required={items.map((x) => x.packageName.toLowerCase())}
        onClose={() => setPicking(null)}
        onPick={(entry) => {
          onChange(picking?.index != null ? items.map((x, j) => (j === picking.index ? entry : x)) : [...items, entry]);
          setPicking(null);
        }} />
    </div>
  );
}

function PackagePicker({ open, packages, modeOptions, current, required, onClose, onPick }: {
  open: boolean; packages: LegacyAgentRequiredAppPackageView[]; modeOptions: ReadonlyArray<{ id: AgentRequiredAppMode; label: string }>;
  /** The entry whose version is changed (the list is then filtered on its package), or null to add an app. */
  current: AgentRequiredApp | null; required: string[];
  onClose: () => void; onPick: (entry: AgentRequiredApp) => void;
}) {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [mode, setMode] = useState<AgentRequiredAppMode>('install');
  useEffect(() => { if (open) { setQuery(''); setMode(current?.mode ?? 'install'); } }, [open, current]);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return packages
      .filter((p) => !current || p.packageName.toLowerCase() === current.packageName.toLowerCase())
      .filter((p) => !q || p.packageName.toLowerCase().includes(q) || (p.label ?? '').toLowerCase().includes(q))
      .sort((a, b) => a.packageName.localeCompare(b.packageName) || codeNum(b.versionCode) - codeNum(a.versionCode));
  }, [packages, query, current]);

  return (
    <Modal open={open} onClose={onClose} size="lg"
      title={current ? (t('legacyAgentPolicy.requiredApps.changeVersion') || 'Change the version') : (t('legacyAgentPolicy.requiredApps.pickTitle') || 'Choose a package')}
      footer={<Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>}>
      <div className="space-y-3">
        <input className={fieldCls} value={query} placeholder={t('legacyAgentPolicy.requiredApps.search') || 'Search by name or package'} onChange={(e) => setQuery(e.target.value)} />
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-text-muted">{t('legacyAgentPolicy.requiredApps.mode') || 'Mode'}</span>
          <ChipChoice value={mode} options={modeOptions} onChange={setMode} />
        </div>
        {shown.length === 0
          ? <p className="text-sm text-text-muted">{t('legacyAgentPolicy.requiredApps.noPackage') || 'No package in this tenant: upload or harvest one on the Android agent page.'}</p>
          : (
            <ul className="max-h-96 divide-y divide-border/50 overflow-y-auto rounded-xl bg-bg-secondary">
              {shown.map((p) => {
                const already = !current && required.includes(p.packageName.toLowerCase());
                const disabled = !p.confirmed || already;
                return (
                  <li key={p.id}>
                    <button type="button" disabled={disabled}
                      onClick={() => onPick({ packageName: p.packageName, packageId: p.id.toLowerCase(), mode })}
                      className={`flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left text-sm ${disabled ? 'cursor-not-allowed opacity-50' : 'hover:bg-bg-tertiary'}`}>
                      <Package className="h-4 w-4 text-text-muted" />
                      <span className="text-text-primary">{p.label ?? p.packageName}</span>
                      <span className="font-mono text-[11px] text-text-muted">{p.packageName}</span>
                      <span className="rounded-full bg-accent/10 px-2 py-0.5 text-[11px] text-accent">{versionOf(p)}</span>
                      {!p.confirmed && (
                        <span className="rounded-full bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-400">{t('legacyAgentPolicy.requiredApps.toConfirm') || 'To confirm'}</span>
                      )}
                      {already && (
                        <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-muted">{t('legacyAgentPolicy.requiredApps.alreadyRequired') || 'Already required'}</span>
                      )}
                      {current && current.packageId.toLowerCase() === p.id.toLowerCase() && (
                        <span className="rounded-full bg-green-400/10 px-2 py-0.5 text-[11px] text-green-400">✓</span>
                      )}
                      <span className="ml-auto text-[11px] text-text-muted">{humanSize(p.sizeBytes)} ·{formatDateTime(p.createdAt)}</span>
                      {!p.confirmed && (
                        <span className="w-full text-[11px] text-text-muted">{t('legacyAgentPolicy.requiredApps.toConfirmHint') || 'Confirm it on the Packages page of the Android agent first'}</span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
      </div>
    </Modal>
  );
}
