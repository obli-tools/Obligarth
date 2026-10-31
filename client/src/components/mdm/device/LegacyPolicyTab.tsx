import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, PauseCircle, RefreshCw, RotateCcw } from 'lucide-react';
import type { AgentPolicyItemState, LegacyAgentDeviceAction, LegacyAgentPolicyStatusView } from '@obligarth/shared';
import { AGENT_POLICY_ITEM_STATES, isAgentPolicyWarning } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { useLegacyActionRunner } from '@/components/mdm/actions/useLegacyActionRunner';
import { ITEM_STATE_TONE, agentKeyLabel, codeLabel, itemStateLabel } from '@/components/legacyAgentPolicy/ui';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The "Agent policy" tab of a device of the bridge agent (lot PONT-POL §11.3): the version of its agent (a policy needs
// 1.3.0), the desired and delivered hashes, the state of its artifact agent:policy and why, the agent's last report
// item by item (filterable by state), what the compilation dropped and what the freeze held back even before the agent
// reports, and the two actions of the policy (re-apply, suspend the kiosk) greyed by the menu of the device.

const ARTIFACT_TONE: Record<string, 'green' | 'gray' | 'blue' | 'amber' | 'red' | 'violet'> = {
  applied: 'green', delivering: 'blue', pending: 'blue', error: 'red', removing: 'amber', removed: 'gray',
};
const short = (h: string | null | undefined): string => (h ? h.slice(0, 12) : '—');
// A warning item (a network added by the user) is shown and filtered apart from its state.
type Shown = AgentPolicyItemState | 'warning';
const shown = (i: { state: AgentPolicyItemState; code: string }): Shown => (isAgentPolicyWarning(i) ? 'warning' : i.state);

export function LegacyPolicyTab({ deviceId, canAct }: { deviceId: number; canAct: boolean }) {
  const { t } = useTranslation();
  const [view, setView] = useState<LegacyAgentPolicyStatusView | null>(null);
  const [actions, setActions] = useState<LegacyAgentDeviceAction[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Shown | 'all'>('all');
  const load = useCallback(() => {
    legacyAgentApi.devicePolicy(deviceId).then((v) => { setView(v); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
    legacyAgentApi.actions(deviceId).then(setActions).catch(() => setActions([]));
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  const runner = useLegacyActionRunner({ deviceId, onQueued: load });
  const items = useMemo(() => (view?.report?.items ?? []).filter((i) => filter === 'all' || shown(i) === filter), [view, filter]);
  const act = (type: 'policy.reapply' | 'kiosk.suspend') => actions.find((a) => a.type === type);

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!view) return <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>;
  const r = view.report;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {!view.supported && (
          <span className="inline-flex items-center gap-1 rounded-full bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-400">
            <AlertTriangle className="h-3.5 w-3.5" />{t('legacyAgentPolicy.device.tooOld') || 'Agent older than 1.3.0: policies are ignored until it is updated'}
          </span>
        )}
        <span className="ml-auto flex flex-wrap gap-2">
          {(['policy.reapply', 'kiosk.suspend'] as const).map((type) => {
            const a = act(type);
            if (!a) return null;
            return (
              <Button key={type} size="sm" variant="secondary" disabled={!canAct || !a.available || runner.busy === type} title={a.unavailable ? trCode(`legacyAgent.unavailable.${a.unavailable}`, a.unavailable) : undefined}
                onClick={() => runner.run(a)}>
                {type === 'policy.reapply' ? <RotateCcw className="mr-1 h-3.5 w-3.5" /> : <PauseCircle className="mr-1 h-3.5 w-3.5" />}
                {type === 'policy.reapply' ? (t('legacyAgentPolicy.actions.reapply') || 'Re-apply the policy') : (t('legacyAgentPolicy.actions.suspendKiosk') || 'Suspend the kiosk')}
              </Button>
            );
          })}
          <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'} className="rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary">
            <RefreshCw className="h-4 w-4" />
          </button>
        </span>
      </div>

      <dl className="grid gap-3 rounded-xl bg-bg-secondary p-3 text-sm sm:grid-cols-3">
        <Fact label={t('legacyAgentPolicy.device.agent') || 'Agent'}>{`${Math.floor(view.agentVersionCode / 10000)}.${Math.floor(view.agentVersionCode / 100) % 100}.${view.agentVersionCode % 100}`}</Fact>
        <Fact label={t('legacyAgentPolicy.device.desired') || 'Desired policy'}><span className="font-mono">{short(view.desiredHash)}</span></Fact>
        <Fact label={t('legacyAgentPolicy.device.delivered') || 'Delivered'}><span className="font-mono">{short(view.deliveredHash)}</span></Fact>
        <Fact label={t('legacyAgentPolicy.device.state') || 'State'}>
          {view.artifactState ? <StateBadge tone={ARTIFACT_TONE[view.artifactState] ?? 'gray'} label={trCode(`legacyAgentPolicy.artifactStates.${view.artifactState}`, view.artifactState)} />
            : <span className="text-text-muted">{t('legacyAgentPolicy.device.noPolicy') || 'No policy'}</span>}
          {view.reasons.length > 0 && <span className="block text-[11px] text-text-muted">{view.reasons.map((x) => trCode(`legacyAgentPolicy.reasons.${x.replace(/[:.]/g, '_')}`, x)).join(' · ')}</span>}
        </Fact>
        <Fact label={t('legacyAgentPolicy.device.reported') || 'Last report'}>{r ? formatDateTime(r.reportedAt) : '—'}</Fact>
        <Fact label="Knox">{r?.knoxState ? trCode(`legacyAgent.knox.${r.knoxState}`, r.knoxState) : '—'}</Fact>
      </dl>

      {(view.dropped.length > 0 || view.withheld.length > 0) && (
        <div className="space-y-1 rounded-xl bg-amber-400/5 p-3 text-sm">
          {view.dropped.map((d) => (
            <p key={d.key} className="flex flex-wrap gap-2"><span className="text-text-primary">{agentKeyLabel(d.key)}</span><span className="text-amber-400">{codeLabel(d.code)}</span></p>
          ))}
          {view.withheld.map((k) => (
            <p key={k} className="flex flex-wrap gap-2"><span className="text-text-primary">{agentKeyLabel(k)}</span><span className="text-amber-400">{codeLabel('wipe_withheld')}</span></p>
          ))}
        </div>
      )}

      {r && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {(['all', ...AGENT_POLICY_ITEM_STATES, 'warning'] as const).map((s) => {
              const n = s === 'all' ? r.items.length : r.items.filter((i) => shown(i) === s).length;
              if (s !== 'all' && n === 0) return null;
              return (
                <button key={s} type="button" onClick={() => setFilter(s)}
                  className={`rounded-full px-2.5 py-1 text-xs ${filter === s ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'}`}>
                  {s === 'all' ? (t('common.all') || 'All') : s === 'warning' ? (t('legacyAgentPolicy.itemStates.warning') || 'Warning') : itemStateLabel(s)} · {n}
                </button>
              );
            })}
          </div>
          <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
            {items.map((i) => (
              <li key={i.key} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm hover:bg-bg-tertiary">
                <span className="min-w-0 flex-1 break-words text-text-primary">{agentKeyLabel(i.key)}</span>
                {shown(i) === 'warning'
                  ? <StateBadge tone="amber" label={t('legacyAgentPolicy.itemStates.warning') || 'Warning'} />
                  : <StateBadge tone={ITEM_STATE_TONE[i.state] ?? 'gray'} label={itemStateLabel(i.state)} />}
                <span className="text-xs text-text-secondary">{codeLabel(i.code)}</span>
                {i.detail && <span className="w-full text-[11px] text-text-muted">{i.detail}</span>}
              </li>
            ))}
            {items.length === 0 && <li className="px-3 py-2 text-sm text-text-muted">{t('legacyAgentPolicy.device.noItem') || 'No item.'}</li>}
          </ul>
        </div>
      )}
      {!r && view.desiredHash && <p className="text-sm text-text-muted">{t('legacyAgentPolicy.device.noReport') || 'The agent has not reported this policy yet.'}</p>}
      {runner.dialogs}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-text-muted">{label}</dt>
      <dd className="break-words text-text-primary">{children}</dd>
    </div>
  );
}
