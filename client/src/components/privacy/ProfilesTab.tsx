import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, Clock, History, RefreshCw, RotateCcw, Send } from 'lucide-react';
import {
  OWNERSHIPS, PRIVACY_BOOLEAN_RULES, PRIVACY_COLLECTION_SCOPES, PRIVACY_RULE_KEYS, privacyRuleChanges,
  type Ownership, type PrivacyCollectionScope, type PrivacyImpactDto, type PrivacyOwnershipProfileDto, type PrivacyProfileRules,
  type PrivacyProfilesDto, type PrivacyRuleKey,
} from '@obligarth/shared';
import { privacyApi } from '@/api/privacy.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime, ownershipLabel } from '@/components/mdm/PlatformIcon';
import { registerSocketListener } from '@/socket/socketListeners';
import { apiErrorMessage } from '@/utils/apiError';
import { ApprovalsLink } from './ApprovalsLink';
import { readOnlyNotice, ruleHint, ruleLabel, scopeLabel } from './privacyLabels';

// The Profiles tab of the privacy console (P0-13 T7, CNF-02): one panel per ownership. The rules in force (the defaults
// while no version is published), the imposed rules greyed and marked as such, the change waiting for its approval;
// for a holder of mdm.privacy.manage, a draft of the rules with its impact (devices, data cleaned, data newly collected),
// a justification, and its filing as an approval request (always: D3), under the reminder to update the DPIA and
// consult the employee representatives; the last versions.

const JUSTIFICATION_MIN = 10;
const isBoolean = (k: PrivacyRuleKey): boolean => (PRIVACY_BOOLEAN_RULES as readonly string[]).includes(k);
const sameRules = (a: PrivacyProfileRules, b: PrivacyProfileRules): boolean => PRIVACY_RULE_KEYS.every((k) => a[k] === b[k]);
const textareaCls = 'mt-1 w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent';

function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
}

export function ProfilesTab() {
  const { t } = useTranslation();
  const [data, setData] = useState<PrivacyProfilesDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ownership, setOwnership] = useState<Ownership>('corporate');
  const load = useCallback(() => {
    privacyApi.profiles().then((d) => { setData(d); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, []);
  useEffect(() => { load(); }, [load]);
  // A request examined elsewhere (approved: a new version; denied, expired: no longer waiting).
  useEffect(() => registerSocketListener('APPROVAL_UPDATED', () => { load(); }), [load]);

  const profile = data?.profiles.find((p) => p.ownership === ownership) ?? null;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start gap-2">
        <p className="min-w-0 flex-1 text-sm text-text-muted">
          {t('privacy.profiles.intro') || 'What the organisation collects from its devices, per ownership. Each change is a request that a second person approves before it applies.'}
        </p>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>
      {error && <p className="text-sm text-status-down">{error}</p>}
      <SegmentedTabs<Ownership>
        tabs={OWNERSHIPS.map((o) => {
          const p = data?.profiles.find((x) => x.ownership === o);
          return {
            id: o, label: ownershipLabel(t, o),
            badge: p?.pending ? <Clock className="h-3.5 w-3.5 text-amber-400" aria-label={t('privacy.profiles.pendingShort') || 'Change waiting'} /> : undefined,
          };
        })}
        value={ownership}
        onChange={setOwnership}
        size="sm"
        ariaLabel={t('privacy.profiles.ownership') || 'Ownership'}
      />
      {!data && !error && <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>}
      {profile && <OwnershipPanel key={`${profile.ownership}:${profile.current?.version ?? 0}:${profile.pending?.approvalId ?? 0}`}
        profile={profile} canManage={data!.canManage} onFiled={load} />}
    </div>
  );
}

function OwnershipPanel({ profile, canManage, onFiled }: { profile: PrivacyOwnershipProfileDto; canManage: boolean; onFiled: () => void }) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<PrivacyProfileRules>(profile.effective);
  const [justification, setJustification] = useState('');
  const [impact, setImpact] = useState<PrivacyImpactDto | null>(null);
  const [impactError, setImpactError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const imposed = useMemo(() => new Set(profile.imposed), [profile.imposed]);
  const editable = canManage && !profile.pending;
  const changed = !sameRules(draft, profile.effective);
  // A first version may change nothing in the rules shown and still be published (it replaces the defaults).
  const first = profile.current === null;
  const diff = privacyRuleChanges(profile.effective, draft);

  // The impact of the draft, once it settles (the rules in force when nothing changed and a version exists: no call).
  useEffect(() => {
    if (!editable || (!changed && !first)) { setImpact(null); setImpactError(null); return undefined; }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      privacyApi.impact(profile.ownership, draft)
        .then((r) => { if (!cancelled) { setImpact(r); setImpactError(null); } })
        .catch((err) => { if (!cancelled) { setImpact(null); setImpactError(apiErrorMessage(err)); } });
    }, 350);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [editable, changed, first, draft, profile.ownership]);

  const set = (k: PrivacyRuleKey, v: boolean | PrivacyCollectionScope) => setDraft((d) => ({ ...d, [k]: v }));
  const justified = justification.trim().length >= JUSTIFICATION_MIN;
  const submit = async () => {
    setBusy(true);
    try {
      const r = await privacyApi.requestProfile(profile.ownership, draft, justification.trim());
      toast.success(r.reviewerSide === 'client'
        ? (t('privacy.requestFiledClient', { id: r.approvalId }) || `Request #${r.approvalId} filed: a client approver of the tenant reviews it.`)
        : (t('privacy.requestFiledPlatform', { id: r.approvalId }) || `Request #${r.approvalId} filed: another platform administrator reviews it.`),
      { duration: 8000 });
      onFiled();
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };

  return (
    <section className="space-y-4 rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-base font-semibold text-text-primary">{ownershipLabel(t, profile.ownership)}</h2>
        {profile.current
          ? <StateBadge tone="green" label={t('privacy.profiles.version', { version: profile.current.version }) || `Version ${profile.current.version}`} />
          : <StateBadge tone="amber" label={t('privacy.profiles.defaults') || 'Default rules'} />}
        {profile.current && (
          <span className="text-xs text-text-muted">{t('privacy.profiles.since', { date: formatDateTime(profile.current.createdAt) }) || `since ${formatDateTime(profile.current.createdAt)}`}</span>
        )}
      </div>
      {!profile.current && (
        <p className="text-xs text-text-muted">
          {t('privacy.profiles.defaultsHint') || 'No version published for this ownership: the rules applied before the privacy profiles stay in force (Android devices then collect less than shown, until a first version).'}
        </p>
      )}

      {profile.pending && <PendingPanel profile={profile} />}

      <ul className="divide-y divide-border/60">
        {PRIVACY_RULE_KEYS.map((k) => {
          const isImposed = imposed.has(k);
          const value = draft[k];
          const moved = value !== profile.effective[k];
          return (
            <li key={k} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5">
              <div className="min-w-0 flex-1 basis-56">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-text-primary">{ruleLabel(k)}</span>
                  {isImposed && <StateBadge tone="gray" label={t('privacy.profiles.imposed') || 'Imposed'}
                    title={t('privacy.profiles.imposedHint') || 'Fixed for this ownership: no profile may change it.'} />}
                  {moved && <StateBadge tone="blue" label={t('privacy.profiles.changed') || 'Changed'} />}
                </div>
                <p className="text-xs text-text-muted">{ruleHint(k)}</p>
              </div>
              {isBoolean(k) ? (
                <span className="flex items-center gap-2">
                  <span className="text-xs text-text-muted">{k === 'remoteAssistance'
                    // P0-15: a permission, not a datum collected.
                    ? (value ? (t('privacy.rules.remoteAssistance.on') || 'Allowed') : (t('privacy.rules.remoteAssistance.off') || 'Not allowed'))
                    : (value ? (t('privacy.rules.collected') || 'Collected') : (t('privacy.rules.notCollected') || 'Not collected'))}</span>
                  <ToggleSwitch checked={value === true} onChange={(v) => set(k, v)} disabled={!editable || isImposed} ariaLabel={ruleLabel(k)} />
                </span>
              ) : (
                <SegmentedTabs<PrivacyCollectionScope>
                  tabs={PRIVACY_COLLECTION_SCOPES.map((s) => ({ id: s, label: scopeLabel(k, s), disabled: !editable || isImposed }))}
                  value={value as PrivacyCollectionScope}
                  onChange={(s) => set(k, s)}
                  size="sm"
                  fill={false}
                  ariaLabel={ruleLabel(k)}
                />
              )}
            </li>
          );
        })}
      </ul>

      {editable && (changed || first) && (
        <div className="space-y-3 border-t border-border pt-4">
          <ImpactView impact={impact} error={impactError} diff={diff} />
          <div className="flex items-start gap-2 rounded-md border border-amber-400/40 bg-amber-400/10 p-3 text-xs">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden />
            <span className="text-text-secondary">
              {t('privacy.profiles.dpiaBanner') || 'Before filing: update the data protection impact assessment (DPIA) and consult the employee representatives. The notice of the employees is generated again once the version is published.'}
            </span>
          </div>
          <label className="block text-sm text-text-secondary">
            {t('privacy.justification') || 'Justification'}
            <textarea value={justification} onChange={(e) => setJustification(e.target.value)} rows={2} maxLength={1000} className={textareaCls}
              placeholder={t('privacy.justificationPlaceholder') || 'Why this change (10 characters at least)'} />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => { void submit(); }} disabled={!justified || busy} loading={busy} className="gap-1.5">
              <Send className="h-4 w-4" aria-hidden />{t('privacy.requestApproval') || 'Request approval'}
            </Button>
            {changed && (
              <Button size="sm" variant="secondary" onClick={() => setDraft(profile.effective)} disabled={busy} className="gap-1.5">
                <RotateCcw className="h-4 w-4" aria-hidden />{t('privacy.discard') || 'Discard the changes'}
              </Button>
            )}
          </div>
        </div>
      )}
      {!canManage && (
        <p className="text-xs text-text-muted">{readOnlyNotice(t)}</p>
      )}

      <HistoryList profile={profile} />
    </section>
  );
}

function PendingPanel({ profile }: { profile: PrivacyOwnershipProfileDto }) {
  const { t } = useTranslation();
  const p = profile.pending!;
  const diff = privacyRuleChanges(profile.effective, p.rules);
  return (
    <div className="space-y-1 rounded-md border border-amber-400/40 bg-amber-400/10 p-3 text-sm">
      <p className="flex flex-wrap items-center gap-2 text-text-primary">
        <Clock className="h-4 w-4 text-amber-400" aria-hidden />
        {t('privacy.profiles.pending', { id: p.approvalId }) || `Request #${p.approvalId} waits for its approval`}
        <ApprovalsLink />
      </p>
      <p className="text-xs text-text-muted">
        {t('privacy.requestedAt', { date: formatDateTime(p.requestedAt), expires: formatDateTime(p.expiresAt) })
          || `Filed ${formatDateTime(p.requestedAt)}, expires ${formatDateTime(p.expiresAt)}`}
      </p>
      <RuleChanges narrowed={diff.narrowed} widened={diff.widened} />
    </div>
  );
}

function RuleChanges({ narrowed, widened }: { narrowed: PrivacyRuleKey[]; widened: PrivacyRuleKey[] }) {
  const { t } = useTranslation();
  if (!narrowed.length && !widened.length) return null;
  return (
    <ul className="space-y-0.5 text-xs">
      {narrowed.length > 0 && (
        <li className="text-text-secondary">
          <span className="font-medium text-text-primary">{t('privacy.profiles.narrowed') || 'Collects less'}</span>{' '}
          {narrowed.map(ruleLabel).join(', ')}
        </li>
      )}
      {widened.length > 0 && (
        <li className="text-text-secondary">
          <span className="font-medium text-text-primary">{t('privacy.profiles.widened') || 'Collects more'}</span>{' '}
          {widened.map(ruleLabel).join(', ')}
        </li>
      )}
    </ul>
  );
}

function ImpactView({ impact, error, diff }: { impact: PrivacyImpactDto | null; error: string | null; diff: { narrowed: PrivacyRuleKey[]; widened: PrivacyRuleKey[] } }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-2 rounded-md bg-bg-tertiary/60 p-3">
      <h3 className="text-sm font-semibold text-text-primary">{t('privacy.profiles.impact') || 'Impact of the change'}</h3>
      <RuleChanges narrowed={diff.narrowed} widened={diff.widened} />
      {error ? <p className="text-xs text-status-down">{error}</p> : !impact ? (
        <p className="text-xs italic text-text-muted">{t('privacy.profiles.computing') || 'Computing the impact…'}</p>
      ) : (
        <div className="space-y-1 text-xs text-text-secondary">
          <p>
            {t('privacy.profiles.devices', { count: impact.devices.total, apple: impact.devices.apple, android: impact.devices.android, agent: impact.devices.legacyAgent })
              || `${impact.devices.total} device(s) of this ownership (Apple ${impact.devices.apple}, Android ${impact.devices.android}, Android agent ${impact.devices.legacyAgent})`}
          </p>
          {(impact.scrub.apps > 0 || impact.scrub.locations > 0) && (
            <p>
              {t('privacy.profiles.scrub', { apps: impact.scrub.apps, locations: impact.scrub.locations })
                || `Removed at the publication: ${impact.scrub.apps} application(s) not managed, ${impact.scrub.locations} position(s)`}
            </p>
          )}
          {impact.narrowed.length > 0 && (
            <p>{t('privacy.profiles.narrowedHint') || 'The data no longer collected are cleaned from the records once the version is published.'}</p>
          )}
          {impact.widened.length > 0 && (
            <p>{t('privacy.profiles.widenedHint') || 'New data will be collected: the employees are told by the notice, generated again at the publication.'}</p>
          )}
          {impact.firstVersion && (
            <p>{t('privacy.profiles.firstVersionHint') || 'First version of this ownership: it replaces the default rules, and Android devices may then collect more than before (IMEI of a corporate device, network of a personally enabled one) if these rules allow it.'}</p>
          )}
        </div>
      )}
    </div>
  );
}

function HistoryList({ profile }: { profile: PrivacyOwnershipProfileDto }) {
  const { t } = useTranslation();
  if (!profile.history.length) return null;
  return (
    <details className="group/hist border-t border-border pt-3 text-sm">
      <summary className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-text-secondary hover:text-text-primary coarse:py-2">
        <History className="h-3.5 w-3.5" aria-hidden />{t('privacy.profiles.history') || 'Versions'} ({profile.history.length})
      </summary>
      <ul className="mt-2 divide-y divide-border/60">
        {profile.history.map((v, i) => {
          const before = profile.history[i + 1]?.rules ?? profile.defaults;
          const diff = privacyRuleChanges(before, v.rules);
          return (
            <li key={v.id} className="space-y-1 py-2">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-medium text-text-primary">{t('privacy.profiles.version', { version: v.version }) || `Version ${v.version}`}</span>
                <span className="text-text-muted">{formatDateTime(v.createdAt)}</span>
                {v.supersededAt === null && <StateBadge tone="green" label={t('privacy.current') || 'In force'} />}
                {v.approvalId !== null && <span className="text-text-muted">{t('privacy.approvalRef', { id: v.approvalId }) || `request #${v.approvalId}`}</span>}
              </div>
              {v.justification && <p className="break-words text-xs text-text-secondary">{v.justification}</p>}
              <RuleChanges narrowed={diff.narrowed} widened={diff.widened} />
            </li>
          );
        })}
      </ul>
    </details>
  );
}
