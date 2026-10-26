import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Clock, RefreshCw, RotateCcw, Send, Undo2 } from 'lucide-react';
import {
  MASTER_TENANT_ID, RETENTION_LOWERING_DELAY_DAYS, retentionChanges, retentionValueErrors,
  type RetentionCategory, type RetentionCategoryDto, type RetentionPolicyDto,
} from '@obligarth/shared';
import { privacyApi } from '@/api/privacy.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { registerSocketListener } from '@/socket/socketListeners';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { apiErrorMessage } from '@/utils/apiError';
import { ApprovalsLink } from './ApprovalsLink';
import { categoryHint, categoryLabel, durationLabel, fixedLabel, readOnlyNotice, unitLabel } from './privacyLabels';

// The Retention tab of the privacy console (P0-13 T7, CNF-04): how long each category of data is kept by the tenant
// (value in force, default, range, decrease waiting for its date), the retentions of the platform (read only, D16) and
// the audit log's. For a holder of mdm.privacy.manage, new values filed as an approval request (always: D3): an increase
// applies at the approval, a decrease 7 days after it (D4). A decrease waiting is cancelled the same way, by asking the
// value in force again (the server has no other route for it).

type Values = Partial<Record<RetentionCategory, number>>;

const JUSTIFICATION_MIN = 10;
const inputCls = 'w-24 rounded-md bg-bg-tertiary px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent coarse:min-h-10';
const textareaCls = 'mt-1 w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent';

function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
}

export function RetentionTab() {
  const { t } = useTranslation();
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const { currentTenantId } = useTenantStore();
  const [data, setData] = useState<RetentionPolicyDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** What the user typed, per category (a text: an empty or partial input stays as typed). */
  const [draft, setDraft] = useState<Partial<Record<RetentionCategory, string>>>({});
  const [justification, setJustification] = useState('');
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    privacyApi.retention().then((d) => { setData(d); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => registerSocketListener('APPROVAL_UPDATED', () => { load(); }), [load]);

  // The introduction and its Refresh button stay whatever happens: a failed read is retried from there, and the values
  // already read stay shown under the error.
  const header = (
    <div className="flex flex-wrap items-start gap-2">
      <p className="min-w-0 flex-1 text-sm text-text-muted">
        {t('privacy.retention.intro', { days: RETENTION_LOWERING_DELAY_DAYS })
          || `How long the tenant keeps each category of data. A change is a request that a second person approves: a longer duration applies at the approval, a shorter one ${RETENTION_LOWERING_DELAY_DAYS} days after it.`}
      </p>
      <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
        className="rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
        <RefreshCw className="h-4 w-4" />
      </button>
    </div>
  );
  const errorLine = error ? <p className="text-sm text-status-down">{error}</p> : null;
  if (!data) {
    return (
      <div className="space-y-4">
        {header}
        {errorLine ?? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>}
      </div>
    );
  }

  const editable = data.canManage && !data.request;
  const inForce = Object.fromEntries(data.categories.map((c) => [c.key, c.value])) as Record<RetentionCategory, number>;
  const pending = Object.fromEntries(data.categories.filter((c) => c.pending !== null).map((c) => [c.key, c.pending])) as Values;
  // The values asked: only the categories typed (a number), as the server reads them.
  const asked: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(draft)) if (v !== undefined && v.trim() !== '') asked[k] = Number(v);
  const errors = retentionValueErrors(asked);
  const invalid = new Set<string>([...errors.outOfRange, ...Object.entries(draft).filter(([, v]) => v !== undefined && v.trim() === '').map(([k]) => k)]);
  const changes = invalid.size ? { raised: [], lowered: [], restored: [] } : retentionChanges(inForce, Object.keys(pending).length ? pending : null, asked as Values);
  const changedKeys = [...changes.raised, ...changes.lowered, ...changes.restored];
  const justified = justification.trim().length >= JUSTIFICATION_MIN;

  /** The value an input shows untouched: the value that will be in force (a decrease waiting, else the value now). */
  const shown = (c: RetentionCategoryDto): string => draft[c.key] ?? String(c.pending ?? c.value);
  const setValue = (k: RetentionCategory, v: string) => setDraft((d) => ({ ...d, [k]: v.replace(/[^0-9]/g, '').slice(0, 4) }));
  const cancelDecrease = (c: RetentionCategoryDto) => setDraft((d) => ({ ...d, [c.key]: String(c.value) }));

  const submit = async () => {
    const values: Values = {};
    for (const k of changedKeys) values[k] = asked[k] as number;
    setBusy(true);
    try {
      const r = await privacyApi.requestRetention(values, justification.trim());
      toast.success(r.reviewerSide === 'client'
        ? (t('privacy.requestFiledClient', { id: r.approvalId }) || `Request #${r.approvalId} filed: a client approver of the tenant reviews it.`)
        : (t('privacy.requestFiledPlatform', { id: r.approvalId }) || `Request #${r.approvalId} filed: another platform administrator reviews it.`),
      { duration: 8000 });
      setDraft({});
      setJustification('');
      load();
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };

  const list = (keys: RetentionCategory[]): string => keys.map((k) => {
    const d = data.categories.find((c) => c.key === k)!;
    return `${categoryLabel(k)} (${durationLabel(t, inForce[k], d.unit)} → ${durationLabel(t, asked[k] as number, d.unit)})`;
  }).join(', ');

  return (
    <div className="space-y-4">
      {header}
      {errorLine}

      {data.request && (
        <div className="space-y-1 rounded-md border border-amber-400/40 bg-amber-400/10 p-3 text-sm">
          <p className="flex flex-wrap items-center gap-2 text-text-primary">
            <Clock className="h-4 w-4 text-amber-400" aria-hidden />
            {t('privacy.retention.requestPending', { id: data.request.approvalId }) || `Request #${data.request.approvalId} waits for its approval`}
            <ApprovalsLink />
          </p>
          <p className="text-xs text-text-muted">
            {t('privacy.requestedAt', { date: formatDateTime(data.request.requestedAt), expires: formatDateTime(data.request.expiresAt) })
              || `Filed ${formatDateTime(data.request.requestedAt)}, expires ${formatDateTime(data.request.expiresAt)}`}
          </p>
          <ul className="text-xs text-text-secondary">
            {(Object.entries(data.request.values) as Array<[RetentionCategory, number]>).map(([k, v]) => {
              const d = data.categories.find((c) => c.key === k);
              return d ? <li key={k}>{categoryLabel(k)} ({durationLabel(t, inForce[k], d.unit)} → {durationLabel(t, v, d.unit)})</li> : null;
            })}
          </ul>
        </div>
      )}
      {data.pendingEffectiveAt && (
        <p className="flex items-start gap-2 text-sm text-text-secondary">
          <Clock className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden />
          {t('privacy.retention.decreasesOn', { date: formatDateTime(data.pendingEffectiveAt) })
            || `Shorter durations approved take effect on ${formatDateTime(data.pendingEffectiveAt)}.`}
        </p>
      )}

      <section className="rounded-lg border border-border bg-bg-secondary">
        <ul className="divide-y divide-border/60">
          {data.categories.map((c) => {
            const bad = invalid.has(c.key);
            return (
              <li key={c.key} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                <div className="min-w-0 flex-1 basis-60">
                  <p className="text-sm text-text-primary">{categoryLabel(c.key)}</p>
                  <p className="text-xs text-text-muted">{categoryHint(c.key)}</p>
                  <p className="mt-0.5 text-[11px] text-text-muted">
                    {t('privacy.retention.defaultRange', {
                      default: durationLabel(t, c.default, c.unit), min: c.min, max: c.max, unit: unitLabel(t, c.unit),
                    }) || `Default ${durationLabel(t, c.default, c.unit)} · from ${c.min} to ${c.max} ${unitLabel(t, c.unit)}`}
                  </p>
                </div>
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-text-primary">{durationLabel(t, c.value, c.unit)}</span>
                  {c.configured === null && <StateBadge tone="gray" label={t('privacy.retention.default') || 'Default'} />}
                  {c.pending !== null && (
                    <StateBadge tone="amber" label={t('privacy.retention.pendingValue', { value: durationLabel(t, c.pending, c.unit) })
                      || `→ ${durationLabel(t, c.pending, c.unit)} soon`} title={data.pendingEffectiveAt ? formatDateTime(data.pendingEffectiveAt) : undefined} />
                  )}
                </div>
                {editable && (
                  <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
                    <span className="flex items-center gap-1.5 text-xs text-text-muted">
                      <input type="text" inputMode="numeric" value={shown(c)} onChange={(e) => setValue(c.key, e.target.value)}
                        aria-label={categoryLabel(c.key)} aria-invalid={bad} className={`${inputCls} ${bad ? 'ring-2 ring-status-down' : ''}`} />
                      {unitLabel(t, c.unit)}
                    </span>
                    {c.pending !== null && draft[c.key] !== String(c.value) && (
                      <Button size="sm" variant="ghost" onClick={() => cancelDecrease(c)} className="gap-1 text-xs">
                        <Undo2 className="h-3.5 w-3.5" aria-hidden />{t('privacy.retention.cancelDecrease') || 'Cancel the decrease'}
                      </Button>
                    )}
                    {bad && <span className="w-full text-[11px] text-status-down">{t('privacy.retention.outOfRange', { min: c.min, max: c.max }) || `From ${c.min} to ${c.max}`}</span>}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </section>

      {editable && changedKeys.length > 0 && (
        <div className="space-y-3 rounded-lg border border-border bg-bg-secondary p-4">
          <h3 className="text-sm font-semibold text-text-primary">{t('privacy.retention.summary') || 'The request'}</h3>
          <ul className="space-y-1 text-xs text-text-secondary">
            {changes.raised.length > 0 && (
              <li><span className="font-medium text-text-primary">{t('privacy.retention.raised') || 'Longer, at the approval:'}</span> {list(changes.raised)}</li>
            )}
            {changes.lowered.length > 0 && (
              <li>
                <span className="font-medium text-text-primary">{t('privacy.retention.lowered', { days: RETENTION_LOWERING_DELAY_DAYS }) || `Shorter, ${RETENTION_LOWERING_DELAY_DAYS} days after the approval:`}</span> {list(changes.lowered)}
              </li>
            )}
            {changes.restored.length > 0 && (
              <li>
                <span className="font-medium text-text-primary">{t('privacy.retention.restored') || 'Decrease cancelled:'}</span> {changes.restored.map(categoryLabel).join(', ')}
              </li>
            )}
          </ul>
          {changes.lowered.length > 0 && (
            <p className="text-xs text-text-muted">{t('privacy.retention.loweredHint') || 'Once in force, a shorter duration also purges the data already older than it.'}</p>
          )}
          <label className="block text-sm text-text-secondary">
            {t('privacy.justification') || 'Justification'}
            <textarea value={justification} onChange={(e) => setJustification(e.target.value)} rows={2} maxLength={1000} className={textareaCls}
              placeholder={t('privacy.justificationPlaceholder') || 'Why this change (10 characters at least)'} />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => { void submit(); }} disabled={!justified || busy} loading={busy} className="gap-1.5">
              <Send className="h-4 w-4" aria-hidden />{t('privacy.requestApproval') || 'Request approval'}
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setDraft({})} disabled={busy} className="gap-1.5">
              <RotateCcw className="h-4 w-4" aria-hidden />{t('privacy.discard') || 'Discard the changes'}
            </Button>
          </div>
        </div>
      )}
      {!data.canManage && (
        <p className="text-xs text-text-muted">{readOnlyNotice(t)}</p>
      )}
      {data.version > 0 && data.updatedAt && (
        <p className="text-xs text-text-muted">
          {t('privacy.retention.lastChange', { version: data.version, date: formatDateTime(data.updatedAt) })
            || `Change ${data.version}, ${formatDateTime(data.updatedAt)}`}
          {data.justification ? ` — ${data.justification}` : ''}
        </p>
      )}

      <section className="space-y-2 rounded-lg border border-border bg-bg-secondary p-4">
        <h3 className="text-sm font-semibold text-text-primary">{t('privacy.retention.auditLog') || 'Audit log'}</h3>
        <p className="text-sm text-text-secondary">
          {durationLabel(t, data.auditLog.months, 'months')}
          {data.auditLog.pendingMonths !== null && data.auditLog.pendingEffectiveAt && (
            <span className="ml-2 text-xs text-text-muted">
              {t('privacy.retention.auditPending', { value: durationLabel(t, data.auditLog.pendingMonths, 'months'), date: formatDateTime(data.auditLog.pendingEffectiveAt) })
                || `→ ${durationLabel(t, data.auditLog.pendingMonths, 'months')} on ${formatDateTime(data.auditLog.pendingEffectiveAt)}`}
            </span>
          )}
        </p>
        {isPlatformAdmin && currentTenantId === MASTER_TENANT_ID ? (
          <Link to="/admin/security?tab=auditSettings" className="text-xs text-accent hover:underline">{t('privacy.retention.auditSettings') || 'Settings of the audit log'}</Link>
        ) : (
          <p className="text-xs text-text-muted">{t('privacy.retention.auditHint') || 'Set per tenant by the platform administrators, in the settings of the audit log.'}</p>
        )}
      </section>

      <section className="space-y-2 rounded-lg border border-border bg-bg-secondary p-4">
        <h3 className="text-sm font-semibold text-text-primary">{t('privacy.retention.fixedTitle') || 'Durations of the platform'}</h3>
        <p className="text-xs text-text-muted">{t('privacy.retention.fixedHint') || 'Set for every tenant by the platform; shown for the record of processing.'}</p>
        <ul className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
          {data.fixed.map((f) => (
            <li key={f.key} className="flex items-baseline justify-between gap-3 text-sm">
              <span className="min-w-0 text-text-secondary">{fixedLabel(f.key)}</span>
              <span className="shrink-0 text-text-primary">{durationLabel(t, f.value, f.unit)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
