import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, ShieldAlert, ShieldCheck, Users } from 'lucide-react';
import type { ImpactApprovalReason, ImpactDevicesPage, PolicyConflict, PolicyImpact } from '@obligarth/shared';
import { parseSettingKey, shortType } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage, apiErrorStatus } from '@/utils/apiError';

// The preview of a change of the effective configuration (modele-donnees-mdm §7.11, PLT-18): shown before a
// publication, a change of assignments, and the move or the deletion of a group. What it touches, what it adds,
// changes and removes, the conflicts it would create, and whether a second approver is required (DM23).

const REASON_FALLBACK: Record<ImpactApprovalReason, string> = {
  devices_threshold: '25 devices or more are touched',
  fleet_share: '10 % of the fleet or more is touched',
  removal_threshold: 'something is removed from 3 devices or more',
  restriction: 'the restriction of this tenant requires it',
};

export const approvalReasonLabel = (t: TFunction, r: ImpactApprovalReason): string =>
  t(`mdm.impact.reason.${r}`) || REASON_FALLBACK[r] || r;

/** 'passcode.settings · RequirePasscode', 'wifi.managed [Office]' from a setting key (its type, then its key or
 *  its instance); the key itself when it is not one of the model's. */
export function settingKeyLabel(settingKey: string): string {
  const p = parseSettingKey(settingKey);
  if (!p) return settingKey;
  if (p.kind === 'raw') return `raw.profile [${(p.instance ?? '').slice(0, 8)}]`;
  const type = shortType(p.type);
  if (p.kind === 'keyed') return `${type} · ${p.key}`;
  if (p.kind === 'collection' || p.kind === 'app') return `${type} [${p.instance}]`;
  return type;
}

function Counter({ label, value, tone }: { label: string; value: number; tone?: 'warn' | 'danger' }) {
  return (
    <div className="rounded-lg bg-bg-tertiary px-3 py-2 min-w-[110px]">
      <div className={`text-lg font-semibold tabular-nums ${tone === 'danger' && value > 0 ? 'text-red-400' : tone === 'warn' && value > 0 ? 'text-amber-400' : 'text-text-primary'}`}>{value}</div>
      <div className="text-[11px] text-text-muted">{label}</div>
    </div>
  );
}

export function ConflictList({ conflicts }: { conflicts: PolicyConflict[] }) {
  const { t } = useTranslation();
  if (!conflicts.length) return null;
  return (
    <div className="rounded-lg border border-red-400/30 bg-red-400/5 p-3 space-y-1.5">
      <p className="flex items-center gap-1.5 text-sm font-medium text-red-400">
        <AlertTriangle className="w-4 h-4" />
        {t('mdm.impact.conflicts', { count: conflicts.length }) || `${conflicts.length} conflict(s)`}
      </p>
      <ul className="space-y-1 text-xs text-text-secondary">
        {conflicts.slice(0, 20).map((c, i) => (
          <li key={`${c.settingKey}-${i}`}>
            <span className="font-mono text-text-primary break-all">{settingKeyLabel(c.settingKey)}</span>
            {' — '}
            {c.resources.map((r) => r.name).join(', ')}
          </li>
        ))}
      </ul>
      <p className="text-[11px] text-text-muted">{t('mdm.impact.conflictsHint') || 'Two resources set the same key on the same target with the same priority and different values: change a priority or a value.'}</p>
    </div>
  );
}

export function ImpactPreview({ impact, compact = false }: { impact: PolicyImpact; compact?: boolean }) {
  const { t } = useTranslation();
  const [devicesOpen, setDevicesOpen] = useState(false);
  const removals = impact.artifacts.removals + impact.artifacts.appRemovals;
  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap gap-2">
        <Counter label={t('mdm.impact.devicesTouched') || 'Devices touched'} value={impact.devicesTouched} />
        <Counter label={t('mdm.impact.devicesInScope') || 'Devices in scope'} value={impact.devicesInScope} />
        <Counter label={t('mdm.impact.devicesAdded') || 'Start receiving it'} value={impact.devicesAdded} />
        <Counter label={t('mdm.impact.devicesRemoved') || 'Stop receiving it'} value={impact.devicesRemoved} tone="warn" />
        <Counter label={t('mdm.impact.installs') || 'Installations'} value={impact.artifacts.installs} />
        <Counter label={t('mdm.impact.removals') || 'Removals'} value={removals} tone="danger" />
        {impact.artifacts.kioskLockChanges > 0 && (
          <Counter label={t('mdm.impact.kioskLockChanges') || 'Kiosk lock changes'} value={impact.artifacts.kioskLockChanges} tone="danger" />
        )}
      </div>

      <div
        className={`flex items-start gap-2 rounded-lg border p-3 ${impact.approval.required ? 'border-amber-400/40 bg-amber-400/5' : 'border-border bg-bg-tertiary/40'}`}
      >
        {impact.approval.required
          ? <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0 text-amber-400" />
          : <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0 text-green-400" />}
        <div className="min-w-0">
          <p className="font-medium text-text-primary">
            {impact.approval.required
              ? (t('mdm.impact.approvalRequired') || 'A second approver is required')
              : (t('mdm.impact.stepUpOnly') || 'Your second factor is enough')}
          </p>
          {impact.approval.required && impact.approval.reasons.length > 0 && (
            <ul className="mt-0.5 text-xs text-text-secondary list-disc pl-4">
              {impact.approval.reasons.map((r) => <li key={r}>{approvalReasonLabel(t, r)}</li>)}
            </ul>
          )}
          <p className="mt-0.5 text-[11px] text-text-muted">
            {t('mdm.impact.fleet', { touched: impact.devicesTouched, fleet: impact.fleetSize }) || `${impact.devicesTouched} of ${impact.fleetSize} enrolled devices`}
            {' · '}
            {t('mdm.impact.computedAt', { at: new Date(impact.computedAt).toLocaleTimeString() }) || `computed at ${new Date(impact.computedAt).toLocaleTimeString()}`}
          </p>
        </div>
      </div>

      <ConflictList conflicts={impact.conflicts} />

      {!compact && impact.keys.length > 0 && (
        <div className="rounded-lg bg-bg-tertiary/40 overflow-hidden">
          <div className="max-h-56 overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-bg-tertiary text-text-muted">
                <tr>
                  <th className="text-left font-medium px-3 py-1.5">{t('mdm.impact.key') || 'Setting'}</th>
                  <th className="text-right font-medium px-2 py-1.5">{t('mdm.impact.added') || 'Added'}</th>
                  <th className="text-right font-medium px-2 py-1.5">{t('mdm.impact.changed') || 'Changed'}</th>
                  <th className="text-right font-medium px-2 py-1.5">{t('mdm.impact.removed') || 'Removed'}</th>
                  <th className="text-right font-medium px-3 py-1.5">{t('mdm.impact.notApplicable') || 'Not applicable'}</th>
                </tr>
              </thead>
              <tbody>
                {impact.keys.map((k) => (
                  <tr key={k.settingKey} className="border-t border-border/50">
                    <td className="px-3 py-1 font-mono break-all text-text-primary">{settingKeyLabel(k.settingKey)}</td>
                    <td className="px-2 py-1 text-right tabular-nums">{k.added || ''}</td>
                    <td className="px-2 py-1 text-right tabular-nums">{k.changed || ''}</td>
                    <td className={`px-2 py-1 text-right tabular-nums ${k.removed ? 'text-red-400' : ''}`}>{k.removed || ''}</td>
                    <td className="px-3 py-1 text-right tabular-nums text-text-muted">{k.notApplicable || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {impact.devicesTouched === 0 && impact.conflicts.length === 0 && (
        <p className="text-xs text-text-muted">{t('mdm.impact.nothing') || 'No device changes: nothing is installed nor removed.'}</p>
      )}

      {impact.sample.length > 0 && (
        <div className="text-xs">
          <p className="flex items-center gap-1.5 text-text-muted mb-1">
            <Users className="w-3.5 h-3.5" />
            {t('mdm.impact.sample', { count: impact.sample.length }) || `Sample of ${impact.sample.length} device(s) within your scopes`}
          </p>
          <div className="flex flex-wrap gap-1">
            {impact.sample.slice(0, compact ? 8 : 20).map((d) => (
              <span key={d.deviceId} className="px-1.5 py-0.5 rounded bg-bg-tertiary text-text-secondary" title={[...d.added.map((k) => `+ ${settingKeyLabel(k)}`), ...d.changed.map((k) => `~ ${settingKeyLabel(k)}`), ...d.removed.map((k) => `- ${settingKeyLabel(k)}`)].join('\n')}>
                {anonymize(d.label)}
              </span>
            ))}
            {impact.devicesToken && impact.devicesTouched > 0 && (
              <button type="button" onClick={() => setDevicesOpen(true)} className="px-1.5 py-0.5 text-accent hover:underline coarse:min-h-9">
                {t('mdm.impact.allDevices') || 'All the devices…'}
              </button>
            )}
          </div>
        </div>
      )}

      {impact.devicesToken && (
        <ImpactDevicesModal open={devicesOpen} onClose={() => setDevicesOpen(false)} token={impact.devicesToken} />
      )}
    </div>
  );
}

/** The touched devices of a preview, by pages (the token lasts 15 minutes; the caller's scopes apply). */
function ImpactDevicesModal({ open, onClose, token }: { open: boolean; onClose: () => void; token: string }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [data, setData] = useState<ImpactDevicesPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setError(null);
    mdmApi.impactDevices(token, page, 100)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((err) => {
        if (cancelled) return;
        // The token of a preview lasts 15 minutes: past them the server answers 404, without a code.
        const expired = t('mdm.impact.expired') || 'This preview has expired: compute it again.';
        setError(apiErrorStatus(err) === 404 ? expired : apiErrorMessage(err, expired));
      });
    return () => { cancelled = true; };
  }, [open, token, page, t]);

  const pages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title={t('mdm.impact.devicesTitle') || 'Devices touched'}
      footer={(
        <>
          <span className="mr-auto text-xs text-text-muted">{data ? `${data.total}` : ''}</span>
          <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>{t('common.back') || 'Back'}</Button>
          <span className="text-xs text-text-muted tabular-nums">{page} / {pages}</span>
          <Button variant="secondary" size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>{t('common.next') || 'Next'}</Button>
        </>
      )}
    >
      {error ? <p className="text-sm text-red-400">{error}</p> : !data ? (
        <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
      ) : (
        <ul className="divide-y divide-border/50 text-xs">
          {data.devices.map((d) => (
            <li key={d.deviceId} className="py-1.5">
              <span className="font-medium text-text-primary">{anonymize(d.label)}</span>
              <span className="ml-2 text-text-muted">
                {[d.added.length && `+${d.added.length}`, d.changed.length && `~${d.changed.length}`, d.removed.length && `-${d.removed.length}`].filter(Boolean).join('  ')}
              </span>
            </li>
          ))}
          {data.devices.length === 0 && <li className="py-3 text-text-muted">{t('mdm.impact.noVisibleDevice') || 'No device within your scopes.'}</li>}
        </ul>
      )}
    </Modal>
  );
}

/**
 * A change that goes through the preview: computes it when opened, shows it, then asks for the confirmation.
 * `load` returns the preview (dry run); `apply` writes (the interceptor asks for the second factor); the caller
 * tells the user what happened from the result of `apply`.
 */
export function ImpactConfirmDialog({ open, onClose, title, intro, load, apply, confirmLabel, danger = false, allowConflicts = false }: {
  open: boolean;
  onClose: () => void;
  title: string;
  intro?: string;
  load: () => Promise<PolicyImpact>;
  apply: () => Promise<void>;
  confirmLabel?: string;
  danger?: boolean;
  /** The server writes the change even when it creates conflicts (a group moved or deleted: they are settled by the
   *  resolution and reported); a publication or a change of assignments is refused instead. */
  allowConflicts?: boolean;
}) {
  const { t } = useTranslation();
  const [impact, setImpact] = useState<PolicyImpact | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setImpact(null);
    setError(null);
    load().then((i) => { if (!cancelled) setImpact(i); }).catch((err) => { if (!cancelled) setError(apiErrorMessage(err)); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const blocked = !impact || (impact.conflicts.length > 0 && !allowConflicts);
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="lg"
      title={title}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            loading={busy}
            disabled={blocked || busy}
            onClick={async () => {
              setBusy(true);
              // A failure is told to the user by `apply` (or by the interceptor of the second factor): the
              // dialog stays open on its preview.
              try { await apply(); onClose(); } catch { /* told by the caller */ } finally { setBusy(false); }
            }}
          >
            {impact?.approval.required
              ? (t('mdm.impact.request') || 'Request approval')
              : (confirmLabel || t('common.confirm') || 'Confirm')}
          </Button>
        </>
      )}
    >
      {intro && <p className="text-sm text-text-secondary mb-3">{intro}</p>}
      {error ? <p className="text-sm text-red-400">{error}</p>
        : !impact ? <p className="text-sm text-text-muted italic">{t('mdm.impact.computing') || 'Computing the preview…'}</p>
          : <ImpactPreview impact={impact} />}
    </Modal>
  );
}
