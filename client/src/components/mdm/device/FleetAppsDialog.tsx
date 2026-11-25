import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Download, PackageSearch } from 'lucide-react';
import { LEGACY_AGENT_FLEET_APPS_CHECKED_SHARE, type LegacyAgentFleetAppView, type LegacyAgentFleetAppsView } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { apiErrorMessage } from '@/utils/apiError';

// The apps of the fleet a device of the bridge agent lacks (a phone reset in a shop), compared with its group's devices
// (GET /legacy-agent/devices/:id/fleet-apps): the store's apps most of them carry are checked, each chosen one is queued
// as an app.install of the package the server picked, through the command route (its capability, restriction, guard).

const installable = (a: LegacyAgentFleetAppView): boolean => a.package !== null && !a.queued;
const mb = (bytes: number): string => `${(bytes / 1_048_576).toFixed(1)} MB`;

export function FleetAppsDialog({ deviceId, open, onClose, onQueued }: { deviceId: number; open: boolean; onClose: () => void; onQueued?: () => void }) {
  const { t } = useTranslation();
  const [view, setView] = useState<LegacyAgentFleetAppsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setView(null);
    setError(null);
    legacyAgentApi.deviceFleetApps(deviceId).then((v) => {
      setView(v);
      setChecked(new Set(v.items.filter((a) => installable(a) && a.share >= LEGACY_AGENT_FLEET_APPS_CHECKED_SHARE).map((a) => a.packageName)));
    }).catch((err) => setError(apiErrorMessage(err)));
  }, [deviceId, open]);

  const chosen = useMemo(() => (view?.items ?? []).filter((a) => installable(a) && checked.has(a.packageName)), [view, checked]);
  const toggle = (p: string) => setChecked((prev) => { const n = new Set(prev); if (n.has(p)) n.delete(p); else n.add(p); return n; });

  const install = async () => {
    setBusy(true);
    let queued = 0;
    let pending = 0;
    const failed: string[] = [];
    try {
      for (const a of chosen) {
        try {
          const r = await legacyAgentApi.send(deviceId, 'app.install', { packageId: a.package!.id },
            t('legacyAgent.fleetApps.reason') || 'Apps of the fleet put back');
          if ('approvalId' in r) pending++; else queued++;
        } catch (err) {
          if (isStepUpHandled(err)) return;
          failed.push(`${a.label ?? a.packageName}: ${apiErrorMessage(err)}`);
        }
      }
    } finally {
      setBusy(false);
    }
    if (queued) toast.success(t('legacyAgent.fleetApps.queued', { count: queued }) || `${queued} install(s) queued`);
    if (pending) toast.success(t('legacyAgent.fleetApps.pending', { count: pending }) || `${pending} install(s) sent for approval`);
    if (failed.length) toast.error(failed.join('\n'), { duration: 10000 });
    if (queued || pending) { onQueued?.(); onClose(); }
  };

  const missing = (view?.items ?? []).filter((a) => a.package === null);
  return (
    <Modal open={open} onClose={busy ? () => undefined : onClose} dismissible={!busy} size="lg"
      icon={<PackageSearch className="w-4 h-4 text-accent" />} title={t('legacyAgent.fleetApps.title') || 'Put back the apps of the fleet'}
      footer={<>
        <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
        <Button onClick={() => void install()} disabled={busy || chosen.length === 0}>
          <Download className="w-3.5 h-3.5 mr-1" />{t('legacyAgent.fleetApps.install', { count: chosen.length }) || `Install (${chosen.length})`}
        </Button>
      </>}>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {!error && view === null && <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>}
      {view && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            {view.scope.groupName
              ? t('legacyAgent.fleetApps.scopeGroup', { group: view.scope.groupName, count: view.scope.peers })
                || `Compared with the ${view.scope.peers} device(s) of the group ${view.scope.groupName}.`
              : t('legacyAgent.fleetApps.scopeTenant', { count: view.scope.peers })
                || `Compared with the ${view.scope.peers} device(s) of the tenant.`}
            {' '}{t('legacyAgent.fleetApps.prompt') || 'Without a Knox licence, the phone asks to confirm each install on its screen.'}
          </p>
          {view.items.length === 0 ? (
            <p className="text-sm text-text-muted">{t('legacyAgent.fleetApps.none') || 'This device lacks none of the usual apps of its fleet.'}</p>
          ) : (
            <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
              {view.items.map((a) => {
                const can = installable(a);
                return (
                  <li key={a.packageName}>
                    <label className={`flex items-start gap-3 px-3 py-2 text-sm ${can ? 'cursor-pointer hover:bg-bg-tertiary' : 'opacity-60'}`}>
                      <input type="checkbox" className="mt-1" disabled={!can || busy} checked={can && checked.has(a.packageName)} onChange={() => toggle(a.packageName)} />
                      <span className="min-w-0 flex-1">
                        <span className="block text-text-primary">{a.label ?? a.packageName}</span>
                        <span className="block font-mono text-[11px] text-text-muted break-all">{a.packageName}</span>
                        <span className="block text-[11px] text-text-muted">
                          {t('legacyAgent.fleetApps.share', { percent: Math.round(a.share * 100), count: a.peersWith })
                            || `On ${Math.round(a.share * 100)} % of the fleet (${a.peersWith})`}
                          {a.package && <> · {a.package.versionName ?? a.package.versionCode} · {mb(a.package.sizeBytes)}</>}
                        </span>
                        {a.queued && <span className="block text-[11px] text-accent">{t('legacyAgent.fleetApps.alreadyQueued') || 'An install is already queued'}</span>}
                        {!a.package && <span className="block text-[11px] text-amber-400">{t('legacyAgent.fleetApps.noPackage') || 'No APK of this app in the store: pull it from a device first'}</span>}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
          )}
          {missing.length > 0 && (
            <p className="text-[11px] text-text-muted">{t('legacyAgent.fleetApps.missingHint') || 'An app without an APK in the store can be pulled from a device that carries it (Android agent panel, Pull an APK).'}</p>
          )}
        </div>
      )}
    </Modal>
  );
}
