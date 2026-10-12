import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import type { ArtifactState, DeviceArtifactView, DeviceConfigurationView, EffectiveSettingView, UnavailableReason } from '@obligarth/shared';
import { SocketEvents } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { registerSocketListener } from '@/socket/socketListeners';
import { ConfigBadge, StateBadge } from '@/components/mdm/DeviceStateBadges';
import { AssignmentsPanel } from '@/components/mdm/Assignments';
import { settingKeyLabel } from '@/components/mdm/ImpactPreview';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// The effective configuration of a device (modele-donnees-mdm §7.6, §7.8, §7.10; criterion 9): each key the
// resolution retained with its value (never a secret), its provenance, its availability (greyed, with the reason
// when it does not apply) and its conflicts; then the artifacts delivered to the device and their state.

const UNAVAILABLE_FALLBACK: Record<UnavailableReason, string> = {
  schema_unknown: 'Unknown to the current schema',
  platform_unsupported: 'Not supported on this platform',
  enrollment_type_unsupported: 'Not supported by this type of enrollment',
  supervision_required: 'Needs a supervised device',
  os_removed: 'Removed from this version of the operating system',
  os_too_old: 'Needs a newer operating system',
  ownership_forbidden: 'Not allowed for this ownership',
  client_unsupported: 'Not supported by the device',
  asset_not_supported: 'Needs an asset the device cannot receive yet',
  variable_unresolved: 'A variable has no value for this device',
  license_unavailable: 'No license available',
};
export const unavailableLabel = (t: TFunction, r: UnavailableReason | string): string =>
  t(`mdm.unavailable.${r}`) || UNAVAILABLE_FALLBACK[r as UnavailableReason] || r;

const ARTIFACT_TONE: Record<ArtifactState, 'green' | 'gray' | 'blue' | 'amber' | 'red'> = {
  pending: 'blue', delivering: 'blue', applied: 'green', error: 'red', not_applicable: 'gray', removing: 'amber', removed: 'gray',
};
const ARTIFACT_FALLBACK: Record<ArtifactState, string> = {
  pending: 'Pending', delivering: 'Being delivered', applied: 'Applied', error: 'Error', not_applicable: 'Not applicable',
  removing: 'Being removed', removed: 'Removed',
};
export const artifactStateLabel = (t: TFunction, s: ArtifactState): string => t(`mdm.artifactState.${s}`) || ARTIFACT_FALLBACK[s] || s;

/**
 * Why an artifact is in its state: a reason of the delivery (drift, attempts exhausted…), a problem of the
 * compilation or of the rendering ('compile:required:<key>', 'render:<code>'), a reason of unavailability, or an
 * error code of the device shown as it is. ':' separates namespaces in a translation key: '_' stands for it.
 */
export function artifactReasonLabel(reason: string): string {
  const required = /^compile:required:(.+)$/.exec(reason);
  if (required) return trCode('mdm.artifactReason.compile_required', reason, { key: required[1] });
  const key = reason.replace(/[^A-Za-z0-9_]/g, '_');
  return trCode(`mdm.artifactReason.${key}`, trCode(`mdm.unavailable.${key.replace(/^render_/, '')}`, reason));
}

const CHANNEL_FALLBACK: Record<DeviceArtifactView['channel'], string> = {
  ddm: 'Declaration', profile: 'Profile', setting: 'Setting', app: 'App',
};

/** Where an effective setting comes from: "inherited from: group X", "set on the device", "whole tenant". */
export function ProvenanceBadge({ setting, deviceGroupId }: { setting: Pick<EffectiveSettingView, 'source' | 'sourceName' | 'sourceVersion'>; deviceGroupId?: number | null }) {
  const { t } = useTranslation();
  const { scope, scopeId } = setting.source;
  const label = scope === 'device' ? (t('mdm.provenance.device') || 'Set on the device')
    : scope === 'group' ? (scopeId !== null && scopeId === deviceGroupId
      ? (t('mdm.provenance.ownGroup') || "The device's group")
      : (t('mdm.provenance.group') || 'Inherited from a group'))
      : scope === 'library' ? (t('mdm.provenance.library') || 'Library')
        : (t('mdm.provenance.tenant') || 'Whole tenant');
  const cls = scope === 'device'
    ? 'bg-amber-500/10 text-amber-500'
    : scope === 'library' ? 'bg-violet-400/10 text-violet-400' : 'bg-accent/10 text-accent';
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${cls}`}>{label}</span>
      {scope === 'group' && scopeId !== null && (
        <Link to={`/group/${scopeId}`} className="text-[11px] text-text-muted hover:text-accent">#{scopeId}</Link>
      )}
      {setting.source.type === 'policy' ? (
        <Link to={`/policies/${setting.source.id}`} className="text-xs text-text-primary hover:text-accent">
          {setting.sourceName || `#${setting.source.id}`}{setting.sourceVersion ? ` v${setting.sourceVersion}` : ''}
        </Link>
      ) : (
        <span className="text-xs text-text-primary">{setting.sourceName || `#${setting.source.id}`}</span>
      )}
    </span>
  );
}

/** A value of the effective configuration: a secret shows as dots, an object as compact JSON. */
function ValueCell({ value, removed }: { value: EffectiveSettingView['value']; removed: boolean }) {
  const { t } = useTranslation();
  if (removed) return <span className="italic text-text-muted">{t('mdm.config.removed') || 'removed'}</span>;
  if (value === undefined) return <span className="text-text-muted">—</span>;
  if (value && typeof value === 'object' && !Array.isArray(value) && '$secret' in value) {
    return <span className="text-text-muted" title={t('mdm.config.secret') || 'Secret: kept in the vault, never shown'}>••••••</span>;
  }
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return <span className="font-mono break-all" title={text.length > 120 ? text : undefined}>{text.length > 120 ? `${text.slice(0, 120)}…` : text}</span>;
}

export function DeviceConfigurationTab({ deviceId, groupId, canManagePolicies }: { deviceId: number; groupId: number | null; canManagePolicies: boolean }) {
  const { t } = useTranslation();
  const [data, setData] = useState<DeviceConfigurationView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    mdmApi.configuration(deviceId)
      .then((d) => { setData(d); setError(null); })
      .catch((err) => setError(apiErrorMessage(err)))
      .finally(() => setLoading(false));
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  // A resolution that recomputed this device's configuration reloads it.
  useEffect(() => registerSocketListener(SocketEvents.DEVICE_CONFIG_CHANGED, (p: { deviceIds?: number[] }) => {
    if (Array.isArray(p?.deviceIds) && p.deviceIds.map(Number).includes(deviceId)) load();
  }), [deviceId, load]);

  const settings = data?.settings ?? [];
  const artifacts = data?.artifacts ?? [];
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        {data && <ConfigBadge state={data.configState} size="md" />}
        <span className="text-xs text-text-muted">
          {t('mdm.config.counts', { settings: settings.length, artifacts: artifacts.length }) || `${settings.length} setting(s), ${artifacts.length} artifact(s)`}
        </span>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="ml-auto p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}

      {/* Effective settings */}
      <section>
        <h3 className="text-sm font-semibold text-text-primary mb-2">{t('mdm.config.settingsTitle') || 'Effective settings'}</h3>
        {settings.length === 0 ? (
          <p className="text-sm text-text-muted">{loading ? (t('common.loading') || 'Loading…') : (t('mdm.config.noSettings') || 'No policy applies to this device.')}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg bg-bg-secondary">
            <table className="w-full text-xs">
              <thead className="text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-3 py-2">{t('mdm.config.key') || 'Setting'}</th>
                  <th className="font-medium px-3 py-2">{t('mdm.config.value') || 'Value'}</th>
                  <th className="font-medium px-3 py-2">{t('mdm.config.provenance') || 'Provenance'}</th>
                  <th className="font-medium px-3 py-2">{t('mdm.config.availability') || 'Availability'}</th>
                </tr>
              </thead>
              <tbody>
                {settings.map((s) => {
                  const off = s.availability.status === 'not_applicable';
                  return (
                    <tr key={s.settingKey} className={`border-t border-border/50 align-top ${off ? 'opacity-50' : ''}`}>
                      <td className="px-3 py-2 text-text-primary">
                        <span className="font-mono break-all" title={s.settingKey}>{settingKeyLabel(s.settingKey)}</span>
                        {s.conflict && s.conflict.length > 0 && (
                          <span className="mt-1 flex items-start gap-1 text-amber-400">
                            <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                            <span>
                              {t('mdm.config.conflict') || 'Conflict with'}{' '}
                              {s.conflictNames.map((c) => c.name || `#${c.id}`).join(', ')}
                            </span>
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-text-secondary max-w-[280px]"><ValueCell value={s.value} removed={s.removed} /></td>
                      <td className="px-3 py-2"><ProvenanceBadge setting={s} deviceGroupId={groupId} /></td>
                      <td className="px-3 py-2">
                        {s.availability.status === 'not_applicable' ? (
                          <span className="text-text-secondary" title={s.availability.detail}>
                            {unavailableLabel(t, s.availability.reason)}
                            {s.availability.detail && <span className="block text-[11px] text-text-muted">{s.availability.detail}</span>}
                          </span>
                        ) : (
                          <span className="text-green-400">{t('mdm.config.available') || 'Applies'}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Artifacts and their state */}
      <section>
        <h3 className="text-sm font-semibold text-text-primary mb-2">{t('mdm.config.artifactsTitle') || 'Delivered artifacts'}</h3>
        {artifacts.length === 0 ? (
          <p className="text-sm text-text-muted">{t('mdm.config.noArtifacts') || 'Nothing is delivered to this device by a policy.'}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg bg-bg-secondary">
            <table className="w-full text-xs">
              <thead className="text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-3 py-2">{t('mdm.config.artifact') || 'Artifact'}</th>
                  <th className="font-medium px-3 py-2">{t('mdm.config.channel') || 'Channel'}</th>
                  <th className="font-medium px-3 py-2">{t('common.status') || 'Status'}</th>
                  <th className="font-medium px-3 py-2">{t('mdm.config.delivered') || 'Delivered'}</th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((a) => (
                  <tr key={a.artifactKey} className="border-t border-border/50 align-top">
                    <td className="px-3 py-2 text-text-primary">
                      <span className="font-mono break-all">{a.artifactKey}</span>
                      {a.sources.length > 0 && (
                        <span className="block text-[11px] text-text-muted">{a.sources.slice(0, 6).map(settingKeyLabel).join(' · ')}{a.sources.length > 6 ? ` +${a.sources.length - 6}` : ''}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-text-secondary">{t(`mdm.channel.${a.channel}`) || CHANNEL_FALLBACK[a.channel] || a.channel}</td>
                    <td className="px-3 py-2">
                      <StateBadge tone={ARTIFACT_TONE[a.state] ?? 'gray'} label={artifactStateLabel(t, a.state)} title={formatDateTime(a.stateAt)} />
                      {a.stateReasons.length > 0 && (
                        <ul className="mt-1 text-[11px] text-text-muted">
                          {a.stateReasons.slice(0, 5).map((r, i) => <li key={`${r}-${i}`}>{artifactReasonLabel(r)}</li>)}
                        </ul>
                      )}
                    </td>
                    <td className="px-3 py-2 text-text-secondary">{formatDateTime(a.deliveredAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Policies assigned to this very device (the others come from its group and from the tenant) */}
      <section>
        <AssignmentsPanel target={{ scope: 'device', id: deviceId }} canManage={canManagePolicies} onChanged={load} />
      </section>
    </div>
  );
}
