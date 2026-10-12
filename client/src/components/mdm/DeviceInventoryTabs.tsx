import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Lock, ShieldCheck } from 'lucide-react';
import type { CollectedField, DeviceAppView, DeviceCertificateView, DeviceProfileView } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { formatBytes, formatDate, formatDateTime } from '@/components/mdm/PlatformIcon';
import { apiErrorMessage } from '@/utils/apiError';

// The inventory of a device (modele-donnees-mdm §5): applications, configuration profiles, certificates. What the
// privacy rules of the device's ownership do not collect is absent from the answer, and said so here (an empty
// list is not "nothing installed").

function useInventory<T>(load: () => Promise<T[]>, deps: unknown[]): { rows: T[] | null; error: string | null } {
  const [rows, setRows] = useState<T[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    setRows(null);
    setError(null);
    load().then((r) => { if (!cancelled) setRows(r); }).catch((err) => { if (!cancelled) { setRows([]); setError(apiErrorMessage(err)); } });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { rows, error };
}

function Shell({ rows, error, empty, note, lastAt, search, onSearch, children }: {
  rows: unknown[] | null; error: string | null; empty: string; note?: string; lastAt?: string | null;
  search?: string; onSearch?: (v: string) => void; children: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        {onSearch && (
          <input
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            placeholder={t('common.search') || 'Search'}
            className="w-full max-w-xs rounded-lg bg-bg-tertiary px-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50"
          />
        )}
        <span className="text-xs text-text-muted">
          {rows ? rows.length : ''}
          {lastAt !== undefined && ` · ${t('mdm.inventory.lastCollected', { at: lastAt ? formatDateTime(lastAt) : (t('common.never') || 'Never') }) || `collected: ${formatDateTime(lastAt)}`}`}
        </span>
      </div>
      {note && <p className="text-xs text-text-muted rounded-lg bg-bg-tertiary/50 px-3 py-2">{note}</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <p className="text-sm text-text-muted">{empty}</p>
          : <div className="overflow-x-auto rounded-lg bg-bg-secondary">{children}</div>}
    </div>
  );
}

const th = 'font-medium px-3 py-2 text-left';
const td = 'px-3 py-2 align-top';

export function DeviceAppsTab({ deviceId, collected, lastAt }: { deviceId: number; collected: CollectedField[]; lastAt?: string | null }) {
  const { t } = useTranslation();
  const { rows, error } = useInventory<DeviceAppView>(() => mdmApi.apps(deviceId), [deviceId]);
  const [q, setQ] = useState('');
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (rows ?? []).filter((a) => !needle || a.identifier.toLowerCase().includes(needle) || (a.name ?? '').toLowerCase().includes(needle));
  }, [rows, q]);
  return (
    <Shell
      rows={rows === null ? null : shown}
      error={error}
      lastAt={lastAt}
      search={q}
      onSearch={setQ}
      empty={t('mdm.inventory.noApps') || 'No application reported.'}
      note={collected.includes('allApps') ? undefined
        : (t('mdm.inventory.managedAppsOnly') || 'Managed applications only: the other applications of this device are not collected (privacy rules of its ownership).')}
    >
      <table className="w-full text-xs">
        <thead className="text-text-muted">
          <tr>
            <th className={th}>{t('mdm.inventory.app') || 'Application'}</th>
            <th className={th}>{t('mdm.inventory.version') || 'Version'}</th>
            <th className={th}>{t('mdm.inventory.management') || 'Management'}</th>
            <th className={th}>{t('mdm.inventory.size') || 'Size'}</th>
            <th className={th}>{t('mdm.inventory.lastSeen') || 'Last seen'}</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((a) => (
            <tr key={a.identifier} className="border-t border-border/50">
              <td className={td}>
                <span className="text-text-primary">{a.name || a.identifier}</span>
                {a.name && <span className="block font-mono text-[11px] text-text-muted break-all">{a.identifier}</span>}
              </td>
              <td className={`${td} text-text-secondary`}>{a.shortVersion || a.version || '—'}</td>
              <td className={td}>
                {a.managed ? (
                  <span className="inline-flex items-center gap-1 text-accent">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    {a.managementStatus || (t('mdm.inventory.managed') || 'Managed')}
                  </span>
                ) : <span className="text-text-muted">{t('mdm.inventory.unmanaged') || 'Not managed'}</span>}
              </td>
              <td className={`${td} text-text-secondary`}>{formatBytes(a.bundleSize)}</td>
              <td className={`${td} text-text-secondary`}>{formatDate(a.lastSeenAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Shell>
  );
}

export function DeviceProfilesTab({ deviceId, lastAt }: { deviceId: number; lastAt?: string | null }) {
  const { t } = useTranslation();
  const { rows, error } = useInventory<DeviceProfileView>(() => mdmApi.profiles(deviceId), [deviceId]);
  return (
    <Shell rows={rows} error={error} lastAt={lastAt} empty={t('mdm.inventory.noProfiles') || 'No profile reported.'}>
      <table className="w-full text-xs">
        <thead className="text-text-muted">
          <tr>
            <th className={th}>{t('mdm.inventory.profile') || 'Profile'}</th>
            <th className={th}>{t('mdm.inventory.payloads') || 'Payloads'}</th>
            <th className={th}>{t('mdm.inventory.origin') || 'Origin'}</th>
            <th className={th}>{t('mdm.inventory.lastSeen') || 'Last seen'}</th>
          </tr>
        </thead>
        <tbody>
          {(rows ?? []).map((p) => (
            <tr key={p.payloadIdentifier} className="border-t border-border/50">
              <td className={td}>
                <span className="text-text-primary">{p.displayName || p.payloadIdentifier}</span>
                <span className="block font-mono text-[11px] text-text-muted break-all">{p.payloadIdentifier}</span>
                {p.organization && <span className="block text-[11px] text-text-muted">{p.organization}</span>}
              </td>
              <td className={`${td} text-text-secondary`}>
                {p.payloadTypes.length ? p.payloadTypes.map((x) => x.replace(/^com\.apple\./, '')).join(', ') : '—'}
              </td>
              <td className={td}>
                <span className="flex flex-wrap items-center gap-1.5">
                  {p.artifactKey ? (
                    <span className="px-1.5 py-0.5 rounded bg-accent/10 text-accent" title={p.artifactKey}>{t('mdm.inventory.fromPolicy') || 'Policy'}</span>
                  ) : p.isManaged ? (
                    <span className="px-1.5 py-0.5 rounded bg-bg-tertiary text-text-secondary">{t('mdm.inventory.managed') || 'Managed'}</span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded bg-bg-tertiary text-text-muted">{t('mdm.inventory.installedByUser') || 'Installed outside management'}</span>
                  )}
                  {p.removalDisallowed && <span className="inline-flex items-center gap-1 text-text-muted" title={t('mdm.inventory.removalDisallowed') || 'The user cannot remove it'}><Lock className="w-3 h-3" /></span>}
                  {p.isEncrypted && <span className="text-[11px] text-text-muted">{t('mdm.inventory.encrypted') || 'encrypted'}</span>}
                </span>
              </td>
              <td className={`${td} text-text-secondary`}>{formatDate(p.lastSeenAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Shell>
  );
}

export function DeviceCertificatesTab({ deviceId, collected, lastAt }: { deviceId: number; collected: CollectedField[]; lastAt?: string | null }) {
  const { t } = useTranslation();
  const { rows, error } = useInventory<DeviceCertificateView>(() => mdmApi.certificates(deviceId), [deviceId]);
  const now = Date.now();
  return (
    <Shell
      rows={rows}
      error={error}
      lastAt={lastAt}
      empty={t('mdm.inventory.noCertificates') || 'No certificate reported.'}
      note={collected.includes('allCertificates') ? undefined
        : (t('mdm.inventory.managedCertificatesOnly') || 'Only the certificates of the management are collected on this device (privacy rules of its ownership).')}
    >
      <table className="w-full text-xs">
        <thead className="text-text-muted">
          <tr>
            <th className={th}>{t('mdm.inventory.certificate') || 'Certificate'}</th>
            <th className={th}>{t('mdm.inventory.issuer') || 'Issuer'}</th>
            <th className={th}>{t('mdm.inventory.validUntil') || 'Valid until'}</th>
            <th className={th}>{t('mdm.inventory.lastSeen') || 'Last seen'}</th>
          </tr>
        </thead>
        <tbody>
          {(rows ?? []).map((c) => {
            const expired = c.notAfter ? new Date(c.notAfter).getTime() < now : false;
            return (
              <tr key={c.sha256} className="border-t border-border/50">
                <td className={td}>
                  <span className="text-text-primary">{c.commonName || c.subject || c.sha256.slice(0, 16)}</span>
                  <span className="block font-mono text-[11px] text-text-muted break-all">{c.sha256.slice(0, 32)}…</span>
                  {(c.isMdmIdentity || c.isIdentity) && (
                    <span className="mt-0.5 inline-block px-1.5 py-0.5 rounded bg-accent/10 text-accent">
                      {c.isMdmIdentity ? (t('mdm.inventory.mdmIdentity') || 'Management identity') : (t('mdm.inventory.identity') || 'Identity')}
                    </span>
                  )}
                </td>
                <td className={`${td} text-text-secondary`}>{c.issuer || '—'}</td>
                <td className={`${td} ${expired ? 'text-red-400' : 'text-text-secondary'}`}>{formatDate(c.notAfter)}</td>
                <td className={`${td} text-text-secondary`}>{formatDate(c.lastSeenAt)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Shell>
  );
}
