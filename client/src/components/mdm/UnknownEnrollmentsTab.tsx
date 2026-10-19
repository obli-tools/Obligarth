import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { RefreshCw } from 'lucide-react';
import type { AttachOutcome, EnrollmentProfileView, ReleaseOutcome, UnknownEnrollmentView } from '@obligarth/shared';
import { enrollmentApi } from '@/api/enrollment.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage, trCode } from '@/utils/apiError';

// Enrollments without session (integration-apple-edge §13.1, §13.2; lot C5): devices enrolled at apple-edge that no
// record of the tenant holds (an enrollment whose session is unknown, a restore of the brain). The ownership is never
// guessed (DM25): the operator attaches them to an enrollment profile, whose ownership they take, or releases them.

export function UnknownEnrollmentsTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [rows, setRows] = useState<UnknownEnrollmentView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [profiles, setProfiles] = useState<EnrollmentProfileView[]>([]);
  const [profileId, setProfileId] = useState('');
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => {
    setError(null);
    enrollmentApi.unknownEnrollments()
      .then((r) => { setRows(r); setSelected((prev) => new Set([...prev].filter((id) => r.some((x) => x.enrollmentId === id)))); })
      .catch((err) => { setRows((prev) => prev ?? []); setError(apiErrorMessage(err)); });
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { enrollmentApi.profiles().then(setProfiles).catch(() => setProfiles([])); }, []);
  const toggle = (id: string) => setSelected((prev) => {
    const n = new Set(prev);
    if (n.has(id)) n.delete(id); else n.add(id);
    return n;
  });
  const ids = [...selected];
  const summary = (results: Record<string, AttachOutcome | ReleaseOutcome>): string => {
    const counts = new Map<string, number>();
    for (const r of Object.values(results)) counts.set(r, (counts.get(r) ?? 0) + 1);
    return [...counts.entries()].map(([k, n]) => `${trCode(`deviceEnrollment.unknownOutcome.${k}`, k)}: ${n}`).join(', ');
  };
  const run = async (fn: () => Promise<{ results: Record<string, AttachOutcome | ReleaseOutcome> }>) => {
    setBusy(true);
    try {
      const r = await fn();
      toast.success(summary(r.results), { duration: 7000 });
      setSelected(new Set());
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const attach = () => {
    if (!profileId || ids.length === 0) return;
    void run(() => enrollmentApi.attachUnknown(profileId, ids));
  };
  const release = async () => {
    if (ids.length === 0) return;
    const ok = await confirm({
      title: t('deviceEnrollment.unknownReleaseTitle') || 'Release these enrollments?',
      message: t('deviceEnrollment.unknownReleaseMessage', { count: ids.length })
        || `${ids.length} enrollment(s) will be released: their certificates are revoked and the devices must enroll again.`,
      confirmLabel: t('deviceEnrollment.unknownRelease') || 'Release',
      danger: true,
    });
    if (ok) void run(() => enrollmentApi.releaseUnknown(ids));
  };
  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted">
        {t('deviceEnrollment.unknownIntro')
          || 'Devices enrolled at the device service without an enrollment session of this tenant (a lost enrollment, a restore): their ownership is never guessed. Attach them to an enrollment profile, whose ownership they take, or release them.'}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <select value={profileId} onChange={(e) => setProfileId(e.target.value)} aria-label={t('deviceEnrollment.profile') || 'Profile'}
          className="rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm">
          <option value="">{t('deviceEnrollment.unknownChooseProfile') || 'Enrollment profile…'}</option>
          {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <Button size="sm" onClick={attach} disabled={busy || !profileId || ids.length === 0}>
          {t('deviceEnrollment.unknownAttach', { count: ids.length }) || `Attach (${ids.length})`}
        </Button>
        <Button size="sm" variant="danger" onClick={() => { void release(); }} disabled={busy || ids.length === 0}>
          {t('deviceEnrollment.unknownRelease') || 'Release'}
        </Button>
        <button type="button" onClick={() => load()} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">
            {t('deviceEnrollment.unknownNone') || 'Every enrollment of the device service has its record.'}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">
                    <input type="checkbox" aria-label={t('deviceEnrollment.unknownSelectAll') || 'Select all'} checked={selected.size === rows.length}
                      onChange={(e) => setSelected(e.target.checked ? new Set(rows.map((r) => r.enrollmentId)) : new Set())} />
                  </th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.unknownEnrollment') || 'Enrollment'}</th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.unknownType') || 'Type'}</th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.started') || 'Started'}</th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.unknownLastSeen') || 'Last contact'}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.enrollmentId} className="border-t border-border/50">
                    <td className="px-4 py-2.5">
                      <input type="checkbox" checked={selected.has(r.enrollmentId)} onChange={() => toggle(r.enrollmentId)}
                        aria-label={t('deviceEnrollment.unknownSelect') || 'Select'} />
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-text-primary break-all">{anonymize(r.enrollmentId)}</td>
                    <td className="px-3 py-2.5 text-text-secondary">
                      {r.type === 'Device' ? (t('deviceEnrollment.unknownTypeDevice') || 'Device') : (t('deviceEnrollment.unknownTypeUser') || 'User enrollment')}
                      {r.proof === 'ade' && <span className="block text-[11px] text-text-muted">{t('deviceEnrollment.unknownProofAde') || 'Apple Business proof'}</span>}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-text-secondary">{formatDateTime(r.createdAt)}</td>
                    <td className="px-3 py-2.5 text-xs text-text-secondary">{formatDateTime(r.lastSeenAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
}
