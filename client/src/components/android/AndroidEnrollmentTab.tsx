import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Archive, Ban, Check, Eye, FileText, KeyRound, Mail, Pencil, Plus, QrCode, RefreshCw, X } from 'lucide-react';
import {
  ANDROID_BYOD_INVITATION_TTL_HOURS, ANDROID_ENROLLMENT_METHODS, ENROLLMENT_LOCALES,
  type AndroidByodInvitationCreated, type AndroidByodNoticeView, type AndroidByodInvitationView, type AndroidCreatedTokenView, type AndroidEnrollmentMethod,
  type AndroidEnrollmentProfileRequest, type AndroidEnrollmentProfileView, type AndroidEnrollmentTokenView, type AndroidKmeConfiguration,
  type AndroidPendingDeviceView, type DeviceGroup, type EndUser,
} from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { groupsApi } from '@/api/groups.api';
import { mdmApi } from '@/api/mdm.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { apiErrorBody, trCode } from '@/utils/apiError';
import { anonymize } from '@/utils/anonymize';
import { CopyValue, Fact, Labeled, dateOf, errorToast, fieldClass } from './ui';

// The Android part of the Device enrollment page (android-amapi §10, §12.1; lot AN-C2): the Android enrollment
// profiles (method, ownership, group, settings: usage, kiosk app, minimum API level, Google authentication, approval of
// the new devices, serial numbers), their tokens (creation, QR code, value to type after afw#setup or by NFC, KME
// JSON, reveal under step-up, revocation), the devices awaiting approval and the BYOD invitations. A token value is
// shown in the dialog of its creation or of its audited reveal only.

type Tone = 'green' | 'gray' | 'blue' | 'amber' | 'red';
type Ownership = AndroidEnrollmentProfileRequest['ownership'];

/** The ownerships each Android method admits (enrollment_profiles_rules_check, android branch; the server checks). */
export const ANDROID_METHOD_OWNERSHIPS: Readonly<Record<AndroidEnrollmentMethod, readonly Ownership[]>> = {
  android_qr: ['corporate', 'corporate_personal'],
  android_token: ['corporate', 'corporate_personal'],
  android_afw: ['corporate', 'corporate_personal'],
  android_nfc: ['corporate'],
  android_zero_touch: ['corporate', 'corporate_personal'],
  android_kme: ['corporate', 'corporate_personal'],
  android_byod_link: ['personal'],
  android_signin_url: ['corporate', 'corporate_personal', 'personal'],
};
/** The methods whose tokens the console creates here (BYOD: by invitation; sign-in: by the device's session). */
const TOKEN_METHODS: ReadonlySet<AndroidEnrollmentMethod> = new Set(['android_qr', 'android_token', 'android_afw', 'android_nfc', 'android_zero_touch', 'android_kme']);
const TOKEN_TONE: Record<AndroidEnrollmentTokenView['state'], Tone> = { creating: 'blue', active: 'green', used: 'gray', expired: 'gray', revoked: 'gray', failed: 'red' };
const POLICY_TONE: Record<string, Tone> = { pushed: 'green', pending: 'blue', error: 'red' };

export function AndroidEnrollmentTab() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [profiles, setProfiles] = useState<AndroidEnrollmentProfileView[] | null>(null);
  const [tokens, setTokens] = useState<AndroidEnrollmentTokenView[]>([]);
  const [pending, setPending] = useState<AndroidPendingDeviceView[]>([]);
  const [invitations, setInvitations] = useState<AndroidByodInvitationView[]>([]);
  const [archived, setArchived] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<AndroidEnrollmentProfileView | 'new' | null>(null);
  const [shown, setShown] = useState<AndroidCreatedTokenView | null>(null);
  const [kme, setKme] = useState<AndroidKmeConfiguration | null>(null);
  const [inviteFor, setInviteFor] = useState<AndroidEnrollmentProfileView | null>(null);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [p, tk, pd, inv] = await Promise.all([
        androidApi.profiles(archived), androidApi.tokens(), androidApi.pendingApprovals().catch(() => []), androidApi.byodInvitations().catch(() => []),
      ]);
      setProfiles(p); setTokens(tk); setPending(pd); setInvitations(inv); setError(null);
    } catch (err) {
      setProfiles([]);
      setError(trCode(`errors.${apiErrorBody(err)?.code ?? ''}`, t('android.enrollment.unavailable') || 'The Android enrollment is not available (no linked Android enterprise?).'));
    }
  }, [archived, t]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(key);
    try { await fn(); if (done) toast.success(done); await load(); } catch (err) { errorToast(err); } finally { setBusy(null); }
  };
  const byId = useMemo(() => new Map((profiles ?? []).map((p) => [p.id, p])), [profiles]);

  const newToken = (p: AndroidEnrollmentProfileView) => act(`token:${p.id}`, async () => setShown(await androidApi.createToken({ profileId: p.id })));
  const reveal = (tk: AndroidEnrollmentTokenView) => act(`reveal:${tk.id}`, async () => {
    if (tk.kind === 'kme') setKme(await androidApi.kme(tk.id));
    else setShown(await androidApi.revealToken(tk.id));
  });
  const revoke = async (tk: AndroidEnrollmentTokenView) => {
    if (!(await confirm({ message: t('android.tokens.confirmRevoke') || 'Revoke this token? A device that has not enrolled with it yet can no longer use it.', danger: true }))) return;
    await act(`revoke:${tk.id}`, () => androidApi.revokeToken(tk.id), t('android.tokens.revoked') || 'Token revoked');
  };
  const revokeInvitation = async (iv: AndroidByodInvitationView) => {
    if (!(await confirm({ message: t('android.byod.confirmRevoke') || 'Revoke this invitation? Its code no longer serves, and a device that has not enrolled with it yet can no longer do so.', danger: true }))) return;
    await act(`inv:${iv.id}`, () => androidApi.revokeByodInvitation(iv.id), t('android.byod.revoked') || 'Invitation revoked');
  };
  const archive = async (p: AndroidEnrollmentProfileView) => {
    if (!(await confirm({ message: t('android.profiles.confirmArchive', { name: p.name }) || `Archive the profile "${p.name}"? Its active tokens are revoked.`, danger: true }))) return;
    await act(`archive:${p.id}`, () => androidApi.archiveProfile(p.id), t('android.profiles.archived') || 'Profile archived');
  };

  if (profiles === null) return <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>;
  return (
    <div className="space-y-6">
      {error && <p className="text-sm text-text-muted">{error}</p>}

      {/* Devices awaiting approval (AN17) */}
      {pending.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-text-primary">{t('android.approvals.title') || 'Android devices awaiting approval'}</h2>
          <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
            {pending.map((d) => (
              <li key={d.deviceId} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                <Link to={`/devices/${d.deviceId}`} className="min-w-0 flex-1 text-text-primary hover:underline">{anonymize(d.displayName ?? `#${d.deviceId}`)}</Link>
                <span className="text-xs text-text-muted">{d.model ?? ''}</span>
                <span className="text-xs text-text-muted">{d.profileId ? byId.get(d.profileId)?.name ?? '' : ''}</span>
                <span className="text-xs text-text-muted">{dateOf(d.enrolledAt)}</span>
                <Button size="sm" disabled={busy !== null} onClick={() => void act(`approve:${d.deviceId}`, () => androidApi.approveDevice(d.deviceId), t('android.approvals.approved') || 'Device approved')}>
                  <Check className="w-3.5 h-3.5 mr-1" />{t('android.approvals.approve') || 'Approve'}
                </Button>
                <Button size="sm" variant="danger" disabled={busy !== null} onClick={async () => {
                  if (await confirm({ message: t('android.approvals.confirmRefuse') || 'Refuse this device? It stays disabled; its removal is decided afterwards.', danger: true })) {
                    await act(`refuse:${d.deviceId}`, () => androidApi.refuseDevice(d.deviceId), t('android.approvals.refused') || 'Device refused');
                  }
                }}>
                  <X className="w-3.5 h-3.5 mr-1" />{t('android.approvals.refuse') || 'Refuse'}
                </Button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Profiles */}
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold text-text-primary">{t('android.profiles.title') || 'Android enrollment profiles'}</h2>
          <label className="flex items-center gap-1.5 text-xs text-text-muted">
            <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} className="accent-accent" />
            {t('android.profiles.showArchived') || 'Show the archived ones'}
          </label>
          <span className="ml-auto flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => void load()} aria-label={t('common.refresh') || 'Refresh'}><RefreshCw className="w-4 h-4" /></Button>
            <Button size="sm" onClick={() => setEditing('new')}><Plus className="w-4 h-4 mr-1" />{t('android.profiles.new') || 'New Android profile'}</Button>
          </span>
        </div>
        {profiles.length === 0 ? <p className="text-sm text-text-muted">{t('android.profiles.empty') || 'No Android profile yet.'}</p> : (
          <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
            {profiles.map((p) => (
              <li key={p.id} className="px-3 py-2.5 text-sm space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-text-primary">{p.name}</span>
                  <span className="text-xs text-text-muted">{trCode(`mdm.enrollmentMethod.${p.method}`, p.method)}</span>
                  <span className="text-xs text-text-muted">{trCode(`android.ownership.${p.ownership}`, p.ownership)}</span>
                  {p.settings.deviceUsage === 'kiosk' && <StateBadge tone="violet" label={t('android.profiles.kiosk') || 'kiosk'} />}
                  {!p.enabled && <StateBadge tone="gray" label={t('android.profiles.disabled') || 'disabled'} />}
                  {p.archivedAt && <StateBadge tone="gray" label={t('android.profiles.archivedBadge') || 'archived'} />}
                  <StateBadge tone={POLICY_TONE[p.enrollmentPolicy.state] ?? 'gray'}
                    label={trCode(`android.profiles.policyState.${p.enrollmentPolicy.state}`, p.enrollmentPolicy.state)}
                    title={p.enrollmentPolicy.lastError ? trCode(`android.profiles.policyError.${p.enrollmentPolicy.lastError}`, p.enrollmentPolicy.lastError) : undefined} />
                  <span className="ml-auto flex flex-wrap gap-1.5">
                    {!p.archivedAt && TOKEN_METHODS.has(p.method) && (
                      <Button size="sm" disabled={busy !== null || p.enrollmentPolicy.state !== 'pushed' || !p.enabled} onClick={() => void newToken(p)}>
                        <QrCode className="w-3.5 h-3.5 mr-1" />{t('android.tokens.create') || 'New token'}
                      </Button>
                    )}
                    {!p.archivedAt && p.method === 'android_byod_link' && (
                      <Button size="sm" disabled={busy !== null || p.enrollmentPolicy.state !== 'pushed' || !p.enabled} onClick={() => setInviteFor(p)}>
                        <Mail className="w-3.5 h-3.5 mr-1" />{t('android.byod.invite') || 'Invite'}
                      </Button>
                    )}
                    {!p.archivedAt && (
                      <>
                        <Button size="sm" variant="secondary" onClick={() => setEditing(p)} aria-label={t('common.edit') || 'Edit'}><Pencil className="w-3.5 h-3.5" /></Button>
                        <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void archive(p)} aria-label={t('android.profiles.archive') || 'Archive'}><Archive className="w-3.5 h-3.5" /></Button>
                      </>
                    )}
                  </span>
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-text-muted">
                  {p.defaultGroupName && <span>{t('android.profiles.group') || 'Group'}: {p.defaultGroupName}</span>}
                  <span>{t('android.profiles.activeTokens', { count: p.activeTokens }) || `${p.activeTokens} active token(s)`}</span>
                  {p.settings.requireApproval && <span>{t('android.profiles.requireApproval') || 'new devices approved by hand'}</span>}
                  {p.settings.minimumApiLevel ? <span>{t('android.profiles.minApi', { level: p.settings.minimumApiLevel }) || `API ${p.settings.minimumApiLevel} at least`}</span> : null}
                  {p.settings.kioskApp && <span className="font-mono">{p.settings.kioskApp}</span>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Tokens */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-text-primary">{t('android.tokens.title') || 'Android enrollment tokens'}</h2>
        {tokens.length === 0 ? <p className="text-sm text-text-muted">{t('android.tokens.empty') || 'No token yet.'}</p> : (
          <div className="overflow-x-auto rounded-lg bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">{t('android.tokens.profile') || 'Profile'}</th>
                  <th className="px-3 py-2 font-medium">{t('android.tokens.kind') || 'Kind'}</th>
                  <th className="px-3 py-2 font-medium">{t('android.tokens.state') || 'State'}</th>
                  <th className="px-3 py-2 font-medium">{t('android.tokens.uses') || 'Uses'}</th>
                  <th className="px-3 py-2 font-medium">{t('android.tokens.expires') || 'Expires'}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {tokens.map((tk) => {
                  const active = tk.state === 'active' && new Date(tk.expiresAt).getTime() > Date.now();
                  return (
                    <tr key={tk.id}>
                      <td className="px-3 py-2 text-text-primary">{byId.get(tk.profileId)?.name ?? '—'}</td>
                      <td className="px-3 py-2 text-text-secondary">{trCode(`android.tokens.kinds.${tk.kind}`, tk.kind)}{tk.requiresApproval ? ` · ${t('android.tokens.approvalShort') || 'approval'}` : ''}</td>
                      <td className="px-3 py-2"><StateBadge tone={TOKEN_TONE[tk.state]} label={trCode(`android.tokens.states.${tk.state}`, tk.state)} /></td>
                      <td className="px-3 py-2 text-text-secondary">{tk.maxUses === null ? tk.uses : `${tk.uses} / ${tk.maxUses}`}</td>
                      <td className="px-3 py-2 text-text-secondary">{dateOf(tk.expiresAt)}</td>
                      <td className="px-3 py-2">
                        {active && (
                          <span className="flex justify-end gap-1.5">
                            {tk.kind !== 'byod_link' && tk.kind !== 'signin' && (
                              <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void reveal(tk)}>
                                {tk.kind === 'kme' ? <KeyRound className="w-3.5 h-3.5 mr-1" /> : <Eye className="w-3.5 h-3.5 mr-1" />}
                                {tk.kind === 'kme' ? (t('android.tokens.kme') || 'KME JSON') : (t('android.tokens.reveal') || 'Show')}
                              </Button>
                            )}
                            {tk.kind === 'zero_touch' && (
                              <Link to={`/enrollment/android/zero-touch?token=${encodeURIComponent(tk.id)}`} className="inline-flex items-center px-2 text-xs text-accent hover:underline">
                                {t('android.tokens.zeroTouch') || 'Zero-touch portal'}
                              </Link>
                            )}
                            <Button size="sm" variant="danger" disabled={busy !== null} onClick={() => void revoke(tk)} aria-label={t('android.tokens.revoke') || 'Revoke'}>
                              <Ban className="w-3.5 h-3.5" />
                            </Button>
                          </span>
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

      {/* BYOD invitations (lot AN-F1) */}
      {(invitations.length > 0 || (profiles ?? []).some((p) => p.method === 'android_byod_link' && !p.archivedAt)) && (
        <section className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold text-text-primary">{t('android.byod.title') || 'BYOD invitations'}</h2>
            <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setNoticeOpen(true)}>
              <FileText className="w-3.5 h-3.5 mr-1" />{t('android.byod.noticePreview') || 'Notice shown to the user'}
            </Button>
          </div>
          <p className="text-xs text-text-muted">{t('android.byod.help') || 'A work profile on the user\'s own device: the organization manages the work apps and data only, never the personal data. The invitation is single use; the user reads and accepts the privacy notice before enrolling. Removing the device erases the work profile only.'}</p>
          {invitations.length === 0 ? (
            <p className="text-sm text-text-muted italic">{t('android.byod.none') || 'No invitation yet: invite a user from a BYOD profile.'}</p>
          ) : (
            <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
              {invitations.map((iv) => (
                <li key={iv.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                  <span className="font-mono text-text-primary">{iv.prefix}…</span>
                  <span className="text-text-primary">{iv.endUserName ? anonymize(iv.endUserName) : (iv.endUserId ? `#${iv.endUserId}` : '')}</span>
                  <span className="text-text-secondary">{iv.label ?? ''}</span>
                  <span className="text-xs text-text-muted">{byId.get(iv.profileId)?.name ?? ''}</span>
                  <StateBadge tone={iv.state === 'active' || iv.state === 'issued' || iv.state === 'issuing' ? 'green' : iv.state === 'used' ? 'blue' : 'gray'} label={trCode(`android.byod.states.${iv.state}`, iv.state)} />
                  {iv.acknowledgedAt && (
                    <span className="text-xs text-text-muted" title={iv.noticeVersionId ?? ''}>{t('android.byod.acknowledgedAt', { date: dateOf(iv.acknowledgedAt) }) || `Notice accepted ${dateOf(iv.acknowledgedAt)}`}</span>
                  )}
                  {iv.deviceId !== null && (
                    <Link to={`/devices/${iv.deviceId}`} className="text-xs text-text-primary hover:underline">{t('android.byod.device') || 'Device'}</Link>
                  )}
                  <span className="ml-auto text-xs text-text-muted">
                    {iv.state === 'used' && iv.usedAt ? (t('android.byod.usedAt', { date: dateOf(iv.usedAt) }) || `Used ${dateOf(iv.usedAt)}`)
                      : iv.state === 'revoked' && iv.revokedAt ? (t('android.byod.revokedAt', { date: dateOf(iv.revokedAt) }) || `Revoked ${dateOf(iv.revokedAt)}`)
                      : (t('android.byod.expiresAt', { date: dateOf(iv.expiresAt) }) || `Expires ${dateOf(iv.expiresAt)}`)}
                  </span>
                  {(iv.state === 'active' || iv.state === 'issuing' || iv.state === 'issued') && (
                    <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void revokeInvitation(iv)}>
                      <Ban className="w-3.5 h-3.5 mr-1" />{t('android.byod.revoke') || 'Revoke'}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <ProfileDialog target={editing} onClose={() => setEditing(null)} onSaved={() => void load()} />
      <TokenDialog token={shown} onClose={() => { setShown(null); void load(); }} />
      <KmeDialog config={kme} onClose={() => setKme(null)} />
      <InvitationDialog profile={inviteFor} onClose={() => { setInviteFor(null); void load(); }} onPreview={() => setNoticeOpen(true)} />
      <NoticeDialog open={noticeOpen} onClose={() => setNoticeOpen(false)} />
    </div>
  );
}

// ── Profile ─────────────────────────────────────────────────────────────────────

interface ProfileForm {
  name: string; method: AndroidEnrollmentMethod; ownership: Ownership; groupId: string; locale: string; enabled: boolean;
  deviceUsage: 'standard' | 'kiosk'; kioskApp: string; minimumApiLevel: string; googleAuth: 'UNSPECIFIED' | 'OPTIONAL' | 'REQUIRED';
  /** default: the method's default (long tokens: approval), never sent; yes/no: the profile's choice. */
  requireApproval: 'default' | 'yes' | 'no'; approvedSerials: string;
}

const formOf = (p: AndroidEnrollmentProfileView | null): ProfileForm => ({
  name: p?.name ?? '', method: p?.method ?? 'android_qr', ownership: p?.ownership ?? 'corporate', groupId: p?.defaultGroupId ? String(p.defaultGroupId) : '',
  locale: p?.locale ?? 'fr', enabled: p?.enabled ?? true, deviceUsage: p?.settings.deviceUsage ?? 'standard', kioskApp: p?.settings.kioskApp ?? '',
  minimumApiLevel: p?.settings.minimumApiLevel ? String(p.settings.minimumApiLevel) : '', googleAuth: p?.settings.googleAuth ?? 'UNSPECIFIED',
  requireApproval: p?.settings.requireApproval === undefined || p?.settings.requireApproval === null ? 'default' : p.settings.requireApproval ? 'yes' : 'no', approvedSerials: (p?.settings.approvedSerials ?? []).join('\n'),
});

function ProfileDialog({ target, onClose, onSaved }: { target: AndroidEnrollmentProfileView | 'new' | null; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation();
  const existing = target && target !== 'new' ? target : null;
  const [f, setF] = useState<ProfileForm>(formOf(null));
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [busy, setBusy] = useState(false);
  const [issues, setIssues] = useState<Array<{ code: string; field: string }>>([]);
  useEffect(() => {
    if (target === null) return;
    setF(formOf(existing));
    setIssues([]);
    groupsApi.list().then(setGroups).catch(() => setGroups([]));
  }, [target]); // eslint-disable-line react-hooks/exhaustive-deps
  const up = <K extends keyof ProfileForm>(k: K, v: ProfileForm[K]) => setF((prev) => ({ ...prev, [k]: v }));
  const owners = ANDROID_METHOD_OWNERSHIPS[f.method];
  useEffect(() => { if (!owners.includes(f.ownership)) up('ownership', owners[0]); }, [f.method]); // eslint-disable-line react-hooks/exhaustive-deps
  const kioskPossible = f.ownership === 'corporate' && f.method !== 'android_byod_link' && f.method !== 'android_signin_url';

  const save = async () => {
    const body: AndroidEnrollmentProfileRequest = {
      name: f.name.trim(), method: f.method, ownership: f.ownership, defaultGroupId: f.groupId ? Number(f.groupId) : null, locale: f.locale,
      enabled: f.enabled,
      settings: {
        deviceUsage: kioskPossible ? f.deviceUsage : 'standard',
        ...(kioskPossible && f.deviceUsage === 'kiosk' && f.kioskApp.trim() ? { kioskApp: f.kioskApp.trim() } : {}),
        ...(f.minimumApiLevel ? { minimumApiLevel: Number(f.minimumApiLevel) } : {}),
        googleAuth: f.googleAuth,
        // A kiosk always requires the approval of its new devices (server rule); otherwise the method's default unless chosen.
        ...(kioskPossible && f.deviceUsage === 'kiosk' ? { requireApproval: true } : f.requireApproval === 'default' ? {} : { requireApproval: f.requireApproval === 'yes' }),
        ...(f.approvedSerials.trim() ? { approvedSerials: f.approvedSerials.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean) } : {}),
      },
    };
    setBusy(true);
    try {
      if (existing) await androidApi.updateProfile(existing.id, body);
      else await androidApi.createProfile(body);
      toast.success(t('common.saved') || 'Saved');
      onSaved();
      onClose();
    } catch (err) {
      const details = apiErrorBody(err)?.details as { issues?: Array<{ code: string; field: string }> } | undefined;
      setIssues(Array.isArray(details?.issues) ? details!.issues : []);
      errorToast(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={target !== null} onClose={() => { if (!busy) onClose(); }} size="lg"
      title={existing ? (t('android.profiles.edit') || 'Edit the Android profile') : (t('android.profiles.new') || 'New Android profile')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void save()} disabled={busy || !f.name.trim()}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Labeled label={t('android.profiles.name') || 'Name'}>
          <input value={f.name} maxLength={200} onChange={(e) => up('name', e.target.value)} className={fieldClass} />
        </Labeled>
        <Labeled label={t('android.profiles.method') || 'Method'} hint={existing ? (t('android.profiles.methodFixed') || 'The method of a profile never changes.') : undefined}>
          <select value={f.method} disabled={!!existing} onChange={(e) => up('method', e.target.value as AndroidEnrollmentMethod)} className={fieldClass}>
            {ANDROID_ENROLLMENT_METHODS.map((m) => <option key={m} value={m}>{trCode(`mdm.enrollmentMethod.${m}`, m)}</option>)}
          </select>
        </Labeled>
        <Labeled label={t('android.profiles.ownership') || 'Ownership'}>
          <select value={f.ownership} onChange={(e) => up('ownership', e.target.value as Ownership)} className={fieldClass}>
            {owners.map((o) => <option key={o} value={o}>{trCode(`android.ownership.${o}`, o)}</option>)}
          </select>
        </Labeled>
        <Labeled label={t('android.profiles.group') || 'Group'}>
          <select value={f.groupId} onChange={(e) => up('groupId', e.target.value)} className={fieldClass}>
            <option value="">{t('android.profiles.noGroup') || '— none —'}</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </Labeled>
        <Labeled label={t('android.profiles.locale') || 'Language of the messages'}>
          <select value={f.locale} onChange={(e) => up('locale', e.target.value)} className={fieldClass}>
            {ENROLLMENT_LOCALES.map((l) => <option key={l} value={l}>{trCode(`android.locales.${l}`, l)}</option>)}
          </select>
        </Labeled>
        <Labeled label={t('android.profiles.googleAuth') || 'Google authentication at enrollment'}>
          <select value={f.googleAuth} onChange={(e) => up('googleAuth', e.target.value as ProfileForm['googleAuth'])} className={fieldClass}>
            {(['UNSPECIFIED', 'OPTIONAL', 'REQUIRED'] as const).map((g) => <option key={g} value={g}>{trCode(`android.profiles.googleAuthValues.${g}`, g)}</option>)}
          </select>
        </Labeled>
        <Labeled label={t('android.profiles.minimumApiLevel') || 'Minimum API level'} hint={f.ownership === 'corporate_personal' ? (t('android.profiles.copeMinApi') || '30 at least for a company device with a work profile.') : undefined}>
          <input type="number" min={21} max={40} value={f.minimumApiLevel} onChange={(e) => up('minimumApiLevel', e.target.value)} className={fieldClass} />
        </Labeled>
        {kioskPossible && (
          <Labeled label={t('android.profiles.usage') || 'Usage'}>
            <select value={f.deviceUsage} onChange={(e) => up('deviceUsage', e.target.value as ProfileForm['deviceUsage'])} className={fieldClass}>
              <option value="standard">{t('android.profiles.usageStandard') || 'Standard (one user)'}</option>
              <option value="kiosk">{t('android.profiles.usageKiosk') || 'Kiosk (dedicated device, no user)'}</option>
            </select>
          </Labeled>
        )}
        {kioskPossible && f.deviceUsage === 'kiosk' && (
          <Labeled label={t('android.profiles.kioskApp') || 'Kiosk app (package of the catalog)'}>
            <input value={f.kioskApp} maxLength={255} onChange={(e) => up('kioskApp', e.target.value)} className={`${fieldClass} font-mono`} spellCheck={false} />
          </Labeled>
        )}
        <Labeled label={t('android.profiles.requireApprovalLabel') || 'New devices wait for an approval (they stay disabled until then)'}>
          <select value={kioskPossible && f.deviceUsage === 'kiosk' ? 'yes' : f.requireApproval} disabled={kioskPossible && f.deviceUsage === 'kiosk'}
            onChange={(e) => up('requireApproval', e.target.value as ProfileForm['requireApproval'])} className={fieldClass}>
            <option value="default">{t('android.profiles.approvalDefault') || 'Default of the method (long tokens: yes)'}</option>
            <option value="yes">{t('android.common.yes') || 'Yes'}</option>
            <option value="no">{t('android.common.no') || 'No'}</option>
          </select>
        </Labeled>
        <div className="sm:col-span-2">
          <Labeled label={t('android.profiles.serials') || 'Serial numbers allowed (one per line; empty: any)'}>
            <textarea value={f.approvedSerials} rows={3} onChange={(e) => up('approvedSerials', e.target.value)} className={`${fieldClass} font-mono`} spellCheck={false} />
          </Labeled>
        </div>
        <label className="flex items-center gap-2 text-sm text-text-secondary sm:col-span-2">
          <input type="checkbox" checked={f.enabled} onChange={(e) => up('enabled', e.target.checked)} className="accent-accent" />
          {t('android.profiles.enabled') || 'Profile enabled (tokens can be created)'}
        </label>
      </div>
      {issues.length > 0 && (
        <ul className="mt-3 space-y-0.5 rounded border border-red-400/30 bg-red-400/5 p-2 text-sm text-red-400">
          {issues.map((i, n) => <li key={n}>{trCode(`errors.${i.code}`, i.code)}{i.field ? ` (${i.field})` : ''}</li>)}
        </ul>
      )}
    </Modal>
  );
}

// ── Token shown once (creation) or again (reveal) ───────────────────────────────

export function TokenDialog({ token, onClose }: { token: AndroidCreatedTokenView | null; onClose: () => void }) {
  const { t } = useTranslation();
  const p = token?.payload;
  return (
    <Modal open={token !== null} onClose={onClose} size="lg" title={t('android.tokens.shownTitle') || 'Android enrollment token'}
      footer={<Button onClick={onClose}>{t('common.close') || 'Close'}</Button>}>
      {token && p && (
        <div className="space-y-3 text-sm">
          <p className="rounded border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-text-secondary">
            {t('android.tokens.secretWarning') || 'Anyone holding this token can enroll a device in this tenant until it expires: hand it only to the people who enroll the devices. It is not shown again without a new audited request.'}
          </p>
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-3">
            <Fact label={t('android.tokens.kind') || 'Kind'}>{trCode(`android.tokens.kinds.${token.kind}`, token.kind)}</Fact>
            <Fact label={t('android.tokens.expires') || 'Expires'}>{dateOf(token.expiresAt)}</Fact>
            <Fact label={t('android.tokens.approval') || 'Approval'}>{token.requiresApproval ? (t('android.common.yes') || 'Yes') : (t('android.common.no') || 'No')}</Fact>
          </dl>
          {p.form === 'qr' && (
            <>
              {p.qrDataUrl && (
                <div className="flex justify-center">
                  <img src={p.qrDataUrl} alt={t('android.tokens.qrAlt') || 'QR code of the enrollment'} className="h-72 w-72 rounded bg-white p-2" />
                </div>
              )}
              <ol className="list-decimal space-y-0.5 pl-5 text-xs text-text-secondary">
                <li>{t('android.tokens.qrStep1') || 'On a new or reset device, tap the welcome screen six times to open the QR reader.'}</li>
                <li>{t('android.tokens.qrStep2') || 'Scan this code: the device connects, downloads Android Device Policy and enrolls.'}</li>
                <li>{t('android.tokens.afwStep') || 'Without a QR reader: at the Google account step, type afw#setup, then this value when asked for a code.'}</li>
              </ol>
              <CopyValue label={t('android.tokens.value') || 'Value to type (afw#setup, NFC)'} value={p.value} />
              <details>
                <summary className="cursor-pointer text-xs text-text-muted">{t('android.tokens.provisioningJson') || 'Provisioning JSON'}</summary>
                <CopyValue value={p.qrCode} multiline />
              </details>
            </>
          )}
          {(p.form === 'link' || p.form === 'signin') && <CopyValue label={t('android.tokens.link') || 'Enrollment link'} value={p.url} />}
          {p.form === 'kme' && <CopyValue label={t('android.tokens.kmeJson') || 'Custom JSON of the Knox profile'} value={p.json} multiline />}
          {p.form === 'zero_touch' && <CopyValue label={t('android.tokens.dpcExtras') || 'DPC extras of the zero-touch configuration'} value={p.dpcExtras} multiline />}
        </div>
      )}
    </Modal>
  );
}

function KmeDialog({ config, onClose }: { config: AndroidKmeConfiguration | null; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal open={config !== null} onClose={onClose} size="lg" title={t('android.kme.title') || 'Knox Mobile Enrollment'}
      footer={<Button onClick={onClose}>{t('common.close') || 'Close'}</Button>}>
      {config && (
        <div className="space-y-3 text-sm">
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
            <Fact label={t('android.kme.profileType') || 'Profile type in the Knox portal'}>{t('android.kme.androidEnterprise') || 'Android Enterprise'}</Fact>
            <Fact label={t('android.kme.dpc') || 'EMM agent'}><span className="font-mono">{config.dpcPackage}</span></Fact>
            <Fact label={t('android.tokens.expires') || 'Expires'}>{dateOf(config.expiresAt)}</Fact>
          </dl>
          <CopyValue label={t('android.tokens.kmeJson') || 'Custom JSON of the Knox profile'} value={config.customJson} multiline />
          {config.warnings.map((w) => <p key={w} className="text-xs text-amber-400">{trCode(`android.warnings.${w}`, w)}</p>)}
        </div>
      )}
    </Modal>
  );
}

/** Lifetimes offered for an invitation, in hours (7 days at most: AN17). */
const INVITATION_TTLS = [24, 72, ANDROID_BYOD_INVITATION_TTL_HOURS.max] as const;

function InvitationDialog({ profile, onClose, onPreview }: { profile: AndroidEnrollmentProfileView | null; onClose: () => void; onPreview: () => void }) {
  const { t, i18n } = useTranslation();
  const [users, setUsers] = useState<EndUser[]>([]);
  const [endUserId, setEndUserId] = useState('');
  const [label, setLabel] = useState('');
  const [email, setEmail] = useState('');
  const [ttlHours, setTtlHours] = useState<number>(ANDROID_BYOD_INVITATION_TTL_HOURS.dflt);
  const [locale, setLocale] = useState<'fr' | 'en'>('fr');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<AndroidByodInvitationCreated | null>(null);
  useEffect(() => {
    if (!profile) { setCreated(null); setEndUserId(''); setLabel(''); setEmail(''); setTtlHours(ANDROID_BYOD_INVITATION_TTL_HOURS.dflt); return; }
    setLocale(profile.locale === 'en' || (profile.locale !== 'fr' && i18n.language?.startsWith('en')) ? 'en' : 'fr');
    mdmApi.listEndUsers({ status: 'active', pageSize: 200 }).then((r) => setUsers(r.items)).catch(() => setUsers([]));
  }, [profile, i18n.language]);
  const pick = (id: string) => {
    setEndUserId(id);
    // The user's address by default (still editable, never stored by the server).
    const u = users.find((x) => String(x.id) === id);
    if (u?.email && !email.trim()) setEmail(u.email);
  };
  const create = async () => {
    if (!profile) return;
    setBusy(true);
    try {
      setCreated(await androidApi.createByodInvitation({
        profileId: profile.id, endUserId: Number(endUserId), ttlHours, locale,
        ...(label.trim() ? { label: label.trim() } : {}), ...(email.trim() ? { email: email.trim() } : {}),
      }));
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <Modal open={profile !== null} onClose={onClose} size="md" title={t('android.byod.inviteTitle') || 'Invite to a personal device enrollment'}
      footer={created ? <Button onClick={onClose}>{t('common.close') || 'Close'}</Button> : (
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={busy || !endUserId} onClick={() => void create()}>{t('android.byod.create') || 'Create the invitation'}</Button>
        </>
      )}>
      {created ? (
        <div className="space-y-3 text-sm">
          <p className="text-xs text-text-secondary">{t('android.byod.codeOnce') || 'The code is shown once: give it to the user with the link.'}</p>
          <CopyValue label={t('android.byod.code') || 'Code'} value={created.code} />
          <CopyValue label={t('android.byod.link') || 'Link'} value={created.link} />
          <p className="text-xs text-text-muted">{t('android.byod.expiresAt', { date: dateOf(created.expiresAt) }) || `Expires ${dateOf(created.expiresAt)}`}</p>
          <p className="text-xs text-text-muted">{trCode(`android.byod.mail.${created.mail}`, created.mail)}</p>
        </div>
      ) : (
        <div className="space-y-3">
          <Labeled label={t('android.byod.endUser') || 'User'}>
            <select value={endUserId} onChange={(e) => pick(e.target.value)} className={fieldClass}>
              <option value="">{t('android.byod.chooseUser') || '— choose —'}</option>
              {users.map((u) => <option key={u.id} value={u.id}>{anonymize(u.displayName ?? u.email ?? `#${u.id}`)}</option>)}
            </select>
          </Labeled>
          <Labeled label={t('android.byod.label') || 'Label (optional)'}>
            <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={100} className={fieldClass} />
          </Labeled>
          <Labeled label={t('android.byod.email') || 'Send to (optional)'}>
            <input value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} type="email" className={fieldClass} />
          </Labeled>
          <div className="grid grid-cols-2 gap-3">
            <Labeled label={t('android.byod.ttl') || 'Valid for'}>
              <select value={ttlHours} onChange={(e) => setTtlHours(Number(e.target.value))} className={fieldClass}>
                {INVITATION_TTLS.map((h) => <option key={h} value={h}>{t(`android.byod.ttlOptions.h${h}`) || `${h / 24} d`}</option>)}
              </select>
            </Labeled>
            <Labeled label={t('android.byod.locale') || 'Language of the notice and the e-mail'}>
              <select value={locale} onChange={(e) => setLocale(e.target.value === 'en' ? 'en' : 'fr')} className={fieldClass}>
                <option value="fr">{t('android.byod.locales.fr') || 'French'}</option>
                <option value="en">{t('android.byod.locales.en') || 'English'}</option>
              </select>
            </Labeled>
          </div>
          <p className="text-xs text-text-muted">{t('android.byod.singleUse') || 'Single use: once a device has enrolled with it, the code serves no more. The user accepts the privacy notice on the device before the Google enrollment.'}</p>
          <Button size="sm" variant="secondary" onClick={onPreview}>
            <FileText className="w-3.5 h-3.5 mr-1" />{t('android.byod.noticePreview') || 'Notice shown to the user'}
          </Button>
        </div>
      )}
    </Modal>
  );
}

/** The notice of a personal device, exactly as the device surface shows it before the Google link (plain text). */
function NoticeDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const [locale, setLocale] = useState<'fr' | 'en'>('fr');
  const [notice, setNotice] = useState<AndroidByodNoticeView | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => { if (open) setLocale(i18n.language?.startsWith('en') ? 'en' : 'fr'); }, [open, i18n.language]);
  useEffect(() => {
    if (!open) { setNotice(null); setFailed(false); return; }
    let live = true;
    androidApi.byodNotice(locale).then((n) => { if (live) { setNotice(n); setFailed(false); } }).catch(() => { if (live) { setNotice(null); setFailed(true); } });
    return () => { live = false; };
  }, [open, locale]);
  return (
    <Modal open={open} onClose={onClose} size="lg" title={t('android.byod.noticePreview') || 'Notice shown to the user'}
      footer={<Button onClick={onClose}>{t('common.close') || 'Close'}</Button>}>
      <div className="space-y-3 text-sm">
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-muted">{t('android.byod.noticeIntro') || 'The user reads and accepts this notice on the device before the Google enrollment; the acceptance is recorded with its version.'}</span>
          <select value={locale} onChange={(e) => setLocale(e.target.value === 'en' ? 'en' : 'fr')} className={`${fieldClass} ml-auto w-auto`}>
            <option value="fr">{t('android.byod.locales.fr') || 'French'}</option>
            <option value="en">{t('android.byod.locales.en') || 'English'}</option>
          </select>
        </div>
        {failed && <p className="text-text-muted">{t('errors.androidByodNoticeUnavailable') || 'The notice is not available.'}</p>}
        {notice && (
          <article className="space-y-3 rounded-lg bg-bg-secondary p-3" lang={notice.locale}>
            <h3 className="font-semibold text-text-primary">{notice.title}</h3>
            {notice.sections.map((sec, i) => (
              <section key={i} className="space-y-1">
                <h4 className="font-medium text-text-primary">{sec.heading}</h4>
                {sec.paragraphs.map((para, j) => <p key={j} className="text-text-secondary">{para}</p>)}
              </section>
            ))}
            {notice.contact && <p className="text-text-secondary">{notice.contact}</p>}
            <p className="text-text-secondary italic">{notice.consentSummary}</p>
            <p className="text-xs text-text-muted font-mono">{t('android.byod.noticeVersion', { version: notice.versionId }) || `Version ${notice.versionId}`}</p>
          </article>
        )}
      </div>
    </Modal>
  );
}
