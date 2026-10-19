import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Archive, Copy, Link2, Mail, Pencil, Plus, RefreshCw, Search, Ticket, XCircle } from 'lucide-react';
import {
  ENROLLMENT_LIMITS, ENROLLMENT_METHOD_OWNERSHIPS, ENROLLMENT_PROFILE_METHODS, ENROLLMENT_SESSION_STATES, ENROLLMENT_TOKEN_STATES,
  SocketEvents,
  type AdeDeviceView, type DeviceGroup, type EnrollmentInvitationCreated, type EnrollmentLinkCreated, type EnrollmentMailOutcome, type EnrollmentProfileInput,
  type EnrollmentProfileMethod, type EnrollmentProfileSettings, type EnrollmentProfileView, type EnrollmentSessionState,
  type EnrollmentSessionView, type EnrollmentTokenKind, type EnrollmentTokenState, type EnrollmentTokenView, type Ownership,
} from '@obligarth/shared';
import { enrollmentApi } from '@/api/enrollment.api';
import { groupsApi } from '@/api/groups.api';
import { isStepUpHandled } from '@/api/client';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { registerSocketListener } from '@/socket/socketListeners';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import { integrationsApi } from '@/api/integrations.api';
import { ReadinessPanel } from '@/pages/IntegrationsPage';
import { UnknownEnrollmentsTab } from '@/components/mdm/UnknownEnrollmentsTab';
import type { ReadinessItem } from '@obligarth/shared';

// Device enrollment (integration-apple-edge §10.9, lot C1): enrollment profiles, OTA links (URL and QR code
// shown once), invitations of an account-driven enrollment (code and link shown once, e-mailed when a channel is
// configured), revocation, sessions. Lot C2: the ADE settings of a profile and where it is defined at Apple, the
// devices of Apple Business and the enrollment profile chosen for each (§10.6). Tenant capability
// mdm.enrollment.manage. Lot C5: the enrollments apple-edge holds that no record of the tenant holds, to attach to an
// enrollment profile (the record is born with its ownership) or to release (§13.1, §13.2).

type Tab = 'profiles' | 'tokens' | 'sessions' | 'ade' | 'unknown';
const METHOD_FALLBACK: Record<EnrollmentProfileMethod, string> = { ota: 'Link or QR code (OTA)', ade: 'Automated (ADE)', byod_account: 'Personal device (account)' };
const OWNERSHIP_FALLBACK: Record<Ownership, string> = { corporate: 'Corporate', corporate_personal: 'Corporate, personal use', personal: 'Personal' };
const TOKEN_TONE: Record<EnrollmentTokenState, 'green' | 'gray' | 'amber' | 'red'> = { active: 'green', exhausted: 'gray', expired: 'amber', revoked: 'red' };
const SESSION_TONE: Record<EnrollmentSessionState, 'green' | 'gray' | 'blue' | 'amber' | 'red' | 'violet'> = {
  started: 'gray', acknowledged: 'blue', profile_issued: 'blue', certificate_issued: 'violet', authenticated: 'violet', enrolled: 'green', failed: 'red', expired: 'amber',
};

const fieldCls = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';

function useLabels() {
  const { t } = useTranslation();
  return {
    method: (m: EnrollmentProfileMethod) => trCode(`deviceEnrollment.method.${m}`, METHOD_FALLBACK[m]),
    ownership: (o: Ownership) => trCode(`deviceEnrollment.ownership.${o}`, OWNERSHIP_FALLBACK[o]),
    tokenState: (s: EnrollmentTokenState) => trCode(`deviceEnrollment.tokenState.${s}`, s),
    sessionState: (s: EnrollmentSessionState) => trCode(`deviceEnrollment.sessionState.${s}`, s),
    kind: (k: EnrollmentTokenKind) => (k === 'link' ? (t('deviceEnrollment.kind.link') || 'Link') : (t('deviceEnrollment.kind.invitation') || 'Invitation')),
    mail: (m: EnrollmentMailOutcome) => trCode(`deviceEnrollment.mail.${m}`, m),
  };
}

async function copy(text: string, done: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(done);
  } catch { /* the field stays selectable */ }
}

export function DeviceEnrollmentPage() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>('profiles');
  // The readiness of the tenant (§11.5, lot C3): what is not ready yet, when the user may read it.
  const [readiness, setReadiness] = useState<ReadinessItem[] | null>(null);
  useEffect(() => { integrationsApi.readiness().then(setReadiness).catch(() => setReadiness(null)); }, []);
  return (
    <PageContainer className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('deviceEnrollment.title') || 'Device enrollment'}</h1>
        <p className="mt-1 text-sm text-text-muted">
          {t('deviceEnrollment.subtitle') || 'Enrollment profiles, links and invitations, and the enrollments in progress.'}
        </p>
      </div>
      {readiness && <ReadinessPanel items={readiness} compact />}
      <div className="flex gap-1 border-b border-border">
        {(['profiles', 'tokens', 'sessions', 'ade', 'unknown'] as const).map((k) => (
          <button key={k} type="button" onClick={() => setTab(k)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px coarse:min-h-10 ${tab === k ? 'border-accent text-accent' : 'border-transparent text-text-muted hover:text-text-primary'}`}>
            {k === 'profiles' ? (t('deviceEnrollment.tabs.profiles') || 'Profiles')
              : k === 'tokens' ? (t('deviceEnrollment.tabs.tokens') || 'Links and invitations')
                : k === 'sessions' ? (t('deviceEnrollment.tabs.sessions') || 'Sessions')
                  : k === 'ade' ? (t('deviceEnrollment.tabs.ade') || 'Apple Business devices')
                    : (t('deviceEnrollment.tabs.unknown') || 'Without session')}
          </button>
        ))}
      </div>
      {tab === 'profiles' && <ProfilesTab />}
      {tab === 'tokens' && <TokensTab />}
      {tab === 'sessions' && <SessionsTab />}
      {tab === 'ade' && <AdeDevicesTab />}
      {tab === 'unknown' && <UnknownEnrollmentsTab />}
    </PageContainer>
  );
}

// ── Profiles ─────────────────────────────────────────────────────────────────────

function ProfilesTab() {
  const { t } = useTranslation();
  const L = useLabels();
  const confirm = useConfirm();
  const [archived, setArchived] = useState(false);
  const [rows, setRows] = useState<EnrollmentProfileView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<EnrollmentProfileView | 'new' | null>(null);
  const [linkFor, setLinkFor] = useState<EnrollmentProfileView | null>(null);
  const [inviteFor, setInviteFor] = useState<EnrollmentProfileView | null>(null);

  const load = useCallback(() => {
    enrollmentApi.profiles(archived)
      .then((r) => { setRows(r); setError(null); })
      .catch((err) => { setRows([]); setError(apiErrorMessage(err)); });
  }, [archived]);
  useEffect(() => { load(); }, [load]);

  const archive = async (p: EnrollmentProfileView) => {
    const ok = await confirm({
      message: t('deviceEnrollment.confirmArchive', { name: p.name }) || `Archive the profile ${p.name}? Its links and invitations stop working.`,
      danger: true,
    });
    if (!ok) return;
    try {
      await enrollmentApi.archiveProfile(p.id);
      toast.success(t('deviceEnrollment.archived') || 'Profile archived');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-2 text-xs text-text-muted">
          <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} />
          {t('deviceEnrollment.showArchived') || 'Show archived profiles'}
        </label>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
        <span className="ml-auto">
          <Button size="sm" onClick={() => setEditing('new')}><Plus className="w-4 h-4 mr-1" />{t('deviceEnrollment.newProfile') || 'New profile'}</Button>
        </span>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? (
          <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">{t('deviceEnrollment.noProfile') || 'No enrollment profile yet.'}</div>
        ) : (
          <div className="overflow-x-auto rounded-xl bg-bg-secondary">
            <table className="w-full text-sm">
              <thead className="text-xs text-text-muted">
                <tr className="text-left">
                  <th className="font-medium px-4 py-2">{t('deviceEnrollment.name') || 'Name'}</th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.methodLabel') || 'Method'}</th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.ownershipLabel') || 'Ownership'}</th>
                  <th className="font-medium px-3 py-2">{t('deviceEnrollment.defaultGroup') || 'Default group'}</th>
                  <th className="font-medium px-3 py-2 text-right">{t('deviceEnrollment.activeTokens') || 'Usable links'}</th>
                  <th className="font-medium px-3 py-2">{t('common.status') || 'Status'}</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr key={p.id} className="border-t border-border/50">
                    <td className="px-4 py-2.5 text-text-primary">
                      {p.name}
                      <span className="block text-[10px] text-text-muted">v{p.version}{p.usage ? ` · ${p.usage}` : ''}{p.isDefault ? ` · ${t('deviceEnrollment.isDefault') || 'default'}` : ''}</span>
                      {p.method === 'ade' && !p.archivedAt && <AdeBindingLine profile={p} />}
                    </td>
                    <td className="px-3 py-2.5 text-text-secondary">{L.method(p.method)}</td>
                    <td className="px-3 py-2.5 text-text-secondary">{L.ownership(p.ownership)}</td>
                    <td className="px-3 py-2.5 text-text-secondary">{p.defaultGroupName ?? <span className="text-text-muted">—</span>}</td>
                    <td className="px-3 py-2.5 text-right tabular-nums">{p.activeTokens}</td>
                    <td className="px-3 py-2.5">
                      {p.archivedAt
                        ? <StateBadge tone="gray" label={t('deviceEnrollment.archivedLabel') || 'Archived'} />
                        : p.enabled
                          ? <StateBadge tone="green" label={t('deviceEnrollment.enabled') || 'Active'} />
                          : <StateBadge tone="amber" label={t('deviceEnrollment.disabled') || 'Disabled'} />}
                    </td>
                    <td className="px-3 py-2.5">
                      {!p.archivedAt && (
                        <span className="flex justify-end gap-1">
                          {p.method === 'ota' && p.enabled && (
                            <IconButton label={t('deviceEnrollment.newLink') || 'New link'} onClick={() => setLinkFor(p)}><Link2 className="w-4 h-4" /></IconButton>
                          )}
                          {p.method === 'byod_account' && p.enabled && (
                            <IconButton label={t('deviceEnrollment.newInvitation') || 'New invitation'} onClick={() => setInviteFor(p)}><Ticket className="w-4 h-4" /></IconButton>
                          )}
                          <IconButton label={t('common.edit') || 'Edit'} onClick={() => setEditing(p)}><Pencil className="w-4 h-4" /></IconButton>
                          <IconButton label={t('deviceEnrollment.archive') || 'Archive'} danger onClick={() => { void archive(p); }}><Archive className="w-4 h-4" /></IconButton>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      <ProfileDialog target={editing} onClose={() => setEditing(null)} onSaved={load} />
      <LinkDialog profile={linkFor} onClose={() => { setLinkFor(null); load(); }} />
      <InvitationDialog profile={inviteFor} onClose={() => { setInviteFor(null); load(); }} />
    </div>
  );
}

function IconButton({ label, onClick, children, danger = false }: { label: string; onClick: () => void; children: React.ReactNode; danger?: boolean }) {
  return (
    <button type="button" onClick={onClick} aria-label={label} title={label}
      className={`p-1.5 rounded text-text-muted hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10 ${danger ? 'hover:text-red-400' : 'hover:text-text-primary'}`}>
      {children}
    </button>
  );
}

interface ProfileForm {
  name: string;
  method: EnrollmentProfileMethod;
  ownership: Ownership;
  usage: string;
  defaultGroupId: string;
  noticeRequired: boolean;
  locale: 'fr' | 'en';
  enabled: boolean;
  isDefault: boolean;
  deviceNameTemplate: string;
  linkTtlHours: string;
  linkMaxUses: string;
  invitationTtlHours: string;
  webAuth: boolean;
  supportPhone: string;
  supportEmail: string;
  department: string;
  minOsIos: string;
  minOsIpados: string;
  skipSetupItems: string;
  adeLanguage: string;
  adeRegion: string;
}

function formOf(p: EnrollmentProfileView | null): ProfileForm {
  const s = p?.settings ?? {};
  return {
    name: p?.name ?? '', method: p?.method ?? 'ota', ownership: p?.ownership ?? 'corporate', usage: p?.usage ?? '',
    defaultGroupId: p?.defaultGroupId ? String(p.defaultGroupId) : '', noticeRequired: p?.noticeRequired ?? true,
    locale: p?.locale === 'en' ? 'en' : 'fr', enabled: p?.enabled ?? true, isDefault: p?.isDefault ?? false,
    deviceNameTemplate: s.deviceNameTemplate ?? '',
    linkTtlHours: String(s.linkTtlHours ?? ENROLLMENT_LIMITS.linkTtlHours.default),
    linkMaxUses: String(s.linkMaxUses ?? ENROLLMENT_LIMITS.linkMaxUses.default),
    invitationTtlHours: String(s.invitationTtlHours ?? ENROLLMENT_LIMITS.invitationTtlHours.default),
    webAuth: s.webAuth ?? true, supportPhone: s.supportPhone ?? '', supportEmail: s.supportEmail ?? '', department: s.department ?? '',
    minOsIos: s.minOsVersion?.ios ?? '', minOsIpados: s.minOsVersion?.ipados ?? '',
    skipSetupItems: s.skipSetupItems ? s.skipSetupItems.join(', ') : '', adeLanguage: s.language ?? '', adeRegion: s.region ?? '',
  };
}

function inputOf(f: ProfileForm, existing: EnrollmentProfileView | null): EnrollmentProfileInput {
  const settings: EnrollmentProfileSettings = { ...(existing?.method === f.method ? existing.settings : {}) };
  const set = <K extends keyof EnrollmentProfileSettings>(k: K, v: EnrollmentProfileSettings[K] | undefined) => {
    if (v === undefined || v === '') delete settings[k]; else settings[k] = v;
  };
  set('deviceNameTemplate', f.deviceNameTemplate.trim() || undefined);
  if (f.method === 'ota') {
    set('linkTtlHours', Number(f.linkTtlHours));
    set('linkMaxUses', Number(f.linkMaxUses));
  } else if (f.method === 'byod_account') {
    set('invitationTtlHours', Number(f.invitationTtlHours));
  } else {
    set('webAuth', f.webAuth);
    set('supportPhone', f.supportPhone.trim() || undefined);
    set('supportEmail', f.supportEmail.trim() || undefined);
    set('department', f.department.trim() || undefined);
    const ios = f.minOsIos.trim();
    const ipados = f.minOsIpados.trim();
    set('minOsVersion', ios || ipados ? { ...(ios ? { ios } : {}), ...(ipados ? { ipados } : {}) } : undefined);
    const items = f.skipSetupItems.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
    set('skipSetupItems', f.skipSetupItems.trim() ? items : undefined);
    set('language', f.adeLanguage.trim().toLowerCase() || undefined);
    set('region', f.adeRegion.trim().toUpperCase() || undefined);
  }
  return {
    name: f.name.trim(), method: f.method, ownership: f.ownership, usage: f.method === 'ade' ? (f.usage.trim() || null) : null,
    defaultGroupId: f.defaultGroupId ? Number(f.defaultGroupId) : null, noticeRequired: f.method === 'ade' ? f.noticeRequired : true,
    locale: f.locale, settings, isDefault: f.method === 'ade' ? f.isDefault : false, enabled: f.enabled,
  };
}

function ProfileDialog({ target, onClose, onSaved }: { target: EnrollmentProfileView | 'new' | null; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation();
  const L = useLabels();
  const existing = target && target !== 'new' ? target : null;
  const [f, setF] = useState<ProfileForm>(formOf(null));
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (target === null) return;
    setF(formOf(existing));
    groupsApi.list().then(setGroups).catch(() => setGroups([]));
  }, [target]); // eslint-disable-line react-hooks/exhaustive-deps
  const up = <K extends keyof ProfileForm>(k: K, v: ProfileForm[K]) => setF((prev) => ({ ...prev, [k]: v }));
  const owners = ENROLLMENT_METHOD_OWNERSHIPS[f.method];
  useEffect(() => { if (!owners.includes(f.ownership)) up('ownership', owners[0]); }, [f.method]); // eslint-disable-line react-hooks/exhaustive-deps
  const save = async () => {
    setBusy(true);
    try {
      const body = inputOf(f, existing);
      if (existing) await enrollmentApi.updateProfile(existing.id, body);
      else await enrollmentApi.createProfile(body);
      toast.success(t('common.saved') || 'Saved');
      onSaved();
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const num = (k: 'linkTtlHours' | 'linkMaxUses' | 'invitationTtlHours', label: string, min: number, max: number, hint?: string) => (
    <label className="block">
      <span className="text-xs text-text-muted">{label}</span>
      <input type="number" min={min} max={max} value={f[k]} onChange={(e) => up(k, e.target.value)} className={fieldCls} />
      {hint && <span className="text-[11px] text-text-muted">{hint}</span>}
    </label>
  );
  const text = (k: 'name' | 'usage' | 'deviceNameTemplate' | 'supportPhone' | 'supportEmail' | 'department' | 'minOsIos' | 'minOsIpados'
    | 'skipSetupItems' | 'adeLanguage' | 'adeRegion', label: string, max: number, hint?: string) => (
    <label className="block">
      <span className="text-xs text-text-muted">{label}</span>
      <input type="text" value={f[k]} maxLength={max} onChange={(e) => up(k, e.target.value)} autoCapitalize="off" spellCheck={false} className={fieldCls} />
      {hint && <span className="text-[11px] text-text-muted">{hint}</span>}
    </label>
  );
  const LIM = ENROLLMENT_LIMITS;
  return (
    <Modal open={target !== null} onClose={() => { if (!busy) onClose(); }} size="lg"
      title={existing ? (t('deviceEnrollment.editProfile') || 'Edit the enrollment profile') : (t('deviceEnrollment.newProfile') || 'New profile')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy} disabled={!f.name.trim() || (f.method === 'ade' && !f.usage.trim())}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="grid gap-3 sm:grid-cols-2 text-sm">
        {text('name', t('deviceEnrollment.name') || 'Name', 200)}
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceEnrollment.methodLabel') || 'Method'}</span>
          <select value={f.method} disabled={!!existing} onChange={(e) => up('method', e.target.value as EnrollmentProfileMethod)} className={fieldCls}>
            {ENROLLMENT_PROFILE_METHODS.map((m) => <option key={m} value={m}>{L.method(m)}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceEnrollment.ownershipLabel') || 'Ownership'}</span>
          <select value={f.ownership} onChange={(e) => up('ownership', e.target.value as Ownership)} className={fieldCls}>
            {owners.map((o) => <option key={o} value={o}>{L.ownership(o)}</option>)}
          </select>
          <span className="text-[11px] text-text-muted">{t('deviceEnrollment.ownershipHint') || 'Chosen before the enrollment; it decides what is collected.'}</span>
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceEnrollment.defaultGroup') || 'Default group'}</span>
          <select value={f.defaultGroupId} onChange={(e) => up('defaultGroupId', e.target.value)} className={fieldCls}>
            <option value="">{t('deviceEnrollment.noGroup') || 'No group'}</option>
            {groups.map((g) => <option key={g.id} value={String(g.id)}>{g.name}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('deviceEnrollment.locale') || 'Language of the pages and of the profile'}</span>
          <select value={f.locale} onChange={(e) => up('locale', e.target.value as 'fr' | 'en')} className={fieldCls}>
            <option value="fr">Français</option>
            <option value="en">English</option>
          </select>
        </label>
        {text('deviceNameTemplate', t('deviceEnrollment.deviceNameTemplate') || 'Device name template', 63,
          t('deviceEnrollment.deviceNameTemplateHint') || 'Variables {serial}, {model}, {n}; never a value of the employee.')}
        {f.method === 'ota' && (
          <>
            {num('linkTtlHours', t('deviceEnrollment.linkTtlHours') || 'Link lifetime (hours)', LIM.linkTtlHours.min, LIM.linkTtlHours.max)}
            {num('linkMaxUses', t('deviceEnrollment.linkMaxUses') || 'Uses of a link', LIM.linkMaxUses.min, LIM.linkMaxUses.max,
              t('deviceEnrollment.linkMaxUsesHint') || 'One by default: a link for several devices is an explicit choice.')}
          </>
        )}
        {f.method === 'byod_account' && num('invitationTtlHours', t('deviceEnrollment.invitationTtlHours') || 'Invitation lifetime (hours)',
          LIM.invitationTtlHours.min, LIM.invitationTtlHours.max)}
        {f.method === 'ade' && (
          <>
            {text('usage', t('deviceEnrollment.usage') || 'ADE usage key', 32, t('deviceEnrollment.usageHint') || 'Lower case letters, digits and _ (standard, kiosk…).')}
            {text('supportPhone', t('deviceEnrollment.supportPhone') || 'Support phone', 40)}
            {text('supportEmail', t('deviceEnrollment.supportEmail') || 'Support e-mail', 320)}
            {text('department', t('deviceEnrollment.department') || 'Department', 100)}
            {text('minOsIos', t('deviceEnrollment.minOsIos') || 'Minimum iOS version', 8, t('deviceEnrollment.minOsHint') || 'For example 17.6; older devices are asked to update in the setup assistant.')}
            {text('minOsIpados', t('deviceEnrollment.minOsIpados') || 'Minimum iPadOS version', 8)}
            {text('adeLanguage', t('deviceEnrollment.adeLanguage') || 'Language of the setup assistant', 2, t('deviceEnrollment.adeLanguageHint') || 'Two letters (fr by default).')}
            {text('adeRegion', t('deviceEnrollment.adeRegion') || 'Region of the setup assistant', 2, t('deviceEnrollment.adeRegionHint') || 'Two letters (FR by default).')}
            <div className="sm:col-span-2">
              {text('skipSetupItems', t('deviceEnrollment.skipSetupItems') || 'Setup assistant panes skipped', 1200,
                t('deviceEnrollment.skipSetupItemsHint') || 'Keys of Apple, separated by commas (Location, Siri, Privacy…); empty: the recommended list.')}
            </div>
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              <input type="checkbox" checked={f.noticeRequired} onChange={(e) => up('noticeRequired', e.target.checked)} />
              {t('deviceEnrollment.noticeRequired') || 'Show the employee notice (turn off for kiosks only)'}
            </label>
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              <input type="checkbox" checked={f.webAuth} onChange={(e) => up('webAuth', e.target.checked)} />
              {t('deviceEnrollment.webAuth') || 'Web view during the setup assistant'}
            </label>
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              <input type="checkbox" checked={f.isDefault} onChange={(e) => up('isDefault', e.target.checked)} />
              {t('deviceEnrollment.isDefaultLabel') || 'Default ADE profile of the tenant'}
            </label>
          </>
        )}
        <label className="flex items-center gap-2 text-xs text-text-secondary">
          <input type="checkbox" checked={f.enabled} onChange={(e) => up('enabled', e.target.checked)} />
          {t('deviceEnrollment.enabledLabel') || 'Enrollments allowed'}
        </label>
      </div>
    </Modal>
  );
}

function MailOutcome({ mail }: { mail: EnrollmentMailOutcome }) {
  const L = useLabels();
  if (mail === 'not_requested') return null;
  const tone = mail === 'sent' ? 'text-green-400' : mail === 'failed' ? 'text-red-400' : 'text-amber-400';
  return <p className={`text-xs flex items-center gap-1 ${tone}`}><Mail className="w-3.5 h-3.5" />{L.mail(mail)}</p>;
}

function LinkDialog({ profile, onClose }: { profile: EnrollmentProfileView | null; onClose: () => void }) {
  const { t } = useTranslation();
  const [label, setLabel] = useState('');
  const [maxUses, setMaxUses] = useState('1');
  const [ttl, setTtl] = useState('72');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<EnrollmentLinkCreated | null>(null);
  useEffect(() => {
    if (!profile) return;
    setLabel(''); setEmail(''); setCreated(null);
    setMaxUses(String(profile.settings.linkMaxUses ?? ENROLLMENT_LIMITS.linkMaxUses.default));
    setTtl(String(profile.settings.linkTtlHours ?? ENROLLMENT_LIMITS.linkTtlHours.default));
  }, [profile]);
  const create = async () => {
    if (!profile) return;
    setBusy(true);
    try {
      setCreated(await enrollmentApi.createLink(profile.id, {
        label: label.trim() || null, maxUses: Number(maxUses), ttlHours: Number(ttl), ...(email.trim() ? { email: email.trim() } : {}),
      }));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open={profile !== null} onClose={() => { if (!busy) onClose(); }} size="md" title={t('deviceEnrollment.newLink') || 'New link'}
      footer={created
        ? <Button onClick={onClose}>{t('common.close') || 'Close'}</Button>
        : (
          <>
            <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
            <Button onClick={create} loading={busy}>{t('deviceEnrollment.create') || 'Create'}</Button>
          </>
        )}>
      {created ? (
        <div className="space-y-3 text-sm">
          <p className="text-amber-400 text-xs">{t('deviceEnrollment.shownOnce') || 'Shown only once: copy it now. The console keeps only its prefix.'}</p>
          <div className="flex justify-center"><img src={created.qrPng} alt={t('deviceEnrollment.qrAlt') || 'QR code of the enrollment link'} className="w-48 h-48 bg-white rounded" /></div>
          <div className="flex gap-2">
            <input readOnly value={created.url} onFocus={(e) => e.target.select()} className={`${fieldCls} font-mono text-xs`} />
            <Button size="sm" variant="secondary" onClick={() => { void copy(created.url, t('common.copied') || 'Copied'); }}><Copy className="w-4 h-4" /></Button>
          </div>
          <p className="text-xs text-text-muted">
            {t('deviceEnrollment.linkFacts', { uses: created.maxUses, expires: formatDateTime(created.expiresAt) })
              || `${created.maxUses} use(s), expires ${formatDateTime(created.expiresAt)}`}
          </p>
          <MailOutcome mail={created.mail} />
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          <label className="block">
            <span className="text-xs text-text-muted">{t('deviceEnrollment.label') || 'Label (optional)'}</span>
            <input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} className={fieldCls} />
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs text-text-muted">{t('deviceEnrollment.linkMaxUses') || 'Uses of a link'}</span>
              <input type="number" min={1} max={ENROLLMENT_LIMITS.linkMaxUses.max} value={maxUses} onChange={(e) => setMaxUses(e.target.value)} className={fieldCls} />
            </label>
            <label className="block">
              <span className="text-xs text-text-muted">{t('deviceEnrollment.linkTtlHours') || 'Link lifetime (hours)'}</span>
              <input type="number" min={1} max={ENROLLMENT_LIMITS.linkTtlHours.max} value={ttl} onChange={(e) => setTtl(e.target.value)} className={fieldCls} />
            </label>
          </div>
          <label className="block">
            <span className="text-xs text-text-muted">{t('deviceEnrollment.emailTo') || 'Send by e-mail to (optional)'}</span>
            <input type="email" value={email} maxLength={320} onChange={(e) => setEmail(e.target.value)} autoCapitalize="off" spellCheck={false} className={fieldCls} />
            <span className="text-[11px] text-text-muted">{t('deviceEnrollment.emailHint') || 'Sent when an SMTP server is configured for the tenant or the platform.'}</span>
          </label>
        </div>
      )}
    </Modal>
  );
}

function InvitationDialog({ profile, onClose }: { profile: EnrollmentProfileView | null; onClose: () => void }) {
  const { t } = useTranslation();
  const [account, setAccount] = useState('');
  const [label, setLabel] = useState('');
  const [ttl, setTtl] = useState('168');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<EnrollmentInvitationCreated | null>(null);
  useEffect(() => {
    if (!profile) return;
    setAccount(''); setLabel(''); setEmail(''); setCreated(null);
    setTtl(String(profile.settings.invitationTtlHours ?? ENROLLMENT_LIMITS.invitationTtlHours.default));
  }, [profile]);
  const create = async () => {
    if (!profile) return;
    setBusy(true);
    try {
      setCreated(await enrollmentApi.createInvitation(profile.id, {
        managedAppleAccount: account.trim(), label: label.trim() || null, ttlHours: Number(ttl), ...(email.trim() ? { email: email.trim() } : {}),
      }));
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open={profile !== null} onClose={() => { if (!busy) onClose(); }} size="md" title={t('deviceEnrollment.newInvitation') || 'New invitation'}
      footer={created
        ? <Button onClick={onClose}>{t('common.close') || 'Close'}</Button>
        : (
          <>
            <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
            <Button onClick={create} loading={busy} disabled={!account.trim()}>{t('deviceEnrollment.create') || 'Create'}</Button>
          </>
        )}>
      {created ? (
        <div className="space-y-3 text-sm">
          <p className="text-amber-400 text-xs">{t('deviceEnrollment.shownOnce') || 'Shown only once: copy it now. The console keeps only its prefix.'}</p>
          <div className="text-center">
            <div className="text-xs text-text-muted">{t('deviceEnrollment.invitationCode') || 'Invitation code'}</div>
            <div className="font-mono text-2xl tracking-widest text-text-primary select-all">{created.code}</div>
          </div>
          <div className="flex gap-2">
            <input readOnly value={created.link} onFocus={(e) => e.target.select()} className={`${fieldCls} font-mono text-xs`} />
            <Button size="sm" variant="secondary" onClick={() => { void copy(`${created.code}\n${created.link}`, t('common.copied') || 'Copied'); }}><Copy className="w-4 h-4" /></Button>
          </div>
          <p className="text-xs text-text-muted">
            {t('deviceEnrollment.invitationFacts', { expires: formatDateTime(created.expiresAt) })
              || `Single use, expires ${formatDateTime(created.expiresAt)}. The link shows the steps to the employee.`}
          </p>
          <MailOutcome mail={created.mail} />
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          <label className="block">
            <span className="text-xs text-text-muted">{t('deviceEnrollment.managedAppleAccount') || 'Managed Apple Account'}</span>
            <input type="email" value={account} maxLength={320} onChange={(e) => setAccount(e.target.value)} autoCapitalize="off" spellCheck={false} className={fieldCls} />
          </label>
          <label className="block">
            <span className="text-xs text-text-muted">{t('deviceEnrollment.label') || 'Label (optional)'}</span>
            <input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} className={fieldCls} />
          </label>
          <label className="block">
            <span className="text-xs text-text-muted">{t('deviceEnrollment.invitationTtlHours') || 'Invitation lifetime (hours)'}</span>
            <input type="number" min={1} max={ENROLLMENT_LIMITS.invitationTtlHours.max} value={ttl} onChange={(e) => setTtl(e.target.value)} className={fieldCls} />
          </label>
          <label className="block">
            <span className="text-xs text-text-muted">{t('deviceEnrollment.emailTo') || 'Send by e-mail to (optional)'}</span>
            <input type="email" value={email} maxLength={320} onChange={(e) => setEmail(e.target.value)} autoCapitalize="off" spellCheck={false} className={fieldCls} />
            <span className="text-[11px] text-text-muted">{t('deviceEnrollment.emailHint') || 'Sent when an SMTP server is configured for the tenant or the platform.'}</span>
          </label>
        </div>
      )}
    </Modal>
  );
}

// ── Links and invitations ──────────────────────────────────────────────────────

function TokensTab() {
  const { t } = useTranslation();
  const L = useLabels();
  const confirm = useConfirm();
  const [kind, setKind] = useState<EnrollmentTokenKind | ''>('');
  const [state, setState] = useState<EnrollmentTokenState | ''>('active');
  const [rows, setRows] = useState<EnrollmentTokenView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    enrollmentApi.tokens({ ...(kind ? { kind } : {}), ...(state ? { state } : {}) })
      .then((r) => { setRows(r); setError(null); })
      .catch((err) => { setRows([]); setError(apiErrorMessage(err)); });
  }, [kind, state]);
  useEffect(() => { load(); }, [load]);
  const revoke = async (tk: EnrollmentTokenView) => {
    const ok = await confirm({ message: t('deviceEnrollment.confirmRevoke', { prefix: tk.prefix }) || `Revoke ${tk.prefix}? It can no longer be used.`, danger: true });
    if (!ok) return;
    try {
      await enrollmentApi.revokeToken(tk.id);
      toast.success(t('deviceEnrollment.revoked') || 'Revoked');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    }
  };
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <select value={kind} onChange={(e) => setKind(e.target.value as EnrollmentTokenKind | '')} className="rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm">
          <option value="">{t('deviceEnrollment.allKinds') || 'Links and invitations'}</option>
          <option value="link">{L.kind('link')}</option>
          <option value="invitation">{L.kind('invitation')}</option>
        </select>
        <select value={state} onChange={(e) => setState(e.target.value as EnrollmentTokenState | '')} className="rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm">
          <option value="">{t('common.all') || 'All'}</option>
          {ENROLLMENT_TOKEN_STATES.map((s) => <option key={s} value={s}>{L.tokenState(s)}</option>)}
        </select>
        <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">{t('deviceEnrollment.noToken') || 'Nothing here.'}</div>
          : (
            <div className="overflow-x-auto rounded-xl bg-bg-secondary">
              <table className="w-full text-sm">
                <thead className="text-xs text-text-muted">
                  <tr className="text-left">
                    <th className="font-medium px-4 py-2">{t('deviceEnrollment.prefix') || 'Prefix'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.kindLabel') || 'Kind'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.profile') || 'Profile'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.label') || 'Label (optional)'}</th>
                    <th className="font-medium px-3 py-2 text-right">{t('deviceEnrollment.uses') || 'Uses'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.expires') || 'Expires'}</th>
                    <th className="font-medium px-3 py-2">{t('common.status') || 'Status'}</th>
                    <th className="px-3 py-2" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className="border-t border-border/50">
                      <td className="px-4 py-2.5 font-mono text-xs text-text-primary">{r.prefix}…</td>
                      <td className="px-3 py-2.5 text-text-secondary">
                        {L.kind(r.kind)}
                        {r.managedAppleAccount && <span className="block text-[11px] text-text-muted break-all">{anonymize(r.managedAppleAccount)}</span>}
                      </td>
                      <td className="px-3 py-2.5 text-text-secondary">{r.profileName}</td>
                      <td className="px-3 py-2.5 text-text-secondary">{r.label ?? <span className="text-text-muted">—</span>}</td>
                      <td className="px-3 py-2.5 text-right tabular-nums">{r.uses} / {r.maxUses}</td>
                      <td className="px-3 py-2.5 text-text-secondary text-xs">{formatDateTime(r.expiresAt)}</td>
                      <td className="px-3 py-2.5"><StateBadge tone={TOKEN_TONE[r.state]} label={L.tokenState(r.state)} /></td>
                      <td className="px-3 py-2.5">
                        {r.state !== 'revoked' && (
                          <span className="flex justify-end">
                            <IconButton label={t('deviceEnrollment.revoke') || 'Revoke'} danger onClick={() => { void revoke(r); }}><XCircle className="w-4 h-4" /></IconButton>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
    </div>
  );
}

// ── Sessions ───────────────────────────────────────────────────────────────────

function SessionsTab() {
  const { t } = useTranslation();
  const L = useLabels();
  const [state, setState] = useState<EnrollmentSessionState | ''>('');
  const [rows, setRows] = useState<EnrollmentSessionView[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback((after: string | null = null) => {
    enrollmentApi.sessions({ ...(state ? { state } : {}), cursor: after })
      .then((r) => { setRows((prev) => (after ? [...(prev ?? []), ...r.items] : r.items)); setCursor(r.nextCursor); setError(null); })
      .catch((err) => { setRows((prev) => prev ?? []); setError(apiErrorMessage(err)); });
  }, [state]);
  useEffect(() => { load(); }, [load]);
  // Live: a session of the tenant changed (identifiers only; the list is read again).
  useEffect(() => registerSocketListener(SocketEvents.ENROLLMENT_SESSION_CHANGED, () => { load(); }), [load]);
  const failure = useMemo(() => (code: string | null) => (code ? trCode(`deviceEnrollment.failure.${code}`, code) : null), []);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <select value={state} onChange={(e) => setState(e.target.value as EnrollmentSessionState | '')} className="rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm">
          <option value="">{t('common.all') || 'All'}</option>
          {ENROLLMENT_SESSION_STATES.map((s) => <option key={s} value={s}>{L.sessionState(s)}</option>)}
        </select>
        <button type="button" onClick={() => load()} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">{t('deviceEnrollment.noSession') || 'No enrollment session.'}</div>
          : (
            <div className="overflow-x-auto rounded-xl bg-bg-secondary">
              <table className="w-full text-sm">
                <thead className="text-xs text-text-muted">
                  <tr className="text-left">
                    <th className="font-medium px-4 py-2">{t('deviceEnrollment.started') || 'Started'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.profile') || 'Profile'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.methodLabel') || 'Method'}</th>
                    <th className="font-medium px-3 py-2">{t('common.status') || 'Status'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.prefix') || 'Prefix'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.device') || 'Device'}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.id} className="border-t border-border/50">
                      <td className="px-4 py-2.5 text-xs text-text-secondary">{formatDateTime(s.createdAt)}</td>
                      <td className="px-3 py-2.5 text-text-secondary">
                        {s.profileName}
                        {s.managedAppleAccount && <span className="block text-[11px] text-text-muted break-all">{anonymize(s.managedAppleAccount)}</span>}
                        {s.serialNumber && <span className="block text-[11px] text-text-muted font-mono">{anonymize(s.serialNumber)}</span>}
                      </td>
                      <td className="px-3 py-2.5 text-text-secondary">{L.method(s.method)}</td>
                      <td className="px-3 py-2.5">
                        <StateBadge tone={SESSION_TONE[s.state]} label={L.sessionState(s.state)} title={formatDateTime(s.stateAt)} />
                        {s.failureCode && <span className="block text-[11px] text-red-400">{failure(s.failureCode)}</span>}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-xs text-text-muted">{s.tokenPrefix ? `${s.tokenPrefix}…` : '—'}</td>
                      <td className="px-3 py-2.5">
                        {s.deviceId ? <Link to={`/devices/${s.deviceId}`} className="text-accent hover:underline">#{s.deviceId}</Link> : <span className="text-text-muted">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      {cursor && (
        <div className="flex justify-end">
          <Button size="sm" variant="secondary" onClick={() => load(cursor)}>{t('deviceEnrollment.more') || 'More'}</Button>
        </div>
      )}
    </div>
  );
}

// ── ADE: where a profile is defined at Apple ──────────────────────────────────────

function AdeBindingLine({ profile }: { profile: EnrollmentProfileView }) {
  const { t } = useTranslation();
  const list = profile.adeBindings ?? [];
  if (list.length === 0) {
    return <span className="block text-[10px] text-text-muted">{t('deviceEnrollment.adeNoServer') || 'No active ADE server yet'}</span>;
  }
  const ok = list.filter((b) => b.upToDate).length;
  const errors = list.filter((b) => !b.upToDate && b.lastErrorCode);
  const tone = errors.length ? 'text-red-400' : ok === list.length ? 'text-green-400' : 'text-amber-400';
  return (
    <span className={`block text-[10px] ${tone}`} title={errors.map((b) => `${b.serverName}: ${b.lastErrorCode}`).join('\n') || undefined}>
      {ok === list.length
        ? (t('deviceEnrollment.adeDefined', { count: list.length }) || `Defined at Apple on ${list.length} server(s)`)
        : errors.length
          ? (t('deviceEnrollment.adeDefineFailed', { count: errors.length }) || `Not defined at Apple on ${errors.length} server(s)`)
          : (t('deviceEnrollment.adePending', { done: ok, total: list.length }) || `Being defined at Apple (${ok}/${list.length})`)}
    </span>
  );
}

// ── ADE devices (Apple Business) ──────────────────────────────────────────────────

function AdeDevicesTab() {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [rows, setRows] = useState<AdeDeviceView[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<EnrollmentProfileView[]>([]);
  const [busy, setBusy] = useState<number | null>(null);
  const load = useCallback((after: string | null = null) => {
    enrollmentApi.adeDevices({ q: query || undefined, cursor: after })
      .then((r) => { setRows((prev) => (after ? [...(prev ?? []), ...r.items] : r.items)); setCursor(r.nextCursor); setError(null); })
      .catch((err) => { setRows((prev) => prev ?? []); setError(apiErrorMessage(err)); });
  }, [query]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    enrollmentApi.profiles().then((r) => setProfiles(r.filter((p) => p.method === 'ade'))).catch(() => setProfiles([]));
  }, []);
  const choose = async (d: AdeDeviceView, value: string) => {
    setBusy(d.id);
    try {
      await enrollmentApi.setAdeDeviceProfile(d.id, value || null);
      toast.success(t('deviceEnrollment.adeProfileChosen') || 'Enrollment profile chosen: it is assigned at Apple shortly');
      load();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted">
        {t('deviceEnrollment.adeIntro') || 'Devices assigned to this tenant in Apple Business. Without a choice, a device receives the default ADE profile.'}
      </p>
      <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); setQuery(q.trim()); }}>
        <input value={q} maxLength={64} onChange={(e) => setQ(e.target.value)} autoCapitalize="off" spellCheck={false}
          placeholder={t('deviceEnrollment.adeSearch') || 'Serial number'} aria-label={t('deviceEnrollment.adeSearch') || 'Serial number'}
          className="rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm" />
        <button type="submit" aria-label={t('common.search') || 'Search'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <Search className="w-4 h-4" />
        </button>
        <button type="button" onClick={() => load()} aria-label={t('common.refresh') || 'Refresh'}
          className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10">
          <RefreshCw className="w-4 h-4" />
        </button>
      </form>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {rows === null ? <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>
        : rows.length === 0 ? <div className="p-10 text-center bg-bg-secondary rounded-xl text-text-muted">{t('deviceEnrollment.adeNoDevice') || 'No device of Apple Business yet.'}</div>
          : (
            <div className="overflow-x-auto rounded-xl bg-bg-secondary">
              <table className="w-full text-sm">
                <thead className="text-xs text-text-muted">
                  <tr className="text-left">
                    <th className="font-medium px-4 py-2">{t('deviceEnrollment.adeSerial') || 'Serial number'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.adeModel') || 'Model'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.adeServer') || 'ADE server'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.adeApplied') || 'Profile at Apple'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.adeWanted') || 'Enrollment profile'}</th>
                    <th className="font-medium px-3 py-2">{t('deviceEnrollment.device') || 'Device'}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((d) => (
                    <tr key={d.id} className="border-t border-border/50">
                      <td className="px-4 py-2.5 font-mono text-xs text-text-primary">{anonymize(d.serialNumber)}</td>
                      <td className="px-3 py-2.5 text-text-secondary">{d.description ?? d.model ?? <span className="text-text-muted">—</span>}</td>
                      <td className="px-3 py-2.5 text-text-secondary">{d.serverName}</td>
                      <td className="px-3 py-2.5 text-text-secondary">
                        {d.appliedProfileName ?? <span className="text-text-muted">—</span>}
                        {d.profileStatus && <span className="block text-[11px] text-text-muted">{trCode(`deviceEnrollment.adeStatus.${d.profileStatus}`, d.profileStatus)}</span>}
                      </td>
                      <td className="px-3 py-2.5">
                        <select value={d.wantedProfileId ?? ''} disabled={busy === d.id} onChange={(e) => { void choose(d, e.target.value); }}
                          aria-label={t('deviceEnrollment.adeWanted') || 'Enrollment profile'}
                          className="rounded border border-border bg-bg-secondary px-2 py-1 text-sm">
                          <option value="">{t('deviceEnrollment.adeDefault') || 'Default ADE profile'}</option>
                          {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                        </select>
                      </td>
                      <td className="px-3 py-2.5">
                        {d.deviceId ? <Link to={`/devices/${d.deviceId}`} className="text-accent hover:underline">#{d.deviceId}</Link> : <span className="text-text-muted">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      {cursor && (
        <div className="flex justify-end">
          <Button size="sm" variant="secondary" onClick={() => load(cursor)}>{t('deviceEnrollment.more') || 'More'}</Button>
        </div>
      )}
    </div>
  );
}
