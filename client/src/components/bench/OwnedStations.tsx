import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Ban, KeyRound, Pause, Pencil, Play, Plus, ShieldAlert, Tag, Trash2 } from 'lucide-react';
import {
  BENCH_ROLE_POLICIES, normaliseBenchVerificationCode,
  type BenchOwnedStationView, type BenchOwnedTargetView, type BenchRolePolicy, type DeviceGroup,
} from '@obligarth/shared';
import { benchStationsApi, type BenchTargetPatch } from '@/api/benchStations.api';
import { groupsApi } from '@/api/groups.api';
import { apiErrorCode } from '@/utils/apiError';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { useConfirm, usePrompt } from '@/components/common/ConfirmDialog';
import { NameTemplateDialog, NameTemplateField, templateCheck } from './NameTemplateField';
import { StationStatusPill, cardCls, cardTitleCls, chipCls, fail, fieldCls, fmt, labelCls, useRolePolicyLabel } from './benchUi';

// The bench stations a client tenant owns (lot BANC-T §4; /api/bench-stations, mdm.bench.manage; never in the master
// tenant): « Add a station of this tenant » (the name and the XXXX-XXXX code its screen shows, then a strict second
// factor asked by the client's dialog), the stations with their actions (rename, suspend, resume unless the platform
// suspended it, revoke, the session closed) and their targets, groups of this tenant only (add, policy, developer
// options, exception D3, template of the suggested name, suspend, resume, remove). A station the platform suspended
// shows a banner: only the platform lifts it.

/** The claim refusals named (one 422 for every mismatch, by design). */
function claimError(err: unknown, t: (k: string) => string): void {
  const code = apiErrorCode(err);
  if (code === 'claim_mismatch') toast.error(t('bench.claim.mismatch') || 'No station waiting for its approval has this name and this code.', { duration: 7000 });
  else if (code === 'claim_conflict') toast.error(t('bench.claim.conflict') || 'This station already serves another tenant: ask the platform.', { duration: 9000 });
  else if (code === 'rate_limited') toast.error(t('bench.claim.rateLimited') || 'Too many attempts: try again later.', { duration: 9000 });
  else fail(err);
}

/** A failure of an action on an owned station, with the refusals of lot BANC-T named. */
function ownedError(err: unknown, t: (k: string) => string): void {
  const code = apiErrorCode(err);
  if (code === 'suspendedByPlatform') toast.error(t('bench.owned.platformSuspendedError') || 'The platform suspended this station or this target: only the platform resumes it.', { duration: 7000 });
  else if (code === 'targetRefused') toast.error(t('bench.owned.targetRefused') || 'This station cannot target this group.', { duration: 7000 });
  else if (code === 'targetExists') toast.error(t('bench.owned.targetExists') || 'This group is a target of the station already.', { duration: 7000 });
  else fail(err);
}

export function OwnedStations({ onChanged }: { onChanged: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const [rows, setRows] = useState<BenchOwnedStationView[] | null>(null);
  const [claiming, setClaiming] = useState(false);
  const [adding, setAdding] = useState<BenchOwnedStationView | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const load = useCallback(() => { benchStationsApi.owned().then(setRows).catch((err) => { setRows([]); fail(err); }); }, []);
  useEffect(() => { load(); }, [load]);
  const act = async (fn: () => Promise<unknown>, done?: string) => {
    try { await fn(); load(); onChanged(); if (done) toast.success(done); } catch (err) { ownedError(err, t); load(); }
  };

  const rename = async (s: BenchOwnedStationView) => {
    const name = await prompt({ title: t('bench.stations.rename') || 'Rename', defaultValue: s.name, required: true });
    if (name && name.trim() !== s.name) await act(() => benchStationsApi.ownedRename(s.id, name.trim()));
  };
  const revoke = async (s: BenchOwnedStationView) => {
    const ok = await confirm({
      title: t('bench.stations.revokeTitle', { name: s.name }) || `Revoke ${s.name}`, danger: true, confirmLabel: t('bench.stations.revoke') || 'Revoke',
      message: t('bench.stations.revokeConfirm') || 'Final: its unused enrollment tokens are revoked, its open provisionings abandoned and its session closed. A second factor is asked.',
    });
    if (ok) await act(() => benchStationsApi.ownedRevoke(s.id), t('bench.stations.revoked') || 'Station revoked');
  };

  const live = (rows ?? []).filter((s) => s.status !== 'revoked');
  const revoked = (rows ?? []).filter((s) => s.status === 'revoked');
  const shown = showRevoked ? [...live, ...revoked] : live;

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h3 className={clsx(cardTitleCls, 'mb-0')}>{t('bench.owned.title') || 'Stations of this tenant'}</h3>
        {revoked.length > 0 && (
          <button type="button" className={chipCls(showRevoked)} onClick={() => setShowRevoked((v) => !v)}>
            {t('bench.owned.showRevoked') || 'Revoked'}<span className="tabular-nums opacity-70">{revoked.length}</span>
          </button>
        )}
        <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setClaiming(true)}><KeyRound className="mr-1 h-3.5 w-3.5" />{t('bench.claim.button') || 'Add a station of this tenant'}</Button>
      </div>
      {rows && shown.length === 0 && (
        <p className={clsx(cardCls, 'text-center text-sm text-text-muted')}>
          {t('bench.owned.empty') || 'No station belongs to this tenant. Install the bench station on a PC, then add it here with the code its screen shows.'}
        </p>
      )}
      <ul className="space-y-2">
        {shown.map((s) => (
          <li key={s.id} className={clsx(cardCls, 'space-y-3 text-sm')}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-text-primary">{s.name}</span>
              <StationStatusPill status={s.status} />
              <span className="rounded-full bg-accent/15 px-2 py-0.5 text-[11px] font-medium text-accent">{t('bench.owned.badge') || 'This tenant'}</span>
              <span className="text-xs text-text-muted">{s.hostname || '—'}{s.stationVersion ? ` · ${s.stationVersion}` : ''}</span>
              <span className="text-xs text-text-muted">{t('bench.stations.lastSeen') || 'Last activity'} : {fmt(s.lastSeenAt)}</span>
              {s.status !== 'revoked' && (
                <span className="ml-auto flex flex-wrap items-center gap-1">
                  {s.status === 'approved' && <Button size="sm" variant="ghost" onClick={() => void act(() => benchStationsApi.ownedSuspend(s.id), t('bench.stations.suspended') || 'Station suspended')}><Pause className="mr-1 h-3.5 w-3.5" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
                  {s.status === 'suspended' && !s.suspendedByPlatform && <Button size="sm" variant="ghost" onClick={() => void act(() => benchStationsApi.ownedResume(s.id))}><Play className="mr-1 h-3.5 w-3.5" />{t('bench.stations.resume') || 'Resume'}</Button>}
                  <Button size="sm" variant="ghost" onClick={() => void rename(s)}><Pencil className="mr-1 h-3.5 w-3.5" />{t('bench.stations.rename') || 'Rename'}</Button>
                  <Button size="sm" variant="ghost" className="text-red-400" onClick={() => void revoke(s)}><Ban className="mr-1 h-3.5 w-3.5" />{t('bench.stations.revoke') || 'Revoke'}</Button>
                </span>
              )}
            </div>
            {s.status === 'suspended' && s.suspendedByPlatform && (
              <div className="flex items-start gap-2 rounded-xl bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>{t('bench.owned.platformSuspended', { at: fmt(s.suspendedAt) }) || `Suspended by the platform since ${fmt(s.suspendedAt)}: only the platform resumes it. Contact it if this is unexpected.`}</span>
              </div>
            )}
            {s.status === 'revoked' && s.revokedAt && (
              <div className="text-xs text-text-muted">
                {t('bench.stations.revokedAt') || 'Revoked'} : {fmt(s.revokedAt)}{s.revokedReason ? ` (${t(`bench.stations.revokedReason.${s.revokedReason}`) || s.revokedReason})` : ''}
              </div>
            )}
            {s.status !== 'revoked' && (
              <>
                <div>
                  <div className="mb-1 flex items-center">
                    <span className={labelCls}>{t('bench.stations.targets.title') || 'Targets'}</span>
                    <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setAdding(s)}><Plus className="mr-1 h-3.5 w-3.5" />{t('bench.stations.targets.add') || 'Add a target'}</Button>
                  </div>
                  {s.targets.length === 0
                    ? <p className="rounded-md px-2 py-1 text-xs text-text-muted">{t('bench.stations.targets.empty') || 'No target: the station can enroll nothing.'}</p>
                    : <div className="space-y-1">{s.targets.map((x) => <OwnedTargetRow key={x.groupId} station={s} target={x} act={act} />)}</div>}
                </div>
              </>
            )}
          </li>
        ))}
      </ul>
      {claiming && <ClaimDialog onClose={() => setClaiming(false)} onClaimed={() => { setClaiming(false); load(); onChanged(); }} />}
      {adding && <OwnedAddTargetDialog station={adding} onClose={() => setAdding(null)} onAdded={() => { setAdding(null); load(); onChanged(); }} />}
    </section>
  );
}

function OwnedTargetRow({ station, target: x, act }: {
  station: BenchOwnedStationView; target: BenchOwnedTargetView; act: (fn: () => Promise<unknown>, done?: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const policyLabel = useRolePolicyLabel();
  const [editing, setEditing] = useState(false);
  const patch = (p: BenchTargetPatch) => act(() => benchStationsApi.ownedPatchTarget(station.id, x.groupId, p));
  const allowLegacy = async (on: boolean) => {
    if (on && !(await confirm({
      danger: true, confirmLabel: t('common.confirm') || 'Confirm',
      message: t('bench.stations.targets.legacyOwnerWarning') || 'Exception: the agent 1.3.0 set as the owner of the device cannot give it back; only a reset removes it. For a test target only. A second factor is asked.',
    }))) return;
    await patch({ allowLegacyOwner: on });
  };
  const remove = async () => {
    if (await confirm({ danger: true, message: t('bench.tenant.removeConfirm', { station: station.name, group: x.groupPath }) || `Remove the group ${x.groupPath} from the station ${station.name}?` })) {
      await act(() => benchStationsApi.ownedRemoveTarget(station.id, x.groupId));
    }
  };
  return (
    <div className="space-y-2 rounded-md px-2 py-2 text-xs transition-colors hover:bg-bg-tertiary">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-text-primary">{x.groupPath}</span>
        {x.suspendedAt && <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-400">{x.suspendedByPlatform
          ? (t('bench.owned.targetSuspendedByPlatform') || 'Suspended by the platform')
          : (t('bench.stations.targets.suspended') || 'Suspended')}</span>}
        <span className="ml-auto flex gap-1">
          {/* Q1: a target the platform suspended is neither resumed nor removed by the client. */}
          {x.suspendedByPlatform ? null : x.suspendedAt
            ? <Button size="sm" variant="ghost" onClick={() => void patch({ suspended: false })}><Play className="mr-1 h-3.5 w-3.5" />{t('bench.stations.resume') || 'Resume'}</Button>
            : <Button size="sm" variant="ghost" onClick={() => void patch({ suspended: true })}><Pause className="mr-1 h-3.5 w-3.5" />{t('bench.stations.suspend') || 'Suspend'}</Button>}
          {!x.suspendedByPlatform && <Button size="sm" variant="ghost" title={t('bench.stations.targets.remove') || 'Remove'} onClick={() => void remove()}><Trash2 className="h-3.5 w-3.5" /></Button>}
        </span>
      </div>
      {x.suspendedByPlatform && (
        <p className="text-amber-400">{t('bench.owned.targetSuspendedByPlatformNote') || 'The platform suspended this target: only the platform resumes it. Contact it if this is unexpected.'}</p>
      )}
      <div className="flex flex-wrap gap-1">
        {BENCH_ROLE_POLICIES.map((p) => (
          <button key={p} type="button" className={chipCls(x.rolePolicy === p)} onClick={() => { if (x.rolePolicy !== p) void patch({ rolePolicy: p }); }}>{policyLabel(p)}</button>
        ))}
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        <ToggleSwitch size="sm" checked={x.disableDevOptions} onChange={(on) => void patch({ disableDevOptions: on })}
          label={t('bench.stations.targets.disableDevOptions') || 'Turn the developer options off at the end'} />
        <ToggleSwitch size="sm" checked={x.allowLegacyOwner} onChange={(on) => void allowLegacy(on)}
          label={t('bench.stations.targets.allowLegacyOwner') || 'Exception: device owner with the agent 1.3.0'} />
      </div>
      <div className="flex flex-wrap items-center gap-2 text-text-muted">
        <Tag className="h-3.5 w-3.5" />
        <span>{t('bench.nameTemplate.short') || 'Suggested name'} :</span>
        {x.nameTemplate
          ? <span className="font-mono text-text-secondary">{x.nameTemplate}</span>
          : <span>{t('bench.nameTemplate.none') || 'none (prefix and ADB serial)'}{x.namePrefix ? <span className="ml-1 font-mono text-text-secondary">{x.namePrefix}</span> : null}</span>}
        <Button size="sm" variant="ghost" onClick={() => setEditing(true)}><Pencil className="mr-1 h-3.5 w-3.5" />{t('bench.nameTemplate.edit') || 'Change'}</Button>
      </div>
      {editing && (
        <NameTemplateDialog initial={x.nameTemplate} target={x.groupPath} onClose={() => setEditing(false)}
          onSave={async (nameTemplate) => {
            try { await benchStationsApi.ownedPatchTarget(station.id, x.groupId, { nameTemplate }); setEditing(false); await act(async () => undefined); } catch (err) { ownedError(err, t); }
          }} />
      )}
    </div>
  );
}

/** « Add a station of this tenant »: the name and the code the station shows; the second factor is asked next. */
function ClaimDialog({ onClose, onClaimed }: { onClose: () => void; onClaimed: (s: BenchOwnedStationView) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const ready = name.trim().length > 0 && normaliseBenchVerificationCode(code).length === 8;
  const claim = async () => {
    if (!ready || busy) return;
    setBusy(true);
    try {
      const s = await benchStationsApi.claim(name.trim(), code.trim());
      toast.success(t('bench.claim.done', { name: s.name }) || `${s.name} now belongs to this tenant`);
      onClaimed(s);
    } catch (err) { claimError(err, t); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} size="md" icon={<KeyRound className="h-4 w-4 text-accent" />}
      title={t('bench.claim.title') || 'Add a station of this tenant'}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void claim()} disabled={!ready || busy}>{t('bench.claim.submit') || 'Add the station'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <p className="text-text-secondary">
          {t('bench.claim.hint') || 'On the PC of the station, the bench tool waits for its approval and shows its name and a verification code. Type both here: the station then belongs to this tenant and serves only it. A second factor is asked next.'}
        </p>
        <label className={labelCls}>{t('bench.claim.name') || 'Name of the station (as shown on its screen)'}
          <input className={fieldCls} value={name} maxLength={100} autoComplete="off" autoFocus onChange={(e) => setName(e.target.value)} />
        </label>
        <label className={labelCls}>{t('bench.stations.verificationCode') || 'Verification code'}
          <input className={`${fieldCls} font-mono uppercase tracking-widest`} value={code} maxLength={9} autoComplete="off" spellCheck={false}
            placeholder="XXXX-XXXX" onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') void claim(); }} />
        </label>
        <p className="text-xs text-text-muted">{t('bench.claim.expiry') || 'A station waits 24 hours for its approval. Several wrong attempts block the claim for a while.'}</p>
      </div>
    </Modal>
  );
}

/** The groups of the tenant with their path (root first). */
function groupPaths(groups: DeviceGroup[]): Array<{ id: number; path: string }> {
  const byId = new Map(groups.map((g) => [g.id, g]));
  return groups.map((g) => {
    const names: string[] = [];
    let cur: DeviceGroup | undefined = g;
    for (let i = 0; cur && i < 32; i++) { names.unshift(cur.name); cur = cur.parentId === null ? undefined : byId.get(cur.parentId); }
    return { id: g.id, path: names.join('/') };
  }).sort((a, b) => a.path.localeCompare(b.path));
}

function OwnedAddTargetDialog({ station, onClose, onAdded }: { station: BenchOwnedStationView; onClose: () => void; onAdded: () => void }) {
  const { t } = useTranslation();
  const policyLabel = useRolePolicyLabel();
  const [groups, setGroups] = useState<Array<{ id: number; path: string }>>([]);
  const [form, setForm] = useState<{ groupId: number | null; rolePolicy: BenchRolePolicy; namePrefix: string; nameTemplate: string; disableDevOptions: boolean }>(
    { groupId: null, rolePolicy: 'owner_preferred', namePrefix: '', nameTemplate: '', disableDevOptions: true });
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { groupsApi.list().then((g) => setGroups(groupPaths(g))).catch(fail); }, []);
  const taken = useMemo(() => new Set(station.targets.map((x) => x.groupId)), [station.targets]);
  const prefixOk = /^[A-Za-z0-9_-]{0,32}$/.test(form.namePrefix);
  const templateOk = templateCheck(form.nameTemplate).ok;
  const shown = groups.filter((g) => !taken.has(g.id) && (!q.trim() || g.path.toLowerCase().includes(q.trim().toLowerCase()))).slice(0, 200);
  const add = async () => {
    if (form.groupId === null) return;
    setBusy(true);
    try {
      await benchStationsApi.ownedAddTarget(station.id, {
        groupId: form.groupId, rolePolicy: form.rolePolicy, namePrefix: form.namePrefix || null, nameTemplate: form.nameTemplate || null,
        disableDevOptions: form.disableDevOptions,
      });
      onAdded();
    } catch (err) { ownedError(err, t); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} size="lg" title={t('bench.owned.addTargetTitle', { name: station.name }) || `Add a target to ${station.name}`}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void add()} disabled={form.groupId === null || !prefixOk || !templateOk || busy}>{t('bench.stations.targets.add') || 'Add a target'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <div>
          <span className={labelCls}>{t('bench.stations.targets.group') || 'Group'}</span>
          <input className={fieldCls} value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('bench.stations.targets.search') || 'Search a group'} />
          <div className="mt-1 max-h-56 overflow-y-auto rounded-xl bg-bg-secondary py-1">
            {shown.map((g) => (
              <button key={g.id} type="button" onClick={() => setForm({ ...form, groupId: g.id })}
                className={clsx('block w-full px-3 py-1.5 text-left text-sm transition-colors hover:bg-bg-tertiary', g.id === form.groupId ? 'text-accent' : 'text-text-primary')}>
                {g.path}
              </button>
            ))}
            {shown.length === 0 && <div className="px-3 py-2 text-xs text-text-muted">{t('bench.stations.targets.noGroup') || 'No group.'}</div>}
          </div>
        </div>
        <div>
          <span className={labelCls}>{t('bench.stations.targets.rolePolicy') || 'Role'}</span>
          <div className="mt-1 flex flex-wrap gap-1">
            {BENCH_ROLE_POLICIES.map((p) => <button key={p} type="button" className={chipCls(form.rolePolicy === p)} onClick={() => setForm({ ...form, rolePolicy: p })}>{policyLabel(p)}</button>)}
          </div>
        </div>
        <NameTemplateField value={form.nameTemplate} onChange={(v) => setForm({ ...form, nameTemplate: v })} />
        <label className={labelCls}>{t('bench.stations.targets.namePrefix') || 'Name prefix'}
          <input className={fieldCls} value={form.namePrefix} maxLength={32} onChange={(e) => setForm({ ...form, namePrefix: e.target.value })} placeholder="AB" />
        </label>
        <ToggleSwitch size="sm" checked={form.disableDevOptions} onChange={(on) => setForm({ ...form, disableDevOptions: on })}
          label={t('bench.stations.targets.disableDevOptions') || 'Turn the developer options off at the end'} />
        <p className="text-xs text-text-muted">{t('bench.owned.addTargetHint') || 'A group of this tenant only. A second factor is asked.'}</p>
      </div>
    </Modal>
  );
}
