import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Building2, Plus, Pencil, Trash2, Users, X, Check } from 'lucide-react';
import type { Tenant } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { IconButton } from '@/components/common/IconButton';
import { Modal } from '@/components/common/Modal';
import { PageContainer } from '@/components/common/PageContainer';
import { useConfirm } from '@/components/common/ConfirmDialog';
import toast from 'react-hot-toast';
import apiClient, { isStepUpHandled } from '@/api/client';
import { apiErrorMessage } from '@/utils/apiError';
import { useTenantStore } from '@/store/tenantStore';

interface TenantMember {
 id: number;
 username: string;
 display_name: string | null;
 role: string;
 is_active: boolean;
 /** 'admin' or the slug of a permission set ('member', the pre-091 name, is the 'user' set). */
 tenantRole: string;
}

interface RoleOption {
 value: string;
 label: string;
}

interface TenantWithMemberCount extends Tenant {
 memberCount?: number;
}

// ── Inline form for creating / editing a tenant ────────────────────────────
function TenantForm({
 initial,
 onSave,
 onCancel,
}: {
 initial?: { name: string; slug: string };
 onSave: (name: string, slug: string) => Promise<void>;
 onCancel: () => void;
}) {
 const { t } = useTranslation();
 const [name, setName] = useState(initial?.name ?? '');
 const [slug, setSlug] = useState(initial?.slug ?? '');
 const [saving, setSaving] = useState(false);
 const [error, setError] = useState('');

 const autoSlug = (n: string) =>
 n.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

 const handleNameChange = (v: string) => {
 setName(v);
 if (!initial) setSlug(autoSlug(v));
 };

 const handleSubmit = async () => {
 if (!name.trim() || !slug.trim()) { setError(t('common.requiredField', 'This field is required')); return; }
 setSaving(true);
 setError('');
 try {
 await onSave(name.trim(), slug.trim());
 } catch (e: unknown) {
 setError(e instanceof Error ? e.message : t('common.error'));
 } finally {
 setSaving(false);
 }
 };

 // Phones: fields stacked full width, error on its own line.
 return (
 <div className="flex flex-col sm:flex-row sm:items-end gap-2">
 <div className="flex-1">
 <label className="block text-xs text-text-muted mb-1">{t('tenant.name')}</label>
 <input
 type="text"
 value={name}
 onChange={(e) => handleNameChange(e.target.value)}
 className="w-full rounded-lg bg-bg-primary px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
 placeholder={t('tenant.namePlaceholder')}
 />
 </div>
 <div className="w-full sm:w-40">
 <label className="block text-xs text-text-muted mb-1">{t('tenant.slug')}</label>
 <input
 type="text"
 value={slug}
 onChange={(e) => setSlug(e.target.value)}
 autoCapitalize="off"
 autoCorrect="off"
 spellCheck={false}
 className="w-full rounded-lg bg-bg-primary px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
 placeholder="my-org"
 />
 </div>
 {error && <p className="text-xs text-red-400">{error}</p>}
 <div className="flex gap-2 max-sm:justify-end">
 <Button size="sm" onClick={handleSubmit} disabled={saving} aria-label={t('common.save')} title={t('common.save')} className="coarse:min-h-10 coarse:min-w-10">
 <Check size={14} />
 </Button>
 <Button size="sm" variant="ghost" onClick={onCancel} disabled={saving} aria-label={t('common.cancel')} title={t('common.cancel')} className="coarse:min-h-10 coarse:min-w-10">
 <X size={14} />
 </Button>
 </div>
 </div>
 );
}

// ── Members panel ───────────────────────────────────────────────────────────
function MembersPanel({ tenantId, onClose }: { tenantId: number; onClose: () => void }) {
 const { t } = useTranslation();
 const confirm = useConfirm();
 const [members, setMembers] = useState<TenantMember[]>([]);
 const [allUsers, setAllUsers] = useState<{ id: number; username: string }[]>([]);
 const [loading, setLoading] = useState(true);
 const [addingId, setAddingId] = useState<number | ''>('');

 const [roles, setRoles] = useState<RoleOption[]>([]);
 const [busy, setBusy] = useState(false);

 // Every call goes through apiClient: the server's refusal is read and said (toast), and a second factor the
 // server asks for is prompted by its interceptor.
 const fetchMembers = async () => {
 try {
 const res = await apiClient.get<{ data?: TenantMember[] }>(`/tenants/${tenantId}/members`);
 setMembers(res.data.data ?? []);
 } catch (err) {
 toast.error(apiErrorMessage(err));
 } finally {
 setLoading(false);
 }
 };

 const fetchUsers = async () => {
 try {
 const res = await apiClient.get<{ data?: { id: number; username: string }[] }>('/users');
 setAllUsers(res.data.data ?? []);
 } catch {
 setAllUsers([]);
 }
 };

 // The roles of a membership: tenant administrator, or one of the permission sets (their slug is stored).
 const fetchRoles = async () => {
 try {
 const res = await apiClient.get<{ data?: { slug: string; name: string }[] }>('/permission-sets');
 setRoles((res.data.data ?? []).filter((s) => s.slug !== 'admin').map((s) => ({ value: s.slug, label: s.name })));
 } catch {
 setRoles([]);
 }
 };

 useEffect(() => {
 fetchMembers();
 fetchUsers();
 fetchRoles();
 }, [tenantId]);

 /** Runs one write, then re-reads the members (also after a refusal: the list shows what is stored). */
 const write = async (run: () => Promise<unknown>) => {
 if (busy) return;
 setBusy(true);
 try {
 await run();
 } catch (err) {
 if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
 } finally {
 setBusy(false);
 void fetchMembers();
 }
 };

 const addMember = async () => {
 if (!addingId) return;
 const userId = addingId;
 await write(async () => {
 await apiClient.post(`/tenants/${tenantId}/members`, { userId, role: 'member' });
 setAddingId('');
 });
 };

 /** The role options of one member: administrator, the permission sets, and its current role if none of them. */
 const roleOptionsOf = (current: string): RoleOption[] => {
 const base: RoleOption[] = [{ value: 'admin', label: t('tenant.roleAdministrator') || 'Administrator' }, ...roles];
 if (!roles.some((r) => r.value === 'user')) base.push({ value: 'user', label: t('tenant.roleMember') || 'Member' });
 const normalised = current === 'member' ? 'user' : current;
 if (!base.some((r) => r.value === normalised)) base.push({ value: normalised, label: normalised });
 return base;
 };

 const changeRole = async (member: TenantMember, newRole: string) => {
 const current = member.tenantRole === 'member' ? 'user' : member.tenantRole;
 if (newRole === current) return;
 const label = roleOptionsOf(member.tenantRole).find((r) => r.value === newRole)?.label ?? newRole;
 if (!(await confirm({
 message: t('tenant.confirmRoleChange', { user: member.username, role: label }) || `Give ${member.username} the role "${label}" in this workspace?`,
 danger: newRole === 'admin' || current === 'admin',
 confirmLabel: t('common.confirm') || 'Confirm',
 }))) return;
 await write(() => apiClient.put(`/tenants/${tenantId}/members/${member.id}`, { role: newRole }));
 };

 const removeMember = async (userId: number) => {
 if (!(await confirm({ message: t('common.confirmDelete'), danger: true, confirmLabel: t('tenant.removeMember') }))) return;
 await write(() => apiClient.delete(`/tenants/${tenantId}/members/${userId}`));
 };

 const nonMembers = allUsers.filter((u) => !members.find((m) => m.id === u.id));

 return (
 <Modal
 open
 onClose={onClose}
 size="md"
 closeOnBackdrop={false}
 icon={<Users size={15} className="text-text-primary" />}
 title={t('tenant.members')}
 // sm+: header padding of the former hand-rolled dialog (px-5 py-4).
 className="sm:rounded-2xl sm:[&>div:first-child]:px-5 sm:[&>div:first-child]:py-4"
 overlayClassName="backdrop-blur-none"
 bodyClassName="px-5 py-4 space-y-3 sm:max-h-80"
 footerClassName="flex-nowrap justify-start px-5"
 footer={nonMembers.length > 0 ? (
 <>
 <select
 value={addingId}
 onChange={(e) => setAddingId(e.target.value ? Number(e.target.value) : '')}
 className="min-w-0 flex-1 rounded-lg bg-bg-primary px-3 py-1.5 coarse:py-2 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
 >
 <option value="">{t('tenant.selectUser')}</option>
 {nonMembers.map((u) => (
 <option key={u.id} value={u.id}>{u.username}</option>
 ))}
 </select>
 <Button size="sm" onClick={addMember} disabled={!addingId || busy} className="shrink-0 coarse:min-h-10">
 {t('tenant.addMember')}
 </Button>
 </>
 ) : undefined}
 >
 {loading ? (
 <p className="text-sm text-text-muted text-center py-4">{t('common.loading')}</p>
 ) : members.length === 0 ? (
 <p className="text-sm text-text-muted text-center py-4">{t('tenant.noMembers')}</p>
 ) : (
 members.map((m) => (
 <div key={m.id} className="flex items-center justify-between gap-2">
 <div className="min-w-0 break-words">
 <span className="text-sm text-text-primary font-medium">{m.username}</span>
 {m.display_name && (
 <span className="ml-1 text-xs text-text-muted">({m.display_name})</span>
 )}
 </div>
 <div className="flex items-center gap-2 shrink-0">
 {/* The real roles (administrator or a permission set), changed after a confirmation: a one-click
 toggle promoted any member to administrator and lost a particular permission set. */}
 <select
 value={m.tenantRole === 'member' ? 'user' : m.tenantRole}
 disabled={busy}
 onChange={(e) => { void changeRole(m, e.target.value); }}
 aria-label={t('tenant.roleOf', { user: m.username }) || `Role of ${m.username}`}
 className={`max-w-[10rem] rounded-lg bg-bg-primary px-2 py-0.5 coarse:py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-accent ${
 m.tenantRole === 'admin' ? 'text-accent' : 'text-text-secondary'
 }`}
 >
 {roleOptionsOf(m.tenantRole).map((r) => (
 <option key={r.value} value={r.value}>{r.label}</option>
 ))}
 </select>
 <IconButton
 label={t('tenant.removeMember')}
 icon={<X size={13} />}
 size="xs"
 variant="plain"
 onClick={() => removeMember(m.id)}
 className="hover:text-red-400"
 />
 </div>
 </div>
 ))
 )}
 </Modal>
 );
}

// ── Main page ───────────────────────────────────────────────────────────────
export function AdminTenantsPage() {
 const { t } = useTranslation();
 const confirm = useConfirm();
 const [tenants, setTenants] = useState<TenantWithMemberCount[]>([]);
 const [loading, setLoading] = useState(true);
 const [creating, setCreating] = useState(false);
 const [editingId, setEditingId] = useState<number | null>(null);
 const [membersForId, setMembersForId] = useState<number | null>(null);

 const fetchTenants = async () => {
 setLoading(true);
 try {
 const res = await apiClient.get<{ data?: TenantWithMemberCount[] }>('/tenants');
 setTenants(res.data.data ?? []);
 } catch (err) {
 toast.error(apiErrorMessage(err));
 } finally {
 setLoading(false);
 }
 };

 useEffect(() => { fetchTenants(); }, []);

 // The forms show the server's refusal under their fields.
 const asFormError = (err: unknown): Error => new Error(apiErrorMessage(err) || t('common.error'));

 const handleCreate = async (name: string, slug: string) => {
 try {
 await apiClient.post('/tenants', { name, slug });
 } catch (err) {
 throw asFormError(err);
 }
 setCreating(false);
 fetchTenants();
 };

 const handleUpdate = async (id: number, name: string, slug: string) => {
 try {
 await apiClient.put(`/tenants/${id}`, { name, slug });
 } catch (err) {
 throw asFormError(err);
 }
 setEditingId(null);
 fetchTenants();
 };

 const setTwoStepApproval = async (id: number, checked: boolean) => {
 try {
 await apiClient.put(`/tenants/${id}`, { twoStepApproval: checked });
 } catch (err) {
 if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
 }
 fetchTenants();
 };

 // Irreversible (the tenant's keys are destroyed, its devices and data deleted): its slug is typed to
 // confirm, then the server asks for a fresh second factor (the apiClient interceptor prompts for it).
 const handleDelete = async (tenant: TenantWithMemberCount) => {
 if (!(await confirm({
 title: t('tenant.deleteTitle', { name: tenant.name }) || `Delete the workspace "${tenant.name}"`,
 message: t('tenant.confirmDeleteTyped', { slug: tenant.slug }) || `All its data, its devices under management included, will be permanently removed. Type "${tenant.slug}" to confirm.`,
 danger: true,
 requireText: tenant.slug,
 }))) return;
 try {
 await apiClient.delete(`/tenants/${tenant.id}`);
 toast.success(t('tenant.deleted', { name: tenant.name }) || `Workspace "${tenant.name}" deleted`);
 // The tenant switcher must not offer it any more.
 void useTenantStore.getState().fetchTenants();
 } catch (err) {
 // A refusal (a linked Android enterprise: 409, a second factor declined…) is said, never swallowed.
 if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
 }
 fetchTenants();
 };

 return (
 <PageContainer>
 <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
 <div>
 <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
 <Building2 size={20} className="text-accent" />
 {t('tenant.pageTitle')}
 </h1>
 <p className="text-sm text-text-muted mt-0.5">{t('tenant.pageDesc')}</p>
 </div>
 {!creating && (
 <Button size="sm" onClick={() => setCreating(true)}>
 <Plus size={14} />
 {t('tenant.create')}
 </Button>
 )}
 </div>

 {creating && (
 <div className="mb-4 p-4 rounded-xl bg-bg-secondary">
 <TenantForm onSave={handleCreate} onCancel={() => setCreating(false)} />
 </div>
 )}

 {loading ? (
 <p className="text-sm text-text-muted">{t('common.loading')}</p>
 ) : tenants.length === 0 ? (
 <p className="text-sm text-text-muted">{t('tenant.noTenants')}</p>
 ) : (
 <div className="space-y-2">
 {tenants.map((tenant) => (
 <div
 key={tenant.id}
 className="rounded-xl bg-bg-secondary px-4 py-3"
 >
 {editingId === tenant.id ? (
 <TenantForm
 initial={{ name: tenant.name, slug: tenant.slug }}
 onSave={(name, slug) => handleUpdate(tenant.id, name, slug)}
 onCancel={() => setEditingId(null)}
 />
 ) : (
 <div className="flex flex-wrap items-center justify-between gap-3">
 <div className="min-w-0">
 <div className="flex items-center gap-2">
 <Building2 size={14} className="text-accent shrink-0" />
 <span className="text-sm font-semibold text-text-primary break-words min-w-0">{tenant.name}</span>
 {tenant.id === 1 && (
 <span className="text-[10px] bg-accent/15 text-accent rounded px-1.5 py-0.5">
 {t('tenant.default')}
 </span>
 )}
 </div>
 <p className="text-xs text-text-muted mt-0.5">
 /{tenant.slug} · {t('tenant.createdAt')} {new Date(tenant.createdAt).toLocaleDateString()}
 </p>
 <label className="flex items-center gap-2 mt-2 coarse:py-1 cursor-pointer">
 <input
 type="checkbox"
 checked={!!tenant.twoStepApproval}
 onChange={(e) => { void setTwoStepApproval(tenant.id, e.target.checked); }}
 className="accent-accent shrink-0 coarse:h-5 coarse:w-5"
 />
 <span className="text-[11px] text-text-secondary">
 {t('tenant.twoStepApproval', 'Require 2nd-admin approval for destructive actions')}
 </span>
 </label>
 </div>
 <div className="flex items-center gap-1 shrink-0">
 <button
 onClick={() => setMembersForId(tenant.id)}
 title={t('tenant.manageMembers')}
 className="flex items-center gap-1 text-xs text-text-muted hover:text-text-primary px-2 py-1 coarse:min-h-10 rounded-md hover:bg-bg-hover transition-colors"
 >
 <Users size={13} />
 {t('tenant.members')}
 </button>
 <IconButton
 label={t('common.edit')}
 icon={<Pencil size={13} />}
 onClick={() => setEditingId(tenant.id)}
 className="rounded-md"
 />
 {tenant.id !== 1 && (
 <IconButton
 label={t('common.delete')}
 icon={<Trash2 size={13} />}
 onClick={() => handleDelete(tenant)}
 className="rounded-md hover:text-red-400"
 />
 )}
 </div>
 </div>
 )}
 </div>
 ))}
 </div>
 )}

 {membersForId !== null && (
 <MembersPanel tenantId={membersForId} onClose={() => setMembersForId(null)} />
 )}
 </PageContainer>
 );
}
