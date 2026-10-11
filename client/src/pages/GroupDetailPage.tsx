import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { Pencil, Trash2, ArrowLeft, FolderOpen } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useGroupStore } from '@/store/groupStore';
import { useAuthStore } from '@/store/authStore';
import { anonymize } from '@/utils/anonymize';
import { groupsApi } from '@/api/groups.api';
import type { DeviceGroup } from '@obligarth/shared';
import { DeviceTable } from '@/components/devices/DeviceTable';
import { TenantBadge } from '@/components/common/TenantBadge';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import toast from 'react-hot-toast';
import { PageContainer } from '@/components/common/PageContainer';
import { useConfirm } from '@/components/common/ConfirmDialog';

export function GroupDetailPage() {
 const { id } = useParams<{ id: string }>();
 const navigate = useNavigate();
 const { t } = useTranslation();
 const { isAdmin, canWriteGroup } = useAuthStore();
 const { removeGroup, fetchGroups, fetchTree } = useGroupStore();
 // Shared dialog (window.confirm is a no-op in the Android WebView — docs §5.6).
 const confirm = useConfirm();

 const groupId = parseInt(id!, 10);
 const canWrite = canWriteGroup(groupId);

 const [group, setGroup] = useState<DeviceGroup | null>(null);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
 async function loadData() {
 try {
 const g = await groupsApi.getById(groupId);
 setGroup(g);
 } catch {}
 setLoading(false);
 }
 loadData();
 }, [groupId]);

 if (loading && !group) {
 return (
 <div className="flex h-full items-center justify-center">
 <LoadingSpinner size="lg" />
 </div>
 );
 }

 if (!group) {
 return (
 <div className="flex h-full flex-col items-center justify-center">
 <p className="text-text-muted">{t('groups.notFound') || 'Group not found'}</p>
 <Link to="/" className="mt-4">
 <Button variant="secondary">{t('groups.backToDashboard')}</Button>
 </Link>
 </div>
 );
 }

 const handleDelete = async () => {
 if (!(await confirm({ message: t('groups.confirmDelete', { name: group.name }), danger: true }))) return;
 try {
 // A deletion that changes what devices inherit may wait for a second approver: nothing deleted yet.
 if (!(await groupsApi.delete(groupId))) {
 toast.success(t('groups.deleteAwaitingApproval') || 'Deletion sent for approval: it will apply once a second administrator approves it');
 return;
 }
 removeGroup(groupId);
 fetchGroups();
 fetchTree();
 toast.success(t('groups.deleted'));
 navigate('/');
 } catch {
 toast.error(t('groups.failedDelete'));
 }
 };

 return (
 <PageContainer>
 {/* Back button */}
 <Link to="/" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary mb-4 coarse:min-h-10">
 <ArrowLeft size={14} />
 {t('groups.backToDashboard')}
 </Link>

 {/* Header — below md the title block takes the full width (long
 names wrap instead of being squeezed to nothing) and the actions
 drop to their own line. */}
 <div className="flex items-start justify-between mb-6 max-md:flex-wrap max-md:gap-3">
 <div className="flex items-center gap-4 max-md:min-w-0 max-md:basis-full max-sm:gap-3">
 <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10 max-md:shrink-0 max-sm:h-10 max-sm:w-10">
 <FolderOpen size={24} className="text-accent" />
 </div>
 <div className="max-md:min-w-0">
 <div className="flex items-center gap-2 flex-wrap">
 <h1 className="text-2xl font-semibold text-text-primary max-md:min-w-0 max-md:break-words max-sm:text-xl">{anonymize(group.name)}</h1>
 {/* Tenant pill on master/god view so the admin sees which
 customer they're operating on at a glance. */}
 <TenantBadge tenantId={group.tenantId} tenantName={group.tenantName} size="md" />
 </div>
 {group.description && (
 <p className="text-sm text-text-muted mt-1">{group.description}</p>
 )}
 </div>
 </div>

 {canWrite && (
 <div className="flex items-center gap-2 max-md:flex-wrap">
 <Link to={`/group/${groupId}/edit`}>
 <Button variant="secondary" size="sm">
 <Pencil size={14} className="mr-1.5" />
 {t('common.edit')}
 </Button>
 </Link>
 {isAdmin() && (
 <Button variant="danger" size="sm" onClick={handleDelete}>
 <Trash2 size={14} className="mr-1.5" />
 {t('common.delete')}
 </Button>
 )}
 </div>
 )}
 </div>

 {/* Device grid — same UX as /devices, pre-filtered on this group (+ descendants).
 `embedded`: this page already pads the content, so the table drops
 its own padding below lg (desktop keeps the historic double p-6). */}
 <DeviceTable mode="monitoring" groupId={groupId} embedded />
 </PageContainer>
 );
}
