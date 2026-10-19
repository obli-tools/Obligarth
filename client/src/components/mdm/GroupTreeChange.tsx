import { useCallback, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { PolicyImpact } from '@obligarth/shared';
import { groupsApi } from '@/api/groups.api';
import { isStepUpHandled } from '@/api/client';
import { ImpactConfirmDialog } from '@/components/mdm/ImpactPreview';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';

// A group moved in the tree or deleted changes what the devices of its subtree inherit (the policies assigned to
// its ancestors, its own assignments): the server previews it (?dryRun=true), then asks for a second factor or a
// second approver (modele-donnees-mdm S12, lot B5b). The console shows that preview before the confirmation:
// always for a deletion; for a move, as soon as it touches a device, creates a conflict or needs an approver (a
// move that changes nothing for any device goes through at once).

export type GroupTreeChange =
  | { kind: 'move'; groupId: number; groupName: string; newParentId: number | null; newParentName?: string | null;
      /** Runs once the group has moved (the new order among its siblings). */
      after?: () => Promise<void> }
  | { kind: 'delete'; groupId: number; groupName: string; hasSubgroups?: boolean };

/** What the change did: applied at once, waiting for a second approver (nothing changed yet), or failed. */
export type GroupTreeOutcome = 'done' | 'awaiting_approval' | 'failed';

const quiet = (i: PolicyImpact): boolean => i.devicesTouched === 0 && i.conflicts.length === 0 && !i.approval.required
  && i.artifacts.removals === 0 && i.artifacts.appRemovals === 0 && i.artifacts.kioskLockChanges === 0;

/**
 * `request(change)` previews a change of the tree and applies it (after the confirmation of its preview when
 * there is something to confirm); `dialog` is rendered once by the caller. `onDone` tells the caller what happened.
 */
export function useGroupTreeChange(onDone?: (change: GroupTreeChange, outcome: GroupTreeOutcome) => void): {
  request: (change: GroupTreeChange) => Promise<void>;
  dialog: ReactNode;
} {
  const { t } = useTranslation();
  const [pending, setPending] = useState<{ change: GroupTreeChange; impact: PolicyImpact | null } | null>(null);

  const apply = useCallback(async (change: GroupTreeChange): Promise<void> => {
    try {
      if (change.kind === 'move') {
        const moved = await groupsApi.move(change.groupId, change.newParentId);
        if (moved === null) {
          toast(t('groups.moveAwaitingApproval') || 'Move sent for approval: it will apply once a second administrator approves it', { duration: 7000 });
          onDone?.(change, 'awaiting_approval');
          return;
        }
        await change.after?.();
        toast.success(t('groups.moved', 'Group moved'));
      } else {
        if (!(await groupsApi.delete(change.groupId))) {
          toast(t('groups.deleteAwaitingApproval') || 'Deletion sent for approval: it will apply once a second administrator approves it', { duration: 7000 });
          onDone?.(change, 'awaiting_approval');
          return;
        }
        toast.success(t('groups.deleted') || 'Group deleted');
      }
      onDone?.(change, 'done');
    } catch (err) {
      if (!isStepUpHandled(err)) {
        toast.error(apiErrorMessage(err, change.kind === 'move' ? (t('groups.failedMove') || 'Failed to move group') : (t('groups.failedDelete') || 'Failed to delete group')), { duration: 7000 });
      }
      onDone?.(change, 'failed');
      throw err;
    }
  }, [t, onDone]);

  const request = useCallback(async (change: GroupTreeChange): Promise<void> => {
    if (change.kind === 'delete') {
      // A group with subgroups is not deleted: its subgroups are moved first (the server answers 409 groupHasSubgroups).
      if (change.hasSubgroups) {
        toast.error(t('errors.groupHasSubgroups') || 'This group has subgroups: move them first, then delete the group.', { duration: 7000 });
        onDone?.(change, 'failed');
        return;
      }
      setPending({ change, impact: null });
      return;
    }
    let impact: PolicyImpact;
    try {
      impact = await groupsApi.previewMove(change.groupId, change.newParentId);
    } catch (err) {
      toast.error(apiErrorMessage(err, t('groups.failedMove') || 'Failed to move group'), { duration: 7000 });
      onDone?.(change, 'failed');
      return;
    }
    if (quiet(impact)) {
      await apply(change).catch(() => { /* told above */ });
      return;
    }
    setPending({ change, impact });
  }, [apply, onDone, t]);

  const change = pending?.change;
  const name = change ? anonymize(change.groupName) : '';
  const dialog = (
    <ImpactConfirmDialog
      open={pending !== null}
      onClose={() => setPending(null)}
      danger={change?.kind === 'delete'}
      allowConflicts
      title={change?.kind === 'delete'
        ? (t('groups.deletePreviewTitle', { name }) || `Delete the group "${name}"`)
        : (t('groups.movePreviewTitle', { name }) || `Move the group "${name}"`)}
      intro={change?.kind === 'delete'
        ? (t('groups.deletePreviewIntro') || 'The assignments of this group are removed with it and its devices become ungrouped: they lose what they inherited from it.')
        : change?.kind === 'move'
          ? (t('groups.movePreviewIntro', { parent: change.newParentName ? anonymize(change.newParentName) : (t('groupPanel.rootLevel') || 'Root level (no parent)') })
            || 'The devices of this group and of its subgroups stop inheriting the policies of the groups it leaves, and inherit those of its new parent.')
          : undefined}
      confirmLabel={change?.kind === 'delete' ? (t('common.delete') || 'Delete') : (t('devices.batch.moveHere') || 'Move')}
      load={async () => {
        if (pending?.impact) return pending.impact;
        return change!.kind === 'delete' ? groupsApi.previewDelete(change!.groupId) : groupsApi.previewMove(change!.groupId, (change as { newParentId: number | null }).newParentId);
      }}
      apply={() => apply(change!)}
    />
  );
  return { request, dialog };
}
