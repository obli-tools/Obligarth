import { useCallback, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { PolicyImpact } from '@obligarth/shared';
import { mdmApi } from '@/api/mdm.api';
import { isStepUpHandled } from '@/api/client';
import { ImpactConfirmDialog } from '@/components/mdm/ImpactPreview';
import { apiErrorMessage } from '@/utils/apiError';

// Devices moved into a group inherit what its ancestry carries (the policies of the group and of its ancestors):
// the server previews the move (?dryRun=true), then asks for a second factor or a second approver like a change of
// assignments (modele-donnees-mdm S12; decision of the owners of 15/10/2026). The console shows that preview before
// the confirmation as soon as the move touches a device's configuration, creates a conflict or needs an approver; a
// move that changes nothing for any device goes through at once.

export interface DeviceMove {
  deviceIds: number[];
  groupId: number | null;
  /** One device from its page: the route of that device (its tenant, from the global view too). */
  single?: boolean;
}

/** What the move did: applied at once, waiting for a second approver (nothing changed yet), or failed. */
export type DeviceMoveOutcome = 'done' | 'awaiting_approval' | 'failed';

const quiet = (i: PolicyImpact): boolean => i.devicesTouched === 0 && i.conflicts.length === 0 && !i.approval.required
  && i.artifacts.removals === 0 && i.artifacts.appRemovals === 0 && i.artifacts.kioskLockChanges === 0;

/** `request(move)` previews a move and applies it (after the confirmation of its preview when there is something to
 *  confirm); `dialog` is rendered once by the caller; `onDone` tells the caller what happened. */
export function useDeviceMove(onDone?: (move: DeviceMove, outcome: DeviceMoveOutcome) => void): {
  request: (move: DeviceMove) => Promise<void>;
  dialog: ReactNode;
} {
  const { t } = useTranslation();
  const [pending, setPending] = useState<{ move: DeviceMove; impact: PolicyImpact } | null>(null);

  const preview = (move: DeviceMove): Promise<PolicyImpact> => (move.single
    ? mdmApi.previewSetGroupOne(move.deviceIds[0], move.groupId)
    : mdmApi.previewSetGroup(move.deviceIds, move.groupId));

  const apply = useCallback(async (move: DeviceMove): Promise<void> => {
    try {
      let count = move.deviceIds.length;
      let waiting = false;
      if (move.single) {
        const r = await mdmApi.setGroup(move.deviceIds[0], move.groupId);
        waiting = r === null;
        count = r?.changed ? 1 : 0;
      } else {
        const r = await mdmApi.batchSetGroup(move.deviceIds, move.groupId);
        waiting = r === null;
        count = r?.changed ?? 0;
      }
      if (waiting) {
        toast(t('mdm.outcome.awaitingApproval') || 'Waiting for a second approver: nothing has changed yet.', { duration: 7000 });
        onDone?.(move, 'awaiting_approval');
        return;
      }
      toast.success(t('devices.batch.groupChanged', { count, defaultValue: `Moved ${count} device${count > 1 ? 's' : ''}` }));
      onDone?.(move, 'done');
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
      onDone?.(move, 'failed');
      throw err;
    }
  }, [t, onDone]);

  const request = useCallback(async (move: DeviceMove): Promise<void> => {
    let impact: PolicyImpact;
    try {
      impact = await preview(move);
    } catch (err) {
      toast.error(apiErrorMessage(err), { duration: 7000 });
      onDone?.(move, 'failed');
      return;
    }
    if (quiet(impact)) {
      await apply(move).catch(() => { /* told above */ });
      return;
    }
    setPending({ move, impact });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apply, onDone]);

  const move = pending?.move;
  const dialog = (
    <ImpactConfirmDialog
      open={pending !== null}
      onClose={() => setPending(null)}
      allowConflicts
      title={t('devices.move.previewTitle', { count: move?.deviceIds.length ?? 0 }) || `Move ${move?.deviceIds.length ?? 0} device(s)`}
      intro={t('devices.move.previewIntro') || 'The devices stop inheriting the policies of the group they leave, and inherit those of the group they join and of its ancestors.'}
      confirmLabel={t('devices.batch.moveHere') || 'Move'}
      load={async () => pending!.impact}
      apply={() => apply(move!)}
    />
  );
  return { request, dialog };
}
