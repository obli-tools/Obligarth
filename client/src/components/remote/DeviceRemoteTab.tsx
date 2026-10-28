import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, Hand } from 'lucide-react';
import type { LegacyAgentDeviceAction } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { Button } from '@/components/common/Button';
import { legacyActionLabel, useLegacyActionRunner } from '@/components/mdm/actions/useLegacyActionRunner';
import { trCode } from '@/utils/apiError';
import { RemoteSessionList } from './RemoteSessionList';

// The Remote assistance tab of a device of the bridge agent (P0-15 §7): « See the screen » and « Take control » with
// the reason they are not possible (the menu of the server, checkOpenable), then the sessions of the device.

export function DeviceRemoteTab({ deviceId, canAct }: { deviceId: number; canAct: boolean }) {
  const { t } = useTranslation();
  const [actions, setActions] = useState<LegacyAgentDeviceAction[] | null>(null);
  const load = useCallback(() => {
    legacyAgentApi.actions(deviceId).then(setActions).catch(() => setActions([]));
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);
  const runner = useLegacyActionRunner({ deviceId, onQueued: load });
  const remote = (actions ?? []).filter((a) => a.type === 'remote.view' || a.type === 'remote.control');
  return (
    <div className="space-y-4">
      {remote.length > 0 && (
        <div className="flex flex-wrap gap-3">
          {remote.map((a) => (
            <div key={a.type} className="min-w-0">
              <Button size="sm" variant={a.type === 'remote.control' ? 'primary' : 'secondary'} disabled={!canAct || !a.available} onClick={() => runner.run(a)}>
                {a.type === 'remote.control' ? <Hand size={14} className="mr-1" /> : <Eye size={14} className="mr-1" />}
                {legacyActionLabel(t, a.type)}
              </Button>
              {!a.available && a.unavailable && (
                <p className="mt-1 max-w-xs text-[11px] text-text-muted">{trCode(`legacyAgent.unavailable.${a.unavailable}`, a.unavailable)}</p>
              )}
            </div>
          ))}
        </div>
      )}
      <RemoteSessionList filters={{ deviceId }} showDevice={false} />
      {runner.dialogs}
    </div>
  );
}
