import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import type { BenchStationView } from '@obligarth/shared';
import { normaliseBenchVerificationCode } from '@obligarth/shared';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { fieldCls, labelCls } from './benchUi';

// The approval of a bench station (lot BANC §3.3): the code the station shows, typed again by the administrator and
// checked by the server (verification_mismatch), then the second factor the server asks for (the client's dialog).

export function StationDecisionDialog({ station, onClose, onApprove }: {
  station: BenchStationView; onClose: () => void; onApprove: (code: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const typed = normaliseBenchVerificationCode(code);
  const ready = typed.length === 8;
  const approve = async () => {
    setBusy(true);
    try { await onApprove(code.trim()); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} size="md" icon={<ShieldCheck className="h-4 w-4 text-accent" />}
      title={t('bench.stations.approveTitle', { name: station.name }) || `Approve ${station.name}`}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void approve()} disabled={!ready || busy}>{t('bench.stations.approve') || 'Approve'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <p className="text-text-secondary">{t('bench.stations.approveHint') || 'Read the verification code on the screen of the station, then type it here. A second factor is asked next.'}</p>
        <div className="rounded-xl bg-bg-secondary px-3 py-2 text-xs text-text-muted">
          {t('bench.stations.host') || 'Host'} : <span className="text-text-primary">{station.hostname || '—'}</span>
          {' · '}{t('bench.stations.registerIp') || 'Registered from'} : <span className="font-mono text-text-primary">{station.registerIp ?? '—'}</span>
        </div>
        <label className={labelCls}>{t('bench.stations.verificationCode') || 'Verification code'}
          <input className={`${fieldCls} font-mono uppercase tracking-widest`} value={code} maxLength={9} autoComplete="off" spellCheck={false}
            placeholder="XXXX-XXXX" onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && ready) void approve(); }} />
        </label>
      </div>
    </Modal>
  );
}
