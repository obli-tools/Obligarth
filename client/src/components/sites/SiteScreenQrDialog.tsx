import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Maximize2, MonitorSmartphone, X } from 'lucide-react';
import { LEGACY_AGENT_TOKEN_BOUNDS, type LegacyAgentTokenCreated, type SiteDetail } from '@obligarth/shared';
import { legacyAgentApi } from '@/api/legacyAgent.api';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';

// "QR code on screen" on the page of a site: the enrollment QR code shown on the console's screen, for a technician who
// scans it with the phone in hand, nothing printed. It is an ordinary token of the site (POST /api/legacy-agent/tokens
// with siteId, siteSheet false): the printed sheet of the store keeps working (only a new sheet revokes the previous
// one), the phone is attached to the site and filed in its group. Short by default (1 day, 5 phones). Like every
// token, the QR code is shown once: nothing of it is kept once the window closes.

const fieldCls = 'mt-1 w-full rounded-lg border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none';
const labelCls = 'block text-xs font-medium text-text-muted';
const SCREEN_DEFAULTS = { days: 1, maxUses: 5 } as const;

/** Mounted while open only: a fresh form each time, the QR code gone once closed. */
export function SiteScreenQrDialog({ site, onClose }: { site: SiteDetail; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const [form, setForm] = useState(() => ({
    label: t('sites.screen.defaultLabel', { code: site.code }) || `Screen ${site.code}`, days: String(SCREEN_DEFAULTS.days), maxUses: String(SCREEN_DEFAULTS.maxUses),
  }));
  const [token, setToken] = useState<LegacyAgentTokenCreated | null>(null);
  const [busy, setBusy] = useState(false);
  const [full, setFull] = useState(false);
  // Escape leaves the full screen (the Modal is not mounted then).
  useEffect(() => {
    if (!full) return undefined;
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') setFull(false); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [full]);

  const days = Number(form.days);
  const maxUses = Number(form.maxUses);
  const valid = form.label.trim().length > 0 && form.label.trim().length <= 100
    && Number.isInteger(days) && days >= 1 && days <= LEGACY_AGENT_TOKEN_BOUNDS.daysMax
    && Number.isInteger(maxUses) && maxUses >= 1 && maxUses <= LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax;

  const create = async () => {
    setBusy(true);
    try {
      setToken(await legacyAgentApi.createToken({ label: form.label.trim(), siteId: site.id, groupId: null, days, maxUses }));
    } catch (err) {
      toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally { setBusy(false); }
  };
  const close = () => { if (!busy) { setToken(null); setFull(false); onClose(); } };

  if (!token) {
    return (
      <Modal open onClose={close} size="md" title={t('sites.screen.title', { name: site.name }) || `QR code on screen for ${site.name}`} icon={<MonitorSmartphone className="h-5 w-5" />}
        footer={(
          <>
            <Button variant="secondary" onClick={close} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
            <Button onClick={() => { void create(); }} loading={busy} disabled={!valid}>{t('sites.screen.create') || 'Show the QR code'}</Button>
          </>
        )}>
        <div className="space-y-3 text-sm">
          <p className="text-xs text-text-muted">{t('sites.screen.intro') || 'The enrollment QR code shown on this screen, to scan with the phone: nothing to print. The phones that scan it are enrolled, attached to the site and filed in its group. The printed sheet of the site keeps working.'}</p>
          <label className={labelCls}>{t('sites.sheet.label') || 'Label'}
            <input className={fieldCls} maxLength={100} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} /></label>
          <div className="grid grid-cols-2 gap-3">
            <label className={labelCls}>{t('sites.sheet.days') || 'Validity (days)'}
              <input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.daysMax} value={form.days} onChange={(e) => setForm({ ...form, days: e.target.value })} /></label>
            <label className={labelCls}>{t('sites.sheet.maxUses') || 'Phones (quota)'}
              <input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax} value={form.maxUses} onChange={(e) => setForm({ ...form, maxUses: e.target.value })} /></label>
          </div>
        </div>
      </Modal>
    );
  }

  const expires = new Date(token.expiresAt).toLocaleString(i18n.language || undefined, { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' });
  const validity = t('sites.screen.validUntil', { date: expires, count: token.maxUses }) || `Valid until ${expires}, for ${token.maxUses} phone(s).`;
  const qr = (cls: string) => <img src={token.qrPng} alt={t('sites.sheet.qrAlt') || 'Enrollment QR code'} className={`${cls} [image-rendering:pixelated]`} />;

  if (full) {
    // Full window, white, the QR code as large as the screen allows: what the phone's camera reads best.
    return createPortal(
      <div className="fixed inset-0 z-[100] flex flex-col items-center justify-center gap-4 bg-white p-6 text-black" role="dialog" aria-modal="true">
        <button type="button" className="absolute right-4 top-4 rounded-full p-2 text-gray-600 hover:bg-gray-100" onClick={() => setFull(false)}
          aria-label={t('sites.screen.exitFull') || 'Leave full screen'}><X className="h-6 w-6" /></button>
        <p className="text-2xl font-bold">{anonymize(site.name)}</p>
        {qr('h-[min(75vh,75vw)] w-[min(75vh,75vw)]')}
        <p className="text-lg">{validity}</p>
      </div>,
      document.body,
    );
  }

  return (
    <Modal open onClose={close} size="lg" title={t('sites.screen.readyTitle') || 'Scan this QR code with the phone'} icon={<MonitorSmartphone className="h-5 w-5" />}
      footer={(
        <>
          <Button variant="secondary" onClick={close}>{t('common.close') || 'Close'}</Button>
          <Button onClick={() => setFull(true)}><Maximize2 className="mr-1 h-4 w-4" />{t('sites.screen.full') || 'Full screen'}</Button>
        </>
      )}>
      <p className="mb-3 text-xs text-amber-400">{t('sites.screen.onceWarning') || 'The QR code is shown only once: once this window is closed, create a new one. Do not show it to anyone outside the company: it enrolls phones into your fleet.'}</p>
      <div className="flex flex-col items-center gap-3 rounded-lg bg-white p-6 text-black">
        {qr('h-80 w-80')}
        <p className="text-sm font-medium">{validity}</p>
      </div>
      <ol className="mt-3 list-decimal space-y-1 pl-6 text-sm text-text-secondary">
        <li>{t('sites.sheet.step2') || 'Open the Obligarth Agent app.'}</li>
        <li>{t('sites.screen.step') || 'Tap "Scan the enrollment QR code" and point the camera at this screen.'}</li>
        <li>{t('sites.sheet.step4') || 'Tap "Activate" to allow the management of the phone.'}</li>
      </ol>
    </Modal>
  );
}

