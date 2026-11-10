import { useEffect, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Printer, QrCode } from 'lucide-react';
import { LEGACY_AGENT_TOKEN_BOUNDS, SITE_SHEET_DEFAULTS, type SiteDetail, type SiteEnrollmentSheet } from '@obligarth/shared';
import { sitesApi } from '@/api/sites.api';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { anonymize } from '@/utils/anonymize';
import { apiErrorMessage } from '@/utils/apiError';

// "Enroll a phone" on the page of a site (lot P1-QR §3.2): the label, validity and quota of the sheet (30 days, 5 phones
// by default, decision D2), then the printable A4 sheet: the name of the site, the enrollment QR code (drawn by the
// server), its expiry and the four steps of the store. The sheet replaces the previous one of the site (revoked by the
// server). Like the token, the QR code is shown only once: nothing of it is kept once the dialog closes. Printing hides
// the console (index.css, body.obg-print-sheet) and prints the sheet rendered beside it (.obg-print-root).

const fieldCls = 'mt-1 w-full rounded-lg border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none';
const labelCls = 'block text-xs font-medium text-text-muted';

/** Mounted while open only (the page renders it on demand): a fresh form each time, the sheet gone once closed. */
export function SiteSheetDialog({ site, onClose }: { site: SiteDetail; onClose: () => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState(() => ({
    label: t('sites.sheet.defaultLabel', { code: site.code }) || `Sheet ${site.code}`, days: String(SITE_SHEET_DEFAULTS.days), maxUses: String(SITE_SHEET_DEFAULTS.maxUses),
  }));
  const [sheet, setSheet] = useState<SiteEnrollmentSheet | null>(null);
  const [busy, setBusy] = useState(false);

  const days = Number(form.days);
  const maxUses = Number(form.maxUses);
  const valid = form.label.trim().length > 0 && form.label.trim().length <= 100
    && Number.isInteger(days) && days >= 1 && days <= LEGACY_AGENT_TOKEN_BOUNDS.daysMax
    && Number.isInteger(maxUses) && maxUses >= 1 && maxUses <= LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax;

  const create = async () => {
    setBusy(true);
    try {
      const s = await sitesApi.enrollmentSheet(site.id, { label: form.label.trim(), days, maxUses });
      setSheet(s);
      if (s.revokedPrevious > 0) toast.success(t('sites.sheet.replaced', { count: s.revokedPrevious }) || 'The previous sheet of the site no longer works.');
    } catch (err) {
      toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally { setBusy(false); }
  };
  const close = () => { if (!busy) { setSheet(null); onClose(); } };

  if (!sheet) {
    return (
      <Modal open onClose={close} size="md" title={t('sites.sheet.title', { name: site.name }) || `Enroll a phone at ${site.name}`} icon={<QrCode className="h-5 w-5" />}
        footer={(
          <>
            <Button variant="secondary" onClick={close} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
            <Button onClick={() => { void create(); }} loading={busy} disabled={!valid}>{t('sites.sheet.create') || 'Create the sheet'}</Button>
          </>
        )}>
        <div className="space-y-3 text-sm">
          <p className="text-xs text-text-muted">{t('sites.sheet.intro') || 'A printable sheet with a QR code: the phones that scan it are enrolled, attached to the site and filed in its group.'}</p>
          <label className={labelCls}>{t('sites.sheet.label') || 'Label'}
            <input className={fieldCls} maxLength={100} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} /></label>
          <div className="grid grid-cols-2 gap-3">
            <label className={labelCls}>{t('sites.sheet.days') || 'Validity (days)'}
              <input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.daysMax} value={form.days} onChange={(e) => setForm({ ...form, days: e.target.value })} /></label>
            <label className={labelCls}>{t('sites.sheet.maxUses') || 'Phones (quota)'}
              <input className={fieldCls} type="number" min={1} max={LEGACY_AGENT_TOKEN_BOUNDS.maxUsesMax} value={form.maxUses} onChange={(e) => setForm({ ...form, maxUses: e.target.value })} /></label>
          </div>
          <p className="text-xs text-amber-400">{t('sites.sheet.replaceWarning') || 'The previous sheet of the site stops working as soon as this one is created.'}</p>
        </div>
      </Modal>
    );
  }
  return (
    <>
      <Modal open onClose={close} size="lg" title={t('sites.sheet.readyTitle') || 'Sheet created: print it now'} icon={<QrCode className="h-5 w-5" />}
        footer={(
          <>
            <Button variant="secondary" onClick={close}>{t('common.close') || 'Close'}</Button>
            <Button onClick={() => window.print()}><Printer className="mr-1 h-4 w-4" />{t('sites.sheet.print') || 'Print'}</Button>
          </>
        )}>
        <p className="mb-3 text-xs text-amber-400">{t('sites.sheet.onceWarning') || 'The QR code is shown only once: print the sheet before closing this window. Keep it out of public reach: it enrolls phones into your fleet.'}</p>
        <div className="overflow-hidden rounded-lg bg-white text-black shadow-inner">
          <SheetPage sheet={sheet} preview />
        </div>
      </Modal>
      <PrintRoot><SheetPage sheet={sheet} /></PrintRoot>
    </>
  );
}

/** The sheet, mounted beside the console only while it is shown: what the printer gets. */
function PrintRoot({ children }: { children: ReactNode }) {
  useEffect(() => {
    document.body.classList.add('obg-print-sheet');
    return () => { document.body.classList.remove('obg-print-sheet'); };
  }, []);
  return createPortal(<div className="obg-print-root">{children}</div>, document.body);
}

/** One A4 page: the site, the QR code, the expiry and the four steps (formal "vous" in French). */
function SheetPage({ sheet, preview = false }: { sheet: SiteEnrollmentSheet; preview?: boolean }) {
  const { t, i18n } = useTranslation();
  const expires = new Date(sheet.token.expiresAt).toLocaleDateString(i18n.language || undefined, { day: 'numeric', month: 'long', year: 'numeric' });
  const steps = [
    sheet.apkUrl
      ? (t('sites.sheet.step1', { url: sheet.apkUrl }) || `Install Obligarth Agent: on the phone, open Chrome at ${sheet.apkUrl} (or scan the small QR code), then install the downloaded file.`)
      : (t('sites.sheet.step1NoUrl') || 'Install Obligarth Agent on the phone (ask your IT department for the link).'),
    t('sites.sheet.step2') || 'Open the Obligarth Agent app.',
    t('sites.sheet.step3') || 'Tap "Scan the enrollment QR code" and point the camera at the QR code of this sheet.',
    t('sites.sheet.step4') || 'Tap "Activate" to allow the management of the phone.',
  ];
  return (
    <div className={preview ? 'mx-auto flex flex-col gap-4 p-6 text-[13px]' : 'obg-sheet-page flex flex-col gap-6 text-[14pt]'}>
      <div>
        <p className="text-xs uppercase tracking-wider text-gray-500">{t('sites.sheet.heading') || 'Phone enrollment sheet'}</p>
        <h1 className={preview ? 'text-xl font-bold' : 'text-[24pt] font-bold'}>{anonymize(sheet.site.name)}</h1>
        <p className="text-gray-600">{[anonymize(sheet.site.code), sheet.site.city ? anonymize(sheet.site.city) : null].filter(Boolean).join(' · ')}</p>
      </div>
      <div className="flex justify-center">
        <img src={sheet.token.qrPng} alt={t('sites.sheet.qrAlt') || 'Enrollment QR code'} className={preview ? 'h-56 w-56 [image-rendering:pixelated]' : 'h-[95mm] w-[95mm] [image-rendering:pixelated]'} />
      </div>
      <p className="text-center font-medium">
        {t('sites.sheet.validUntil', { date: expires, count: sheet.token.maxUses }) || `Valid until ${expires}, for ${sheet.token.maxUses} phone(s).`}
      </p>
      <div className="flex items-start gap-4">
        <ol className="flex-1 list-decimal space-y-2 pl-6">
          {steps.map((s, i) => <li key={i}>{s}</li>)}
        </ol>
        {sheet.apkQrPng && <img src={sheet.apkQrPng} alt={t('sites.sheet.apkQrAlt') || 'QR code of the agent download link'} className={preview ? 'h-20 w-20' : 'h-[30mm] w-[30mm]'} />}
      </div>
      <p className="text-xs text-gray-500">{t('sites.sheet.footer') || 'Keep this sheet out of public reach: it enrolls phones into the fleet of your company. A new sheet for the site replaces it.'}</p>
    </div>
  );
}
