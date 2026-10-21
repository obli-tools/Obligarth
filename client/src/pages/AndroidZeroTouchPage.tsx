import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, ExternalLink } from 'lucide-react';
import type { AndroidEnrollmentTokenView, AndroidZeroTouchIframe } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { PageContainer } from '@/components/common/PageContainer';
import { Labeled, dateOf, errorToast, fieldClass } from '@/components/android/ui';
import { trCode } from '@/utils/apiError';
import { useOwnDocument } from '@/hooks/useOwnDocument';

// The zero-touch portal of the client, embedded (android-amapi §10.5, ANDROID_ZERO_TOUCH_PAGE; lots AN-F2 and AN-C2):
// the console asks the server for the iframe URL of an active zero-touch token (step-up; the URL carries the value of
// the long token: in memory only, never stored nor logged) and shows Google's page, whose parentFrameUrl is this page.
// The console's proxy gives this path its own Content-Security-Policy (client/nginx.conf, lot AN-E: Google's frames,
// the sign-in of a Google account included [NV]); reached by an in-app link, the page reloads the document at its own
// path first (useOwnDocument) [AR: Google's iframe checked at AN-J].

export function AndroidZeroTouchPage() {
  const own = useOwnDocument();
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const [tokens, setTokens] = useState<AndroidEnrollmentTokenView[]>([]);
  const [tokenId, setTokenId] = useState(params.get('token') ?? '');
  const [frame, setFrame] = useState<AndroidZeroTouchIframe | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!own) return;
    androidApi.tokens().then((all) => setTokens(all.filter((x) => x.kind === 'zero_touch' && x.state === 'active'))).catch(() => setTokens([]));
  }, [own]);
  const open = async () => {
    setBusy(true);
    try {
      setFrame(await androidApi.zeroTouchIframe(tokenId));
      setParams((p) => { const n = new URLSearchParams(p); n.delete('token'); return n; }, { replace: true });
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  if (!own) return <PageContainer><p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p></PageContainer>;
  return (
    <PageContainer className="space-y-4">
      <Link to="/device-enrollment" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
        <ArrowLeft size={14} />{t('android.zeroTouch.back') || 'Back to the enrollment'}
      </Link>
      <div>
        <h1 className="text-2xl font-bold text-text-primary">{t('android.zeroTouch.title') || 'Zero-touch enrollment'}</h1>
        <p className="mt-1 text-sm text-text-muted">
          {t('android.zeroTouch.subtitle') || 'The client\'s zero-touch portal of Google: link its reseller account and set the default configuration with the token below.'}
        </p>
      </div>
      {!frame && (
        <div className="flex flex-wrap items-end gap-2">
          <Labeled label={t('android.zeroTouch.token') || 'Zero-touch token'}>
            <select value={tokenId} onChange={(e) => setTokenId(e.target.value)} className={`${fieldClass} sm:w-96`}>
              <option value="">{t('android.zeroTouch.chooseToken') || '— choose —'}</option>
              {tokens.map((tk) => <option key={tk.id} value={tk.id}>{t('android.zeroTouch.tokenOption', { at: dateOf(tk.expiresAt) }) || `expires ${dateOf(tk.expiresAt)}`}</option>)}
            </select>
          </Labeled>
          <Button disabled={!tokenId || busy} onClick={() => void open()}><ExternalLink className="w-4 h-4 mr-1" />{t('android.zeroTouch.open') || 'Open the portal'}</Button>
        </div>
      )}
      {tokens.length === 0 && !frame && <p className="text-sm text-text-muted">{t('android.zeroTouch.noToken') || 'No active zero-touch token: create one from a zero-touch profile.'}</p>}
      {frame && (
        <>
          {frame.warnings.map((w) => <p key={w} className="text-xs text-amber-400">{trCode(`android.warnings.${w}`, w)}</p>)}
          <iframe title={t('android.zeroTouch.frameTitle') || 'Zero-touch portal'} src={frame.iframeUrl} className="h-[75vh] w-full rounded-lg border border-border bg-white"
            referrerPolicy="no-referrer" />
        </>
      )}
    </PageContainer>
  );
}
