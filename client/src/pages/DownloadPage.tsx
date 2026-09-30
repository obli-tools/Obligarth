import { useState, useEffect } from 'react';
import {
  Download, Loader2, CheckCircle, AlertCircle, Smartphone, RefreshCw, Copy,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { isAndroidApp, nativeInfo, canUseNative, native } from '@/native/bridge';
import { downloadUrl as downloadServerFile } from '@/utils/download';
import { copyText } from '@/utils/clipboard';

// /download — the administration app for Android (APK served by this
// server). Inside the Android shell the page is the app's "about / updates"
// screen.

/** GET /api/mobile/android/version — docs/obli-mobile.md §6. */
interface AndroidVersionInfo {
  app: string;
  packageName: string | null;
  version: string;
  versionCode: number;
  minSupportedVersionCode: number;
  minSdk?: number | null;
  sha256: string | null;
  sizeBytes: number | null;
  signerSha256: string | null;
  builtAt: string | null;
  available: boolean;
  downloadUrl: string;
  releaseNotes: string | null;
}

const ANDROID_VERSION_URL = '/api/mobile/android/version';

// Android API level → marketing version, for the "Android X+" requirement.
const ANDROID_RELEASE_BY_SDK: Record<number, string> = {
  21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0', 25: '7.1', 26: '8.0', 27: '8.1',
  28: '9', 29: '10', 30: '11', 31: '12', 32: '12L', 33: '13', 34: '14', 35: '15', 36: '16',
};

// ── Component ────────────────────────────────────────────────────────────────

export function DownloadPage() {
  const { t } = useTranslation();

  if (isAndroidApp()) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8 sm:py-12">
        <AndroidAppSection inApp />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-4 py-8 sm:py-12">
      <h1 className="mb-3 text-2xl font-bold text-text-primary">
        {t('download.android.sectionTitle') || 'Mobile app'}
      </h1>
      <AndroidAppSection inApp={false} />
    </div>
  );
}

// ── Android app card ─────────────────────────────────────────────────────────
//
// Browser: version / size / notes + APK download (absolute URL, copyable so it
// can be sent to the phone) + install steps.
// Inside the Android shell: installed version + "Check for updates"
// (native.checkForUpdate — the shell's updater verifies SHA-256 + signer and
// runs the installer). Shells without the `update` capability fall back to a
// plain DownloadManager download of the newer APK.

type UpdateCheck =
  | { kind: 'available'; version: string }
  | { kind: 'upToDate' }
  | { kind: 'error' };

function toAbsoluteUrl(url: string): string {
  try {
    return new URL(url, window.location.origin).href;
  } catch {
    return url;
  }
}

function AndroidAppSection({ inApp }: { inApp: boolean }) {
  const { t, i18n } = useTranslation();

  const [info, setInfo] = useState<AndroidVersionInfo | null>(null);
  const [infoError, setInfoError] = useState(false);
  const [checking, setChecking] = useState(false);
  const [updateCheck, setUpdateCheck] = useState<UpdateCheck | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(ANDROID_VERSION_URL, { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((data: AndroidVersionInfo) => { if (!cancelled) setInfo(data); })
      .catch(() => { if (!cancelled) setInfoError(true); });
    return () => { cancelled = true; };
  }, []);

  const available = !!info?.available;
  // Absolute so it can be copied / typed on the phone (the API returns a path).
  const absoluteUrl = info ? toAbsoluteUrl(info.downloadUrl) : '';
  const apkName = info ? `Obligarth-${info.version}.apk` : 'Obligarth.apk';
  const serverOrigin = window.location.origin;

  const sizeLabel = available && info?.sizeBytes
    ? (t('download.android.sizeMb', {
        size: (info.sizeBytes / (1024 * 1024)).toLocaleString(i18n.language, { minimumFractionDigits: 1, maximumFractionDigits: 1 }),
      }) || `${(info.sizeBytes / (1024 * 1024)).toFixed(1)} MB`)
    : null;
  const androidRelease = info?.minSdk ? ANDROID_RELEASE_BY_SDK[info.minSdk] : undefined;
  const requiresLabel = androidRelease
    ? (t('download.android.requires', { version: androidRelease }) || `Android ${androidRelease}+`)
    : null;
  const builtLabel = available && info?.builtAt && !Number.isNaN(Date.parse(info.builtAt))
    ? `${t('download.released') || 'released'} ${new Date(info.builtAt).toLocaleDateString(i18n.language)}`
    : null;

  const handleCopy = async () => {
    const ok = await copyText(absoluteUrl);
    if (ok) toast.success(t('common.copied') || 'Copied!');
    else toast.error(t('common.error') || 'Error');
  };

  // ── In-app ────────────────────────────────────────────────────────────────
  const app = inApp ? nativeInfo() : null;
  const canCheck = inApp && canUseNative('checkForUpdate');
  const newerOnServer = !!app && available && !!info && info.versionCode > app.versionCode;

  const handleCheckUpdate = async () => {
    setChecking(true);
    setUpdateCheck(null);
    try {
      const r = await native.checkForUpdate();
      setUpdateCheck(r.available ? { kind: 'available', version: r.versionName } : { kind: 'upToDate' });
    } catch {
      setUpdateCheck({ kind: 'error' });
    } finally {
      setChecking(false);
    }
  };

  const handleDownloadUpdate = async () => {
    const ok = await downloadServerFile(absoluteUrl, apkName);
    if (ok) toast.success(t('download.android.downloadStarted') || 'Download started');
    else toast.error(t('common.error') || 'Error');
  };

  const releaseNotesBlock = available && info?.releaseNotes ? (
    <div className="mt-5">
      <div className="mb-2 text-sm font-semibold text-text-primary">
        {t('download.android.releaseNotes', { version: info.version }) || `What's new in v${info.version}`}
      </div>
      <pre className="max-h-64 overflow-y-auto overscroll-contain whitespace-pre-wrap break-words rounded-lg bg-bg-tertiary p-3 text-xs text-text-secondary font-mono">
        {info.releaseNotes}
      </pre>
    </div>
  ) : null;

  if (inApp) {
    return (
      <>
        <div className="mb-8 text-center">
          <div className="mb-4 flex justify-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/10 text-accent">
              <Smartphone size={32} />
            </div>
          </div>
          <h1 className="mb-2 text-2xl font-bold text-text-primary sm:text-3xl">
            {t('download.android.appTitle') || 'Obligarth for Android'}
          </h1>
          {app && (
            <p className="text-text-secondary">
              {t('download.android.inAppVersion', { version: app.appVersion }) || `You are using the app v${app.appVersion}`}
            </p>
          )}
        </div>

        <div className="rounded-xl bg-bg-secondary p-5">
          {!info && !infoError && (
            <p className="mb-4 flex items-center gap-1.5 text-sm text-text-muted">
              <Loader2 size={14} className="animate-spin" />
              {t('download.android.loading') || 'Loading version…'}
            </p>
          )}
          {available && info && (
            <p className="mb-4 text-sm text-text-secondary">
              {newerOnServer
                ? (t('download.android.newerOnServer', { version: info.version }) ||
                  `A newer version (v${info.version}) is available on this server.`)
                : (t('download.android.serverVersion', { version: info.version }) ||
                  `Latest version on this server: v${info.version}`)}
            </p>
          )}
          {(infoError || (info && !available)) && !canCheck && (
            <p className="text-sm text-text-muted">
              {t('download.android.unavailable') || 'The Android app is not published on this server yet.'}
            </p>
          )}

          {canCheck ? (
            <>
              <button
                type="button"
                onClick={handleCheckUpdate}
                disabled={checking}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50 transition-colors"
              >
                {checking ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />}
                {checking
                  ? (t('download.android.checking') || 'Checking…')
                  : (t('download.android.checkUpdates') || 'Check for updates')}
              </button>
              {updateCheck && (
                <p
                  role="status"
                  className={`mt-3 flex items-start gap-1.5 text-sm ${updateCheck.kind === 'error' ? 'text-red-400' : 'text-text-secondary'}`}
                >
                  {updateCheck.kind === 'error'
                    ? <AlertCircle size={16} className="mt-0.5 shrink-0" />
                    : <CheckCircle size={16} className="mt-0.5 shrink-0 text-accent" />}
                  <span>
                    {updateCheck.kind === 'available'
                      ? (t('download.android.updateAvailable', { version: updateCheck.version }) ||
                        `Version v${updateCheck.version} is available. Follow the app's prompt to install it.`)
                      : updateCheck.kind === 'upToDate'
                        ? (t('download.android.upToDate') || 'The app is up to date.')
                        : (t('download.android.checkFailed') || 'Could not check for updates.')}
                  </span>
                </p>
              )}
            </>
          ) : newerOnServer ? (
            <>
              <button
                type="button"
                onClick={handleDownloadUpdate}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3 text-sm font-semibold text-white hover:opacity-90 transition-colors"
              >
                <Download size={16} />
                {t('download.android.downloadUpdate') || 'Download the update'}
              </button>
            </>
          ) : available ? (
            <p className="flex items-center gap-1.5 text-sm text-text-secondary">
              <CheckCircle size={16} className="shrink-0 text-accent" />
              {t('download.android.upToDate') || 'The app is up to date.'}
            </p>
          ) : null}

          {releaseNotesBlock}
        </div>
      </>
    );
  }

  // ── Browser ───────────────────────────────────────────────────────────────
  const meta = [
    info ? `v${info.version}` : null,
    builtLabel,
    sizeLabel,
    requiresLabel,
  ].filter(Boolean).join(' · ');

  return (
    <div className="rounded-xl bg-bg-secondary p-5">
      <div className="mb-3 flex items-center gap-2.5 text-text-primary">
        <Smartphone size={22} className="shrink-0 text-text-secondary" />
        <div className="min-w-0 flex-1">
          <div className="font-semibold">{t('download.android.title') || 'Android'}</div>
          <div className="mt-0.5 text-xs text-text-muted">
            {available ? meta
              : infoError || info ? (t('download.android.unavailable') || 'The Android app is not published on this server yet.')
              : (t('download.android.loading') || 'Loading version…')}
          </div>
        </div>
      </div>

      <p className="mb-4 text-sm text-text-secondary">
        {t('download.android.description') ||
          'Obligarth on your Android phone or tablet: native downloads, notifications and in-app updates.'}
      </p>

      {available && info && (
        <>
          <a
            href={absoluteUrl}
            download={apkName}
            className="w-full flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3 text-sm font-semibold text-white hover:opacity-90 transition-colors"
          >
            <Download size={16} />
            {t('download.android.button') || 'Download the app (.apk)'}
          </a>

          {/* Direct link: to open or send to the phone from a desktop browser */}
          <div className="mt-3 flex items-center gap-2 rounded-lg bg-bg-tertiary px-3 py-2">
            <div className="min-w-0 flex-1">
              <div className="text-[11px] uppercase tracking-wide text-text-muted">
                {t('download.android.directLink') || 'Direct link'}
              </div>
              <div className="select-all break-all font-mono text-xs text-text-primary">{absoluteUrl}</div>
            </div>
            <button
              type="button"
              onClick={handleCopy}
              className="flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors coarse:min-h-10"
            >
              <Copy size={13} />
              {t('common.copy') || 'Copy'}
            </button>
          </div>

          {/* Install instructions */}
          <div className="mt-5">
            <div className="mb-2 text-sm font-semibold text-text-primary">
              {t('download.android.installTitle') || 'How to install'}
            </div>
            <ol className="list-decimal space-y-1.5 pl-5 text-sm text-text-secondary">
              <li>
                {t('download.android.step1') ||
                  'Open this page on your Android phone or tablet and download the APK (or send the link above to it).'}
              </li>
              <li>
                {t('download.android.step2') ||
                  'Open the downloaded file. If Android asks, allow your browser or file manager to install unknown apps, then tap Install.'}
              </li>
              <li>
                {t('download.android.step3') || "Launch the app and enter this server's address:"}{' '}
                <code className="break-all rounded bg-bg-tertiary px-1 py-0.5 font-mono text-xs text-text-primary">{serverOrigin}</code>
              </li>
              <li>
                {t('download.android.step4') || 'Updates are then offered directly inside the app.'}
              </li>
            </ol>
          </div>

          {releaseNotesBlock}

          {/* Integrity details — lets an admin cross-check the signer */}
          {(info.sha256 || info.signerSha256 || info.packageName) && (
            <details className="mt-5 text-xs text-text-muted">
              <summary className="cursor-pointer select-none py-1 text-text-secondary">
                {t('download.android.details') || 'Technical details'}
              </summary>
              <dl className="mt-2 space-y-2">
                {info.packageName && (
                  <div>
                    <dt>{t('download.android.packageName') || 'Package'}</dt>
                    <dd className="break-all font-mono text-text-primary">{info.packageName}</dd>
                  </div>
                )}
                <div>
                  <dt>{t('download.android.versionCode') || 'Version code'}</dt>
                  <dd className="font-mono text-text-primary">{info.versionCode}</dd>
                </div>
                {info.sha256 && (
                  <div>
                    <dt>{t('download.android.sha256') || 'APK SHA-256'}</dt>
                    <dd className="select-all break-all font-mono text-text-primary">{info.sha256}</dd>
                  </div>
                )}
                {info.signerSha256 && (
                  <div>
                    <dt>{t('download.android.signer') || 'Signing certificate SHA-256'}</dt>
                    <dd className="select-all break-all font-mono text-text-primary">{info.signerSha256}</dd>
                  </div>
                )}
              </dl>
            </details>
          )}
        </>
      )}
    </div>
  );
}
