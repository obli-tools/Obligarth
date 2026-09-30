import { useState, useEffect } from 'react';
import {
  Monitor, MonitorDown, MonitorPlay, Download, FolderOpen, Loader2, CheckCircle, AlertCircle, ExternalLink,
  Smartphone, RefreshCw, Copy, TerminalSquare, MessageSquare, Server, AppWindow, ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { isAndroidApp, nativeInfo, canUseNative, native } from '@/native/bridge';
import { downloadUrl as downloadServerFile } from '@/utils/download';
import { copyText } from '@/utils/clipboard';

// /download — presents Oblireach Desktop (the Windows operator app:
// ObliReach remote control, remote terminals, file explorer, chat,
// multi-server, detached tabbed windows, one-click updates) and serves its
// MSI from this server (GET /api/oblireach-desktop/version + /download,
// server/src/controllers/oblireachDesktop.controller.ts), then the Android app.
// Obliance does not distribute Obli.tools: nothing here may present it.

const DESKTOP_DOWNLOAD_URL = '/api/oblireach-desktop/download';
const WEBVIEW2_URL = 'https://developer.microsoft.com/microsoft-edge/webview2/';

// ── Native desktop-app Go bindings ───────────────────────────────────────────
// These are injected by the Obliance Desktop overlay (Go + webview) when
// the UI runs inside it. When undefined we're in a regular browser and
// fall back to a plain <a href=...> download.
// (Unrelated to the Android shell, which goes through @/native/bridge.)

type NativeWindow = Window & {
  __obliance_is_native_app?: boolean;
  __go_getDownloadDir?: () => Promise<string>;
  __go_chooseDownloadDir?: () => Promise<string>;
  __go_downloadFile?: (relUrl: string, filename: string) => Promise<string>;
};

const nw = typeof window !== 'undefined' ? (window as NativeWindow) : null;
const isNativeApp = !!nw?.__obliance_is_native_app;

// ── Version payloads the server hands out ───────────────────────────────────

interface VersionInfo {
  version: string;
  downloadUrl: string;
  releasedAt?: string;
  releaseNotes?: string;
}

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
  // Inside the Obli Android shell the Windows desktop client is irrelevant:
  // the page becomes the app's "about / updates" screen.
  const inAndroidApp = isAndroidApp();

  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  const [versionError, setVersionError] = useState(false);

  const [downloadDir, setDownloadDir] = useState<string>('');
  const [downloading, setDownloading] = useState(false);
  const [downloadedPath, setDownloadedPath] = useState<string | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);

  // Pull the latest version from the public endpoint.
  useEffect(() => {
    if (inAndroidApp) return;
    fetch('/api/oblireach-desktop/version')
      .then((r) => r.ok ? r.json() : Promise.reject(r.status))
      .then((info: VersionInfo) => setVersionInfo(info))
      .catch(() => setVersionError(true));
  }, [inAndroidApp]);

  // Native-app download dir
  useEffect(() => {
    if (!isNativeApp || !nw?.__go_getDownloadDir) return;
    nw.__go_getDownloadDir().then(setDownloadDir).catch(() => {});
  }, []);

  const handleChangeDir = async () => {
    const go = nw?.__go_chooseDownloadDir;
    if (!go) return;
    try { setDownloadDir(await go()); } catch { /* user cancelled */ }
  };

  const handleDownload = async () => {
    if (!versionInfo) return;
    setDlError(null);
    if (isNativeApp && nw?.__go_downloadFile) {
      setDownloading(true);
      try {
        const dest = await nw.__go_downloadFile(versionInfo.downloadUrl, 'OblireachDesktop.msi');
        setDownloadedPath(dest);
        setTimeout(() => setDownloadedPath(null), 6000);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg !== 'cancelled') setDlError(msg);
        if (nw?.__go_getDownloadDir) {
          nw.__go_getDownloadDir().then(setDownloadDir).catch(() => {});
        }
      } finally {
        setDownloading(false);
      }
    } else {
      // Plain browser: trigger a normal download via the MSI endpoint.
      window.location.href = versionInfo.downloadUrl;
    }
  };

  if (inAndroidApp) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-8 sm:py-12">
        <AndroidAppSection inApp />
      </div>
    );
  }

  // Absolute so it can be copied into a deployment tool or sent to a colleague.
  const desktopDirectUrl = toAbsoluteUrl(versionInfo?.downloadUrl || DESKTOP_DOWNLOAD_URL);
  const serverOrigin = window.location.origin;

  const handleCopyDirect = async () => {
    const ok = await copyText(desktopDirectUrl);
    if (ok) toast.success(t('common.copied') || 'Copied!');
    else toast.error(t('common.error') || 'Error');
  };

  // What the Desktop does — keep in line with the Oblireach client-app (no
  // notification-area icon, no silent update: say only what it really does).
  const desktopFeatures: Array<{ key: string; icon: LucideIcon; title: string; text: string }> = [
    {
      key: 'remote',
      icon: MonitorPlay,
      title: t('download.desktop.features.remote.title') || 'Remote control',
      text: t('download.desktop.features.remote.text') ||
        'Screen, keyboard, mouse, clipboard, file transfer and multiple monitors, with ObliReach.',
    },
    {
      key: 'terminals',
      icon: TerminalSquare,
      title: t('download.desktop.features.terminals.title') || 'Remote terminals',
      text: t('download.desktop.features.terminals.text') ||
        'CMD and PowerShell on Windows, SSH shell on Linux and macOS, opened through the Obliance agent: no inbound port to open on the device.',
    },
    {
      key: 'files',
      icon: FolderOpen,
      title: t('download.desktop.features.files.title') || 'File explorer',
      text: t('download.desktop.features.files.text') ||
        "Browse a device's files, send files to it and download files from it.",
    },
    {
      key: 'chat',
      icon: MessageSquare,
      title: t('download.desktop.features.chat.title') || 'Chat',
      text: t('download.desktop.features.chat.text') ||
        'Talk with the person in front of the device, during a session or from the Chat section.',
    },
    {
      key: 'multiServer',
      icon: Server,
      title: t('download.desktop.features.multiServer.title') || 'Several servers',
      text: t('download.desktop.features.multiServer.text') ||
        'Several Obliance servers in the same app, switched in one click.',
    },
    {
      key: 'windows',
      icon: AppWindow,
      title: t('download.desktop.features.windows.title') || 'Tabs and detached windows',
      text: t('download.desktop.features.windows.text') ||
        'Several sessions side by side in tabs, detachable into separate windows to spread across your screens.',
    },
    {
      key: 'updates',
      icon: RefreshCw,
      title: t('download.desktop.features.updates.title') || 'Built-in updates',
      text: t('download.desktop.features.updates.text') ||
        'New versions published on this server are detected and installed in one click, after their signature is checked.',
    },
    {
      key: 'permissions',
      icon: ShieldCheck,
      title: t('download.desktop.features.permissions.title') || 'Your Obliance permissions',
      text: t('download.desktop.features.permissions.text') ||
        "The app applies your Obliance account's permissions: you only see the devices you already have access to.",
    },
  ];

  return (
    <div className="mx-auto max-w-3xl px-4 py-8 sm:py-12">
      {/* Header */}
      <div className="mb-10 text-center">
        <div className="mb-4 flex justify-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/10 text-accent">
            <MonitorDown size={32} />
          </div>
        </div>
        <h1 className="mb-2 text-2xl font-bold text-text-primary sm:text-3xl">
          {t('download.desktop.title') || 'Oblireach Desktop'}
        </h1>
        <p className="font-medium text-text-primary">
          {t('download.desktop.tagline') || 'The Windows app for taking control of your devices.'}
        </p>
        <p className="mx-auto mt-2 max-w-xl text-sm text-text-secondary">
          {t('download.desktop.description') ||
            'ObliReach remote control, remote terminals, file explorer and chat with the user, together in one app, with your Obliance account.'}
        </p>
      </div>

      {/* Download folder row — native app only */}
      {isNativeApp && (
        <div className="mb-6 flex items-center gap-3 rounded-lg bg-bg-secondary px-4 py-3 text-sm">
          <FolderOpen size={15} className="text-text-muted shrink-0" />
          <div className="flex-1 min-w-0">
            <span className="text-text-secondary">{t('download.downloadFolder') || 'Download folder: '}</span>
            {downloadDir
              ? <span className="font-mono text-text-primary break-all">{downloadDir}</span>
              : <span className="text-text-muted italic">{t('download.downloadFolderPlaceholder') || 'not set — will prompt on first download'}</span>
            }
          </div>
          <button
            onClick={handleChangeDir}
            className="shrink-0 rounded-md px-3 py-1 text-xs text-text-secondary hover:bg-bg-tertiary transition-colors"
          >
            {t('download.changeFolder') || 'Change'}
          </button>
        </div>
      )}

      {/* Main download card — the Windows MSI served by this server */}
      <div className="rounded-xl bg-bg-secondary p-5">
        <div className="mb-4 flex items-center gap-2.5 text-text-primary">
          <Monitor size={22} className="shrink-0 text-text-secondary" />
          <div className="min-w-0 flex-1">
            <div className="font-semibold">{t('download.windows') || 'Windows'}</div>
            <div className="text-xs text-text-muted mt-0.5">
              {versionInfo ? (
                <>
                  v{versionInfo.version}
                  {versionInfo.releasedAt && (
                    <> · {t('download.released') || 'released'} {new Date(versionInfo.releasedAt).toLocaleDateString()}</>
                  )}
                </>
              ) : versionError ? (
                <span className="text-red-400">
                  {t('download.versionUnavailable') || 'Version info unavailable — the server may still be building the release.'}
                </span>
              ) : (
                t('download.loading') || 'Loading version…'
              )}
            </div>
          </div>
        </div>

        {dlError && (
          <div className="mb-3 flex items-center gap-1.5 text-xs text-red-400">
            <AlertCircle size={12} />
            <span className="truncate">{dlError}</span>
          </div>
        )}

        <button
          onClick={handleDownload}
          disabled={!versionInfo || downloading}
          className="w-full flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-3 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50 transition-colors"
        >
          {downloading ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              {t('common.downloading') || 'Downloading…'}
            </>
          ) : downloadedPath ? (
            <>
              <CheckCircle size={16} />
              {t('common.saved') || 'Saved'}
            </>
          ) : (
            <>
              <Download size={16} />
              {t('download.installerButton') || 'Download installer (.msi)'}
            </>
          )}
        </button>

        {downloadedPath && isNativeApp && (
          <p className="mt-2 text-xs text-text-muted font-mono break-all">
            {downloadedPath}
          </p>
        )}

        {/* Direct link: for a deployment tool, or to send to a colleague */}
        {versionInfo && !isNativeApp && (
          <div className="mt-3 flex items-center gap-2 rounded-lg bg-bg-tertiary px-3 py-2">
            <div className="min-w-0 flex-1">
              <div className="text-[11px] uppercase tracking-wide text-text-muted">
                {t('download.desktop.directLink') || 'Direct link'}
              </div>
              <div className="select-all break-all font-mono text-xs text-text-primary">{desktopDirectUrl}</div>
            </div>
            <button
              type="button"
              onClick={handleCopyDirect}
              className="flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors coarse:min-h-10"
            >
              <Copy size={13} />
              {t('common.copy') || 'Copy'}
            </button>
          </div>
        )}

        {/* Requirements */}
        <div className="mt-5">
          <div className="mb-2 text-sm font-semibold text-text-primary">
            {t('download.desktop.requirementsTitle') || 'Requirements'}
          </div>
          <ul className="space-y-1.5 text-sm text-text-secondary">
            <li className="flex gap-2">
              <span className="mt-0.5 shrink-0 text-accent">•</span>
              <span>{t('download.desktop.requirementOs') || 'Windows 10 or 11, 64-bit (x64)'}</span>
            </li>
            <li className="flex gap-2">
              <span className="mt-0.5 shrink-0 text-accent">•</span>
              <span>
                {t('download.desktop.requirementWebView2') ||
                  'Microsoft Edge WebView2 Runtime (already present on Windows 11 and on up-to-date Windows 10)'}
                {' '}
                <a
                  href={WEBVIEW2_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-accent hover:underline"
                >
                  {t('download.desktop.webView2Link') || 'Get WebView2'}
                  <ExternalLink size={12} />
                </a>
              </span>
            </li>
            <li className="flex gap-2">
              <span className="mt-0.5 shrink-0 text-accent">•</span>
              <span>{t('download.desktop.requirementAdmin') || 'Administrator rights to install the app'}</span>
            </li>
          </ul>
        </div>
      </div>

      {/* What it does */}
      <h2 className="mt-10 mb-3 text-lg font-semibold text-text-primary">
        {t('download.desktop.featuresTitle') || 'What Oblireach Desktop does'}
      </h2>
      <div className="grid gap-3 sm:grid-cols-2">
        {desktopFeatures.map(({ key, icon: Icon, title, text }) => (
          <div key={key} className="flex gap-3 rounded-xl bg-bg-secondary p-4">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent">
              <Icon size={18} />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-text-primary">{title}</div>
              <p className="mt-0.5 text-sm text-text-secondary">{text}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Getting started */}
      <div className="mt-6 rounded-xl bg-bg-secondary p-5">
        <div className="mb-2 text-sm font-semibold text-text-primary">
          {t('download.desktop.installTitle') || 'Getting started'}
        </div>
        <ol className="list-decimal space-y-1.5 pl-5 text-sm text-text-secondary">
          <li>{t('download.desktop.step1') || 'Download the installer (.msi) and run it.'}</li>
          <li>
            {t('download.desktop.step2') ||
              "Launch Oblireach from the Start menu or the desktop shortcut, then enter this server's address:"}{' '}
            <code className="break-all rounded bg-bg-tertiary px-1 py-0.5 font-mono text-xs text-text-primary">{serverOrigin}</code>
          </li>
          <li>{t('download.desktop.step3') || 'Sign in with your Obliance account (local or SSO).'}</li>
          <li>{t('download.desktop.step4') || 'New versions are then offered directly in the app.'}</li>
        </ol>
      </div>

      {/* Release notes */}
      {versionInfo?.releaseNotes && (
        <div className="mt-6 rounded-xl bg-bg-secondary p-5">
          <div className="mb-2 text-sm font-semibold text-text-primary">
            {t('download.releaseNotes') || 'Release notes'}
          </div>
          <pre className="max-h-64 overflow-y-auto overscroll-contain whitespace-pre-wrap break-words text-xs text-text-secondary font-mono">
            {versionInfo.releaseNotes}
          </pre>
        </div>
      )}

      {/* Android app */}
      <h2 className="mt-10 mb-3 text-lg font-semibold text-text-primary">
        {t('download.android.sectionTitle') || 'Mobile app'}
      </h2>
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
  const apkName = info ? `Obliance-${info.version}.apk` : 'Obliance.apk';
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
            {t('download.android.appTitle') || 'Obliance for Android'}
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
          'Obliance on your Android phone or tablet: native downloads, notifications and in-app updates.'}
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
