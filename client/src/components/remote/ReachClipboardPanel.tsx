import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ClipboardCopy, ClipboardPaste, Copy, Download, FileText, RefreshCw, Send, Upload } from 'lucide-react';
import { Modal } from '@/components/common/Modal';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { copyText } from '@/utils/clipboard';
import type { ReachClipboardFile } from './reachProtocol';

/**
 * Clipboard panel of the ObliReach viewer — the text-box fallback the owner
 * asked for when the browser refuses clipboard access (plain http, Safari,
 * WebViews), and the place where the remote clipboard is shown:
 *   - "Send to remote": text → remote clipboard (optionally pasted at once),
 *   - "Remote clipboard": live, read-only, Copy (a user gesture) / Refresh,
 *   - "Sync automatically" (agent push of remote changes),
 *   - files copied on the remote (Explorer) → Download.
 */

export type ReachClipboardSupport = 'full' | 'legacy' | 'none';

export interface ReachClipboardPanelProps {
  open: boolean;
  onClose: () => void;
  /** full = clipboard_text feature; legacy = old agent (no working clipboard: update it); none = unavailable (sign-in screen…). */
  support: ReachClipboardSupport;
  pushSupported: boolean;
  sync: boolean;
  onSyncChange: (on: boolean) => void;
  remoteText: string | null;
  remoteTruncated?: boolean;
  refreshing?: boolean;
  onRefresh: () => void;
  onSend: (text: string, paste: boolean) => void;
  /** Initial content of the "send" box (e.g. what the local clipboard read gave). */
  draft?: string;
  remoteFiles: ReachClipboardFile[];
  downloadSupported: boolean;
  onDownload: (f: ReachClipboardFile) => void;
  /** Opens the file picker (upload), null when uploads are unavailable. */
  onSendFiles: (() => void) | null;
  /** File transfers not permitted in this session: why, null otherwise. */
  filesDenied?: string | null;
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function ReachClipboardPanel(p: ReachClipboardPanelProps) {
  const { t } = useTranslation();
  const [text, setText] = useState('');

  useEffect(() => {
    if (p.open) setText(p.draft ?? '');
    // Only when the panel opens (typing must not be reset by a new draft).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.open]);

  const send = (paste: boolean) => {
    if (!text) return;
    p.onSend(text, paste);
    setText('');
  };

  const copyRemote = async () => {
    if (p.remoteText == null) return;
    const ok = await copyText(p.remoteText);
    if (ok) toast.success(t('common.copied', 'Copied!'));
    else toast.error(t('reach.copyFailed', 'Copy failed — select the text and copy it manually'));
  };

  // 'legacy' = an agent from before the clipboard protocol: it drops what it
  // is sent (Windows capture helper) or ignores it (Linux / macOS) — nothing
  // may pretend otherwise.
  const disabled = p.support !== 'full';

  return (
    <Modal
      open={p.open}
      onClose={p.onClose}
      title={t('reach.clip.title', 'Clipboard')}
      icon={<ClipboardPaste className="w-4 h-4 text-accent" />}
      size="md"
      phoneLayout="sheet"
      bodyClassName="p-4 space-y-5"
    >
      {p.support === 'none' && (
        <p className="rounded-lg bg-orange-500/10 px-3 py-2 text-xs text-orange-400">
          {t('reach.clip.unavailable', 'The clipboard is not available on this screen (sign-in or lock screen).')}
        </p>
      )}
      {p.support === 'legacy' && (
        <p className="rounded-lg bg-orange-500/10 px-3 py-2 text-xs text-orange-400">
          {t('reach.clip.agentNoClipboard', 'This ObliReach agent is too old for the shared clipboard: update it to copy and paste between the two computers. Ctrl+V in the session pastes the remote computer\'s own clipboard.')}
        </p>
      )}

      {/* ── Send to remote ── */}
      <section className="space-y-2">
        <label htmlFor="reach-clip-send" className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
          <ClipboardPaste className="w-3.5 h-3.5" />
          {t('reach.clip.sendTitle', 'Send to remote')}
        </label>
        <textarea
          id="reach-clip-send"
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={disabled}
          placeholder={t('reach.clip.sendPlaceholder', 'Paste or type the text to send…')}
          className="w-full h-28 p-3 rounded-lg bg-bg-tertiary text-text-primary font-mono text-xs resize-y focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50"
        />
        <div className="flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={() => send(false)}
            disabled={disabled || !text}
            className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-lg bg-bg-tertiary text-text-primary hover:bg-bg-hover disabled:opacity-40 transition-colors coarse:min-h-11"
          >
            <Send className="w-3.5 h-3.5" />
            {t('reach.clip.send', 'Send')}
          </button>
          <button
            type="button"
            onClick={() => send(true)}
            disabled={disabled || !text}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg bg-accent text-white hover:bg-accent/90 disabled:opacity-40 transition-colors coarse:min-h-11"
          >
            <ClipboardPaste className="w-3.5 h-3.5" />
            {t('reach.clip.sendAndPaste', 'Send and paste')}
          </button>
        </div>
      </section>

      {/* ── Remote clipboard ── */}
      <section className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            <ClipboardCopy className="w-3.5 h-3.5" />
            {t('reach.remoteClipboard', 'Remote clipboard')}
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={p.onRefresh}
              disabled={disabled}
              title={t('reach.clip.refresh', 'Refresh')}
              aria-label={t('reach.clip.refresh', 'Refresh')}
              className="p-1.5 rounded text-text-muted hover:text-text-primary hover:bg-bg-tertiary disabled:opacity-40 transition-colors coarse:min-h-10 coarse:min-w-10"
            >
              <RefreshCw className={p.refreshing ? 'w-4 h-4 animate-spin' : 'w-4 h-4'} />
            </button>
            <button
              type="button"
              onClick={copyRemote}
              disabled={p.remoteText == null || p.remoteText === ''}
              className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded bg-bg-tertiary text-text-primary hover:bg-bg-hover disabled:opacity-40 transition-colors coarse:min-h-10"
            >
              <Copy className="w-3.5 h-3.5" />
              {t('common.copy', 'Copy')}
            </button>
          </div>
        </div>
        <textarea
          readOnly
          value={p.remoteText ?? ''}
          placeholder={t('reach.clip.remoteEmpty', 'Nothing received yet — copy something on the remote, or press Refresh.')}
          aria-label={t('reach.remoteClipboard', 'Remote clipboard')}
          onFocus={(e) => e.currentTarget.select()}
          className="w-full h-28 p-3 rounded-lg bg-bg-tertiary text-text-primary font-mono text-xs resize-y focus:outline-none"
        />
        {p.remoteTruncated && (
          <p className="text-[11px] text-text-muted">{t('reach.clip.truncated', 'The remote text was too long and has been truncated (1 MB max).')}</p>
        )}
        {p.pushSupported && (
          <ToggleSwitch
            checked={p.sync}
            onChange={p.onSyncChange}
            size="sm"
            label={t('reach.clip.sync', 'Sync automatically')}
            description={t('reach.clip.syncHint', 'Text copied on the remote comes to this computer (Ctrl+C there, Ctrl+V here).')}
          />
        )}
      </section>

      {/* ── Files ── */}
      {(p.onSendFiles || p.remoteFiles.length > 0 || p.filesDenied) && (
        <section className="space-y-2">
          <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            <FileText className="w-3.5 h-3.5" />
            {t('reach.files.title', 'Files')}
          </span>
          {p.filesDenied && (
            <p className="rounded-lg bg-bg-tertiary px-3 py-2 text-xs text-text-muted">{p.filesDenied}</p>
          )}
          {p.remoteFiles.length > 0 && (
            <ul className="space-y-1">
              {p.remoteFiles.map((f) => (
                <li key={f.idx} className="flex items-center gap-2 rounded-lg bg-bg-tertiary px-3 py-2">
                  <FileText className="w-4 h-4 shrink-0 text-text-muted" />
                  <span className="min-w-0 flex-1 truncate text-xs text-text-primary" title={f.name}>{f.name}</span>
                  <span className="shrink-0 text-[11px] text-text-muted">{f.dir ? t('reach.files.folder', 'folder') : fmtSize(f.size)}</span>
                  {p.downloadSupported && !f.dir && (
                    <button
                      type="button"
                      onClick={() => p.onDownload(f)}
                      className="flex shrink-0 items-center gap-1 rounded px-2 py-1 text-xs text-accent hover:bg-accent/10 coarse:min-h-10"
                    >
                      <Download className="w-3.5 h-3.5" />
                      {t('reach.files.download', 'Download')}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {p.onSendFiles && (
            <button
              type="button"
              onClick={p.onSendFiles}
              className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-lg bg-bg-tertiary text-text-primary hover:bg-bg-hover transition-colors coarse:min-h-11"
            >
              <Upload className="w-3.5 h-3.5" />
              {t('reach.files.send', 'Send files to the remote…')}
            </button>
          )}
        </section>
      )}
    </Modal>
  );
}
