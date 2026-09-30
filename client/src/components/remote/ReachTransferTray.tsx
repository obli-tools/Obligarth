import { useTranslation } from 'react-i18next';
import { ArrowDownToLine, ArrowUpFromLine, Check, X, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
import type { TransferItem } from './reachFileTransfer';

/**
 * File transfers of the ObliReach viewer (send to the remote Downloads /
 * download from the remote clipboard): progress, cancel, result.
 */

export interface ReachTransferTrayProps {
  items: TransferItem[];
  onCancel: (tid: number) => void;
  onClear: () => void;
}

export function ReachTransferTray({ items, onCancel, onClear }: ReachTransferTrayProps) {
  const { t } = useTranslation();
  if (items.length === 0) return null;
  const finished = items.some((i) => i.status === 'done' || i.status === 'error' || i.status === 'cancelled');

  const errorText = (i: TransferItem) => {
    switch (i.error) {
      case 'too_large': return t('reach.files.err.tooLarge', 'File too large (2 GB max)');
      case 'no_user_session': return t('reach.files.err.noUser', 'No user is signed in on the remote');
      case 'bad_name': return t('reach.files.err.badName', 'Invalid file name');
      case 'denied': return t('reach.files.err.denied', 'Access denied on the remote');
      case 'forbidden': return t('reach.files.err.forbidden', 'File transfers are not permitted in this session');
      case 'disk_full': return t('reach.files.err.diskFull', 'The remote disk is full');
      case 'hash_mismatch': return t('reach.files.err.hash', 'The file arrived damaged (checksum mismatch)');
      case 'busy': return t('reach.files.err.busy', 'Another transfer is already running');
      case 'not_found': return t('reach.files.err.notFound', 'The file is no longer on the remote clipboard');
      case 'unsupported': return t('reach.files.err.unsupported', 'Not supported by this agent');
      case 'timeout': return t('reach.files.err.timeout', 'The agent did not answer');
      case 'disconnected': return t('reach.files.err.disconnected', 'Connection lost during the transfer');
      case 'save_failed': return t('reach.saveFailed', 'Could not save the file');
      default: return i.errorMessage || t('reach.files.err.generic', 'Transfer failed');
    }
  };

  return (
    <div className="absolute bottom-2 right-2 z-20 w-80 max-w-[calc(100%-1rem)] rounded-lg bg-bg-secondary/95 shadow-2xl">
      <div className="flex items-center justify-between px-3 py-2">
        <span className="text-xs font-semibold text-text-primary">{t('reach.files.transfers', 'File transfers')}</span>
        {finished && (
          <button type="button" onClick={onClear} className="text-[11px] text-text-muted hover:text-text-primary coarse:min-h-10">
            {t('reach.files.clear', 'Clear')}
          </button>
        )}
      </div>
      <ul className="max-h-60 overflow-y-auto overscroll-contain px-2 pb-2 space-y-1">
        {items.map((i) => {
          const pct = i.size > 0 ? Math.min(100, Math.round((i.bytes / i.size) * 100)) : (i.status === 'done' ? 100 : 0);
          const running = i.status === 'queued' || i.status === 'waiting' || i.status === 'active' || i.status === 'verifying';
          return (
            <li key={i.tid} className="rounded-md bg-bg-tertiary px-2 py-1.5">
              <div className="flex items-center gap-2">
                {i.dir === 'up'
                  ? <ArrowUpFromLine className="w-3.5 h-3.5 shrink-0 text-text-muted" aria-label={t('reach.files.up', 'Sent to the remote')} />
                  : <ArrowDownToLine className="w-3.5 h-3.5 shrink-0 text-text-muted" aria-label={t('reach.files.down', 'Downloaded from the remote')} />}
                <span className="min-w-0 flex-1 truncate text-xs text-text-primary" title={i.path || i.name}>{i.name}</span>
                {i.status === 'done' && <Check className="w-3.5 h-3.5 shrink-0 text-green-400" />}
                {i.status === 'error' && <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-red-400" />}
                {running && (
                  <button
                    type="button"
                    onClick={() => onCancel(i.tid)}
                    title={t('common.cancel', 'Cancel')}
                    aria-label={t('common.cancel', 'Cancel')}
                    className="shrink-0 rounded p-0.5 text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
              {running && (
                <div className="mt-1 h-1 overflow-hidden rounded bg-bg-primary">
                  <div className={clsx('h-full bg-accent transition-[width]', i.status === 'waiting' && 'animate-pulse')} style={{ width: `${pct}%` }} />
                </div>
              )}
              <div className="mt-0.5 text-[10px] text-text-muted">
                {i.status === 'queued' && t('reach.files.queued', 'Queued')}
                {i.status === 'waiting' && t('reach.files.waiting', 'Waiting for the agent…')}
                {i.status === 'active' && `${pct} %`}
                {i.status === 'verifying' && t('reach.files.verifying', 'Checking…')}
                {i.status === 'done' && (i.dir === 'up'
                  ? t('reach.files.sentTo', 'Saved on the remote: {{path}}', { path: i.path || i.name })
                  : t('reach.files.downloaded', 'Downloaded'))}
                {i.status === 'cancelled' && t('reach.files.cancelled', 'Cancelled')}
                {i.status === 'error' && <span className="text-red-400">{errorText(i)}</span>}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
