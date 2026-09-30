import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Camera,
  Circle,
  ClipboardCopy,
  ClipboardPaste,
  Hand,
  LayoutGrid,
  Lock,
  Maximize2,
  MessageCircle,
  Minimize2,
  MousePointer2,
  ShieldAlert,
  Unlock,
  Upload,
  Volume2,
  VolumeX,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import { Drawer } from '@/components/common/Drawer';
import { cn } from '@/utils/cn';
import type { TouchInputMode } from './useRemotePointer';
import { MousePointerOff } from './reachIcons';
import { KEEPALIVE_LABELS, KEEPALIVE_MODES, type KeepaliveMode } from './reachKeepalive';

/**
 * "⋯" tools sheet of the ObliReach viewer on narrow screens — every toolbar
 * control that does not fit a phone toolbar, with a visible label
 * (docs/obli-mobile.md §5.1 / §5.9). Desktop keeps its inline toolbar.
 */

export interface ReachMonitor {
  index: number;
  name: string;
  width: number;
  height: number;
}

export interface ReachSystemChord {
  id: string;
  label: string;
  title: string;
  codes: string[];
  group: 'win' | 'window' | 'misc';
}

export interface ReachToolsSheetProps {
  open: boolean;
  onClose: () => void;
  streaming: boolean;
  // Display
  monitors: ReachMonitor[];
  activeMonitor: number;
  onMonitor: (index: number) => void;
  /** All screens at once (null: agent without mosaic, or a single screen). */
  mosaic?: { active: boolean; pending: boolean; onToggle: () => void } | null;
  codecId: string;
  codecs: Array<{ id: string; label: string }>;
  onCodec: (codec: string) => void;
  /** Touch-only view controls (null hides them). */
  zoom?: { zoomed: boolean; onZoomIn: () => void; onZoomOut: () => void; onReset: () => void } | null;
  // Input
  inputBlocked: boolean;
  onToggleInputBlock: () => void;
  /** View only (local: the mouse and keyboard stay here), null hides it. */
  viewOnly?: { active: boolean; onToggle: () => void } | null;
  touchMode?: TouchInputMode | null;
  onTouchMode?: (m: TouchInputMode) => void;
  onCtrlAltDel: () => void;
  systemChords: ReachSystemChord[];
  chordGroupLabel: (g: ReachSystemChord['group']) => string;
  onChord: (codes: string[]) => void;
  // Clipboard
  onPaste: () => void;
  onCopy: () => void;
  /** Opens the clipboard panel (text box, remote clipboard, files). */
  onClipboardPanel?: () => void;
  /** Opens the file picker (send files to the remote), null when unsupported. */
  onSendFiles?: (() => void) | null;
  /** File transfers not permitted in this session: why (shown next to a
   *  disabled "Send files"), null otherwise. */
  filesDenied?: string | null;
  // Session / media
  chat?: { open: boolean; onToggle: () => void } | null;
  chatSound?: { enabled: boolean; onToggle: () => void } | null;
  audio?: { enabled: boolean; onToggle: () => void } | null;
  /** Keep sessions alive (setting of this browser, see reachKeepalive);
   *  `supported`: this session's agent can do it. Null hides it. */
  keepalive?: { mode: KeepaliveMode; supported: boolean; onChange: (mode: KeepaliveMode) => void } | null;
  onScreenshot: () => void;
  recording: boolean;
  onToggleRecording: () => void;
  fullscreen?: { active: boolean; onToggle: () => void } | null;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="px-1 text-[11px] font-semibold uppercase tracking-wider text-text-muted">{title}</h3>
      {children}
    </section>
  );
}

function Tool({
  icon,
  label,
  onClick,
  active = false,
  danger = false,
  disabled = false,
}: {
  icon: ReactNode;
  label: string;
  onClick: () => void;
  active?: boolean;
  danger?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-pressed={active || undefined}
      className={cn(
        'flex min-h-12 w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors disabled:opacity-40',
        active
          ? 'bg-accent/15 text-accent'
          : danger
            ? 'bg-bg-tertiary text-red-400 active:bg-red-500/10'
            : 'bg-bg-tertiary text-text-primary active:bg-bg-hover',
      )}
    >
      <span className="flex shrink-0 items-center">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
    </button>
  );
}

function Chip({ active, onClick, children, title }: { active?: boolean; onClick: () => void; children: ReactNode; title?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-pressed={active || undefined}
      className={cn(
        'min-h-10 rounded-md px-3 text-xs font-semibold transition-colors',
        active ? 'bg-accent text-white' : 'bg-bg-tertiary text-text-primary active:bg-accent/15',
      )}
    >
      {children}
    </button>
  );
}

export function ReachToolsSheet(p: ReachToolsSheetProps) {
  const { t } = useTranslation();
  const run = (fn: () => void) => () => { fn(); p.onClose(); };

  return (
    <Drawer
      open={p.open}
      onClose={p.onClose}
      side="bottom"
      size="lg"
      title={t('reach.tools', 'Session tools')}
      bodyClassName="px-3 pb-4 pt-1 space-y-5"
    >
      {p.streaming && (
        <Section title={t('reach.section.display', 'Display')}>
          {p.monitors.length > 1 && (
            <div className="flex flex-wrap gap-2">
              {p.mosaic && (
                <Chip active={p.mosaic.active} onClick={run(p.mosaic.onToggle)} title={t('reach.mosaicHint', 'Show all the screens at once, at their real positions')}>
                  <span className="inline-flex items-center gap-1.5">
                    <LayoutGrid className="h-3.5 w-3.5" />
                    {t('reach.mosaic', 'Mosaic')}
                  </span>
                </Chip>
              )}
              {p.monitors.map((m) => (
                <Chip key={m.index} active={!p.mosaic?.active && m.index === p.activeMonitor} onClick={run(() => p.onMonitor(m.index))}>
                  {t('reach.monitorN', 'Screen {{n}}', { n: m.index + 1 })} · {m.width}×{m.height}
                </Chip>
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <span className="mr-1 text-xs text-text-muted">{t('reach.codec', 'Video codec')}</span>
            {p.codecs.map((c) => (
              <Chip key={c.id} active={c.id === p.codecId} onClick={run(() => p.onCodec(c.id))}>
                {c.label}
              </Chip>
            ))}
          </div>
          {p.zoom && (
            <div className="grid grid-cols-3 gap-2">
              <Tool icon={<ZoomOut className="h-4 w-4" />} label={t('reach.zoomOut', 'Zoom out')} onClick={p.zoom.onZoomOut} disabled={!p.zoom.zoomed} />
              <Tool icon={<ZoomIn className="h-4 w-4" />} label={t('reach.zoomIn', 'Zoom in')} onClick={p.zoom.onZoomIn} />
              <Tool icon={<Minimize2 className="h-4 w-4" />} label={t('reach.fit', 'Fit')} onClick={run(p.zoom.onReset)} disabled={!p.zoom.zoomed} />
            </div>
          )}
        </Section>
      )}

      {p.streaming && (
        <Section title={t('reach.section.input', 'Input')}>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {p.touchMode && p.onTouchMode && (
              <Tool
                icon={p.touchMode === 'trackpad' ? <MousePointer2 className="h-4 w-4" /> : <Hand className="h-4 w-4" />}
                label={p.touchMode === 'trackpad'
                  ? t('reach.touchModeTrackpad', 'Touch: trackpad (relative cursor)')
                  : t('reach.touchModeDirect', 'Touch: direct (tap where you click)')}
                active={p.touchMode === 'trackpad'}
                onClick={() => p.onTouchMode!(p.touchMode === 'trackpad' ? 'direct' : 'trackpad')}
              />
            )}
            <Tool
              icon={p.inputBlocked ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
              label={p.inputBlocked ? t('reach.unblockInput', 'Unblock remote user input') : t('reach.blockInput', 'Block remote user input')}
              active={p.inputBlocked}
              onClick={run(p.onToggleInputBlock)}
            />
            {p.viewOnly && (
              <Tool
                icon={<MousePointerOff className="h-4 w-4" />}
                label={t('reach.viewOnlyShort', 'View only')}
                active={p.viewOnly.active}
                onClick={run(p.viewOnly.onToggle)}
              />
            )}
            <Tool icon={<ShieldAlert className="h-4 w-4" />} label={t('reach.sendCad', 'Send Ctrl+Alt+Del')} onClick={run(p.onCtrlAltDel)} />
          </div>
          {(['win', 'window', 'misc'] as const).map((g) => {
            const keys = p.systemChords.filter((k) => k.group === g);
            if (keys.length === 0) return null;
            return (
              <div key={g} className="space-y-1.5">
                <div className="px-1 text-[10px] font-mono uppercase tracking-wider text-text-muted">{p.chordGroupLabel(g)}</div>
                <div className="flex flex-wrap gap-1.5">
                  {keys.map((k) => (
                    <Chip key={k.id} onClick={run(() => p.onChord(k.codes))} title={k.title}>
                      <span className="font-mono">{k.label}</span>
                    </Chip>
                  ))}
                </div>
              </div>
            );
          })}
        </Section>
      )}

      {p.streaming && (
        <Section title={t('reach.section.clipboard', 'Clipboard')}>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <Tool icon={<ClipboardPaste className="h-4 w-4" />} label={t('reach.pasteToRemote', 'Paste to remote')} onClick={run(p.onPaste)} />
            <Tool icon={<ClipboardCopy className="h-4 w-4" />} label={t('reach.copyFromRemote', 'Copy from remote')} onClick={run(p.onCopy)} />
            {p.onClipboardPanel && (
              <Tool icon={<ClipboardPaste className="h-4 w-4" />} label={t('reach.clip.open', 'Clipboard panel (text box)')} onClick={run(p.onClipboardPanel)} />
            )}
            {p.onSendFiles && (
              <Tool icon={<Upload className="h-4 w-4" />} label={t('reach.files.send', 'Send files to the remote…')} onClick={run(p.onSendFiles)} />
            )}
            {!p.onSendFiles && p.filesDenied && (
              <Tool icon={<Upload className="h-4 w-4" />} label={t('reach.files.send', 'Send files to the remote…')} onClick={() => undefined} disabled />
            )}
          </div>
          {!p.onSendFiles && p.filesDenied && (
            <p className="px-1 text-xs text-text-muted">{p.filesDenied}</p>
          )}
        </Section>
      )}

      <Section title={t('reach.section.session', 'Session')}>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {p.chat && (
            <Tool
              icon={<MessageCircle className="h-4 w-4" />}
              label={p.chat.open ? t('reach.hideChat', 'Hide chat') : t('reach.chatWithUser', 'Chat with user')}
              active={p.chat.open}
              onClick={run(p.chat.onToggle)}
            />
          )}
          {p.chatSound && (
            <Tool
              icon={p.chatSound.enabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
              label={p.chatSound.enabled ? t('reach.muteChat', 'Mute chat notifications') : t('reach.unmuteChat', 'Unmute chat notifications')}
              onClick={p.chatSound.onToggle}
            />
          )}
          {p.streaming && p.audio && (
            <Tool
              icon={p.audio.enabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
              label={p.audio.enabled ? t('reach.muteAudio', 'Mute remote audio') : t('reach.enableAudio', 'Enable remote audio')}
              active={p.audio.enabled}
              onClick={p.audio.onToggle}
            />
          )}
          {p.streaming && (
            <Tool icon={<Camera className="h-4 w-4" />} label={t('reach.screenshot', 'Take screenshot')} onClick={run(p.onScreenshot)} />
          )}
          {p.streaming && (
            <Tool
              icon={<Circle className={cn('h-4 w-4', p.recording && 'fill-red-400 text-red-400')} />}
              label={p.recording ? t('reach.stopRecording', 'Stop recording') : t('reach.record', 'Record session')}
              danger={p.recording}
              onClick={run(p.onToggleRecording)}
            />
          )}
          {p.fullscreen && (
            <Tool
              icon={p.fullscreen.active ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
              label={p.fullscreen.active ? t('reach.exitFullscreen', 'Exit fullscreen') : t('reach.fullscreen', 'Fullscreen')}
              onClick={run(p.fullscreen.onToggle)}
            />
          )}
        </div>
        {p.streaming && p.keepalive && (
          <div className="space-y-1.5">
            <div id="reach-keepalive-title" className="px-1 text-[10px] font-mono uppercase tracking-wider text-text-muted">
              {t('reach.keepalive.title', 'Keep sessions alive')}
            </div>
            <div role="group" aria-labelledby="reach-keepalive-title" className="flex flex-wrap gap-1.5">
              {KEEPALIVE_MODES.map((m) => (
                <Chip key={m} active={p.keepalive!.mode === m} onClick={() => p.keepalive!.onChange(m)}>
                  {t(KEEPALIVE_LABELS[m].key, KEEPALIVE_LABELS[m].fallback)}
                </Chip>
              ))}
            </div>
            <p className="px-1 text-xs leading-snug text-text-muted">
              {t('reach.keepalive.hint', 'The agent ends a session after 10 minutes without input; this keeps watched sessions open.')}
            </p>
            {!p.keepalive.supported && (
              <p className="px-1 text-xs leading-snug text-amber-400">
                {t('reach.keepalive.unsupported', 'This ObliReach agent cannot do it yet: update it to keep watched sessions open.')}
              </p>
            )}
          </div>
        )}
      </Section>
    </Drawer>
  );
}
