import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, CornerDownLeft, Delete, Send } from 'lucide-react';
import { REMOTE_LIMITS, type RemoteKeyCode } from '@obligarth/shared';
import { textPieces } from './reachProtocol';

// =============================================================================
// The text of the operator for the field focused on the device (P0-15 §5.2): type_text (256 characters a message, a
// longer text in pieces) and the keys of a phone keyboard (Enter, Delete, the arrows). The text typed is never kept nor
// journaled (the audit counts the inputs only).
// =============================================================================

const KEYS: Array<{ code: RemoteKeyCode; icon: JSX.Element; key: string; fallback: string }> = [
  { code: 'enter', icon: <CornerDownLeft size={15} />, key: 'remote.keys.enter', fallback: 'Enter' },
  { code: 'del', icon: <Delete size={15} />, key: 'remote.keys.del', fallback: 'Delete' },
  { code: 'left', icon: <ArrowLeft size={15} />, key: 'remote.keys.left', fallback: 'Left' },
  { code: 'right', icon: <ArrowRight size={15} />, key: 'remote.keys.right', fallback: 'Right' },
  { code: 'up', icon: <ArrowUp size={15} />, key: 'remote.keys.up', fallback: 'Up' },
  { code: 'down', icon: <ArrowDown size={15} />, key: 'remote.keys.down', fallback: 'Down' },
];

export function RemoteTextInput({ disabled, keysEnabled, onText, onKey }: {
  disabled: boolean;
  /** The agent announced key. */
  keysEnabled: boolean;
  onText: (text: string) => void;
  onKey: (code: RemoteKeyCode) => void;
}) {
  const { t } = useTranslation();
  const [text, setText] = useState('');
  const submit = () => {
    if (!text || disabled) return;
    for (const piece of textPieces(text)) onText(piece);
    setText('');
  };
  return (
    <div className="space-y-2">
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={disabled}
          maxLength={REMOTE_LIMITS.typeTextMax * 4}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          placeholder={t('remote.text.placeholder') || 'Text to type on the device'}
          aria-label={t('remote.text.label') || 'Text to type on the device'}
          className="min-w-0 flex-1 rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={disabled || !text}
          title={t('remote.text.send') || 'Type it'}
          aria-label={t('remote.text.send') || 'Type it'}
          className="flex h-9 w-10 shrink-0 items-center justify-center rounded-lg bg-accent text-white disabled:opacity-40 coarse:h-10"
        >
          <Send size={15} />
        </button>
      </form>
      {keysEnabled && (
        <div className="flex flex-wrap gap-1">
          {KEYS.map((k) => {
            const label = t(k.key) || k.fallback;
            return (
              <button
                key={k.code}
                type="button"
                title={label}
                aria-label={label}
                disabled={disabled}
                onClick={() => onKey(k.code)}
                className="flex h-8 w-9 items-center justify-center rounded bg-bg-tertiary text-text-secondary hover:text-text-primary disabled:opacity-40 coarse:h-10 coarse:w-10"
              >
                {k.icon}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
