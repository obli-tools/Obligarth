import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { Tag } from 'lucide-react';
import { BENCH_NAME_TEMPLATE_MAX, checkBenchNameTemplate, renderBenchName, type BenchNameTemplateCheck } from '@obligarth/shared';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { fieldCls, labelCls } from './benchUi';

// The template of the name a bench suggests for a device of a site (lot BANC-T §10), per target: literal text and the
// tokens {site.code}, {site.code:N} (zero-padded to N), {n}, {n:N} (the number of the device in the site, the highest
// already used + 1). Checked by the shared rule (the server and the station apply the same), shown with a live preview
// on an example site code. Empty: no template (the name prefix and the ADB serial, as before).

type Reason = Extract<BenchNameTemplateCheck, { ok: false }>['reason'];

/** The check of a template typed in a field: '' is valid (no template). */
export function templateCheck(v: string): BenchNameTemplateCheck {
  return v === '' ? { ok: true } : checkBenchNameTemplate(v);
}

export function NameTemplateField({ value, onChange, autoFocus }: { value: string; onChange: (v: string) => void; autoFocus?: boolean }) {
  const { t } = useTranslation();
  const [siteCode, setSiteCode] = useState('42');
  const check = templateCheck(value);
  const reasonText = (r: Reason): string => {
    const fallback: Record<Reason, string> = {
      empty: 'The template is empty.', too_long: `At most ${BENCH_NAME_TEMPLATE_MAX} characters, without spaces at the ends.`,
      bad_char: 'Control characters are not allowed.', bad_token: 'Unknown token: use {site.code}, {site.code:N}, {n} or {n:N}.',
      no_number: 'The template needs the number {n} (or {n:N}).', two_numbers: 'The number {n} appears once only.',
    };
    return t(`bench.nameTemplate.error.${r}`) || fallback[r];
  };
  const code = siteCode.trim() || '42';
  const samples = value && check.ok ? [1, 2, 3].map((n) => renderBenchName(value, code, n)).filter((x): x is string => !!x) : [];
  return (
    <div className="space-y-2">
      <label className={labelCls}>{t('bench.nameTemplate.label') || 'Template of the suggested name'}
        <input className={clsx(fieldCls, 'font-mono', !check.ok && 'ring-2 ring-red-500/60')} value={value} maxLength={BENCH_NAME_TEMPLATE_MAX}
          autoComplete="off" spellCheck={false} autoFocus={autoFocus} placeholder="AB{site.code:5}-{n}" onChange={(e) => onChange(e.target.value)} />
      </label>
      <p className="text-xs text-text-muted">
        {t('bench.nameTemplate.hint') || 'Tokens: {site.code} the code of the site, {site.code:5} the same padded with zeros to 5 characters, {n} the number of the device in the site (the highest already used + 1). Empty: the name prefix and the ADB serial.'}
      </p>
      {!check.ok && <p className="text-xs text-red-400">{reasonText(check.reason)}</p>}
      {value && check.ok && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl bg-bg-tertiary/40 px-3 py-2 text-xs">
          <Tag className="h-3.5 w-3.5 text-text-muted" />
          <span className="text-text-muted">{t('bench.nameTemplate.preview') || 'Preview, site'}</span>
          <input className="w-20 rounded-md bg-bg-tertiary px-2 py-0.5 font-mono text-xs text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50"
            value={siteCode} maxLength={16} onChange={(e) => setSiteCode(e.target.value)} aria-label={t('bench.nameTemplate.exampleSite') || 'Example site code'} />
          <span className="text-text-muted">→</span>
          {samples.map((s) => <span key={s} className="rounded-full bg-accent/15 px-2 py-0.5 font-mono text-accent">{s}</span>)}
          <span className="text-text-muted">…</span>
        </div>
      )}
    </div>
  );
}

/** The template of an existing target changed (the server asks for a strict second factor). */
export function NameTemplateDialog({ initial, target, onClose, onSave }: {
  initial: string | null; target: string; onClose: () => void; onSave: (template: string | null) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [value, setValue] = useState(initial ?? '');
  const [busy, setBusy] = useState(false);
  const ok = templateCheck(value).ok;
  const save = async () => {
    setBusy(true);
    try { await onSave(value === '' ? null : value); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} size="md" icon={<Tag className="h-4 w-4 text-accent" />}
      title={t('bench.nameTemplate.title', { target }) || `Suggested name: ${target}`}
      footer={(
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={() => void save()} disabled={!ok || busy || value === (initial ?? '')}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="space-y-3 text-sm">
        <NameTemplateField value={value} onChange={setValue} autoFocus />
        <p className="text-xs text-text-muted">{t('bench.nameTemplate.secondFactor') || 'A second factor is asked. The bench refuses a name already used in the site.'}</p>
      </div>
    </Modal>
  );
}
