import { useEffect, useId, useMemo, useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import { clsx } from 'clsx';
import {
  RULE_FIELDS, RULE_LIMITS, type DeviceFacets, type DeviceGroupTreeNode, type RuleValue,
} from '@obligarth/shared';
import { anonymize } from '@/utils/anonymize';
import { ruleValueLabel } from './ruleCatalog';
import { DAYS_OPS, LIST_OPS, NO_VALUE_OPS, type EditorCondition } from './ruleModel';

// =============================================================================
// The value (and the key) of a condition of the rule builder, by the type of its field and its operator: a select or
// toggles for an enum, text with suggestions from the facets of the fleet, a list of tokens, a pair of bounds, a
// number of days, a static group. The values are those of the shared catalog; validateRule judges them.
// =============================================================================

export const inputCls = 'min-w-0 rounded-md border border-border bg-bg-tertiary px-2 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 coarse:min-h-10';

interface Suggestion { value: string; label?: string; count?: number }

interface RuleValueInputProps {
  cond: EditorCondition;
  onChange: (patch: Partial<EditorCondition>) => void;
  facets?: DeviceFacets | null;
  groups?: DeviceGroupTreeNode[];
  disabled?: boolean;
}

/** The static groups, depth first, with their depth (for the group field). */
function flattenGroups(nodes: DeviceGroupTreeNode[], depth = 0, out: Array<{ id: number; name: string; depth: number }> = []) {
  for (const n of [...nodes].sort((a, b) => a.name.localeCompare(b.name))) {
    out.push({ id: n.id, name: anonymize(n.name) || n.name, depth });
    flattenGroups(n.children, depth + 1, out);
  }
  return out;
}

export function RuleValueInput({ cond, onChange, facets, groups = [], disabled }: RuleValueInputProps) {
  const { t } = useTranslation();
  const def = RULE_FIELDS[cond.field];
  const { op } = cond;
  const flatGroups = useMemo(() => (def.type === 'group' ? flattenGroups(groups) : []), [def.type, groups]);

  const suggestions = useMemo((): Suggestion[] => {
    if (!facets) return [];
    switch (cond.field) {
      case 'model_name': return facets.model.map((m) => ({ value: m.value, count: m.count }));
      case 'tags': return facets.tag.map((m) => ({ value: m.value, count: m.count }));
      case 'os_version': {
        const seen = new Map<string, number>();
        for (const v of facets.osVersion) seen.set(v.value, (seen.get(v.value) ?? 0) + v.count);
        return [...seen.entries()].sort((a, b) => b[0].localeCompare(a[0], undefined, { numeric: true })).slice(0, 30)
          .map(([value, count]) => ({ value, count }));
      }
      default: return [];
    }
  }, [facets, cond.field]);

  const enumCounts = useMemo((): Map<string, number> => {
    const list = !facets ? [] : cond.field === 'platform' ? facets.platform : cond.field === 'ownership' ? facets.ownership
      : cond.field === 'enrollment_state' ? facets.enrollmentState : cond.field === 'compliance_state' ? facets.complianceState
        : cond.field === 'config_state' ? facets.configState : [];
    return new Map(list.map((x) => [x.value, x.count]));
  }, [facets, cond.field]);

  const keyInput = def.keyed ? (
    <input
      value={cond.key ?? ''}
      onChange={(e) => onChange({ key: e.target.value })}
      disabled={disabled}
      maxLength={def.type === 'app' ? RULE_LIMITS.maxAppKey : RULE_LIMITS.maxCustomKey}
      placeholder={def.type === 'app' ? (t('rules.value.appKey') || 'Application identifier (com.example.app)') : (t('rules.value.customKey') || 'Name of the custom field')}
      aria-label={def.type === 'app' ? (t('rules.value.appKey') || 'Application identifier (com.example.app)') : (t('rules.value.customKey') || 'Name of the custom field')}
      autoCapitalize="off" autoCorrect="off" spellCheck={false}
      className={clsx(inputCls, 'w-full sm:w-48')}
    />
  ) : null;

  const value = cond.value;
  const set = (v: RuleValue | undefined) => onChange({ value: v });
  const valueLabel = t('rules.value.label') || 'Value';

  let input: JSX.Element | null = null;
  if (NO_VALUE_OPS.has(op)) {
    input = null;
  } else if (DAYS_OPS.has(op)) {
    input = (
      <span className="flex items-center gap-2">
        <NumberInput value={typeof value === 'number' ? value : undefined} onChange={set} integer min={1} max={RULE_LIMITS.maxDays}
          disabled={disabled} ariaLabel={t('rules.value.days') || 'Number of days'} className="w-24" />
        <span className="text-xs text-text-muted">{t('rules.value.daysUnit') || 'days'}</span>
      </span>
    );
  } else if (def.type === 'enum') {
    const values = def.values ?? [];
    if (LIST_OPS.has(op)) {
      const chosen = new Set(Array.isArray(value) ? value.map(String) : []);
      input = (
        <div className="flex flex-wrap gap-1.5" role="group" aria-label={valueLabel}>
          {values.map((v) => {
            const on = chosen.has(v);
            return (
              <button key={v} type="button" disabled={disabled} aria-pressed={on}
                onClick={() => { const next = new Set(chosen); if (on) next.delete(v); else next.add(v); set(values.filter((x) => next.has(x))); }}
                className={clsx('flex items-center gap-1 rounded-full px-2.5 py-1 text-xs transition-colors coarse:py-2',
                  on ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary')}>
                {ruleValueLabel(t, cond.field, v)}
                {enumCounts.has(v) && <span className="text-text-muted/70">{enumCounts.get(v)}</span>}
              </button>
            );
          })}
        </div>
      );
    } else {
      input = (
        <select value={typeof value === 'string' ? value : ''} onChange={(e) => set(e.target.value)} disabled={disabled}
          aria-label={valueLabel} className={clsx(inputCls, 'w-full sm:w-auto')}>
          {values.map((v) => (
            <option key={v} value={v}>{ruleValueLabel(t, cond.field, v)}{enumCounts.has(v) ? ` (${enumCounts.get(v)})` : ''}</option>
          ))}
        </select>
      );
    }
  } else if (def.type === 'bool') {
    input = (
      <select value={value === false ? 'false' : 'true'} onChange={(e) => set(e.target.value === 'true')} disabled={disabled}
        aria-label={valueLabel} className={clsx(inputCls, 'w-full sm:w-auto')}>
        <option value="true">{t('rules.value.yes') || 'Yes'}</option>
        <option value="false">{t('rules.value.no') || 'No'}</option>
      </select>
    );
  } else if (def.type === 'group') {
    if (LIST_OPS.has(op)) {
      const chosen = new Set(Array.isArray(value) ? value.map(Number) : []);
      input = flatGroups.length === 0 ? <span className="text-xs italic text-text-muted">{t('rules.value.noGroups') || 'No static group in this tenant.'}</span> : (
        <div className="max-h-40 w-full overflow-y-auto rounded-md border border-border bg-bg-tertiary py-1 sm:w-64" role="group" aria-label={valueLabel}>
          {flatGroups.map((g) => (
            <label key={g.id} className="flex items-center gap-2 px-2 py-1 text-sm text-text-primary hover:bg-bg-hover coarse:py-2" style={{ paddingLeft: 8 + g.depth * 12 }}>
              <input type="checkbox" className="accent-accent" checked={chosen.has(g.id)} disabled={disabled}
                onChange={() => { const next = new Set(chosen); if (next.has(g.id)) next.delete(g.id); else next.add(g.id); set(flatGroups.filter((x) => next.has(x.id)).map((x) => x.id)); }} />
              <span className="truncate">{g.name}</span>
            </label>
          ))}
        </div>
      );
    } else {
      input = (
        <select value={typeof value === 'number' ? String(value) : ''} onChange={(e) => set(e.target.value ? Number(e.target.value) : undefined)}
          disabled={disabled} aria-label={valueLabel} className={clsx(inputCls, 'w-full sm:w-56')}>
          <option value="">{t('rules.value.pickGroup') || 'Choose a group…'}</option>
          {flatGroups.map((g) => <option key={g.id} value={g.id}>{`${'  '.repeat(g.depth)}${g.name}`}</option>)}
        </select>
      );
    }
  } else if (def.type === 'number') {
    if (LIST_OPS.has(op)) {
      input = (
        <TokenInput values={Array.isArray(value) ? value.map(String) : []} disabled={disabled} inputMode="numeric"
          onChange={(vs) => set(vs.map((s) => (s.trim() !== '' && Number.isFinite(Number(s)) ? Number(s) : s)))} />
      );
    } else if (op === 'between') {
      const [a, b] = Array.isArray(value) ? value : [];
      const num = (x: unknown) => (typeof x === 'number' ? x : undefined);
      input = (
        <Between
          first={<NumberInput value={num(a)} onChange={(v) => set([v ?? '', b ?? ''] as RuleValue)} integer={def.integer} min={def.min} max={def.max} disabled={disabled} ariaLabel={t('rules.value.from') || 'From'} className="w-28" />}
          second={<NumberInput value={num(b)} onChange={(v) => set([a ?? '', v ?? ''] as RuleValue)} integer={def.integer} min={def.min} max={def.max} disabled={disabled} ariaLabel={t('rules.value.to') || 'To'} className="w-28" />}
        />
      );
    } else {
      input = <NumberInput value={typeof value === 'number' ? value : undefined} onChange={set} integer={def.integer} min={def.min} max={def.max} disabled={disabled} ariaLabel={valueLabel} className="w-28" />;
    }
  } else if (def.type === 'date') {
    if (op === 'between') {
      const [a, b] = Array.isArray(value) ? value.map(String) : ['', ''];
      input = (
        <Between
          first={<input type="date" value={a ?? ''} onChange={(e) => set([e.target.value, b ?? ''])} disabled={disabled} aria-label={t('rules.value.from') || 'From'} className={inputCls} />}
          second={<input type="date" value={b ?? ''} onChange={(e) => set([a ?? '', e.target.value])} disabled={disabled} aria-label={t('rules.value.to') || 'To'} className={inputCls} />}
        />
      );
    } else {
      input = <input type="date" value={typeof value === 'string' ? value : ''} onChange={(e) => set(e.target.value || undefined)} disabled={disabled} aria-label={valueLabel} className={inputCls} />;
    }
  } else if (def.type === 'tags' || LIST_OPS.has(op)) {
    input = (
      <TokenInput values={Array.isArray(value) ? value.map(String) : []} onChange={(vs) => set(vs)} suggestions={suggestions} disabled={disabled}
        placeholder={def.type === 'tags' ? (t('rules.value.tagPlaceholder') || 'Add a tag') : undefined} />
    );
  } else if (op === 'between') {
    // version
    const [a, b] = Array.isArray(value) ? value.map(String) : ['', ''];
    input = (
      <Between
        first={<TextInput value={a ?? ''} onChange={(v) => set([v, b ?? ''])} suggestions={suggestions} disabled={disabled} ariaLabel={t('rules.value.from') || 'From'} className="w-28" inputMode="decimal" />}
        second={<TextInput value={b ?? ''} onChange={(v) => set([a ?? '', v])} suggestions={suggestions} disabled={disabled} ariaLabel={t('rules.value.to') || 'To'} className="w-28" inputMode="decimal" />}
      />
    );
  } else {
    // string, kv, version, app (a version)
    const isVersion = def.type === 'version' || def.type === 'app';
    input = (
      <TextInput value={typeof value === 'string' ? value : value === undefined ? '' : String(value)} onChange={(v) => set(v === '' ? undefined : v)}
        suggestions={suggestions} disabled={disabled} ariaLabel={valueLabel} inputMode={isVersion ? 'decimal' : undefined}
        placeholder={isVersion ? (t('rules.value.versionPlaceholder') || '17.5') : undefined}
        className={isVersion ? 'w-28' : 'w-full sm:w-56'} maxLength={RULE_LIMITS.maxString} />
    );
  }

  if (!keyInput && !input) return null;
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      {keyInput}
      {input}
    </div>
  );
}

function Between({ first, second }: { first: JSX.Element; second: JSX.Element }) {
  const { t } = useTranslation();
  return (
    <span className="flex flex-wrap items-center gap-2">
      {first}
      <span className="text-xs text-text-muted">{t('rules.value.and') || 'and'}</span>
      {second}
    </span>
  );
}

function TextInput({ value, onChange, suggestions = [], disabled, ariaLabel, placeholder, className, inputMode, maxLength }: {
  value: string; onChange: (v: string) => void; suggestions?: Suggestion[]; disabled?: boolean; ariaLabel: string;
  placeholder?: string; className?: string; inputMode?: 'decimal' | 'numeric'; maxLength?: number;
}) {
  const listId = useId();
  return (
    <>
      <input value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} aria-label={ariaLabel} placeholder={placeholder}
        list={suggestions.length ? listId : undefined} inputMode={inputMode} maxLength={maxLength}
        autoCapitalize="off" autoCorrect="off" spellCheck={false} className={clsx(inputCls, className)} />
      {suggestions.length > 0 && (
        <datalist id={listId}>
          {suggestions.map((s) => <option key={s.value} value={s.value}>{s.count !== undefined ? `${s.value} (${s.count})` : s.value}</option>)}
        </datalist>
      )}
    </>
  );
}

/** A number typed as text (a partial "1." stays as typed), committed when it parses. */
function NumberInput({ value, onChange, integer, min, max, disabled, ariaLabel, className }: {
  value: number | undefined; onChange: (v: number | undefined) => void; integer?: boolean; min?: number; max?: number;
  disabled?: boolean; ariaLabel: string; className?: string;
}) {
  const [text, setText] = useState(value === undefined ? '' : String(value));
  useEffect(() => {
    // An outside change (another operator, a reset) replaces the text; the same number keeps what is typed.
    setText((cur) => (cur.trim() !== '' && Number(cur.replace(',', '.')) === value ? cur : value === undefined ? '' : String(value)));
  }, [value]);
  return (
    <input value={text} disabled={disabled} aria-label={ariaLabel} inputMode={integer ? 'numeric' : 'decimal'}
      min={min} max={max}
      onChange={(e) => {
        const raw = e.target.value;
        setText(raw);
        const n = Number(raw.replace(',', '.'));
        onChange(raw.trim() === '' || !Number.isFinite(n) ? undefined : n);
      }}
      className={clsx(inputCls, className)} />
  );
}

/** A list of values: chips, and a field that adds one on Enter, a comma, or leaving it. */
function TokenInput({ values, onChange, suggestions = [], disabled, placeholder, inputMode }: {
  values: string[]; onChange: (v: string[]) => void; suggestions?: Suggestion[]; disabled?: boolean; placeholder?: string;
  inputMode?: 'numeric' | 'decimal';
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState('');
  const listId = useId();
  const add = (raw: string) => {
    const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length === 0) return;
    const next = [...values];
    for (const p of parts) if (!next.includes(p)) next.push(p);
    onChange(next.slice(0, RULE_LIMITS.maxValues));
    setDraft('');
  };
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(draft); } else if (e.key === 'Backspace' && draft === '' && values.length > 0) onChange(values.slice(0, -1));
  };
  const free = suggestions.filter((s) => !values.includes(s.value));
  return (
    <div className="flex w-full min-w-0 flex-wrap items-center gap-1.5 rounded-md border border-border bg-bg-tertiary px-1.5 py-1 sm:w-auto sm:min-w-[14rem]">
      {values.map((v) => (
        <span key={v} className="flex max-w-full items-center gap-1 rounded-full bg-accent/15 px-2 py-0.5 text-xs text-accent">
          <span className="truncate">{v}</span>
          <button type="button" disabled={disabled} onClick={() => onChange(values.filter((x) => x !== v))}
            aria-label={t('rules.value.removeValue', { value: v }) || `Remove ${v}`} className="shrink-0 rounded-full p-0.5 hover:bg-accent/20 coarse:p-1.5">
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={onKeyDown} onBlur={() => add(draft)} disabled={disabled}
        list={free.length ? listId : undefined} placeholder={placeholder ?? (t('rules.value.addValue') || 'Add a value')}
        aria-label={placeholder ?? (t('rules.value.addValue') || 'Add a value')} inputMode={inputMode} maxLength={RULE_LIMITS.maxString}
        autoCapitalize="off" autoCorrect="off" spellCheck={false}
        className="min-w-[6rem] flex-1 bg-transparent px-1 py-1 text-sm text-text-primary placeholder:text-text-muted focus:outline-none coarse:min-h-9" />
      {free.length > 0 && (
        <datalist id={listId}>
          {free.map((s) => <option key={s.value} value={s.value}>{s.count !== undefined ? `${s.value} (${s.count})` : s.value}</option>)}
        </datalist>
      )}
    </div>
  );
}
