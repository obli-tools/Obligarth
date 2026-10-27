import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Ban, FolderPlus, Loader2, Plus, Trash2 } from 'lucide-react';
import { clsx } from 'clsx';
import {
  RULE_FIELDS, RULE_LIMITS,
  type DeviceFacets, type DeviceGroupTreeNode, type RuleFieldKey, type RuleIssue, type RuleNode, type RuleOp, type RuleUse,
} from '@obligarth/shared';
import { apiErrorMessage } from '@/utils/apiError';
import {
  RULE_CATEGORIES, fieldsOfCategory, ruleCategoryLabel, ruleFieldLabel, ruleIssueLabel, ruleOpLabelFor,
  ruleRestrictionLabel, ruleRestrictionOf,
} from './ruleCatalog';
import {
  appendChild, canNest, checkTree, fromRule, newCondition, newGroup, removeNode, updateNode, valueForOp, withField,
  type EditorCondition, type EditorGroup, type EditorNode, type RuleCheck,
} from './ruleModel';
import { RuleValueInput, inputCls } from './RuleValueInput';

// =============================================================================
// The rule builder (P0-5 §6): a tree of groups (all / any, negated or not) and conditions (field, operator, value) over
// the shared catalog of the rule language. The fields a use does not permit (allowed: 'targetable' or 'filterable',
// D2) are greyed in the picker, and a condition that names one says why (PLT-16). The issues of the shared
// validateRule show on the node they name. The live preview (preview, when given) runs 500 ms after the last change of
// a valid rule. Uncontrolled: it starts from initialRule (a new `key` starts it again) and tells every change
// (onChange: the rule, its issues, whether it is valid).
// =============================================================================

export interface RuleBuilderProps {
  initialRule?: RuleNode | null;
  /** Where the rule is used (D2): every field in a view; the targetable or filterable ones otherwise. */
  allowed?: RuleUse;
  onChange?: (check: RuleCheck & { tooLong: boolean }) => void;
  /** Values offered from the fleet (models, tags, OS versions, counts of the enum values). */
  facets?: DeviceFacets | null;
  /** The static groups of the tenant (the group field). */
  groups?: DeviceGroupTreeNode[];
  /** The live count of the devices the rule selects (null: no rule). */
  preview?: (rule: RuleNode | null) => Promise<number>;
  /** The sentence of the preview's count (default: "{{count}} devices match"). */
  previewLabel?: (count: number) => string;
  /** Can the JSON of the rule be used (a query parameter: its length, and its length once encoded in the address)?
   *  false refuses the rule. */
  jsonFits?: (json: string) => boolean;
  disabled?: boolean;
}

export function RuleBuilder({
  initialRule, allowed = 'view', onChange, facets, groups, preview, previewLabel, jsonFits, disabled = false,
}: RuleBuilderProps) {
  const { t } = useTranslation();
  const [root, setRoot] = useState<EditorGroup>(() => fromRule(initialRule));
  const check = useMemo(() => checkTree(root, allowed), [root, allowed]);
  const json = check.rule ? JSON.stringify(check.rule) : '';
  const tooLong = !!jsonFits && json !== '' && !jsonFits(json);

  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  useEffect(() => { onChangeRef.current?.({ ...check, tooLong, valid: check.valid && !tooLong }); }, [check, tooLong]);

  // ── Live preview: 500 ms after the last change of a valid rule; a late answer of an older rule is dropped. ──
  const [pv, setPv] = useState<{ state: 'idle' | 'loading' | 'done' | 'error'; count?: number; error?: string }>({ state: 'idle' });
  const previewRef = useRef(preview);
  previewRef.current = preview;
  const canPreview = !!preview && check.valid && !tooLong;
  useEffect(() => {
    if (!previewRef.current || !canPreview) { setPv({ state: 'idle' }); return undefined; }
    let alive = true;
    setPv((p) => ({ ...p, state: 'loading' }));
    const timer = setTimeout(() => {
      previewRef.current!(check.rule)
        .then((count) => { if (alive) setPv({ state: 'done', count }); })
        .catch((err) => { if (alive) setPv({ state: 'error', error: apiErrorMessage(err) }); });
    }, 500);
    return () => { alive = false; clearTimeout(timer); };
    // The rule's JSON is the dependency: a new tree of the same rule does not count again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [json, canPreview]);

  const update = (id: string, fn: (n: EditorNode) => EditorNode) => setRoot((r) => updateNode(r, id, fn));
  const ctx: NodeCtx = {
    root, check, allowed, facets, groups, disabled,
    update, remove: (id) => setRoot((r) => removeNode(r, id)),
    add: (groupId, child) => setRoot((r) => appendChild(r, groupId, child)),
  };

  const rootIssues = (check.byNode.get(root.id) ?? []).filter((i) => i.path === '$' || i.path === '$.not');
  return (
    <div className="space-y-3">
      <GroupView group={root} isRoot ctx={ctx} />
      {allowed !== 'view' && (
        <p className="flex items-start gap-1.5 text-[11px] text-text-muted">
          <Ban className="mt-0.5 h-3 w-3 shrink-0" />
          {t('rules.builder.restrictedHint') || 'Greyed fields are not permitted here: derived and time-relative fields, the static group, the installed applications and the name of the device (its user can change it).'}
        </p>
      )}
      {(rootIssues.length > 0 || tooLong) && (
        <ul className="space-y-1 text-xs text-red-400">
          {rootIssues.map((i, k) => <li key={k} className="flex items-start gap-1.5"><AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />{ruleIssueLabel(t, i.code)}</li>)}
          {tooLong && (
            <li className="flex items-start gap-1.5"><AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
              {t('rules.builder.tooLong') || 'This rule is too long for the list: remove some conditions or values.'}
            </li>
          )}
        </ul>
      )}
      {preview && (
        <div className="flex min-h-[1.5rem] items-center gap-2 text-xs" aria-live="polite">
          {pv.state === 'loading' && <><Loader2 className="h-3.5 w-3.5 animate-spin text-text-muted" /><span className="text-text-muted">{t('rules.builder.previewLoading') || 'Counting the devices…'}</span></>}
          {pv.state === 'done' && pv.count !== undefined && (
            <span className="font-medium text-text-primary">
              {previewLabel ? previewLabel(pv.count) : (t('rules.builder.previewCount', { count: pv.count }) || `${pv.count} devices match`)}
            </span>
          )}
          {pv.state === 'error' && <span className="text-red-400">{pv.error}</span>}
          {pv.state === 'idle' && !check.valid && check.conditions > 0 && (
            <span className="text-text-muted">{t('rules.builder.previewIncomplete') || 'Complete the conditions to see how many devices match.'}</span>
          )}
        </div>
      )}
    </div>
  );
}

interface NodeCtx {
  root: EditorGroup;
  check: RuleCheck;
  allowed: RuleUse;
  facets?: DeviceFacets | null;
  groups?: DeviceGroupTreeNode[];
  disabled: boolean;
  update: (id: string, fn: (n: EditorNode) => EditorNode) => void;
  remove: (id: string) => void;
  add: (groupId: string, child: EditorNode) => void;
}

const conditionCount = (n: EditorNode): number => (n.kind === 'cond' ? 1 : n.children.reduce((s, c) => s + conditionCount(c), 0));

/** The NOT of a condition or a group: its visible text is its accessible name (WCAG 2.5.3, a voice command says it), the
 *  action its description (title). */
function NegateToggle({ on, onToggle, disabled, label }: { on: boolean; onToggle: () => void; disabled: boolean; label: string }) {
  const { t } = useTranslation();
  return (
    <button type="button" onClick={onToggle} disabled={disabled} aria-pressed={on} title={label}
      className={clsx('shrink-0 rounded-md px-2 py-1 text-[11px] font-semibold uppercase tracking-wider transition-colors coarse:min-h-10 coarse:min-w-10',
        on ? 'bg-amber-500/15 text-amber-400' : 'bg-bg-tertiary text-text-muted hover:text-text-primary')}>
      {t('rules.builder.not') || 'Not'}
    </button>
  );
}

function GroupView({ group, isRoot = false, ctx }: { group: EditorGroup; isRoot?: boolean; ctx: NodeCtx }) {
  const { t } = useTranslation();
  const { disabled } = ctx;
  const total = conditionCount(ctx.root);
  const full = total >= RULE_LIMITS.maxConditions;
  const nestable = canNest(ctx.root, group.id);
  const issues = (ctx.check.byNode.get(group.id) ?? []).filter((i) => !isRoot || (i.path !== '$' && i.path !== '$.not'));
  const joiner = group.mode === 'all' ? (t('rules.builder.and') || 'and') : (t('rules.builder.or') || 'or');

  return (
    <div className={clsx(!isRoot && 'rounded-lg border border-border bg-bg-primary/40 p-2 sm:p-3', 'space-y-2')}>
      <div className="flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-md bg-bg-tertiary p-0.5" role="group" aria-label={t('rules.builder.mode') || 'Match'}>
          {(['all', 'any'] as const).map((m) => (
            <button key={m} type="button" disabled={disabled} aria-pressed={group.mode === m}
              onClick={() => ctx.update(group.id, (n) => (n.kind === 'group' ? { ...n, mode: m } : n))}
              className={clsx('rounded px-2.5 py-1 text-xs font-medium transition-colors coarse:min-h-9',
                group.mode === m ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary')}>
              {m === 'all' ? (t('rules.builder.matchAll') || 'All of these') : (t('rules.builder.matchAny') || 'Any of these')}
            </button>
          ))}
        </div>
        <NegateToggle on={group.negated} disabled={disabled}
          label={isRoot ? (t('rules.builder.negateRoot') || 'Keep the devices that do not match') : (t('rules.builder.negateGroup') || 'Negate this group')}
          onToggle={() => ctx.update(group.id, (n) => ({ ...n, negated: !n.negated }))} />
        {group.negated && (
          <span className="text-[11px] text-amber-400">{t('rules.builder.negatedHint') || 'The devices that do not match'}</span>
        )}
        {!isRoot && (
          <button type="button" disabled={disabled} onClick={() => ctx.remove(group.id)}
            aria-label={t('rules.builder.removeGroup') || 'Remove the group'} title={t('rules.builder.removeGroup') || 'Remove the group'}
            className="ml-auto rounded-md p-1.5 text-text-muted hover:bg-red-400/10 hover:text-red-400 coarse:min-h-10 coarse:min-w-10">
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </div>

      {group.children.length === 0 ? (
        <p className="text-xs italic text-text-muted">
          {isRoot ? (t('rules.builder.empty') || 'No condition: the advanced filter selects every device.') : (t('rules.builder.emptyGroup') || 'Empty group.')}
        </p>
      ) : (
        <div className="space-y-1.5">
          {group.children.map((c, i) => (
            <div key={c.id}>
              {i > 0 && <div className="py-0.5 pl-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">{joiner}</div>}
              {c.kind === 'group' ? <GroupView group={c} ctx={ctx} /> : <ConditionRow cond={c} ctx={ctx} />}
            </div>
          ))}
        </div>
      )}

      {issues.length > 0 && <IssueList issues={issues} />}

      <div className="flex flex-wrap items-center gap-2">
        <button type="button" disabled={disabled || full} onClick={() => ctx.add(group.id, newCondition())}
          className="flex items-center gap-1.5 rounded-md bg-bg-tertiary px-2.5 py-1.5 text-xs text-text-primary hover:bg-bg-active disabled:opacity-40 coarse:min-h-10">
          <Plus className="h-3.5 w-3.5 text-accent" />
          {t('rules.builder.addCondition') || 'Add a condition'}
        </button>
        {nestable && (
          <button type="button" disabled={disabled || full} onClick={() => ctx.add(group.id, newGroup(group.mode === 'all' ? 'any' : 'all'))}
            className="flex items-center gap-1.5 rounded-md bg-bg-tertiary px-2.5 py-1.5 text-xs text-text-primary hover:bg-bg-active disabled:opacity-40 coarse:min-h-10">
            <FolderPlus className="h-3.5 w-3.5 text-accent" />
            {t('rules.builder.addGroup') || 'Add a group'}
          </button>
        )}
        {isRoot && full && <span className="text-[11px] text-amber-400">{t('rules.builder.full', { max: RULE_LIMITS.maxConditions }) || `${RULE_LIMITS.maxConditions} conditions at most.`}</span>}
      </div>
    </div>
  );
}

function ConditionRow({ cond, ctx }: { cond: EditorCondition; ctx: NodeCtx }) {
  const { t } = useTranslation();
  const { disabled } = ctx;
  const def = RULE_FIELDS[cond.field];
  const restriction = ruleRestrictionOf(def, ctx.allowed);
  const issues = ctx.check.byNode.get(cond.id) ?? [];
  const bad = issues.length > 0 || !!restriction;
  const set = (patch: Partial<EditorCondition>) => ctx.update(cond.id, (n) => (n.kind === 'cond' ? { ...n, ...patch } : n));

  return (
    <div className={clsx('space-y-2 rounded-lg border p-2', bad ? 'border-red-500/40 bg-red-500/5' : 'border-transparent bg-bg-tertiary/40')}>
      <div className="flex flex-wrap items-center gap-2">
        {/* Phone: the negation, the field and the removal on one line; from sm up, items of the row (removal last). */}
        <div className="flex w-full min-w-0 items-center gap-2 sm:contents">
          <NegateToggle on={cond.negated} disabled={disabled} label={t('rules.builder.negateCondition') || 'Negate this condition'}
            onToggle={() => set({ negated: !cond.negated })} />
          <select value={cond.field} disabled={disabled} aria-label={t('rules.builder.field') || 'Field'}
            onChange={(e) => ctx.update(cond.id, (n) => (n.kind === 'cond' ? withField(n, e.target.value as RuleFieldKey) : n))}
            className={clsx(inputCls, 'min-w-0 flex-1 sm:w-52 sm:flex-none')}>
            {RULE_CATEGORIES.map((c) => (
              <optgroup key={c} label={ruleCategoryLabel(t, c)}>
                {fieldsOfCategory(c).map((f) => {
                  const off = !!ruleRestrictionOf(RULE_FIELDS[f], ctx.allowed);
                  return (
                    <option key={f} value={f} disabled={off && f !== cond.field}>
                      {off ? `${ruleFieldLabel(t, f)} — ${t('rules.builder.notPermitted') || 'not permitted here'}` : ruleFieldLabel(t, f)}
                    </option>
                  );
                })}
              </optgroup>
            ))}
          </select>
          <button type="button" disabled={disabled} onClick={() => ctx.remove(cond.id)}
            aria-label={t('rules.builder.removeCondition') || 'Remove the condition'} title={t('rules.builder.removeCondition') || 'Remove the condition'}
            className="shrink-0 rounded-md p-1.5 text-text-muted hover:bg-red-400/10 hover:text-red-400 sm:order-last coarse:min-h-10 coarse:min-w-10">
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
        <select value={cond.op} disabled={disabled} aria-label={t('rules.builder.operator') || 'Operator'}
          onChange={(e) => { const op = e.target.value as RuleOp; set({ op, value: valueForOp(cond, op) }); }}
          className={clsx(inputCls, 'w-full sm:w-auto')}>
          {def.ops.map((op) => <option key={op} value={op}>{ruleOpLabelFor(t, cond.field, op)}</option>)}
        </select>
        <div className="w-full min-w-0 sm:w-auto sm:flex-1">
          <RuleValueInput cond={cond} onChange={set} facets={ctx.facets} groups={ctx.groups} disabled={disabled} />
        </div>
      </div>
      {restriction && (
        <p className="flex items-start gap-1.5 text-xs text-red-400"><Ban className="mt-0.5 h-3 w-3 shrink-0" />{ruleRestrictionLabel(t, restriction)}</p>
      )}
      {issues.length > 0 && <IssueList issues={issues} />}
      {def.privacy && (
        <p className="text-[11px] text-text-muted">
          {def.privacy === 'serialNumber'
            ? (t('rules.builder.privacySerial') || 'Devices whose privacy rules do not collect the serial number never match this condition.')
            : (t('rules.builder.privacyApps') || 'Only the applications the privacy rules of a device let the console see are compared.')}
        </p>
      )}
    </div>
  );
}

function IssueList({ issues }: { issues: RuleIssue[] }) {
  const { t } = useTranslation();
  // One line per message (the key of an application and of a custom field have their own).
  const lines = [...new Set(issues.map((i) => ruleIssueLabel(t, i.code, i.field)))];
  return (
    <ul className="space-y-0.5 text-xs text-red-400">
      {lines.map((l) => <li key={l} className="flex items-start gap-1.5"><AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />{l}</li>)}
    </ul>
  );
}
