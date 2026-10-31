import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { AgentDpmFieldSpec, AgentKnoxFieldSpec, JsonValue, PolicyValidationIssue } from '@obligarth/shared';
import { AGENT_DPM_FIELDS, AGENT_KNOX_FIELDS } from '@obligarth/shared';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { ChipChoice, IssueList, fieldCls, issuesUnder } from './ui';

// The restrictions of the bridge agent (lot PONT-POL §11.1): the device administrator's (every agent, API 24) and Knox's
// (licensed devices only; "pending licence" on the others). Each row is "Not managed" or a value; a value removed from
// the policy is undone on the device. The wipe threshold erases a device after failed passwords: corporate devices only,
// a second approver at every publication that adds, changes or removes it.

type Values = Record<string, JsonValue>;

export function RestrictionsPanel({ dpm, knox, editable, issues, onChange, lockoutConfirmed = false, lockoutIssues = [], onConfirmLockout }: {
  dpm: Values; knox: Values; editable: boolean; issues: PolicyValidationIssue[];
  onChange: (next: { dpm: Values; knox: Values }) => void;
  /** Lot BANC (D16): Knox usbDebugging=false cuts ADB; the server asks for this explicit confirmation. */
  lockoutConfirmed?: boolean; lockoutIssues?: PolicyValidationIssue[]; onConfirmLockout?: (on: boolean) => void;
}) {
  const { t } = useTranslation();
  const setDpm = (field: string, v: JsonValue | undefined) => {
    const next = { ...dpm };
    if (v === undefined) delete next[field]; else next[field] = v;
    onChange({ dpm: next, knox });
  };
  const setKnox = (field: string, v: JsonValue | undefined) => {
    const next = { ...knox };
    if (v === undefined) delete next[field]; else next[field] = v;
    onChange({ dpm, knox: next });
  };
  return (
    <div className="space-y-5">
      <section className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('legacyAgentPolicy.restrictions.dpm') || 'Device administrator (all agents)'}</h3>
        <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
          {AGENT_DPM_FIELDS.map((f) => (
            <li key={f.field} className="space-y-1.5 px-3 py-2 text-sm hover:bg-bg-tertiary">
              <div className="flex flex-wrap items-center gap-2">
                <span className="min-w-0 flex-1 text-text-primary">{t(`legacyAgentPolicy.dpm.${f.field}`) || f.field}</span>
                {f.wipe && <span className="rounded-full bg-red-400/10 px-2 py-0.5 text-[11px] text-red-400">{t('legacyAgentPolicy.restrictions.erases') || 'Erases the device'}</span>}
                {f.complianceOnly && <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-muted">{t('legacyAgentPolicy.restrictions.checkOnly') || 'checked only'}</span>}
              </div>
              <DpmControl spec={f} value={dpm[f.field]} editable={editable} onChange={(v) => setDpm(f.field, v)} />
              {f.wipe && (
                <p className="text-[11px] text-text-muted">
                  {t('legacyAgentPolicy.restrictions.wipeHint') || 'Corporate devices only, with a password quality set; every publication that adds, changes or removes it needs a second approver.'}
                </p>
              )}
              <IssueList issues={issuesUnder(issues, `dpm.${f.field}`)} />
            </li>
          ))}
        </ul>
      </section>
      <section className="space-y-2">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('legacyAgentPolicy.restrictions.knox') || 'Knox (licensed devices only)'}</h3>
          <span className="rounded-full bg-violet-400/10 px-2 py-0.5 text-[11px] text-violet-400">{t('legacyAgentPolicy.knoxRequired') || 'Knox licence required'}</span>
        </div>
        <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
          {AGENT_KNOX_FIELDS.map((f) => (
            <li key={f.field} className="space-y-1.5 px-3 py-2 text-sm hover:bg-bg-tertiary">
              <span className="text-text-primary">{t(`legacyAgentPolicy.knox.${f.field}`) || f.field}</span>
              <KnoxControl spec={f} value={knox[f.field]} editable={editable} onChange={(v) => setKnox(f.field, v)} />
              {f.field === 'usbDebugging' && knox[f.field] === false && (
                <div className="space-y-1 rounded-md bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-400">
                  <p>{t('legacyAgentPolicy.restrictions.benchLockout') || 'Cuts ADB: the device can no longer go back to a bench station without a bench window or a reset.'}</p>
                  <ToggleSwitch size="sm" checked={lockoutConfirmed} disabled={!editable} onChange={(on) => onConfirmLockout?.(on)}
                    label={t('legacyAgentPolicy.restrictions.benchLockoutConfirm') || 'I confirm: cut ADB on these devices'} />
                  <IssueList issues={lockoutIssues} />
                </div>
              )}
              <IssueList issues={issuesUnder(issues, `knox.${f.field}`)} />
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function DpmControl({ spec, value, editable, onChange }: { spec: AgentDpmFieldSpec; value: JsonValue | undefined; editable: boolean; onChange: (v: JsonValue | undefined) => void }) {
  const { t } = useTranslation();
  const unmanaged = t('legacyAgentPolicy.restrictions.notManaged') || 'Not managed';
  if (spec.type === 'bool') {
    return (
      <ChipChoice disabled={!editable} value={value === undefined ? 'none' : value ? 'on' : 'off'} onChange={(v) => onChange(v === 'none' ? undefined : v === 'on')}
        options={[{ id: 'none', label: unmanaged }, { id: 'on', label: t('legacyAgentPolicy.restrictions.yes') || 'Yes' }, { id: 'off', label: t('legacyAgentPolicy.restrictions.no') || 'No' }]} />
    );
  }
  if (spec.type === 'enum') {
    return (
      <ChipChoice disabled={!editable} value={typeof value === 'string' ? value : 'none'} onChange={(v) => onChange(v === 'none' ? undefined : v)}
        options={[{ id: 'none', label: unmanaged }, ...(spec.values ?? []).map((v) => ({ id: v, label: t(`legacyAgentPolicy.enum.${v}`) || v }))]} />
    );
  }
  if (spec.type === 'flags') {
    const list = Array.isArray(value) ? value.filter((x): x is string => typeof x === 'string') : null;
    return (
      <div className="flex flex-wrap gap-1.5">
        <button type="button" disabled={!editable} onClick={() => onChange(list ? undefined : [])}
          className={`rounded-full px-2.5 py-1 text-xs ${list ? 'bg-bg-tertiary text-text-muted' : 'bg-accent/15 text-accent'}`}>{unmanaged}</button>
        {(spec.values ?? []).map((v) => {
          const on = !!list?.includes(v);
          return (
            <button key={v} type="button" disabled={!editable} onClick={() => onChange(on ? (list ?? []).filter((x) => x !== v) : [...(list ?? []), v])}
              className={`rounded-full px-2.5 py-1 text-xs ${on ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'}`}>
              {t(`legacyAgentPolicy.enum.${v}`) || v}
            </button>
          );
        })}
      </div>
    );
  }
  return (
    <input className={`${fieldCls} max-w-[10rem]`} inputMode="numeric" disabled={!editable} placeholder={unmanaged}
      value={typeof value === 'number' ? String(value) : ''} maxLength={4}
      onChange={(e) => { const s = e.target.value.replace(/[^0-9]/g, ''); onChange(s === '' ? undefined : Math.min(spec.max ?? 9999, Number(s))); }} />
  );
}

function KnoxControl({ spec, value, editable, onChange }: { spec: AgentKnoxFieldSpec; value: JsonValue | undefined; editable: boolean; onChange: (v: JsonValue | undefined) => void }) {
  const { t } = useTranslation();
  if (spec.type === 'bool') {
    return (
      <ChipChoice disabled={!editable} value={value === undefined ? 'none' : value ? 'allow' : 'block'} onChange={(v) => onChange(v === 'none' ? undefined : v === 'allow')}
        options={[{ id: 'none', label: t('legacyAgentPolicy.restrictions.notManaged') || 'Not managed' }, { id: 'allow', label: t('legacyAgentPolicy.restrictions.allow') || 'Allow' },
          { id: 'block', label: t('legacyAgentPolicy.restrictions.block') || 'Block' }]} />
    );
  }
  const list = Array.isArray(value) ? value.filter((x): x is string => typeof x === 'string') : [];
  return <PackageList list={list} editable={editable} placeholder={t('legacyAgentPolicy.restrictions.packagesHint') || 'One package per line (com.example.app)'} onChange={onChange} />;
}

/** A list of packages, one per line: typed freely, kept on blur. */
function PackageList({ list, editable, placeholder, onChange }: { list: string[]; editable: boolean; placeholder: string; onChange: (v: JsonValue | undefined) => void }) {
  const [text, setText] = useState(list.join('\n'));
  useEffect(() => { setText(list.join('\n')); }, [list.join('\n')]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <textarea className={`${fieldCls} font-mono text-xs`} rows={2} disabled={!editable} spellCheck={false} placeholder={placeholder}
      value={text} onChange={(e) => setText(e.target.value)}
      onBlur={() => { const l = [...new Set(text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean))]; onChange(l.length ? l : undefined); }} />
  );
}
