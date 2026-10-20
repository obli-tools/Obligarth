import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Braces, Plus, Trash2 } from 'lucide-react';
import {
  ANDROID_FORM_GROUPS, ANDROID_INSTALL_TYPES,
  type AndroidAppEntry, type AndroidFormCatalogView, type AndroidFormField, type AndroidFormNode, type AndroidPolicySection as Section,
  type JsonValue, type PolicyValidationIssue,
} from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { trCode } from '@/utils/apiError';
import { fieldClass } from './ui';

// The Android section of the policy editor (android-amapi §9.2, §12.1; lot AN-C2): forms generated from the catalog
// of the compiler (GET /api/android/policy-catalog: the AMAPI Policy schema of the pinned revision with the overlay),
// the fields grouped by intention, with their modes, minimum API level and the settings that can wipe a device; the
// apps of the policy; the JSON of the fragment as a fallback. A value the form cannot express (an array of objects, a
// field of type any, a nesting deeper than two levels) is edited as JSON in place. Secrets are written as
// {"$secretValue": "…"} (moved to the vault at the save) or {"$secret": "<uuid>"}; the server validates everything.

const pretty = (v: unknown): string => JSON.stringify(v ?? null, null, 2);

/** The label of a field of the catalog: its translation, else its name in words (the catalog ships no description). */
export function fieldLabel(name: string): string {
  const words = name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2').toLowerCase();
  return trCode(`android.policy.fields.${name}`, words.charAt(0).toUpperCase() + words.slice(1));
}
/** The label of a value of an enumeration: its translation, else the value in words (UNSPECIFIED kept as is). */
export function valueLabel(v: string): string {
  const words = v.toLowerCase().replace(/_/g, ' ');
  return trCode(`android.policy.values.${v}`, words.charAt(0).toUpperCase() + words.slice(1));
}
const MAX_FORM_DEPTH = 2;

/** The node with its $ref resolved (one level). */
function resolve(node: AndroidFormNode | undefined, schemas: Record<string, AndroidFormNode>): AndroidFormNode | undefined {
  if (!node) return undefined;
  return node.$ref ? schemas[node.$ref] : node;
}

/** A default value of a node when a field is added. */
function emptyOf(node: AndroidFormNode | undefined, schemas: Record<string, AndroidFormNode>): JsonValue {
  const n = resolve(node, schemas);
  switch (n?.type) {
    case 'boolean': return false;
    case 'integer': case 'number': return 0;
    case 'string': return n.enum ? (n.enum.find((v) => !/_UNSPECIFIED$/.test(v) && !(n.deprecatedValues ?? []).includes(v)) ?? n.enum[0]) : '';
    case 'array': return [];
    case 'object': return {};
    default: return null;
  }
}

export function AndroidPolicySection({ section, editable, issues, onChange }: {
  section: Section | undefined;
  editable: boolean;
  issues: PolicyValidationIssue[];
  onChange: (next: Section | undefined) => void;
}) {
  const { t } = useTranslation();
  const [catalog, setCatalog] = useState<AndroidFormCatalogView | null>(null);
  const [catalogError, setCatalogError] = useState(false);
  const [adding, setAdding] = useState(false);
  const [jsonOpen, setJsonOpen] = useState(false);
  useEffect(() => { androidApi.policyCatalog().then(setCatalog).catch(() => setCatalogError(true)); }, []);

  const fragment = section?.fragment ?? {};
  const apps = section?.applications ?? [];
  const fields = useMemo(() => new Map((catalog?.fields ?? []).map((f) => [f.name, f])), [catalog]);
  const set = (next: Section) => onChange(Object.keys(next.fragment).length === 0 && !(next.applications?.length) ? undefined : next);
  const setField = (name: string, value: JsonValue | undefined) => {
    const f = { ...fragment };
    if (value === undefined) delete f[name]; else f[name] = value;
    set({ fragment: f, ...(apps.length ? { applications: apps } : {}) });
  };
  const setApps = (next: AndroidAppEntry[]) => set({ fragment, ...(next.length ? { applications: next } : {}) });
  const issuesAt = (prefix: string) => issues.filter((i) => i.path === prefix || i.path.startsWith(`${prefix}.`) || i.path.startsWith(`${prefix}[`));
  const names = Object.keys(fragment).sort();
  const byGroup = ANDROID_FORM_GROUPS.map((g) => ({ g, list: names.filter((n) => (fields.get(n)?.group ?? 'other') === g) })).filter((x) => x.list.length);
  const loose = issues.filter((i) => !names.some((n) => i.path.startsWith(`fragment.${n}`)) && !i.path.startsWith('applications') && !i.path.startsWith('fragment.applications'));

  return (
    <section className="space-y-3 rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold text-text-primary">{t('android.policy.title') || 'Android settings'}</h2>
        {catalog && <span className="text-[11px] text-text-muted">{t('android.policy.revision', { revision: catalog.release.revision }) || `AMAPI catalog ${catalog.release.revision}`}</span>}
        <span className="ml-auto flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" onClick={() => setJsonOpen(true)}><Braces className="w-3.5 h-3.5 mr-1" />{t('android.policy.json') || 'JSON'}</Button>
          {editable && catalog && <Button size="sm" variant="secondary" onClick={() => setAdding(true)}><Plus className="w-3.5 h-3.5 mr-1" />{t('android.policy.addSetting') || 'Add a setting'}</Button>}
        </span>
      </div>
      {catalogError && <p className="text-xs text-amber-400">{t('android.policy.catalogUnavailable') || 'The catalog of the Android settings cannot be read: edit the section as JSON.'}</p>}
      {loose.length > 0 && (
        <ul className="space-y-0.5 text-sm text-red-400">
          {loose.map((i, n) => <li key={n} className="flex gap-1.5"><AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />{trCode(`mdm.validation.${i.code}`, i.code)} ({i.path})</li>)}
        </ul>
      )}
      {names.length === 0 && apps.length === 0 && <p className="text-sm text-text-muted">{t('android.policy.empty') || 'No Android setting in this version.'}</p>}

      {catalog && byGroup.map(({ g, list }) => (
        <div key={g} className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{trCode(`android.policy.groups.${g}`, g)}</h3>
          {list.map((name) => (
            <FieldCard key={name} name={name} field={fields.get(name)} value={fragment[name]} schemas={catalog.schemas} editable={editable}
              issues={issuesAt(`fragment.${name}`)} onChange={(v) => setField(name, v)} onRemove={() => setField(name, undefined)} />
          ))}
        </div>
      ))}
      {!catalog && !catalogError && names.length > 0 && <p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p>}

      <AppsEditor apps={apps} editable={editable} issues={issues.filter((i) => i.path.startsWith('applications') || i.path.startsWith('fragment.applications'))} onChange={setApps} />

      <AddSettingDialog open={adding} onClose={() => setAdding(false)} catalog={catalog} taken={new Set(names)}
        onAdd={(f) => { setField(f.name, emptyOf(f.node, catalog!.schemas)); setAdding(false); }} />
      <JsonDialog open={jsonOpen} onClose={() => setJsonOpen(false)} section={section} editable={editable} onSave={(s) => { onChange(s); setJsonOpen(false); }} />
    </section>
  );
}

// ── One top-level field ─────────────────────────────────────────────────────────

function FieldCard({ name, field, value, schemas, editable, issues, onChange, onRemove }: {
  name: string; field: AndroidFormField | undefined; value: JsonValue; schemas: Record<string, AndroidFormNode>; editable: boolean;
  issues: PolicyValidationIssue[]; onChange: (v: JsonValue) => void; onRemove: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className={`rounded-lg bg-bg-secondary p-3 space-y-2 ${issues.length ? 'ring-1 ring-red-400/50' : ''}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-text-primary">{fieldLabel(name)}</span>
        <span className="font-mono text-[11px] text-text-muted">{name}</span>
        {!field && <StateBadge tone="red" label={t('android.policy.unknownField') || 'unknown field'} />}
        {field?.deprecated && <StateBadge tone="amber" label={field.replacement ? (t('android.policy.deprecatedFor', { replacement: field.replacement }) || `deprecated: ${field.replacement}`) : (t('android.policy.deprecated') || 'deprecated')} />}
        {field?.wipeCapable && <StateBadge tone="red" label={t('android.policy.wipeCapable') || 'can wipe a device'} title={t('android.policy.wipeCapableHint') || 'Published at the restricted level (a second approver), held while the tenant is frozen.'} />}
        {field?.secretSlots && <StateBadge tone="violet" label={t('android.policy.secretSlots') || 'secrets'} title={t('android.policy.secretHint') || 'A secret is written {"$secretValue": "…"}: moved to the vault at the save.'} />}
        {field?.modes && <span className="text-[11px] text-text-muted">{field.modes.map((m) => trCode(`android.modes.${m}`, m)).join(', ')}</span>}
        {field?.minApi !== undefined && <span className="text-[11px] text-text-muted">{t('android.policy.minApi', { level: field.minApi }) || `API ${field.minApi}+`}</span>}
        {editable && (
          <button type="button" onClick={onRemove} aria-label={t('common.delete') || 'Delete'} title={t('common.delete') || 'Delete'}
            className="ml-auto p-1 rounded text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10"><Trash2 className="w-4 h-4" /></button>
        )}
      </div>
      <ValueEditor node={field?.node} value={value} schemas={schemas} editable={editable} depth={0} onChange={onChange} />
      {issues.length > 0 && (
        <ul className="text-xs text-red-400 space-y-0.5">
          {issues.map((i, n) => <li key={n}>{trCode(`mdm.validation.${i.code}`, i.code)} <span className="font-mono">({i.path.replace(/^fragment\./, '')})</span></li>)}
        </ul>
      )}
    </div>
  );
}

/** The editor of a value: generated for the simple forms, JSON otherwise. */
function ValueEditor({ node, value, schemas, editable, depth, onChange }: {
  node: AndroidFormNode | undefined; value: JsonValue | undefined; schemas: Record<string, AndroidFormNode>; editable: boolean; depth: number;
  onChange: (v: JsonValue) => void;
}) {
  const { t } = useTranslation();
  const n = resolve(node, schemas);
  if (n?.type === 'boolean') {
    return (
      <label className="flex items-center gap-2 text-sm text-text-secondary">
        <input type="checkbox" checked={value === true} disabled={!editable} onChange={(e) => onChange(e.target.checked)} className="accent-accent" />
        {value === true ? (t('android.common.yes') || 'Yes') : (t('android.common.no') || 'No')}
      </label>
    );
  }
  if (n?.type === 'string' && n.enum) {
    return (
      <select value={typeof value === 'string' ? value : ''} disabled={!editable} onChange={(e) => onChange(e.target.value)} className={`${fieldClass} sm:w-auto`}>
        {typeof value !== 'string' && <option value="">—</option>}
        {n.enum.map((v) => (
          <option key={v} value={v} disabled={(n.deprecatedValues ?? []).includes(v) && v !== value}>
            {valueLabel(v)}
          </option>
        ))}
      </select>
    );
  }
  if (n?.type === 'string' && (n.format === undefined || n.format === 'google-duration' || n.format === 'google-datetime' || n.format === 'int64' || n.format === 'uint64')) {
    return (
      <input value={typeof value === 'string' || typeof value === 'number' ? String(value) : ''} disabled={!editable} onChange={(e) => onChange(e.target.value)}
        placeholder={n.format === 'google-duration' ? (t('android.policy.durationPlaceholder') || '3600s') : undefined} className={fieldClass} spellCheck={false} />
    );
  }
  if (n?.type === 'integer' || n?.type === 'number') {
    return (
      <input type="number" value={typeof value === 'number' ? value : ''} disabled={!editable}
        onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))} className={`${fieldClass} sm:w-48`} />
    );
  }
  if (n?.type === 'array') {
    const item = resolve(n.items, schemas);
    const arr = Array.isArray(value) ? value : [];
    if (item?.type === 'string' && item.enum) {
      return (
        <div className="grid gap-1 sm:grid-cols-2">
          {item.enum.filter((v) => !/_UNSPECIFIED$/.test(v)).map((v) => (
            <label key={v} className="flex items-center gap-2 text-xs text-text-secondary">
              <input type="checkbox" checked={arr.includes(v)} disabled={!editable || ((item.deprecatedValues ?? []).includes(v) && !arr.includes(v))} className="accent-accent"
                onChange={(e) => onChange(e.target.checked ? [...arr, v] : arr.filter((x) => x !== v))} />
              {valueLabel(v)}
            </label>
          ))}
        </div>
      );
    }
    if (item?.type === 'string' && !item.format) {
      return (
        <textarea rows={Math.min(8, Math.max(2, arr.length + 1))} value={arr.filter((x) => typeof x === 'string').join('\n')} disabled={!editable}
          onChange={(e) => onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))} className={`${fieldClass} font-mono text-xs`}
          placeholder={t('android.policy.onePerLine') || 'one value per line'} spellCheck={false} />
      );
    }
  }
  if (n?.type === 'object' && n.properties && depth < MAX_FORM_DEPTH && !n.additionalProperties) {
    const obj = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, JsonValue> : {};
    return (
      <div className="space-y-2 border-l border-border pl-3">
        {Object.entries(n.properties).sort(([a], [b]) => a.localeCompare(b)).map(([k, child]) => {
          const isSet = Object.prototype.hasOwnProperty.call(obj, k);
          return (
            <div key={k} className="space-y-1">
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={isSet} disabled={!editable || (child.deprecated === true && !isSet)} className="accent-accent"
                  onChange={(e) => {
                    const next = { ...obj };
                    if (e.target.checked) next[k] = emptyOf(child, schemas); else delete next[k];
                    onChange(next);
                  }} />
                <span className="text-text-primary">{fieldLabel(k)}</span>
                <span className="font-mono text-[10px] text-text-muted">{k}</span>
                {child.deprecated && <span className="text-[10px] text-amber-400">{t('android.policy.deprecated') || 'deprecated'}</span>}
              </label>
              {isSet && <ValueEditor node={child} value={obj[k]} schemas={schemas} editable={editable} depth={depth + 1} onChange={(v) => onChange({ ...obj, [k]: v })} />}
            </div>
          );
        })}
      </div>
    );
  }
  return <JsonValueEditor value={value ?? null} editable={editable} onChange={onChange} />;
}

/** A value edited as JSON: applied when it parses, the error shown otherwise. */
function JsonValueEditor({ value, editable, onChange }: { value: JsonValue; editable: boolean; onChange: (v: JsonValue) => void }) {
  const { t } = useTranslation();
  const [text, setText] = useState(pretty(value));
  const [error, setError] = useState(false);
  // The text typed is kept while it parses to the value received (no reformatting under the cursor).
  const emitted = useRef(JSON.stringify(value));
  useEffect(() => {
    const now = JSON.stringify(value);
    if (now !== emitted.current) { emitted.current = now; setText(pretty(value)); setError(false); }
  }, [value]);
  return (
    <div>
      <textarea value={text} readOnly={!editable} rows={Math.min(14, Math.max(3, text.split('\n').length))} spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          try { const v = JSON.parse(e.target.value) as JsonValue; emitted.current = JSON.stringify(v); setError(false); onChange(v); } catch { setError(true); }
        }}
        className={`${fieldClass} font-mono text-xs ${error ? 'ring-1 ring-red-400/60' : ''}`} />
      {error && <p className="text-[11px] text-red-400">{t('android.policy.invalidJson') || 'Not valid JSON: the last valid value is kept.'}</p>}
    </div>
  );
}

// ── Apps of the policy ──────────────────────────────────────────────────────────

function AppsEditor({ apps, editable, issues, onChange }: { apps: AndroidAppEntry[]; editable: boolean; issues: PolicyValidationIssue[]; onChange: (a: AndroidAppEntry[]) => void }) {
  const { t } = useTranslation();
  const [pkg, setPkg] = useState('');
  const update = (i: number, entry: AndroidAppEntry) => onChange(apps.map((a, n) => (n === i ? entry : a)));
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">{t('android.policy.apps') || 'Apps of the policy'}</h3>
      <p className="text-[11px] text-text-muted">{t('android.policy.appsHint') || 'The apps assigned from the catalog are added by the assignments; the entries here belong to this policy (its install type, its permissions, its managed configuration).'}</p>
      {apps.map((a, i) => {
        const { packageName, installType, ...rest } = a;
        const mine = issues.filter((x) => x.path.includes(`[${packageName}]`) || x.path.includes(`[${i}]`));
        return (
          <div key={`${packageName}:${i}`} className={`rounded-lg bg-bg-secondary p-3 space-y-2 ${mine.length ? 'ring-1 ring-red-400/50' : ''}`}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-text-primary">{packageName}</span>
              <select value={typeof installType === 'string' ? installType : ''} disabled={!editable} className={`${fieldClass} sm:w-auto`}
                onChange={(e) => update(i, { ...a, installType: e.target.value })}>
                <option value="">—</option>
                {ANDROID_INSTALL_TYPES.map((x) => <option key={x} value={x}>{trCode(`android.policy.installTypes.${x}`, x)}</option>)}
              </select>
              {editable && (
                <button type="button" onClick={() => onChange(apps.filter((_, n) => n !== i))} aria-label={t('common.delete') || 'Delete'}
                  className="ml-auto p-1 rounded text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10"><Trash2 className="w-4 h-4" /></button>
              )}
            </div>
            <JsonValueEditor value={rest as JsonValue} editable={editable}
              onChange={(v) => { if (v && typeof v === 'object' && !Array.isArray(v)) update(i, { packageName, ...(installType !== undefined ? { installType } : {}), ...(v as Record<string, JsonValue>) }); }} />
            {mine.length > 0 && <ul className="text-xs text-red-400">{mine.map((x, n) => <li key={n}>{trCode(`mdm.validation.${x.code}`, x.code)} ({x.path})</li>)}</ul>}
          </div>
        );
      })}
      {editable && (
        <div className="flex flex-wrap gap-2">
          <input value={pkg} onChange={(e) => setPkg(e.target.value)} maxLength={255} placeholder={t('android.policy.packagePlaceholder') || 'com.example.app'}
            className={`${fieldClass} font-mono sm:w-80`} spellCheck={false} />
          <Button size="sm" variant="secondary" disabled={!pkg.trim() || apps.some((a) => a.packageName === pkg.trim())}
            onClick={() => { onChange([...apps, { packageName: pkg.trim(), installType: 'AVAILABLE' }]); setPkg(''); }}>
            <Plus className="w-3.5 h-3.5 mr-1" />{t('android.policy.addApp') || 'Add an app'}
          </Button>
        </div>
      )}
    </div>
  );
}

// ── Dialogs ─────────────────────────────────────────────────────────────────────

function AddSettingDialog({ open, onClose, catalog, taken, onAdd }: {
  open: boolean; onClose: () => void; catalog: AndroidFormCatalogView | null; taken: Set<string>; onAdd: (f: AndroidFormField) => void;
}) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  useEffect(() => { if (open) setQ(''); }, [open]);
  const query = q.trim().toLowerCase();
  const list = (catalog?.fields ?? []).filter((f) => !taken.has(f.name) && !f.deprecated
    && (!query || f.name.toLowerCase().includes(query) || fieldLabel(f.name).toLowerCase().includes(query)));
  return (
    <Modal open={open} onClose={onClose} size="lg" title={t('android.policy.addSetting') || 'Add a setting'}>
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('android.policy.search') || 'Search'} className={`${fieldClass} mb-3`} autoFocus />
      <div className="max-h-[60vh] space-y-3 overflow-y-auto">
        {ANDROID_FORM_GROUPS.map((g) => {
          const items = list.filter((f) => f.group === g);
          if (!items.length) return null;
          return (
            <div key={g}>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">{trCode(`android.policy.groups.${g}`, g)}</h3>
              <ul className="divide-y divide-border/50 rounded-lg bg-bg-secondary">
                {items.map((f) => (
                  <li key={f.name}>
                    <button type="button" onClick={() => onAdd(f)} className="flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left text-sm hover:bg-bg-tertiary coarse:min-h-10">
                      <span className="text-text-primary">{fieldLabel(f.name)}</span>
                      <span className="font-mono text-[11px] text-text-muted">{f.name}</span>
                      {f.wipeCapable && <StateBadge tone="red" label={t('android.policy.wipeCapable') || 'can wipe a device'} />}
                      {f.modes && <span className="ml-auto text-[11px] text-text-muted">{f.modes.map((m) => trCode(`android.modes.${m}`, m)).join(', ')}</span>}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </Modal>
  );
}

function JsonDialog({ open, onClose, section, editable, onSave }: {
  open: boolean; onClose: () => void; section: Section | undefined; editable: boolean; onSave: (s: Section | undefined) => void;
}) {
  const { t } = useTranslation();
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (open) { setText(pretty(section ?? { fragment: {} })); setError(null); } }, [open, section]);
  const save = () => {
    try {
      const v = JSON.parse(text) as Section;
      if (!v || typeof v !== 'object' || Array.isArray(v) || !v.fragment || typeof v.fragment !== 'object' || Array.isArray(v.fragment)) {
        throw new Error(t('android.policy.jsonShape') || 'The section is { "fragment": { … }, "applications": [ … ] }');
      }
      onSave(Object.keys(v.fragment).length === 0 && !(v.applications?.length) ? undefined : v);
    } catch (err) { setError((err as Error).message); }
  };
  return (
    <Modal open={open} onClose={onClose} size="2xl" title={t('android.policy.jsonTitle') || 'Android section as JSON'}
      footer={editable ? (
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save}>{t('android.policy.applyJson') || 'Apply'}</Button>
        </>
      ) : <Button onClick={onClose}>{t('common.close') || 'Close'}</Button>}>
      <textarea value={text} readOnly={!editable} onChange={(e) => setText(e.target.value)} rows={24} spellCheck={false} className={`${fieldClass} font-mono text-xs`} />
      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
    </Modal>
  );
}
