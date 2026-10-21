import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Trash2 } from 'lucide-react';
import {
  ANDROID_AUTO_UPDATE_MODES, ANDROID_INSTALL_TYPES, ANDROID_PERMISSION_POLICIES, isSecretRef,
  type AndroidAppDetail, type AndroidManagedPropertyView, type JsonValue,
} from '@obligarth/shared';
import { trCode } from '@/utils/apiError';
import { fieldClass } from './ui';

// The options of an assignment of an Android app (android-amapi §4.6, §9.6; lot AN-E), edited in the assignment
// dialog: install type, updates, minimum version, priority and constraint of the installation, permissions, tracks,
// and the managed configuration: a form generated from the app's schema (managedProperties), or the configuration
// saved in the managed configurations iframe (its id, managedConfigurationTemplate). A HIDDEN property, and a text
// property the administrator marks as secret, take a secret ({"$secretValue"}): the server moves it to the tenant's
// vault before anything stores the assignment; a secret already stored stays a reference ({"$secret"}) the console
// never reads. The server checks everything again (apps/appPolicy.ts).

const CONSTRAINTS = {
  networkTypeConstraint: ['INSTALL_ON_ANY_NETWORK', 'INSTALL_ONLY_ON_UNMETERED_NETWORK'],
  chargingConstraint: ['CHARGING_NOT_REQUIRED', 'INSTALL_ONLY_WHEN_CHARGING'],
  deviceIdleConstraint: ['DEVICE_IDLE_NOT_REQUIRED', 'INSTALL_ONLY_WHEN_DEVICE_IDLE'],
} as const;
type ConstraintKey = keyof typeof CONSTRAINTS;
const PRIORITY_TYPES = new Set(['FORCE_INSTALLED', 'PREINSTALLED']);
const PERMISSION_RE = /^[A-Za-z][A-Za-z0-9_.]{0,254}$/;
const TEMPLATE_RE = /^[0-9]{1,20}$/;

type Obj = Record<string, JsonValue>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);

export interface AndroidOptionsDraft {
  installType: string;
  autoUpdateMode: string;
  minimumVersionCode: string;
  installPriority: string;
  constraint: Record<ConstraintKey, string>;
  defaultPermissionPolicy: string;
  grants: Array<{ permission: string; policy: string }>;
  tracks: string[];
  configMode: 'none' | 'form' | 'template';
  config: Obj;
  templateId: string;
}

/** The draft of existing options (an assignment being edited, or a configuration chosen in the iframe). */
export function draftOf(options: Record<string, JsonValue> | null | undefined): AndroidOptionsDraft {
  const o = options ?? {};
  const c = Array.isArray(o.installConstraint) && isObj(o.installConstraint[0]) ? o.installConstraint[0] : {};
  const tpl = isObj(o.managedConfigurationTemplate) ? o.managedConfigurationTemplate : null;
  return {
    installType: typeof o.installType === 'string' ? o.installType : '',
    autoUpdateMode: typeof o.autoUpdateMode === 'string' ? o.autoUpdateMode : '',
    minimumVersionCode: typeof o.minimumVersionCode === 'number' ? String(o.minimumVersionCode) : '',
    installPriority: typeof o.installPriority === 'number' ? String(o.installPriority) : '',
    constraint: {
      networkTypeConstraint: typeof c.networkTypeConstraint === 'string' ? c.networkTypeConstraint : '',
      chargingConstraint: typeof c.chargingConstraint === 'string' ? c.chargingConstraint : '',
      deviceIdleConstraint: typeof c.deviceIdleConstraint === 'string' ? c.deviceIdleConstraint : '',
    },
    defaultPermissionPolicy: typeof o.defaultPermissionPolicy === 'string' ? o.defaultPermissionPolicy : '',
    grants: Array.isArray(o.permissionGrants)
      ? o.permissionGrants.filter(isObj).map((g) => ({ permission: String(g.permission ?? ''), policy: String(g.policy ?? 'GRANT') })) : [],
    tracks: Array.isArray(o.accessibleTrackIds) ? o.accessibleTrackIds.filter((x): x is string => typeof x === 'string') : [],
    configMode: tpl ? 'template' : isObj(o.managedConfiguration) ? 'form' : 'none',
    config: isObj(o.managedConfiguration) ? o.managedConfiguration : {},
    templateId: tpl && typeof tpl.templateId === 'string' ? tpl.templateId : '',
  };
}

/** A configuration value worth sending (an empty bundle or list, an empty text, is left out). */
function pruned(v: JsonValue | undefined): JsonValue | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  if (Array.isArray(v)) {
    const items = v.map(pruned).filter((x): x is JsonValue => x !== undefined);
    return items.length ? items : undefined;
  }
  if (isObj(v)) {
    if (isSecretRef(v)) return v;
    if (Object.keys(v).length === 1 && typeof v.$secretValue === 'string') return v.$secretValue ? v : undefined;
    const out: Obj = {};
    for (const [k, x] of Object.entries(v)) { const p = pruned(x); if (p !== undefined) out[k] = p; }
    return Object.keys(out).length ? out : undefined;
  }
  return v;
}

/** The options of the draft, or the list of the fields to correct (keys of androidApps.options.errors). */
export function optionsOf(d: AndroidOptionsDraft, app: Pick<AndroidAppDetail, 'kind'>): { options: Record<string, JsonValue>; errors: string[] } {
  const options: Record<string, JsonValue> = {};
  const errors: string[] = [];
  if (d.installType) options.installType = d.installType;
  if (d.autoUpdateMode) options.autoUpdateMode = d.autoUpdateMode;
  if (d.minimumVersionCode.trim()) {
    const n = Number(d.minimumVersionCode);
    if (Number.isInteger(n) && n >= 1 && n <= 2 ** 31 - 1) options.minimumVersionCode = n; else errors.push('minimumVersionCode');
  }
  if (d.installPriority.trim()) {
    const n = Number(d.installPriority);
    if (!PRIORITY_TYPES.has(d.installType)) errors.push('installPriorityType');
    else if (Number.isInteger(n) && n >= 0 && n <= 10_000) options.installPriority = n; else errors.push('installPriority');
  }
  const constraint: Obj = {};
  for (const k of Object.keys(CONSTRAINTS) as ConstraintKey[]) if (d.constraint[k]) constraint[k] = d.constraint[k];
  if (Object.keys(constraint).length) options.installConstraint = [constraint];
  if (d.defaultPermissionPolicy) options.defaultPermissionPolicy = d.defaultPermissionPolicy;
  const grants = d.grants.filter((g) => g.permission.trim());
  if (grants.length) {
    const seen = new Set<string>();
    for (const g of grants) {
      if (!PERMISSION_RE.test(g.permission.trim()) || seen.has(g.permission.trim())) errors.push('permission');
      seen.add(g.permission.trim());
    }
    options.permissionGrants = grants.map((g) => ({ permission: g.permission.trim(), policy: g.policy }));
  }
  if (d.tracks.length) options.accessibleTrackIds = [...d.tracks];
  if (app.kind !== 'web') {
    if (d.configMode === 'template') {
      if (TEMPLATE_RE.test(d.templateId.trim())) options.managedConfigurationTemplate = { templateId: d.templateId.trim() };
      else errors.push('templateId');
    } else if (d.configMode === 'form') {
      const c = pruned(d.config);
      if (c !== undefined) options.managedConfiguration = c;
    }
  }
  return { options, errors: [...new Set(errors)] };
}

function Select({ label, value, values, prefix, onChange, empty }: {
  label: string; value: string; values: readonly string[]; prefix: string; onChange: (v: string) => void; empty: string;
}) {
  return (
    <label className="block text-sm">
      <span className="text-xs text-text-muted">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className={`mt-1 ${fieldClass}`}>
        <option value="">{empty}</option>
        {values.map((v) => <option key={v} value={v}>{trCode(`${prefix}.${v}`, v)}</option>)}
      </select>
    </label>
  );
}

export function AndroidAppOptionsFields({ app, value, onChange }: {
  app: AndroidAppDetail; value: AndroidOptionsDraft; onChange: (v: AndroidOptionsDraft) => void;
}) {
  const { t } = useTranslation();
  const set = (patch: Partial<AndroidOptionsDraft>) => onChange({ ...value, ...patch });
  const byDefault = t('androidApps.options.default') || 'Default';
  const canForm = app.managedConfiguration === 'json' && !!app.managedProperties?.length;
  const canTemplate = app.kind !== 'web';
  return (
    <div className="space-y-3 rounded border border-border p-2 text-sm">
      <p className="text-xs font-semibold text-text-secondary">{t('androidApps.options.title') || 'Options of the Android app'}</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <Select label={t('androidApps.options.installType') || 'Installation'} value={value.installType} values={ANDROID_INSTALL_TYPES}
          prefix="androidApps.installTypes" empty={t('androidApps.options.installTypeDefault') || 'Available (default)'} onChange={(v) => set({ installType: v })} />
        <Select label={t('androidApps.options.autoUpdateMode') || 'Updates'} value={value.autoUpdateMode} values={ANDROID_AUTO_UPDATE_MODES}
          prefix="androidApps.autoUpdateModes" empty={byDefault} onChange={(v) => set({ autoUpdateMode: v })} />
        <label className="block text-sm">
          <span className="text-xs text-text-muted">{t('androidApps.options.minimumVersionCode') || 'Minimum version code'}</span>
          <input type="number" min={1} value={value.minimumVersionCode} onChange={(e) => set({ minimumVersionCode: e.target.value })} className={`mt-1 ${fieldClass}`} />
        </label>
        {PRIORITY_TYPES.has(value.installType) && (
          <label className="block text-sm">
            <span className="text-xs text-text-muted">{t('androidApps.options.installPriority') || 'Install priority (0 to 10,000, lower first)'}</span>
            <input type="number" min={0} max={10000} value={value.installPriority} onChange={(e) => set({ installPriority: e.target.value })} className={`mt-1 ${fieldClass}`} />
          </label>
        )}
      </div>
      <fieldset className="space-y-2">
        <legend className="text-xs text-text-muted">{t('androidApps.options.constraint') || 'Installation constraint'}</legend>
        <div className="grid gap-2 sm:grid-cols-3">
          {(Object.keys(CONSTRAINTS) as ConstraintKey[]).map((k) => (
            <Select key={k} label={t(`androidApps.constraints.${k}`) || k} value={value.constraint[k]} values={CONSTRAINTS[k]} prefix="androidApps.constraintValues"
              empty={byDefault} onChange={(v) => set({ constraint: { ...value.constraint, [k]: v } })} />
          ))}
        </div>
      </fieldset>
      <fieldset className="space-y-2">
        <legend className="text-xs text-text-muted">{t('androidApps.options.permissions') || 'Runtime permissions'}</legend>
        <Select label={t('androidApps.options.defaultPermissionPolicy') || 'Default policy'} value={value.defaultPermissionPolicy} values={ANDROID_PERMISSION_POLICIES}
          prefix="androidApps.permissionPolicies" empty={byDefault} onChange={(v) => set({ defaultPermissionPolicy: v })} />
        {value.grants.map((g, i) => (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <input list={`perm-${app.uuid}`} value={g.permission} placeholder="android.permission.CAMERA" spellCheck={false} autoCapitalize="off"
              aria-label={t('androidApps.options.permission') || 'Permission'}
              onChange={(e) => set({ grants: value.grants.map((x, j) => (j === i ? { ...x, permission: e.target.value } : x)) })}
              className={`${fieldClass} flex-1 min-w-[12rem] font-mono text-xs`} />
            <select value={g.policy} aria-label={t('androidApps.options.permissionPolicy') || 'Policy of the permission'}
              onChange={(e) => set({ grants: value.grants.map((x, j) => (j === i ? { ...x, policy: e.target.value } : x)) })} className={`${fieldClass} w-auto`}>
              {ANDROID_PERMISSION_POLICIES.map((p) => <option key={p} value={p}>{trCode(`androidApps.permissionPolicies.${p}`, p)}</option>)}
            </select>
            <button type="button" onClick={() => set({ grants: value.grants.filter((_, j) => j !== i) })} aria-label={t('androidApps.options.removePermission') || 'Remove'}
              className="p-1 text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10"><Trash2 className="w-3.5 h-3.5" /></button>
            {/* Review AN-E: the server's warning permission_not_declared (not refused), shown while it is typed. */}
            {app.permissions.length > 0 && g.permission.trim() !== '' && !app.permissions.includes(g.permission.trim()) && (
              <p className="basis-full text-[11px] text-amber-400">{t('androidApps.options.permissionNotDeclared') || 'The app does not declare this permission: the policy has no effect on it.'}</p>
            )}
          </div>
        ))}
        <datalist id={`perm-${app.uuid}`}>{app.permissions.map((p) => <option key={p} value={p} />)}</datalist>
        <button type="button" onClick={() => set({ grants: [...value.grants, { permission: '', policy: 'GRANT' }] })}
          className="inline-flex items-center gap-1 text-xs text-accent hover:underline coarse:min-h-10"><Plus className="w-3.5 h-3.5" />{t('androidApps.options.addPermission') || 'Add a permission'}</button>
      </fieldset>
      {app.tracks.length > 0 && (
        <fieldset className="space-y-1">
          <legend className="text-xs text-text-muted">{t('androidApps.options.tracks') || 'Test tracks the devices may receive'}</legend>
          {app.tracks.map((tr) => (
            <label key={tr.trackId} className="flex items-center gap-2">
              <input type="checkbox" checked={value.tracks.includes(tr.trackId)}
                onChange={(e) => set({ tracks: e.target.checked ? [...value.tracks, tr.trackId] : value.tracks.filter((x) => x !== tr.trackId) })} />
              <span>{tr.trackAlias || tr.trackId}</span>
            </label>
          ))}
        </fieldset>
      )}
      {canTemplate && (
        <fieldset className="space-y-2">
          <legend className="text-xs text-text-muted">{t('androidApps.options.managedConfiguration') || 'Managed configuration'}</legend>
          <div className="flex flex-wrap gap-3">
            {(['none', ...(canForm ? ['form'] : []), 'template'] as Array<AndroidOptionsDraft['configMode']>).map((m) => (
              <label key={m} className="flex items-center gap-1.5">
                <input type="radio" name={`cfg-${app.uuid}`} checked={value.configMode === m} onChange={() => set({ configMode: m })} />
                {t(`androidApps.options.configModes.${m}`) || m}
              </label>
            ))}
          </div>
          {app.oemConfig && <p className="text-[11px] text-text-muted">{t('androidApps.options.oemConfigHint') || 'An OEMConfig app is configured in the managed configurations iframe only.'}</p>}
          {value.configMode === 'form' && canForm && (
            <PropertiesForm props={app.managedProperties ?? []} value={value.config} onChange={(config) => set({ config })} depth={0} />
          )}
          {value.configMode === 'template' && (
            <label className="block text-sm">
              <span className="text-xs text-text-muted">{t('androidApps.options.templateId') || 'Id of the configuration saved in the iframe'}</span>
              <input value={value.templateId} inputMode="numeric" onChange={(e) => set({ templateId: e.target.value.trim() })} className={`mt-1 ${fieldClass} font-mono`} />
              <span className="mt-0.5 block text-[11px] text-text-muted">{t('androidApps.options.templateHint') || 'Saved from the page « Managed configuration » of the app.'}</span>
            </label>
          )}
        </fieldset>
      )}
    </div>
  );
}

/** The fields of a bundle of managed properties (the app's schema; titles are Google's text, rendered as text). */
function PropertiesForm({ props, value, onChange, depth }: { props: AndroidManagedPropertyView[]; value: Obj; onChange: (v: Obj) => void; depth: number }) {
  const put = (key: string, v: JsonValue | undefined) => {
    const next = { ...value };
    if (v === undefined) delete next[key]; else next[key] = v;
    onChange(next);
  };
  return (
    <div className={`space-y-2 ${depth > 0 ? 'border-l border-border pl-3' : ''}`}>
      {props.map((p) => <PropertyField key={p.key} prop={p} value={value[p.key]} onChange={(v) => put(p.key, v)} depth={depth} />)}
    </div>
  );
}

function SecretInput({ value, onChange, label }: { value: JsonValue | undefined; onChange: (v: JsonValue | undefined) => void; label: string }) {
  const { t } = useTranslation();
  // Review AN-E: the stored secret being replaced is kept aside, so that « Keep » restores it (left empty, the
  // replacement would otherwise remove it from the configuration without a word). An emptied field stays a secret
  // field ({"$secretValue": ""}, left out of the options by pruned): it never falls back to a text field in clear.
  const [stored, setStored] = useState<JsonValue | null>(null);
  if (isSecretRef(value)) {
    return (
      <div className="flex items-center gap-2 text-xs">
        <span className="text-text-secondary">{t('androidApps.options.secretStored') || 'Secret stored in the vault'}</span>
        <button type="button" className="text-accent hover:underline coarse:min-h-10" onClick={() => { setStored(value); onChange({ $secretValue: '' }); }}>{t('androidApps.options.secretReplace') || 'Replace'}</button>
      </div>
    );
  }
  const typed = isObj(value) && typeof value.$secretValue === 'string' ? value.$secretValue : '';
  return (
    <div className="flex items-center gap-2">
      <input type="password" autoComplete="new-password" aria-label={label} value={typed}
        onChange={(e) => onChange({ $secretValue: e.target.value })} className={fieldClass} />
      {stored && (
        <button type="button" className="shrink-0 text-xs text-accent hover:underline coarse:min-h-10" onClick={() => { onChange(stored); setStored(null); }}>
          {t('androidApps.options.secretKeep') || 'Keep the stored secret'}
        </button>
      )}
    </div>
  );
}

function PropertyField({ prop, value, onChange, depth }: { prop: AndroidManagedPropertyView; value: JsonValue | undefined; onChange: (v: JsonValue | undefined) => void; depth: number }) {
  const { t } = useTranslation();
  const label = prop.title || prop.key;
  const head = (
    <span className="flex items-baseline gap-2 text-xs">
      <span className="text-text-primary">{label}</span>
      <span className="font-mono text-[10px] text-text-muted">{prop.key}</span>
    </span>
  );
  const unset = t('androidApps.options.unset') || 'Not set';
  switch (prop.type) {
    case 'BOOL':
      return (
        <label className="block">{head}
          <select value={value === true ? 'true' : value === false ? 'false' : ''} onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value === 'true')} className={`mt-1 ${fieldClass}`}>
            <option value="">{unset}</option>
            <option value="true">{t('androidApps.options.yes') || 'Yes'}</option>
            <option value="false">{t('androidApps.options.no') || 'No'}</option>
          </select>
        </label>
      );
    case 'INTEGER':
      return (
        <label className="block">{head}
          <input type="number" step={1} value={typeof value === 'number' ? String(value) : ''}
            onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))} className={`mt-1 ${fieldClass}`} />
        </label>
      );
    case 'HIDDEN':
      return (
        <div className="block">{head}
          <div className="mt-1"><SecretInput value={value} onChange={onChange} label={label} /></div>
          <span className="block text-[11px] text-text-muted">{t('androidApps.options.hiddenHint') || 'Hidden property: kept in the vault, never shown again.'}</span>
        </div>
      );
    case 'STRING': {
      const secret = isObj(value) && (isSecretRef(value) || typeof value.$secretValue === 'string');
      return (
        <div className="block">{head}
          <div className="mt-1">
            {secret ? <SecretInput value={value} onChange={onChange} label={label} />
              : <input value={typeof value === 'string' ? value : ''} onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)} className={fieldClass} aria-label={label} />}
          </div>
          <label className="mt-0.5 flex items-center gap-1.5 text-[11px] text-text-muted">
            <input type="checkbox" checked={secret} onChange={(e) => onChange(e.target.checked ? { $secretValue: typeof value === 'string' ? value : '' } : undefined)} />
            {t('androidApps.options.asSecret') || 'Secret (kept in the vault)'}
          </label>
        </div>
      );
    }
    case 'CHOICE':
      return (
        <label className="block">{head}
          <select value={typeof value === 'string' ? value : ''} onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)} className={`mt-1 ${fieldClass}`}>
            <option value="">{unset}</option>
            {(prop.entries ?? []).map((en) => <option key={en.value} value={en.value}>{en.name}</option>)}
          </select>
        </label>
      );
    case 'MULTISELECT': {
      const chosen = Array.isArray(value) ? value.filter((x): x is string => typeof x === 'string') : [];
      return (
        <fieldset className="block">{head}
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
            {(prop.entries ?? []).map((en) => (
              <label key={en.value} className="flex items-center gap-1.5 text-xs">
                <input type="checkbox" checked={chosen.includes(en.value)}
                  onChange={(e) => { const next = e.target.checked ? [...chosen, en.value] : chosen.filter((x) => x !== en.value); onChange(next.length ? next : undefined); }} />
                {en.name}
              </label>
            ))}
          </div>
        </fieldset>
      );
    }
    case 'BUNDLE':
      return (
        <fieldset className="block">{head}
          <div className="mt-1"><PropertiesForm props={prop.nested ?? []} value={isObj(value) ? value : {}} depth={depth + 1}
            onChange={(v) => onChange(Object.keys(v).length ? v : undefined)} /></div>
        </fieldset>
      );
    case 'BUNDLE_ARRAY': {
      const nested = prop.nested ?? [];
      const shape = nested.length === 1 && nested[0].type === 'BUNDLE' ? nested[0].nested ?? [] : nested;
      const items = Array.isArray(value) ? value.map((x) => (isObj(x) ? x : {})) : [];
      const put = (next: Obj[]) => onChange(next.length ? next : undefined);
      return (
        <fieldset className="block">{head}
          <div className="mt-1 space-y-2">
            {items.map((item, i) => (
              <div key={i} className="rounded border border-border/60 p-2">
                <div className="flex justify-end">
                  <button type="button" onClick={() => put(items.filter((_, j) => j !== i))} aria-label={t('androidApps.options.removeItem') || 'Remove the item'}
                    className="p-1 text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10"><Trash2 className="w-3.5 h-3.5" /></button>
                </div>
                <PropertiesForm props={shape} value={item} depth={depth + 1} onChange={(v) => put(items.map((x, j) => (j === i ? v : x)))} />
              </div>
            ))}
            <button type="button" onClick={() => put([...items, {}])} className="inline-flex items-center gap-1 text-xs text-accent hover:underline coarse:min-h-10">
              <Plus className="w-3.5 h-3.5" />{t('androidApps.options.addItem') || 'Add an item'}
            </button>
          </div>
        </fieldset>
      );
    }
    default:
      return null;
  }
}

/** The issues of the server's check, each one translated (androidApps.issues.<code>) with the path it names. */
export function AndroidOptionIssues({ issues }: { issues: Array<{ path: string; code: string }> }) {
  if (!issues.length) return null;
  return (
    <ul className="list-disc pl-5 text-xs text-red-400">
      {issues.slice(0, 20).map((i, n) => (
        <li key={n}>{trCode(`androidApps.issues.${i.code}`, i.code)}{i.path ? <span className="ml-1 font-mono text-text-muted">{i.path}</span> : null}</li>
      ))}
    </ul>
  );
}
