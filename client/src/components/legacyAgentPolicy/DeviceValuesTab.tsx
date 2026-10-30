import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { FolderOpen, Search, SortAsc, SortDesc } from 'lucide-react';
import type { DeviceValuesParseResult, LegacyAgentDeviceValuesImportResult, LegacyAgentDeviceValuesPreviewRow as PreviewRow, LegacyAgentDeviceView } from '@obligarth/shared';
import { LEGACY_AGENT_DEVICE_VALUES_LIMITS, decodeText, deviceCodePattern, mapDeviceValueKeys, parseCsvValues, parseFolderTree, parseJsonValues } from '@obligarth/shared';
import { legacyAgentApi, type DeviceValuesMatch } from '@/api/legacyAgent.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';
import { useAuthStore } from '@/store/authStore';
import { apiErrorMessage, trCode } from '@/utils/apiError';
import { ChipChoice, Field, fieldCls } from './ui';

// The per-device values of the agent policies (lot PONT-POL §11.2, §12.1): the import wizard — a folder tree (one folder
// per device name holding a JSON file, the MobiControl file-sync export among others), a CSV or a JSON document, read in
// this browser; the keys renamed or left out; the matching by device name, or by a code taken from the name; a preview
// by the server (what changes, the devices a dynamic group would move, the policy impact), then the import — a request
// for approval beyond the publication thresholds — and the current values of each device. The values are customer data:
// they are sent to the server only, never logged.

type Source = 'folder' | 'csv' | 'json';

export function DeviceValuesTab() {
  const { t } = useTranslation();
  const canImport = useAuthStore((s) => s.isAdmin() || ((s.permissions?.tenantCapabilities ?? []).includes('devices.manage')
    && (s.permissions?.tenantCapabilities ?? []).includes('mdm.policies.manage')));
  const [source, setSource] = useState<Source>('folder');
  const [glob, setGlob] = useState('*.json');
  const [parsed, setParsed] = useState<DeviceValuesParseResult | null>(null);
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [prefix, setPrefix] = useState('');
  const [byName, setByName] = useState(true);
  const [byCode, setByCode] = useState(false);
  const [nameRegex, setNameRegex] = useState('^C01(\\d{5})');
  const [codeField, setCodeField] = useState('');
  const [pad, setPad] = useState('5');
  const [preview, setPreview] = useState<LegacyAgentDeviceValuesImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [devices, setDevices] = useState<LegacyAgentDeviceView[] | null>(null);
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 }>({ key: '', dir: 1 });
  const loadDevices = () => { legacyAgentApi.devices({}).then(setDevices).catch(() => setDevices([])); };
  useEffect(loadDevices, []);

  const keys = useMemo(() => [...new Set((parsed?.rows ?? []).flatMap((r) => Object.keys(r.values)))].sort(), [parsed]);
  const rows = useMemo(() => (parsed ? mapDeviceValueKeys(parsed.rows, mapping, prefix) : []), [parsed, mapping, prefix]);
  const mappedKeys = useMemo(() => [...new Set(rows.flatMap((r) => Object.keys(r.values)))].sort(), [rows]);
  const match: DeviceValuesMatch = { byName, ...(byCode && codeField ? { byCode: { nameRegex, field: codeField, pad: Math.max(1, Math.min(12, Number(pad) || 1)) } } : {}) };

  const read = async (list: FileList | null) => {
    if (!list || !list.length) return;
    setPreview(null); setMapping({});
    try {
      if (source === 'folder') {
        const files: Array<{ relPath: string; bytes: Uint8Array }> = [];
        for (const f of Array.from(list)) {
          if (f.size > 64 * 1024) { files.push({ relPath: (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name, bytes: new Uint8Array(64 * 1024 + 1) }); continue; }
          files.push({ relPath: (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
          if (files.length > 20_000) break;
        }
        setParsed(parseFolderTree(files, { glob }));
      } else {
        const f = list[0];
        const { text } = decodeText(new Uint8Array(await f.arrayBuffer()));
        setParsed(source === 'csv' ? parseCsvValues(text) : parseJsonValues(text));
      }
    } catch (err) { toast.error(apiErrorMessage(err)); }
  };

  /** Sends the rows in batches of 500; the results are added up. */
  const run = async (apply: boolean) => {
    if (!rows.length) return;
    setBusy(true);
    try {
      const total: LegacyAgentDeviceValuesImportResult = { applied: apply, rows: [], updated: 0, unchanged: 0, skipped: { unmatched: 0, conflict: 0, governed: 0, outOfScope: 0 }, policyImpact: 0 };
      const batch = LEGACY_AGENT_DEVICE_VALUES_LIMITS.batch;
      const payload = rows.slice(0, LEGACY_AGENT_DEVICE_VALUES_LIMITS.rows).map((r) => ({ deviceKey: r.deviceKey, values: r.values, source: r.source.slice(0, 300) }));
      for (let i = 0; i < payload.length; i += batch) {
        const r = await legacyAgentApi.importDeviceValues(payload.slice(i, i + batch), match, apply);
        if ('approvalId' in r) { toast.success(t('legacyAgentPolicy.values.approval') || 'Beyond the thresholds: a request for approval was filed.'); setBusy(false); return; }
        total.rows.push(...r.rows.map((x) => ({ ...x, index: x.index + i })));
        total.updated += r.updated; total.unchanged += r.unchanged; total.policyImpact += r.policyImpact;
        for (const k of Object.keys(total.skipped) as Array<keyof typeof total.skipped>) total.skipped[k] += r.skipped[k];
      }
      setPreview(total);
      if (apply) { toast.success(t('legacyAgentPolicy.values.applied', { count: total.updated }) || `${total.updated} device(s) updated`); loadDevices(); }
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
    } finally {
      setBusy(false);
    }
  };

  const columns = useMemo(() => [...new Set((devices ?? []).flatMap((d) => Object.keys(d.customFields ?? {})))].sort().slice(0, 8), [devices]);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    const list = (devices ?? []).filter((d) => !s || (d.name ?? '').toLowerCase().includes(s) || Object.values(d.customFields ?? {}).some((v) => v.toLowerCase().includes(s)));
    const v = (d: LegacyAgentDeviceView) => (sort.key ? d.customFields?.[sort.key] ?? '' : d.name ?? '');
    return list.sort((a, b) => v(a).localeCompare(v(b), undefined, { numeric: true }) * sort.dir);
  }, [devices, q, sort]);
  const th = (label: string, key: string) => (
    <th key={key || 'name'} className="whitespace-nowrap px-4 py-2 font-medium">
      <button type="button" onClick={() => setSort((x) => ({ key, dir: x.key === key ? (x.dir === 1 ? -1 : 1) : 1 }))}
        className={clsx('inline-flex items-center gap-0.5 uppercase tracking-wider', sort.key === key ? 'text-accent' : 'hover:text-text-primary')}>
        {label}{sort.key === key ? (sort.dir === 1 ? <SortAsc className="h-3 w-3" /> : <SortDesc className="h-3 w-3" />) : null}
      </button>
    </th>
  );

  return (
    <div className="space-y-6">
      {canImport && (
        <section className="space-y-4 rounded-xl bg-bg-secondary p-4">
          <h2 className="text-base font-semibold text-text-primary">{t('legacyAgentPolicy.values.import') || 'Import per-device values'}</h2>
          <p className="text-xs text-text-muted">{t('legacyAgentPolicy.values.intro') || 'Values read by the file templates (the device.custom.<name> variables). They are merged into the custom fields of the devices; nothing is removed.'}</p>
          <ChipChoice value={source} onChange={(s) => { setSource(s); setParsed(null); setPreview(null); }}
            options={[{ id: 'folder', label: t('legacyAgentPolicy.values.folder') || 'Folder tree' }, { id: 'csv', label: 'CSV' }, { id: 'json', label: 'JSON' }]} />
          <div className="flex flex-wrap items-end gap-3">
            {source === 'folder' && (
              <Field label={t('legacyAgentPolicy.values.glob') || 'File names'}><input className={`${fieldCls} w-40 font-mono`} value={glob} maxLength={100} onChange={(e) => setGlob(e.target.value)} /></Field>
            )}
            <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-bg-tertiary px-3 py-2 text-sm text-text-primary hover:bg-bg-tertiary/70">
              <FolderOpen className="h-4 w-4" />
              {source === 'folder' ? (t('legacyAgentPolicy.values.pickFolder') || 'Pick a folder…') : (t('legacyAgentPolicy.values.pickFile') || 'Pick a file…')}
              <input type="file" className="hidden" multiple={source === 'folder'} accept={source === 'csv' ? '.csv,text/csv' : source === 'json' ? '.json' : undefined}
                {...(source === 'folder' ? { webkitdirectory: '', directory: '' } as Record<string, string> : {})}
                onChange={(e) => { void read(e.target.files); e.target.value = ''; }} />
            </label>
          </div>

          {parsed && (
            <div className="space-y-3">
              <p className="text-sm text-text-secondary">
                {t('legacyAgentPolicy.values.parsed', { rows: parsed.rows.length, issues: parsed.issues.length, conflicts: parsed.conflicts.length })
                  || `${parsed.rows.length} row(s), ${parsed.issues.length} remark(s), ${parsed.conflicts.length} device(s) with several files`}
              </p>
              {parsed.issues.length > 0 && (
                <details className="text-xs text-text-muted">
                  <summary className="cursor-pointer">{t('legacyAgentPolicy.values.issues') || 'Remarks'}</summary>
                  <ul className="mt-1 max-h-40 space-y-0.5 overflow-y-auto">
                    {parsed.issues.slice(0, 300).map((i, n) => <li key={n}>{i.source}: {trCode(`legacyAgentPolicy.values.issueCodes.${i.code}`, i.code)}{i.detail ? ` (${i.detail})` : ''}</li>)}
                  </ul>
                </details>
              )}
              <div className="space-y-1.5">
                <span className="text-xs text-text-muted">{t('legacyAgentPolicy.values.keys') || 'Keys (rename, or empty to leave out)'}</span>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {keys.map((k) => (
                    <label key={k} className="flex items-center gap-2 text-sm">
                      <span className="w-32 shrink-0 truncate font-mono text-xs text-text-muted" title={k}>{k}</span>
                      <input className={`${fieldCls} font-mono`} value={mapping[k] ?? k} maxLength={64} onChange={(e) => setMapping((m) => ({ ...m, [k]: e.target.value }))} />
                    </label>
                  ))}
                </div>
                <Field label={t('legacyAgentPolicy.values.prefix') || 'Prefix (optional)'}><input className={`${fieldCls} w-40 font-mono`} value={prefix} maxLength={20} onChange={(e) => setPrefix(e.target.value)} /></Field>
              </div>
              <div className="space-y-2 rounded-lg bg-bg-tertiary/40 p-3">
                <ToggleSwitch checked={byName} onChange={setByName} label={t('legacyAgentPolicy.values.byName') || 'Match the device name exactly'} />
                <ToggleSwitch checked={byCode} onChange={setByCode} label={t('legacyAgentPolicy.values.byCode') || 'Else match a code taken from the device name'} />
                {byCode && (
                  <div className="grid gap-3 sm:grid-cols-3">
                    <Field label={t('legacyAgentPolicy.values.regex') || 'Regular expression (one group)'}>
                      <input className={clsx(fieldCls, 'font-mono', !deviceCodePattern(nameRegex) && 'text-red-400')} value={nameRegex} maxLength={200} onChange={(e) => setNameRegex(e.target.value)} />
                      {!deviceCodePattern(nameRegex) && (
                        <span className="mt-1 block text-xs text-red-400">{t('legacyAgentPolicy.values.regexForm') || 'Only a literal prefix, one digit group such as (\\d{5}) and a literal suffix.'}</span>
                      )}
                    </Field>
                    <Field label={t('legacyAgentPolicy.values.field') || 'Key holding the code'}>
                      <ChipChoice value={codeField} onChange={setCodeField} options={mappedKeys.map((k) => ({ id: k, label: k }))} />
                    </Field>
                    <Field label={t('legacyAgentPolicy.values.pad') || 'Digits'}><input className={`${fieldCls} w-20`} inputMode="numeric" value={pad} maxLength={2} onChange={(e) => setPad(e.target.value.replace(/[^0-9]/g, ''))} /></Field>
                  </div>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="secondary" loading={busy} disabled={!rows.length} onClick={() => void run(false)}><Search className="mr-1 h-4 w-4" />{t('legacyAgentPolicy.values.preview') || 'Preview'}</Button>
                <Button loading={busy} disabled={!preview || preview.applied || preview.updated === 0} onClick={() => void run(true)}>{t('legacyAgentPolicy.values.apply') || 'Import'}</Button>
              </div>
            </div>
          )}

          {preview && (
            <div className="space-y-2">
              <p className="text-sm text-text-secondary">
                {t('legacyAgentPolicy.values.summary', { updated: preview.updated, unchanged: preview.unchanged, unmatched: preview.skipped.unmatched, conflict: preview.skipped.conflict,
                  governed: preview.skipped.governed, outOfScope: preview.skipped.outOfScope, impact: preview.policyImpact })
                  || `${preview.updated} to update, ${preview.unchanged} unchanged, ${preview.skipped.unmatched} unmatched, ${preview.skipped.conflict} conflict(s), ${preview.skipped.governed} governed, ${preview.skipped.outOfScope} out of scope; policy impact: ${preview.policyImpact} device(s)`}
              </p>
              <div className="max-h-96 overflow-auto rounded-xl bg-bg-secondary">
                <table className="w-full text-sm">
                  <tbody>
                    {preview.rows.flatMap((r): Array<{ r: PreviewRow; d: PreviewRow['devices'][number] | null }> => (r.devices.length ? r.devices.map((d) => ({ r, d })) : [{ r, d: null }])).slice(0, 1000).map(({ r, d }, n) => (
                      <tr key={n} className="border-t border-border/40 hover:bg-bg-tertiary">
                        <td className="px-3 py-1.5 font-mono text-xs text-text-primary">{r.deviceKey}</td>
                        <td className="px-3 py-1.5 text-xs text-text-muted">{trCode(`legacyAgentPolicy.values.matches.${r.match}`, r.match)}</td>
                        <td className="px-3 py-1.5 text-xs text-text-secondary">{d?.name ?? '—'}</td>
                        <td className="px-3 py-1.5 text-xs">{d ? trCode(`legacyAgentPolicy.values.statuses.${d.status}`, d.status) : ''}</td>
                        <td className="px-3 py-1.5 text-[11px] text-text-muted">{d?.changes.map((c) => `${c.key}: ${c.from ?? '∅'} → ${c.to}`).join(' · ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}

      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-base font-semibold text-text-primary">{t('legacyAgentPolicy.values.current') || 'Current values'}</h2>
          <div className="relative ml-auto w-full sm:w-64">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
            <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('legacyAgentPolicy.values.search') || 'Search'}
              className="w-full rounded-lg bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50" />
          </div>
        </div>
        <div className="overflow-x-auto rounded-xl bg-bg-secondary">
          <table className="w-full text-sm">
            <thead className="bg-bg-tertiary/50 text-left text-[10px] font-medium uppercase tracking-wider text-text-muted">
              <tr>{th(t('legacyAgent.cols.name') || 'Name', '')}{columns.map((c) => th(c, c))}</tr>
            </thead>
            <tbody>
              {devices === null && <tr><td colSpan={columns.length + 1} className="p-8 text-center text-text-muted">{t('common.loading') || 'Loading…'}</td></tr>}
              {shown.map((d) => (
                <tr key={d.deviceId} className="transition-colors hover:bg-bg-tertiary">
                  <td className="px-4 py-2 font-medium text-text-primary">{d.name ?? `#${d.deviceId}`}</td>
                  {columns.map((c) => <td key={c} className="px-4 py-2 text-xs text-text-secondary">{d.customFields?.[c] ?? '—'}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
