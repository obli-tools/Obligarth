import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Plus, X } from 'lucide-react';
import { SITE_LIMITS, SITE_RESERVED_KEYS, SITE_VALUE_KEY_RE, type SiteDetail, type SiteView } from '@obligarth/shared';
import { sitesApi } from '@/api/sites.api';
import { isStepUpHandled } from '@/api/client';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { GroupTreePicker } from '@/components/devices/GroupTreePicker';
import { pendingSaid, useValueRows } from '@/components/sites/siteUi';
import { apiErrorBody, apiErrorMessage, trCode } from '@/utils/apiError';

// A site created or changed (lot P1-SITE §2.4): its code, name, city, contact, the group its phones are filed in, and
// its values (key → text: the {{site.<key>}} of the file templates, and the fallback of {{device.custom.<key>}}).

const fieldBase = 'rounded-lg bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50';
const fieldCls = 'mt-1 w-full rounded-lg bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50';

/** The message of a refused site: its issues translated (invalidSite details.issues). */
export function siteErrorMessage(err: unknown): string {
  const issues = (apiErrorBody(err)?.details as { issues?: unknown } | undefined)?.issues;
  if (Array.isArray(issues) && issues.length) return issues.map((i) => trCode(`sites.issue.${String(i)}`, String(i))).join(' · ');
  return apiErrorMessage(err);
}

const keyProblem = (k: string): boolean => !!k.trim() && (!SITE_VALUE_KEY_RE.test(k.trim()) || (SITE_RESERVED_KEYS as readonly string[]).includes(k.trim().toLowerCase()));

export function SiteEditDialog({ open, site, onClose, onSaved }: {
  open: boolean; site: SiteView | SiteDetail | null; onClose: () => void; onSaved: (s: SiteDetail) => void;
}) {
  const { t } = useTranslation();
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [city, setCity] = useState('');
  const [contact, setContact] = useState('');
  const [groupId, setGroupId] = useState<number | null>(null);
  const { rows, setRows, asValues } = useValueRows(open ? site?.values : undefined);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    setCode(site?.code ?? ''); setName(site?.name ?? ''); setCity(site?.city ?? ''); setContact(site?.contact ?? '');
    setGroupId(site?.groupId ?? null);
  }, [open, site]);
  const badKey = rows.some((r) => keyProblem(r.key));
  const ok = code.trim() && name.trim() && !badKey && rows.length <= SITE_LIMITS.valuesMax;
  const save = async () => {
    setBusy(true);
    try {
      const body = { code: code.trim(), name: name.trim(), city: city.trim() || null, contact: contact.trim() || null, groupId, values: asValues() };
      const saved = site ? await sitesApi.update(site.id, body) : await sitesApi.create(body);
      // Held for a second person (beyond the publication thresholds): nothing changed yet.
      if (pendingSaid(t, saved)) { onClose(); return; }
      toast.success(t('common.saved') || 'Saved');
      onSaved(saved);
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(siteErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open={open} onClose={() => { if (!busy) onClose(); }} size="lg"
      title={site ? (t('sites.edit.title') || 'Edit the site') : (t('sites.edit.newTitle') || 'New site')}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy} disabled={!ok}>{t('common.save') || 'Save'}</Button>
        </>
      )}>
      <div className="space-y-4 text-sm">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fields.code') || 'Code'}</span>
            <input value={code} onChange={(e) => setCode(e.target.value)} maxLength={SITE_LIMITS.codeMax} placeholder="99001" className={fieldCls} autoCapitalize="off" spellCheck={false} /></label>
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fields.name') || 'Name'}</span>
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={SITE_LIMITS.nameMax} placeholder={t('sites.fields.namePlaceholder') || 'Store Exemple-Nord'} className={fieldCls} /></label>
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fields.city') || 'City'}</span>
            <input value={city} onChange={(e) => setCity(e.target.value)} maxLength={SITE_LIMITS.cityMax} className={fieldCls} /></label>
          <label className="block"><span className="text-xs text-text-muted">{t('sites.fields.contact') || 'Contact'}</span>
            <input value={contact} onChange={(e) => setContact(e.target.value)} maxLength={SITE_LIMITS.contactMax} className={fieldCls} /></label>
        </div>
        <div>
          <span className="text-xs text-text-muted">{t('sites.fields.group') || 'Group of its phones (optional)'}</span>
          <p className="mb-1 text-[11px] text-text-muted">{t('sites.fields.groupHint') || 'A phone attached to the site is then offered a move into this group (with its usual confirmation).'}</p>
          <div className="flex items-start gap-2">
            <div className="min-w-0 flex-1"><GroupTreePicker value={groupId} onChange={(id) => setGroupId(id)} /></div>
            {groupId !== null && <Button size="sm" variant="ghost" onClick={() => setGroupId(null)}>{t('sites.fields.noGroup') || 'No group'}</Button>}
          </div>
        </div>
        <div>
          <span className="text-xs text-text-muted">{t('sites.fields.values') || 'Values of the site'}</span>
          <p className="mb-1 text-[11px] text-text-muted">{t('sites.fields.valuesHint') || 'Read by the file templates: {{site.<key>}}, and {{device.custom.<key>}} when the phone has no value of its own.'}</p>
          <div className="space-y-1.5">
            {rows.map((r, i) => (
              <div key={i} className="flex items-center gap-2">
                <input value={r.key} onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)))} placeholder="codeMag"
                  className={`${fieldBase} w-40 shrink-0 font-mono text-xs ${keyProblem(r.key) ? 'ring-2 ring-red-500/60' : ''}`} autoCapitalize="off" spellCheck={false} maxLength={64} />
                <input value={r.value} onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))}
                  className={`${fieldBase} min-w-0 flex-1`} placeholder={t('sites.fields.valuePlaceholder') || 'Value'} maxLength={SITE_LIMITS.valueMax} />
                <button type="button" onClick={() => setRows(rows.filter((_x, j) => j !== i))} aria-label={t('common.delete') || 'Delete'}
                  className="rounded p-1.5 text-text-muted hover:bg-bg-tertiary hover:text-red-400 coarse:min-h-10 coarse:min-w-10">
                  <X className="h-4 w-4" />
                </button>
              </div>
            ))}
            {badKey && <p className="text-[11px] text-red-400">{t('sites.issue.value_key_invalid') || 'A key: a letter, then letters, digits or _ (64 at most); code, name, city and contact are reserved.'}</p>}
            {rows.length < SITE_LIMITS.valuesMax && (
              <Button size="sm" variant="ghost" onClick={() => setRows([...rows, { key: '', value: '' }])}>
                <Plus className="mr-1 h-4 w-4" />{t('sites.fields.addValue') || 'Add a value'}
              </Button>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
}
