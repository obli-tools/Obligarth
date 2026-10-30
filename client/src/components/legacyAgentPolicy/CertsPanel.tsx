import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, ShieldCheck, Trash2 } from 'lucide-react';
import type { AgentCertItem, PolicyValidationIssue } from '@obligarth/shared';
import { LEGACY_AGENT_POLICY_LIMITS } from '@obligarth/shared';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { Field, IssueList, fieldCls, issuesUnder } from './ui';

// The CAs the bridge agent installs into the system store (lot PONT-POL §11.1): a licensed Knox only. A Wi-Fi network
// carries its own CA (WifiDialog): this list is for the other apps of the device.

export function CertsPanel({ certs, editable, issues, onChange }: {
  certs: AgentCertItem[]; editable: boolean; issues: PolicyValidationIssue[]; onChange: (next: AgentCertItem[]) => void;
}) {
  const { t } = useTranslation();
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState<AgentCertItem>({ id: '', name: '', pem: '' });
  const ok = LEGACY_AGENT_POLICY_LIMITS.idRe.test(draft.id) && !certs.some((c) => c.id === draft.id) && draft.name.trim() !== ''
    && draft.pem.includes('-----BEGIN CERTIFICATE-----');
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="rounded-full bg-violet-400/10 px-2 py-0.5 text-[11px] text-violet-400">{t('legacyAgentPolicy.knoxRequired') || 'Knox licence required'}</span>
        {editable && certs.length < LEGACY_AGENT_POLICY_LIMITS.certs && (
          <Button size="sm" variant="secondary" className="ml-auto" onClick={() => { setDraft({ id: '', name: '', pem: '' }); setAdding(true); }}>
            <Plus className="mr-1 h-3.5 w-3.5" />{t('legacyAgentPolicy.certs.add') || 'Add a CA'}
          </Button>
        )}
      </div>
      {certs.length === 0 ? <p className="text-sm text-text-muted">{t('legacyAgentPolicy.certs.none') || 'No CA in the system store.'}</p> : (
        <ul className="divide-y divide-border/50 rounded-xl bg-bg-secondary">
          {certs.map((c, i) => (
            <li key={c.id} className="px-3 py-2 text-sm hover:bg-bg-tertiary">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-text-muted" />
                <span className="text-text-primary">{c.name}</span>
                <span className="font-mono text-[11px] text-text-muted">{c.id}</span>
                {editable && (
                  <button type="button" className="ml-auto rounded p-1.5 text-text-muted hover:text-red-400" aria-label={t('common.delete') || 'Delete'}
                    onClick={() => onChange(certs.filter((_, j) => j !== i))}><Trash2 className="h-4 w-4" /></button>
                )}
              </div>
              <IssueList issues={issuesUnder(issues, `certs[${i}]`)} />
            </li>
          ))}
        </ul>
      )}
      <Modal open={adding} onClose={() => setAdding(false)} size="md" title={t('legacyAgentPolicy.certs.add') || 'Add a CA'}
        footer={(
          <>
            <Button variant="secondary" onClick={() => setAdding(false)}>{t('common.cancel') || 'Cancel'}</Button>
            <Button disabled={!ok} onClick={() => { onChange([...certs, { ...draft, name: draft.name.trim() }]); setAdding(false); }}>{t('common.save') || 'Save'}</Button>
          </>
        )}>
        <div className="space-y-3">
          <Field label={t('legacyAgentPolicy.files.id') || 'Identifier'}><input className={fieldCls} value={draft.id} maxLength={48} placeholder="corp-root" onChange={(e) => setDraft({ ...draft, id: e.target.value.toLowerCase() })} /></Field>
          <Field label={t('legacyAgentPolicy.certs.name') || 'Name'}><input className={fieldCls} value={draft.name} maxLength={100} placeholder="Example Root CA" onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></Field>
          <Field label="PEM"><textarea className={`${fieldCls} font-mono text-[11px]`} rows={6} spellCheck={false} value={draft.pem} onChange={(e) => setDraft({ ...draft, pem: e.target.value })} /></Field>
        </div>
      </Modal>
    </div>
  );
}
