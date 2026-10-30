import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, Archive, ArrowLeft, CheckCircle2, FileUp, Pencil, Plus, RefreshCw, Save, Send, Trash2 } from 'lucide-react';
import type {
  AndroidPolicySection as AndroidSectionContent, AppleItem, JsonValue, LegacyAgentPolicySection as LegacyAgentSectionContent, Policy, PolicyConflict, PolicyContentV1, PolicyValidationIssue, PolicyVersion, SchemaKey,
} from '@obligarth/shared';
import { POLICY_CATEGORIES, POLICY_CATEGORY_RE, POLICY_MAX_ITEMS, RAW_PROFILE_TYPE, SocketEvents, shortType } from '@obligarth/shared';
import { mdmApi, type RawProfileImport, type SchemaCatalogView } from '@/api/mdm.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { registerSocketListener } from '@/socket/socketListeners';
import { PageContainer } from '@/components/common/PageContainer';
import { Modal } from '@/components/common/Modal';
import { Button } from '@/components/common/Button';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { AssignmentsPanel, announceSubmitOutcome } from '@/components/mdm/Assignments';
import { ConflictList, ImpactConfirmDialog } from '@/components/mdm/ImpactPreview';
import { formatDateTime } from '@/components/mdm/PlatformIcon';
import { AndroidPolicySection } from '@/components/android/AndroidPolicySection';
import { LegacyAgentPolicySection } from '@/components/legacyAgentPolicy/LegacyAgentPolicySection';
import { VERSION_TONE, categoryLabel, policyStateLabel, versionStateLabel } from '@/pages/PoliciesPage';
import { apiErrorBody, apiErrorCode, apiErrorMessage, trCode } from '@/utils/apiError';

// The editor of a policy (modele-donnees-mdm §7.1, §7.2, §11.3): its envelope, its versions (a published version
// is immutable: a change is a new draft), the items of its Apple section, the validation, the impact preview and
// the publication, its assignments. The Apple items are edited as JSON (the generated forms are CFG-01, another lot):
// the keys of each type are listed from the schema catalog to write them by hand. The Android section (lot AN-C2) has
// forms generated from the catalog of the AMAPI compiler (AndroidPolicySection).

type SchemaType = SchemaCatalogView['types'][number];
interface Row { item: AppleItem; text: string; error: string | null }

const pretty = (v: unknown): string => JSON.stringify(v ?? {}, null, 2);
/** The item id of the issues of the Android section (server: ANDROID_SECTION_ITEM). */
const ANDROID_ITEM = 'android';
/** The item id of the issues of the bridge agent's section (server: LEGACY_AGENT_SECTION_ITEM, lot PONT-POL). */
const AGENT_ITEM = 'legacyAgent';
const rowOf = (item: AppleItem): Row => ({ item, text: pretty(item.values ?? {}), error: null });
const newId = (): string => (typeof crypto.randomUUID === 'function' ? crypto.randomUUID()
  : 'xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx'.replace(/x/g, () => Math.floor(Math.random() * 16).toString(16)));
const issueText = (i: PolicyValidationIssue): string => `${trCode(`mdm.validation.${i.code}`, i.code)}${i.path ? ` (${i.path})` : ''}`;

export function PolicyEditorPage() {
  const { id } = useParams<{ id: string }>();
  const policyId = Number.parseInt(id ?? '', 10);
  const { t } = useTranslation();
  const confirm = useConfirm();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('mdm.policies.manage');

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [versions, setVersions] = useState<Array<Omit<PolicyVersion, 'content'>>>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [version, setVersion] = useState<PolicyVersion | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  // The Android section (lot AN-C2): its fragment and apps, edited by the generated forms.
  const [android, setAndroid] = useState<AndroidSectionContent | undefined>(undefined);
  // The section of the bridge agent (lot PONT-POL): files, Wi-Fi, kiosk, restrictions, CAs.
  const [legacyAgent, setLegacyAgent] = useState<LegacyAgentSectionContent | undefined>(undefined);
  const [changeNote, setChangeNote] = useState('');
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [catalog, setCatalog] = useState<SchemaCatalogView | null>(null);
  const [issues, setIssues] = useState<PolicyValidationIssue[]>([]);
  const [conflicts, setConflicts] = useState<PolicyConflict[]>([]);
  const [validated, setValidated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [envelopeOpen, setEnvelopeOpen] = useState(false);
  const [publishOpen, setPublishOpen] = useState(false);
  const [imported, setImported] = useState<RawProfileImport | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const dirtyRef = useRef(false);
  dirtyRef.current = dirty;

  /** The envelope and the list of versions; `keep`: stay on the version shown when it still exists. */
  const loadPolicy = useCallback(async (keep: number | null = null): Promise<void> => {
    try {
      const [p, vs] = await Promise.all([mdmApi.getPolicy(policyId), mdmApi.listVersions(policyId)]);
      setPolicy(p);
      setVersions(vs);
      setNotFound(false);
      const wanted = keep !== null && vs.some((v) => v.version === keep) ? keep
        : p.openVersion?.version ?? p.currentVersion ?? vs[0]?.version ?? null;
      setSelected(wanted);
    } catch {
      setNotFound(true);
    } finally {
      setLoading(false);
    }
  }, [policyId]);
  useEffect(() => { void loadPolicy(); }, [loadPolicy]);
  useEffect(() => { mdmApi.schema().then(setCatalog).catch(() => setCatalog(null)); }, []);

  const applyVersion = useCallback((v: PolicyVersion) => {
    setVersion(v);
    setRows((v.content?.sections?.apple?.items ?? []).map(rowOf));
    setAndroid(v.content?.sections?.android);
    setLegacyAgent(v.content?.sections?.legacyAgent);
    setChangeNote(v.changeNote ?? '');
    setDirty(false);
    setIssues([]);
    setConflicts([]);
    setValidated(false);
  }, []);
  useEffect(() => {
    if (selected === null) { setVersion(null); setRows([]); return; }
    let cancelled = false;
    mdmApi.getVersion(policyId, selected).then((v) => { if (!cancelled) applyVersion(v); }).catch((err) => { if (!cancelled) toast.error(apiErrorMessage(err)); });
    return () => { cancelled = true; };
  }, [policyId, selected, applyVersion]);

  // Live: the policy changed elsewhere (another administrator, an approval executed). An unsaved draft is kept.
  useEffect(() => registerSocketListener(SocketEvents.POLICY_CHANGED, (p: { policyIds?: number[] }) => {
    if (Array.isArray(p?.policyIds) && p.policyIds.map(Number).includes(policyId) && !dirtyRef.current) void loadPolicy(selected);
  }), [policyId, loadPolicy, selected]);

  const types = useMemo(() => new Map((catalog?.types ?? []).map((x) => [x.type, x])), [catalog]);
  const editable = canManage && version?.state === 'draft' && policy?.state !== 'archived' && policy?.shared !== true;

  const patchRow = (index: number, patch: Partial<Row> | ((r: Row) => Row)) => {
    setRows((prev) => prev.map((r, i) => (i === index ? (typeof patch === 'function' ? patch(r) : { ...r, ...patch }) : r)));
    setDirty(true);
    setValidated(false);
  };

  /** The content as edited; null (and the rows marked) when a block of JSON does not parse. */
  const buildContent = (): PolicyContentV1 | null => {
    let ok = true;
    const items: AppleItem[] = [];
    const next = rows.map((r) => {
      if (r.item.type === RAW_PROFILE_TYPE || r.item.remove) { items.push(r.item); return { ...r, error: null }; }
      try {
        const values = JSON.parse(r.text || '{}') as unknown;
        if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error(t('policies.editor.valuesObject') || 'The values are a JSON object');
        items.push({ ...r.item, values: values as Record<string, JsonValue> });
        return { ...r, error: null };
      } catch (err) {
        ok = false;
        return { ...r, error: (err as Error).message };
      }
    });
    setRows(next);
    if (!ok) return null;
    const sections: PolicyContentV1['sections'] = { ...(version?.content?.sections ?? {}), apple: { items } };
    if (android) sections.android = android; else delete sections.android;
    if (legacyAgent) sections.legacyAgent = legacyAgent; else delete sections.legacyAgent;
    return { format: 1, sections };
  };

  const save = async (): Promise<boolean> => {
    if (!version) return false;
    const content = buildContent();
    if (!content) { toast.error(t('policies.editor.invalidJson') || 'An item is not valid JSON: fix it before saving.'); return false; }
    setBusy(true);
    try {
      const saved = await mdmApi.saveDraft(policyId, version.version, content, changeNote.trim() || null);
      applyVersion(saved);
      toast.success(t('policies.editor.saved') || 'Draft saved');
      void loadPolicy(saved.version);
      return true;
    } catch (err) {
      if (apiErrorCode(err) === 'validationFailed') {
        const details = apiErrorBody(err)?.details;
        setIssues(Array.isArray(details) ? details as PolicyValidationIssue[] : []);
      }
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const validate = async () => {
    if (!version) return;
    if (dirty && !(await save())) return;
    setBusy(true);
    try {
      const r = await mdmApi.validateVersion(policyId, version.version);
      setIssues(r.issues);
      setConflicts(r.conflicts);
      setValidated(true);
      if (r.valid) toast.success(t('policies.editor.valid') || 'The content is valid');
    } catch (err) {
      toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  const openPublish = async () => {
    if (dirty && !(await save())) return;
    setPublishOpen(true);
  };

  const newVersion = async (from?: number) => {
    setBusy(true);
    try {
      const v = await mdmApi.newVersion(policyId, from);
      await loadPolicy(v.version);
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  const discard = async () => {
    if (!version) return;
    if (!(await confirm({ message: t('policies.editor.confirmDiscard', { version: version.version }) || `Discard version ${version.version}? Its content is lost.`, danger: true }))) return;
    setBusy(true);
    try {
      await mdmApi.discardVersion(policyId, version.version);
      toast.success(t('policies.editor.discarded') || 'Version discarded');
      // The envelope stays (a new draft starts from the published version, or empty).
      await loadPolicy();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  const archive = async () => {
    if (!policy) return;
    if (!(await confirm({ message: t('policies.editor.confirmArchive', { name: policy.name }) || `Archive the policy "${policy.name}"? It can no longer be assigned.`, danger: true }))) return;
    setBusy(true);
    try {
      setPolicy(await mdmApi.archivePolicy(policyId));
      toast.success(t('policies.editor.archived') || 'Policy archived');
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };

  const importProfile = async (file: File) => {
    if (dirty && !(await save())) return;
    setBusy(true);
    try {
      const out = await mdmApi.importRawProfile(policyId, file);
      applyVersion(out.version);
      setImported(out);
      void loadPolicy(out.version.version);
    } catch (err) {
      if (!isStepUpHandled(err)) {
        const reason = (apiErrorBody(err)?.details as { reason?: string } | undefined)?.reason;
        toast.error(reason ? trCode(`mdm.rawProfile.${reason}`, apiErrorMessage(err)) : apiErrorMessage(err), { duration: 8000 });
      }
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  if (loading) {
    return <div className="flex h-64 items-center justify-center"><RefreshCw className="w-6 h-6 animate-spin text-text-muted" /></div>;
  }
  if (notFound || !policy) {
    return (
      <PageContainer className="space-y-4 text-center">
        <p className="text-text-muted">{t('policies.notFound') || 'Policy not found'}</p>
        <Link to="/policies" className="text-sm text-accent hover:underline">{t('policies.back') || 'Back to the policies'}</Link>
      </PageContainer>
    );
  }

  const itemIssues = (itemId: string) => issues.filter((i) => i.itemId === itemId);
  const globalIssues = issues.filter((i) => i.itemId !== ANDROID_ITEM && i.itemId !== AGENT_ITEM && (i.itemId === null || !rows.some((r) => r.item.id === i.itemId)));
  const rejected = version?.state === 'rejected';

  return (
    <PageContainer className="space-y-5">
      <Link to="/policies" className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
        <ArrowLeft size={14} />{t('policies.back') || 'Back to the policies'}
      </Link>

      {/* Envelope */}
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-text-primary break-words">{policy.name}</h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-text-muted">
            <StateBadge tone={policy.state === 'published' ? 'green' : policy.state === 'draft' ? 'blue' : 'gray'} label={policyStateLabel(t, policy.state)} />
            <span>{categoryLabel(policy.category)}</span>
            {policy.currentVersion && <span>{t('policies.editor.publishedVersion', { version: policy.currentVersion }) || `published: v${policy.currentVersion}`}</span>}
            {policy.shared && <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-violet-400/10 text-violet-400">{t('policies.shared') || 'library'}</span>}
          </p>
          {policy.description && <p className="mt-1 text-sm text-text-secondary whitespace-pre-wrap">{policy.description}</p>}
        </div>
        {canManage && policy.state !== 'archived' && !policy.shared && (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => setEnvelopeOpen(true)}><Pencil size={14} className="mr-1.5" />{t('common.edit') || 'Edit'}</Button>
            <Button size="sm" variant="secondary" disabled={busy} onClick={archive}><Archive size={14} className="mr-1.5" />{t('policies.editor.archive') || 'Archive'}</Button>
          </div>
        )}
      </div>

      {/* Versions */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-text-muted">{t('policies.editor.versions') || 'Versions'}</span>
        {versions.map((v) => (
          <button key={v.id} type="button"
            onClick={async () => {
              if (v.version === selected) return;
              if (dirty && !(await confirm({ message: t('policies.editor.confirmLeave') || 'The draft has unsaved changes: leave it anyway?', danger: true }))) return;
              setSelected(v.version);
            }}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full coarse:py-2 ${v.version === selected ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted hover:text-text-primary'}`}>
            v{v.version}
            <span className="opacity-80">{versionStateLabel(t, v.state)}</span>
          </button>
        ))}
        {canManage && policy.state !== 'archived' && !policy.shared && !policy.openVersion && (
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => newVersion()}>
            <Plus className="w-3.5 h-3.5 mr-1" />{t('policies.editor.newVersion') || 'New version'}
          </Button>
        )}
      </div>

      {version && (
        <>
          <div className="flex flex-wrap items-center gap-2 rounded-lg bg-bg-secondary px-3 py-2 text-sm">
            <StateBadge tone={VERSION_TONE[version.state] ?? 'gray'} label={`v${version.version} · ${versionStateLabel(t, version.state)}`} size="md" />
            <span className="text-xs text-text-muted">
              {version.publishedAt ? (t('policies.editor.publishedAt', { at: formatDateTime(version.publishedAt) }) || `published ${formatDateTime(version.publishedAt)}`)
                : version.submittedAt ? (t('policies.editor.submittedAt', { at: formatDateTime(version.submittedAt) }) || `submitted ${formatDateTime(version.submittedAt)}`)
                  : (t('policies.editor.createdAt', { at: formatDateTime(version.createdAt) }) || `created ${formatDateTime(version.createdAt)}`)}
            </span>
            {version.state === 'pending_approval' && (
              <Link to="/admin/security?tab=approvals" className="text-xs text-accent hover:underline">{t('policies.editor.seeApproval') || 'See the approval request'}</Link>
            )}
            {!editable && version.state === 'draft' && !canManage && <span className="text-xs text-text-muted">{t('policies.editor.readOnly') || 'Read only: you cannot edit the policies.'}</span>}
            <span className="ml-auto flex flex-wrap gap-2">
              {editable && (
                <>
                  <input ref={fileRef} type="file" accept=".mobileconfig,application/x-apple-aspen-config,text/xml,application/xml" className="hidden"
                    onChange={(e) => { const f = e.target.files?.[0]; if (f) void importProfile(f); }} />
                  <Button size="sm" variant="secondary" disabled={busy} onClick={() => fileRef.current?.click()}>
                    <FileUp className="w-3.5 h-3.5 mr-1" />{t('policies.editor.importProfile') || 'Import a profile'}
                  </Button>
                  <Button size="sm" variant="secondary" disabled={busy || rows.length >= POLICY_MAX_ITEMS} onClick={() => setAddOpen(true)}>
                    <Plus className="w-3.5 h-3.5 mr-1" />{t('policies.editor.addItem') || 'Add an item'}
                  </Button>
                  <Button size="sm" variant="secondary" disabled={busy || !dirty} onClick={() => { void save(); }}>
                    <Save className="w-3.5 h-3.5 mr-1" />{t('common.save') || 'Save'}
                  </Button>
                </>
              )}
              {version.state === 'draft' && (
                <Button size="sm" variant="secondary" disabled={busy} onClick={() => { void validate(); }}>
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1" />{t('policies.editor.validate') || 'Validate'}
                </Button>
              )}
              {editable && (
                <Button size="sm" disabled={busy || (rows.length === 0 && !android && !legacyAgent)} onClick={() => { void openPublish(); }}>
                  <Send className="w-3.5 h-3.5 mr-1" />{t('policies.editor.publish') || 'Publish…'}
                </Button>
              )}
              {canManage && rejected && !policy.openVersion && (
                <Button size="sm" variant="secondary" disabled={busy} onClick={() => newVersion(version.version)}>
                  {t('policies.editor.takeUpAgain') || 'Take it up again as a draft'}
                </Button>
              )}
              {canManage && (version.state === 'draft' || rejected) && !policy.shared && (
                <Button size="sm" variant="secondary" disabled={busy} onClick={discard}><Trash2 className="w-3.5 h-3.5 mr-1" />{t('policies.editor.discard') || 'Discard'}</Button>
              )}
            </span>
          </div>

          {validated && issues.length === 0 && conflicts.length === 0 && (
            <p className="flex items-center gap-1.5 text-sm text-green-400"><CheckCircle2 className="w-4 h-4" />{t('policies.editor.valid') || 'The content is valid'}</p>
          )}
          {globalIssues.length > 0 && (
            <ul className="rounded-lg border border-red-400/30 bg-red-400/5 p-3 text-sm text-red-400 space-y-0.5">
              {globalIssues.map((i, n) => <li key={n} className="flex items-start gap-1.5"><AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />{issueText(i)}</li>)}
            </ul>
          )}
          <ConflictList conflicts={conflicts} />

          {editable && (
            <label className="block text-sm">
              <span className="text-xs text-text-muted">{t('policies.editor.changeNote') || 'Note of this version (what changes, for the approver and the history)'}</span>
              <input value={changeNote} onChange={(e) => { setChangeNote(e.target.value); setDirty(true); }} maxLength={2000}
                className="mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary" />
            </label>
          )}
          {!editable && version.changeNote && <p className="text-sm text-text-secondary">{version.changeNote}</p>}

          {/* Items of the Apple section (hidden for a version that has only Android settings) */}
          {(rows.length > 0 || (!android && !legacyAgent)) && <section className="space-y-3">
            <h2 className="text-sm font-semibold text-text-primary">
              {t('policies.editor.items', { count: rows.length }) || `${rows.length} item(s)`}
            </h2>
            {rows.length === 0 && <p className="text-sm text-text-muted">{t('policies.editor.noItem') || 'This version has no item yet.'}</p>}
            {rows.map((r, index) => (
              <ItemEditor
                key={r.item.id}
                row={r}
                type={types.get(r.item.type)}
                editable={!!editable}
                issues={itemIssues(r.item.id)}
                onChange={(patch) => patchRow(index, patch)}
                onDelete={() => { setRows((prev) => prev.filter((_, i) => i !== index)); setDirty(true); setValidated(false); }}
              />
            ))}
          </section>}
        </>
      )}

      {version && (android || editable) && (
        <AndroidPolicySection
          section={android}
          editable={!!editable}
          issues={issues.filter((i) => i.itemId === ANDROID_ITEM)}
          onChange={(next) => { setAndroid(next); setDirty(true); setValidated(false); }}
        />
      )}

      {version && (legacyAgent || editable) && (
        <LegacyAgentPolicySection
          key={version.id}
          section={legacyAgent}
          editable={!!editable}
          issues={issues.filter((i) => i.itemId === AGENT_ITEM)}
          onChange={(next) => { setLegacyAgent(next); setDirty(true); setValidated(false); }}
        />
      )}

      {/* Assignments */}
      <section className="pt-2">
        <AssignmentsPanel
          resource={{ id: policy.id, tenantId: policy.tenantId, name: policy.name, published: policy.currentVersion !== null && policy.state === 'published' }}
          canManage={canManage && policy.state !== 'archived'}
          onChanged={() => { void loadPolicy(selected); }}
        />
      </section>

      <AddItemDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        types={catalog?.types ?? []}
        onAdd={(type) => {
          setRows((prev) => [...prev, rowOf({ id: newId(), type, values: {} })]);
          setDirty(true);
          setValidated(false);
        }}
      />
      <EnvelopeDialog open={envelopeOpen} onClose={() => setEnvelopeOpen(false)} policy={policy} onSaved={setPolicy} />
      <ImpactConfirmDialog
        open={publishOpen}
        onClose={() => setPublishOpen(false)}
        title={t('policies.editor.publishTitle', { name: policy.name, version: version?.version ?? '' }) || `Publish "${policy.name}" v${version?.version ?? ''}`}
        intro={t('policies.editor.publishIntro') || 'A published version is immutable: it replaces the previous one on every device the policy is assigned to.'}
        confirmLabel={t('policies.editor.publishNow') || 'Publish'}
        load={() => mdmApi.versionImpact(policyId, version!.version)}
        apply={async () => {
          try {
            const outcome = await mdmApi.submitVersion(policyId, version!.version);
            announceSubmitOutcome(t, outcome);
            await loadPolicy(version!.version);
            // The version shown changed state (published, or awaiting approval): read it again.
            mdmApi.getVersion(policyId, version!.version).then(applyVersion).catch(() => { /* list reloaded above */ });
          } catch (err) {
            if (apiErrorCode(err) === 'validationFailed') {
              const details = apiErrorBody(err)?.details;
              setIssues(Array.isArray(details) ? details as PolicyValidationIssue[] : []);
            }
            if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
            throw err;
          }
        }}
      />
      <Modal
        open={imported !== null}
        onClose={() => setImported(null)}
        size="md"
        title={t('policies.editor.importedTitle') || 'Profile imported'}
        footer={<Button onClick={() => setImported(null)}>{t('common.close') || 'Close'}</Button>}
      >
        {imported && (
          <div className="space-y-2 text-sm">
            <p className="text-text-secondary">{t('policies.editor.importedPayloads') || 'Payloads'}: <span className="text-text-primary">{imported.payloadTypes.map(shortType).join(', ') || '—'}</span></p>
            {imported.movedSecrets.length > 0 && (
              <p className="text-text-secondary">
                {t('policies.editor.importedSecrets', { count: imported.movedSecrets.length }) || `${imported.movedSecrets.length} secret(s) moved to the vault`}:
                <span className="ml-1 font-mono text-text-primary">{imported.movedSecrets.join(', ')}</span>
              </p>
            )}
            {(imported.suspectKeys?.length ?? 0) > 0 && (
              <div className="rounded border border-amber-400/40 bg-amber-400/5 p-2 text-xs text-amber-400">
                <p>{t('policies.editor.importedSuspect', { count: imported.suspectKeys!.length }) || `${imported.suspectKeys!.length} key(s) look like secrets but were kept in clear in the policy (they are still delivered encrypted to each device). Check them before publishing; delete the item to remove them.`}</p>
                <p className="mt-1 font-mono text-text-primary break-all">{imported.suspectKeys!.join(', ')}</p>
              </div>
            )}
            {imported.signed && imported.signature?.signer && (
              <p className="text-xs text-text-secondary">
                {(imported.signature.trusted
                  ? t('policies.editor.importedSignedTrusted', { signer: imported.signature.signer.subject })
                  : t('policies.editor.importedSignedUntrusted', { signer: imported.signature.signer.subject }))
                  || `The file was signed by ${imported.signature.signer.subject}: the signature verifies${imported.signature.trusted ? ' and its certificate chains to a public root' : ', but its certificate does not chain to a public root'}. The signature was removed: the profile is delivered by this server, encrypted for each device.`}
              </p>
            )}
            {imported.signature?.status === 'unsupported' && (
              <p className="text-xs text-amber-400">{t('policies.editor.importedSignedUnverified') || 'The file was signed with an algorithm this server does not verify: the signature was removed without being checked. The profile is delivered by this server, encrypted for each device.'}</p>
            )}
            <p className="text-xs text-text-muted">{t('policies.editor.importedHint') || 'Check the payloads before publishing: a raw profile is delivered as it is.'}</p>
          </div>
        )}
      </Modal>
    </PageContainer>
  );
}

function keyLine(k: SchemaKey, secret: boolean): string {
  return `${k.name}: ${k.type}${k.required ? ' *' : ''}${secret ? ' (secret)' : ''}`;
}

function ItemEditor({ row, type, editable, issues, onChange, onDelete }: {
  row: Row;
  type: SchemaType | undefined;
  editable: boolean;
  issues: PolicyValidationIssue[];
  onChange: (patch: Partial<Row> | ((r: Row) => Row)) => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const [keysOpen, setKeysOpen] = useState(false);
  const { item } = row;
  const raw = item.type === RAW_PROFILE_TYPE;
  const descriptor = type?.descriptor as { merge?: string; instanceKey?: string } | undefined;
  const needsInstance = !raw && descriptor?.merge === 'collection' && !descriptor.instanceKey;
  const canRemove = !raw && descriptor?.merge !== undefined && descriptor.merge !== 'keyed';
  const setItem = (patch: Partial<AppleItem>) => onChange((r) => ({ ...r, item: { ...r.item, ...patch } }));
  const field = 'rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
  return (
    <div className={`rounded-lg bg-bg-secondary p-3 space-y-2 ${issues.length || row.error ? 'ring-1 ring-red-400/50' : ''}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-text-primary">{type?.title || shortType(item.type)}</span>
        <span className="font-mono text-[11px] text-text-muted break-all">{item.type}</span>
        {type && !type.enabled && <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-amber-400/10 text-amber-400">{t('policies.editor.typeDisabled') || 'not offered'}</span>}
        {item.remove && <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-red-400/10 text-red-400">{t('policies.editor.tombstone') || 'removes the inherited one'}</span>}
        {editable && (
          <button type="button" onClick={onDelete} aria-label={t('common.delete') || 'Delete'} title={t('common.delete') || 'Delete'}
            className="ml-auto p-1 rounded text-text-muted hover:text-red-400 coarse:min-h-10 coarse:min-w-10">
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>

      {(needsInstance || item.instance !== undefined) && (
        <label className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-xs text-text-muted">{t('policies.editor.instance') || 'Instance'}</span>
          <input value={item.instance ?? ''} disabled={!editable} onChange={(e) => setItem({ instance: e.target.value || undefined })} maxLength={64} className={`${field} w-64 max-w-full`} />
        </label>
      )}
      {canRemove && (editable || item.remove) && (
        <label className="flex items-center gap-2 text-sm text-text-secondary">
          <input type="checkbox" checked={item.remove === true} disabled={!editable} className="accent-accent"
            onChange={(e) => onChange((r) => {
              const next = { ...r.item };
              if (e.target.checked) { next.remove = true; delete next.values; } else { delete next.remove; next.values = {}; }
              return { ...r, item: next, text: pretty(next.values ?? {}) };
            })} />
          {t('policies.editor.removeInherited') || 'Remove the inherited instance instead of setting values'}
        </label>
      )}

      {raw ? (
        <p className="text-xs text-text-muted">{t('policies.editor.rawProfile') || 'Imported profile: delivered as it is, encrypted for each device. Its content is not edited here (delete the item and import the file again to replace it).'}</p>
      ) : !item.remove && (
        <>
          <textarea
            value={row.text}
            readOnly={!editable}
            onChange={(e) => onChange({ text: e.target.value, error: null })}
            rows={Math.min(18, Math.max(4, row.text.split('\n').length))}
            spellCheck={false}
            autoCapitalize="off"
            className="w-full rounded border border-border bg-bg-primary px-2 py-1.5 font-mono text-xs text-text-primary"
          />
          {row.error && <p className="text-xs text-red-400">{row.error}</p>}
          {type && type.keys.length > 0 && (
            <div className="text-xs">
              <button type="button" onClick={() => setKeysOpen(!keysOpen)} className="text-accent hover:underline coarse:min-h-9" aria-expanded={keysOpen}>
                {keysOpen ? (t('policies.editor.hideKeys') || 'Hide the keys of this type') : (t('policies.editor.showKeys', { count: type.keys.length }) || `Keys of this type (${type.keys.length})`)}
              </button>
              {keysOpen && (
                <>
                  <ul className="mt-1 grid gap-x-4 gap-y-0.5 font-mono text-[11px] text-text-secondary sm:grid-cols-2">
                    {type.keys.map((k) => <li key={k.name} title={k.title}>{keyLine(k, k.name in (type.secretKeys ?? {}))}</li>)}
                  </ul>
                  <p className="mt-1 text-[11px] text-text-muted">
                    {t('policies.editor.keysHint', { secret: '{"$secretValue": "…"}', variables: '{{device.name}}, {{user.email}}' })}
                  </p>
                </>
              )}
            </div>
          )}
        </>
      )}

      {editable ? (
        <input value={item.note ?? ''} onChange={(e) => setItem({ note: e.target.value || undefined })} maxLength={500}
          placeholder={t('policies.editor.note') || 'Comment (never sent to a device)'} className={`${field} w-full text-xs`} />
      ) : item.note ? <p className="text-xs text-text-muted">{item.note}</p> : null}

      {issues.length > 0 && (
        <ul className="text-xs text-red-400 space-y-0.5">
          {issues.map((i, n) => <li key={n} className="flex items-start gap-1.5"><AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />{issueText(i)}</li>)}
        </ul>
      )}
    </div>
  );
}

function AddItemDialog({ open, onClose, types, onAdd }: { open: boolean; onClose: () => void; types: SchemaType[]; onAdd: (type: string) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  useEffect(() => { if (open) setQ(''); }, [open]);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return types
      .filter((x) => x.enabled && x.type !== RAW_PROFILE_TYPE)
      .filter((x) => !needle || x.type.toLowerCase().includes(needle) || (x.title ?? '').toLowerCase().includes(needle))
      .sort((a, b) => (a.title || a.type).localeCompare(b.title || b.type));
  }, [types, q]);
  return (
    <Modal open={open} onClose={onClose} size="lg" title={t('policies.editor.addItem') || 'Add an item'}>
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('common.search') || 'Search'} autoFocus
        className="w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary" />
      <ul className="mt-2 max-h-[50vh] overflow-auto divide-y divide-border/50 text-sm">
        {shown.map((x) => (
          <li key={x.type}>
            <button type="button" onClick={() => { onAdd(x.type); onClose(); }} className="w-full text-left px-2 py-2 hover:bg-bg-tertiary">
              <span className="text-text-primary">{x.title || shortType(x.type)}</span>
              <span className="ml-2 text-[10px] uppercase text-text-muted">{trCode(`policies.family.${x.family}`, x.family)}</span>
              <span className="block font-mono text-[11px] text-text-muted break-all">{x.type}</span>
            </button>
          </li>
        ))}
        {shown.length === 0 && <li className="px-2 py-4 text-text-muted">{t('policies.editor.noType') || 'No type matches.'}</li>}
      </ul>
    </Modal>
  );
}

function EnvelopeDialog({ open, onClose, policy, onSaved }: { open: boolean; onClose: () => void; policy: Policy; onSaved: (p: Policy) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState(policy.name);
  const [description, setDescription] = useState(policy.description ?? '');
  const [category, setCategory] = useState(policy.category);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setName(policy.name); setDescription(policy.description ?? ''); setCategory(policy.category); } }, [open, policy]);
  const categories = POLICY_CATEGORIES.includes(policy.category as typeof POLICY_CATEGORIES[number]) ? [...POLICY_CATEGORIES] : [...POLICY_CATEGORIES, policy.category];
  const save = async () => {
    setBusy(true);
    try {
      onSaved(await mdmApi.updatePolicy(policy.id, { name: name.trim(), description: description.trim() || null, category }));
      toast.success(t('common.saved') || 'Saved');
      onClose();
    } catch (err) {
      if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 7000 });
    } finally {
      setBusy(false);
    }
  };
  const field = 'mt-1 w-full rounded border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary';
  return (
    <Modal
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      size="md"
      title={t('policies.editor.envelopeTitle') || 'Edit the policy'}
      footer={(
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>{t('common.cancel') || 'Cancel'}</Button>
          <Button onClick={save} loading={busy} disabled={!name.trim() || !POLICY_CATEGORY_RE.test(category)}>{t('common.save') || 'Save'}</Button>
        </>
      )}
    >
      <div className="space-y-3 text-sm">
        <label className="block">
          <span className="text-xs text-text-muted">{t('policies.name') || 'Name'}</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} className={field} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('common.description') || 'Description'}</span>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} maxLength={10000} className={field} />
        </label>
        <label className="block">
          <span className="text-xs text-text-muted">{t('policies.categoryLabel') || 'Category'}</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)} className={field}>
            {categories.map((c) => <option key={c} value={c}>{categoryLabel(c)}</option>)}
          </select>
        </label>
      </div>
    </Modal>
  );
}
