import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, ExternalLink, FileText, Link2, RefreshCw, RotateCcw, Save, XCircle } from 'lucide-react';
import {
  NOTICE_ACK_CHANNELS, NOTICE_LOCALES, NOTICE_PLATFORMS, NOTICE_SETTINGS_FIELDS, NOTICE_SETTINGS_KEYS, OWNERSHIPS, noticeDisplayed,
  noticeSettingsErrors, normalizeNoticeSetting,
  type NoticeAcknowledgementCountDto, type NoticeContentDto, type NoticeLocale, type NoticePlatform, type NoticeSettingsDto,
  type NoticeSettingsKey, type NoticeVersionDto, type NoticesDto, type Ownership,
} from '@obligarth/shared';
import { privacyApi } from '@/api/privacy.api';
import { isStepUpHandled } from '@/api/client';
import { Button } from '@/components/common/Button';
import { SegmentedTabs } from '@/components/common/SegmentedTabs';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { formatDateTime, ownershipLabel } from '@/components/mdm/PlatformIcon';
import { CopyButton } from '@/components/mdm/ui/InfoCard';
import { apiErrorCode, apiErrorMessage } from '@/utils/apiError';
import { openExternal } from '@/utils/openExternal';
import {
  ackChannelLabel, localeLabel, missingLabel, platformName, readOnlyNotice, settingHint, settingLabel, stageLabel,
} from './privacyLabels';

// The Notice tab of the privacy console (P0-13 T7, USR-01): whether the notice of the employees is complete (D7: the
// data controller and a contact; outside the stage lab an enrollment is refused until it is), the link of its public
// page (D6), its settings (changed with mdm.privacy.manage alone, no second person: D3; plain text, the notices are
// generated again at once), the notice an enrollment shows per platform, ownership and language (rendered as text,
// never as markup), its versions and their acknowledgements.

type Form = Record<NoticeSettingsKey, string>;

/** What a complete notice needs (D7): the data controller, and the DPO or another contact. */
const REQUIRED = new Set<NoticeSettingsKey>(['controllerName', 'dpoContact', 'contact']);

const fieldCls = 'mt-1 w-full rounded-md bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-60 coarse:min-h-10';

function errorToast(err: unknown): void {
  if (!isStepUpHandled(err)) toast.error(apiErrorMessage(err), { duration: 8000 });
}

const formOf = (d: NoticeSettingsDto): Form =>
  Object.fromEntries(NOTICE_SETTINGS_KEYS.map((k) => [k, d.settings[k] ?? ''])) as Form;

export function NoticeTab() {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<NoticeSettingsDto | null>(null);
  const [notices, setNotices] = useState<NoticesDto | null>(null);
  // Each read keeps its own error: a success of one never hides the failure of the other.
  const [error, setError] = useState<string | null>(null);
  const [noticesError, setNoticesError] = useState<string | null>(null);
  const loadSettings = useCallback(() => {
    privacyApi.noticeSettings().then((d) => { setSettings(d); setError(null); }).catch((err) => setError(apiErrorMessage(err)));
  }, []);
  const loadNotices = useCallback(() => {
    privacyApi.notices().then((d) => { setNotices(d); setNoticesError(null); }).catch((err) => setNoticesError(apiErrorMessage(err)));
  }, []);
  const load = useCallback(() => { loadSettings(); loadNotices(); }, [loadSettings, loadNotices]);
  useEffect(() => { load(); }, [load]);
  // The notices are generated again by a background job after a change of the settings: read them again shortly.
  const [refreshSoon, setRefreshSoon] = useState(0);
  useEffect(() => {
    if (!refreshSoon) return undefined;
    const timer = window.setTimeout(loadNotices, 3000);
    return () => window.clearTimeout(timer);
  }, [refreshSoon, loadNotices]);

  // The introduction and its Refresh button stay whatever happens: a failed read is retried from there.
  const header = (
    <div className="flex flex-wrap items-start gap-2">
      <p className="min-w-0 flex-1 text-sm text-text-muted">
        {t('privacy.notice.intro') || 'The notice an employee reads before enrolling a device: generated from the privacy profiles, the retention and the settings below, in French and in English.'}
      </p>
      <button type="button" onClick={load} aria-label={t('common.refresh') || 'Refresh'}
        className="rounded-lg p-2 text-text-muted hover:bg-bg-tertiary hover:text-text-primary coarse:min-h-10 coarse:min-w-10">
        <RefreshCw className="h-4 w-4" />
      </button>
    </div>
  );
  const errorLine = error ? <p className="text-sm text-status-down">{error}</p> : null;
  if (!settings) {
    return (
      <div className="space-y-4">
        {header}
        {errorLine ?? <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>}
      </div>
    );
  }
  return (
    <div className="space-y-4">
      {header}
      {errorLine}
      <StatusCard s={settings} />
      <SettingsForm key={settings.version} s={settings} onSaved={(d) => { setSettings(d); loadNotices(); setRefreshSoon((n) => n + 1); }} onStale={loadSettings} />
      <PreviewCard notices={notices} noticesError={noticesError} />
    </div>
  );
}

// ── Completeness, stage, public page ───────────────────────────────────────────

function StatusCard({ s }: { s: NoticeSettingsDto }) {
  const { t } = useTranslation();
  const complete = s.missing.length === 0;
  return (
    <section className="space-y-3 rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex flex-wrap items-center gap-2">
        {complete ? <CheckCircle2 className="h-5 w-5 text-status-up" aria-hidden />
          : s.enrollmentRefused ? <XCircle className="h-5 w-5 text-status-down" aria-hidden />
            : <AlertTriangle className="h-5 w-5 text-amber-400" aria-hidden />}
        <h2 className="text-base font-semibold text-text-primary">
          {complete ? (t('privacy.notice.complete') || 'Notice complete') : (t('privacy.notice.incomplete') || 'Notice incomplete')}
        </h2>
        <StateBadge tone={s.stage === 'lab' ? 'blue' : 'violet'} label={t('privacy.notice.stageBadge', { stage: stageLabel(s.stage) }) || `Stage: ${stageLabel(s.stage)}`} />
      </div>
      {!complete && (
        <p className="text-sm text-text-secondary">
          {t('privacy.notice.missingList', { list: s.missing.map(missingLabel).join(', ') }) || `Missing: ${s.missing.map(missingLabel).join(', ')}.`}{' '}
          {s.enrollmentRefused
            ? (t('privacy.notice.refused') || 'Every enrollment of the tenant is refused until the notice is complete.')
            : (t('privacy.notice.labServed') || 'In the laboratory stage the notice is shown anyway; from the pilot stage on, the enrollments are refused until it is complete.')}
        </p>
      )}
      <div className="space-y-1">
        <p className="flex items-center gap-1.5 text-xs font-medium text-text-secondary"><Link2 className="h-3.5 w-3.5" aria-hidden />{t('privacy.notice.publicPage') || 'Public page of the notice'}</p>
        {s.publicUrl ? (
          <div className="group flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 break-all font-mono text-xs text-text-primary">{s.publicUrl}</span>
            <CopyButton value={s.publicUrl} label={t('privacy.notice.copyLink') || 'Copy the link'} />
            <a href={s.publicUrl} target="_blank" rel="noopener noreferrer"
              onClick={(e) => { e.preventDefault(); void openExternal(s.publicUrl!); }}
              className="inline-flex items-center gap-1 text-xs text-accent hover:underline coarse:min-h-10">
              <ExternalLink className="h-3.5 w-3.5" aria-hidden />{t('privacy.notice.open') || 'Open'}
            </a>
            <p className="w-full text-[11px] text-text-muted">{t('privacy.notice.publicHint') || 'Anyone with the link reads the notice in force, before any enrollment (the link carries the key of the enrollment links).'}</p>
          </div>
        ) : (
          <p className="text-xs text-text-muted">{t('privacy.notice.noPublicPage') || 'No public page: this instance serves no device surface yet.'}</p>
        )}
      </div>
    </section>
  );
}

// ── Settings ───────────────────────────────────────────────────────────────────

function SettingsForm({ s, onSaved, onStale }: { s: NoticeSettingsDto; onSaved: (d: NoticeSettingsDto) => void; onStale: () => void }) {
  const { t } = useTranslation();
  const initial = useMemo(() => formOf(s), [s]);
  const [form, setForm] = useState<Form>(initial);
  const [busy, setBusy] = useState(false);
  const editable = s.canManage;
  // The settings that change, as the server stores them (trimmed, empty as null).
  const changed: Partial<Record<NoticeSettingsKey, string | null>> = {};
  for (const k of NOTICE_SETTINGS_KEYS) {
    const v = normalizeNoticeSetting(k, form[k]);
    if (v !== s.settings[k]) changed[k] = v;
  }
  const errors = noticeSettingsErrors(changed);
  const bad = new Set<NoticeSettingsKey>([...errors.tooLong, ...errors.markup]);
  const dirty = Object.keys(changed).length > 0;

  const save = async () => {
    setBusy(true);
    try {
      const d = await privacyApi.updateNoticeSettings({ settings: changed, baseVersion: s.version });
      toast.success(d.changed === false ? (t('privacy.notice.unchanged') || 'Nothing changed.')
        : (t('privacy.notice.saved') || 'Settings saved: the notices are generated again.'));
      onSaved(d);
    } catch (err) {
      if (apiErrorCode(err) === 'noticeSettingsChanged') {
        toast.error(t('privacy.notice.stale') || 'Someone changed these settings meanwhile: they are read again, check them before saving.', { duration: 8000 });
        onStale();
      } else errorToast(err);
    } finally { setBusy(false); }
  };

  return (
    <section className="space-y-3 rounded-lg border border-border bg-bg-secondary p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-base font-semibold text-text-primary">{t('privacy.notice.settings') || 'Settings of the notice'}</h2>
        {s.version > 0 && s.updatedAt && (
          <span className="text-xs text-text-muted">{t('privacy.notice.settingsVersion', { version: s.version, date: formatDateTime(s.updatedAt) }) || `Version ${s.version}, ${formatDateTime(s.updatedAt)}`}</span>
        )}
      </div>
      <p className="text-xs text-text-muted">{t('privacy.notice.plainText') || 'Plain text only: no markup (angle brackets are refused). Changed without a second person; each change is written to the audit log.'}</p>
      <p className="text-xs text-text-muted"><span className="text-amber-400" aria-hidden>* </span>{t('privacy.notice.required') || 'A complete notice needs the data controller, and the data protection officer or another contact.'}</p>
      <div className="grid gap-3 md:grid-cols-2">
        {NOTICE_SETTINGS_KEYS.map((k) => {
          const f = NOTICE_SETTINGS_FIELDS[k];
          const length = [...form[k]].length;
          const id = `notice-${k}`;
          const wide = f.multiline && f.max > 500;
          return (
            <div key={k} className={wide ? 'md:col-span-2' : undefined}>
              <label htmlFor={id} className="block text-sm text-text-secondary">
                {settingLabel(k)}
                {REQUIRED.has(k) && <span className="ml-1 text-amber-400" aria-hidden>*</span>}
              </label>
              {f.multiline ? (
                <textarea id={id} value={form[k]} onChange={(e) => setForm((x) => ({ ...x, [k]: e.target.value }))} disabled={!editable}
                  rows={wide ? 4 : 3} maxLength={f.max + 50} aria-invalid={bad.has(k)} className={`${fieldCls} ${bad.has(k) ? 'ring-2 ring-status-down' : ''}`} />
              ) : (
                <input id={id} type="text" value={form[k]} onChange={(e) => setForm((x) => ({ ...x, [k]: e.target.value }))} disabled={!editable}
                  maxLength={f.max + 50} aria-invalid={bad.has(k)} className={`${fieldCls} ${bad.has(k) ? 'ring-2 ring-status-down' : ''}`} />
              )}
              <div className="mt-0.5 flex flex-wrap items-start justify-between gap-2 text-[11px]">
                <span className="min-w-0 text-text-muted">{settingHint(k)}</span>
                <span className={length > f.max ? 'text-status-down' : 'text-text-muted'}>{length}/{f.max}</span>
              </div>
              {errors.markup.includes(k) && <p className="text-[11px] text-status-down">{t('privacy.notice.markup') || 'Angle brackets and control characters are not accepted.'}</p>}
              {errors.tooLong.includes(k) && <p className="text-[11px] text-status-down">{t('privacy.notice.tooLong', { max: f.max }) || `${f.max} characters at most.`}</p>}
            </div>
          );
        })}
      </div>
      {editable ? (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => { void save(); }} disabled={!dirty || bad.size > 0 || busy} loading={busy} className="gap-1.5">
            <Save className="h-4 w-4" aria-hidden />{t('common.save') || 'Save'}
          </Button>
          {dirty && (
            <Button size="sm" variant="secondary" onClick={() => setForm(initial)} disabled={busy} className="gap-1.5">
              <RotateCcw className="h-4 w-4" aria-hidden />{t('privacy.discard') || 'Discard the changes'}
            </Button>
          )}
        </div>
      ) : (
        <p className="text-xs text-text-muted">{readOnlyNotice(t)}</p>
      )}
    </section>
  );
}

// ── Preview, versions, acknowledgements ──────────────────────────────────────────

function PreviewCard({ notices, noticesError }: { notices: NoticesDto | null; noticesError: string | null }) {
  const { t } = useTranslation();
  const [platform, setPlatform] = useState<NoticePlatform>('apple');
  const [ownership, setOwnership] = useState<Ownership>('corporate');
  const [locale, setLocale] = useState<NoticeLocale>('fr');
  const [preview, setPreview] = useState<{ key: string; content: NoticeContentDto } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const comboKey = `${platform}:${ownership}:${locale}`;
  const current = notices?.current.find((v) => v.platform === platform && v.ownership === ownership && v.locale === locale) ?? null;
  const history = (notices?.history ?? []).filter((v) => v.platform === platform && v.ownership === ownership && v.locale === locale);
  const displayed = noticeDisplayed(platform, ownership);

  // No version yet for this combination (never generated): the notice the settings in force give now, nothing published.
  useEffect(() => {
    if (!notices || current) return undefined;
    let cancelled = false;
    setPreviewError(null);
    privacyApi.noticePreview(platform, ownership, locale)
      .then((p) => { if (!cancelled) setPreview({ key: comboKey, content: p.content }); })
      .catch((err) => { if (!cancelled) setPreviewError(apiErrorMessage(err)); });
    return () => { cancelled = true; };
  }, [notices, current, platform, ownership, locale, comboKey]);

  const content = current?.content ?? (preview?.key === comboKey ? preview.content : null);
  return (
    <section className="space-y-3 rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="flex items-center gap-2 text-base font-semibold text-text-primary"><FileText className="h-4 w-4 text-accent" aria-hidden />{t('privacy.notice.preview') || 'The notice'}</h2>
      <div className="flex flex-wrap gap-2">
        <SegmentedTabs<NoticePlatform> tabs={NOTICE_PLATFORMS.map((p) => ({ id: p, label: platformName(p) }))} value={platform} onChange={setPlatform}
          size="sm" fill={false} ariaLabel={t('privacy.notice.platform') || 'Platform'} />
        <SegmentedTabs<NoticeLocale> tabs={NOTICE_LOCALES.map((l) => ({ id: l, label: localeLabel(l) }))} value={locale} onChange={setLocale}
          size="sm" fill={false} ariaLabel={t('privacy.notice.locale') || 'Language'} />
        <SegmentedTabs<Ownership> tabs={OWNERSHIPS.map((o) => ({ id: o, label: ownershipLabel(t, o) }))} value={ownership} onChange={setOwnership}
          size="sm" fill={false} className="max-w-full" ariaLabel={t('privacy.profiles.ownership') || 'Ownership'} />
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {current ? (
          <>
            <StateBadge tone="green" label={t('privacy.notice.inForce') || 'In force'} />
            <span className="text-text-muted">{t('privacy.notice.generatedAt', { date: formatDateTime(current.generatedAt) }) || `Generated ${formatDateTime(current.generatedAt)}`}</span>
            <span className="font-mono text-text-muted" title={current.sha256}>{current.sha256.slice(0, 12)}</span>
          </>
        ) : notices ? <StateBadge tone="gray" label={t('privacy.notice.notPublished') || 'Not generated yet: preview'} /> : null}
        {!displayed && <StateBadge tone="amber" label={t('privacy.notice.notDisplayed') || 'Not shown at enrollment yet'}
          title={t('privacy.notice.notDisplayedHint') || 'The notice of the Android company devices is generated, not yet shown at their enrollment.'} />}
      </div>
      {/* The versions could not be read (kept from an earlier read when there is one): their error, never an endless
          "Loading". */}
      {noticesError && <p className="text-sm text-status-down">{noticesError}</p>}
      {previewError && !current && <p className="text-sm text-status-down">{previewError}</p>}
      {!content
        ? (!previewError && !(noticesError && !notices) && <p className="text-sm italic text-text-muted">{t('common.loading') || 'Loading…'}</p>)
        : <NoticeText content={content} />}
      {history.length > 0 && <VersionList versions={history} />}
    </section>
  );
}

/** The text of a notice: plain text in React elements (escaped), never markup. */
function NoticeText({ content }: { content: NoticeContentDto }) {
  const { t } = useTranslation();
  return (
    <article className="max-h-[32rem] space-y-3 overflow-y-auto overscroll-contain rounded-md bg-bg-tertiary/50 p-3 text-sm">
      <h3 className="text-base font-semibold text-text-primary break-words">{content.title}</h3>
      {content.sections.map((s, i) => (
        <div key={i} className="space-y-1">
          <h4 className="font-medium text-text-primary break-words">{s.heading}</h4>
          {s.paragraphs.map((p, j) => <p key={j} className="whitespace-pre-line break-words text-text-secondary">{p}</p>)}
        </div>
      ))}
      <div className="border-t border-border pt-2">
        <p className="text-xs font-medium text-text-secondary">{t('privacy.notice.consentSummary') || 'Summary in the enrollment profile'}</p>
        <p className="whitespace-pre-line break-words text-xs text-text-muted">{content.consentSummary}</p>
      </div>
    </article>
  );
}

function VersionList({ versions }: { versions: NoticeVersionDto[] }) {
  const { t } = useTranslation();
  return (
    <details className="border-t border-border pt-3 text-sm">
      <summary className="cursor-pointer select-none text-xs text-text-secondary hover:text-text-primary coarse:py-2">
        {t('privacy.notice.versions') || 'Versions'} ({versions.length})
      </summary>
      <ul className="mt-2 divide-y divide-border/60">
        {versions.map((v) => <VersionRow key={v.id} v={v} />)}
      </ul>
    </details>
  );
}

function VersionRow({ v }: { v: NoticeVersionDto }) {
  const { t } = useTranslation();
  const [acks, setAcks] = useState<NoticeAcknowledgementCountDto | null>(null);
  const [busy, setBusy] = useState(false);
  const detail = async () => {
    setBusy(true);
    try { setAcks(await privacyApi.acknowledgements(v.id)); } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <li className="space-y-1 py-2 text-xs">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-text-primary">{formatDateTime(v.generatedAt)}</span>
        {v.supersededAt === null
          ? <StateBadge tone="green" label={t('privacy.notice.inForce') || 'In force'} />
          : <span className="text-text-muted">{t('privacy.notice.supersededAt', { date: formatDateTime(v.supersededAt) }) || `replaced ${formatDateTime(v.supersededAt)}`}</span>}
        <span className="font-mono text-text-muted" title={v.sha256}>{v.sha256.slice(0, 12)}</span>
        <span className="text-text-muted">
          {v.profileVersion === null
            ? (t('privacy.notice.fromDefaults') || 'default rules')
            : (t('privacy.notice.fromProfile', { version: v.profileVersion }) || `profile version ${v.profileVersion}`)}
        </span>
        <button type="button" onClick={() => { void detail(); }} disabled={busy || v.acknowledgements === 0}
          className="text-accent hover:underline disabled:cursor-default disabled:text-text-muted disabled:no-underline coarse:min-h-10">
          {t('privacy.notice.acknowledgements', { count: v.acknowledgements }) || `${v.acknowledgements} acknowledgement(s)`}
        </button>
      </div>
      {acks && (
        <ul className="flex flex-wrap gap-x-4 text-text-muted">
          {NOTICE_ACK_CHANNELS.map((c) => <li key={c}>{ackChannelLabel(c)} <span className="text-text-primary">{acks.byChannel[c]}</span></li>)}
        </ul>
      )}
    </li>
  );
}
