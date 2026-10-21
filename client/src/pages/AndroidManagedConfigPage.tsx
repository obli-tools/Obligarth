import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, Plus, SlidersHorizontal, X } from 'lucide-react';
import { ANDROID_IFRAME_EVENTS, type AndroidAppDetail, type Assignment } from '@obligarth/shared';
import { androidApi } from '@/api/android.api';
import { mdmApi } from '@/api/mdm.api';
import { Button } from '@/components/common/Button';
import { PageContainer } from '@/components/common/PageContainer';
import { AndroidAssignmentEditDialog, AssignmentCreateDialog, targetLabel } from '@/components/mdm/Assignments';
import { useOwnDocument } from '@/hooks/useOwnDocument';
import { eventField, openGoogleFrame } from '@/utils/googleIframes';
import { apiErrorMessage } from '@/utils/apiError';

// The managed configuration of an Android app by Google's iframe (android-amapi §9.6, CFG-11; lot AN-E): the
// MANAGED_CONFIGURATIONS iframe of managed Google Play for this app of the tenant's catalog (parentFrameUrl: this page),
// where the administrator creates or edits a configuration (OEMConfig apps are configured here only). Its event
// onconfigupdated names the configuration saved (mcmId, digits only): the page then applies it to an assignment of the
// app (managedConfigurationTemplate.templateId, through the assignments' preview and guard) or assigns the app with it.
// The configuration itself stays at Google: Obligarth keeps its id only. Capability mdm.apps.manage.

const MCM_RE = /^[0-9]{1,20}$/;

export function AndroidManagedConfigPage() {
  const own = useOwnDocument();
  const { t, i18n } = useTranslation();
  const { uuid = '' } = useParams();
  const { pathname } = useLocation();
  const [app, setApp] = useState<AndroidAppDetail | null>(null);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [frameError, setFrameError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [opening, setOpening] = useState(false);
  const [chosen, setChosen] = useState<{ mcmId: string; name: string | null } | null>(null);
  const [applyTo, setApplyTo] = useState<Assignment | null>(null);
  const [creating, setCreating] = useState(false);
  const frameRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<(() => void) | null>(null);

  const load = useCallback(() => {
    androidApi.app(uuid).then((a) => {
      setApp(a); setError(null);
      mdmApi.listAssignments({ resourceType: 'app', resourceId: a.id }).then((l) => setAssignments(l.filter((x) => x.mode === 'include'))).catch(() => setAssignments([]));
    }).catch((err) => setError(apiErrorMessage(err)));
  }, [uuid]);
  useEffect(() => { if (own) load(); }, [own, load]);
  useEffect(() => () => { closeRef.current?.(); }, []);

  const openFrame = async () => {
    if (!app) return;
    closeRef.current?.();
    setFrameError(null);
    setOpening(true);
    setOpen(true);
    try {
      const tk = await androidApi.iframeToken({ screen: 'managed_config', parentPath: pathname, appId: app.uuid, locale: i18n.language });
      if (!frameRef.current) return;
      closeRef.current = await openGoogleFrame(frameRef.current, tk.iframeUrl, t('androidApps.config.frameTitle') || 'Managed configuration', {
        [ANDROID_IFRAME_EVENTS.configUpdated]: (payload) => {
          const mcmId = eventField(payload, 'mcmId', MCM_RE);
          if (mcmId) setChosen({ mcmId, name: eventField(payload, 'name', /^[^\u0000-\u001f]{1,200}$/) });
        },
        [ANDROID_IFRAME_EVENTS.configDeleted]: (payload) => {
          const mcmId = eventField(payload, 'mcmId', MCM_RE);
          setChosen((c) => (c && c.mcmId === mcmId ? null : c));
        },
      });
    } catch (err) {
      setOpen(false);
      setFrameError(err instanceof Error && /^gapi/.test(err.message) ? (t('androidApps.gapiFailed') || 'Google\'s iframe library could not be loaded.') : apiErrorMessage(err));
    } finally { setOpening(false); }
  };
  const closeFrame = () => { closeRef.current?.(); closeRef.current = null; setOpen(false); };

  // Stable while the dialog is open (the dialog starts again from them when they change).
  const template = useMemo(() => (chosen ? { managedConfigurationTemplate: { templateId: chosen.mcmId } } : undefined), [chosen]);
  const resource = useMemo(() => (app ? { id: app.id, tenantId: app.tenantId, name: app.name, type: 'app' as const, android: app } : undefined), [app]);

  if (!own) return <PageContainer><p className="text-sm text-text-muted italic">{t('common.loading') || 'Loading…'}</p></PageContainer>;
  return (
    <PageContainer className="space-y-4">
      <Link to={`/apps/android?app=${encodeURIComponent(uuid)}`} className="inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary coarse:min-h-10">
        <ArrowLeft size={14} />{t('androidApps.config.back') || 'Back to the app'}
      </Link>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {app && (
        <>
          <div>
            <h1 className="text-2xl font-bold text-text-primary">{t('androidApps.config.title', { name: app.name }) || `Managed configuration of ${app.name}`}</h1>
            <p className="mt-1 text-sm text-text-muted">{t('androidApps.config.subtitle') || 'Create or edit a configuration in Google\'s iframe, then apply it to an assignment of the app. The configuration stays at Google: Obligarth keeps its id only.'}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {!open && <Button disabled={opening || app.kind === 'web'} onClick={() => void openFrame()}><SlidersHorizontal className="w-4 h-4 mr-1" />{t('androidApps.config.open') || 'Open the configurations'}</Button>}
            {open && <Button variant="ghost" onClick={closeFrame}><X className="w-4 h-4 mr-1" />{t('androidApps.play.close') || 'Close'}</Button>}
          </div>
          {frameError && <p className="text-sm text-red-400">{frameError}</p>}
          <div ref={frameRef} className={open ? 'h-[65vh] w-full overflow-hidden rounded-lg border border-border bg-white' : 'hidden'} data-testid="android-mcm-frame" />
          {chosen && (
            <section className="space-y-2 rounded-lg border border-border bg-bg-secondary p-4 text-sm">
              <p className="text-text-primary">
                {t('androidApps.config.chosen', { name: chosen.name ?? chosen.mcmId, id: chosen.mcmId }) || `Configuration « ${chosen.name ?? chosen.mcmId} » (id ${chosen.mcmId}) saved.`}
              </p>
              {assignments.length === 0 ? <p className="text-xs text-text-muted">{t('androidApps.config.noAssignment') || 'The app has no assignment yet.'}</p> : (
                <ul className="divide-y divide-border/50 rounded bg-bg-primary/40">
                  {assignments.map((a) => (
                    <li key={a.id} className="flex items-center gap-2 px-3 py-2">
                      <span className="flex-1 truncate">{targetLabel(t, a)}</span>
                      <Button size="sm" variant="secondary" onClick={() => setApplyTo(a)}>{t('androidApps.config.apply') || 'Apply to this assignment'}</Button>
                    </li>
                  ))}
                </ul>
              )}
              <Button size="sm" onClick={() => setCreating(true)}><Plus className="w-4 h-4 mr-1" />{t('androidApps.config.assignWith') || 'Assign the app with this configuration'}</Button>
            </section>
          )}
          {applyTo && chosen && (
            <AndroidAssignmentEditDialog app={app} assignment={applyTo} patch={{ configMode: 'template', templateId: chosen.mcmId }}
              onClose={() => setApplyTo(null)} onDone={() => load()} />
          )}
          <AssignmentCreateDialog open={creating} onClose={() => setCreating(false)} initialAndroidOptions={template}
            resource={resource} onDone={() => load()} />
        </>
      )}
    </PageContainer>
  );
}
