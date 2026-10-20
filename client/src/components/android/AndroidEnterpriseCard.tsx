import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { CheckCircle2, CircleDashed, ExternalLink, Link2, RefreshCw, Smartphone, Unlink } from 'lucide-react';
import {
  ANDROID_PUBLISHER_TERMS_VERSION, ANDROID_SIGNIN_PERSONAL_USAGE,
  type AndroidDeadline, type AndroidOffboardingView, type AndroidOnboardingView, type AndroidSigninConfig,
} from '@obligarth/shared';
import { androidApi, type AndroidEnterpriseCard as Enterprise } from '@/api/android.api';
import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { usePrompt } from '@/components/common/ConfirmDialog';
import { StateBadge } from '@/components/mdm/DeviceStateBadges';
import { useAuthStore } from '@/store/authStore';
import { trCode } from '@/utils/apiError';
import { openExternal } from '@/utils/openExternal';
import { AndroidCard, Fact, Labeled, dateOf, errorToast, fieldClass } from './ui';

// The « Android Enterprise » card of the Integrations page (android-amapi §6, §12.1; lot AN-C2): the state of the
// tenant's enterprise, the linking assistant (domain, terms of the publisher, Google's flow in a new tab, wait for the
// return), the Android part of the onboarding assistant, the deadlines, the sign-in URL, the unlink (a restricted
// request) and the offboarding with the client's guide. Never a Google token: the server keeps them.

type Tone = 'green' | 'gray' | 'blue' | 'amber' | 'red';
const STATE_TONE: Record<string, Tone> = { linked: 'green', pending: 'blue', unlinking: 'amber', unlinked: 'gray', error: 'red' };
const DEADLINE_TONE: Record<AndroidDeadline['status'], Tone> = { ok: 'green', warning: 'amber', overdue: 'red' };

const ONBOARD_FALLBACK: Record<string, string> = {
  'android.onboarding.identity': 'Google identity of the instance',
  'android.onboarding.enterprise_linked': 'Android enterprise linked',
  'android.onboarding.topic_set': 'Notifications of the enterprise set',
  'android.onboarding.test_message': 'First notification received',
  'android.onboarding.enrollment_profile': 'Android enrollment profile ready',
  'android.onboarding.first_device': 'First Android device enrolled',
};

export function AndroidEnterpriseCard() {
  const { t } = useTranslation();
  const prompt = usePrompt();
  const { isAdmin, permissions } = useAuthStore();
  const canManage = isAdmin() || (permissions?.tenantCapabilities ?? []).includes('mdm.integrations.manage');
  const [e, setE] = useState<Enterprise | null | undefined>(undefined);
  const [disabled, setDisabled] = useState<string | null>(null);
  const [onboarding, setOnboarding] = useState<AndroidOnboardingView | null>(null);
  const [deadlines, setDeadlines] = useState<AndroidDeadline[]>([]);
  const [offboarding, setOffboarding] = useState<AndroidOffboardingView | null>(null);
  const [signin, setSignin] = useState<AndroidSigninConfig | null>(null);
  const [wizard, setWizard] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const card = await androidApi.enterprise();
      setE(card);
      setDisabled(null);
      const live = card && card.state !== 'unlinked';
      const [o, d, off, s] = await Promise.all([
        androidApi.onboarding().catch(() => null),
        live ? androidApi.deadlines().catch(() => []) : Promise.resolve([] as AndroidDeadline[]),
        live || card?.state === 'unlinked' ? androidApi.offboarding().catch(() => null) : Promise.resolve(null),
        card?.state === 'linked' ? androidApi.signin().catch(() => null) : Promise.resolve(null),
      ]);
      setOnboarding(o);
      setDeadlines(d);
      setOffboarding(off);
      setSignin(s);
    } catch (err) {
      const code = (err as { response?: { data?: { code?: string } } })?.response?.data?.code;
      setE(null);
      setDisabled(code ?? 'error');
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const run = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try { await fn(); toast.success(done, { duration: 6000 }); await load(); } catch (err) { errorToast(err); } finally { setBusy(false); }
  };

  const askReason = async (title: string): Promise<string | null> => prompt({
    title, message: t('android.enterprise.reasonHint') || 'Reason (kept in the audit journal, shown to the second approver).',
    multiline: true, required: true,
  });

  const unlink = async () => {
    const reason = await askReason(t('android.enterprise.unlinkTitle') || 'Unlink the Android enterprise');
    if (reason) await run(() => androidApi.unlink(reason), t('android.enterprise.unlinkRequested') || 'Unlink requested: a second approver must approve it.');
  };
  const forceUnlink = async () => {
    const reason = await askReason(t('android.enterprise.forceUnlinkTitle') || 'Go on without the devices left');
    if (reason) await run(() => androidApi.forceUnlink(reason), t('android.enterprise.unlinkRequested') || 'Unlink requested: a second approver must approve it.');
  };

  const state = e?.state ?? 'none';
  const linkable = e === null || e?.state === 'unlinked';
  return (
    <AndroidCard
      title={t('android.enterprise.title') || 'Android Enterprise'}
      icon={<Smartphone className="w-5 h-5 text-accent" />}
      badge={e !== undefined && <StateBadge tone={STATE_TONE[state] ?? 'gray'} label={trCode(`android.enterprise.state.${state}`, state)} />}
      action={(
        <>
          <Button size="sm" variant="secondary" onClick={() => void load()} aria-label={t('common.refresh') || 'Refresh'}><RefreshCw className="w-4 h-4" /></Button>
          {canManage && linkable && !disabled && (
            <Button size="sm" onClick={() => setWizard(true)}><Link2 className="w-4 h-4 mr-1" />{t('android.enterprise.link') || 'Link'}</Button>
          )}
        </>
      )}
    >
      {disabled && (
        <p className="text-sm text-text-muted">{trCode(`errors.${disabled}`, t('android.enterprise.unavailable') || 'Android is not available on this instance.')}</p>
      )}
      {!disabled && linkable && (
        <p className="text-sm text-text-muted">
          {t('android.enterprise.linkHelp') || 'Link the managed Google Play account of this client (its domain) to enroll Android devices. Google opens in a new tab; the card turns « linked » once Google sends the browser back.'}
        </p>
      )}
      {e && e.state !== 'unlinked' && (
        <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-3">
          <Fact label={t('android.enterprise.type') || 'Type'}>{e.enterpriseType ? trCode(`android.enterprise.enterpriseType.${e.enterpriseType}`, e.enterpriseType) : '—'}</Fact>
          <Fact label={t('android.enterprise.domain') || 'Domain'}>{e.adminDomain ?? '—'}</Fact>
          <Fact label={t('android.enterprise.displayName') || 'Name shown on the devices'}>{e.displayName ?? '—'}</Fact>
          <Fact label={t('android.enterprise.linkedAt') || 'Linked'}>{dateOf(e.linkedAt)}</Fact>
          <Fact label={t('android.enterprise.topic') || 'Notifications'}>
            {e.topicSet ? (t('android.enterprise.topicSet') || 'set') : (t('android.enterprise.topicPending') || 'being set')}
          </Fact>
          <Fact label={t('android.enterprise.testMessage') || 'Last test notification'}>{dateOf(e.testMessageAt)}</Fact>
        </dl>
      )}
      {e?.state === 'linked' && (
        <p className="rounded border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-text-secondary">
          {t('android.enterprise.backupAdmins') || 'Reminder: the client keeps at least two administrators of its managed Google Play account (its own accounts). Without them, nobody can recover the enterprise if this instance loses its access.'}
        </p>
      )}
      {e?.state === 'error' && (
        <div className="space-y-2 rounded border border-red-500/30 bg-red-500/5 p-2 text-sm">
          <p className="text-text-secondary">{t('android.enterprise.errorHelp') || 'Google refuses the access of this instance to the enterprise (unlinked from the client\'s Google console, or deleted). Check again, or confirm that it was unlinked outside Obligarth.'}</p>
          {canManage && (
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => void run(() => androidApi.recheck(), t('android.enterprise.rechecked') || 'Checked again')}>
                {t('android.enterprise.recheck') || 'Check again'}
              </Button>
              <Button size="sm" variant="danger" disabled={busy} onClick={() => void run(() => androidApi.confirmExternalUnlink(), t('android.enterprise.externalConfirmed') || 'Unlink confirmed')}>
                {t('android.enterprise.confirmExternal') || 'Confirm the unlink'}
              </Button>
            </div>
          )}
        </div>
      )}

      {onboarding && <Onboarding steps={onboarding.steps} />}
      {deadlines.length > 0 && (
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">{t('android.enterprise.deadlines') || 'Deadlines'}</h3>
          <ul className="space-y-1 text-sm">
            {deadlines.map((d) => (
              <li key={`${d.kind}:${d.ref ?? ''}`} className="flex flex-wrap items-center gap-2">
                <StateBadge tone={DEADLINE_TONE[d.status]} label={trCode(`android.deadlines.status.${d.status}`, d.status)} />
                <span className="text-text-primary">{trCode(`android.deadlines.kind.${d.kind}`, d.kind)}</span>
                <span className="text-xs text-text-muted">{dateOf(d.dueAt)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {signin && <SigninPanel config={signin} canManage={canManage} onSaved={setSignin} />}
      {offboarding && <Offboarding view={offboarding} canManage={canManage} busy={busy} onForce={() => void forceUnlink()} />}

      {canManage && e?.state === 'linked' && (
        <div className="flex flex-wrap gap-2 border-t border-border pt-3">
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => void run(() => androidApi.reconcile(), t('android.enterprise.reconcileRequested') || 'Reconciliation requested: it runs within the minute.')}>
            <RefreshCw className="w-4 h-4 mr-1" />{t('android.enterprise.reconcile') || 'Reconcile now'}
          </Button>
          <Button size="sm" variant="danger" disabled={busy} onClick={() => void unlink()}>
            <Unlink className="w-4 h-4 mr-1" />{t('android.enterprise.unlink') || 'Unlink…'}
          </Button>
        </div>
      )}

      <SignupWizard open={wizard} onClose={() => setWizard(false)} onLinked={() => { setWizard(false); void load(); }} />
    </AndroidCard>
  );
}

function Onboarding({ steps }: { steps: AndroidOnboardingView['steps'] }) {
  const { t } = useTranslation();
  if (steps.every((s) => s.done)) return null;
  return (
    <div>
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">{t('android.onboarding.title') || 'Getting Android ready'}</h3>
      <ul className="grid gap-1 sm:grid-cols-2">
        {steps.map((s) => (
          <li key={s.key} className="flex items-center gap-2 text-sm">
            {s.done ? <CheckCircle2 className="w-4 h-4 text-status-up" /> : <CircleDashed className="w-4 h-4 text-text-muted" />}
            <span className={s.done ? 'text-text-primary' : 'text-text-secondary'}>{trCode(s.key, ONBOARD_FALLBACK[s.key] ?? s.key)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SigninPanel({ config, canManage, onSaved }: { config: AndroidSigninConfig; canManage: boolean; onSaved: (c: AndroidSigninConfig) => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [usage, setUsage] = useState<string>(config.allowPersonalUsage ?? 'PERSONAL_USAGE_DISALLOWED');
  const save = async (enabled: boolean) => {
    setBusy(true);
    try {
      onSaved(await androidApi.configureSignin({ enabled, ...(enabled ? { allowPersonalUsage: usage as typeof ANDROID_SIGNIN_PERSONAL_USAGE[number] } : {}) }));
      toast.success(t('android.signin.saved') || 'Sign-in enrollment saved');
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-2 rounded border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-text-primary">{t('android.signin.title') || 'Enrollment by Google sign-in'}</h3>
        <StateBadge tone={config.enabled ? 'green' : 'gray'} label={config.enabled ? (t('android.signin.enabled') || 'enabled') : (t('android.signin.disabled') || 'disabled')} />
      </div>
      <p className="text-xs text-text-muted">{t('android.signin.help') || 'A user who adds a work account on a new device is sent to Obligarth to authenticate (Obligate), then receives a single-use enrollment.'}</p>
      {config.signinUrl && <p className="font-mono text-xs break-all text-text-secondary">{config.signinUrl}</p>}
      {canManage && (
        <div className="flex flex-wrap items-end gap-2">
          <Labeled label={t('android.signin.personalUsage') || 'Personal use'}>
            <select value={usage} onChange={(ev) => setUsage(ev.target.value)} className={fieldClass} disabled={busy}>
              {ANDROID_SIGNIN_PERSONAL_USAGE.map((u) => <option key={u} value={u}>{trCode(`android.signin.usage.${u}`, u)}</option>)}
            </select>
          </Labeled>
          <Button size="sm" disabled={busy} onClick={() => void save(true)}>{config.enabled ? (t('common.save') || 'Save') : (t('android.signin.enable') || 'Enable')}</Button>
          {config.enabled && <Button size="sm" variant="secondary" disabled={busy} onClick={() => void save(false)}>{t('android.signin.disable') || 'Disable'}</Button>}
        </div>
      )}
    </div>
  );
}

function Offboarding({ view, canManage, busy, onForce }: { view: AndroidOffboardingView; canManage: boolean; busy: boolean; onForce: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-2 rounded border border-amber-500/30 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-text-primary">{t('android.offboarding.title') || 'Unlink in progress'}</h3>
        <StateBadge tone={view.step === 'done' ? 'green' : 'amber'} label={trCode(`android.offboarding.step.${view.step}`, view.step)} />
        <span className="text-xs text-text-muted">{dateOf(view.startedAt)}</span>
      </div>
      {view.step !== 'done' && (
        <p className="text-sm text-text-secondary">
          {t('android.offboarding.devicesLeft', { count: view.devicesLeft }) || `${view.devicesLeft} device(s) still managed`}
        </p>
      )}
      {view.releaseFailed && <p className="text-sm text-status-down">{t('android.offboarding.releaseFailed') || 'Google refused the release of the enterprise: it is retried.'}</p>}
      {canManage && view.step === 'waiting_devices' && !view.forced && (
        <Button size="sm" variant="danger" disabled={busy} onClick={onForce}>{t('android.offboarding.force') || 'Go on without the devices left…'}</Button>
      )}
      {view.step === 'done' && view.guide.length > 0 && (
        <ol className="list-decimal space-y-0.5 pl-5 text-sm text-text-secondary">
          {view.guide.map((k) => <li key={k}>{trCode(k, k)}</li>)}
        </ol>
      )}
    </div>
  );
}

// ── Linking assistant (§6.2, AN35) ─────────────────────────────────────────────

function SignupWizard({ open, onClose, onLinked }: { open: boolean; onClose: () => void; onLinked: () => void }) {
  const { t } = useTranslation();
  const [domain, setDomain] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [color, setColor] = useState('#2563eb');
  const [terms, setTerms] = useState(false);
  const [onBehalf, setOnBehalf] = useState('');
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (!open) { setUrl(null); setTerms(false); return; }
  }, [open]);
  // Waiting for Google's return: the card is read again every 5 seconds while the assistant stays open.
  useEffect(() => {
    if (!open || !url) return;
    timer.current = window.setInterval(() => {
      androidApi.enterprise().then((e) => { if (e?.state === 'linked') { toast.success(t('android.signup.linked') || 'Android enterprise linked'); onLinked(); } }).catch(() => { /* next tick */ });
    }, 5000);
    return () => { if (timer.current) window.clearInterval(timer.current); };
  }, [open, url, onLinked, t]);

  const start = async () => {
    setBusy(true);
    try {
      const r = await androidApi.startSignup({
        domain: domain.trim().toLowerCase(), displayName: displayName.trim(), termsAccepted: terms, termsVersion: ANDROID_PUBLISHER_TERMS_VERSION,
        ...(adminEmail.trim() ? { adminEmail: adminEmail.trim() } : {}),
        ...(/^#[0-9a-f]{6}$/i.test(color) ? { primaryColor: Number.parseInt(color.slice(1), 16) } : {}),
        ...(onBehalf.trim() ? { onBehalfReason: onBehalf.trim() } : {}),
      });
      setUrl(r.url);
      void openExternal(r.url);
    } catch (err) { errorToast(err); } finally { setBusy(false); }
  };

  const ready = domain.trim().length >= 3 && displayName.trim().length > 0 && terms;
  return (
    <Modal open={open} onClose={onClose} size="lg" title={t('android.signup.title') || 'Link an Android enterprise'}
      footer={url ? <Button variant="secondary" onClick={onClose}>{t('common.close') || 'Close'}</Button> : (
        <>
          <Button variant="secondary" onClick={onClose}>{t('common.cancel') || 'Cancel'}</Button>
          <Button disabled={!ready || busy} onClick={() => void start()}><ExternalLink className="w-4 h-4 mr-1" />{t('android.signup.start') || 'Continue at Google'}</Button>
        </>
      )}>
      {url ? (
        <div className="space-y-3 text-sm">
          <p className="text-text-secondary">{t('android.signup.waiting') || 'Google opened in a new tab: the client\'s administrator signs in with an account of the domain and accepts the terms of managed Google Play. This window updates once Google sends the browser back (the link is valid for one hour).'}</p>
          <p className="flex items-center gap-2 text-text-muted"><RefreshCw className="w-4 h-4 animate-spin" />{t('android.signup.waitingShort') || 'Waiting for Google…'}</p>
          <Button size="sm" variant="secondary" onClick={() => void openExternal(url)}><ExternalLink className="w-4 h-4 mr-1" />{t('android.signup.openAgain') || 'Open Google again'}</Button>
        </div>
      ) : (
        <div className="space-y-3">
          <Labeled label={t('android.signup.domain') || 'Domain of the client'} hint={t('android.signup.domainHint') || 'A domain the client owns (never a public mail domain): Google checks it.'}>
            <input value={domain} onChange={(ev) => setDomain(ev.target.value)} maxLength={253} className={fieldClass} placeholder={t('android.signup.domainPlaceholder') || 'example.com'} />
          </Labeled>
          <Labeled label={t('android.signup.adminEmail') || 'E-mail of the client\'s administrator (optional)'}>
            <input value={adminEmail} onChange={(ev) => setAdminEmail(ev.target.value)} maxLength={320} className={fieldClass} type="email" />
          </Labeled>
          <Labeled label={t('android.signup.displayName') || 'Name shown on the devices'}>
            <input value={displayName} onChange={(ev) => setDisplayName(ev.target.value)} maxLength={100} className={fieldClass} />
          </Labeled>
          <Labeled label={t('android.signup.color') || 'Color'}>
            <input type="color" value={color} onChange={(ev) => setColor(ev.target.value)} className="h-9 w-16 rounded border border-border bg-bg-secondary" />
          </Labeled>
          <Labeled label={t('android.signup.onBehalf') || 'You act for the client: reason (optional, audited)'}>
            <input value={onBehalf} onChange={(ev) => setOnBehalf(ev.target.value)} maxLength={500} className={fieldClass} />
          </Labeled>
          <label className="flex items-start gap-2 text-sm text-text-secondary">
            <input type="checkbox" checked={terms} onChange={(ev) => setTerms(ev.target.checked)} className="mt-0.5 accent-accent" />
            <span>{t('android.signup.terms', { version: ANDROID_PUBLISHER_TERMS_VERSION }) || `The client accepts the terms of the publisher (version ${ANDROID_PUBLISHER_TERMS_VERSION}) for the management of its Android devices by this instance.`}</span>
          </label>
        </div>
      )}
    </Modal>
  );
}

