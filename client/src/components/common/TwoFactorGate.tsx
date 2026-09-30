import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { TwoFactorPromptModal } from './TwoFactorPromptModal';
import { setTwoFactorListener, TWO_FACTOR_CANCELLED } from '@/utils/twoFactorGate';

// Mount this ONCE at the app root. It registers a listener the axios
// response interceptor calls into when the server demands a fresh 2FA
// code. The modal is displayed; on submit the pending promise resolves
// with the code so axios can retry the original request.
//
// No props — this component is intentionally a singleton. Its lifecycle
// is tied to the signed-in app shell.

// `reason` of `?reauth=failed&reason=<code>` (server: obligateCallback.routes.ts,
// /auth/sso-redirect?reauth=1 and completeReauth) → a precise message. An
// unknown or missing code keeps the generic one.
const REAUTH_FAILURE_REASONS: Record<string, string> = {
  no_otp: 'Enable two-factor authentication in your Obligate account first: the confirmation needs your password and a code.',
  identity: 'Another Obligate account was used. Confirm with the Obligate account you are signed in with here.',
  stale_auth: 'Obligate did not ask for a new sign-in. Try again and enter your password and code at Obligate.',
  unsupported: 'Confirmation with Obligate is not available on this server right now.',
  verifier_unavailable: 'Obligate could not confirm your account right now. Try again in a moment.',
  unreachable: 'Obligate cannot be reached right now. Try again in a moment.',
  cancelled: 'Confirmation cancelled at Obligate.',
  origin: 'Open Obliance at its public address to confirm with Obligate.',
  expired: 'The confirmation took too long (over 10 minutes). Try again.',
  signed_out: 'You were signed out meanwhile. Sign in again.',
  state: 'The confirmation could not be matched to this session. Try again from this page.',
  exchange: 'Obligate did not confirm the sign-in. Try again.',
  not_sso: 'This account does not sign in with Obligate: confirmation with Obligate does not apply.',
  misconfigured: 'Obligate is misconfigured on this server (it points to Obliance itself). Contact an administrator.',
  error: 'Obligate re-authentication failed. Try again.',
};

/** i18n key + English fallback of a `reason` code (the generic message for an unknown one). */
function reauthFailureKey(reason: string | null): [string, string] {
  if (reason && Object.prototype.hasOwnProperty.call(REAUTH_FAILURE_REASONS, reason)) {
    return [`deviceKeys.reauth.reason.${reason}`, REAUTH_FAILURE_REASONS[reason]];
  }
  return ['deviceKeys.reauth.failed', 'Obligate re-authentication failed. Try again.'];
}

interface Pending {
  actionLabel: string;
  currentIp?: string;
  trustIpAllowed?: boolean;
  codeMustBeNew?: boolean;
  mode?: 'code' | 'password';
  passwordRequired?: boolean;
  codeLocked?: boolean;
  reauthRequired?: boolean;
  resolve: (result: { code: string; trustIp: boolean; password?: string }) => void;
  reject: (err: Error) => void;
}

export function TwoFactorGate() {
  const { t } = useTranslation();
  const [pending, setPending] = useState<Pending | null>(null);

  useEffect(() => {
    setTwoFactorListener((p) => setPending(p as Pending));
    return () => setTwoFactorListener(null);
  }, []);

  // Back from an Obligate re-authentication (lot O, /auth/sso-redirect?reauth=1):
  // `?reauth=ok|failed&reason=<code>` is reported once, then removed from the address.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const outcome = params.get('reauth');
    if (outcome !== 'ok' && outcome !== 'failed') return;
    if (outcome === 'ok') {
      toast.success(t('deviceKeys.reauth.ok', 'Identity confirmed with Obligate for 5 minutes: run the action again and enter your code.'));
    } else {
      const [key, fallback] = reauthFailureKey(params.get('reason'));
      toast.error(t(key, fallback), { duration: 8000 });
    }
    params.delete('reauth');
    params.delete('reason');
    const q = params.toString();
    window.history.replaceState(window.history.state, '', window.location.pathname + (q ? `?${q}` : '') + window.location.hash);
  }, [t]);

  if (!pending) return null;

  return (
    <TwoFactorPromptModal
      actionLabel={pending.actionLabel}
      currentIp={pending.currentIp}
      trustIpAllowed={pending.trustIpAllowed !== false}
      codeMustBeNew={pending.codeMustBeNew === true}
      mode={pending.mode === 'password' ? 'password' : 'code'}
      passwordRequired={pending.passwordRequired === true}
      codeLocked={pending.codeLocked === true}
      reauthRequired={pending.reauthRequired === true}
      onClose={() => {
        pending.reject(new Error(TWO_FACTOR_CANCELLED));
        setPending(null);
      }}
      onSubmit={async (code, { trustIp, password }) => {
        pending.resolve({ code, trustIp, password });
        setPending(null);
      }}
    />
  );
}
