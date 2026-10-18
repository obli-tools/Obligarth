// The authentication of the user of a sign-in URL flow (lot AN-F2, section 10.5: « authentifie l'utilisateur par
// Obligate »): an authorization request to Obligate (the browser of the device is sent to its /authorize page with the
// public client id, a redirect_uri on the device surface and a state), then the server-to-server exchange of the code
// it returns (single use, bound to the redirect_uri). The default provider uses the Obligate settings of the instance
// (app_config and the vault, as /auth/sso-redirect and /auth/callback do); the junction may replace it
// (setSigninIdentityProvider: a provider of Obligate dedicated to the end users, once Obligate offers one), the testbed
// does. The e-mail of provisioningInfo (authenticatedUserEmail) is only a login hint: never stored, never logged.
import { appConfigService } from '../../services/appConfig.service';
import { obligateService } from '../../services/obligate.service';

export interface SigninIdentity {
  /** The identity Obligate authenticated: its e-mail (compared, lowercased, with the end users of the tenant). */
  email: string;
  /** Obligate's id of the identity (audited, never shown to the device). */
  subject: string;
}

export interface SigninIdentityProvider {
  /** The origin of the authorization page (the CSP of the notice page lets its form be redirected there), or null
   *  when no provider is configured. */
  origin(): Promise<string | null>;
  /** The URL of the authorization request, or null when no provider is configured. */
  authorizeUrl(a: { state: string; redirectUri: string; loginHint?: string }): Promise<string | null>;
  /** The identity of an answer (the code exchanged once, bound to the redirect_uri), or null when refused. */
  exchange(code: string, redirectUri: string): Promise<SigninIdentity | null>;
}

const EMAIL_RE = /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
/** Is it a plausible e-mail (a hint is sent only then)? */
export const isEmail = (v: unknown): v is string => typeof v === 'string' && v.length <= 320 && EMAIL_RE.test(v);

const httpsOrigin = (url: string | null): string | null => {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;
  } catch {
    return null;
  }
};

/** The provider of the instance's Obligate settings (the same client as the console's SSO). */
export const obligateSigninProvider: SigninIdentityProvider = {
  async origin() {
    const raw = await appConfigService.getObligateRaw();
    return raw.apiKey ? httpsOrigin(raw.url) : null;
  },
  async authorizeUrl(a) {
    const raw = await appConfigService.getObligateRaw();
    const clientId = obligateService.authorizeClientId(raw);
    const origin = httpsOrigin(raw.url);
    if (!origin || !clientId) return null;
    const u = new URL('/authorize', raw.url!.replace(/\/+$/, '') + '/');
    u.searchParams.set('client_id', clientId);
    u.searchParams.set('redirect_uri', a.redirectUri);
    u.searchParams.set('state', a.state);
    if (a.loginHint && isEmail(a.loginHint)) u.searchParams.set('login_hint', a.loginHint);
    return u.toString();
  },
  async exchange(code, redirectUri) {
    const r = await obligateService.exchangeCode(code, redirectUri);
    if (!r || !isEmail(r.email)) return null;
    return { email: r.email, subject: String(r.obligateUserId) };
  },
};

let provider: SigninIdentityProvider = obligateSigninProvider;

/** The junction (or the testbed) plugs another provider. */
export function setSigninIdentityProvider(p: SigninIdentityProvider): void { provider = p; }
export function resetSigninIdentityProvider(): void { provider = obligateSigninProvider; }
export const signinIdentity = (): SigninIdentityProvider => provider;
