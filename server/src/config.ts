import './env';

function publicUrlFromEnv(): string {
  const appUrl = (process.env.APP_URL || '').trim();
  if (appUrl) return appUrl.replace(/\/+$/, '');
  const clientOrigin = (process.env.CLIENT_ORIGIN || '').trim();
  try {
    const host = new URL(clientOrigin).hostname;
    if (host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127\./.test(host)) return '';
  } catch {
    return '';
  }
  return clientOrigin.replace(/\/+$/, '');
}

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isDev: process.env.NODE_ENV !== 'production',
  databaseUrl: process.env.DATABASE_URL || 'postgres://obliance:changeme@localhost:5432/obliance',
  sessionSecret: process.env.SESSION_SECRET || 'change-this-secret',
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  forceHttps: process.env.FORCE_HTTPS === 'true',
  appName: process.env.APP_NAME || 'Obliance',
  appUrl: process.env.APP_URL || '',
  // The public address of this instance: APP_URL, else CLIENT_ORIGIN when the
  // operator set it explicitly (in the Docker deployment both name the same
  // origin: nginx serves the web client and proxies the API). Never the dev
  // default above, never derived from a request header.
  publicUrl: publicUrlFromEnv(),
  // Default admin credentials — only consulted on a fresh DB. The
  // password defaults to the canonical "admin123" so dev installs Just
  // Work, but `ensureDefaultAdmin` refuses to bootstrap if the password
  // is still the default OR shorter than 12 characters (see
  // index.ts:ensureDefaultAdmin). Production installs MUST set
  // DEFAULT_ADMIN_PASSWORD via env.
  defaultAdminUsername: process.env.DEFAULT_ADMIN_USERNAME || 'admin',
  defaultAdminPassword: process.env.DEFAULT_ADMIN_PASSWORD || 'admin123',
  disable2faForce: process.env.DISABLE_2FA_FORCE === 'true',
  minPushInterval: parseInt(process.env.MIN_PUSH_INTERVAL || '10', 10),
  customDir: process.env.CUSTOM_DIR || './custom',
  // Remote access
  remoteTunnelPath: '/api/remote/tunnel',
  // SSH Bastion (ObliJump) — opt-in via .env, like the Oblihub stacks. The
  // ssh2 server only binds when enabled; SSH_BASTION_PORT must NOT be 22 (that
  // stays the host sshd). This port is the one guarded by the IP whitelist,
  // anti-bruteforce and honeypot.
  sshBastion: {
    enabled: process.env.SSH_BASTION_ENABLED === 'true',
    port: parseInt(process.env.SSH_BASTION_PORT || '2222', 10),
  },
  // Device-bound 2FA (docs/mobile/device-bound-2fa.md §9). Parsed and
  // validated by services/deviceKey/deviceKey.service.ts.
  deviceKeys: {
    /** Emergency switch, overrides the platform settings. */
    disabled: process.env.DEVICE_KEYS_DISABLED === 'true',
    /** Extra enrolment origins (comma-separated), next to APP_URL [D17]. */
    origins: process.env.DEVICE_KEY_ORIGINS || '',
    /** Accepted app packages (comma-separated); default tools.obli.obliance.next. */
    appIds: process.env.DEVICE_KEY_APP_IDS || '',
    /** Accepted APK signer SHA-256 digests (comma-separated, ':' ignored);
     *  default: the release signer. A debug signer is added here only on a
     *  development server [D19]. */
    appSigners: process.env.DEVICE_KEY_APP_SIGNERS || '',
    /** Secret of the request-binding body key (HMAC, §4.5 v2); empty →
     *  derived from SESSION_SECRET. Never stored in the database. */
    bindingSecret: process.env.DEVICE_KEY_BINDING_SECRET || '',
    /** Lot O opt-in (SSO / Obligate accounts): OFF unless exactly 'true'.
     *  While off, Obligate's capabilities are never read and SSO accounts
     *  keep today's behaviour (no phone key, no consuming verify-totp). */
    ssoEnabled: process.env.DEVICE_KEYS_SSO_ENABLED === 'true',
  },
};
