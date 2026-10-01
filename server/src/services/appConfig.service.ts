import { db } from '../db';
import { currentDbContext, switchToIdentity } from '../db/context';
import { vault } from '../vault';
import type { AppConfigData, ObligateConfig } from '@obligarth/shared';

// ── Platform settings of the modules ────────────────────────────────────────
// A module's own app_config keys (registerConfigKey): listed by getAll()
// after the core's, in registration order, and written through
// PUT /api/admin/config/:key (settingsWrite.service).

export interface ModuleConfigKey {
  key: string;
  /** 'boolean': 'true' / 'false' only; 'enum': one of `values`. Stored as is. */
  type: 'boolean' | 'enum';
  values?: readonly string[];
  /** The value getAll() returns, from the stored one (undefined when absent). */
  read: (stored: string | undefined) => string;
  /** Called once a new value is stored (e.g. a cache refreshed at once). */
  afterWrite?: (value: string) => void;
}

const moduleConfigKeys: ModuleConfigKey[] = [];

export function registerConfigKey(def: ModuleConfigKey): void {
  if (!/^[a-z0-9_]+$/.test(def.key)) throw new Error(`Invalid config key: ${def.key}`);
  if (moduleConfigKeys.some((k) => k.key === def.key)) throw new Error(`Config key '${def.key}' registered twice`);
  if (def.type === 'enum' && !def.values?.length) throw new Error(`Config key '${def.key}' has no values`);
  moduleConfigKeys.push(def);
}

/** A module's config key, if this is one. */
export function moduleConfigKey(key: string): ModuleConfigKey | undefined {
  return moduleConfigKeys.find((k) => k.key === key);
}

const OBLIGATE_CONFIG_KEY = 'obligate_config';

// ── Obligate settings helpers ─────────────────────────────────────────────
// The browser-facing /authorize client_id is always the public id
// sha256(api key) (obligateService.authorizeClientId): Obligate refuses the
// raw key there. The former 'raw' mode (setting clientIdMode, env
// OBLIGATE_CLIENT_ID_MODE) is gone; a stored or env value is ignored.
// Environment override (optional, harmless when unset):
//   OBLIGATE_INBOUND_SECRET — a secret distinct from the API key that Obligate
//     must present (Bearer) on its calls to this server. Unset → the Settings
//     value → the API key (today's behaviour).
// Storage (docs: coffre-secrets §7.3): app_config 'obligate_config' keeps the
// URL only; the API key and the inbound secret are instance secrets of the
// vault (obligate_api_key, obligate_inbound_secret), sealed under the
// instance DEK, never returned (flags only). The boot backfill moved the
// values an older version kept in clear in the JSON.
const OBLIGATE_API_KEY = 'obligate_api_key';
const OBLIGATE_INBOUND_SECRET = 'obligate_inbound_secret';

function currentUserId(): number | null {
  const actor = currentDbContext()?.actor;
  return actor?.type === 'user' ? actor.userId : null;
}

/** The URL kept in app_config 'obligate_config' (the JSON's only key). */
function parseObligateUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const url = (JSON.parse(raw) as { url?: unknown }).url;
    return typeof url === 'string' && url ? url : null;
  } catch {
    return null;
  }
}

interface ObligateStored {
  url: string | null;
  apiKey: string | null;
  inboundSecret: string | null;
}

function envInboundSecret(): string | null {
  const v = process.env.OBLIGATE_INBOUND_SECRET?.trim();
  return v ? v : null;
}
/** What the admin UI may see: flags, never a secret. */
function obligatePublicView(s: { url: string | null; apiKeySet: boolean; inboundSecretSet: boolean }, enabled: boolean): ObligateConfig {
  const envSecret = envInboundSecret();
  return {
    url: s.url,
    apiKeySet: s.apiKeySet,
    enabled,
    inboundSecretSet: !!envSecret || s.inboundSecretSet,
    inboundSecretFromEnv: !!envSecret,
  };
}
export const appConfigService = {
  async get(key: string): Promise<string | null> {
    const row = await db('app_config').where({ key }).first('value');
    return row?.value ?? null;
  },

  /** Platform settings are a catalog (rls-tenant §5.2): read in any
   *  context, written in the identity context (after the route's checks). */
  async set(key: string, value: string): Promise<void> {
    await switchToIdentity(() => db('app_config')
      .insert({ key, value })
      .onConflict('key')
      .merge({ value }));
  },

  /** The platform settings. The rows of the removed RMM's keys (the agent's
   *  automatic approval, push / fast-poll intervals and command poll delay,
   *  remote sessions, script schedules), seeded by migration 001, are never
   *  returned; they stay until the future base migration. */
  async getAll(): Promise<AppConfigData> {
    const rows = await db('app_config').select('key', 'value');
    const map = Object.fromEntries(rows.map((r: { key: string; value: string }) => [r.key, r.value]));

    /** Extract only the URL from a JSON config blob (never expose apiKey) */
    const parseUrl = (key: string): string | null => {
      if (!map[key]) return null;
      try { return (JSON.parse(map[key]) as { url?: string }).url || null; } catch { return null; }
    };

    const data: AppConfigData = {
      allow_2fa: map['allow_2fa'] ?? 'false',
      force_2fa: map['force_2fa'] ?? 'false',
      otp_smtp_server_id: map['otp_smtp_server_id'] ?? null,
      inventory_retention_days: map['inventory_retention_days'] ?? '90',
      app_name: map['app_name'] ?? 'Obligarth',
      default_language: map['default_language'] ?? 'en',
      obligate_url:     parseUrl(OBLIGATE_CONFIG_KEY),
      obligate_enabled: map['obligate_enabled'] ?? 'false',
      // Device-bound 2FA (§9 [D15]): on by default; read as === 'true'.
      device_keys_enabled: map['device_keys_enabled'] ?? 'true',
      device_keys_login: map['device_keys_login'] ?? 'true',
      device_keys_require_attestation: map['device_keys_require_attestation'] ?? 'true',
      device_keys_strict_session: map['device_keys_strict_session'] ?? 'true',
    };
    // The modules' keys (registerConfigKey), after the core's.
    for (const def of moduleConfigKeys) {
      (data as unknown as Record<string, string>)[def.key] = def.read(map[def.key]);
    }
    return data;
  },

  // ── Obligate SSO gateway ────────────────────────────────────────────────

  async getObligateConfig(): Promise<ObligateConfig> {
    const enabled = (await this.get('obligate_enabled')) === 'true';
    return obligatePublicView({
      url: parseObligateUrl(await this.get(OBLIGATE_CONFIG_KEY)),
      apiKeySet: await vault.hasInstanceSecret(OBLIGATE_API_KEY),
      inboundSecretSet: await vault.hasInstanceSecret(OBLIGATE_INBOUND_SECRET),
    }, enabled);
  },

  /**
   * Obligate settings as stored (URL in app_config 'obligate_config', the
   * secrets in the vault, opened here), without the environment overrides.
   * Internal: callers use getObligateRaw().
   */
  async readObligateStored(): Promise<ObligateStored> {
    const url = parseObligateUrl(await this.get(OBLIGATE_CONFIG_KEY));
    const apiKey = await vault.getInstanceSecret(OBLIGATE_API_KEY);
    const inboundSecret = await vault.getInstanceSecret(OBLIGATE_INBOUND_SECRET);
    return { url, apiKey: apiKey || null, inboundSecret: inboundSecret || null };
  },

  /**
   * Effective Obligate settings (environment overrides applied).
   *  - apiKey: the app's Obligate API key — outbound Bearer (this server →
   *    Obligate) and, unless an inbound secret is set, the secret Obligate
   *    presents on its calls to this server.
   *  - inboundSecret: optional distinct secret expected from Obligate.
   */
  async getObligateRaw(): Promise<{ url: string | null; apiKey: string | null; inboundSecret: string | null }> {
    const s = await this.readObligateStored();
    return {
      url: s.url,
      apiKey: s.apiKey,
      inboundSecret: envInboundSecret() ?? s.inboundSecret,
    };
  },

  /** url: replaced when given; apiKey: a non-empty string replaces it, absent
   *  or empty keeps it; inboundSecret: a non-empty string replaces it, null
   *  (or '') clears it, absent keeps it. One transaction, identity context
   *  (app_config is a catalog), the secrets sealed by the vault (audited by
   *  it: vault.instance_secret_changed). */
  async patchObligateConfig(patch: {
    url?: string | null; apiKey?: string | null; enabled?: boolean;
    inboundSecret?: string | null;
  }): Promise<ObligateConfig> {
    const actor = { userId: currentUserId() };
    await switchToIdentity(() => db.transaction(async (trx) => {
      const row = await trx('app_config').where({ key: OBLIGATE_CONFIG_KEY }).forUpdate().first('value') as { value: string } | undefined;
      const url = 'url' in patch ? (patch.url ?? null) : parseObligateUrl(row?.value);
      const value = JSON.stringify({ url });
      await trx('app_config').insert({ key: OBLIGATE_CONFIG_KEY, value }).onConflict('key').merge({ value });
      if ('apiKey' in patch && typeof patch.apiKey === 'string' && patch.apiKey) {
        await vault.setInstanceSecret(OBLIGATE_API_KEY, patch.apiKey, actor, { trx });
      }
      if ('inboundSecret' in patch) {
        const v = typeof patch.inboundSecret === 'string' && patch.inboundSecret ? patch.inboundSecret : null;
        await vault.setInstanceSecret(OBLIGATE_INBOUND_SECRET, v, actor, { trx });
      }
      if ('enabled' in patch) {
        const enabledValue = patch.enabled ? 'true' : 'false';
        await trx('app_config').insert({ key: 'obligate_enabled', value: enabledValue }).onConflict('key').merge({ value: enabledValue });
      }
    }));
    return this.getObligateConfig();
  },
};
