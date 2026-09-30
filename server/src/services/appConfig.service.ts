import { db } from '../db';
import type { AppConfigData, DeviceNotificationTypes, ObligateConfig } from '@obliance/shared';

// ── Platform settings of the modules ────────────────────────────────────────
// A module's own app_config keys (registerConfigKey; modules/rmm.ts for the
// RMM's): listed by getAll() after the core's, in registration order, and
// written through PUT /api/admin/config/:key (settingsWrite.service).

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

const AGENT_GLOBAL_CONFIG_KEY = 'agent_global_config';
const OBLIGATE_CONFIG_KEY     = 'obligate_config';

// ── Obligate settings helpers ─────────────────────────────────────────────
// The browser-facing /authorize client_id is always the public id
// sha256(api key) (obligateService.authorizeClientId): Obligate refuses the
// raw key there. The former 'raw' mode (setting clientIdMode, env
// OBLIGATE_CLIENT_ID_MODE) is gone; a stored or env value is ignored.
// Environment override (optional, harmless when unset):
//   OBLIGATE_INBOUND_SECRET — a secret distinct from the API key that Obligate
//     must present (Bearer) on its calls to this server. Unset → the Settings
//     value → the API key (today's behaviour).
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
function obligatePublicView(s: ObligateStored, enabled: boolean): ObligateConfig {
  const envSecret = envInboundSecret();
  return {
    url: s.url,
    apiKeySet: !!s.apiKey,
    enabled,
    inboundSecretSet: !!(envSecret ?? s.inboundSecret),
    inboundSecretFromEnv: !!envSecret,
  };
}
export interface AgentGlobalConfig {
  checkIntervalSeconds: number | null;
  scanIntervalSeconds: number | null;  // 0 = disabled, >0 = run all scans every N seconds
  heartbeatMonitoring: boolean | null;
  maxMissedPushes: number | null;
  notificationTypes: DeviceNotificationTypes | null;
}

const DEFAULT_NOTIFICATION_TYPES: Required<DeviceNotificationTypes> = {
  online: true,
  offline: true,
  warning: true,
  critical: true,
  update: false,
};

export const appConfigService = {
  async get(key: string): Promise<string | null> {
    const row = await db('app_config').where({ key }).first('value');
    return row?.value ?? null;
  },

  async set(key: string, value: string): Promise<void> {
    await db('app_config')
      .insert({ key, value })
      .onConflict('key')
      .merge({ value });
  },

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
      agent_auto_approve: map['agent_auto_approve'] ?? 'false',
      default_push_interval: map['default_push_interval'] ?? '60',
      fast_poll_interval: map['fast_poll_interval'] ?? '5',
      remote_fast_poll_interval: map['remote_fast_poll_interval'] ?? '3',
      task_retrieve_delay_seconds: map['task_retrieve_delay_seconds'] ?? '10',
      remote_session_timeout_minutes: map['remote_session_timeout_minutes'] ?? '30',
      catchup_window_days: map['catchup_window_days'] ?? '7',
      inventory_retention_days: map['inventory_retention_days'] ?? '90',
      app_name: map['app_name'] ?? 'Obliance',
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
    const stored = await this.readObligateStored();
    return obligatePublicView(stored, enabled);
  },

  /**
   * Obligate settings as stored (app_config 'obligate_config'), without the
   * environment overrides. Internal: callers use getObligateRaw().
   */
  async readObligateStored(): Promise<ObligateStored> {
    const raw = await this.get(OBLIGATE_CONFIG_KEY);
    if (!raw) return { url: null, apiKey: null, inboundSecret: null };
    try {
      const cfg = JSON.parse(raw) as { url?: string; apiKey?: string; inboundSecret?: string };
      return {
        url: cfg.url ?? null,
        apiKey: cfg.apiKey ?? null,
        inboundSecret: typeof cfg.inboundSecret === 'string' && cfg.inboundSecret ? cfg.inboundSecret : null,
      };
    } catch { return { url: null, apiKey: null, inboundSecret: null }; }
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

  async patchObligateConfig(patch: {
    url?: string | null; apiKey?: string | null; enabled?: boolean;
    inboundSecret?: string | null;
  }): Promise<ObligateConfig> {
    const existing = await this.readObligateStored();
    const merged: ObligateStored = {
      url: 'url' in patch ? (patch.url ?? null) : existing.url,
      apiKey: ('apiKey' in patch && patch.apiKey) ? patch.apiKey : existing.apiKey,
      // a non-empty string sets it, null clears it, absent keeps it
      inboundSecret: 'inboundSecret' in patch
        ? (typeof patch.inboundSecret === 'string' && patch.inboundSecret ? patch.inboundSecret : null)
        : existing.inboundSecret,
    };
    const toStore: Record<string, unknown> = { url: merged.url, apiKey: merged.apiKey };
    if (merged.inboundSecret) toStore.inboundSecret = merged.inboundSecret;
    await this.set(OBLIGATE_CONFIG_KEY, JSON.stringify(toStore));
    if ('enabled' in patch) {
      await this.set('obligate_enabled', patch.enabled ? 'true' : 'false');
    }
    const enabled = (await this.get('obligate_enabled')) === 'true';
    return obligatePublicView(merged, enabled);
  },

  /** Get global agent defaults from app_config */
  async getAgentGlobal(): Promise<AgentGlobalConfig> {
    const raw = await this.get(AGENT_GLOBAL_CONFIG_KEY);
    if (!raw) {
      return {
        checkIntervalSeconds: null,
        scanIntervalSeconds: null,
        heartbeatMonitoring: null,
        maxMissedPushes: null,
        notificationTypes: null,
      };
    }
    try {
      return JSON.parse(raw) as AgentGlobalConfig;
    } catch {
      return {
        checkIntervalSeconds: null,
        scanIntervalSeconds: null,
        heartbeatMonitoring: null,
        maxMissedPushes: null,
        notificationTypes: null,
      };
    }
  },

  /** Merge-patch global agent defaults */
  async setAgentGlobal(patch: Partial<AgentGlobalConfig>): Promise<AgentGlobalConfig> {
    const current = await this.getAgentGlobal();
    const updated: AgentGlobalConfig = { ...current, ...patch };
    await this.set(AGENT_GLOBAL_CONFIG_KEY, JSON.stringify(updated));
    return updated;
  },

  /**
   * Read the global notification types (fully resolved -- each field falls back to
   * DEFAULT_NOTIFICATION_TYPES when null).
   */
  async getResolvedAgentNotificationTypes(): Promise<Required<DeviceNotificationTypes>> {
    const cfg = await this.getAgentGlobal();
    const nt: DeviceNotificationTypes | null = cfg.notificationTypes ?? null;
    return {
      online:   nt?.online   ?? DEFAULT_NOTIFICATION_TYPES.online,
      offline:  nt?.offline  ?? DEFAULT_NOTIFICATION_TYPES.offline,
      warning:  nt?.warning  ?? DEFAULT_NOTIFICATION_TYPES.warning,
      critical: nt?.critical ?? DEFAULT_NOTIFICATION_TYPES.critical,
      update:   nt?.update   ?? DEFAULT_NOTIFICATION_TYPES.update,
    };
  },
};
