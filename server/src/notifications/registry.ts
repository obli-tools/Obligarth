import type { NotificationPlugin } from './types';
import type { NotificationConfigField, NotificationPluginMeta } from '@obligarth/shared';
import { webhookPlugin } from './plugins/webhook';
import { discordPlugin } from './plugins/discord';
import { telegramPlugin } from './plugins/telegram';
import { slackPlugin } from './plugins/slack';
import { teamsPlugin } from './plugins/teams';
import { gotifyPlugin } from './plugins/gotify';
import { ntfyPlugin } from './plugins/ntfy';
import { pushoverPlugin } from './plugins/pushover';
import { smtpPlugin } from './plugins/smtp';
import { freemobilePlugin } from './plugins/freemobile';

const plugins = new Map<string, NotificationPlugin>();

// Register built-in plugins
[
  webhookPlugin,
  discordPlugin,
  telegramPlugin,
  slackPlugin,
  teamsPlugin,
  gotifyPlugin,
  ntfyPlugin,
  pushoverPlugin,
  smtpPlugin,
  freemobilePlugin,
].forEach((plugin) => {
  plugins.set(plugin.type, plugin);
});

export function getPlugin(type: string): NotificationPlugin | undefined {
  return plugins.get(type);
}

export function getAllPlugins(): NotificationPlugin[] {
  return Array.from(plugins.values());
}

// ── Secret fields (write-only, docs: coffre-secrets V8, §7.3) ──────────────
// A field is secret when its plugin declares it so (`secret: true`: the
// webhook URLs of Discord, Slack and Teams, which carry their own token) or
// when it is of type 'password'. Its value is sealed by the vault
// (notification_channels.secrets_enc), never stored in `config` nor returned.

export function isSecretField(field: NotificationConfigField): boolean {
  return field.secret === true || field.type === 'password';
}

/** The secret fields of a plugin type (none for an unknown type). */
export function secretFieldsOf(type: string): string[] {
  const plugin = plugins.get(type);
  return plugin ? plugin.configFields.filter(isSecretField).map((f) => f.key) : [];
}

/** Every key that is a secret field of some plugin (backfill filter). */
export function allSecretFieldKeys(): string[] {
  return [...new Set(getAllPlugins().flatMap((p) => p.configFields.filter(isSecretField).map((f) => f.key)))].sort();
}

export function getPluginMetas(): NotificationPluginMeta[] {
  return getAllPlugins().map((p) => ({
    type: p.type,
    name: p.name,
    description: p.description,
    configFields: p.configFields.map((f) => (isSecretField(f) ? { ...f, secret: true } : f)),
  }));
}

export function registerPlugin(plugin: NotificationPlugin): void {
  plugins.set(plugin.type, plugin);
}
