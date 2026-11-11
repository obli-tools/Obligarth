import type { NotificationPlugin, NotificationPayload } from '../types';
import { statusIcon, STATUS_COLORS_HEX } from '../statusIcons';
import { guardedPost } from '../../utils/ssrfGuard';

export const discordPlugin: NotificationPlugin = {
  type: 'discord',
  name: 'Discord',
  description: 'Send to a Discord channel via webhook',
  configFields: [
    { key: 'webhookUrl', label: 'Discord Webhook URL', type: 'url', secret: true, required: true, placeholder: 'https://discord.com/api/webhooks/...' },
    { key: 'username', label: 'Bot Username (optional)', type: 'text', placeholder: 'Obligarth' },
  ],

  async send(config, payload) {
    const embed = {
      title: `${statusIcon(payload.newStatus)} ${payload.monitorName}`,
      description: payload.message || `Status changed: **${payload.oldStatus}** → **${payload.newStatus}**`,
      color: STATUS_COLORS_HEX[payload.newStatus] ?? 0x95a5a6,
      fields: [
        { name: 'Status', value: payload.newStatus.toUpperCase(), inline: true },
        ...(payload.monitorUrl ? [{ name: 'URL', value: payload.monitorUrl, inline: true }] : []),
      ],
      timestamp: payload.timestamp,
    };

    const body: Record<string, unknown> = { embeds: [embed] };
    if (config.username) body.username = config.username;

    // A public destination only, no redirect; the status alone in the error (never the remote page).
    const res = await guardedPost(String(config.webhookUrl), { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, 'public');
    if (!res.ok) throw new Error(`Discord returned ${res.status}`);
  },

  async sendTest(config) {
    await this.send(config, {
      monitorName: 'Test Monitor',
      oldStatus: 'up',
      newStatus: 'down',
      message: 'This is a test notification from Obligarth',
      timestamp: new Date().toISOString(),
    });
  },
};
