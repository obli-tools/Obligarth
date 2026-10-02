import type { Knex } from 'knex';
import { db } from '../db';
import type { NotificationChannel, NotificationChannelType, NotificationBinding, OverrideMode } from '@obligarth/shared';
import { isMasterTenant } from '@obligarth/shared';

import type { NotificationPayload } from '../notifications/types';
import { getPlugin, isSecretField, secretFieldsOf } from '../notifications/registry';
import { smtpServerService } from './smtpServer.service';
import { config } from '../config';
import { logger } from '../utils/logger';
import { AppError } from '../middleware/errorHandler';
import { vault, type SecretLocator } from '../vault';
import { currentDbContext, switchToTenant } from '../db/context';

interface ChannelRow {
  id: number;
  name: string;
  type: string;
  config: Record<string, unknown>;
  is_enabled: boolean;
  created_by: number | null;
  tenant_id: number;
  created_at: Date;
  updated_at: Date;
  uuid?: string;
  secret_fields?: unknown;
}

interface BindingRow {
  id: number;
  tenant_id: number;
  channel_id: number;
  scope: string;
  scope_id: number | null;
  override_mode: string;
}

// ── Secret fields: write-only (docs: coffre-secrets V8, §7.3) ──────────────
// The secret fields of a channel's plugin (notifications/registry.ts:
// `secret: true`, or type 'password') never sit in `config`: they are sealed
// together, as one JSON object, in `secrets_enc` under the DEK of the
// channel's tenant (AAD obligarth.notification_channels:secrets_enc:<id>:
// <tenant>), and their names in `secret_fields`. The API returns `config`
// (public fields only) and `secretFieldsSet` (names), never a value; an
// update keeps a secret field that is absent or empty, replaces it with a new
// string, clears it with null. resolveChannelConfig, right before a send, is
// the only place that opens `secrets_enc`.

/** The columns a channel's mapper may read (R6): never secrets_enc. */
const PUBLIC_COLUMNS = ['id', 'name', 'type', 'config', 'is_enabled', 'created_by', 'tenant_id',
  'created_at', 'updated_at', 'uuid', 'secret_fields'] as const;
const publicColumns = (): string[] => [...PUBLIC_COLUMNS];

const secretsAt = (id: number, tenantId: number): SecretLocator =>
  ({ table: 'notification_channels', column: 'secrets_enc', pk: id, tenantId });

// Pass `currentTenantId` to redact when the caller doesn't own the channel —
// typical for the FreeMobile-fan-out scenario: master creates a channel with
// its API key, shares it with tenant B who sees its existence (so admins can
// recognize "Notifications: FreeMobile master is bound here") but never a
// secret. The secret fields are never in `config` (write-only); this mask is
// a last net for unknown keys that look secret. The mask is also signaled with
// `readOnly: true` so the UI can disable the edit form on the child side.
const SECRET_KEY_TEST = /(secret|token|password|webhook|api[_-]?key|key)$/i;

function parseObject(raw: unknown): Record<string, unknown> {
  const v = typeof raw === 'string' ? (() => { try { return JSON.parse(raw); } catch { return {}; } })() : raw;
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
}

/** The public part of a stored config: the plugin's secret fields are
 *  dropped (a legacy clear value never leaves, even before the backfill). */
function publicConfig(type: string, raw: unknown): Record<string, unknown> {
  const secret = new Set(secretFieldsOf(type));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(parseObject(raw))) if (!secret.has(k)) out[k] = v;
  return out;
}

function redactConfig(cfg: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(cfg)) out[k] = SECRET_KEY_TEST.test(k) ? '__REDACTED__' : v;
  return out;
}

function secretNames(raw: unknown): string[] {
  const v = typeof raw === 'string' ? (() => { try { return JSON.parse(raw); } catch { return []; } })() : raw;
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function rowToChannel(row: ChannelRow, currentTenantId?: number): NotificationChannel {
  const isCallerOwner = currentTenantId == null || currentTenantId === row.tenant_id || isMasterTenant(currentTenantId);
  const cfg = publicConfig(row.type, row.config);
  const ch: NotificationChannel = {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    type: row.type as NotificationChannelType,
    config: isCallerOwner ? cfg : redactConfig(cfg),
    secretFieldsSet: isCallerOwner ? secretNames(row.secret_fields) : [],
    uuid: row.uuid ?? '',
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    // `readOnly` flag for the client form — true when the caller
    // is a child tenant viewing a master-shared channel.
    readOnly: !isCallerOwner,
  } as NotificationChannel & { readOnly: boolean };
  return ch;
}

/** A submitted config split along the plugin's fields: the public ones
 *  (declared, not secret) and the secret ones; an unknown key is dropped. */
function splitConfig(type: string, submitted: Record<string, unknown>): {
  publicCfg: Record<string, unknown>; secrets: Record<string, unknown>;
} {
  const plugin = getPlugin(type);
  const publicCfg: Record<string, unknown> = {};
  const secrets: Record<string, unknown> = {};
  for (const field of plugin?.configFields ?? []) {
    if (!Object.prototype.hasOwnProperty.call(submitted, field.key)) continue;
    const v = submitted[field.key];
    if (isSecretField(field)) secrets[field.key] = v;
    else publicCfg[field.key] = v;
  }
  return { publicCfg, secrets };
}

const hasValue = (v: unknown): boolean => v !== undefined && v !== null && v !== '';

async function sealSecrets(trx: Knex.Transaction, id: number, tenantId: number, secrets: Record<string, unknown>):
  Promise<{ secrets_enc: string | null; secret_fields: string }> {
  const names = Object.keys(secrets).filter((k) => hasValue(secrets[k])).sort();
  if (!names.length) return { secrets_enc: null, secret_fields: '[]' };
  const value = Object.fromEntries(names.map((k) => [k, secrets[k]]));
  return {
    secrets_enc: await vault.sealJson(secretsAt(id, tenantId), value, { trx }),
    secret_fields: JSON.stringify(names),
  };
}

function rowToBinding(row: BindingRow): NotificationBinding {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    channelId: row.channel_id,
    scope: row.scope as NotificationBinding['scope'],
    scopeId: row.scope_id,
    overrideMode: row.override_mode as OverrideMode,
  };
}

/**
 * The text of a send error, without the URL it may quote: fetch() and URL
 * parsing repeat the address they were given ("Failed to parse URL from
 * https://hooks.example.com/services/<secret>"), and a webhook URL or a token
 * in a query string are write-only secrets of the channel (review of lot A4;
 * integration of lot A). Kept for the test's answer and the send log.
 */
export function channelErrorText(err: unknown): string {
  const raw = err instanceof Error ? err.message : 'Unknown error';
  return raw
    .replace(/Failed to parse URL from .*/gs, 'Failed to parse the URL')
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, '<url>')
    .slice(0, 500);
}

export const notificationService = {
  // ── Channel CRUD ──

  async getAllChannels(tenantId: number): Promise<NotificationChannel[]> {
    // Master sees every channel install-wide; otherwise: own channels +
    // channels shared to this tenant via the junction table.
    const isMaster = isMasterTenant(tenantId);
    const q = db('notification_channels').select(publicColumns()).orderBy('name');
    if (!isMaster) {
      q.where(function () {
        this.where('notification_channels.tenant_id', tenantId)
          .orWhereIn(
            'notification_channels.id',
            db('notification_channel_tenants').select('channel_id').where({ tenant_id: tenantId }),
          );
      });
    }
    const rows = await q as unknown as ChannelRow[];
    return rows.map((row) => rowToChannel(row, tenantId));
  },

  /** UNSAFE without tenant scope. Used by internal lookups (channel
   *  resolver during notification dispatch, sharing-junction join). The
   *  HTTP route handlers MUST validate ownership before exposing the
   *  row — pattern: check `channel.tenantId === req.tenantId` or that
   *  the caller's tenant has the channel via the junction table, or
   *  bypass on master. See `notification.routes.ts` for the canonical
   *  guard. `currentTenantId`: the tenant of the request, for an answer to
   *  it (a recipient of a shared channel gets it read-only, without the
   *  names of its secret fields, as the list gives it). */
  async getChannelById(id: number, currentTenantId?: number): Promise<NotificationChannel | null> {
    const row = await db('notification_channels').where({ id }).first(publicColumns()) as unknown as ChannelRow | undefined;
    return row ? rowToChannel(row, currentTenantId) : null;
  },

  /** A new channel: public fields in `config`, secret fields sealed (the id
   *  is allocated first: it is part of the AAD). */
  async createChannel(data: {
    name: string;
    type: string;
    config: Record<string, unknown>;
    isEnabled?: boolean;
    createdBy?: number;
  }, tenantId: number): Promise<NotificationChannel> {
    const plugin = getPlugin(data.type);
    if (!plugin) throw new Error(`Unknown notification type: ${data.type}`);
    const { publicCfg, secrets } = splitConfig(data.type, data.config ?? {});
    for (const [k, v] of Object.entries(secrets)) {
      if (v !== null && v !== undefined && typeof v !== 'string') throw new AppError(400, `${k} must be a string`, 'invalidSecretField');
    }
    return db.transaction(async (trx) => {
      const id = await vault.allocateId('notification_channels', { trx });
      const sealed = await sealSecrets(trx, id, tenantId, secrets);
      const [row] = await trx('notification_channels')
        .insert({
          id,
          name: data.name,
          type: data.type,
          config: JSON.stringify(publicCfg),
          is_enabled: data.isEnabled ?? true,
          created_by: data.createdBy ?? null,
          tenant_id: tenantId,
          ...sealed,
        })
        .returning(publicColumns()) as ChannelRow[];
      return rowToChannel(row);
    });
  },

  /** `config` replaces the public fields; a secret field absent or '' is
   *  kept, a string replaces it, null clears it (400 for a required one).
   *  The secrets are resealed only when one of them changes. */
  async updateChannel(id: number, data: {
    name?: string;
    config?: Record<string, unknown>;
    isEnabled?: boolean;
  }, opts: { requestTenantId?: number } = {}): Promise<NotificationChannel | null> {
    return db.transaction(async (trx) => {
      const cur = await trx('notification_channels').where({ id }).forUpdate()
        .first('id', 'tenant_id', 'type', 'secrets_enc') as { id: number; tenant_id: number; type: string; secrets_enc: string | null } | undefined;
      if (!cur) return null;
      const updateData: Record<string, unknown> = { updated_at: new Date() };
      if (data.name !== undefined) updateData.name = data.name;
      if (data.isEnabled !== undefined) updateData.is_enabled = data.isEnabled;
      if (data.config !== undefined) {
        const { publicCfg, secrets: submitted } = splitConfig(cur.type, data.config ?? {});
        updateData.config = JSON.stringify(publicCfg);
        const fields = new Map((getPlugin(cur.type)?.configFields ?? []).map((f) => [f.key, f]));
        let stored: Record<string, unknown> | null = null;
        const load = async (): Promise<Record<string, unknown>> => {
          if (!stored) {
            stored = cur.secrets_enc
              ? await vault.openJson<Record<string, unknown>>(secretsAt(cur.id, cur.tenant_id), cur.secrets_enc,
                { trx, requestTenantId: opts.requestTenantId })
              : {};
          }
          return stored;
        };
        let changed = false;
        for (const [key, v] of Object.entries(submitted)) {
          if (v === undefined || v === '') continue;                       // kept
          if (v === null) {
            if (fields.get(key)?.required) throw new AppError(400, `${key} is required and cannot be cleared`, 'secretFieldRequired');
            const s = await load();
            if (key in s) { delete s[key]; changed = true; }
            continue;
          }
          if (typeof v !== 'string') throw new AppError(400, `${key} must be a string`, 'invalidSecretField');
          const s = await load();
          if (s[key] !== v) { s[key] = v; changed = true; }
        }
        if (changed) Object.assign(updateData, await sealSecrets(trx, cur.id, cur.tenant_id, await load()));
      }
      const [row] = await trx('notification_channels')
        .where({ id })
        .update(updateData)
        .returning(publicColumns()) as ChannelRow[];
      return row ? rowToChannel(row) : null;
    });
  },

  async deleteChannel(id: number): Promise<boolean> {
    const count = await db('notification_channels').where({ id }).del();
    return count > 0;
  },

  // ── Cross-tenant channel sharing ──

  /** Returns the list of tenant IDs the channel is shared to (not including its own tenant). */
  async getChannelTenants(channelId: number): Promise<number[]> {
    const rows = await db('notification_channel_tenants')
      .where({ channel_id: channelId })
      .select('tenant_id');
    return rows.map((r: { tenant_id: number }) => r.tenant_id);
  },

  /** Replaces the sharing list for a channel (full replace — not additive).
   *  Only a master-tenant channel is shared (owner_tenant_id = 1, checked by
   *  the database), in the master tenant's context. */
  async setChannelTenants(channelId: number, tenantIds: number[]): Promise<void> {
    await db.transaction(async (trx) => {
      const channel = await trx('notification_channels').where({ id: channelId }).first('tenant_id') as { tenant_id: number } | undefined;
      if (!channel) throw new Error('Channel not found');
      await trx('notification_channel_tenants').where({ channel_id: channelId }).del();
      if (tenantIds.length > 0) {
        await trx('notification_channel_tenants').insert(
          tenantIds.map((tenant_id) => ({ owner_tenant_id: channel.tenant_id, channel_id: channelId, tenant_id })),
        );
      }
    });
  },

  /**
   * The effective config of a channel, right before a send: the only place
   * that opens its secrets (under the DEK of the channel's tenant, read from
   * the row: a recipient of a master channel shared with it reads the master's
   * row, as the row level security allows). For smtp channels using
   * smtpServerId, the SMTP server's transport and credentials: the server of
   * the channel's tenant (or a platform server), read in that tenant's
   * context — the master tenant's for a master channel shared with the
   * caller's tenant, whose row was just read here — never another tenant's
   * (rls-tenant §5.7; coffre-secrets, review of lot A4).
   */
  async resolveChannelConfig(channel: { id: number }): Promise<Record<string, unknown>> {
    const row = await db('notification_channels').where({ id: channel.id })
      .first('id', 'tenant_id', 'type', 'config', 'secrets_enc') as
      { id: number; tenant_id: number; type: string; config: unknown; secrets_enc: string | null } | undefined;
    if (!row) throw new Error('Channel not found');
    const cfg = publicConfig(row.type, row.config);
    if (row.type === 'smtp' && cfg.smtpServerId) {
      const read = () => smtpServerService.getTransportConfig(Number(cfg.smtpServerId), { requestTenantId: row.tenant_id });
      const ctx = currentDbContext();
      const server = ctx?.kind === 'tenant' && ctx.tenantId === row.tenant_id ? await read() : await switchToTenant(row.tenant_id, read);
      if (!server) throw new Error(`SMTP server #${cfg.smtpServerId} not found`);
      return {
        host: server.host,
        port: server.port,
        secure: server.secure,
        username: server.username,
        password: server.password,
        from: cfg.fromOverride || server.fromAddress,
        to: cfg.to,
      };
    }
    const secrets = row.secrets_enc
      ? await vault.openJson<Record<string, unknown>>(secretsAt(row.id, row.tenant_id), row.secrets_enc)
      : {};
    return { ...cfg, ...secrets };
  },

  async testChannel(id: number): Promise<void> {
    const channel = await this.getChannelById(id);
    if (!channel) throw new Error('Channel not found');

    const plugin = getPlugin(channel.type);
    if (!plugin) throw new Error(`No plugin for type: ${channel.type}`);

    const resolvedConfig = await this.resolveChannelConfig(channel);
    await plugin.sendTest(resolvedConfig);
  },

  // ── Bindings ──

  async getBindings(scope: string, scopeId: number | null): Promise<NotificationBinding[]> {
    const rows = await db<BindingRow>('notification_bindings')
      .where({ scope, scope_id: scopeId });
    return rows.map(rowToBinding);
  },

  async addBinding(channelId: number, scope: string, scopeId: number | null, tenantId: number, overrideMode: OverrideMode = 'merge'): Promise<NotificationBinding> {
    // Upsert in code, NOT via .onConflict(): the table has no unique constraint
    // on (channel_id, scope, scope_id), and even with one Postgres treats a NULL
    // scope_id (global scope) as distinct so ON CONFLICT can't dedupe globals.
    // Also set the NOT NULL tenant_id — its omission was the "Activer" 400.
    const existing = await db<BindingRow>('notification_bindings')
      .where({ channel_id: channelId, scope })
      .modify((qb) => {
        if (scopeId === null) qb.whereNull('scope_id');
        else qb.where('scope_id', scopeId);
      })
      .first();
    if (existing) {
      const [row] = await db<BindingRow>('notification_bindings')
        .where({ id: existing.id })
        .update({ override_mode: overrideMode })
        .returning('*');
      return rowToBinding(row);
    }
    const [row] = await db<BindingRow>('notification_bindings')
      .insert({
        tenant_id: tenantId,
        channel_id: channelId,
        scope,
        scope_id: scopeId,
        override_mode: overrideMode,
      })
      .returning('*');
    return rowToBinding(row);
  },

  async removeBinding(channelId: number, scope: string, scopeId: number | null): Promise<boolean> {
    const count = await db('notification_bindings')
      .where({ channel_id: channelId, scope, scope_id: scopeId })
      .del();
    return count > 0;
  },

  // ── Resolution (merge/replace/exclude inheritance) ──

  /**
   * Apply a set of bindings to the current channel set.
   * 1. If any binding has 'replace' mode → clear the set first
   * 2. Add all 'merge' (and 'replace') bindings to the set
   * 3. Remove all 'exclude' bindings from the set
   */
  _applyBindings(channelIds: Set<number>, bindings: NotificationBinding[]): Set<number> {
    if (bindings.length === 0) return channelIds;

    const hasReplace = bindings.some((b) => b.overrideMode === 'replace');
    if (hasReplace) {
      channelIds = new Set();
    }

    // Add merge/replace bindings
    for (const b of bindings) {
      if (b.overrideMode !== 'exclude') {
        channelIds.add(b.channelId);
      }
    }

    // Remove exclude bindings
    for (const b of bindings) {
      if (b.overrideMode === 'exclude') {
        channelIds.delete(b.channelId);
      }
    }

    return channelIds;
  },

  /**
   * Resolve bindings for a scope WITH source info (for the UI).
   * Shows which channels are active and where they come from.
   * Also tracks excluded channels so the UI can show "Unbind" state.
   */
  async resolveBindingsWithSources(
    scope: 'group' | 'device',
    scopeId: number,
    groupId?: number | null,
  ): Promise<{
    channelId: number;
    channelName: string;
    channelType: string;
    source: 'global' | 'group' | 'device';
    sourceId: number | null;
    sourceName: string;
    isDirect: boolean;
    isExcluded: boolean;
  }[]> {
    interface SourceInfo {
      channelId: number;
      source: 'global' | 'group' | 'device';
      sourceId: number | null;
      sourceName: string;
      isDirect: boolean;
      isExcluded: boolean;
    }

    // Build the inheritance chain
    const result: Map<number, SourceInfo> = new Map();
    // Track excluded channel IDs separately for the final output
    const excludedSet: Set<number> = new Set();

    const applyBindingsWithSources = (
      bindings: NotificationBinding[],
      source: SourceInfo['source'],
      sourceId: number | null,
      sourceName: string,
      isDirect: boolean,
    ) => {
      if (bindings.length === 0) return;

      const hasReplace = bindings.some((b) => b.overrideMode === 'replace');
      if (hasReplace) {
        result.clear();
        excludedSet.clear();
      }

      // Add merge/replace bindings
      for (const b of bindings) {
        if (b.overrideMode !== 'exclude') {
          result.set(b.channelId, {
            channelId: b.channelId,
            source,
            sourceId,
            sourceName,
            isDirect,
            isExcluded: false,
          });
          excludedSet.delete(b.channelId);
        }
      }

      // Process excludes
      for (const b of bindings) {
        if (b.overrideMode === 'exclude') {
          // Keep the entry in result (for UI to show it) but mark as excluded
          const existing = result.get(b.channelId);
          if (existing) {
            existing.isExcluded = true;
          }
          excludedSet.add(b.channelId);
        }
      }
    };

    // 1. Global bindings
    const globalBindings = await this.getBindings('global', null);
    applyBindingsWithSources(globalBindings, 'global', null, 'Global', false);

    // 2. Group chain (for device scope: walk group ancestors; for group scope: walk parent ancestors)
    const effectiveGroupId = scope === 'device' ? groupId : null;

    // For group scope, walk the parent chain (ancestors of this group)
    if (scope === 'group') {
      const ancestorRows = await db('device_group_closure')
        .where('descendant_id', scopeId)
        .where('depth', '>', 0) // exclude self
        .orderBy('depth', 'desc')
        .select('ancestor_id');

      for (const row of ancestorRows) {
        const groupBindings = await this.getBindings('group', row.ancestor_id);
        const groupRow = await db('device_groups').where({ id: row.ancestor_id }).first('name');
        applyBindingsWithSources(
          groupBindings,
          'group',
          row.ancestor_id,
          groupRow?.name || `Group #${row.ancestor_id}`,
          false,
        );
      }
    }

    // For device scope, walk all group ancestors (including the direct group)
    if (scope === 'device' && effectiveGroupId !== null && effectiveGroupId !== undefined) {
      const ancestorRows = await db('device_group_closure')
        .where('descendant_id', effectiveGroupId)
        .orderBy('depth', 'desc')
        .select('ancestor_id');

      for (const row of ancestorRows) {
        const groupBindings = await this.getBindings('group', row.ancestor_id);
        const groupRow = await db('device_groups').where({ id: row.ancestor_id }).first('name');
        applyBindingsWithSources(
          groupBindings,
          'group',
          row.ancestor_id,
          groupRow?.name || `Group #${row.ancestor_id}`,
          false,
        );
      }
    }

    // 3. Direct bindings at this scope
    const directBindings = await this.getBindings(scope, scopeId);
    applyBindingsWithSources(directBindings, scope, scopeId, 'Direct', true);

    // Enrich with channel name/type
    const channelIds = Array.from(result.keys());
    if (channelIds.length === 0) return [];

    const channels = await db('notification_channels').whereIn('id', channelIds).select(publicColumns()) as unknown as ChannelRow[];
    const channelMap = new Map(channels.map((c) => [c.id, c]));

    return Array.from(result.values()).map((r) => {
      const ch = channelMap.get(r.channelId);
      return {
        ...r,
        channelName: ch?.name || `Channel #${r.channelId}`,
        channelType: ch?.type || 'unknown',
      };
    });
  },

  // ── Send notifications ──

  /**
   * Resolve channels for a group-level notification.
   * Chain: Global → Group ancestors (root→leaf, including the group itself).
   * No device-level bindings are included.
   */
  async resolveChannelsForGroup(groupId: number): Promise<number[]> {
    let channelIds: Set<number> = new Set();

    // 1. Global bindings
    const globalBindings = await this.getBindings('global', null);
    channelIds = this._applyBindings(channelIds, globalBindings);

    // 2. Group chain (root → leaf, including self via depth >= 0)
    const ancestorRows = await db('device_group_closure')
      .where('descendant_id', groupId)
      .orderBy('depth', 'desc')
      .select('ancestor_id');

    for (const row of ancestorRows) {
      const groupBindings = await this.getBindings('group', row.ancestor_id);
      channelIds = this._applyBindings(channelIds, groupBindings);
    }

    return Array.from(channelIds);
  },

  /**
   * Resolve bindings for an agent device WITH source info (for the UI).
   * Chain: Global → Agent Group ancestors (root→leaf) → Agent-level bindings.
   */
  async resolveBindingsWithSourcesForAgent(
    deviceId: number,
  ): Promise<{
    channelId: number;
    channelName: string;
    channelType: string;
    source: 'global' | 'group' | 'agent';
    sourceId: number | null;
    sourceName: string;
    isDirect: boolean;
    isExcluded: boolean;
  }[]> {
    interface SourceInfo {
      channelId: number;
      source: 'global' | 'group' | 'agent';
      sourceId: number | null;
      sourceName: string;
      isDirect: boolean;
      isExcluded: boolean;
    }

    const result: Map<number, SourceInfo> = new Map();
    const excludedSet: Set<number> = new Set();

    const applyBindingsWithSources = (
      bindings: NotificationBinding[],
      source: SourceInfo['source'],
      sourceId: number | null,
      sourceName: string,
      isDirect: boolean,
    ) => {
      if (bindings.length === 0) return;

      const hasReplace = bindings.some((b) => b.overrideMode === 'replace');
      if (hasReplace) {
        result.clear();
        excludedSet.clear();
      }

      for (const b of bindings) {
        if (b.overrideMode !== 'exclude') {
          result.set(b.channelId, {
            channelId: b.channelId,
            source,
            sourceId,
            sourceName,
            isDirect,
            isExcluded: false,
          });
          excludedSet.delete(b.channelId);
        }
      }

      for (const b of bindings) {
        if (b.overrideMode === 'exclude') {
          const existing = result.get(b.channelId);
          if (existing) {
            existing.isExcluded = true;
          }
          excludedSet.add(b.channelId);
        }
      }
    };

    // 1. Global bindings
    const globalBindings = await this.getBindings('global', null);
    applyBindingsWithSources(globalBindings, 'global', null, 'Global', false);

    // 2. Agent group hierarchy (root → leaf)
    const device = await db('devices').where({ id: deviceId }).select('group_id').first() as { group_id: number | null } | undefined;
    if (device?.group_id) {
      const ancestorRows = await db('device_group_closure')
        .where('descendant_id', device.group_id)
        .orderBy('depth', 'desc')
        .select('ancestor_id');

      for (const row of ancestorRows) {
        const groupBindings = await this.getBindings('group', row.ancestor_id);
        const groupRow = await db('device_groups').where({ id: row.ancestor_id }).first('name') as { name: string } | undefined;
        applyBindingsWithSources(
          groupBindings,
          'group',
          row.ancestor_id,
          groupRow?.name || `Group #${row.ancestor_id}`,
          false,
        );
      }
    }

    // 3. Agent-level bindings
    const agentBindings = await this.getBindings('agent', deviceId);
    applyBindingsWithSources(agentBindings, 'agent', deviceId, 'Direct', true);

    // Enrich with channel name/type
    const channelIds = Array.from(result.keys());
    if (channelIds.length === 0) return [];

    const channels = await db('notification_channels').whereIn('id', channelIds).select(publicColumns()) as unknown as ChannelRow[];
    const channelMap = new Map(channels.map((c) => [c.id, c]));

    return Array.from(result.values()).map((r) => {
      const ch = channelMap.get(r.channelId);
      return {
        ...r,
        channelName: ch?.name || `Channel #${r.channelId}`,
        channelType: ch?.type || 'unknown',
      };
    });
  },

  /**
   * Send a group-level notification (for grouped notifications feature).
   * Resolves channels at the group level (no device bindings) and dispatches.
   * No caller today (the agent channel that fed the grouped notifications is
   * gone); kept for the MDM's group events.
   */
  async sendForGroup(
    groupId: number,
    groupName: string,
    payload: NotificationPayload,
  ): Promise<void> {
    const channelIds = await this.resolveChannelsForGroup(groupId);
    if (channelIds.length === 0) return;

    const enrichedPayload: NotificationPayload = { ...payload, appName: config.appName };

    const channels = await db('notification_channels')
      .select(publicColumns())
      .whereIn('id', channelIds)
      .where({ is_enabled: true }) as unknown as ChannelRow[];

    for (const row of channels) {
      const channel = rowToChannel(row);
      const plugin = getPlugin(channel.type);
      if (!plugin) {
        logger.warn(`No plugin for notification type "${channel.type}"`);
        continue;
      }

      try {
        const resolvedConfig = await this.resolveChannelConfig(channel);
        await plugin.send(resolvedConfig, enrichedPayload);
        await this.logNotification(channel.id, 'group_status_change', true);
        logger.info(`Group notification sent: ${channel.name} (${channel.type}) for group "${groupName}"`);
      } catch (error) {
        const errMsg = channelErrorText(error);
        await this.logNotification(channel.id, 'group_status_change', false, errMsg);
        logger.error(`Group notification failed: ${channel.name} (${channel.type}): ${errMsg}`);
      }
    }
  },

  /**
   * One row of notification_log per send: status 'sent' or 'failed', with the
   * error message. (It used to write `success` and `error`, columns the table
   * never had, so every send through sendForGroup threw here.) A failure to
   * log never turns a sent notification into a failed one.
   */
  async logNotification(
    channelId: number,
    eventType: string,
    success: boolean,
    error?: string,
  ): Promise<void> {
    try {
      await db('notification_log').insert({
        channel_id: channelId,
        event_type: eventType,
        status: success ? 'sent' : 'failed',
        error_message: error ?? null,
      });
    } catch (err) {
      logger.warn({ err, channelId, eventType }, 'notification log write failed');
    }
  },
};
