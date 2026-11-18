import type { Request, Response } from 'express';
import type { ObliwatchAccessKeyItem, ObliwatchAccessKeysResponse } from '@obligarth/shared';
import { keyInfoOf, keyState, keysForTenantOversightFull, type OversightFullKey } from '../../mcp/keys/service';
import { inetText } from '../../mcp/ipUtil';
import { auditRead } from './audit';
import { sendError } from './auth';
import { decodeCursor, encodeCursor } from './cursor';

// =============================================================================
// GET /access-keys?limit=1..200&cursor= (GTH-07, security oversight of the MSP): the MCP access keys whose perimeter
// reaches the tenant of `ost`, revoked and expired ones too for 90 days (mcp/keys/service.ts,
// keysForTenantOversightFull). Owner decisions: the IPs (ipAllow, lastUsedIp) are exposed (Q-L1a); the keys of the
// platform administrators in tenant_mode 'all' are included, their owner shown by username only (Q-L1b).
// The perimeter is REDUCED to the tenant of `ost`: its modes, the groups of this tenant, a count of its devices; no
// identifier of another tenant. Never the hash of the secret (not even selected). Consent 'read' required (router).
// =============================================================================

const ENDPOINT = 'access-keys';
const DEFAULT_LIMIT = 200;

const iso = (v: unknown): string | null => (v ? new Date(v as string | Date).toISOString() : null);
const mode = (m: unknown): 'all' | 'list' => (m === 'list' ? 'list' : 'all');

export function accessKeyItem(k: OversightFullKey, tenantId: number): ObliwatchAccessKeyItem {
  const info = keyInfoOf(k.row);
  const here = k.targets.filter((t) => t.tenantId === tenantId);
  return {
    id: info.publicId,
    name: info.name,
    owner: k.owner.isPlatformAdmin
      ? { userId: null, username: k.owner.username, platformAdmin: true }
      : { userId: k.owner.id, username: k.owner.username, platformAdmin: false },
    scopes: [...info.scopes],
    perimeter: {
      tenantMode: mode(k.row.tenant_mode), groupMode: mode(k.row.group_mode), deviceMode: mode(k.row.device_mode),
      groups: here.filter((t) => t.kind === 'group').map((t) => Number(t.refId)).sort((a, b) => a - b),
      devicesCount: here.filter((t) => t.kind === 'device').length,
      excluded: false,
    },
    ipAllow: info.ipAllow,
    createdAt: iso(k.row.created_at) as string,
    expiresAt: iso(k.row.expires_at) as string,
    revokedAt: iso(k.row.revoked_at),
    revokeReason: (k.row.revoke_reason ?? null) as string | null,
    lastUsedAt: iso(k.row.last_used_at),
    lastUsedIp: inetText(k.row.last_used_ip),
    state: keyState(k.row),
  };
}

interface Position { c: string; i: string }

export async function listAccessKeys(req: Request, res: Response): Promise<void> {
  const caller = req.obliwatch!;
  const rawLimit = req.query.limit === undefined ? DEFAULT_LIMIT : Number(req.query.limit);
  if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 200) { sendError(res, 400, 'limit_invalid', 'limit: 1 to 200'); return; }
  let after: { createdAt: string; id: string } | null = null;
  if (req.query.cursor !== undefined) {
    const pos = typeof req.query.cursor === 'string' ? decodeCursor<Position>(caller.tenantId, ENDPOINT, req.query.cursor) : null;
    if (!pos || typeof pos.c !== 'string' || typeof pos.i !== 'string' || pos.c.length > 64
      || !/^[0-9a-f-]{36}$/i.test(pos.i)) { sendError(res, 400, 'cursor_invalid'); return; }
    after = { createdAt: pos.c, id: pos.i };
  }
  const page = await keysForTenantOversightFull(caller.tenantId, { after, limit: rawLimit });
  const items = page.items.map((k) => accessKeyItem(k, caller.tenantId));
  const last = page.items[page.items.length - 1];
  const body: ObliwatchAccessKeysResponse = {
    items,
    nextCursor: page.more && last ? encodeCursor(caller.tenantId, ENDPOINT, { c: last.position.createdAt, i: last.position.id } satisfies Position) : null,
  };
  auditRead(req, caller.tenantId, ENDPOINT, { count: items.length });
  res.json(body);
}
