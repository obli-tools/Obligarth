import { z } from 'zod';
import { AppError } from '../../middleware/errorHandler';
import { WindowLimiter } from '../../legacyAgent/limits';
import type { McpCaller } from '../caller';

// Shared argument schemas and limits of the tools (docs: specs mcp-server §3.5, §4.3).

export const tenantId = z.number().int().positive().max(2147483647);
export const limit = z.number().int().min(1).max(200).optional();
export const offset = z.number().int().min(0).max(100_000).optional();
export const deviceId = z.number().int().positive().max(2147483647);
/** Device ids of a write: 1 to 50 per call. */
export const deviceIds = z.array(deviceId).min(1).max(50);
/** Free text of the agent: stored as data, marked reasonSource 'agent', never in a summary. */
export const reason = z.string().trim().max(500).optional();

/** Writes per user: the console's enqueue limiter value (60 per minute). */
const writes = new WindowLimiter(60, 60_000);

export function takeWrite(caller: McpCaller): void {
  if (writes.hit(`u:${caller.userId}`) > 0) throw new AppError(429, 'Too many actions: wait a minute', 'rateLimited');
}

/** The message an agent relays to its human for an authorization. */
export const AUTHORIZE_MESSAGE = 'Authorize the action with a 2FA (phone) or a code in the Obligarth interface (notification, or Access keys > Authorizations). Then call get_authorization_status.';
export const APPROVAL_MESSAGE = 'Another person must approve this request in Obligarth.';

/** Names of devices for a summary built by the server (at most `max`, then a count). */
export function namesOf(rows: Array<{ id: number; label: string | null }>, max = 5): string {
  const shown = rows.slice(0, max).map((r) => (r.label ? `${r.label} (#${r.id})` : `#${r.id}`)).join(', ');
  return rows.length > max ? `${shown} and ${rows.length - max} more` : shown;
}
