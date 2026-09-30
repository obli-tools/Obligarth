import crypto from 'crypto';
import type { Server as SocketIOServer } from 'socket.io';
import { isMasterTenant } from '@obliance/shared';
import { db } from '../db';
import { logger } from '../utils/logger';
import { getIO, type SocketConnection } from '../socket';
import { permissionService } from './permission.service';
import { oblireachHub } from './oblireachHub.service';
import type { ChatUnavailableInfo } from './oblireachWebView2.service';

// ── ObliReach chat (Socket.io side) ─────────────────────────────────────────
// Operator <-> end-user chat over the ObliReach agent channel: chat state,
// the checks of the operator's right, and the operator's Socket.io events.
// Installed on every connection by modules/rmm.ts (registerSocketHandler).

/** The Socket.io server, or null before it exists. */
function ioOrNull(): SocketIOServer | null {
  try { return getIO(); } catch { return null; }
}

// Chat ownership, per chatId. A chat outlives the socket that opened it: any
// socket.io reconnect (network blip, the web app's resume after 30 s hidden,
// a server restart) gives the client a NEW server-side socket, so the chat's
// device and owner cannot live in the connection closure. Chats idle for a
// day are forgotten.
//
// Unified chat (Obliance web <-> Oblireach Desktop): ONE live conversation
// per (operator user, device). Every client of that user shares its chatId:
// `chat:open` resumes it (ack {chatId, resumed, history}), operator messages
// are relayed to the user's other sockets (`fromOperator: true`), a new chat
// is announced to them (`chat:opened`, room chatuser:<userId>), its end too
// (`chat:ended`), and `chat:list` returns the user's live chats.
interface ChatOwner {
  deviceUuid: string;
  deviceId: number;
  /** display name or hostname, for the other clients (chat:opened / chat:list). */
  deviceName: string;
  tenantId: number; // the DEVICE's tenant (a master-tenant admin may chat with any tenant)
  userId: number;
  /** Windows session asked for at open (null: the agent picked it). A chat is
   *  only resumed for the same session (RDS host: several users). */
  sessionId: number | null;
  lastUsed: number;
  /** Set once the chat ended (an operator closed it, or the end user closed
   *  the window, or — 'unavailable' — the chat window could not open on the
   *  machine: WebView2 missing / not starting): never resumed, listed or
   *  written to again. Kept a while so a rejoin can answer "ended" instead
   *  of "unknown". */
  ended?: ChatEndReason;
  /** Details of an 'unavailable' end (sent with every chat:ended of it). */
  endedInfo?: ChatUnavailableInfo;
}
type ChatEndReason = 'operator' | 'user' | 'unavailable';
const chatOwners = new Map<string, ChatOwner>();
const CHAT_IDLE_MS = 24 * 60 * 60 * 1000;
const CHAT_ENDED_KEEP_MS = 60 * 60 * 1000;
/** Messages returned with a resumed / rejoined chat. */
const CHAT_HISTORY_LIMIT = 200;

export interface ChatHistoryEntry {
  sender: string;
  message: string;
  fromOperator: boolean;
  timestamp: number;
}

function sweepChats(now: number): void {
  for (const [id, chat] of chatOwners) {
    if (now - chat.lastUsed > (chat.ended ? CHAT_ENDED_KEEP_MS : CHAT_IDLE_MS)) chatOwners.delete(id);
  }
  // The relay's cached rights of chats that are gone (chatRelayAllowed).
  for (const id of relayRights.keys()) {
    if (!chatOwners.has(id)) relayRights.delete(id);
  }
}

/**
 * A display name chosen by a user (the chat's operatorName, a display_name),
 * made a plain one-line label before it travels on: shown in the end user's
 * chat window, stored, relayed, and put on the chat helper's command line by
 * Oblireach agents older than the fix of 28/09 (a quote there added helper
 * arguments). No control, zero-width or bidi characters, no quotes or
 * backslashes, at most 100 characters. '' when nothing is left.
 */
export function cleanDisplayName(v: unknown): string {
  if (typeof v !== 'string') return '';
  const flat = v
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, ' ')
    .replace(/["\\]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return Array.from(flat).slice(0, 100).join('').trim();
}

/** chat:open's sessionId: a Windows session id, or null (the agent picks). */
function chatSessionOf(v: unknown): number | null {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0x7fffffff ? v : null;
}

/** A live chat may be resumed by an open for this session: when either side
 *  names no session (the agent picks it), or both name the same one. */
function sameChatSession(live: number | null, requested: number | null): boolean {
  return requested === null || live === null || live === requested;
}

/**
 * The chat's owner still has the right to it (checked again after chat:open,
 * which a chat outlives): active account; an admin passes; anyone else must
 * still be a member of the device's tenant, the device still be in it, and
 * the capability 'remote' still be granted. Throws when the database fails
 * (the caller refuses without deciding).
 */
async function chatRightOf(userId: number, chat: ChatOwner): Promise<boolean> {
  const u = await db('users').where({ id: userId, is_active: true }).first('role');
  if (!u) return false;
  if (u.role === 'admin') return true;
  const member = await db('user_tenants').where({ user_id: userId, tenant_id: chat.tenantId }).first();
  if (!member) return false;
  const device = await db('devices').where({ id: chat.deviceId, tenant_id: chat.tenantId }).first('id');
  if (!device) return false;
  return permissionService.canUseCapability(userId, chat.deviceId, false, 'remote');
}

/** The user's live (not ended) chat with this device, if any. */
function liveChatOf(userId: number, deviceUuid: string): [string, ChatOwner] | null {
  for (const [id, chat] of chatOwners) {
    if (chat.userId === userId && chat.deviceUuid === deviceUuid && !chat.ended) return [id, chat];
  }
  return null;
}

/** The last CHAT_HISTORY_LIMIT messages of a chat, oldest first. Callers
 *  checked that the chat is the caller's (chatOwners): chat ids are random
 *  and a chat's rows all belong to its device's tenant. */
async function chatHistory(chatId: string): Promise<ChatHistoryEntry[]> {
  try {
    const rows = await db('chat_messages')
      .where({ chat_id: chatId })
      .orderBy('id', 'desc')
      .limit(CHAT_HISTORY_LIMIT)
      .select('sender', 'message', 'is_operator', 'created_at');
    return rows.reverse().map((r: any) => ({
      sender: String(r.sender ?? ''),
      message: String(r.message ?? ''),
      fromOperator: !!r.is_operator,
      timestamp: new Date(r.created_at).getTime() || Date.now(),
    }));
  } catch {
    return [];
  }
}

/**
 * chat:ended payload. 'unavailable' carries why (code: webview2_missing |
 * webview2_failed | webview2_timeout | helper_failed | no_user), whether the
 * runtime is being installed, the agent's WebView2 state, its reason code
 * (wv2Reason, translated by the clients), what the device page offers
 * (installOffer: button | disabled | no_installer) and the agent's technical
 * detail (English). Older clients read any reason other than 'user' as "closed".
 */
function chatEndedPayload(chatId: string, chat: ChatOwner): Record<string, unknown> {
  const info = chat.ended === 'unavailable' ? chat.endedInfo : undefined;
  return info
    ? {
      chatId, reason: chat.ended, code: info.code, installing: info.installing, state: info.state, detail: info.detail,
      wv2Reason: info.wv2Reason, installOffer: info.installOffer,
    }
    : { chatId, reason: chat.ended };
}

/** Ends a chat for every client in its room (idempotent). */
function endChat(chatId: string, reason: ChatEndReason, info?: ChatUnavailableInfo): void {
  const chat = chatOwners.get(chatId);
  if (!chat || chat.ended) return;
  chat.ended = reason;
  if (reason === 'unavailable' && info) chat.endedInfo = info;
  chat.lastUsed = Date.now();
  try { getIO().to(`chat:${chatId}`).emit('chat:ended', chatEndedPayload(chatId, chat)); } catch { /* io not ready */ }
}

/**
 * For the Oblireach agent channel (oblireachHub): the chat when it belongs to
 * THIS device (uuid + tenant of the authenticated channel), ended or not.
 * Anything else — another device's chat, a chat this server does not know
 * (restart) — is not relayed, stored or allowed to end a conversation.
 */
export function chatOfDevice(chatId: unknown, deviceUuid: string, tenantId: number): { deviceId: number; tenantId: number } | null {
  if (typeof chatId !== 'string') return null;
  const chat = chatOwners.get(chatId);
  if (!chat || chat.deviceUuid !== deviceUuid || Number(chat.tenantId) !== Number(tenantId)) return null;
  return { deviceId: chat.deviceId, tenantId: chat.tenantId };
}

/** The end user closed the chat window (agent `chat_event` user_closed). */
export function chatEndedByUser(chatId: string): void {
  endChat(chatId, 'user');
}

/**
 * The chat window could not open on the machine (agent `chat_event`
 * chat_unavailable): the conversation ends with the exact reason, never as
 * "closed by the user". Synchronous: the hub calls it before any await, so
 * the agent's following user_closed (sent for older servers) finds it ended.
 */
export function chatUnavailable(chatId: string, info: ChatUnavailableInfo): void {
  endChat(chatId, 'unavailable', info);
}

/** The chat already ended (whatever the reason). */
export function chatIsEnded(chatId: string): boolean {
  return !!chatOwners.get(chatId)?.ended;
}

// ── The end user's side of a chat reaches its owner only while he may see it ─
// A socket in a chat's room receives whatever is emitted to the room. The
// owner's own actions re-check his right (ownChat), but the end user's side
// (oblireachHub: replies, typing, remote answers, window closed) went to the
// room without a check: an operator whose account was disabled, who left the
// tenant, lost the capability 'remote', or whose device moved to another
// tenant, kept reading the replies on the sockets already in the room until
// his next action or reconnect. The same rule (chatRightOf) now gates every
// relay, cached a few seconds per chat (a stream of replies, a typing burst:
// one query, and concurrent relays share it).
const RELAY_RIGHT_TTL_MS = 5000;
const relayRights = new Map<string, { ok: boolean; at: number }>();
const relayChecks = new Map<string, Promise<boolean | null>>();

/** A fresh decision about the owner's right to a chat (his own check, a
 *  chat:open), so the relay does not act on an older one. */
function noteChatRight(chatId: string, ok: boolean): void {
  relayRights.set(chatId, { ok, at: Date.now() });
}

/** The owner lost the right to the chat: every socket leaves its room (only
 *  his sockets ever join it) and is told, with chat:ended reason 'forbidden'.
 *  The chat itself is left as it is: the end user's window stays open and his
 *  replies are still stored; the owner may resume it with chat:open once his
 *  right is back. */
function chatRelayRevoked(chatId: string, userId: number): void {
  const io = ioOrNull();
  if (!io) return;
  const room = `chat:${chatId}`;
  if (!io.sockets.adapter.rooms.get(room)?.size) return; // nobody left to tell
  io.to(room).emit('chat:ended', { chatId, reason: 'forbidden' });
  io.in(room).socketsLeave(room);
  logger.info({ chatId, userId }, 'Chat: owner lost the right to it, end user side no longer relayed');
}

/**
 * For oblireachHub, before it relays anything of the end user's side of a chat
 * to the chat's room: true while the chat's owner still has the right to it
 * (chatRightOf). When he lost it, his sockets leave the room first
 * (chatRelayRevoked). False too for an unknown chat. When the database
 * cannot tell, the last known decision stands (nothing is decided or cached):
 * a known revocation stays enforced, and otherwise the relay goes on, since
 * every socket in the room joined after a successful check (an outage must
 * not silently drop the end user's replies).
 */
export async function chatRelayAllowed(chatId: string): Promise<boolean> {
  const chat = chatOwners.get(chatId);
  if (!chat) return false;
  let ok: boolean | null;
  const hit = relayRights.get(chatId);
  if (hit && Date.now() - hit.at < RELAY_RIGHT_TTL_MS) {
    ok = hit.ok;
  } else {
    let check = relayChecks.get(chatId);
    if (!check) {
      check = chatRightOf(chat.userId, chat)
        .then((r) => { noteChatRight(chatId, r); return r; }, () => null)
        .finally(() => { relayChecks.delete(chatId); });
      relayChecks.set(chatId, check);
    }
    ok = await check;
  }
  if (ok === null) return hit ? hit.ok : true;
  if (!ok) chatRelayRevoked(chatId, chat.userId);
  return ok;
}

/** The operator's chat events on one connection (chat:*, join). */
export function installChatSocketHandlers({ io, socket, user, tenantId, liveSession }: SocketConnection): void {
  // The user's chat clients (web tabs, Oblireach Desktop): a chat opened
  // on one of them is announced to the others (chat:opened).
  socket.join(`chatuser:${user.id}`);

  // ── Chat (with tenant isolation) ────────────────────────────────────────
  // Chat actions re-read the LIVE session first (liveSession, socket.ts).
  // The same check, run by ANOTHER socket of this user before it shares a
  // chat with this one (chat:opened): see announceChatOpened.
  socket.data.chatLive = liveSession;
  // The operator's name on a chat: the client's value when it is a usable
  // display name, else the account's. Always a cleaned label (cleanDisplayName).
  const operatorNameOf = (requested?: unknown): string =>
    cleanDisplayName(requested)
    || cleanDisplayName(user.display_name || user.displayName || user.username)
    || 'Operator';
  // The owner's right to a chat, re-checked at most every few seconds per
  // socket (a typing burst, a stream of messages). A refusal takes the
  // chat's room away from every client of this user, each told with
  // chat:ended 'forbidden' (chatRelayRevoked): the end user's replies stop
  // reaching them. `tellCaller`: this socket is told too when it was not in
  // the room (an action; a join or chat:list answers through its ack). A
  // database failure refuses this action only (not cached, rooms kept).
  const CHAT_RIGHT_TTL_MS = 5000;
  const chatRights = new Map<string, { ok: boolean; at: number }>();
  const chatAllowed = async (chatId: string, chat: ChatOwner, tellCaller = false): Promise<boolean> => {
    const hit = chatRights.get(chatId);
    if (hit && Date.now() - hit.at < CHAT_RIGHT_TTL_MS) return hit.ok;
    let ok: boolean;
    try {
      ok = await chatRightOf(user.id, chat);
    } catch {
      return false;
    }
    chatRights.set(chatId, { ok, at: Date.now() });
    noteChatRight(chatId, ok);
    if (!ok) {
      const inRoom = socket.rooms.has(`chat:${chatId}`);
      chatRelayRevoked(chatId, user.id);
      if (tellCaller && !inRoom) socket.emit('chat:ended', { chatId, reason: 'forbidden' });
      logger.info({ chatId, userId: user.id }, 'Chat: owner lost the right to it, rooms left');
    }
    return ok;
  };
  // The chat, if this user opened it (from any of their sockets), it has
  // not ended and they still have the right to it. Re-joins its room, so
  // the end user's replies reach this socket after a reconnect. `tellEnded`:
  // a client still writing to an ended chat (an older Oblireach Desktop
  // keeps writing after the user closed the window) is told, with
  // chat:ended, instead of its messages vanishing (also 'forbidden' when
  // this action finds the right lost: chatAllowed).
  const ownChat = async (chatId: unknown, tellEnded = false): Promise<ChatOwner | null> => {
    if (typeof chatId !== 'string') return null;
    const chat = chatOwners.get(chatId);
    if (!chat || chat.userId !== user.id) return null;
    if (chat.ended) {
      if (tellEnded) socket.emit('chat:ended', chatEndedPayload(chatId, chat));
      return null;
    }
    if (!(await chatAllowed(chatId, chat, tellEnded))) return null;
    if (chat.ended || chatOwners.get(chatId) !== chat) return null;
    chat.lastUsed = Date.now();
    socket.join(`chat:${chatId}`);
    return chat;
  };
  // A new chat appears on the user's other clients (web tabs, Oblireach
  // Desktop): each one whose session is still this user's joins the room
  // (it gets the replies at once) and is told with chat:opened.
  const announceChatOpened = async (chatId: string, chat: ChatOwner): Promise<void> => {
    const peers = await io.in(`chatuser:${user.id}`).except(socket.id).fetchSockets().catch(() => null);
    if (!peers) return;
    const payload = { chatId, deviceUuid: chat.deviceUuid, deviceName: chat.deviceName, tenantId: chat.tenantId };
    for (const peer of peers) {
      const peerLive = peer.data?.chatLive;
      if (typeof peerLive !== 'function') continue;
      const ok = await Promise.resolve(peerLive()).catch(() => null);
      if (!ok) continue;
      if (chat.ended || chatOwners.get(chatId) !== chat) return;
      peer.join(`chat:${chatId}`);
      peer.emit('chat:opened', payload);
    }
  };

  // chat:open {deviceUuid, sessionId?, operatorName}
  //   ack {chatId, resumed, history} | {error}
  // The same user already chatting with this device (another tab, the
  // Oblireach Desktop): the SAME chat is resumed — no second window on the
  // user's desktop. Otherwise a new chat opens there.
  socket.on('chat:open', async (payload: { deviceUuid: string; sessionId?: number; operatorName: string }, ack?: (res: any) => void) => {
    if (!payload?.deviceUuid || typeof payload.deviceUuid !== 'string') return;
    const sess = await liveSession();
    if (!sess) { ack?.({ error: 'session expired' }); return; }
    // The session's CURRENT tenant (what the REST API uses), and the live
    // role: a tenant switch or a role change since the handshake counts.
    const chatTenantId = sess.currentTenantId ?? tenantId;
    if (!chatTenantId) return;
    const operatorUser = await db('users').where({ id: user.id, is_active: true }).first().catch(() => null);
    if (!operatorUser) { ack?.({ error: 'forbidden' }); return; }
    const admin = operatorUser.role === 'admin';
    if (!admin) {
      const member = await db('user_tenants').where({ user_id: user.id, tenant_id: chatTenantId }).first().catch(() => null);
      if (!member) { ack?.({ error: 'forbidden' }); return; }
    }
    // Tenant-scoped device lookup — prevents cross-tenant access. An admin on
    // the master tenant sees every tenant (god view), as in the REST API.
    const deviceQ = db('devices').where({ uuid: payload.deviceUuid });
    if (!(admin && isMasterTenant(chatTenantId))) deviceQ.where({ tenant_id: chatTenantId });
    const device = await deviceQ.first().catch(() => null);
    if (!device) { ack?.({ error: 'device not found' }); return; }
    // A chat opens a window on the user's desktop: same right as opening a
    // remote session (capability 'remote'; owner's decision 27/09). Admins pass.
    if (!admin && !(await permissionService.canUseCapability(user.id, device.id, false, 'remote').catch(() => false))) {
      ack?.({ error: 'forbidden' });
      return;
    }

    // Resume this user's live chat with the device (same checks as above
    // passed). A chat that ends while its history is read is not resumed.
    // Only for the same Windows session: on an RDS host a chat with user A
    // must not swallow what is meant for user B (error other_session: one
    // chat per operator and machine, close the other one first).
    const reqSession = chatSessionOf(payload.sessionId);
    for (let attempt = 0; attempt < 3; attempt++) {
      const live = liveChatOf(user.id, device.uuid);
      if (!live) break;
      const [liveId, liveChat] = live;
      if (!sameChatSession(liveChat.sessionId, reqSession)) { ack?.({ error: 'other_session' }); return; }
      const history = await chatHistory(liveId);
      if (liveChat.ended || chatOwners.get(liveId) !== liveChat) continue;
      liveChat.lastUsed = Date.now();
      chatRights.set(liveId, { ok: true, at: Date.now() });
      noteChatRight(liveId, true);
      socket.join(`chat:${liveId}`);
      ack?.({ chatId: liveId, resumed: true, history });
      logger.info({ chatId: liveId, deviceUuid: device.uuid }, 'Chat session resumed');
      return;
    }
    // (No await from here to chatOwners.set: two concurrent opens by the
    // same user cannot both create a chat.)
    if (liveChatOf(user.id, device.uuid)) { ack?.({ error: 'busy' }); return; }

    const chatId = crypto.randomBytes(8).toString('hex');
    // Operator's avatar
    const operatorAvatar = operatorUser.avatar || null;

    const cmd = {
      type: 'open_chat',
      id: `chat_${chatId}`,
      payload: {
        chatId,
        operatorName: operatorNameOf(payload.operatorName),
        operatorAvatar,
        sessionId: reqSession ?? undefined,
      },
    };
    const delivered = oblireachHub.push(device.uuid, cmd);
    if (!delivered) { ack?.({ error: 'agent offline' }); return; }

    const now = Date.now();
    sweepChats(now);
    const chat: ChatOwner = {
      deviceUuid: device.uuid,
      deviceId: device.id,
      deviceName: String(device.display_name || device.hostname || device.uuid),
      tenantId: device.tenant_id,
      userId: user.id,
      sessionId: reqSession,
      lastUsed: now,
    };
    chatOwners.set(chatId, chat);
    chatRights.set(chatId, { ok: true, at: now });
    noteChatRight(chatId, true);
    socket.join(`chat:${chatId}`);
    ack?.({ chatId, resumed: false, history: [] });
    logger.info({ chatId, deviceUuid: payload.deviceUuid }, 'Chat session opened');
    void announceChatOpened(chatId, chat).catch(() => {});
  });

  // chat:list (ack) -> the calling user's live chats, for a client that
  // starts or reconnects. The socket joins their rooms.
  socket.on('chat:list', async (...args: unknown[]) => {
    const ack = args.find((a): a is (res: unknown) => void => typeof a === 'function');
    if (!ack) return;
    if (!(await liveSession())) { ack([]); return; }
    const list: Array<{ chatId: string; deviceUuid: string; deviceName: string; tenantId: number }> = [];
    const mine = [...chatOwners.keys()].filter((id) => {
      const c = chatOwners.get(id);
      return !!c && c.userId === user.id && !c.ended;
    });
    for (const id of mine) {
      // Same rule as every chat action: a chat the user lost the right to
      // is neither listed nor joined (ownChat).
      const chat = await ownChat(id);
      if (!chat) continue;
      list.push({ chatId: id, deviceUuid: chat.deviceUuid, deviceName: chat.deviceName, tenantId: chat.tenantId });
    }
    ack(list);
  });

  socket.on('chat:message', async (payload: { chatId: string; message: string; operatorName?: string }) => {
    if (!payload?.chatId || typeof payload.message !== 'string' || !payload.message) return;
    if (!(await liveSession())) return;
    const chat = await ownChat(payload.chatId, true);
    if (!chat) return;
    const targetUuid = chat.deviceUuid;
    const sender = operatorNameOf(payload.operatorName);
    const timestamp = Date.now();
    const cmd = {
      type: 'chat_message',
      id: `cmsg_${timestamp}`,
      payload: {
        chatId: payload.chatId,
        message: payload.message,
        operatorName: sender,
        timestamp,
      },
    };
    oblireachHub.push(targetUuid, cmd);
    // The same user's other clients show it as their own message.
    socket.to(`chat:${payload.chatId}`).emit('chat:message', {
      chatId: payload.chatId, sender, message: payload.message, timestamp, fromOperator: true,
    });
    // Persist to DB — under the DEVICE's tenant, like the end user's replies
    // (oblireachHub), so one conversation never spans two tenants.
    try {
      await db('chat_messages').insert({
        chat_id: payload.chatId,
        tenant_id: chat.tenantId,
        device_id: chat.deviceId,
        sender,
        message: payload.message,
        is_operator: true,
      });
    } catch {}
  });

  // Ends the chat for everyone: the user's window closes, the operator's
  // other clients get chat:ended.
  socket.on('chat:close', (payload: { chatId: string }) => {
    if (!payload?.chatId) return;
    const chat = chatOwners.get(payload.chatId);
    if (!chat || chat.userId !== user.id || chat.ended) return;
    oblireachHub.push(chat.deviceUuid, {
      type: 'close_chat',
      id: `cclose_${Date.now()}`,
      payload: { chatId: payload.chatId },
    });
    endChat(payload.chatId, 'operator');
  });

  socket.on('chat:file', async (payload: { chatId: string; fileName: string; fileSize: number; fileData: string }) => {
    if (!payload?.chatId || !payload?.fileData) return;
    if (!(await liveSession())) return;
    const chat = await ownChat(payload.chatId, true);
    if (!chat) return;
    oblireachHub.push(chat.deviceUuid, {
      type: 'chat_file',
      id: `cfile_${Date.now()}`,
      payload: { chatId: payload.chatId, fileName: payload.fileName, fileSize: payload.fileSize, fileData: payload.fileData },
    });
    // A line in the conversation (other clients, history), as the web
    // client shows it locally.
    const name = String(payload.fileName ?? '').slice(0, 255);
    const size = Number(payload.fileSize);
    const note = `📎 ${name}${Number.isFinite(size) && size >= 0 ? ` (${(size / 1024).toFixed(1)} KB)` : ''}`;
    const sender = operatorNameOf();
    const timestamp = Date.now();
    socket.to(`chat:${payload.chatId}`).emit('chat:message', {
      chatId: payload.chatId, sender, message: note, timestamp, fromOperator: true,
    });
    try {
      await db('chat_messages').insert({
        chat_id: payload.chatId,
        tenant_id: chat.tenantId,
        device_id: chat.deviceId,
        sender,
        message: note,
        is_operator: true,
      });
    } catch {}
  });

  socket.on('chat:typing', async (payload: { chatId: string }) => {
    if (!payload?.chatId) return;
    const chat = await ownChat(payload.chatId);
    if (!chat) return;
    oblireachHub.push(chat.deviceUuid, {
      type: 'chat_typing',
      id: `ctyp_${Date.now()}`,
      payload: { chatId: payload.chatId },
    });
  });

  socket.on('chat:request_remote', async (payload: { chatId: string; message?: string }) => {
    if (!payload?.chatId) return;
    if (!(await liveSession())) return;
    const chat = await ownChat(payload.chatId, true);
    if (!chat) return;
    oblireachHub.push(chat.deviceUuid, {
      type: 'request_remote',
      id: `creq_${Date.now()}`,
      payload: { chatId: payload.chatId, message: payload.message || '' },
    });
  });

  // (Re)join a chat's room — only a live chat this user opened: the room
  // carries the end user's replies. Clients re-emit it after a reconnect.
  // ack {ok: true, history} (the last messages, for a client that missed
  // them), {ok: false, ended} for a chat that ended (do not reopen it), or
  // {ok: false} when the chat is unknown (server restart: a client may open
  // a new one), {ok: false, error: 'forbidden'} when the user lost the
  // right to it (capability 'remote', tenant membership).
  socket.on('join', async (room: string, ack?: (res: { ok: boolean; ended?: ChatEndReason; code?: unknown; installing?: unknown; state?: unknown; detail?: unknown; wv2Reason?: unknown; installOffer?: unknown; error?: 'forbidden'; history?: ChatHistoryEntry[] }) => void) => {
    if (typeof room !== 'string' || !room.startsWith('chat:')) { ack?.({ ok: false }); return; }
    if (!(await liveSession())) { ack?.({ ok: false }); return; }
    const chatId = room.slice('chat:'.length);
    const known = chatOwners.get(chatId);
    if (known && known.userId === user.id && known.ended) {
      // 'unavailable': with its code / installing / state / detail (chatEndedPayload).
      const { chatId: _c, reason: _r, ...info } = chatEndedPayload(chatId, known);
      ack?.({ ok: false, ended: known.ended, ...info });
      return;
    }
    if (!(await ownChat(chatId))) {
      const denied = !!known && known.userId === user.id && !known.ended && chatRights.get(chatId)?.ok === false;
      ack?.(denied ? { ok: false, error: 'forbidden' } : { ok: false });
      return;
    }
    if (!ack) return;
    ack({ ok: true, history: await chatHistory(chatId) });
  });
}
