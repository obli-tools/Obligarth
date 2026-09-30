import { useEffect, useRef, useState, useCallback } from 'react';
import { X, Send, Shield, Paperclip, Minus, MessageCircle, RotateCcw } from 'lucide-react';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import type { Socket } from 'socket.io-client';
import i18n from '@/i18n';
import { getSocket } from '@/socket/socketClient';
import { useAuthStore } from '@/store/authStore';
import { useSocketStore } from '@/store/socketStore';
import { useChatStore, type ChatSession, type ChatHistoryEntry, type ChatEndReason, type RemoteChatInfo } from '@/store/chatStore';
import { useRemoteShellStore } from '@/store/remoteShellStore';
import { useLayoutMode } from '@/hooks/useMediaQuery';
import { useNativeBack } from '@/hooks/useNativeBack';
import { webview2ReasonText } from '@/components/devices/ObliReachWebView2Line';

// ── Helpers ────────────────────────────────────────────────────────────────────

let audioCtx: AudioContext | null = null;
function playNotificationSound() {
 try {
 if (!audioCtx) audioCtx = new AudioContext();
 const osc = audioCtx.createOscillator();
 const gain = audioCtx.createGain();
 osc.connect(gain);
 gain.connect(audioCtx.destination);
 osc.frequency.value = 800;
 gain.gain.value = 0.15;
 osc.start();
 gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3);
 osc.stop(audioCtx.currentTime + 0.3);
 } catch {}
}

function formatTime(ts: number) {
 return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function getInitials(name: string) {
 return name.split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0, 2);
}

/** Encode an ArrayBuffer to base64 without blowing the call stack (chunked). */
function arrayBufferToBase64(buf: ArrayBuffer): string {
 const bytes = new Uint8Array(buf);
 const chunks: string[] = [];
 for (let i = 0; i < bytes.length; i += 8192) {
 chunks.push(String.fromCharCode(...bytes.subarray(i, i + 8192)));
 }
 return btoa(chunks.join(''));
}

const TEMPLATE_LANGUAGES = [
 { code: 'en', name: 'English' }, { code: 'fr', name: 'Français' },
 { code: 'es', name: 'Español' }, { code: 'de', name: 'Deutsch' },
 { code: 'pt', name: 'Português' }, { code: 'zh', name: '中文' },
 { code: 'ja', name: '日本語' }, { code: 'ko', name: '한국어' },
 { code: 'ru', name: 'Русский' }, { code: 'ar', name: 'العربية' },
 { code: 'it', name: 'Italiano' }, { code: 'nl', name: 'Nederlands' },
 { code: 'pl', name: 'Polski' }, { code: 'tr', name: 'Türkçe' },
 { code: 'sv', name: 'Svenska' }, { code: 'da', name: 'Dansk' },
 { code: 'cs', name: 'Čeština' }, { code: 'uk', name: 'Українська' },
];

// ── Unified chat: socket sync ──────────────────────────────────────────────────
// One conversation per (operator, machine), shared by every client of the
// operator (other tabs, the Oblireach Desktop): chat:open resumes the live
// chat ({chatId, resumed, history}), the operator's messages typed elsewhere
// come back with fromOperator, chat:opened / chat:ended announce the others'
// chats, chat:list recovers them after a (re)connect. Handled here, at the
// panel level (always mounted), so a minimized panel still counts unread
// messages and picks up chats opened elsewhere.

type OpenAck = { chatId?: string; resumed?: boolean; history?: ChatHistoryEntry[]; error?: string };
type JoinAck = { ok?: boolean; ended?: ChatEndReason; error?: string; history?: ChatHistoryEntry[] } & ChatUnavailableEnd;
type IncomingMessage = { chatId: string; sender: string; message: string; timestamp?: number; fromOperator?: boolean };

const OPEN_TIMEOUT_MS = 5000;
/** chat:open attempts per tab: an answer only counts for the tab's latest attempt. */
const openAttempts = new Map<string, number>();
/** Socket id the rejoin / chat:list already ran for (one sync per connection). */
let syncedSocketId: string | null = null;

const chatState = () => useChatStore.getState();
const findByChatId = (chatId: unknown) =>
 typeof chatId === 'string' ? chatState().sessions.find(s => s.chatId === chatId) : undefined;
const systemLine = (key: string, text: string) =>
 chatState().addMessage(key, { sender: 'System', text, timestamp: Date.now(), isSystem: true });
const operatorDisplayName = () => {
 const u = useAuthStore.getState().user;
 return u?.displayName || u?.username || 'Operator';
};

/** Server refusals are codes: say what they mean, never the raw code. */
function openErrorText(error?: string): string {
 if (error === 'forbidden') return i18n.t('chat.forbidden', 'You cannot chat with this machine: it needs the right to open a remote session on it.');
 if (error === 'device not found') return i18n.t('chat.deviceNotFound', 'This machine was not found in the current tenant.');
 if (error === 'session expired') return i18n.t('chat.sessionExpired', 'Your session has expired: sign in again to chat.');
 if (error === 'busy') return i18n.t('chat.busy', 'A chat with this machine is being opened on another of your screens: try again in a moment.');
 if (error === 'other_session') return i18n.t('chat.otherSession', 'You are already chatting with another session of this machine: close that chat first.');
 const reason = !error || error === 'agent offline' ? i18n.t('chat.agentOffline', 'agent offline') : error;
 return i18n.t('chat.failedToOpen', { error: reason, defaultValue: 'Failed to open chat: {{error}}' });
}

/** Details of a chat that could not open on the machine (chat:ended reason 'unavailable'). */
type ChatUnavailableEnd = { code?: unknown; installing?: unknown; state?: unknown; detail?: unknown; wv2Reason?: unknown; installOffer?: unknown };

/**
 * What the operator can do about a missing runtime, from what the server says
 * the device page offers (installOffer): the Install / Retry button, nothing
 * because the platform setting disables installs, or nothing because this
 * ObliReach build cannot install. Unknown: no hint (never a button that is
 * not there).
 */
function chatUnavailableHint(info: ChatUnavailableEnd | undefined, failed: boolean): string {
 const offer = typeof info?.installOffer === 'string' ? info.installOffer : '';
 if (offer === 'disabled') return i18n.t('chat.unavailable.hint.disabled', 'Its automatic installation is disabled (Settings > ObliReach): install it on the machine, or change that setting.');
 if (offer === 'no_installer') return i18n.t('chat.unavailable.hint.noInstaller', 'The ObliReach agent of this machine cannot install it: update ObliReach first.');
 if (offer === 'button') {
 return failed
 ? i18n.t('chat.unavailable.hint.retry', 'It can be retried from the machine\'s page (Remote tab).')
 : i18n.t('chat.unavailable.hint.install', 'It can be installed from the machine\'s page (Remote tab).');
 }
 return '';
}

/** The agent's technical detail (English), apart from the translated sentence. */
function chatTechnicalDetail(info: ChatUnavailableEnd | undefined): string {
 const detail = typeof info?.detail === 'string' ? info.detail.trim() : '';
 return detail ? i18n.t('chat.unavailable.technicalDetail', { detail, defaultValue: 'Technical detail: {{detail}}' }) : '';
}

/** Exact text of a chat that could not open (never "the user closed it"). */
function chatUnavailableText(info: ChatUnavailableEnd | undefined): string {
 const code = typeof info?.code === 'string' ? info.code : '';
 const state = typeof info?.state === 'string' ? info.state : '';
 const wv2Reason = typeof info?.wv2Reason === 'string' ? info.wv2Reason : null;
 const join = (...parts: string[]) => parts.filter(Boolean).join(' ');
 if (code === 'webview2_missing') {
 if (info?.installing === true || state === 'installing') {
 return i18n.t('chat.unavailable.installing', 'The chat window cannot open on this machine: the Microsoft Edge WebView2 Runtime is missing. It is being installed now: start a new chat in a few minutes.');
 }
 if (state === 'blocked') return i18n.t('chat.unavailable.blocked', 'The chat window cannot open on this machine: the Microsoft Edge WebView2 Runtime is missing and a Microsoft Edge Update policy forbids installing it.');
 if (state === 'unsupported') return i18n.t('chat.unavailable.unsupported', 'The chat window cannot open on this machine: its version of Windows does not support the Microsoft Edge WebView2 Runtime.');
 if (state === 'failed') {
 // The reason in words (the device page's own wording); the agent's raw
 // English error only as a technical detail after the sentence.
 const reason = webview2ReasonText(wv2Reason, i18n.t);
 return join(
 reason
 ? i18n.t('chat.unavailable.failedReason', { reason, defaultValue: 'The chat window cannot open on this machine: the Microsoft Edge WebView2 Runtime is missing and its installation failed ({{reason}}).' })
 : i18n.t('chat.unavailable.failed', 'The chat window cannot open on this machine: the Microsoft Edge WebView2 Runtime is missing and its installation failed.'),
 chatUnavailableHint(info, true),
 reason ? '' : chatTechnicalDetail(info),
 );
 }
 return join(
 wv2Reason === 'per_user_only'
 ? i18n.t('chat.unavailable.perUserOnly', 'The chat window cannot open on this machine: the Microsoft Edge WebView2 Runtime is installed for another user only, not for the whole machine.')
 : i18n.t('chat.unavailable.missing', 'The chat window cannot open on this machine: the Microsoft Edge WebView2 Runtime is missing.'),
 chatUnavailableHint(info, false),
 );
 }
 if (code === 'no_user') return i18n.t('chat.unavailable.noUser', 'Nobody is signed in on this machine: the chat window only opens in a signed-in user\'s session. Your message was not shown.');
 if (code === 'webview2_failed') {
 return join(i18n.t('chat.unavailable.webviewFailed', 'The chat window could not start on this machine (Microsoft Edge WebView2 Runtime not working). The user did not see your message.'), chatTechnicalDetail(info));
 }
 if (code === 'webview2_timeout') return i18n.t('chat.unavailable.timeout', 'The chat window took too long to start on this machine (Microsoft Edge WebView2 Runtime). The user did not see your message.');
 return join(i18n.t('chat.unavailable.helperFailed', 'The chat window could not open on this machine. The user did not see your message.'), chatTechnicalDetail(info));
}

/** The chat is over (closed by an operator, here or elsewhere, by the user, or it could not open). */
function endChatSession(key: string, reason: ChatEndReason, info?: ChatUnavailableEnd) {
 const s = chatState().sessions.find(x => x.key === key);
 if (!s || s.ended) return;
 chatState().markEnded(key, reason);
 systemLine(key, reason === 'user'
 ? i18n.t('chat.endedByUser', 'The user closed the chat window: this conversation is over. Start a new chat to write to them again.')
 : reason === 'unavailable'
 ? chatUnavailableText(info)
 : i18n.t('chat.endedByOperator', 'This chat was closed (here or on another of your screens).'));
}

/** chat:open for a tab that has no chat yet (a live chat of this operator with the machine is resumed). */
function startChat(key: string) {
 const s = chatState().sessions.find(x => x.key === key);
 if (!s || s.chatId || s.ended || s.failed || s.opening) return;
 const socket = getSocket();
 if (!socket?.connected) return; // started by the sync once connected
 const attempt = (openAttempts.get(key) ?? 0) + 1;
 openAttempts.set(key, attempt);
 chatState().patchSession(key, { opening: true });
 let answered = false;
 socket.emit('chat:open', { deviceUuid: s.deviceUuid, sessionId: s.sessionId, operatorName: operatorDisplayName() }, (res: OpenAck) => {
 answered = true;
 const cur = chatState().sessions.find(x => x.key === key);
 if (!cur || openAttempts.get(key) !== attempt || cur.chatId || cur.ended) {
 // The tab was closed while opening: a chat created for nobody is closed
 // again — never a resumed one (another client uses it).
 if (!cur && res?.chatId && !res.resumed && !findByChatId(res.chatId)) socket.emit('chat:close', { chatId: res.chatId });
 return;
 }
 if (!res?.chatId) {
 chatState().patchSession(key, { opening: false, failed: true });
 systemLine(key, openErrorText(res?.error));
 return;
 }
 // Another tab here already shows this conversation: keep that one.
 const twin = findByChatId(res.chatId);
 if (twin && twin.key !== key) {
 chatState().closeTab(key);
 useChatStore.setState({ activeKey: twin.key, isOpen: true, isMinimized: false });
 return;
 }
 chatState().patchSession(key, { chatId: res.chatId, opening: false, failed: false, isConnected: true, userClosed: false });
 if (res.resumed) {
 chatState().applyHistory(key, res.history);
 systemLine(key, i18n.t('chat.resumed', 'Conversation resumed: it is also open on another of your screens.'));
 }
 });
 setTimeout(() => {
 if (answered || openAttempts.get(key) !== attempt) return;
 const cur = chatState().sessions.find(x => x.key === key);
 if (!cur || cur.chatId || !cur.opening) return;
 // Said once; a late answer is still taken (the tab keeps waiting for it).
 chatState().patchSession(key, { opening: false, failed: true });
 systemLine(key, i18n.t('chat.connectionTimeout', 'Chat connection timed out.'));
 }, OPEN_TIMEOUT_MS);
}

/** (Re)joins a chat's room; the answer brings its history (a recovered chat) or says it ended. */
function joinChat(socket: Socket, key: string, chatId: string) {
 socket.emit('join', `chat:${chatId}`, (res?: JoinAck) => {
 const cur = chatState().sessions.find(x => x.key === key);
 if (!cur || cur.chatId !== chatId || cur.ended) return;
 if (res?.ok) {
 chatState().setConnected(key, true);
 // The messages missed while disconnected are added (and announced).
 if (chatState().applyHistory(key, res.history) > 0 && chatState().soundEnabled) playNotificationSound();
 return;
 }
 if (res?.ended) { endChatSession(key, res.ended, res); return; }
 // Unknown to the server (restart): the tab offers a new conversation.
 // Refused (the right to chat with this machine was withdrawn): said so.
 chatState().patchSession(key, { isConnected: false, failed: true, remoteRequested: false });
 systemLine(key, res?.error === 'forbidden'
 ? openErrorText('forbidden')
 : i18n.t('chat.resumeFailed', 'The chat could not be resumed after the connection was lost: close it and open it again.'));
 });
}

/** Adds the tab of a chat this operator opened elsewhere, and fetches its messages
 * (`unread`: just opened elsewhere — chat:opened — rather than recovered by chat:list). */
function adoptRemoteChat(socket: Socket, info: RemoteChatInfo, unread = false) {
 if (!info || typeof info.chatId !== 'string' || typeof info.deviceUuid !== 'string') return;
 const key = chatState().addRemoteChat(info, { unread });
 if (key) joinChat(socket, key, info.chatId);
}

/**
 * Socket side of the chat, for the panel's whole life: incoming events, the
 * tabs waiting for a chat, and after each (re)connect the rejoin of the live
 * conversations plus chat:list (chats opened on the operator's other clients).
 */
function useChatSync() {
 const status = useSocketStore(s => s.status);
 const sessions = useChatStore(s => s.sessions);

 // Tabs waiting for a chat (new tab, restart, socket back).
 useEffect(() => {
 if (status !== 'connected') return;
 for (const s of sessions) {
 if (!s.chatId && !s.ended && !s.failed && !s.opening) startChat(s.key);
 }
 }, [sessions, status]);

 useEffect(() => {
 if (status !== 'connected') return;
 const socket = getSocket();
 if (!socket) return;

 const onMessage = (data: IncomingMessage) => {
 const s = findByChatId(data?.chatId);
 if (!s || typeof data.message !== 'string') return;
 // Typed by this operator on another client: their own bubble, silently.
 const own = data.fromOperator === true;
 chatState().addMessage(s.key, { sender: data.sender, text: data.message, timestamp: data.timestamp || Date.now(), isOperator: own });
 if (!own && chatState().soundEnabled) playNotificationSound();
 };
 // Older event of the same end (the window closed on the user's side).
 const onClosed = (data: { chatId: string }) => {
 const s = findByChatId(data?.chatId);
 if (s) endChatSession(s.key, 'user');
 };
 const onEnded = (data: { chatId: string; reason?: string } & ChatUnavailableEnd) => {
 const s = findByChatId(data?.chatId);
 if (!s) return;
 const reason: ChatEndReason = data.reason === 'user' ? 'user' : data.reason === 'unavailable' ? 'unavailable' : 'operator';
 endChatSession(s.key, reason, data);
 };
 const onOpened = (data: RemoteChatInfo) => adoptRemoteChat(socket, data, true);
 const onRemoteResponse = (data: { chatId: string; allowed: boolean }) => {
 const s = findByChatId(data?.chatId);
 if (!s) return;
 const askedHere = !!s.remoteRequested;
 chatState().patchSession(s.key, { remoteRequested: false });
 systemLine(s.key, data.allowed ? i18n.t('chat.remoteGranted', 'Remote control access granted.') : i18n.t('chat.remoteDenied', 'Remote control access denied.'));
 // Start the ObliReach session only where it was asked for (the answer
 // reaches every client of the conversation).
 if (data.allowed && askedHere) chatState().onRemoteAccessGranted?.(s.key);
 };

 const sync = () => {
 if (!socket.connected || !socket.id || syncedSocketId === socket.id) return;
 syncedSocketId = socket.id;
 for (const s of chatState().sessions) {
 if (s.chatId && !s.ended && !s.failed) joinChat(socket, s.key, s.chatId);
 else if (!s.chatId && s.opening) {
 // Its chat:open went down with the old connection: open again.
 openAttempts.set(s.key, (openAttempts.get(s.key) ?? 0) + 1);
 chatState().patchSession(s.key, { opening: false });
 }
 }
 socket.emit('chat:list', (list: unknown) => {
 if (!Array.isArray(list)) return;
 for (const info of list) adoptRemoteChat(socket, info as RemoteChatInfo);
 });
 };

 socket.on('chat:message', onMessage);
 socket.on('chat:closed', onClosed);
 socket.on('chat:ended', onEnded);
 socket.on('chat:opened', onOpened);
 socket.on('chat:remote_response', onRemoteResponse);
 socket.on('connect', sync);
 sync();
 return () => {
 socket.off('chat:message', onMessage);
 socket.off('chat:closed', onClosed);
 socket.off('chat:ended', onEnded);
 socket.off('chat:opened', onOpened);
 socket.off('chat:remote_response', onRemoteResponse);
 socket.off('connect', sync);
 };
 }, [status]);
}

// ── Operator avatar ────────────────────────────────────────────────────────────
function OperatorAvatar({ avatarUrl, size = 28 }: { avatarUrl?: string | null; size?: number }) {
 if (avatarUrl) {
 return <img src={avatarUrl} alt="" className="rounded-full object-cover" style={{ width: size, height: size }} />;
 }
 return (
 <div className="rounded-full bg-accent flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
 <svg className="text-white" style={{ width: size * 0.55, height: size * 0.55 }} fill="currentColor" viewBox="0 0 24 24">
 <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/>
 </svg>
 </div>
 );
}

// ── Single tab content ─────────────────────────────────────────────────────────
function ChatTabContent({ session }: { session: ChatSession }) {
 const { t } = useTranslation();
 const [input, setInput] = useState('');
 const [isDragging, setIsDragging] = useState(false);
 const [uploadProgress, setUploadProgress] = useState<string | null>(null);
 const [showRequestDialog, setShowRequestDialog] = useState(false);
 const [requestMessage, setRequestMessage] = useState('');
 const [isTyping, setIsTyping] = useState(false);
 const [showTemplates, setShowTemplates] = useState(false);
 const [templateLang, setTemplateLang] = useState(() => useAuthStore.getState().user?.preferredLanguage || 'en');

 const bottomRef = useRef<HTMLDivElement>(null);
 const inputRef = useRef<HTMLInputElement>(null);
 const fileInputRef = useRef<HTMLInputElement>(null);

 const store = useChatStore;
 // Reactive auth reads (re-render when avatar/name change)
 const operatorAvatar = useAuthStore(s => s.user?.avatar ?? null);
 const operatorName = useAuthStore(s => s.user?.displayName || s.user?.username || 'Operator');

 // Quick reply templates (loaded once)
 const [quickReplyTemplates, setQuickReplyTemplates] = useState<Array<{ id: number; translations: Record<string, string> }>>([]);
 const personalQuickReplies = useAuthStore(s => s.user?.preferences?.quickReplies ?? []) as string[];
 useEffect(() => {
 import('@/api/quickReplyTemplates.api').then(({ quickReplyTemplatesApi }) => {
 quickReplyTemplatesApi.list().then(setQuickReplyTemplates).catch(() => {});
 });
 }, []);
 const adminRepliesInLang = quickReplyTemplates.map(t => t.translations[templateLang]).filter(Boolean);
 const allQuickReplies = [...personalQuickReplies, ...adminRepliesInLang];

 const { key, chatId, messages, isConnected, ended, failed, opening } = session;
 const remoteRequested = !!session.remoteRequested;

 // Auto-reset typing indicator after 3s of silence
 const typingTimer = useRef<ReturnType<typeof setTimeout>>();
 useEffect(() => {
 if (!isTyping) return;
 typingTimer.current = setTimeout(() => setIsTyping(false), 3000);
 return () => clearTimeout(typingTimer.current);
 }, [isTyping]);

 // Emit typing to agent (debounced — max once per 2s)
 const lastTypingEmit = useRef(0);
 const emitTyping = useCallback(() => {
 if (!chatId || ended) return;
 const now = Date.now();
 if (now - lastTypingEmit.current < 2000) return;
 lastTypingEmit.current = now;
 const socket = getSocket();
 if (socket) socket.emit('chat:typing', { chatId });
 }, [chatId, ended]);

 // Scroll on new messages
 useEffect(() => {
 bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
 }, [messages]);

 // Typing indicator of this tab (messages, the chat's end, remote-control
 // answers: useChatSync at the panel level).
 const socketStatus = useSocketStore(s => s.status);
 useEffect(() => {
 const socket = getSocket();
 if (!socket || !chatId) return;
 const onTyping = (data: { chatId: string }) => {
 if (data?.chatId === chatId) setIsTyping(true);
 };
 const onMessage = (data: { chatId: string; fromOperator?: boolean }) => {
 if (data?.chatId === chatId && !data.fromOperator) setIsTyping(false);
 };
 socket.on('chat:typing', onTyping);
 socket.on('chat:message', onMessage);
 return () => { socket.off('chat:typing', onTyping); socket.off('chat:message', onMessage); };
 }, [chatId, socketStatus]);
 useEffect(() => { if (ended) setIsTyping(false); }, [ended]);

 const canSend = !!chatId && isConnected && !ended;

 const handleSend = useCallback(() => {
 if (!input.trim() || !canSend) return;
 const socket = getSocket();
 if (!socket) return;
 store.getState().addMessage(key, { sender: operatorName, text: input.trim(), timestamp: Date.now(), isOperator: true });
 socket.emit('chat:message', { chatId, message: input.trim(), operatorName });
 setInput('');
 inputRef.current?.focus();
 }, [input, chatId, canSend, key, operatorName]);

 const handleFileSend = useCallback(async (file: File) => {
 if (!canSend) return;
 if (file.size > 5 * 1024 * 1024) {
 store.getState().addMessage(key, { sender: 'System', text: t('chat.fileTooLarge'), timestamp: Date.now(), isSystem: true });
 return;
 }
 setUploadProgress(t('chat.sendingFile', { name: file.name }) || `Sending ${file.name}...`);
 try {
 const buf = await file.arrayBuffer();
 const b64 = arrayBufferToBase64(buf);
 const socket = getSocket();
 if (socket) {
 socket.emit('chat:file', { chatId, fileName: file.name, fileSize: file.size, fileData: b64 });
 store.getState().addMessage(key, { sender: operatorName, text: `📎 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, timestamp: Date.now(), isOperator: true });
 }
 } catch {
 store.getState().addMessage(key, { sender: 'System', text: t('chat.failedSendFile'), timestamp: Date.now(), isSystem: true });
 } finally { setUploadProgress(null); }
 }, [chatId, canSend, key, operatorName]);

 const handleDrop = useCallback((e: React.DragEvent) => {
 e.preventDefault(); setIsDragging(false);
 const file = e.dataTransfer.files[0];
 if (file) handleFileSend(file);
 }, [handleFileSend]);

 const handleRequestRemote = useCallback(() => {
 const socket = getSocket();
 if (!socket || !canSend) return;
 socket.emit('chat:request_remote', { chatId, message: requestMessage });
 // In the store: the answer is handled at the panel level (useChatSync).
 store.getState().patchSession(key, { remoteRequested: true });
 setShowRequestDialog(false);
 store.getState().addMessage(key, { sender: 'System', text: t('chat.remoteRequestSent'), timestamp: Date.now(), isSystem: true });
 }, [chatId, canSend, requestMessage, key]);

 return (
 <div
 className="flex flex-col flex-1 overflow-hidden relative"
 onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
 onDragLeave={() => setIsDragging(false)}
 onDrop={handleDrop}
 >
 {isDragging && (
 <div className="absolute inset-0 z-10 bg-accent/20 border-2 border-dashed border-accent flex items-center justify-center rounded-2xl">
 <span className="text-accent font-medium">{t('chat.dropToSend')}</span>
 </div>
 )}

 {/* Messages */}
 <div className="flex-1 overflow-y-auto px-4 py-2 space-y-3 scrollbar-thin scrollbar-thumb-white/10">
 {messages.map((msg, i) => {
 const isOp = !!msg.isOperator;
 const showTimestamp = i === 0 || (msg.timestamp - messages[i - 1].timestamp > 300_000);
 return (
 <div key={i}>
 {showTimestamp && (
 <div className="text-center py-2">
 <span className="text-[10px] text-text-muted bg-bg-tertiary px-3 py-1 rounded-full">
 {new Date(msg.timestamp).toLocaleDateString([], { weekday: 'long' })}, {formatTime(msg.timestamp)}
 </span>
 </div>
 )}
 {msg.isSystem ? (
 <div className="text-center py-1">
 <span className="text-[11px] text-yellow-400/80 bg-yellow-400/10 px-3 py-1 rounded-full">{msg.text}</span>
 </div>
 ) : (
 <div className={clsx('flex gap-2', isOp ? 'justify-start' : 'justify-end')}>
 {isOp && <OperatorAvatar avatarUrl={operatorAvatar} size={28} />}
 <div className={clsx(
 'max-w-[75%] px-4 py-2.5 rounded-2xl text-[13px] leading-relaxed',
 isOp ? 'bg-accent text-white rounded-bl-md' : 'bg-bg-tertiary text-text-primary rounded-br-md'
 )}>
 {msg.text}
 </div>
 {!isOp && (
 <div className="w-7 h-7 rounded-full bg-bg-hover flex items-center justify-center shrink-0 mt-auto text-[10px] font-bold text-text-secondary">
 {getInitials(msg.sender)}
 </div>
 )}
 </div>
 )}
 </div>
 );
 })}

 {/* Typing indicator (device is typing → right side) */}
 {isTyping && (
 <div className="flex gap-2 items-end justify-end">
 <div className="bg-bg-tertiary px-4 py-2.5 rounded-2xl rounded-br-md">
 <div className="flex gap-1">
 <span className="w-2 h-2 bg-text-muted/60 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
 <span className="w-2 h-2 bg-text-muted/60 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
 <span className="w-2 h-2 bg-text-muted/60 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
 </div>
 </div>
 </div>
 )}

 <div ref={bottomRef} />
 </div>

 {/* Request remote dialog */}
 {showRequestDialog && (
 <div className="px-4 py-3 bg-bg-tertiary space-y-2">
 <p className="text-[11px] text-text-muted">{t('chat.customMessage')}</p>
 <input value={requestMessage} onChange={e => setRequestMessage(e.target.value)}
 placeholder={t('chat.customMessagePlaceholder')}
 className="w-full px-3 py-2 text-xs bg-bg-primary rounded-lg text-text-primary placeholder-text-muted" />
 <div className="flex gap-2">
 <button onClick={handleRequestRemote}
 className="flex-1 px-3 py-2 text-xs bg-accent text-white rounded-lg hover:bg-accent-hover transition-colors font-medium">
 {t('chat.sendRequest')}
 </button>
 <button onClick={() => setShowRequestDialog(false)}
 className="px-3 py-2 text-xs bg-bg-hover text-text-secondary rounded-lg hover:text-text-primary transition-colors">
 {t('common.cancel')}
 </button>
 </div>
 </div>
 )}

 {/* Bottom bar */}
 <div className="shrink-0 px-4 py-3 space-y-2 ">
 {canSend && !remoteRequested && !showRequestDialog && (
 <button onClick={() => setShowRequestDialog(true)}
 className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-[11px] bg-accent/10 text-accent border border-accent/20 rounded-xl hover:bg-accent/20 transition-colors font-medium">
 <Shield className="w-3.5 h-3.5" />
 {t('chat.requestRemote')}
 </button>
 )}
 {remoteRequested && (
 <div className="text-[11px] text-center text-yellow-400/80 py-1">{t('chat.waitingResponse')}</div>
 )}
 {uploadProgress && (
 <div className="text-[11px] text-center text-accent py-1 animate-pulse">{uploadProgress}</div>
 )}
 {/* Ended (here, on another screen, or by the user) or could not open:
 a new conversation starts on demand, never by itself. */}
 {(ended || failed) && (
 <button onClick={() => store.getState().restartChat(key)}
 className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-[11px] bg-accent/10 text-accent border border-accent/20 rounded-xl hover:bg-accent/20 transition-colors font-medium coarse:min-h-10">
 <RotateCcw className="w-3.5 h-3.5" />
 {ended ? t('chat.startNew', 'Start a new chat') : t('chat.retry', 'Try again')}
 </button>
 )}

 {/* Quick replies */}
 {showTemplates && (
 <div className="space-y-1.5 max-h-40 overflow-y-auto">
 {quickReplyTemplates.length > 0 && (
 <select value={templateLang} onChange={e => setTemplateLang(e.target.value)}
 className="w-full px-2 py-1 text-[11px] bg-bg-primary rounded-lg text-text-secondary mb-1">
 {TEMPLATE_LANGUAGES.map(l => (
 <option key={l.code} value={l.code}>{l.name}</option>
 ))}
 </select>
 )}
 {personalQuickReplies.length > 0 && (
 <div className="text-[9px] text-text-muted uppercase tracking-wider px-1">{t('chat.personal')}</div>
 )}
 {personalQuickReplies.map((t, i) => (
 <button key={`p-${i}`} onClick={() => { setInput(t); setShowTemplates(false); inputRef.current?.focus(); }}
 className="w-full text-left px-3 py-1.5 text-[11px] bg-bg-hover text-text-secondary rounded-lg hover:bg-accent/15 hover:text-text-primary truncate transition-colors">
 {t}
 </button>
 ))}
 {adminRepliesInLang.length > 0 && (
 <div className="text-[9px] text-text-muted uppercase tracking-wider px-1 pt-1">{t('chat.templates')}</div>
 )}
 {adminRepliesInLang.map((t, i) => (
 <button key={`t-${i}`} onClick={() => { setInput(t); setShowTemplates(false); inputRef.current?.focus(); }}
 className="w-full text-left px-3 py-1.5 text-[11px] bg-accent/10 text-text-secondary rounded-lg hover:bg-accent/20 hover:text-text-primary truncate transition-colors">
 {t}
 </button>
 ))}
 {allQuickReplies.length === 0 && (
 <div className="text-[11px] text-text-muted text-center py-2 italic">{t('chat.noQuickReplies')}</div>
 )}
 </div>
 )}

 {/* Input */}
 <div className="flex items-center gap-2 bg-bg-primary rounded-2xl px-3 py-1.5">
 <button onClick={() => setShowTemplates(v => !v)} title={t('chat.quickReplies')}
 aria-label={t('chat.quickReplies')} aria-expanded={showTemplates}
 className="text-text-muted hover:text-accent transition-colors text-xs font-mono coarse:min-h-10 coarse:min-w-8 coarse:text-sm">/</button>
 <input
 ref={inputRef}
 value={input}
 onChange={e => { setInput(e.target.value); emitTyping(); }}
 onKeyDown={e => e.key === 'Enter' && handleSend()}
 placeholder={canSend ? t('chat.messagePlaceholder')
 : ended === 'unavailable' ? t('chat.unavailableShort', 'Chat could not open')
 : ended ? t('chat.ended', 'Chat ended')
 : opening ? t('chat.connecting', 'Connecting…')
 : t('chat.disconnected')}
 aria-label={t('chat.messagePlaceholder')}
 enterKeyHint="send"
 disabled={!canSend}
 className="flex-1 bg-transparent text-[13px] text-text-primary placeholder-text-muted outline-none disabled:opacity-40"
 />
 <input ref={fileInputRef} type="file" className="hidden"
 onChange={e => { const f = e.target.files?.[0]; if (f) handleFileSend(f); e.target.value = ''; }} />
 <button onClick={() => fileInputRef.current?.click()} disabled={!canSend}
 title={t('chat.attachFile') || 'Attach a file'} aria-label={t('chat.attachFile') || 'Attach a file'}
 className="text-text-muted hover:text-accent transition-colors disabled:opacity-30 coarse:min-h-10 coarse:min-w-10 coarse:flex coarse:items-center coarse:justify-center">
 <Paperclip className="w-4 h-4" />
 </button>
 <button onClick={handleSend} disabled={!canSend || !input.trim()}
 aria-label={t('chat.send') || 'Send'}
 className="w-8 h-8 rounded-xl bg-accent flex items-center justify-center hover:bg-accent-hover disabled:opacity-30 transition-colors shrink-0 coarse:w-10 coarse:h-10">
 <Send className="w-3.5 h-3.5 text-white" />
 </button>
 </div>
 </div>
 </div>
 );
}

// ── Main component ─────────────────────────────────────────────────────────────
/**
 * Global chat: a FAB when minimized, a 400×620 panel otherwise — both live
 * in the bottom-right FloatingDock (AppLayout) so they stack with the toasts
 * and the shell pill instead of overlapping them. On phones the open panel
 * is full screen (safe areas, keyboard-aware via dvh) and the Android back
 * button minimizes it.
 */
export function GlobalChatPanel() {
 const { t } = useTranslation();
 useChatSync();
 const { sessions, activeKey, isOpen, isMinimized } = useChatStore();
 const { setActiveTab, closeTab, setMinimized, toggleOpen, clearUnread } = useChatStore();
 // Status dot of a conversation: live, ended by the user (yellow), anything else (grey).
 const dotClass = (s: ChatSession | null) =>
 s?.isConnected && !s.ended ? 'bg-green-400' : s?.ended === 'user' ? 'bg-yellow-400' : 'bg-gray-500';
 const statusLabel = (s: ChatSession | null) =>
 s?.isConnected && !s.ended ? t('chat.online')
 : s?.ended === 'user' ? t('chat.userDisconnected')
 : s?.ended === 'unavailable' ? t('chat.unavailableShort', 'Chat could not open')
 : s?.ended ? t('chat.ended', 'Chat ended')
 : s?.opening ? t('chat.connecting', 'Connecting…')
 : t('chat.offline');
 const isPhone = useLayoutMode() === 'phone';
 const panelOpen = sessions.length > 0 && isOpen && !isMinimized;
 // Phone: the full-screen remote-shell panel owns the bottom of the screen
 // (virtual keys) — the chat FAB would sit on top of them. It comes back
 // as soon as the shell panel is minimized to its pill.
 const shellPanelOpen = useRemoteShellStore((s) => s.sessions.length > 0 && s.isOpen);
 // Android back: minimize the chat (the session stays alive).
 useNativeBack(() => { setMinimized(true); }, panelOpen);

 const activeSession = sessions.find(s => s.key === activeKey) ?? null;
 const totalUnread = sessions.reduce((sum, s) => sum + s.unread, 0);
 // Reactive avatar read
 const operatorAvatar = useAuthStore(s => s.user?.avatar ?? null);

 // Clear unread when tab becomes active
 useEffect(() => {
 if (activeKey && isOpen && !isMinimized) {
 clearUnread(activeKey);
 }
 }, [activeKey, isOpen, isMinimized, clearUnread]);

 // Nothing to show
 if (sessions.length === 0) return null;

 // Minimized FAB
 if (isMinimized || !isOpen) {
 if (isPhone && shellPanelOpen) return null;
 return (
 <button
 onClick={() => { if (isMinimized) setMinimized(false); else toggleOpen(); }}
 aria-label={totalUnread > 0
 ? `${t('chat.openChat') || 'Open chat'} (${totalUnread})`
 : (t('chat.openChat') || 'Open chat')}
 // md+: 8 px extra margin puts the FAB back at its historic 24 px corner
 // offset (the dock pads 16 px); only when it is the dock's last item.
 className="pointer-events-auto relative z-[2] shrink-0 w-14 h-14 rounded-full bg-accent shadow-lg shadow-accent/30 flex items-center justify-center hover:scale-105 transition-transform md:mr-2 md:last:mb-2"
 >
 <MessageCircle className="w-6 h-6 text-white" />
 {totalUnread > 0 && (
 <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center">
 {totalUnread > 9 ? '9+' : totalUnread}
 </span>
 )}
 </button>
 );
 }

 // Closing a tab ends the conversation for every client of this operator
 // (and closes the window on the user's side); minimize only hides it.
 const handleCloseTab = (key: string, chatId: string | null) => {
 const socket = getSocket();
 const ended = !!sessions.find(s => s.key === key)?.ended;
 if (socket && chatId && !ended) socket.emit('chat:close', { chatId });
 closeTab(key);
 };

 return (
 <div
 className={clsx(
 'pointer-events-auto z-[2] flex flex-col bg-bg-secondary overflow-hidden',
 isPhone
 // Phone: full screen above the page (dvh follows the soft keyboard).
 ? 'fixed inset-0 h-dvh pt-safe pb-safe px-safe'
 // Dock item: 400×620, shrinks (min 240 px) when the dock is short.
 : 'relative min-h-[240px] max-w-[calc(100vw-2rem)] rounded-2xl shadow-2xl',
 )}
 style={isPhone ? undefined : { width: 400, flex: '0 1 620px' }}
 role="dialog"
 aria-label={t('chat.discussionWith', { name: activeSession?.deviceName ?? '...' })}
 >
 {/* ── Header — "Discussion avec {deviceName}" ── */}
 <div className="flex items-center gap-3 px-4 py-3 shrink-0 ">
 <OperatorAvatar avatarUrl={operatorAvatar} size={40} />
 <div className="flex-1 min-w-0">
 <div className="text-sm font-semibold text-text-primary truncate">
 {t('chat.discussionWith', { name: activeSession?.deviceName ?? '...' })}
 </div>
 <div className="flex items-center gap-1.5">
 <span className={clsx('w-2 h-2 rounded-full', dotClass(activeSession))} />
 <span className="text-[11px] text-text-muted">
 {statusLabel(activeSession)}
 </span>
 </div>
 </div>
 <button onClick={() => setMinimized(true)}
 title={t('chat.minimize') || 'Minimize'} aria-label={t('chat.minimize') || 'Minimize'}
 className="p-1.5 text-text-muted hover:text-text-primary transition-colors coarse:min-h-10 coarse:min-w-10 coarse:flex coarse:items-center coarse:justify-center">
 <Minus className="w-4 h-4" />
 </button>
 <button
 onClick={() => { if (activeSession) handleCloseTab(activeSession.key, activeSession.chatId); }}
 title={t('chat.closeChat') || 'Close chat'} aria-label={t('chat.closeChat') || 'Close chat'}
 className="p-1.5 text-text-muted hover:text-red-400 transition-colors coarse:min-h-10 coarse:min-w-10 coarse:flex coarse:items-center coarse:justify-center"
 >
 <X className="w-4 h-4" />
 </button>
 </div>

 {/* ── Tabs (only if multiple sessions) ── */}
 {sessions.length > 1 && (
 <div className="flex items-center gap-1 px-3 py-1.5 shrink-0 overflow-x-auto bg-bg-tertiary/30">
 {sessions.map(s => (
 <div
 key={s.key}
 // The whole pill activates the tab (as before); the inner button is
 // the keyboard / screen-reader entry point (its click bubbles here).
 onClick={() => { setActiveTab(s.key); clearUnread(s.key); }}
 className={clsx(
 'flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-medium rounded-lg transition-colors shrink-0 max-w-[140px] cursor-pointer coarse:max-w-[180px]',
 s.key === activeKey
 ? 'bg-accent/15 text-accent border border-accent/30'
 : 'text-text-muted hover:text-text-primary hover:bg-bg-hover border border-transparent',
 )}
 >
 <button
 type="button"
 aria-pressed={s.key === activeKey}
 className="flex min-w-0 items-center gap-1.5 coarse:min-h-8"
 >
 <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', dotClass(s))} />
 <span className="truncate">{s.deviceName}</span>
 {s.unread > 0 && (
 <span className="w-4 h-4 bg-accent text-white text-[9px] font-bold rounded-full flex items-center justify-center shrink-0">
 {s.unread > 9 ? '9+' : s.unread}
 </span>
 )}
 </button>
 <button
 type="button"
 onClick={e => { e.stopPropagation(); handleCloseTab(s.key, s.chatId); }}
 aria-label={t('chat.closeTab', { name: s.deviceName }) || `Close ${s.deviceName}`}
 className="relative shrink-0 p-0.5 rounded hover:bg-bg-hover text-text-muted hover:text-text-primary coarse:after:absolute coarse:after:left-1/2 coarse:after:top-1/2 coarse:after:h-10 coarse:after:w-10 coarse:after:-translate-x-1/2 coarse:after:-translate-y-1/2 coarse:after:content-['']"
 >
 <X className="w-2.5 h-2.5" />
 </button>
 </div>
 ))}
 </div>
 )}

 {/* ── Active tab content ── */}
 {activeSession ? (
 <ChatTabContent key={activeSession.key} session={activeSession} />
 ) : (
 <div className="flex-1 flex items-center justify-center text-text-muted text-sm">
 {t('chat.noActiveChat')}
 </div>
 )}
 </div>
 );
}
