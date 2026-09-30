import { create } from 'zustand';

export interface ChatMessage {
  sender: string;
  text: string;
  timestamp: number;
  isSystem?: boolean;
  isOperator?: boolean;
}

/** A message of the server's chat history (chat:open resume, join ack). */
export interface ChatHistoryEntry {
  sender: string;
  message: string;
  fromOperator: boolean;
  timestamp: number;
}

/** 'unavailable': the chat window could not open on the machine (WebView2 missing / not starting). */
export type ChatEndReason = 'operator' | 'user' | 'unavailable';

export interface ChatSession {
  /** Unique key for this tab (e.g. `${deviceUuid}:${sessionId}`) */
  key: string;
  deviceUuid: string;
  deviceName: string;
  sessionId?: number;
  chatId: string | null;
  messages: ChatMessage[];
  isConnected: boolean;
  userClosed: boolean;
  /** Unread count (incremented when tab is not active) */
  unread: number;
  /** chat:open sent, no answer yet. */
  opening?: boolean;
  /** chat:open refused or timed out: nothing is retried until the operator asks. */
  failed?: boolean;
  /** The chat ended (an operator closed it, or the user closed the window): input disabled. */
  ended?: ChatEndReason;
  /** THIS client asked for remote control and waits for the answer. */
  remoteRequested?: boolean;
}

/** A live chat of this user opened elsewhere (chat:opened / chat:list). */
export interface RemoteChatInfo {
  chatId: string;
  deviceUuid: string;
  deviceName: string;
  tenantId?: number;
}

interface ChatState {
  /** All open chat sessions (tabs) */
  sessions: ChatSession[];
  /** Key of the currently active tab */
  activeKey: string | null;
  /** Whether the chat window is visible */
  isOpen: boolean;
  /** Whether the chat window is minimized (FAB only) */
  isMinimized: boolean;
  /** Sound enabled globally */
  soundEnabled: boolean;

  // ── Actions ──
  openChat: (deviceUuid: string, deviceName: string, sessionId?: number) => void;
  /** Starts a new conversation in an ended / failed tab. */
  restartChat: (key: string) => void;
  closeTab: (key: string) => void;
  setActiveTab: (key: string) => void;
  toggleOpen: () => void;
  setMinimized: (v: boolean) => void;
  toggleSound: () => void;
  setChatId: (key: string, chatId: string) => void;
  setConnected: (key: string, connected: boolean) => void;
  setUserClosed: (key: string, closed: boolean) => void;
  patchSession: (key: string, patch: Partial<Omit<ChatSession, 'key'>>) => void;
  addMessage: (key: string, msg: ChatMessage) => void;
  /** Server history of the tab's chat: fills an empty tab, or appends the
   *  messages missed while disconnected. Returns how many of the added ones
   *  come from the end user AND were missed (0 when it only filled the tab). */
  applyHistory: (key: string, history: ChatHistoryEntry[] | undefined) => number;
  markEnded: (key: string, reason: ChatEndReason) => void;
  /** Adds (or re-binds) the tab of a chat opened on another client; returns its key, or null when nothing changed.
   *  `unread`: flag it (a chat just opened elsewhere), not a recovered one (chat:list). */
  addRemoteChat: (info: RemoteChatInfo, opts?: { unread?: boolean }) => string | null;
  clearUnread: (key: string) => void;

  /** Callback when remote access is granted via chat (set by DeviceDetailPage) */
  onRemoteAccessGranted: ((key: string) => void) | null;
  setOnRemoteAccessGranted: (cb: ((key: string) => void) | null) => void;

  /** Close everything */
  closeAll: () => void;
}

function makeKey(deviceUuid: string, sessionId?: number): string {
  return sessionId ? `${deviceUuid}:${sessionId}` : deviceUuid;
}

/** A tab that no longer holds a conversation: the next open starts a new one. */
const isDead = (s: ChatSession) => !!s.ended || !!s.failed;

/** Reset of a tab for a new conversation (restart, or a chat opened elsewhere). */
const FRESH: Pick<ChatSession, 'chatId' | 'messages' | 'isConnected' | 'userClosed' | 'unread' | 'opening' | 'failed' | 'ended' | 'remoteRequested'> = {
  chatId: null,
  messages: [],
  isConnected: false,
  userClosed: false,
  unread: 0,
  opening: false,
  failed: false,
  ended: undefined,
  remoteRequested: false,
};

export const useChatStore = create<ChatState>((set, get) => ({
  sessions: [],
  activeKey: null,
  onRemoteAccessGranted: null,
  setOnRemoteAccessGranted: (cb) => set({ onRemoteAccessGranted: cb }),
  isOpen: false,
  isMinimized: false,
  soundEnabled: true,

  openChat: (deviceUuid, deviceName, sessionId) => {
    const key = makeKey(deviceUuid, sessionId);
    const { sessions } = get();
    // One conversation per machine (the server keeps one per operator and
    // machine, whatever the Windows session): a live tab of this machine is
    // brought forward, an ended / failed one starts a new conversation.
    const existing = sessions.find(s => s.deviceUuid === deviceUuid && !isDead(s))
      ?? sessions.find(s => s.key === key)
      ?? sessions.find(s => s.deviceUuid === deviceUuid);
    if (existing) {
      set(s => ({
        sessions: isDead(existing)
          ? s.sessions.map(ss => ss.key === existing.key ? { ...ss, ...FRESH, deviceName, sessionId: sessionId ?? ss.sessionId } : ss)
          : s.sessions,
        activeKey: existing.key,
        isOpen: true,
        isMinimized: false,
      }));
      return;
    }
    const newSession: ChatSession = {
      key,
      deviceUuid,
      deviceName,
      sessionId,
      ...FRESH,
    };
    set(s => ({
      sessions: [...s.sessions, newSession],
      activeKey: key,
      isOpen: true,
      isMinimized: false,
    }));
  },

  restartChat: (key) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key && isDead(ss) ? { ...ss, ...FRESH } : ss),
  })),

  closeTab: (key) => {
    set(s => {
      const sessions = s.sessions.filter(ss => ss.key !== key);
      let activeKey = s.activeKey;
      if (activeKey === key) {
        activeKey = sessions.length > 0 ? sessions[sessions.length - 1].key : null;
      }
      return {
        sessions,
        activeKey,
        isOpen: sessions.length > 0 ? s.isOpen : false,
        isMinimized: sessions.length > 0 ? s.isMinimized : false,
      };
    });
  },

  setActiveTab: (key) => set({ activeKey: key }),

  toggleOpen: () => set(s => ({ isOpen: !s.isOpen, isMinimized: false })),

  setMinimized: (v) => set({ isMinimized: v }),

  toggleSound: () => set(s => ({ soundEnabled: !s.soundEnabled })),

  setChatId: (key, chatId) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key ? { ...ss, chatId } : ss),
  })),

  setConnected: (key, connected) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key ? { ...ss, isConnected: connected } : ss),
  })),

  setUserClosed: (key, closed) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key ? { ...ss, userClosed: closed } : ss),
  })),

  patchSession: (key, patch) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key ? { ...ss, ...patch } : ss),
  })),

  addMessage: (key, msg) => set(s => {
    const isActive = s.activeKey === key && s.isOpen && !s.isMinimized;
    // Only the user's messages count as unread: system lines and the
    // operator's own messages (typed here or on another client) do not.
    const counts = !msg.isSystem && !msg.isOperator;
    return {
      sessions: s.sessions.map(ss =>
        ss.key === key
          ? { ...ss, messages: [...ss.messages, msg], unread: isActive ? 0 : ss.unread + (counts ? 1 : 0) }
          : ss
      ),
    };
  }),

  applyHistory: (key, history) => {
    let missed = 0;
    set(s => {
      const isActive = s.activeKey === key && s.isOpen && !s.isMinimized;
      return {
        sessions: s.sessions.map(ss => {
          if (ss.key !== key || !Array.isArray(history) || history.length === 0) return ss;
          const fromServer: ChatMessage[] = history
            .filter(h => h && typeof h.message === 'string')
            .map(h => ({
              sender: String(h.sender ?? ''),
              text: h.message,
              timestamp: typeof h.timestamp === 'number' && h.timestamp > 0 ? h.timestamp : Date.now(),
              isOperator: !!h.fromOperator,
            }));
          const local = ss.messages.filter(m => !m.isSystem);
          // An empty tab takes the whole history (before its system lines).
          if (local.length === 0) return { ...ss, messages: [...fromServer, ...ss.messages] };
          // Otherwise only what follows the tab's last messages (up to 5
          // matched, as the Oblireach Desktop does): the messages missed while
          // disconnected. No match: the tab is left as it is.
          let start = -1;
          for (let m = Math.min(local.length, 5, fromServer.length); m >= 1 && start < 0; m--) {
            for (let j = fromServer.length; j >= m && start < 0; j--) {
              let same = true;
              for (let k = 1; k <= m && same; k++) {
                const a = local[local.length - k];
                const b = fromServer[j - k];
                same = a.text === b.text && !!a.isOperator === !!b.isOperator;
              }
              if (same) start = j;
            }
          }
          if (start < 0) return ss;
          const added = fromServer.slice(start);
          if (added.length === 0) return ss;
          missed = added.filter(m => !m.isOperator).length;
          return { ...ss, messages: [...ss.messages, ...added], unread: isActive ? 0 : ss.unread + missed };
        }),
      };
    });
    return missed;
  },

  markEnded: (key, reason) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key
      ? { ...ss, ended: reason, userClosed: reason === 'user', isConnected: false, opening: false, remoteRequested: false }
      : ss),
  })),

  addRemoteChat: (info, opts) => {
    const { sessions } = get();
    const unread = opts?.unread ? 1 : 0;
    if (!info?.chatId || !info.deviceUuid) return null;
    if (sessions.some(s => s.chatId === info.chatId)) return null;
    const deviceName = info.deviceName || info.deviceUuid;
    const sameDevice = sessions.find(s => s.deviceUuid === info.deviceUuid && !s.ended && !s.failed)
      ?? sessions.find(s => s.deviceUuid === info.deviceUuid);
    if (sameDevice) {
      // Our own chat:open for this machine is on its way: its answer resumes
      // this same chat.
      if (sameDevice.opening) return null;
      // An ended / idle tab of this machine takes the new conversation.
      set(s => ({
        sessions: s.sessions.map(ss => ss.key === sameDevice.key
          ? { ...ss, ...FRESH, chatId: info.chatId, isConnected: true, deviceName, unread, messages: ss.chatId ? [] : ss.messages }
          : ss),
      }));
      return sameDevice.key;
    }
    const session: ChatSession = {
      key: info.deviceUuid,
      deviceUuid: info.deviceUuid,
      deviceName,
      ...FRESH,
      chatId: info.chatId,
      isConnected: true,
      unread,
    };
    // The least intrusive: a new tab, the panel only shows up as the
    // minimized button (with its unread badge) when nothing was open yet.
    set(s => ({
      sessions: [...s.sessions, session],
      activeKey: s.activeKey ?? session.key,
      isOpen: s.sessions.length > 0 ? s.isOpen : true,
      isMinimized: s.sessions.length > 0 ? s.isMinimized : true,
    }));
    return session.key;
  },

  clearUnread: (key) => set(s => ({
    sessions: s.sessions.map(ss => ss.key === key ? { ...ss, unread: 0 } : ss),
  })),

  closeAll: () => set({ sessions: [], activeKey: null, isOpen: false, isMinimized: false }),
}));
