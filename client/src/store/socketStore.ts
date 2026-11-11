import { create } from 'zustand';

export type SocketStatus = 'connected' | 'disconnected' | 'reconnecting';

interface SocketState {
  status: SocketStatus;
  /** Bumped each time connectSocket() creates a new socket instance (login, tenant switch): the app-wide
   *  listeners (useSocket) are bound to one instance and must be re-bound to the new one. */
  generation: number;
  setStatus: (status: SocketStatus) => void;
  bumpGeneration: () => void;
}

export const useSocketStore = create<SocketState>((set) => ({
  status: 'disconnected',
  generation: 0,
  setStatus: (status) => set({ status }),
  bumpGeneration: () => set((s) => ({ generation: s.generation + 1 })),
}));
