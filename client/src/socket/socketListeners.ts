import type { Socket } from 'socket.io-client';

// ── App-wide socket listeners ────────────────────────────────────────────────
// Declared by the modules that own the state they feed (device store, group
// store…) instead of by the shell, which then does not need to know them.
// useSocket() binds them to the session socket and unbinds each one by its
// own reference: never `socket.off(event)` without a handler, which would also
// drop the listeners other components put on the same event.

// Server payloads are not typed at this boundary.
type SocketListener = (...args: any[]) => void;

interface Registration {
  event: string;
  listener: SocketListener;
}

const registrations: Registration[] = [];
let boundSocket: Socket | null = null;

/** Declares an app-wide listener (bound at once if a socket is already
 *  bound). Returns the function that removes it. */
export function registerSocketListener(event: string, listener: SocketListener): () => void {
  const registration: Registration = { event, listener };
  registrations.push(registration);
  boundSocket?.on(event, listener);
  return () => {
    const index = registrations.indexOf(registration);
    if (index >= 0) registrations.splice(index, 1);
    boundSocket?.off(event, listener);
  };
}

/** Binds every registered listener to `socket`; returns the unbind function. */
export function bindSocketListeners(socket: Socket): () => void {
  boundSocket = socket;
  for (const { event, listener } of registrations) socket.on(event, listener);
  return () => {
    for (const { event, listener } of registrations) socket.off(event, listener);
    if (boundSocket === socket) boundSocket = null;
  };
}
