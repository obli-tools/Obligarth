import type { IncomingMessage, Server as HttpServer } from 'http';
import type { Duplex } from 'stream';
import type { Server as SocketIOServer } from 'socket.io';

// ── Module lifecycle ────────────────────────────────────────────────────────
//
// index.ts wires the core start-up (migrations, default admin, HTTP server,
// Socket.io, the core's own periodic jobs). A module adds its background work
// here instead of in index.ts, so removing the module removes its
// registration, never a line of index.ts (modules/rmm.ts registers the
// RMM's):
//   boot  — awaited one after the other, after the migrations and the default
//           admin, before the HTTP app is created (no request can arrive);
//   start — one after the other once the HTTP and Socket.io servers exist,
//           before the port is opened; a task that returns a promise is
//           awaited (a task that must not hold the start-up returns nothing);
//   stop  — one after the other at SIGTERM / SIGINT, before the HTTP server
//           closes.
// An error of a task is not caught here: each task handles its own, as the
// inline code of index.ts did.
//
// Raw WebSocket upgrades that are not Socket.io's (agent channels, relays)
// are served by the modules' upgrade handlers (installUpgradeDispatcher).

export interface StartContext {
  server: HttpServer;
  io: SocketIOServer;
}

// A task's result is awaited (a promise holds the start-up until it settles).
type BootTask = () => unknown;
type StartTask = (ctx: StartContext) => unknown;
type StopTask = () => void;

const bootTasks: Array<{ name: string; run: BootTask }> = [];
const startTasks: Array<{ name: string; run: StartTask }> = [];
const stopTasks: Array<{ name: string; run: StopTask }> = [];

function checkName(list: ReadonlyArray<{ name: string }>, name: string): void {
  if (list.some((t) => t.name === name)) throw new Error(`Lifecycle task '${name}' registered twice`);
}

export function registerBootTask(name: string, run: BootTask): void {
  checkName(bootTasks, name);
  bootTasks.push({ name, run });
}

export function registerStartTask(name: string, run: StartTask): void {
  checkName(startTasks, name);
  startTasks.push({ name, run });
}

export function registerStopTask(name: string, run: StopTask): void {
  checkName(stopTasks, name);
  stopTasks.push({ name, run });
}

export async function runBootTasks(): Promise<void> {
  for (const t of bootTasks) await t.run();
}

export async function runStartTasks(ctx: StartContext): Promise<void> {
  for (const t of startTasks) await t.run(ctx);
}

export function runStopTasks(): void {
  for (const t of stopTasks) t.run();
}

// ── Raw WebSocket upgrades ──────────────────────────────────────────────────

/**
 * A module's upgrade handler: returns true when the request is its own (it
 * then answers it — accepts, or refuses before the handshake), false to let
 * the next handler, and finally Socket.io, see it. Must not throw.
 */
export type UpgradeHandler = (request: IncomingMessage, socket: Duplex, head: Buffer, pathname: string) => boolean;

const upgradeHandlers: Array<{ name: string; handle: UpgradeHandler }> = [];

export function registerUpgradeHandler(name: string, handle: UpgradeHandler): void {
  checkName(upgradeHandlers, name);
  upgradeHandlers.push({ name, handle });
}

/**
 * Socket.io (engine.io) registers an 'upgrade' listener that destroys the
 * sockets whose path is not "/socket.io/". To serve other WebSocket paths on
 * the same port, the listeners Socket.io just registered are captured and
 * removed, and one dispatcher takes over: the modules' handlers first (in
 * registration order), everything else to Socket.io's original listeners.
 * Call right after createSocketServer.
 */
export function installUpgradeDispatcher(server: HttpServer): void {
  const sioUpgradeListeners = server.rawListeners('upgrade').slice();
  server.removeAllListeners('upgrade');

  server.on('upgrade', (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    const pathname = new URL(request.url ?? '/', 'http://localhost').pathname;
    for (const h of upgradeHandlers) {
      if (h.handle(request, socket, head, pathname)) return; // handled — do NOT forward to socket.io
    }
    // ── Everything else → forward to socket.io's original listeners ─────────
    for (const listener of sioUpgradeListeners) {
      (listener as (...args: unknown[]) => void).call(server, request, socket, head);
    }
  });
}
