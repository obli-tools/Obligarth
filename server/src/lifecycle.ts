import type { IncomingMessage, Server as HttpServer } from 'http';
import type { Duplex } from 'stream';
import type { Server as SocketIOServer } from 'socket.io';
import { asNone } from './db/context';
import { logger } from './utils/logger';
import { safeErr } from './jobs/errors';

// ── Module lifecycle ────────────────────────────────────────────────────────
//
// index.ts wires the core start-up (boot guard, default admin, durable jobs,
// HTTP server, Socket.io). A module adds its start-up work here instead of in
// index.ts, so removing the module removes its registration, never a line of
// index.ts:
//   boot  — awaited one after the other, after the default admin and the
//           start of the durable jobs (a boot task may send a job), before
//           the HTTP app is created (no request can arrive);
//   start — one after the other once the HTTP and Socket.io servers exist,
//           before the job workers and the port; a task that returns a
//           promise is awaited (a task that must not hold the start-up
//           returns nothing);
//   stop  — one after the other at SIGTERM / SIGINT, after the HTTP server
//           and the jobs stopped; each awaited, an error logged and never
//           propagated.
// An error of a boot or start task is not caught here: each task handles its
// own.
//
// Periodic and deferred work never goes through a task of this file (nor
// through a timer): a module registers durable jobs (jobs/, registerJob),
// which survive a restart, run once across instances, and are retried and
// watched. A task here never creates a timer.
//
// Boot and start tasks run in the database context 'none' of their own job
// actor (j:<task name>).
//
// Raw WebSocket upgrades that are not Socket.io's (a device channel, a relay;
// none today) are served by the modules' upgrade handlers
// (installUpgradeDispatcher).

export interface StartContext {
  server: HttpServer;
  io: SocketIOServer;
}

// A task's result is awaited (a promise holds the start-up until it settles).
type BootTask = () => unknown;
type StartTask = (ctx: StartContext) => unknown;
type StopTask = () => void | Promise<void>;

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
  for (const t of bootTasks) await asNone({ type: 'job', name: t.name }, () => t.run());
}

export async function runStartTasks(ctx: StartContext): Promise<void> {
  for (const t of startTasks) await asNone({ type: 'job', name: t.name }, () => t.run(ctx));
}

/** Each stop task in turn, awaited; an error is logged, never propagated
 *  (the shutdown carries on). */
export async function runStopTasks(): Promise<void> {
  for (const t of stopTasks) {
    try {
      await t.run();
    } catch (err) {
      logger.warn({ err: safeErr(err), task: t.name }, 'stop task failed');
    }
  }
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
