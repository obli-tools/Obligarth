import type { Request, Response } from 'express';
import type { ManagementChannel } from '../../guard/types';

// =============================================================================
// The command queue by channel (android-amapi §11.5, integration-apple-edge §8.12; lot AN-D): the routes of the
// queue (/api/apple/devices/:id/commands, /api/apple/commands/:id/cancel and /relaunch) serve the devices and the
// commands of every platform. Apple's are written by the Apple bus; another module hands its own here: a device of
// its management channel, a command of its platform (mdm_commands.platform), go to its handlers, which check the
// capability, the restriction and the rules of their channel. The Apple module never imports them (COH-9).
// Registered before the routes serve, no I/O.
// =============================================================================

export interface QueueChannel {
  /** Management channel of its devices (devices.management_channel). */
  channel: ManagementChannel;
  /** Platform of its commands (mdm_commands.platform). */
  platform: string;
  /** POST …/devices/:id/commands for a device of the channel (the device already seen by the caller: 404 before). */
  create(req: Request, res: Response, deviceId: number): Promise<void>;
  /** POST …/commands/:id/cancel for a command of the platform (the command seen by the caller). */
  cancel(req: Request, res: Response, commandId: string): Promise<void>;
  /** POST …/commands/:id/relaunch for a command of the platform. */
  relaunch(req: Request, res: Response, commandId: string): Promise<void>;
}

const byChannel = new Map<string, QueueChannel>();
const byPlatform = new Map<string, QueueChannel>();

export function registerQueueChannel(c: QueueChannel): void {
  if (c.platform === 'apple' || c.channel === 'apple_mdm') throw new Error('the Apple queue is the queue routes themselves');
  if (byChannel.has(c.channel) || byPlatform.has(c.platform)) throw new Error(`queue channel ${c.channel} registered twice`);
  byChannel.set(c.channel, c);
  byPlatform.set(c.platform, c);
}

/** The handlers of a device's channel, or undefined (Apple, or a channel without its own). */
export const queueChannelOfDevice = (channel: string | null | undefined): QueueChannel | undefined => (channel ? byChannel.get(channel) : undefined);

/** The handlers of a command's platform, or undefined (Apple). */
export const queueChannelOfPlatform = (platform: string | null | undefined): QueueChannel | undefined => (platform ? byPlatform.get(platform) : undefined);
