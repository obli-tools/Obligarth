// A guarded action served by several management channels (android-amapi §11.4, COH-9, lot AN-P): the module that
// defines an action (its channels: GuardedActionDef.channels) keeps its revalidation and its execution for its own
// devices; another module adds its channel to the same key (registerGuardedActionChannel) with its own parameters,
// prerequisites, revalidation and execution. The engine then sees one action (one key, one restriction, one floor,
// one hourly cap, one whole fleet across the channels of the action: PONT-R-RV3) whose targets are split by channel
// at execution. The prerequisites of a target are those of its channel (Apple: the command catalogue, the
// satellite apple_devices; Android: §11.4 and android_devices); a target of a channel the action does not serve is
// refused at the request (422 channelMismatch, PONT-R-RV4). An action whose targets are all of its own channels
// behaves exactly as before. The parameters are those of the union: each channel reads them again with its own
// schema and sets its targets aside when they do not fit it (params_invalid).
import { z } from 'zod';
import { db } from '../db';
import type {
  GuardedActionDef, GuardExecutionContext, GuardTargetRefusal, GuardTargetResult, ManagementChannel,
} from './types';

export interface GuardedChannelImpl {
  channel: ManagementChannel;
  /** The parameters of the action on this channel (strict). */
  paramsSchema: z.ZodTypeAny;
  /** Per target of the channel, at execution: its prerequisites (still managed, allowed by the channel). */
  revalidate(ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds: number[]): Promise<Map<number, 'ok' | GuardTargetRefusal>>;
  /** Idempotent execution for the targets of the channel. */
  execute(ctx: GuardExecutionContext<Record<string, unknown>>, deviceIds: number[]): Promise<Map<number, GuardTargetResult>>;
  /** Late cancellation of what the action dispatched on this channel (an empty map when nothing was). */
  cancelAfterDispatch?(ctx: GuardExecutionContext<Record<string, unknown>>): Promise<Map<number, 'cancelled' | 'already_delivered' | 'completed'>>;
}

/** The targets by management channel (a device of no known channel stays with the action's own channels). */
async function byChannel(tenantId: number, ids: number[]): Promise<Map<number, string>> {
  if (!ids.length) return new Map();
  const rows = await db('devices').where({ tenant_id: tenantId }).whereIn('id', ids).select('id', 'management_channel') as
    Array<{ id: number; management_channel: string }>;
  return new Map(rows.map((r) => [Number(r.id), String(r.management_channel)]));
}

/**
 * The action `base` (its channels: base.channels) served also by `extra` (the channels base does not serve already).
 * Returns base itself when nothing is added.
 */
export function withChannels<P>(base: GuardedActionDef<P>, extra: readonly GuardedChannelImpl[]): GuardedActionDef<P> {
  const own = new Set<string>(base.channels ?? []);
  const impls = extra.filter((x) => !own.has(x.channel));
  if (!impls.length || !base.channels) return base;
  const implOf = new Map(impls.map((x) => [x.channel as string, x]));
  const fits = (schema: z.ZodTypeAny, params: unknown): boolean => schema.safeParse(params ?? {}).success;
  /** The targets of the base and of each added channel. */
  const split = async (tenantId: number, ids: number[]): Promise<{ base: number[]; added: Map<GuardedChannelImpl, number[]> }> => {
    const ch = await byChannel(tenantId, ids);
    const out = { base: [] as number[], added: new Map<GuardedChannelImpl, number[]>() };
    for (const id of ids) {
      const impl = implOf.get(ch.get(id) ?? '');
      if (!impl) { out.base.push(id); continue; }
      const list = out.added.get(impl) ?? [];
      list.push(id);
      out.added.set(impl, list);
    }
    return out;
  };
  const anyCtx = (ctx: GuardExecutionContext<P>) => ctx as unknown as GuardExecutionContext<Record<string, unknown>>;
  const def: GuardedActionDef<P> = {
    ...base,
    channels: [...base.channels, ...impls.map((x) => x.channel)],
    paramsSchema: z.union([base.paramsSchema as z.ZodTypeAny, ...impls.map((x) => x.paramsSchema)] as unknown as [z.ZodTypeAny, z.ZodTypeAny]) as unknown as z.ZodType<P>,
    async revalidate(ctx) {
      const s = await split(ctx.tenantId, ctx.deviceIds);
      if (!s.added.size) return base.revalidate(ctx);
      const out = new Map<number, 'ok' | GuardTargetRefusal>();
      if (s.base.length) {
        const r = fits(base.paramsSchema as z.ZodTypeAny, ctx.params) ? await base.revalidate({ ...ctx, deviceIds: s.base }) : null;
        for (const d of s.base) out.set(d, r ? r.get(d) ?? { code: 'not_found' } : { code: 'params_invalid' });
      }
      for (const [impl, ids] of s.added) {
        const r = fits(impl.paramsSchema, ctx.params) ? await impl.revalidate(anyCtx(ctx), ids) : null;
        for (const d of ids) out.set(d, r ? r.get(d) ?? { code: 'not_found' } : { code: 'params_invalid' });
      }
      return out;
    },
    async execute(ctx, deviceIds) {
      const s = await split(ctx.tenantId, deviceIds);
      if (!s.added.size) return base.execute(ctx, deviceIds);
      const out = new Map<number, GuardTargetResult>(s.base.length ? await base.execute(ctx, s.base) : []);
      for (const [impl, ids] of s.added) for (const [d, x] of await impl.execute(anyCtx(ctx), ids)) out.set(d, x);
      return out;
    },
  };
  if (base.cancelAfterDispatch || impls.some((x) => x.cancelAfterDispatch)) {
    const cancelBase = base.cancelAfterDispatch;
    def.cancelAfterDispatch = async (ctx) => {
      const out = cancelBase ? await cancelBase(ctx) : new Map<number, 'cancelled' | 'already_delivered' | 'completed'>();
      for (const impl of impls) if (impl.cancelAfterDispatch) for (const [d, x] of await impl.cancelAfterDispatch(anyCtx(ctx))) out.set(d, x);
      return out;
    };
  }
  return def;
}
