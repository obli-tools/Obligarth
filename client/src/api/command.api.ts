import apiClient from './client';
import type { Command, CommandType, CommandPriority } from '@obliance/shared';

interface ApiResponse<T> { data?: T; error?: string; }

export const commandApi = {
  async list(deviceId?: number, params?: { status?: string; page?: number; limit?: number }): Promise<{ items: Command[]; total: number }> {
    const res = await apiClient.get<ApiResponse<{ items: Command[]; total: number }>>(`/commands`, { params: { ...(deviceId !== undefined && { deviceId }), ...params } });
    return res.data.data ?? { items: [], total: 0 };
  },
  async enqueue(deviceId: number, type: CommandType, payload?: Record<string, any>, priority?: CommandPriority): Promise<Command> {
    const res = await apiClient.post<ApiResponse<Command>>('/commands', { deviceId, type, payload: payload ?? {}, priority: priority ?? 'normal' });
    return res.data.data!;
  },
  async cancel(commandId: string): Promise<void> {
    await apiClient.delete(`/commands/${commandId}`);
  },
  /** Queue an agent update (POST /commands, type update_agent). It waits for
   *  an offline device (no expiry), exists at most once per device and is
   *  paced by the server's rollout. A 'restricted' tenant answers 202 with a
   *  pending approval instead. */
  async updateAgent(deviceId: number): Promise<UpdateAgentResult | { approvalId: number; status: 'pending_approval' }> {
    const res = await apiClient.post<ApiResponse<UpdateAgentResult | { approvalId: number; status: 'pending_approval' }>>('/commands', {
      deviceId, type: 'update_agent', payload: {}, priority: 'high',
    });
    return res.data.data!;
  },
};

export type UpdateAgentResult = Command & {
  /** 'sent': handed to the agent; 'queued': waits for the device (next
   *  contact, rollout slot, or back online); 'skipped': already up to date. */
  delivery: 'sent' | 'queued' | 'skipped';
  /** An update was already waiting for this device (returned, not doubled). */
  alreadyQueued: boolean;
  deviceOnline: boolean;
};
