// Pub/Sub operations on the project's subscription only (section 7.1): synchronous pull, acknowledge,
// modifyAckDeadline, seek, testIamPermissions. The subscription is the configured one, never a received name.
import type { PubsubReceived } from '@obligarth/shared';
import type { GoogleHttp } from './http';

export const PUBSUB_OPERATIONS = ['pull', 'acknowledge', 'modifyAckDeadline', 'seek', 'testIamPermissions'] as const;

export function pubsubClient(http: GoogleHttp, base: string, subscription: string, pullMaxBytes: number) {
  const sub = subscription.split('/').map(encodeURIComponent).join('/');
  const url = (verb: string) => `${base}${sub}:${verb}`;
  return {
    async pull(maxMessages: number, signal?: AbortSignal): Promise<PubsubReceived[]> {
      const r = await http.call<{ receivedMessages?: PubsubReceived[] }>({
        op: 'pubsub.pull', method: 'POST', scope: 'project', idempotent: false, url: url('pull'),
        body: { maxMessages }, timeoutMs: 30_000, maxBytes: pullMaxBytes, signal,
      });
      return Array.isArray(r?.receivedMessages) ? r.receivedMessages : [];
    },
    async acknowledge(ackIds: string[]): Promise<void> {
      if (!ackIds.length) return;
      await http.call({ op: 'pubsub.acknowledge', method: 'POST', scope: 'project', idempotent: true, url: url('acknowledge'), body: { ackIds } });
    },
    async modifyAckDeadline(ackIds: string[], seconds: number): Promise<void> {
      if (!ackIds.length) return;
      await http.call({
        op: 'pubsub.modifyAckDeadline', method: 'POST', scope: 'project', idempotent: true, url: url('modifyAckDeadline'),
        body: { ackIds, ackDeadlineSeconds: Math.max(0, Math.min(600, Math.floor(seconds))) },
      });
    },
    async seek(time: Date): Promise<void> {
      await http.call({ op: 'pubsub.seek', method: 'POST', scope: 'project', idempotent: true, url: url('seek'), body: { time: time.toISOString() } });
    },
    async testIamPermissions(permissions: string[]): Promise<string[]> {
      const r = await http.call<{ permissions?: string[] }>({
        op: 'pubsub.testIamPermissions', method: 'POST', scope: 'project', idempotent: true, url: url('testIamPermissions'), body: { permissions },
      });
      return Array.isArray(r?.permissions) ? r.permissions : [];
    },
  };
}

export type PubsubClient = ReturnType<typeof pubsubClient>;
