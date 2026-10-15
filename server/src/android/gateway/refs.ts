// The AndroidEnterpriseRef objects the gateway accepts are only those the registry issued from a row read under RLS
// (enterprises/registry.ts): an object built elsewhere (a name taken from a request) is refused by the gateway.
import type { AndroidEnterpriseRef } from './names';

const issued = new WeakSet<object>();

export function issueEnterpriseRef(row: { id: number; tenant_id: number; enterprise_name: string; state: string }): AndroidEnterpriseRef {
  const ref = Object.freeze({
    id: Number(row.id), tenantId: Number(row.tenant_id), name: String(row.enterprise_name),
    state: row.state as AndroidEnterpriseRef['state'],
  });
  issued.add(ref);
  return ref;
}

export function isIssuedEnterpriseRef(e: unknown): e is AndroidEnterpriseRef {
  return typeof e === 'object' && e !== null && issued.has(e);
}
