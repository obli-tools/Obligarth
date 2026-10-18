// The closed list of AMAPI operations (section 5.1): one function per REST method, nothing generic. Every path is
// built from names already constructed and checked by gateway/names.ts; query parameters are encoded here. No
// enterprises.delete, no migrationTokens, no webApps in v1.
import type {
  AmapiApplication, AmapiCommand, AmapiDevice, AmapiEnrollmentToken, AmapiEnterprise, AmapiEnterpriseBasic, AmapiOperation,
  AmapiPolicy, AmapiSignupUrl,
} from '@obligarth/shared/dist/android/amapi';
import type { GoogleHttp } from './http';

export type AmapiOp =
  | 'signupUrls.create' | 'enterprises.create' | 'enterprises.list' | 'enterprises.get' | 'enterprises.patch'
  | 'enterprises.generateEnterpriseUpgradeUrl' | 'policies.get' | 'policies.patch' | 'policies.delete' | 'enrollmentTokens.create'
  | 'enrollmentTokens.delete' | 'enrollmentTokens.list' | 'enrollmentTokens.get' | 'devices.get' | 'devices.list'
  | 'devices.patch' | 'devices.delete' | 'devices.issueCommand' | 'operations.list' | 'operations.get'
  | 'operations.cancel' | 'webTokens.create' | 'applications.get' | 'provisioningInfo.get';

/** Every operation the instance can reach (essai 197: nothing else is reachable). */
export const AMAPI_OPERATIONS: readonly AmapiOp[] = [
  'signupUrls.create', 'enterprises.create', 'enterprises.list', 'enterprises.get', 'enterprises.patch',
  'enterprises.generateEnterpriseUpgradeUrl', 'policies.get', 'policies.patch', 'policies.delete', 'enrollmentTokens.create',
  'enrollmentTokens.delete', 'enrollmentTokens.list', 'enrollmentTokens.get', 'devices.get', 'devices.list',
  'devices.patch', 'devices.delete', 'devices.issueCommand', 'operations.list', 'operations.get', 'operations.cancel',
  'webTokens.create', 'applications.get', 'provisioningInfo.get',
];

const q = (params: Record<string, string | number | string[] | undefined>): string => {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === '') continue;
    for (const one of Array.isArray(v) ? v : [v]) parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(one))}`);
  }
  return parts.length ? `?${parts.join('&')}` : '';
};

export function amapiClient(http: GoogleHttp, base: string) {
  const url = (path: string, params: Record<string, string | number | string[] | undefined> = {}) => `${base}${path}${q(params)}`;
  return {
    createSignupUrl: (projectId: string, callbackUrl: string, adminEmail: string | undefined, allowedDomains: string[]) =>
      http.call<AmapiSignupUrl>({
        op: 'signupUrls.create', method: 'POST', scope: 'project', idempotent: false,
        url: url('signupUrls', { projectId, callbackUrl, adminEmail, allowedDomains }),
      }),
    createEnterprise: (projectId: string, signupUrlName: string, enterpriseToken: string, body: Partial<AmapiEnterprise>) =>
      http.call<AmapiEnterprise>({
        op: 'enterprises.create', method: 'POST', scope: 'project', idempotent: false, body,
        url: url('enterprises', { projectId, signupUrlName, enterpriseToken }),
      }),
    listEnterprises: (projectId: string, pageToken?: string) =>
      http.call<{ enterprises?: AmapiEnterpriseBasic[]; nextPageToken?: string }>({
        op: 'enterprises.list', method: 'GET', scope: 'project', idempotent: true,
        url: url('enterprises', { projectId, pageToken, pageSize: 100, view: 'BASIC' }),
      }),
    getEnterprise: (enterprise: string) =>
      http.call<AmapiEnterprise>({ op: 'enterprises.get', method: 'GET', scope: 'enterprise', idempotent: true, read: true, url: url(enterprise) }),
    patchEnterprise: (enterprise: string, body: Partial<AmapiEnterprise>, mask: string[]) =>
      http.call<AmapiEnterprise>({
        op: 'enterprises.patch', method: 'PATCH', scope: 'enterprise', idempotent: true, body,
        url: url(enterprise, { updateMask: mask.join(',') }),
      }),
    upgradeUrl: (enterprise: string) =>
      http.call<{ url?: string }>({
        op: 'enterprises.generateEnterpriseUpgradeUrl', method: 'POST', scope: 'enterprise', idempotent: false, body: {},
        url: url(`${enterprise}:generateEnterpriseUpgradeUrl`),
      }),
    // policies.get: read only by the freeze lock of devices.patch (AN15: is the policy a device is attached to
    // wipe-capable?).
    getPolicy: (policy: string) =>
      http.call<AmapiPolicy>({ op: 'policies.get', method: 'GET', scope: 'enterprise', idempotent: true, read: true, url: url(policy) }),
    patchPolicy: (policy: string, body: AmapiPolicy) =>
      http.call<AmapiPolicy>({ op: 'policies.patch', method: 'PATCH', scope: 'enterprise', idempotent: true, body, url: url(policy) }),
    deletePolicy: (policy: string) =>
      http.call<unknown>({ op: 'policies.delete', method: 'DELETE', scope: 'enterprise', idempotent: true, read: true, url: url(policy) }),
    createEnrollmentToken: (enterprise: string, body: Partial<AmapiEnrollmentToken>) =>
      http.call<AmapiEnrollmentToken>({
        op: 'enrollmentTokens.create', method: 'POST', scope: 'enterprise', idempotent: false, body, url: url(`${enterprise}/enrollmentTokens`),
      }),
    deleteEnrollmentToken: (token: string) =>
      http.call<unknown>({ op: 'enrollmentTokens.delete', method: 'DELETE', scope: 'enterprise', idempotent: true, read: true, url: url(token) }),
    listEnrollmentTokens: (enterprise: string, pageToken?: string) =>
      http.call<{ enrollmentTokens?: AmapiEnrollmentToken[]; nextPageToken?: string }>({
        op: 'enrollmentTokens.list', method: 'GET', scope: 'enterprise', idempotent: true,
        url: url(`${enterprise}/enrollmentTokens`, { pageToken, pageSize: 100 }),
      }),
    getEnrollmentToken: (token: string) =>
      http.call<AmapiEnrollmentToken>({ op: 'enrollmentTokens.get', method: 'GET', scope: 'enterprise', idempotent: true, read: true, url: url(token) }),
    getDevice: (device: string) =>
      http.call<AmapiDevice>({ op: 'devices.get', method: 'GET', scope: 'enterprise', idempotent: true, read: true, url: url(device) }),
    listDevices: (enterprise: string, pageToken?: string) =>
      http.call<{ devices?: AmapiDevice[]; nextPageToken?: string }>({
        op: 'devices.list', method: 'GET', scope: 'enterprise', idempotent: true, url: url(`${enterprise}/devices`, { pageToken, pageSize: 100 }),
      }),
    patchDevice: (device: string, body: Partial<AmapiDevice>, mask: string[]) =>
      http.call<AmapiDevice>({
        op: 'devices.patch', method: 'PATCH', scope: 'enterprise', idempotent: true, body, url: url(device, { updateMask: mask.join(',') }),
      }),
    deleteDevice: (device: string, wipeDataFlags: string[] | undefined, wipeReasonMessage: string | undefined) =>
      http.call<unknown>({
        op: 'devices.delete', method: 'DELETE', scope: 'enterprise', idempotent: false, read: true,
        url: url(device, { wipeReasonMessage, wipeDataFlags }),
      }),
    issueCommand: (device: string, cmd: AmapiCommand) =>
      http.call<AmapiOperation>({ op: 'devices.issueCommand', method: 'POST', scope: 'enterprise', idempotent: false, body: cmd, url: url(`${device}:issueCommand`) }),
    listOperations: (device: string, pageToken?: string) =>
      http.call<{ operations?: AmapiOperation[]; nextPageToken?: string }>({
        op: 'operations.list', method: 'GET', scope: 'enterprise', idempotent: true, url: url(`${device}/operations`, { pageToken, pageSize: 100 }),
      }),
    getOperation: (operation: string) =>
      http.call<AmapiOperation>({ op: 'operations.get', method: 'GET', scope: 'enterprise', idempotent: true, read: true, url: url(operation) }),
    cancelOperation: (operation: string) =>
      http.call<unknown>({ op: 'operations.cancel', method: 'POST', scope: 'enterprise', idempotent: true, body: {}, url: url(`${operation}:cancel`) }),
    createWebToken: (enterprise: string, body: { parentFrameUrl: string; enabledFeatures: string[] }) =>
      http.call<{ value?: string }>({ op: 'webTokens.create', method: 'POST', scope: 'enterprise', idempotent: false, body, url: url(`${enterprise}/webTokens`) }),
    getApplication: (application: string, languageCode: string) =>
      http.call<AmapiApplication>({ op: 'applications.get', method: 'GET', scope: 'enterprise', idempotent: true, url: url(application, { languageCode }) }),
    provisioningInfo: (id: string) =>
      http.call<Record<string, unknown>>({ op: 'provisioningInfo.get', method: 'GET', scope: 'project', idempotent: true, read: true, url: url(`provisioningInfo/${encodeURIComponent(id)}`) }),
  };
}

export type AmapiClient = ReturnType<typeof amapiClient>;
