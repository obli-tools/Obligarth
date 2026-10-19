// The Android gateway: the only code of the instance that talks to Google (AMAPI and Pub/Sub). Every method acts
// for the tenant of the current database context; `e` is the AndroidEnterpriseRef read under RLS by the registry
// (enterprises/registry.ts), never a name received from a client. Derived names are built by names.ts.
import type {
  AmapiApplication, AmapiCommand, AmapiDevice, AmapiEnrollmentToken, AmapiEnrollmentTokenPartial, AmapiEnterprise,
  AmapiEnterpriseBasic, AmapiOperation, AmapiPolicy, AmapiProvisioningInfoMin, Page, PubsubReceived,
} from '@obligarth/shared';
import type { BreakerStatus } from '../google/http';
import type { IdentityStatus } from '../google/token';
import type { AndroidEnterpriseRef, PolicyId } from './names';

export type { AndroidEnterpriseRef, PolicyId };

export interface AndroidLinkHealth {
  mode: 'off' | 'google' | 'fake';
  identity: IdentityStatus | null;
  breaker: BreakerStatus | null;
  subscriptionPermission: boolean | null;
}

export interface SignupUrlRequest {
  callbackUrl: string;
  adminEmail?: string;
  allowedDomains: string[];
}

export interface EnterpriseCreateRequest {
  signupUrlName: string;
  enterpriseToken: string;
  enterpriseDisplayName: string;
  primaryColor?: number;
  logo?: { url: string; sha256Hash: string };
}

export type EnterprisePatchField = 'enterpriseDisplayName' | 'logo' | 'primaryColor' | 'termsAndConditions' | 'signinDetails';
export type EnterprisePatch = Partial<Pick<AmapiEnterprise, EnterprisePatchField>>;

export interface EnrollmentTokenRequest {
  policyId?: PolicyId;
  duration: string;
  oneTimeOnly?: boolean;
  allowPersonalUsage?: 'PERSONAL_USAGE_ALLOWED' | 'PERSONAL_USAGE_DISALLOWED' | 'PERSONAL_USAGE_DISALLOWED_USERLESS';
  additionalData: string;
}

export type IframeFeature = 'PLAY_SEARCH' | 'PRIVATE_APPS' | 'WEB_APPS' | 'STORE_BUILDER' | 'MANAGED_CONFIGURATIONS'
  | 'ZERO_TOUCH_CUSTOMER_MANAGEMENT';

export type UserFacingMessage = { defaultMessage: string; localizedMessages?: Record<string, string> };

/** Class of a call for the rate limiter: background work stops at 20 % of the project budget left. */
export type LimiterClass = 'interactive' | 'standard' | 'background';

export interface CallClass { limiter?: LimiterClass }

export interface AndroidGateway {
  readonly mode: 'off' | 'google' | 'fake';
  health(): Promise<AndroidLinkHealth>;
  createSignupUrl(req: SignupUrlRequest): Promise<{ name: string; url: string }>;
  createEnterprise(req: EnterpriseCreateRequest): Promise<AmapiEnterprise>;
  listProjectEnterprises(pageToken?: string): Promise<Page<AmapiEnterpriseBasic>>;
  getEnterprise(e: AndroidEnterpriseRef): Promise<AmapiEnterprise>;
  patchEnterprise(e: AndroidEnterpriseRef, patch: EnterprisePatch, mask: EnterprisePatchField[]): Promise<AmapiEnterprise>;
  setEnterpriseNotifications(e: AndroidEnterpriseRef, on: boolean): Promise<void>;
  upgradeUrl(e: AndroidEnterpriseRef): Promise<{ url: string }>;
  putPolicy(e: AndroidEnterpriseRef, policyId: PolicyId, policy: AmapiPolicy): Promise<{ version: string }>;
  deletePolicy(e: AndroidEnterpriseRef, policyId: PolicyId): Promise<void>;
  createEnrollmentToken(e: AndroidEnterpriseRef, t: EnrollmentTokenRequest): Promise<AmapiEnrollmentToken>;
  deleteEnrollmentToken(e: AndroidEnterpriseRef, tokenId: string): Promise<void>;
  listEnrollmentTokens(e: AndroidEnterpriseRef, pageToken?: string): Promise<Page<AmapiEnrollmentTokenPartial>>;
  getEnrollmentToken(e: AndroidEnterpriseRef, tokenId: string): Promise<AmapiEnrollmentToken | null>;
  getDevice(e: AndroidEnterpriseRef, deviceId: string): Promise<AmapiDevice | null>;
  listDevices(e: AndroidEnterpriseRef, pageToken?: string): Promise<Page<AmapiDevice>>;
  patchDevice(e: AndroidEnterpriseRef, deviceId: string,
    patch: { policyName?: PolicyId; state?: 'ACTIVE' | 'DISABLED'; disabledReason?: UserFacingMessage }): Promise<AmapiDevice>;
  deleteDevice(e: AndroidEnterpriseRef, deviceId: string,
    o: { purpose: 'operator' | 'cleanup'; supersededBy?: string; wipeDataFlags?: string[]; wipeReasonMessage?: string }): Promise<void>;
  issueCommand(e: AndroidEnterpriseRef, deviceId: string, cmd: AmapiCommand): Promise<{ operation: string }>;
  listOperations(e: AndroidEnterpriseRef, deviceId: string, pageToken?: string): Promise<Page<AmapiOperation>>;
  getOperation(e: AndroidEnterpriseRef, operationName: string): Promise<AmapiOperation | null>;
  cancelOperation(e: AndroidEnterpriseRef, operationName: string): Promise<'cancelled' | 'already_done'>;
  createWebToken(e: AndroidEnterpriseRef, w: { parentFrameUrl: string; enabledFeatures: IframeFeature[] }): Promise<{ value: string }>;
  getApplication(e: AndroidEnterpriseRef, packageName: string, languageCode: string): Promise<AmapiApplication>;
  provisioningInfo(e: AndroidEnterpriseRef, id: string): Promise<AmapiProvisioningInfoMin>;
  pull(o: { maxMessages: number; signal?: AbortSignal }): Promise<PubsubReceived[]>;
  modifyAckDeadline(ackIds: string[], seconds: number): Promise<void>;
  acknowledge(ackIds: string[]): Promise<void>;
  seek(time: Date): Promise<void>;
  /** subscriptions.testIamPermissions: does the identity hold pubsub.subscriptions.consume? */
  checkSubscription(): Promise<boolean>;
}
