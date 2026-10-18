// Typed subsets of the Android Management API v1 REST reference (androidmanagement.googleapis.com) and of the
// Pub/Sub v1 messages the instance reads. Unknown fields are kept (index signature): Google adds fields every
// month and a lost field would be a silent regression. Imported by direct path until the shared index exports it.

export type AmapiPassthrough = { [key: string]: unknown };

export type AmapiEnterpriseType =
  | 'ENTERPRISE_TYPE_UNSPECIFIED' | 'MANAGED_GOOGLE_DOMAIN' | 'MANAGED_GOOGLE_PLAY_ACCOUNTS_ENTERPRISE';

export type AmapiNotificationType =
  | 'ENROLLMENT' | 'STATUS_REPORT' | 'COMMAND' | 'USAGE_LOGS' | 'ENTERPRISE_UPGRADE';

export interface AmapiSigninDetail extends AmapiPassthrough {
  signinUrl?: string;
  allowPersonalUsage?: string;
  defaultStatus?: string;
}

export interface AmapiExternalData { url: string; sha256Hash: string }

export interface AmapiEnterprise extends AmapiPassthrough {
  name: string;
  enterpriseDisplayName?: string;
  enterpriseType?: AmapiEnterpriseType;
  managedGoogleDomainType?: 'MANAGED_GOOGLE_DOMAIN_TYPE_UNSPECIFIED' | 'TYPE_TEAM' | 'TYPE_DOMAIN';
  pubsubTopic?: string;
  enabledNotificationTypes?: AmapiNotificationType[];
  primaryColor?: number;
  logo?: AmapiExternalData;
  termsAndConditions?: Array<{ header?: { defaultMessage?: string }; content?: { defaultMessage?: string } }>;
  signinDetails?: AmapiSigninDetail[];
}

export interface AmapiEnterpriseBasic { name: string; enterpriseDisplayName?: string }

export interface AmapiSignupUrl { name: string; url: string }

export interface AmapiEnrollmentToken extends AmapiPassthrough {
  name: string;
  value?: string;
  qrCode?: string;
  expirationTimestamp?: string;
  duration?: string;
  policyName?: string;
  additionalData?: string;
  allowPersonalUsage?: string;
  oneTimeOnly?: boolean;
}

export type AmapiEnrollmentTokenPartial = Pick<AmapiEnrollmentToken, 'name' | 'expirationTimestamp' | 'allowPersonalUsage'>;

export interface AmapiDevice extends AmapiPassthrough {
  name: string;
  managementMode?: 'MANAGEMENT_MODE_UNSPECIFIED' | 'DEVICE_OWNER' | 'PROFILE_OWNER';
  state?: string;
  appliedState?: string;
  ownership?: 'OWNERSHIP_UNSPECIFIED' | 'COMPANY_OWNED' | 'PERSONALLY_OWNED';
  policyName?: string;
  appliedPolicyName?: string;
  appliedPolicyVersion?: string;
  enrollmentTime?: string;
  lastStatusReportTime?: string;
  lastPolicySyncTime?: string;
  enrollmentTokenName?: string;
  enrollmentTokenData?: string;
  previousDeviceNames?: string[];
  apiLevel?: number;
}

export interface AmapiOperation extends AmapiPassthrough {
  name: string;
  done?: boolean;
  metadata?: AmapiPassthrough & { type?: string; createTime?: string };
  error?: { code?: number; message?: string };
}

export interface AmapiCommand {
  type: 'LOCK' | 'RESET_PASSWORD' | 'REBOOT' | 'RELINQUISH_OWNERSHIP' | 'CLEAR_APP_DATA' | 'START_LOST_MODE'
    | 'STOP_LOST_MODE' | 'REQUEST_DEVICE_INFO' | 'WIPE';
  /** Mandatory, e.g. '86400s': the AMAPI default (10 minutes) is never relied on. */
  duration: string;
  [key: string]: unknown;
}

export interface AmapiPolicy extends AmapiPassthrough {
  name?: string;
  version?: string;
}

/** One property of an app's managed configuration schema (Application.managedProperties). */
export interface AmapiManagedProperty extends AmapiPassthrough {
  key?: string;
  type?: 'MANAGED_PROPERTY_TYPE_UNSPECIFIED' | 'BOOL' | 'STRING' | 'INTEGER' | 'CHOICE' | 'MULTISELECT' | 'HIDDEN' | 'BUNDLE' | 'BUNDLE_ARRAY';
  title?: string;
  description?: string;
  entries?: Array<{ name?: string; value?: string }>;
  defaultValue?: unknown;
  nestedProperties?: AmapiManagedProperty[];
}

/** enterprises.applications.get (lot AN-E1): what the catalog keeps of it is minimized (apps/metadata.ts). */
export interface AmapiApplication extends AmapiPassthrough {
  name: string;
  title?: string;
  author?: string;
  iconUrl?: string;
  smallIconUrl?: string;
  distributionChannel?: 'DISTRIBUTION_CHANNEL_UNSPECIFIED' | 'PUBLIC_GOOGLE_HOSTED' | 'PRIVATE_GOOGLE_HOSTED' | 'PRIVATE_SELF_HOSTED';
  minAndroidSdkVersion?: number;
  managedProperties?: AmapiManagedProperty[];
  permissions?: Array<{ permissionId?: string; name?: string; description?: string }>;
  appTracks?: Array<{ trackId?: string; trackAlias?: string }>;
  features?: string[];
}

/** provisioningInfo reduced by the gateway: never imei, meid nor serialNumber. */
export interface AmapiProvisioningInfoMin {
  managementMode?: string;
  ownership?: string;
  apiLevel?: number;
  brand?: string;
  model?: string;
  authenticatedUserEmail?: string;
}

export interface AmapiEnterpriseUpgradeEvent extends AmapiPassthrough {
  enterprise?: string;
  upgradeState?: string;
}

export interface AmapiUsageLogEvents extends AmapiPassthrough {
  device?: string;
  usageLogEvents?: Array<AmapiPassthrough & { eventType?: string; eventTime?: string }>;
}

/** One message of a Pub/Sub pull response (receivedMessages[]). */
export interface PubsubReceived {
  ackId: string;
  message: {
    messageId: string;
    publishTime: string;
    data?: string;
    attributes?: Record<string, string>;
  };
  deliveryAttempt?: number;
}

export interface Page<T> { items: T[]; nextPageToken?: string }
