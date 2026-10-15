// The only Google URLs of the instance (frozen; G-A6: no other file names a googleapis.com host). In fake mode
// the base URLs come from ANDROID_FAKE_BASE_URL instead (config.ts).
export const GOOGLE_AMAPI_BASE_URL = 'https://androidmanagement.googleapis.com/v1/';
export const GOOGLE_PUBSUB_BASE_URL = 'https://pubsub.googleapis.com/v1/';
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
/** Metadata server of Google Cloud (adc, attached service account). */
export const GOOGLE_METADATA_TOKEN_URL =
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';
export const GOOGLE_METADATA_EMAIL_URL =
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email';
/** Scopes of the access token: AMAPI and Pub/Sub. */
export const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/androidmanagement',
  'https://www.googleapis.com/auth/pubsub',
] as const;
