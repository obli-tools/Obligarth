// Paths the logger censors (docs: coffre-secrets V18, R3; écart E-V2): a
// PostgreSQL constraint violation copies the whole row into err.detail
// ("Failing row contains (…)"), secrets and personal data included; and a
// secret, a sealed value or a credential must never reach a log line, at the
// root of the logged object or one level down. Plain constants: imported by
// utils/logger.ts (and the test harness), never by the vault.

const SECRET_KEYS = [
  'password', 'passwd', 'apiKey', 'inboundSecret', 'secret', 'token', 'botToken', 'appToken', 'userKey',
  'webhookUrl', 'totpSecret', 'totp_secret', 'privateKey', 'private_key', 'sToken', 's_token',
  'authorization', 'cookie', 'sealed', 'sealedPayload', 'sealed_payload',
  // the sealed columns of the vault's registry (core and modules)
  'totp_secret_enc', 'password_enc', 'secrets_enc', 'license_key_enc', 'sealed_payload_enc', 'value_enc',
  'pending_totp_secret_enc', 'pendingTotpSecretEnc', 'dek_wrapped',
] as const;

export const LOG_REDACT_PATHS: string[] = [
  'err.detail', 'err.where', 'detail',
  ...SECRET_KEYS,
  ...SECRET_KEYS.map((k) => `*.${k}`),
];

export const LOG_REDACT_CENSOR = '[redacted]';
