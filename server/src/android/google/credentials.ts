// Sources of the Google identity of the instance (section 5.2):
//   - vault_key: the JSON key of the service account obligarth-amapi-runtime@<project>, sealed in the vault
//     (instance secret android_google_credentials), opened in memory only to sign the OAuth 2.0 JWT assertion;
//   - adc: application default credentials without any key file (metadata server of an attached service account;
//     a workload identity federation file, which carries no secret). A service account key file is refused.
// No key, assertion nor access token ever reaches a log line, an error message, the database or a job.
// Pure, erasable TypeScript (unit tests U-A16).
import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';

export class AndroidCredentialError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'AndroidCredentialError';
    this.code = code;
  }
}

/** The fields of a service account key the instance keeps in memory. */
export interface ServiceAccountKey {
  clientEmail: string;
  privateKeyId: string;
  projectId: string;
  tokenUri: string;
  privateKey: KeyObject;
}

/** The expected account of a project: obligarth-amapi-runtime@<project>.iam.gserviceaccount.com. */
export function expectedServiceAccount(projectId: string): string {
  return `obligarth-amapi-runtime@${projectId}.iam.gserviceaccount.com`;
}

const KEY_MAX_BYTES = 16 * 1024;

/**
 * Parses and checks a service account key (the deposit's controls): type service_account, project_id equal to the
 * configured project, client_email the runtime account of that project, token_uri the configured token endpoint,
 * a private key that loads. Messages name the failing field, never a value of the key.
 */
export function parseServiceAccountKey(text: string, o: { projectId: string; tokenUrl: string; requireAccount?: boolean }): ServiceAccountKey {
  if (typeof text !== 'string' || text.length === 0 || Buffer.byteLength(text) > KEY_MAX_BYTES) {
    throw new AndroidCredentialError('invalid_key', 'the key must be a JSON document of 16 KiB at most');
  }
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new AndroidCredentialError('invalid_key', 'the key is not valid JSON');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new AndroidCredentialError('invalid_key', 'the key is not a JSON object');
  if (raw.type !== 'service_account') throw new AndroidCredentialError('wrong_type', 'type must be service_account');
  if (raw.project_id !== o.projectId) throw new AndroidCredentialError('wrong_project', 'project_id differs from ANDROID_GCP_PROJECT_ID');
  if ((o.requireAccount ?? true) && raw.client_email !== expectedServiceAccount(o.projectId)) {
    throw new AndroidCredentialError('wrong_account', 'client_email is not the runtime service account of the project');
  }
  if (typeof raw.client_email !== 'string' || !/^[a-z0-9-]{6,30}@[a-z0-9-]{6,30}\.iam\.gserviceaccount\.com$/.test(raw.client_email)) {
    throw new AndroidCredentialError('wrong_account', 'client_email is not a service account address');
  }
  if (typeof raw.private_key_id !== 'string' || !/^[0-9a-f]{40}$/.test(raw.private_key_id)) {
    throw new AndroidCredentialError('invalid_key', 'private_key_id must be 40 hexadecimal characters');
  }
  if (raw.token_uri !== undefined && raw.token_uri !== o.tokenUrl) {
    throw new AndroidCredentialError('wrong_token_uri', 'token_uri differs from the token endpoint of this mode');
  }
  if (typeof raw.private_key !== 'string' || !raw.private_key.includes('PRIVATE KEY')) {
    throw new AndroidCredentialError('invalid_key', 'private_key is missing');
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: raw.private_key, format: 'pem' });
  } catch {
    throw new AndroidCredentialError('invalid_key', 'private_key does not load');
  }
  if (privateKey.asymmetricKeyType !== 'rsa') throw new AndroidCredentialError('invalid_key', 'private_key must be an RSA key');
  return {
    clientEmail: raw.client_email, privateKeyId: raw.private_key_id, projectId: o.projectId,
    tokenUri: o.tokenUrl, privateKey,
  };
}

/** The signed JWT bearer assertion of OAuth 2.0 (RS256, one hour at most). */
export function signAssertion(key: ServiceAccountKey, scopes: readonly string[], nowSeconds = Math.floor(Date.now() / 1000)): string {
  const header = { alg: 'RS256', typ: 'JWT', kid: key.privateKeyId };
  const claims = { iss: key.clientEmail, scope: scopes.join(' '), aud: key.tokenUri, iat: nowSeconds, exp: nowSeconds + 3600 };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = `${b64(header)}.${b64(claims)}`;
  const sig = createSign('RSA-SHA256').update(input).sign(key.privateKey).toString('base64url');
  return `${input}.${sig}`;
}

/**
 * The adc mode never reads a service account key: GOOGLE_APPLICATION_CREDENTIALS may only name a federation
 * configuration (type external_account, no secret). Returns the kind of source, or throws.
 */
export function checkAdcFile(content: string | null): 'metadata' | 'external_account' {
  if (content === null) return 'metadata';
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(content) as Record<string, unknown>;
  } catch {
    throw new AndroidCredentialError('adc_invalid', 'GOOGLE_APPLICATION_CREDENTIALS is not valid JSON');
  }
  if (raw?.type === 'service_account' || 'private_key' in (raw ?? {})) {
    throw new AndroidCredentialError('adc_key_file', 'a service account key file is refused in adc mode (use the vault)');
  }
  if (raw?.type !== 'external_account') throw new AndroidCredentialError('adc_invalid', 'adc accepts only an external_account configuration');
  return 'external_account';
}
