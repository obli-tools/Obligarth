// =============================================================================
// Hardened audit journal: types shared by the server and the console
// =============================================================================
//
// One hash chain per tenant, written by the database function
// obligarth.audit_append only; each entry keeps its canonical JSON body (the
// proof) and columns projected from it (search, filters). Sealed every hour
// (Merkle tree of the chain heads, Ed25519 signature, optional RFC 3161 time
// stamp), exported to SIEM destinations, purged by the retention job only.

export type AuditCriticality = 'critical' | 'protective' | 'standard';
export type AuditOutcome = 'success' | 'failure' | 'denied' | 'requested' | 'scheduled' | 'cancelled';
export type AuditActorSide = 'msp' | 'client' | 'system' | 'unknown';

export const AUDIT_OUTCOMES: readonly AuditOutcome[] = ['success', 'failure', 'denied', 'requested', 'scheduled', 'cancelled'];
export const AUDIT_CRITICALITIES: readonly AuditCriticality[] = ['critical', 'protective', 'standard'];
export const AUDIT_ACTOR_SIDES: readonly AuditActorSide[] = ['msp', 'client', 'system', 'unknown'];

/** Retention of a tenant's chain (D25): 12 months by default, 6 to 36. */
export const AUDIT_RETENTION_DEFAULT_MONTHS = 12;
export const AUDIT_RETENTION_MIN_MONTHS = 6;
export const AUDIT_RETENTION_MAX_MONTHS = 36;

export interface AuditEntryDto {
  id: number;
  uuid: string;
  tenantId: number;
  tenantName: string | null;
  chainSeq: number;
  occurredAt: string;             // body ts
  recordedAt: string;             // created_at (database clock)
  action: string;
  outcome: AuditOutcome;
  criticality: AuditCriticality;
  actor: {
    type: string; ref: string; label: string | null; displayName: string | null; side: AuditActorSide;
    role: string | null; homeTenantId: number | null;
  };
  onBehalfOfTenantId: number | null;
  deviceId: number | null;
  deviceName: string | null;      // resolved in the entry's tenant only (E14)
  resourceType: string | null;
  resourcePath: string | null;
  resourceName: string | null;    // resolved in the entry's tenant only (E14)
  targetCount: number | null;
  details: Record<string, unknown> | null;
  reason: string | null;
  ticket: string | null;
  approvalIds: number[];
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
  legacy: boolean;
  late: boolean;
  /** Kept for the existing screens: userId = actor user id, username = actor.label, createdAt = recordedAt. */
  userId: number | null;
  username: string | null;
  createdAt: string;
}

export interface AuditEntryList {
  items: AuditEntryDto[];
  total: number;
  /** Next page of a tenant's chain (beforeSeq), null at its start or in the global view. */
  nextBeforeSeq: number | null;
}

/** An inclusion proof of a tenant's chain head in a seal (RFC 6962). */
export interface AuditSealLeafDto {
  index: number;
  seq: number;
  hash: string;
  proof: string[];
}

export interface AuditSealDto {
  seq: number;
  sealedAt: string;
  leaves: number;
  root: string;
  prev: string;
  hash: string;
  keyId: string;
  signature: string;
  tsa: { status: 'ok' | 'disabled' | 'failed'; genTime: string | null };
  /** The reader's tenant's leaf (absent from a global listing). */
  leaf?: AuditSealLeafDto | null;
}

export interface AuditEntryDetailDto extends AuditEntryDto {
  /** The canonical body exactly as hashed. */
  body: string;
  prevHash: string;
  hash: string;
  /** First seal whose leaf of this tenant covers the entry, with its proof. */
  seal: AuditSealDto | null;
}

export interface AuditSealKeyDto {
  keyId: string;
  algorithm: 'ed25519';
  /** Raw public key, 64 hexadecimal characters. */
  publicKey: string;
  /** SubjectPublicKeyInfo PEM (openssl pkeyutl -verify -pubin). */
  publicKeyPem: string;
  createdAt: string;
  retiredAt: string | null;
}

export interface AuditVerificationDto {
  id: number;
  tenantId: number;
  kind: 'incremental' | 'full' | 'on_demand';
  status: 'running' | 'ok' | 'broken' | 'error';
  fromSeq: number | null;
  toSeq: number | null;
  entries: number;
  seals: number;
  problem: Record<string, unknown> | null;
  startedAt: string;
  finishedAt: string | null;
}

export interface AuditChainStatus {
  tenantId: number;
  head: { seq: number; hash: string; appendedAt: string | null } | null;
  anchor: { seq: number; hash: string; purgedAt: string } | null;
  retention: {
    months: number; effectiveMonths: number; pendingMonths: number | null; pendingEffectiveAt: string | null;
    justification: string | null; legalHoldUntil: string | null; legalHoldReason: string | null;
  };
  lastSeal: { seq: number; sealedAt: string; coveredSeq: number; tsaStatus: 'ok' | 'disabled' | 'failed' } | null;
  lastVerification: { at: string; kind: string; status: 'running' | 'ok' | 'broken' | 'error'; entries: number } | null;
  exportLagSeconds?: number | null;                // platform administrators only
}

// ── Administration (platform administrators, master tenant) ─────────────────

export type AuditDestinationKind = 'syslog_tls' | 'webhook';

export interface AuditDestinationDto {
  id: number;
  uuid: string;
  name: string;
  kind: AuditDestinationKind;
  scopeTenantId: number | null;
  /** Settings in clear (never a secret). */
  config: Record<string, unknown>;
  /** Names of the secrets set (never their values). */
  secretsSet: string[];
  enabled: boolean;
  requiredForPurge: boolean;
  includeSeals: boolean;
  lastSealSeq: number;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastErrorCode: string | null;
  lagSeconds: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditRetentionRow {
  tenantId: number;
  tenantName: string | null;
  tenantExists: boolean;
  months: number;
  effectiveMonths: number;
  pendingMonths: number | null;
  pendingEffectiveAt: string | null;
  justification: string | null;
  legalHoldUntil: string | null;
  legalHoldReason: string | null;
  headSeq: number;
  anchorSeq: number;
}

export interface AuditSpoolStatus {
  entries: number;
  oldestSpooledAt: string | null;
  rejected: number;
  files: number;
}

export interface AuditSealingStatus {
  lastSeal: { seq: number; sealedAt: string; leaves: number; tsaStatus: 'ok' | 'disabled' | 'failed' } | null;
  tsaConfigured: boolean;
  activeKeyId: string | null;
  instanceId: string | null;
}
