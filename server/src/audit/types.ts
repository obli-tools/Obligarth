// Types of the hardened audit journal (docs: audit-durci §3, §5.3). No
// database import: the unit tests load this module without a server.
import type { AuditActorSide, AuditCriticality, AuditOutcome } from '@obligarth/shared';
import type { StepUpVia } from '../services/deviceKey/stepUpProof';

export type { AuditActorSide, AuditCriticality, AuditOutcome };

export type AuditActorType = 'user' | 'job' | 'integration' | 'enrollment' | 'anonymous';

export interface AuditActor {
  type: AuditActorType;
  /** RLS actor token: 'u:7', 'j:audit.seal', 'i:obligate', 'e:enroll', 'a:login'. */
  ref: string;
  /** Username, users only (frozen in the entry). */
  label?: string;
  side: AuditActorSide;
  /** 'platform_admin' or the tenant role slug. */
  role?: string;
  /** The session's tenant. */
  homeTenant?: number;
  /** req.session.authMethod. */
  auth?: string;
  /** Fresh proof of this action. */
  stepUp?: StepUpVia;
  /** sha256(session id), 64 hex. */
  session?: string;
}

export interface AuditOrigin { ip?: string; ua?: string; requestId?: string; route?: string }

export interface AuditWriteContext { actor: AuditActor; origin?: AuditOrigin }

export interface AuditTargets {
  deviceIds: number[];
  /** Serial numbers, in the order of deviceIds (destructive executions only, J29). */
  serials?: string[];
  selection?: { groups?: number[]; tenant?: boolean };
}

export interface AuditEntryInput {
  /** Chain (target tenant). */
  tenantId: number;
  action: string;
  /** Default 'success'. */
  outcome?: AuditOutcome;
  target?: { type: string; id: string; device?: number };
  targets?: AuditTargets;
  details?: Record<string, unknown>;
  reason?: string;
  ticket?: string;
  approvalIds?: number[];
  onBehalfOf?: number;
  links?: { action?: string; intent?: string; command?: string; grant?: string };
}

export interface AuditAppendResult { id: number; uuid: string; seq: number; hash: string; appendedAt: string }

export interface AuditActionDef {
  /** Exact action, or a prefix ending with '.'. */
  name: string;
  criticality: AuditCriticality;
  /** English, translated by the console (audit.actions.<name>). */
  label: string;
}

export interface AuditAppendOptions {
  /** Raises the class of the catalog (never lowers it). */
  criticality?: AuditCriticality;
}

export interface AuditInTxOptions {
  /** 'throw' (default): a failure aborts the caller's transaction (write-ahead).
   *  'spool': under a SAVEPOINT, the entries go to the local spool, never throws. */
  onFailure?: 'throw' | 'spool';
}
