// =============================================================================
// Errors of the internal API of apple-edge, as the brain sees them (docs:
// integration-apple-edge §5.4). apple-edge answers {"error": {"code",
// "message"}}; the client adds its own codes for what never reached an answer
// (transport, timeout, circuit open), an answer it cannot read (protocol), a
// version out of the matrix (incompatible) and the integration turned off
// (disabled). The message of apple-edge is never sensitive (apple-edge §5.2).
// Pure (no AppError here: edge/appError.ts maps onto the console's errors);
// the unit tests run under node --test.
// =============================================================================

export type AppleEdgeClientCode = 'transport' | 'timeout' | 'unavailable' | 'protocol' | 'incompatible' | 'disabled';

/** apple-edge's own code, or one of the client's. */
export type AppleEdgeErrorCode = AppleEdgeClientCode | (string & {});

export class AppleEdgeError extends Error {
  /** HTTP status, null when no answer came (transport, timeout, circuit, disabled, incompatible). */
  readonly status: number | null;
  readonly code: AppleEdgeErrorCode;
  /** A later attempt may succeed (transport, timeout, circuit open, 5xx, 502 ade_unavailable). */
  readonly retryable: boolean;
  /** The enrollments the error names (422 target_outside_tenant of the enqueue: apple-edge README §10, point 19);
   *  null when it names none, or more than it lists (targets_truncated). */
  readonly targets: string[] | null;

  constructor(status: number | null, code: AppleEdgeErrorCode, message: string, retryable: boolean, targets: string[] | null = null) {
    super(message);
    this.name = 'AppleEdgeError';
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.targets = targets;
  }
}

export function isAppleEdgeError(err: unknown): err is AppleEdgeError {
  return err instanceof AppleEdgeError || (err as { name?: unknown } | null)?.name === 'AppleEdgeError';
}

/** retryable as §5.4 defines it: transport, timeout, unavailable, 502 and any 5xx. */
export function isRetryableAnswer(status: number | null, code: string): boolean {
  if (status === null) return code === 'transport' || code === 'timeout' || code === 'unavailable';
  return status >= 500 || status === 502 || code === 'unavailable';
}

/** What the console answers for an error of apple-edge (§5.4). */
export interface EdgeErrorResponse {
  status: number;
  message: string;
  code: string | undefined;
}

/** The answer of the console (or of the enrollment pages) for `e`. */
export function edgeErrorResponse(e: AppleEdgeError, context: 'console' | 'enrollment'): EdgeErrorResponse {
  const code = String(e.code);
  const status = e.status;
  const unavailable: EdgeErrorResponse = { status: 503, message: 'The device service (apple-edge) is unavailable', code: 'appleEdgeUnavailable' };
  if (code === 'disabled') return { status: 503, message: 'The Apple integration is turned off on this instance', code: 'appleIntegrationDisabled' };
  if (code === 'incompatible') return { status: 503, message: 'The device service (apple-edge) runs an incompatible version', code: 'appleEdgeIncompatible' };
  if (status === null || code === 'transport' || code === 'timeout' || code === 'unavailable') return unavailable;
  if (code === 'protocol') return { status: 502, message: 'The device service (apple-edge) gave an answer that cannot be read', code: 'appleEdgeProtocol' };
  switch (code) {
    case 'invalid_request': return { status: 500, message: 'The request to the device service was refused', code: 'appleEdgeRejected' };
    case 'unauthorized': return unavailable;
    case 'tenant_not_found': return { status: 409, message: 'This tenant is not provisioned at the device service yet', code: 'appleTenantNotProvisioned' };
    case 'tenant_not_live': return { status: 409, message: 'This tenant is being retired at the device service', code: 'appleTenantNotLive' };
    case 'tenant_not_retiring': return { status: 409, message: 'This tenant is not being retired at the device service', code: 'appleTenantNotRetiring' };
    case 'topic_bound_to_other_tenant': return { status: 409, message: 'This push topic belongs to another tenant', code: 'pushTopicBoundElsewhere' };
    case 'command_uuid_conflict': return { status: 500, message: 'Command identifier conflict at the device service', code: 'appleEdgeRejected' };
    case 'tenant_has_active_enrollments': return { status: 409, message: 'Devices are still enrolled in this tenant: unenroll them first', code: 'appleTenantHasEnrollments' };
    case 'tenant_has_ade_tokens': return { status: 409, message: 'ADE servers are still connected to this tenant: remove them first', code: 'appleTenantHasAdeTokens' };
    case 'enrollment_active': return { status: 409, message: 'The enrollment must be released first', code: 'appleEnrollmentActive' };
    case 'signing_identity_missing':
    case 'signing_identity_unusable':
      return { status: 503, message: 'Enrollment profiles cannot be signed on this instance', code: 'appleSigningUnavailable' };
    case 'ade_token_not_active':
    case 'ade_token_unusable':
      return { status: 409, message: 'The ADE server is not active', code: 'adeTokenNotActive' };
    case 'payload_too_large': return { status: 413, message: 'Too large for the device service', code: 'appleEdgePayloadTooLarge' };
    case 'target_outside_tenant': return { status: 422, message: 'A target is not an enrolled device of this tenant', code: 'appleTargetOutsideTenant' };
    case 'url_outside_tenant': return { status: 500, message: 'The enrollment profile names another tenant', code: 'appleEdgeRejected' };
    case 'secret_unavailable': return { status: 422, message: 'The unlock token of this device is unavailable', code: 'unlockTokenUnavailable' };
    case 'secret_in_command': return { status: 422, message: 'The command carries a secret in clear', code: 'appleSecretInCommand' };
    case 'machine_info_not_found':
    case 'invalid_machine_info':
      return context === 'enrollment'
        ? { status: 403, message: 'This device could not be verified', code: 'appleMachineInfoRefused' }
        : { status: 422, message: 'The device information could not be verified', code: 'appleMachineInfoRefused' };
    case 'validation_failed':
    case 'ade_rejected':
    case 'unknown_usage':
      return { status: 422, message: 'The device service refused the request', code: 'appleEdgeValidationFailed' };
    case 'commands_frozen': return { status: 423, message: 'The commands of this tenant are frozen', code: 'tenantFrozen' };
    case 'enrollment_not_found':
    case 'command_not_found':
    case 'certificate_not_found':
    case 'secret_not_found':
    case 'not_found':
      return { status: 404, message: 'Not found at the device service', code: 'appleEdgeNotFound' };
    case 'ade_unavailable': return unavailable;
    default:
      break;
  }
  if (status >= 500) return unavailable;
  if (status === 404) return { status: 404, message: 'Not found at the device service', code: 'appleEdgeNotFound' };
  return { status: status === 409 || status === 422 || status === 423 ? status : 500, message: 'The device service refused the request', code: 'appleEdgeRejected' };
}
