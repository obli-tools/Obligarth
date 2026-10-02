import { AppError } from '../../middleware/errorHandler';
import { edgeErrorResponse, isAppleEdgeError, type AppleEdgeError } from './errors';

// =============================================================================
// An error of apple-edge as the console answers it (docs: integration-apple-
// edge §5.4): status, English message, code (translated by the client,
// errors.<code>). Kept apart from errors.ts, which the unit tests load
// without the server (AppError is not native TypeScript).
// =============================================================================

export function toAppError(e: AppleEdgeError, context: 'console' | 'enrollment' = 'console'): AppError {
  const r = edgeErrorResponse(e, context);
  return new AppError(r.status, r.message, r.code);
}

/** Rethrows an AppleEdgeError as the console's AppError; anything else unchanged. */
export function rethrowForConsole(err: unknown): never {
  if (isAppleEdgeError(err)) throw toAppError(err as AppleEdgeError, 'console');
  throw err;
}
