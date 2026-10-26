import type { NoticeMissing } from '@obligarth/shared';
import { AppError } from '../../middleware/errorHandler';

// =============================================================================
// The refusal of an enrollment whose notice is not complete outside the stage lab (P0-13 T5, D7): thrown by the notice
// providers (provider.ts), answered by the enrollment surfaces with a message page (Apple: apple/enrollment/surface.ts;
// Android: the provider answers no notice, the surfaces show their page "enrollment unavailable") and by the console
// with 409 noticeIncomplete (errors.noticeIncomplete).
// =============================================================================

export class NoticeIncompleteError extends AppError {
  readonly missing: NoticeMissing[];

  constructor(missing: NoticeMissing[]) {
    super(409, 'The employee notice of the tenant is not complete (data controller, contact): no enrollment outside the laboratory',
      'noticeIncomplete', { missing });
    this.name = 'NoticeIncompleteError';
    this.missing = missing;
  }
}

export const isNoticeIncomplete = (err: unknown): err is NoticeIncompleteError =>
  err instanceof NoticeIncompleteError || (err as { code?: unknown } | null)?.code === 'noticeIncomplete';
