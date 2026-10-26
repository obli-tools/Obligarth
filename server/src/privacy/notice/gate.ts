import { noticeCompleteness, type NoticeMissing, type NoticeSettings, type ObligarthStage } from '@obligarth/shared';

// =============================================================================
// Completeness of the notice at an enrollment (P0-13 T5, D7): a notice lacking its data controller or a contact (the
// DPO or another, noticeCompleteness of shared/src/privacy.ts) is served with a warning in the stage lab (logged and
// counted, the readiness of the tenant says it: P0-13 T6) and refused in pilot and production (noticeIncomplete: the
// enrollment pages answer a message page, nothing is acknowledged, no profile is issued). Pure: the unit tests load it.
// =============================================================================

export type NoticeGate =
  | { kind: 'ok' }
  | { kind: 'warn'; missing: NoticeMissing[] }
  | { kind: 'refuse'; missing: NoticeMissing[] };

export function noticeGate(settings: Readonly<NoticeSettings>, stage: ObligarthStage): NoticeGate {
  const missing = noticeCompleteness(settings);
  if (missing.length === 0) return { kind: 'ok' };
  return stage === 'lab' ? { kind: 'warn', missing } : { kind: 'refuse', missing };
}
