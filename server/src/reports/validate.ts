import { z } from 'zod';
import type { ReportFormat, ReportSection, ReportType } from '@obligarth/shared';

// =============================================================================
// Reports: validation of the definitions written by the console (P0-12 T1)
// =============================================================================
// The routes passed req.body as is to the service: an unknown type, format or
// section ended as a 500 on a CHECK constraint, any column could be written.
// Here every field is bounded and the schema is strict (an unknown field is
// refused). The function is pure (no database): the scope is checked against
// the tenant and the caller's visibility by the route.
// Codes (AppError, translated by the console under errors.*): invalidCron,
// invalidTimezone, invalidOptions (filters), invalidScope, invalidRequest.

/** The types this lot generates (the CHECK reports_type_check holds the same). */
export const REPORT_TYPES = ['fleet', 'software', 'custom'] as const satisfies readonly ReportType[];
export const REPORT_FORMATS = ['json', 'csv', 'pdf', 'excel', 'html'] as const satisfies readonly ReportFormat[];
export const REPORT_SECTIONS = ['hardware', 'software', 'network', 'inventory_detail'] as const satisfies readonly ReportSection[];
export const REPORT_SCOPE_TYPES = ['tenant', 'group', 'device'] as const;

const MAX_INT = 2_147_483_647;

// ── Cron (5 fields) ─────────────────────────────────────────────────────────
// Syntax only: minute, hour, day of month, month, day of week; numbers, '*',
// ranges, steps, lists, and the English names of months and days. The
// planning (cronSchedule, P0-4 T4) adds what only a parser knows: the
// occurrences and the minimal gap.

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const CRON_FIELDS: Array<{ min: number; max: number; names?: string[]; nameBase?: number }> = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12, names: MONTHS, nameBase: 1 },
  { min: 0, max: 7, names: DAYS, nameBase: 0 },
];

function cronValue(raw: string, f: (typeof CRON_FIELDS)[number]): number | null {
  if (/^\d{1,2}$/.test(raw)) {
    const n = Number(raw);
    return n >= f.min && n <= f.max ? n : null;
  }
  const i = f.names ? f.names.indexOf(raw.toLowerCase()) : -1;
  return i >= 0 ? i + (f.nameBase ?? 0) : null;
}

function cronPart(part: string, f: (typeof CRON_FIELDS)[number]): boolean {
  const m = /^([^/]+)(?:\/(\d{1,2}))?$/.exec(part);
  if (!m) return false;
  const [, range, step] = m;
  if (step !== undefined && (Number(step) < 1 || Number(step) > f.max)) return false;
  if (range === '*') return true;
  const bounds = range.split('-');
  if (bounds.length > 2) return false;
  const values = bounds.map((b) => cronValue(b, f));
  if (values.some((v) => v === null)) return false;
  // A single value with a step ('5/15') starts there; a range goes upwards.
  return values.length === 1 || (values[0] as number) <= (values[1] as number);
}

/** A cron of five fields, each one readable. */
export function isCronSyntax(cron: string): boolean {
  if (cron.length > 200) return false;
  const fields = cron.trim().split(/\s+/);
  if (fields.length !== 5) return false;
  return fields.every((field, i) => field.length > 0 && field.split(',').every((part) => cronPart(part, CRON_FIELDS[i])));
}

// ── Time zone ───────────────────────────────────────────────────────────────

/** An IANA time zone name the runtime knows ('UTC', 'Europe/Paris'); never an offset. */
export function isTimeZone(tz: string): boolean {
  if (tz.length > 100 || !/^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+){0,2}$/.test(tz)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

// ── Schemas ─────────────────────────────────────────────────────────────────

const emptyToNull = (v: unknown) => (typeof v === 'string' && v.trim() === '' ? null : v);

const fields = {
  name: z.string().trim().min(1).max(300),
  description: z.preprocess(emptyToNull, z.string().max(2000).nullable()),
  type: z.enum(REPORT_TYPES),
  format: z.enum(REPORT_FORMATS),
  scopeType: z.enum(REPORT_SCOPE_TYPES),
  scopeId: z.number().int().positive().max(MAX_INT).nullable(),
  sections: z.array(z.enum(REPORT_SECTIONS)).max(REPORT_SECTIONS.length)
    .refine((s) => new Set(s).size === s.length, 'each section once'),
  // The types of this lot take no option: an empty object, nothing else.
  filters: z.object({}).strict(),
  scheduleCron: z.preprocess(emptyToNull, z.string().trim().max(200).refine(isCronSyntax, 'five cron fields').nullable()),
  timezone: z.string().trim().max(100).refine(isTimeZone, 'an IANA time zone'),
  isEnabled: z.boolean(),
};

const CreateReport = z.object({
  name: fields.name,
  description: fields.description.optional(),
  type: fields.type.optional(),
  format: fields.format.optional(),
  scopeType: fields.scopeType.optional(),
  scopeId: fields.scopeId.optional(),
  sections: fields.sections.optional(),
  filters: fields.filters.optional(),
  scheduleCron: fields.scheduleCron.optional(),
  timezone: fields.timezone.optional(),
  isEnabled: fields.isEnabled.optional(),
}).strict();

const UpdateReport = CreateReport.partial().strict();

export type ReportCreateInput = z.infer<typeof CreateReport>;
export type ReportUpdateInput = z.infer<typeof UpdateReport>;

export type Validation<T> = { ok: true; data: T } | { ok: false; code: string; message: string };

/** The stable code of a refusal: by its first field. */
function codeOf(error: z.ZodError): { code: string; message: string } {
  const issue = error.issues[0];
  const field = String(issue?.path?.[0] ?? '');
  const code = field === 'scheduleCron' ? 'invalidCron'
    : field === 'timezone' ? 'invalidTimezone'
      : field === 'filters' ? 'invalidOptions'
        : field === 'scopeId' ? 'invalidScope'
          : 'invalidRequest';
  // The message names the field and the rule, never the value received.
  const message = field ? `${field}: ${issue?.message ?? 'invalid'}` : (issue?.message ?? 'Invalid report');
  return { code, message };
}

/** The scope of a definition: a group or a device needs its id; the tenant has none. */
function scopeOf<T extends { scopeType?: string; scopeId?: number | null }>(data: T, previous?: { scopeType: string; scopeId: number | null }): Validation<T> {
  if (data.scopeType === undefined && data.scopeId === undefined) return { ok: true, data };
  const scopeType = data.scopeType ?? previous?.scopeType ?? 'tenant';
  const scopeId = data.scopeId !== undefined ? data.scopeId : (data.scopeType !== undefined ? null : previous?.scopeId ?? null);
  if (scopeType === 'tenant') return { ok: true, data: { ...data, scopeType, scopeId: null } };
  if (scopeId === null) return { ok: false, code: 'invalidScope', message: `scopeId: required for the scope ${scopeType}` };
  return { ok: true, data: { ...data, scopeType, scopeId } };
}

export function parseReportCreate(body: unknown): Validation<ReportCreateInput> {
  const r = CreateReport.safeParse(body ?? {});
  if (!r.success) return { ok: false, ...codeOf(r.error) };
  return scopeOf(r.data);
}

/** A change: `previous` is the stored scope, which a change of only one of
 *  scopeType or scopeId is checked against. */
export function parseReportUpdate(body: unknown, previous: { scopeType: string; scopeId: number | null }): Validation<ReportUpdateInput> {
  const r = UpdateReport.safeParse(body ?? {});
  if (!r.success) return { ok: false, ...codeOf(r.error) };
  return scopeOf(r.data, previous);
}

/** The fields a change names (the audit lists them, never their values). */
export function changedFields(input: ReportUpdateInput): string[] {
  return Object.keys(input).filter((k) => (input as Record<string, unknown>)[k] !== undefined).sort();
}
