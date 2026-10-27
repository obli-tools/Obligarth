// =============================================================================
// Values of the rule language shared by the SQL compiler (compile.ts) and the TypeScript evaluator (evaluate.ts),
// so that both compare exactly the same thing (P0-5 §2): the ASCII folding of the texts, the escape of a LIKE
// pattern, the thresholds of the storage in bytes and of the relative dates. Pure.
// =============================================================================

/** Folds the ASCII letters A-Z to a-z, nothing else: the same in PostgreSQL (FOLD_SQL, translate) whatever the
 *  collation of the database, unlike lower() and toLowerCase(). */
export const asciiFold = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

/** The SQL of asciiFold around an expression of the code (never a value). */
export const FOLD_SQL_PREFIX = 'translate(';
export const FOLD_SQL_SUFFIX = ", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')";

/** Escapes a text for a LIKE pattern (PostgreSQL's default escape character, the backslash). */
export const likeEscape = (s: string): string => s.replace(/[\\%_]/g, (c) => `\\${c}`);

/** The threshold in bytes of a capacity in GB (10^9 bytes, at most 3 decimals, checked by validateRule): an integer,
 *  so that the comparison is exact on both sides. */
export const storageBytes = (gb: number): number => Math.round(gb * 1_000_000) * 1_000;

/** The instant `days` days before `now` (older_than_days: before it; within_days: at it or after). */
export const daysBefore = (now: Date, days: number): Date => new Date(now.getTime() - days * 86_400_000);
