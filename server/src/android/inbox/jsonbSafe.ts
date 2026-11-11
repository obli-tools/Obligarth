// JSON text that PostgreSQL's jsonb accepts (review F024). jsonb refuses the escape \u0000 and a lone UTF-16
// surrogate ("unsupported Unicode escape sequence"); a single such character in a field a device reports (an
// application label) would make the insertion of the whole batch fail, again at every redelivery. Both are removed
// from the strings, keys included. Pure, erasable TypeScript (unit tests under node --test).

const NUL_OR_LONE_SURROGATE = /\u0000|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

export function jsonbSafeString(s: string): string {
  return s.replace(NUL_OR_LONE_SURROGATE, '');
}

function clean(v: unknown): unknown {
  if (typeof v === 'string') return jsonbSafeString(v);
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof (v as { toJSON?: unknown }).toJSON === 'function') return clean((v as { toJSON(): unknown }).toJSON());
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[jsonbSafeString(k)] = clean(x);
    return out;
  }
  return v;
}

/** JSON.stringify of `v` whose text jsonb accepts. */
export function jsonbStringify(v: unknown): string {
  return JSON.stringify(clean(v));
}

/**
 * Is a refused write a refusal of the row's data itself (it would be refused again at every redelivery), not a
 * passing failure (a lock timeout, a serialization conflict, a connection lost)? SQLSTATE class 22 (data exception:
 * an invalid jsonb text, a value too long), class 23 but a uniqueness conflict (a check, a not null), and 54000
 * (program limit: a row or a jsonb too large). Only those rows are reduced and acknowledged.
 */
export function isDataRefusal(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code !== 'string' || code.length !== 5) return false;
  if (code.startsWith('22')) return true;
  if (code.startsWith('23')) return code !== '23505' && code !== '23P01';
  return code === '54000';
}
