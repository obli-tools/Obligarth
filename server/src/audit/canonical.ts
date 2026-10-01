// Canonical serialisation of an audit body (docs: audit-durci §3.2). No
// import: loaded as is by the unit tests and the offline verification tool.
//
// The canonical form serves readability and reproducibility, not the
// verification: a verifier never re-serialises a body, it hashes the stored
// text. The bodies of the entries chained by the migration are in jsonb text
// form and verify the same way.

/** RFC 8785 subset: sorted keys (UTF-16 code units), no whitespace,
 *  JSON.stringify for scalars, undefined properties dropped, non-finite
 *  numbers refused. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new TypeError('audit: non-finite number');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined ? 'null' : canonicalJson(x))).join(',')}]`;
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`;
  }
  throw new TypeError(`audit: unsupported value of type ${typeof v}`);
}
