// =============================================================================
// Compatibility of versions between the brain and apple-edge (docs:
// integration-apple-edge §5.5, I15; apple-edge §5.10). apple-edge announces
// its version in X-Apple-Edge-Version (its build's main.version, 'dev'
// outside a release); the brain's is server/package.json; both images share
// OBLIGARTH_VERSION and the upgrade order is migrations, apple-edge, then the
// brain. Rule: same major version, and apple-edge's minor version equal to
// the brain's or one above (a brain newer than its apple-edge is refused).
// 'dev' only with NODE_ENV=development or APPLE_EDGE_ALLOW_DEV_VERSION=true.
// The API expected is v1 (the path). Pure functions: the unit tests run
// under node --test.
// =============================================================================

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
}

/** 'X.Y.Z' (optional 'v', optional pre-release or build suffix) → numbers; 'dev' → 'dev'; anything else → null. */
export function parseVersion(text: string | null | undefined): ParsedVersion | 'dev' | null {
  const t = String(text ?? '').trim();
  if (t === 'dev') return 'dev';
  const m = /^v?(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(?:[-+][0-9A-Za-z.-]{1,64})?$/.exec(t);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

export type CompatReason = 'unparsable' | 'dev_refused' | 'major_differs' | 'edge_older' | 'edge_too_new';

export type CompatVerdict = { ok: true } | { ok: false; reason: CompatReason };

/** Is apple-edge `edge` compatible with the brain `brain`? */
export function versionCompatible(edge: string | null | undefined, brain: string, o: { allowDev: boolean }): CompatVerdict {
  const e = parseVersion(edge);
  const b = parseVersion(brain);
  if (e === null || b === null) return { ok: false, reason: 'unparsable' };
  if (e === 'dev' || b === 'dev') return o.allowDev ? { ok: true } : { ok: false, reason: 'dev_refused' };
  if (e.major !== b.major) return { ok: false, reason: 'major_differs' };
  if (e.minor < b.minor) return { ok: false, reason: 'edge_older' };
  if (e.minor > b.minor + 1) return { ok: false, reason: 'edge_too_new' };
  return { ok: true };
}

/** An English sentence for the operator (fatal log, alert). */
export function describeIncompatibility(edge: string | null | undefined, brain: string, reason: CompatReason): string {
  const shown = /^[0-9A-Za-z.+-]{1,64}$/.test(String(edge ?? '')) ? String(edge) : '(unreadable)';
  switch (reason) {
    case 'dev_refused':
      return `apple-edge announces the development version "dev": accepted only with NODE_ENV=development or APPLE_EDGE_ALLOW_DEV_VERSION=true (brain ${brain})`;
    case 'major_differs':
      return `apple-edge ${shown} and the brain ${brain} differ in major version: deploy the same OBLIGARTH_VERSION for both`;
    case 'edge_older':
      return `apple-edge ${shown} is older than the brain ${brain}: upgrade apple-edge first (order: migrations, apple-edge, brain)`;
    case 'edge_too_new':
      return `apple-edge ${shown} is more than one minor version ahead of the brain ${brain}: upgrade the brain`;
    default:
      return `apple-edge announces a version the brain cannot read (${shown}; brain ${brain})`;
  }
}
