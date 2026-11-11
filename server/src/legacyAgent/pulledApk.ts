import type { ApkManifest } from './apkManifest';
import type { ApkSigners } from './apkSigner';

// =============================================================================
// The verdict on an APK a device sent back (app.pull, review F028), from what
// the server read in the file itself: its manifest (apkManifest.ts) and its
// signing block (apkSigner.ts). What the device declared is only compared,
// never stored:
//   - the package of the manifest is the one of the command;
//   - its versionCode is the one declared;
//   - signed by v2/v3: one signer per block. When v2 and v3 differ (an app
//     whose key was rotated: v2 keeps the original key, v3 carries the new
//     one) the v2 signer is the one kept: the agent reads the signers with
//     PackageManager.GET_SIGNATURES, which reports the original certificate of
//     a rotated lineage, and compares the one app.install announces to it. A
//     signer declared, or held by the tenant for that package, may be either;
//   - signed by v1 alone (old apps): no signer kept (the server cannot read
//     it; Android checks it at install, and an update must keep the signer of
//     the installed app);
//   - a package of the same name the tenant already holds CONFIRMED with a
//     known signer names this one (a device never brings another key into the
//     catalogue).
// It does not prove that the first package of a name is the genuine app: a
// device that signs its own APK of a name the tenant does not hold yet passes;
// so a pulled package is "to confirm" (review F028, round 3): no app.install
// of it until a human confirms it (routes.ts, POST /packages/:id/confirm).
// No database import: the unit tests load this module alone.
// =============================================================================

export interface PulledDeclared { versionCode: number; signerSha256?: string | null }

export type PulledVerdict =
  | { ok: true; versionCode: number; versionName: string | null; signerSha256: string | null }
  | { ok: false; error: string };

export interface FileSigners {
  /** The signer kept: v2's when there is a v2 block (the original key of a rotation), else v3's. */
  signer: string;
  /** Every signer the blocks name (the old key of a rotation included). */
  names: string[];
}

/** The signers of a file: null without a v2/v3 block; 'several' when a block names more than one signer. */
export function fileSigners(s: ApkSigners): FileSigners | null | 'several' {
  const blocks = [s.v2, s.v3].filter((b): b is string[] => b !== null);
  if (blocks.length === 0) return null;
  // A v3 block may name one signer per range of platform versions: the same certificate is still one signer.
  if (!blocks.every((b) => b.length > 0 && new Set(b).size === 1)) return 'several';
  const signer = (s.v2 ?? s.v3 as string[])[0];
  return { signer, names: [...new Set(blocks.map((b) => b[0]))] };
}

/** The one signer kept for a file (the original key after a rotation); null without a v2/v3 block; 'several' otherwise. */
export function singleSigner(s: ApkSigners): string | null | 'several' {
  const f = fileSigners(s);
  return f === null || f === 'several' ? f : f.signer;
}

const norm = (h: string | null | undefined): string => String(h ?? '').replace(/:/g, '').trim().toLowerCase();

export function pulledVerdict(manifest: ApkManifest, signers: ApkSigners, packageName: string, declared: PulledDeclared,
  heldSigners: string[]): PulledVerdict {
  if (manifest.packageName !== packageName) return { ok: false, error: 'The package of the file is not the one asked' };
  if (manifest.versionCode !== declared.versionCode) return { ok: false, error: 'The versionCode of the file is not the one declared' };
  const f = fileSigners(signers);
  if (f === 'several') return { ok: false, error: 'The file is signed by several certificates' };
  if (f !== null && declared.signerSha256 && !f.names.includes(norm(declared.signerSha256))) {
    return { ok: false, error: 'The signer of the file is not the one declared' };
  }
  const known = [...new Set(heldSigners.map(norm).filter(Boolean))];
  if (known.length > 0 && (f === null || !f.names.some((n) => known.includes(n)))) {
    return { ok: false, error: 'The tenant holds this package signed by another certificate' };
  }
  return { ok: true, versionCode: manifest.versionCode, versionName: manifest.versionName, signerSha256: f === null ? null : f.signer };
}

/** An upload from the console: the signer declared must be one the file names, when its v2/v3 block is readable. */
export function declaredSignerHolds(signers: ApkSigners, declared: string): boolean {
  const f = fileSigners(signers);
  if (f === null) return true; // v1 alone: not readable here, the agent checks it at install
  if (f === 'several') return false; // the agent refuses an APK with several signers when one is declared
  return f.names.includes(norm(declared));
}
