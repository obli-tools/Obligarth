/**
 * Obligarth bench station — the fingerprints pinned in the binary (lot BANC §5.1, §5.8, §6.4).
 *
 * ┌─ THE AGENT'S SIGNER: READ AT BUILD TIME, NEVER WRITTEN HERE ─────────────┐
 * │ `AGENT_SIGNER_SHA256` is the SHA-256 of the certificate of               │
 * │ obligarth-agent.jks, the same value the agent's release pins             │
 * │ (`obligarth.agent.pinnedSigners`). build.mjs reads it from                │
 * │ agent-android/local.properties (or OBLIGARTH_BENCH_AGENT_SIGNER) and     │
 * │ injects it with `define`; a production build without it REFUSES to      │
 * │ build. Nothing in this repository invents it. An APK whose signer is not │
 * │ this one is refused, whatever the server announces.                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE CODE-SIGNING CERTIFICATE OF THE OBLI* SUITE ────────────────────────┐
 * │ The station's exe and MSI are signed with the suite's certificate        │
 * │ (Certum SimplySign, cloud, unlocked by TOTP — outside every repository). │
 * │ The self-update (selfUpdate.ts) installs an MSI only when its            │
 * │ Authenticode signature is Valid AND its certificate's issuer and SHA-256 │
 * │ are in this list — the running exe must itself be signed by one of them. │
 * │ Read on 30/10/2026 from a signed Obli* installer (Get-AuthenticodeSig-    │
 * │ nature), not invented. `next` receives the renewed certificate BEFORE    │
 * │ the current one expires, in a release signed with the current one.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

declare const __AGENT_SIGNER_SHA256__: string | undefined;

/** The agent's signer (lower-case hex), or null in a build that did not inject it (a development run). */
export function agentSignerPin(): string | null {
  const v = typeof __AGENT_SIGNER_SHA256__ === 'string' ? __AGENT_SIGNER_SHA256__ : (process.env.OBLIGARTH_BENCH_AGENT_SIGNER_DEV ?? '');
  const s = v.trim().toLowerCase().replace(/:/g, '');
  return /^[0-9a-f]{64}$/.test(s) ? s : null;
}

export interface CodeSigningPin {
  /** The issuer's distinguished name, as Get-AuthenticodeSignature prints it. */
  issuer: string;
  /** SHA-256 of the certificate (upper-case hex, GetCertHashString('SHA256')). */
  sha256: string;
  /** Free note: validity. */
  note: string;
}

export const CODE_SIGNING_PINS: { current: CodeSigningPin[]; next: CodeSigningPin[] } = {
  current: [
    {
      issuer: 'CN=Certum Code Signing 2021 CA, O=Asseco Data Systems S.A., C=PL',
      sha256: '9487D34D050156CA4BD96AF5BE888B1A0124F2A238607C6D8BDC989ECF797AFF',
      note: 'Obli* suite, valid until 2027-04-02',
    },
  ],
  next: [],
};

export function codeSigningAdmitted(issuer: string, sha256: string, pins = CODE_SIGNING_PINS): boolean {
  const i = issuer.trim();
  const h = sha256.trim().toUpperCase();
  return [...pins.current, ...pins.next].some((p) => p.issuer === i && p.sha256 === h);
}
