// ── Pinned Google hardware attestation root KEYS (device-bound 2FA, §4.3) ──
//
// docs/mobile/device-bound-2fa.md §4.3 step 3: the last certificate of an
// Android key attestation chain must be self-signed and its public key
// (sha256 of the SubjectPublicKeyInfo DER) must be one of these. Keys are
// pinned, not certificates: Google re-issues its roots with the same key
// (the RSA root exists as 2016, 2019 and 2022 certificates, all accepted).
//
// Never downloaded at run time (offline installs must work). Provenance of
// the values below — fetched on 2026-09-26 and cross-checked byte for byte:
//   1. https://android.googleapis.com/attestation/root (JSON array of PEM)
//   2. https://developer.android.com/privacy-and-security/security-key-attestation
//      ("Root certificates" section)
//   3. https://github.com/android/keyattestation (roots.json)
// All three sources carried the same two certificates:
//   - RSA 4096, subject serialNumber=f92009e853b6b045, serial f1c172a699eaf51d,
//     2022-03-20 → 2042-03-15, certificate SHA-256
//     cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc
//   - ECDSA P-384, CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US,
//     serial 84a9d0297b0eb58ae7ff0e80de760605, 2025-07-17 → 2035-07-15
//     (signs new chains from 2026-02-01), certificate SHA-256
//     6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0
//
// `spkiB64` is the public key itself (public data), kept so that the pin can
// be recomputed: attestation.test.ts asserts sha256(spkiB64) === spkiSha256
// and that real Google test chains (android/keyattestation testdata) chain
// to these pins. To add a future root: fetch it from source 1, check it
// against source 2, append an entry — never remove the RSA key while
// factory-provisioned phones still chain to it.

export interface PinnedRoot {
  name: string;
  /** hex sha256 of the SubjectPublicKeyInfo DER. */
  spkiSha256: string;
  /** SubjectPublicKeyInfo DER, base64. */
  spkiB64: string;
}

export const GOOGLE_ATTESTATION_ROOTS: ReadonlyArray<PinnedRoot> = Object.freeze([
  {
    name: 'Google Hardware Attestation Root (RSA 4096, serialNumber=f92009e853b6b045)',
    spkiSha256: 'feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae',
    spkiB64:
      'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2'
      + 'tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3'
      + 'kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPl'
      + 'XTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxn'
      + 'K/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiM'
      + 'm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR'
      + '/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==',
  },
  {
    name: 'Key Attestation CA1 (ECDSA P-384, Google LLC)',
    spkiSha256: '3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec',
    spkiB64:
      'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikN'
      + 'MHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr',
  },
]);

/** The production pin set (hex sha256 of the root SPKI DER). */
export const PINNED_ROOT_SPKI_SHA256: ReadonlyArray<string> = Object.freeze(GOOGLE_ATTESTATION_ROOTS.map((r) => r.spkiSha256));
