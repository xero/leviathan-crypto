<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ML-DSA Cryptographic Audit

Audit of the `leviathan-crypto` WebAssembly ML-DSA implementation (AssemblyScript) against FIPS 204, covering all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) and verified against NIST ACVP vectors.

> ### Table of Contents
> - [HashML-DSA Prehashed-Input Surface](#hashml-dsa-prehashed-input-surface)

| Meta | Description |
| --- | --- |
| Target: | `leviathan-crypto` WebAssembly implementation (AssemblyScript) |
| Spec: | FIPS 204 (ML-DSA Standard, August 2024) |
| Parameter sets: | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| Test vectors: | NIST ACVP (ML-DSA-keyGen-FIPS204, ML-DSA-sigGen-FIPS204, ML-DSA-sigVer-FIPS204) |

---

## HashML-DSA Prehashed-Input Surface

`MlDsaBase` exposes four methods that accept a caller-supplied prehash digest in place of the raw message: `signHashPrehashed`, `signHashPrehashedDeterministic`, `signHashPrehashedDerand`, and `verifyHashPrehashed`. They share the post-PH path with the non-prehashed `signHash` family via two internal helpers, `signWithPrehash` (in `src/ts/mldsa/sign.ts`) and `verifyWithPrehash` (in `src/ts/mldsa/verify.ts`).

**Audit checklist:**

- [ ] `signHashPrehashed` validates digest size against `digestSize(ph)` before signing; mismatch throws `SigningError('sig-malformed-input')`.
- [ ] `signHashPrehashedDeterministic` validates digest size and uses `rnd ← 0³²` per FIPS 204 §3.4 (a fresh `new Uint8Array(32)` is already zeroed; no manual fill needed).
- [ ] `signHashPrehashedDerand` validates both `rnd.length === 32` and `digest.length === digestSize(ph)`; passes caller-supplied `rnd` to `signWithPrehash` without modification.
- [ ] `signHashPrehashed` wipes the hedged-`rnd` Uint8Array in a `finally` block; deterministic and derand variants do not own `rnd` (zeros / caller-supplied) and so do not wipe.
- [ ] `verifyHashPrehashed` returns `false` (no throw) on:
  - wrong-length `vk`,
  - wrong-length `sig`,
  - wrong-size `digest`,
  - non-`Uint8Array` `digest`.
- [ ] `verifyHashPrehashed` throws `RangeError` only on caller-side contract violations (`ctx.length > 255`, unsupported `ph`), mirroring the §3.6.2 posture of `verifyHash`.
- [ ] All four methods call `_assertNotOwned('sha3')` and `_assertNotOwned('mldsa')`, plus `_assertNotOwned('sha2')` when `algoNeedsSha2(ph)` is true (via `_assertHashPrereqs`).
- [ ] `_assertHashPrereqs` validates `ph` (via `digestSize(ph)`) before any sha2-initialization check, so widened-type callers (e.g. parsing vector files via `as PreHashAlgorithm`) hit the canonical "unsupported HashML-DSA pre-hash" `RangeError` rather than a downstream sha2-not-initialized error.
- [ ] `signWithPrehash` builds M' = `0x01 ‖ |ctx| ‖ ctx ‖ OID(algo) ‖ prehash` via `constructMPrimeHash` and wipes M' in `finally`; it does NOT compute the prehash (caller supplies it) and does NOT wipe `prehash` or `rnd` (caller owns).
- [ ] `verifyWithPrehash` mirrors `signWithPrehash`'s contract on the verify side; returns whatever `mldsaVerifyInternal` returns and wipes M' in `finally`.
- [ ] The refactor preserves byte-identical output for the existing `signHash` / `signHashDeterministic` / `signHashDerand` / `verifyHash` methods. Coverage: `test/unit/mldsa/hashvariant.test.ts` (Gates 8/9/10 across 3 parameter sets × 12 pre-hash functions × 90 ACVP sigGen vectors + 90 ACVP sigVer vectors) all pass unchanged.
- [ ] Equivalence with the non-prehashed family is asserted in `test/unit/mldsa/mldsa-prehashed.test.ts`: `signHashDeterministic(sk, M, ph, ctx)` and `signHashPrehashedDeterministic(sk, Hash(M, ph), ph, ctx)` produce byte-identical signatures across all 36 (paramSet × ph) tuples; cross-API verify (sign via prehashed → verify via non-prehashed and vice versa) succeeds.
- [ ] ACVP sigGen vectors with `preHash=preHash` are re-oracled through `signHashPrehashedDeterministic` / `signHashPrehashedDerand` (with externally-computed PH) and produce byte-identical signatures to the canonical vector.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [mldsa](./mldsa.md) | ML-DSA public API reference, including the prehashed surface |
| [audits](./audits.md) | Project audit index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |