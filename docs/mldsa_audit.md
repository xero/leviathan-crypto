<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ML-DSA Cryptographic Audit

Audit of the `leviathan-crypto` WebAssembly ML-DSA implementation (AssemblyScript) against FIPS 204, covering all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) and verified against NIST ACVP vectors.

> ### Table of Contents
> - [HashML-DSA Prehashed-Input Surface](#hashml-dsa-prehashed-input-surface)
> - [Sign_internal Rejection-Path Coverage](#sign_internal-rejection-path-coverage)

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

## Sign_internal Rejection-Path Coverage

FIPS 204 §6.2 Algorithm 7 `ML-DSA.Sign_internal` drives a rejection-sampling loop with four reject conditions: `‖z‖∞ ≥ γ₁ − β`, `‖r₀‖∞ ≥ γ₂ − β`, hint popcount `‖h‖₁ > ω`, and (ML-DSA-44 only) `‖ct₀‖∞ ≥ γ₂`. Random AFT sampling triggers these branches too rarely to give meaningful correctness assurance; ACVP ML-DSA JSON Specification §6.1.2 supplies KATs that exercise each path deterministically.

**Audit checklist:**

- [ ] Rejection-path coverage. Every reachable reject branch on every parameter set is exercised by at least one KAT vector in `test/vectors/mldsa_siggen_kats.ts`. Source: ACVP ML-DSA JSON Specification §6.1.2 Table 1 (5 vectors per parameter set, 15 total). Coverage: `test/unit/mldsa/mldsa_siggen_kats.test.ts` records labelled `t1-seed-*`.
- [ ] High-rejection-count coverage. At least two KAT vectors per parameter set force `‖rejection-count‖ ≥ 32` (the ACVP §6.1.2 SHALL threshold) to confirm the signing loop tolerates heavy retry without early abort. Source: ACVP ML-DSA JSON Specification §6.1.2 Table 2. Recorded counts range 64-100 (ML-DSA-44 has 2 vectors at 77 and 100; ML-DSA-65 has 5 vectors at 64-73; ML-DSA-87 has 5 vectors at 64-69). Coverage: `test/unit/mldsa/mldsa_siggen_kats.test.ts` records labelled `t2-rej-*`.
- [ ] Per-KAT byte equivalence. For every vector, `KeyGen(seed)` reproduces `(pk, sk)` whose `SHA2-256(pk ‖ sk)` matches the spec; `Sign_internal(sk, M′, rnd = 0³²)` produces σ whose `SHA2-256(σ)` matches the spec. The spec stores hashes rather than full bytes to bound vector-file size; the test reconstructs both halves and compares hashes.
- [ ] Vector provenance. ML-DSA-65 and ML-DSA-87 Table 1 entries reflect the Nov 19 2025 ACVP regeneration (`usnistgov/ACVP@f66d187`, "Fixes ML-DSA tables with test cases that cover what they are intended to cover") that superseded the originally published vectors flagged on PQC-Forum. The ML-DSA-44 set was correct in the original specification and is unchanged.
- [ ] Spec authority. Vectors are transcribed verbatim from `usnistgov/ACVP/src/ml-dsa/sections/04-testtypes.adoc` (the asciidoc source for the live spec at `https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html`); the SHA256SUMS entry pins the vector file against further drift.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [mldsa](./mldsa.md) | ML-DSA public API reference, including the prehashed surface |
| [audits](./audits.md) | Project audit index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |