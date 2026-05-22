# Implementation Plan: ML-DSA Rejection-Path KAT Vectors

> [!NOTE]
> Plan for adding ACVP ML-DSA JSON Specification §6.1.2 Table 1 (rejection-path KATs) and Table 2 (high-rejection-count KATs) as hand-rolled test vectors. Companion to `./mldsa-corner-case-blocker.md`. Designed to be picked up cold in a fresh session.

---

> ### Table of Contents
> - [Goal](#goal)
> - [Why we are doing this here](#why-we-are-doing-this-here)
> - [Data sources](#data-sources)
> - [Implementation steps](#implementation-steps)
> - [Open questions to resolve before coding](#open-questions-to-resolve-before-coding)
> - [Definition of done](#definition-of-done)
> - [Risks](#risks)
> - [Out of scope](#out-of-scope)

---

## Goal

Add coverage for the two ML-DSA `Sign_internal` correctness assurances that random AFT (Algorithm Functional Test) sampling cannot reliably trigger:

**Rejection-path coverage.** Vectors that exercise each of the four rejection conditions in FIPS 204 (Module-Lattice-Based Digital Signature Standard) §6.2, Algorithm 7: `‖z‖∞ >= γ₁ - β`, `‖r₀‖∞ >= γ₂ - β`, hint-count `‖h‖₁ > ω`, and `‖ct₀‖∞ >= γ₂`. The fourth condition only fires on ML-DSA-44.

**High-rejection-count coverage.** Vectors that force at least 32 loop iterations before producing a valid candidate. Catches implementations that abort early on retry.

Both assurances are required by ACVP for live certification but absent from the public github JSON corpus that `test/vectors/mldsa_siggen.ts` derives from. The plan is to consume the KATs published directly in the spec.

---

## Why we are doing this here

The verifier-side dispatch hook the original TODO describes will likely never carry value, because the ACVP-Server pool infrastructure that produces non-`none` `cornerCase` records is NIST-internal. The github JSON drop at v1.1.0.42 ships zero corner-case records, and the v1.1.0.42 release notes (relative to v1.1.0.41) describe reducing pool generation, not opening it up. Waiting for the JSON corpus to gain corner-case records is waiting for something that probably will not happen.

The ACVP spec already published the KATs directly (Table 1 and Table 2 in the §6.1.2 ML-DSA SigGen Test Types section). Pulling those tables into leviathan's vector corpus directly delivers the same coverage without depending on upstream JSON publication policy. See `./mldsa-corner-case-blocker.md` for the full rationale.

---

## Data sources

Two authoritative sources, both NIST. Verify each independently before encoding any values.

**Spec text (primary).** ACVP ML-DSA JSON Specification §6.1.2, ML-DSA SigGen Test Types. Tables 1 and 2 give per-parameter-set KATs in the format `(seed, SHA2-256(pk || sk), M', SHA2-256(sig))`. Available at:

- HTML: `https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html`
- Plain text: `https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.txt`
- Asciidoc source: `github.com/usnistgov/ACVP` repo, `src/ml-dsa/sections/06-ml-dsa-siggen-test-vectors.adoc`

**PQC-Forum correction thread (secondary, verifies primary).** On 2025-11-03 Filippo Valsorda reported that the originally published Table 1 vectors did not actually trigger every rejection outcome on ML-DSA-65 and ML-DSA-87. Chris Celi (NIST) confirmed the gap on 2025-11-06 and posted corrected vectors on 2025-11-13. Available at:

- `https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/6U34L4ISYzk`

The PQC-Forum corrections may or may not have made it into the live spec page by the time this work starts. Step 1 of the implementation is to verify which version is current.

The KATs use SHA2-256 hashes for both the keypair (`pk || sk`) and the signature, not full bytes. This is the spec's chosen encoding to save space. It also conveniently sidesteps the question of vector-file size for ML-DSA-87 signatures (4627 bytes each).

---

## Implementation steps

Ordered for a fresh session. Steps 1-3 are research; 4-9 are implementation; 10-12 are finalization.

**1. Verify the spec version.** Fetch `https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html` and confirm whether Tables 1 and 2 contain the Valsorda-flagged broken vectors or the corrected ones. Method: each parameter set in the corrected Table 1 should show all reachable rejection paths exercised at least once across its KATs (z, r₀, h, and on ML-DSA-44 also ct₀). If the live spec still shows the broken vectors, use the corrected vectors from the PQC-Forum thread instead and cite both URLs in the vector file header.

**2. Cross-check against ACVP-Server pool seeds (optional sanity).** The ACVP-Server source at `gen-val/src/oracle/src/NIST.CVP.ACVTS.Libraries.Oracle.Abstractions/ParameterTypes/ML-DSA/MLDSASignatureParameters.cs` defines the same generation parameters that produced the spec tables. The seeds themselves are not in the github source (they live in NIST-internal pools), so this step is only useful for spot-checking that the spec's `M'` length and structure match what the pool generators target.

**3. Extract KATs into a working list.** For each parameter set in {ML-DSA-44, ML-DSA-65, ML-DSA-87}:

- Table 1 entries: one row per rejection path. ML-DSA-44 has four rows (one each for z, r₀, h, ct₀ rejection). ML-DSA-65 and ML-DSA-87 have three rows each (ct₀ unreachable).
- Table 2 entries: at least 5 rows per parameter set per the spec SHALL, with rejection counts in the 32-100 range. Note rejection count per row if the spec gives it.

Each row carries: `seed` (32 bytes hex), `keypairHash` (32 bytes hex of SHA2-256(pk || sk)), `mPrime` (variable-length hex), `sigHash` (32 bytes hex of SHA2-256(sig)). Optionally also: a human label like "z-rejection" or "rej=64" for assertion text.

**4. Create the vector file.** Path: `test/vectors/mldsa_siggen_kats.ts`. Follow the existing `mldsa_siggen.ts` skeleton (ASCII banner, JSDoc, source citation, type, exported arrays). Schema:

```typescript
export interface SigGenKatVector {
    paramSet:    'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
    label:       string;                // 'z-rejection', 'r0-rejection', 'h-rejection', 'ct0-rejection', 'rejection-count-64', etc.
    table:       1 | 2;                 // ACVP spec table number
    seed:        string;                // 32-byte hex, ML-DSA.KeyGen input ξ
    keypairHash: string;                // 32-byte hex, SHA2-256(pk || sk)
    mPrime:      string;                // variable-length hex, ML-DSA.Sign_internal input M'
    sigHash:     string;                // 32-byte hex, SHA2-256(σ)
}

export const ml_dsa_44_siggen_kats: SigGenKatVector[];
export const ml_dsa_65_siggen_kats: SigGenKatVector[];
export const ml_dsa_87_siggen_kats: SigGenKatVector[];
```

Header must cite both the spec URL and (if used) the PQC-Forum URL. Mark this as the authoritative source per AGENTS.md ground rule 1. The hashes are immutable per ground rule 2.

**5. Create the test file.** Path: `test/unit/mldsa/mldsa_siggen_kats.test.ts`. Mirrors `mldsa.test.ts` patterns. Per-record assertion:

```typescript
for (const v of ml_dsa_44_siggen_kats) {
    it(`${v.paramSet}, table ${v.table}, ${v.label}`, () => {
        const ctx = new MlDsa44();
        try {
            const seed = hexToBytes(v.seed);
            const { pk, sk } = ctx.keygenDerand(seed);

            const concat = new Uint8Array(pk.length + sk.length);
            concat.set(pk, 0);
            concat.set(sk, pk.length);
            const kpHashActual = sha256(concat);
            expect(bytesToHex(kpHashActual)).toBe(v.keypairHash);

            const mPrime = hexToBytes(v.mPrime);
            const rnd = new Uint8Array(32); // deterministic, rnd = 0^32
            const sig = mldsaSignInternal(ctx.mx, ctx.sx, MLDSA44, sk, mPrime, rnd);
            const sigHashActual = sha256(sig);
            expect(bytesToHex(sigHashActual)).toBe(v.sigHash);
        } finally {
            ctx.dispose();
        }
    });
}
```

Two surfaces to confirm exist (Open Question 1 below): `MlDsaBase.mx`/`sx` access and the `mldsaSignInternal` export reachability from a test file. If either is gated for internal use only, add a thin test-only export or use a different sign entry point.

Gate annotation: ML-DSA already has a family gate in `mldsa.test.ts` (Gate 0, init system wiring). This new file does not need a separate gate; it depends on the same WASM module and primitive.

**6. SHA2-256 wiring in tests.** The KAT comparison needs a SHA2-256 primitive. Check whether existing ML-DSA tests already import `sha2`; if not, add `sha2` to the `init({ mldsa, sha3, sha2 })` call in `beforeAll`. Use `bytesToHex(sha256(input))` for the comparison rather than encoding the keypair string and hashing the encoding; the spec's hash is over raw concatenated bytes.

**7. CI wiring.** Add the new test file to the `mldsa` group in `scripts/lib/test-groups.ts`. No new workflow file is needed because the existing `unit-mldsa.yml` invokes `bun scripts/test.ts unit:group mldsa` which reads the group at run time. Run `bun pin` after.

**8. Documentation updates.**

Please read the prose-style skill before writing docs.

- `docs/mldsa.md`: add a Test Coverage subsection noting that the test corpus exercises every reachable rejection path on every parameter set and includes high-rejection-count cases up to N iterations, citing ACVP spec §6.1.2.
- `docs/mldsa_audit.md`: add a row or checkbox covering rejection-path KAT coverage and another for high-rejection-count coverage.
- `docs/test-suite.md`: update Test Counts table and add the new file row to the Unit Tests table. Test count comes from the `bun check` output.
- `docs/vector_audit.md`: add a row for the new vector file listing the source and the SHA256SUMS entry.
- `test/vectors/SHA256SUMS`: regenerate to include the new vector file (see existing `scripts/` for how this is maintained).

**9. Lint and full test.** `bun fix` then `bun check`. Capture output. Both must pass.

**10. Per-record diagnostic.** When a KAT fails, the test name should make the failure self-explanatory (`ML-DSA-65, table 1, r0-rejection mismatch: expected sigHash 4f3a..., got a829...`). This is the diagnostic value the original `cornerCase` TODO hook would have delivered, applied directly to the test names instead of to JSON-driven dispatch.

**11. Verify rejection-path coverage independently.** Add a debug-only check (gated behind an env var or scripts/debug helper, not committed as a test): instrument the WASM `Sign_internal` to count rejections per branch and confirm that running the KAT corpus actually triggers each branch at least once. This validates that the spec tables (corrected if needed) actually exercise what they claim. Document the result in `docs/mldsa_audit.md`.

**12. Commit.** Single commit, descriptive message referencing ACVP spec §6.1.2 and (if applicable) the PQC-Forum correction thread.

---

## Open questions to resolve before coding

**1. Internal-interface sign access from a test file.** `mldsaSignInternal` is exported from `src/ts/mldsa/sign.ts` and used by the high-level classes via `this.mx`/`this.sx`. Confirm whether a test file can reach these (either through a public accessor on `MlDsaBase` or via direct import). If neither path works without API changes, decide between: (a) adding a test-only accessor, (b) calling through `signDerand` with an externally-constructed `M'` that round-trips to the same `Sign_internal` call (requires re-deriving the ctx wrapping in reverse, which is fragile), or (c) calling the WASM export directly. Option (a) is cleanest.

**2. Spec corrections status.** Whether the live spec at `pages.nist.gov` has been updated with Celi's 2025-11-13 corrections, or still ships the broken originals. Implementation step 1 must verify this before any KAT bytes are encoded. If the spec is still broken and we use the PQC-Forum corrections, the vector file header must cite both sources.

**3. Table 2 row count and structure.** The spec says "at least 5 tests" with "at least 32 rejections" per parameter set. The exact row layout in Table 2 needs reading. Rows might include explicit rejection counts (per the v1.1.0.41 release notes, the ACVP-Server pool aims for 64 rejections) or just achieve the SHALL minimum. If row count varies per parameter set, the test file should reflect that. Read the actual table before extracting.

**4. Encoding of `M'`.** ML-DSA-44 internal-interface `M'` is a flat byte string built by the caller. For deterministic AFT with `externalMu=false`, `M' = M` directly (the test message). Confirm the spec table's `M'` column is the raw bytes the test should feed into `Sign_internal`, not a higher-level structure.

**5. Whether to gate KAT addition on first running without it.** AGENTS.md ground rule 2 says vectors are immutable once written. If a KAT fails on leviathan's current implementation, the implementation must be debugged, not the vector. Worth running each KAT once against the current implementation in a scratch script before committing the test file, so the first commit is green and any pre-existing bug is found and fixed in an earlier commit. This protects the integrity of the test history.

---

## Definition of done

Maps to AGENTS.md §Definition of Done.

1. `bun check` passes with the new test file present.
2. `bun fix` reports no lint errors on the new files.
3. `test/vectors/mldsa_siggen_kats.ts` cites the spec section and URL.
4. No existing test or vector modified to accommodate the new vectors.
5. Implementation matches the spec; if any KAT fails on current implementation, the bug is fixed in an earlier commit, not the vector adjusted.
6. `test/vectors/SHA256SUMS` regenerated and committed.
7. `docs/mldsa.md`, `docs/mldsa_audit.md`, `docs/test-suite.md`, and `docs/vector_audit.md` updated.
8. `scripts/lib/test-groups.ts` includes the new file in the `mldsa` group; `bun pin` re-run after.

Not part of this task: release notes, version bump, security advisories. This is a test-coverage extension, not an API or behavior change.

---

## Risks

**A KAT fails on current implementation.** Most likely cause is a subtle off-by-one in a rejection-bound comparison that no random AFT vector ever exercised. Treat as a real bug to find and fix per AGENTS.md ground rule 2. Estimated likelihood: low (the codebase passes 360 random AFT vectors and reference implementations of ML-DSA generally do not have rejection-bound bugs), but the whole point of these KATs is to surface that class of bug, so non-zero by construction.

**A KAT we extract is wrong.** If the spec source we read is the Valsorda-flagged broken version, our test will assert against a hash that ACVP's reference implementation also produced from a broken vector, but those signatures still come from running `Sign` correctly on a broken input. The test would pass, but would not actually verify what the label says it verifies. Step 11 (the rejection-counter instrumentation) is the defense against this: if we claim a vector exercises r₀ rejection and our counter shows it does not, we have the wrong vector.

**`signDerand` does not give internal-interface access.** Listed as Open Question 1. Plan B is to add a test-only accessor on `MlDsaBase`; plan C is to call the WASM export directly. Neither is hard; both should be evaluated against the principle that the test should call the same public API the production code uses.

**Spec table extraction errors.** Manual transcription of long hex strings into a TypeScript file is error-prone. Mitigation: extract via a script (parse the spec HTML or asciidoc programmatically), commit the script alongside the vector file, and run the script as the regeneration command rather than hand-editing the vectors. If the script does not survive (one-shot), at minimum diff-check: hash each extracted seed and signature hash before commit and compare against a fresh extraction.

---

## Out of scope

These belong to separate sessions, not this one.

- Wiring `cornerCase` into the Rust verifier dispatch. The companion blocker doc explains why this is unlikely to ever be worth doing. Leave the TODO comment in `parse.rs` as the standing watchlist marker.
- Extending coverage to SLH-DSA (Stateless Hash-Based Digital Signature Standard) or ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism). FIPS 205 (SLH-DSA) and FIPS 203 (ML-KEM) do not have rejection-sampling loops with the same correctness-stress concerns.
- Refactoring the existing `mldsa_siggen.ts` to use hash comparison rather than byte comparison. The existing vectors have full bytes and stand as-is; adding the KAT vectors as a separate file is the lighter-touch addition.
- Adding `cornerCase` as a TypeScript-side label on existing `mldsa_siggen.ts` records. Those records are already `cornerCase: "none"`; the addition would not provide signal.

---

## Companion docs

- `./mldsa-corner-case-blocker.md`: state of the blocker, why the verifier-side dispatch is probably not worth doing.
- ACVP ML-DSA JSON Specification §6.1.2, ML-DSA SigGen Test Types: spec source.
- FIPS 204 §6.2, Algorithm 7 ML-DSA.Sign_internal: rejection-loop definition.
