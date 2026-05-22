<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ECDSA-P256 Cryptographic Audit

Audit of the `leviathan-crypto` ECDSA-P256 implementation
(AssemblyScript) against FIPS 186-5 (Digital Signature Standard)
§6, ECDSA, the NIST P-256 curve parameters from SP 800-186
§3.2.1.3, P-256, RFC 6979 (Deterministic Usage of the Digital
Signature Algorithm) §3.2, and `draft-irtf-cfrg-det-sigs-with-noise-05`
§4, Hedged-Deterministic Nonce Generation. The strict-S
verification posture follows RFC 6979 §3.5 on both signer and
verifier and is verified against the NIST ACVP ECDSA-FIPS186-5
corpora (keyGen, sigGen, sigVer) plus the C2SP Wycheproof
`ecdsa_secp256r1_sha256_p1363` corpus.

> ### Table of Contents
> - [Strict Verification](#strict-verification)
> - [Low-S Enforcement](#low-s-enforcement)
> - [RFC 6979 Deterministic K Gate](#rfc-6979-deterministic-k-gate)
> - [Hedged Nonce Derivation](#hedged-nonce-derivation)
> - [Fault-Injection Defense](#fault-injection-defense)
> - [Embedded SHA-256 Integrity](#embedded-sha-256-integrity)
> - [Embedded HMAC-SHA-256 Integrity](#embedded-hmac-sha-256-integrity)
> - [Constant-Time Discipline](#constant-time-discipline)
> - [Wipe Coverage](#wipe-coverage)
> - [Suite-Layer Integration](#suite-layer-integration)
> - [Cross-References](#cross-references)

| Meta | Description |
| --- | --- |
| Target: | `leviathan-crypto` WebAssembly implementation (AssemblyScript) |
| Spec: | FIPS 186-5 §6, ECDSA, plus SP 800-186 §3.2.1.3, P-256, RFC 6979 §3.2, and `draft-irtf-cfrg-det-sigs-with-noise-05` §4 |
| Parameter sets: | P-256 + SHA-256 only (single combination) |
| Test vectors: | RFC 6979 §A.2.5 (P-256 + SHA-256), NIST ACVP ECDSA-FIPS186-5 keyGen / sigGen / sigVer (filtered to P-256 + SHA-256), C2SP Wycheproof `ecdsa_secp256r1_sha256_p1363` |
| Source files: | `src/asm/p256/field.ts`, `src/asm/p256/scalar.ts`, `src/asm/p256/point.ts`, `src/asm/p256/scalar_mult.ts`, `src/asm/p256/rfc6979.ts`, `src/asm/p256/ecdsa.ts`, `src/asm/p256/sha256.ts`, `src/asm/p256/hmac_sha256.ts`, `src/ts/ecdsa/index.ts`, `src/ts/ecdsa/der.ts`, `src/ts/ecdsa/validate.ts`, `src/ts/sign/suites/ecdsa-p256.ts` |

---

## Strict Verification

Per FIPS 186-5 §6.4.4, ECDSA Signature Verification. The
verifier enforces the strict equation `r ≡ x(u1*G + u2*Q) mod n`
with the leviathan-crypto low-S strict-gate layered on top.
ACVP `testPassed=false` sigVer records and the Wycheproof
malleability corpus exercise these checks.

- [x] **Public-key canonicality.** `pointDecompress` rejects pk
      encodings whose prefix is not `0x02` or `0x03`, whose x
      bytes encode a non-canonical field element (`x >= p`), or
      whose `y^2 = x^3 - 3x + b` square root does not exist.
      `ecdsaVerify` returns 0 on decompression failure. The
      `x < p` gate is the explicit `feIsCanonical(x)` check
      inserted immediately after `feFromBytes` in
      `pointDecompress` (`src/asm/p256/point.ts`); `feFromBytes`
      is a literal byte loader and does not reduce, so without
      this gate an adversarial x in `[p, 2^256)` would silently
      reduce inside the curve-equation `feMul` / `feSqr` calls
      and (for the reducing-to-on-curve shape) produce a
      malleable second encoding for the same logical pk. The
      curve-equation residue check below the gate remains as
      defence-in-depth. Surfacing test:
      `test/unit/p256/ecdsa_pk_canonicality.test.ts` constructs the
      four adversarial shapes (trivial overflow, x = p,
      x = x_valid + p, x = x_off_curve + p) and cross-checks
      that the rejection in case 3 fires at `feIsCanonical`,
      not at `pointOnCurve`.
- [ ] **Identity-element pk rejection.** A decompressed pk equal
      to the curve identity `(0:1:0)` is rejected before the
      signature equation evaluates. The identity check uses
      `pointEqual` against `pointZero`.
- [ ] **`r` in `[1, n-1]`.** `scalarIsCanonical` plus
      `scalarIsZero` reject `r >= n` and `r == 0` before the
      verification equation runs.
- [ ] **`s` in `[1, n-1]`.** Same check on the s component.
- [ ] **Low-S strict-gate, `s <= n/2`.** `scalarIsHighS` rejects
      any signature with `s > n/2` before the equation evaluates.
      See [Low-S Enforcement](#low-s-enforcement) for the spec
      provenance and the FIPS 186-5 §6.4.4 reconciliation.
- [ ] **Signature equation.** `r ≡ x(u1*G + u2*Q) mod n`
      evaluated with `pointMulBase` for `u1*G`, `pointMul` for
      `u2*Q`, `pointAdd` for the combination, and an affine
      projection of the result. The x-coordinate is reduced
      mod n before the comparison.
- [ ] **Verify gate ordering.** Decompress pk, reject identity
      pk, check `r ∈ [1, n-1]`, check `s ∈ [1, n-1]`, check
      `s <= n/2`, then evaluate the equation. Every early
      return wipes the mutable region before exiting and
      returns 0.

---

## Low-S Enforcement

ECDSA has a signature-malleability surface that Ed25519 does
not. Any valid signature `(r, s)` has a counterpart `(r, n - s)`
that also verifies under the same `(pk, msgHash)`. Protocols
that hash or compare signature bytes break under this
transformation.

- [ ] **Signer normalises to low-S.** `ecdsaSign` and
      `ecdsaSignInternalPk` normalise `s ← min(s, n - s)` after
      the per-call signing equation per RFC 6979 §3.5. The
      `scalarIsHighS` mask-driven branch selects the canonical
      half without leaking the original bit on a timing
      observer.
- [ ] **Verifier rejects high-S.** `ecdsaVerify` rejects
      `s > n/2` before evaluating the signature equation, per
      the leviathan-crypto strict-gate posture. The gate
      ordering in `ecdsa.ts` puts the high-S rejection between
      the `s != 0 && s < n` canonical check and the
      `pointMul / pointMulBase` calls.
- [ ] **Wycheproof corpus exercises the strict-gate.** The
      `ecdsa_secp256r1_sha256_p1363` corpus
      (`test/vectors/ecdsa_p256_wycheproof.ts`, 262 records)
      contains every malleability variant the upstream maintains
      plus the strict-gate `'valid'` / `'invalid'` discrimination.
      The corpus drives `EcdsaP256.verify` directly through
      `test/unit/sign/sign-ecdsa-p256-vectors.test.ts`.
- [ ] **ACVP reconciliation documented.** ACVP sigVer records
      use FIPS 186-5 §6.4.4 verbatim (high-S accepted). The
      strict-gate diverges; the test reconciles per-record
      `testPassed` against the high-S check via BigInt
      comparison so the ACVP corpus passes under the
      leviathan-crypto-strict semantics. See
      `test/unit/p256/ecdsa_verify.test.ts` and
      [vector_audit.md §ECDSA-P256](./vector_audit.md).

---

## RFC 6979 Deterministic K Gate

Per RFC 6979 §3.2, Generation of k. The deterministic K
derivation runs `(d, H(m))` through an HMAC-DRBG (SP 800-90A) to
produce k. ACVP supplies an explicit per-record `k` for sigGen,
so it cannot exercise this derivation; the RFC 6979 §A.2.5
test vectors (P-256 + SHA-256 over `"sample"` and `"test"`) are
the only public KAT for the K derivation itself.

- [ ] **RFC 6979 §A.2.5 reproduces expected k byte-for-byte.**
      `deriveKDeterministic(d, H(m), kOut)` for the two RFC
      `(d, m)` pairs writes the RFC-supplied k value to `kOut`
      exactly. `test/unit/p256/rfc6979.test.ts` is the gate.
- [ ] **HMAC-SHA-256 backbone matches CAVP.** The embedded
      HMAC-SHA-256 driving the K-DRBG is a verbatim port of
      `src/asm/sha2/hmac.ts`; correctness against NIST CAVP
      HMAC vectors is inherited from the sha2 audit and
      re-verified end-to-end via the RFC 6979 §A.2.5 reproduction.
- [ ] **K-derivation rejection-sampling terminates.** The K-DRBG
      loop re-samples until `k ∈ [1, n-1]` per RFC 6979 §3.2.
      The probability of rejection per iteration is below
      `(n - 1) / 2^256`, vanishingly small for P-256; expected
      iterations is essentially 1. The substrate caps the loop
      at a fixed iteration count and traps on the unreachable
      branch.
- [ ] **bits2int truncation.** The hash-to-scalar reduction
      follows RFC 6979 §2.3.2; for P-256 + SHA-256 the
      `qlen == hlen == 256` equality makes truncation a no-op.
      `scalarReduce` handles the mod-n step.
- [ ] **bits2octets re-conversion.** RFC 6979 §2.3.4's
      `bits2octets` round-trip is implicit in the embedded
      HMAC inputs; the test corpus reproduces the RFC §A.2.5
      values which exercises the path end-to-end.

---

## Hedged Nonce Derivation

Per `draft-irtf-cfrg-det-sigs-with-noise-05` §4,
Hedged-Deterministic Nonce Generation. The hedged path mixes
per-call entropy into the K-DRBG seed so a successful fault on
one signature does not transfer to the next.

- [ ] **Hedged-by-default at the suite layer.**
      `EcdsaP256Suite.sign` and `EcdsaP256Suite.signPrehashed`
      both generate `rnd = randomBytes(32)` per call and thread
      it through `_signInternalPk`. The suite never exposes a
      deterministic-K knob.
- [ ] **Per-call entropy is 32 bytes.** `validateEntropy`
      enforces `rnd.length === 32` at the TS surface; the WASM
      substrate stages exactly 32 bytes from `RND_STAGE`. The
      32-byte size matches the draft's recommended Z size for
      P-256 (32 bytes for the 256-bit curve).
- [ ] **Domain separation from RFC 6979 §3.2.** The hedged
      branch with all-zero `rnd` is NOT byte-equivalent to the
      pure-deterministic RFC 6979 §3.2 path. The two K values
      differ by design (intentional domain separation per the
      draft §4); `test/unit/p256/hmac_sha256.test.ts` confirms
      this with the all-zero-rnd vs deterministic mismatch.
- [ ] **Verifier reproduces hedged signatures.**
      `test/unit/p256/ecdsa_signhedged.test.ts` signs the same
      `(d, H(m))` twice with two distinct rnd values, confirms
      the resulting signatures differ byte-for-byte, and
      confirms both verify under the matching pk. The hedged
      path is the recommended default per the draft §1
      motivation.
- [ ] **rnd wiped on every path.** Suite-level rnd allocated
      via `randomBytes(32)` is wiped in `finally` after the
      signature operation; class-level rnd staged into the WASM
      `RND_STAGE` slot is wiped by `ioWipe(mx)` plus the WASM
      `wipeBuffers` in `finally`.

---

## Fault-Injection Defense

Per the RFC 6979 §3.2 attack surface analysis: a fault that
biases the K-DRBG inputs (d or H(m)) leaks the long-term scalar
through standard ECDSA-with-known-k recovery. The library
defends by requiring the caller to ALSO know the encoded pk.

- [ ] **Caller pk vs derived pk compare.** `ecdsaSign`
      re-derives `pk_check = compress([d]G)` after the
      signature equation and compares it against the
      caller-supplied `pkOff` via a constant-time byte
      comparison helper. Mismatch wipes the mutable region and
      traps via `unreachable`.
- [ ] **TypeScript rethrow.** `src/ts/ecdsa/index.ts`'s
      `rethrowTrap` helper catches `WebAssembly.RuntimeError`
      and rethrows as `SigningError('sig-malformed-input', ...)`
      so callers can branch on the failure.
- [ ] **Suite-layer collapse documented.**
      `EcdsaP256Suite.sign` routes through `_signInternalPk`,
      which derives pk inside the same WASM call and skips the
      cross-check. At the suite call site the comparison would
      be between two outputs of the same potentially-faulted
      module on the same call, so the defence collapses to no
      defence. The skip saves one fixed-base scalar mult per
      sign. See
      [ecdsa-p256.md §Fault-Injection Defense](./ecdsa-p256.md#fault-injection-defense)
      and [architecture.md §Threat model](./architecture.md#threat-model).
- [ ] **No side effects on caller buffers.** sk, pk, msgHash,
      rnd, and sig buffers passed in by the caller are read but
      NEVER mutated by either the TS layer or the WASM. The
      wrapper copies each into the I/O staging region.

---

## Embedded SHA-256 Integrity

The ECDSA-P256 K-derivation runs through
`src/asm/p256/sha256.ts`, a verbatim port of
`src/asm/sha2/sha256.ts`. Only three permitted deviations apply.

- [ ] **Verbatim port from sha2.** Source pin commit recorded
      in the file header. Re-verify via
      `diff src/asm/sha2/sha256.ts src/asm/p256/sha256.ts`,
      ignoring the buffer-offset import lines and the SHA-224
      strip.
- [ ] **Permitted deviation 1: buffer-offset imports.** The
      offset imports point at `./buffers` (p256 local memory
      layout). The offset constant NAMES (`SHA256_H`,
      `SHA256_BLOCK`, `SHA256_W`, `SHA256_OUT`, `SHA256_INPUT`,
      `SHA256_PARTIAL`, `SHA256_TOTAL`) are preserved so the
      algorithm code compiles unchanged.
- [ ] **Permitted deviation 2: variant strip.** SHA-224 IVs and
      entry points are stripped. ECDSA-P256 + SHA-256 is the
      only consumer; SHA-224 is dead code for this module.
- [ ] **Permitted deviation 3: `sha256UpdateBytes` helper.** A
      module-internal helper appended at the bottom of the
      file loops `memory.copy` plus `sha256Update` in 64-byte
      chunks for the RFC 6979 K-derivation hot path where
      input pieces live at arbitrary memory offsets.
- [ ] **ABI invisibility.** `sha256Init`, `sha256Update`,
      `sha256Final`, and `sha256UpdateBytes` are NOT re-exported
      from `src/asm/p256/index.ts`. The p256 ABI surfaces no
      `sha256*` function; the embedded copy is module-internal.

---

## Embedded HMAC-SHA-256 Integrity

The RFC 6979 §3.2 HMAC-DRBG runs through
`src/asm/p256/hmac_sha256.ts`, a verbatim port of
`src/asm/sha2/hmac.ts`. Two permitted deviations apply.

- [ ] **Verbatim port from sha2.** Source pin commit recorded
      in the file header. Re-verify via
      `diff src/asm/sha2/hmac.ts src/asm/p256/hmac_sha256.ts`,
      ignoring the buffer-offset import lines.
- [ ] **Permitted deviation 1: buffer-offset imports.** The
      offset imports point at `./buffers`. Offset constant
      NAMES (`HMAC256_IPAD`, `HMAC256_OPAD`, `HMAC256_INNER`)
      are preserved.
- [ ] **Permitted deviation 2: variant strip.** HMAC-SHA-384
      and HMAC-SHA-512 are stripped. ECDSA-P256 +
      HMAC-SHA-256 is the only consumer.
- [ ] **ABI invisibility.** `hmac256Init`, `hmac256Update`,
      `hmac256Final` are NOT re-exported from
      `src/asm/p256/index.ts`. The p256 ABI surfaces no
      `hmac256*` function.
- [ ] **HMAC-DRBG K / V state buffers.** `HMAC_DRBG_K` (32 B)
      and `HMAC_DRBG_V` (32 B) live in the p256 mutable region;
      both are zeroed by `wipeBuffers` on every entry-point
      exit.

---

## Constant-Time Discipline

Per RFC 6979 §7, Security Considerations, plus the standard
ECDSA implementation discipline. Every operation that consumes
secret-bearing data (the scalar d, the per-call nonce k, the
HMAC-DRBG K / V state, intermediate scalar-mult points) runs a
fixed-length loop with mask-driven conditional selects.

- [ ] **Scalar reduce binary division.** `scalarReduce` and
      `scalarReduce64` run a bit-by-bit binary division with a
      fixed-iteration loop. The mask-driven conditional subtract
      and constant-time compare helpers carry no branches on
      byte values.
- [ ] **Field arithmetic branch-free on secret data.** `feAdd`,
      `feSub`, `feNeg`, `feMul`, `feSqr`, `feInv`, `feSqrt`,
      `feFromBytes`, `feToBytes`, `feIsZero`, `feIsEqual`,
      `feIsOdd`, `feCondSwap`, and `feCondNeg` use straight-line
      arithmetic plus mask-driven selects. No conditional jump
      reads a secret bit.
- [ ] **Point arithmetic branch-free.** `pointAdd`,
      `pointDouble`, `pointSub`, `pointNegate`, and `pointEqual`
      run the Renes-Costello-Batina 2016 complete-addition
      formulas (Algorithm 4 add, Algorithm 6 double, specialised
      for `a = -3`). The formulas are complete: they correctly
      handle identity, `P = Q`, and `P = -Q` without branches.
- [ ] **Scalar-mult ladder fixed loop.** `pointMul` and
      `pointMulBase` run a constant-time double-and-add-always
      ladder consuming the scalar MSB-first. Each bit drives
      one `pointDouble` and one masked `pointAdd`; the operation
      set per bit is independent of the scalar bit value.
- [ ] **Low-S branch is mask-driven.** The signer's
      `scalarIsHighS` plus conditional `scalarNegate` selects
      the canonical s through a mask rather than a conditional
      jump.
- [ ] **Public-data branches documented.** `ecdsaSign` branches
      on `isAllZero32(rnd)` to dispatch between deterministic
      and hedged K derivation; `rnd` is caller-supplied with a
      public mode-selection role and the branch leaks the
      dispatcher choice, not any secret bits. `ecdsaVerify` is
      wholly public; the substrate maintains constant-time for
      implementation simplicity. `pointDecompress` branches on
      the prefix byte and curve-equation residue, both public.

---

## Wipe Coverage

Per AGENTS.md "Wipe discipline". Every ECDSA-P256 path zeroes
secret-derived state on the way out.

- [ ] **WASM wipe at end of every export.** `ecdsaKeygen`,
      `ecdsaSign`, `ecdsaSignInternalPk`, and `ecdsaVerify`
      each end with a `wipeBuffers()` call equivalent that
      zeroes the mutable region from `MUTABLE_START` (4096) to
      `BUFFER_END` (7054), covering all scratch field elements,
      scratch points, scratch scalars, HMAC-DRBG K / V state,
      embedded SHA-256 streaming state, and the ECDSA
      fault-check buffers.
- [ ] **Early-failure wipes.** Each `unreachable` / `return 0`
      path inside the high-level exports calls the wipe first.
      Decompose failure, scalar non-canonical, high-S
      rejection, identity-pk rejection, and the pk-fault check
      all clear before exiting.
- [ ] **TypeScript I/O staging wipe.** The TS wrapper's
      `ioWipe(mx)` helper zeroes the staging region above
      `BUFFER_END` (`SEED_STAGE`, `PK_STAGE`, `SIG_STAGE`,
      `MSG_HASH_STAGE`, `RND_STAGE`) to the end of linear
      memory. Every public method's `finally` runs `ioWipe(mx)`
      followed by `mx.wipeBuffers()`.
- [ ] **rnd wipe at the suite layer.** `EcdsaP256Suite.sign` /
      `signPrehashed` wipe the locally-allocated rnd buffer in
      `finally` after every signature operation, before the
      `inst.dispose()` call. The wipe runs on both the success
      path and on every throw path.
- [ ] **`dispose()` idempotent.** `EcdsaP256.dispose` runs both
      WASM and TS wipes inside a `try / catch {}` so multiple
      calls are safe even after the module instance has been
      torn down.

---

## Suite-Layer Integration

Per `src/ts/sign/suites/ecdsa-p256.ts` and the
[signaturesuite.md ECDSA-P256 suite](./signaturesuite.md#ecdsa-p256-suite)
section.

- [ ] **`EcdsaP256Suite.formatEnum` is `0x02`.** Matches the
      catalog row in
      [signaturesuite.md §Format byte allocation](./signaturesuite.md#format-byte-allocation).
- [ ] **`formatName` is `'ecdsa-p256'`.**
- [ ] **`ctxDomain` is `'ecdsa-p256-envelope-v3'`.** Built into
      the suite for display purposes only; never bound into the
      signature because the suite rejects non-empty user_ctx.
- [ ] **Suite rejects non-empty user_ctx.** Every entry point
      (`sign`, `verify`, `signPrehashed`, `verifyPrehashed`)
      checks `ctx.length > 0` and throws
      `SigningError('sig-ctx-unsupported')` with an error
      message routing callers to the classical+PQ hybrid suites
      at `0x22` / `0x23` (reserved).
- [ ] **Suite routes through `_signInternalPk`.**
      `EcdsaP256Suite.sign` and `signPrehashed` call
      `inst._signInternalPk(sk, digest, rnd)` rather than
      `inst.sign(sk, pk, digest, rnd)`. The fault-injection
      defence is documented as collapsing at the suite call
      site; see [Fault-Injection Defense](#fault-injection-defense).
- [ ] **Prehash algorithm pinned to `'sha-256'`.**
      `prehashSize: 32` and `prehashAlgorithm: 'sha-256'` are
      constants. Message-taking `sign(msg)` and `verify(msg)`
      paths route through `sha256OneShot(msg)` from
      `src/ts/sign/hasher.ts`. The `SignStream` /
      `VerifyStream` paths use `createRunningHash('sha-256')`,
      which returns a buffered shim (`sha256Buffered`) over the
      one-shot `SHA256` class; chunks are copied and
      concatenated at `finalize()` so the output is
      byte-identical to a one-shot SHA-256 over the full
      message.
- [ ] **`wasmModules` is `['p256', 'sha2']`.** The frozen array
      tells consumers to initialise both modules. Tests verify
      the array contents and that both modules are required at
      init.
- [ ] **Per-call WASM lifecycle.** Each suite method
      instantiates a fresh `EcdsaP256` inside a
      `try / finally { dispose() }` block. No suite-level
      long-lived instance is held.
- [ ] **Conforms to `StreamableSignatureSuite`.** ECDSA-P256
      ALWAYS prehashes the message via SHA-256 (FIPS 186-5
      §6.4 requirement), so streaming is well-defined. The
      type test in `test/unit/sign/sign-ecdsa-p256-suites.test.ts`
      confirms the suite satisfies
      `StreamableSignatureSuite` at the TS type level.
- [ ] **Digest-length contract.** `signPrehashed` and
      `verifyPrehashed` both throw
      `SigningError('sig-malformed-input')` on a wrong-length
      digest, symmetric with the AGENTS.md "verifyPrehashed
      digest-length contract" rule.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [ecdsa-p256](./ecdsa-p256.md) | ECDSA-P256 public API reference |
| [asm_p256](./asm_p256.md) | p256 WASM module reference |
| [signaturesuite](./signaturesuite.md) | `EcdsaP256Suite` const, envelope wire format |
| [vector_audit](./vector_audit.md) | Test-vector tier classification and Rust verifier coverage |
| [audits](./audits.md) | Project audit index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |