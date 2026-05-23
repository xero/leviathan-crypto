<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Ed25519 Cryptographic Audit

Audit of the `leviathan-crypto` Ed25519 implementation
(AssemblyScript) against RFC 8032 (Edwards-Curve Digital
Signature Algorithm) §5.1, Ed25519, and FIPS 186-5 (Digital
Signature Standard) §7.6, EdDSA Signature Algorithm. The strict
verification posture follows FIPS 186-5 §7.6.4, Verification,
and is verified against the NIST ACVP EDDSA corpora (keyGen,
sigGen, sigVer).

> ### Table of Contents
> - [Strict Verification](#strict-verification)
> - [Fault-Injection Defense](#fault-injection-defense)
> - [Embedded SHA-512 Integrity](#embedded-sha-512-integrity)
> - [Constant-Time Discipline](#constant-time-discipline)
> - [dom2 Binding for Prehash Mode](#dom2-binding-for-prehash-mode)
> - [Wipe Coverage](#wipe-coverage)
> - [Suite-Layer Integration](#suite-layer-integration)
> - [Cross-References](#cross-references)

| Meta | Description |
| --- | --- |
| Target: | `leviathan-crypto` WebAssembly implementation (AssemblyScript) |
| Spec: | RFC 8032 §5.1, Ed25519, plus FIPS 186-5 §7.6, EdDSA Signature Algorithm |
| Parameter sets: | Ed25519 only (single-variant) |
| Test vectors: | RFC 8032 §7, Test Vectors for Ed25519, plus NIST ACVP EDDSA keyGen / sigGen / sigVer corpora |
| Source files: | `src/asm/curve25519/ed25519.ts`, `src/asm/curve25519/sha512.ts`, `src/ts/ed25519/index.ts`, `src/ts/sign/suites/ed25519.ts` |

---

## Strict Verification

Per FIPS 186-5 §7.6.4, Verification. The strict form `[s]B = R +
[k]A` is enforced; the permissive cofactor-eight form `[8s]G =
[8](R + [k]A)` is NOT implemented. ACVP's `testPassed=false`
sigVer records targeting strict-S and small-order rejection
exercise these checks.

- [ ] **Public-key canonicality.** `edPointDecompress` rejects pk
      encodings with y >= p; the §5.1.3, Decoding, step 4 edge
      case (x = 0 with the sign bit set) is also rejected.
      `ed25519Verify` returns 0 on decompression failure.
- [ ] **R canonicality.** The same decompression rules apply to
      the R component of the signature. Non-canonical R encodings
      return 0 from `ed25519Verify` and `ed25519VerifyPrehashed`.
- [ ] **Strict S, `s < L`.** `scalarIsCanonical` rejects scalars
      with `s >= L` per FIPS 186-5 §7.6.4. The ACVP "modify s"
      sigVer records depend on this rejection.
- [ ] **Small-order pk rejection, `[8]A != identity`.** Three
      substrate `edPointDouble` calls plus one equality check
      against `(0:1:1:0)` reject small-order pk values. A
      small-order A has order dividing 8, so `[8]A = identity`;
      the rejection inverts that test.
- [ ] **Signature equation.** `[s]B = R + [k]A` evaluated with
      the strict (non-cofactor) form, using `edPointMulBase` for
      `[s]B`, `edPointMul` for `[k]A`, and `edPointAdd` for the
      `R + [k]A` accumulation.
- [ ] **Verify gate ordering.** Decompress pk, decompress R,
      check `s < L`, check `[8]A != identity`, then evaluate the
      equation. Every early return wipes the mutable region
      before exiting and returns 0.

---

## Fault-Injection Defense

Per RFC 8032 §5.1.6, signature generation, the per-signature
nonce `r = SHA-512(prefix || M)` is derived from sk-internal
state. A fault that biases prefix bytes can leak the long-term
scalar through ECC fault analysis. The library defends by
requiring the caller to ALSO know the encoded pk.

- [ ] **Caller pk vs derived pk compare.** `ed25519Sign`
      re-derives `pk_check = compress([a]B)` from the freshly
      clamped scalar and compares it against the caller-supplied
      `pkOff` via the shared constant-time `ctEqual` helper from
      `cte/shared.ts` (inlined into curve25519.wasm at compile
      time). Mismatch wipes the mutable region and traps via
      `unreachable`.
- [ ] **TypeScript rethrow.** The wrapper's `rethrowTrap` helper
      catches `WebAssembly.RuntimeError` and rethrows as
      `SigningError('sig-malformed-input', ...)` so callers can
      branch on the failure.
- [ ] **Prehash path parity.** `ed25519SignPrehashed` runs the
      same pk re-derivation and `ctEqual` check before computing
      r. Same wipe and trap discipline.
- [ ] **Suite-layer collapse documented.** `Ed25519Suite` and
      `Ed25519PreHashSuite` route through `_signInternalPk` /
      `_signPrehashedInternalPk`, which derive pk inside the same
      WASM call and skip the cross-check. At the suite call site
      the comparison would be between two outputs of the same
      potentially-faulted module on the same call, so the defence
      collapses to no defence. The skip saves one basepoint scalar
      mult per sign. See
      [ed25519.md §Fault-Injection Defense](./ed25519.md#fault-injection-defense)
      and [architecture.md §Threat model](./architecture.md#threat-model).
- [ ] **No side effects on caller buffers.** sk, pk, M, digest,
      sig, and ctx buffers passed in are read but NEVER mutated
      by either the TS layer or the WASM.

---

## Embedded SHA-512 Integrity

The Ed25519 hash chain runs through `src/asm/curve25519/sha512.ts`,
a verbatim port of `src/asm/sha2/sha512.ts`. Only four
permitted deviations apply.

- [ ] **Verbatim port from sha2.** Source pin commit recorded in
      the file header. Re-verify via
      `diff src/asm/sha2/sha512.ts src/asm/curve25519/sha512.ts`,
      ignoring the buffer-offset import lines.
- [ ] **Permitted deviation 1: buffer-offset imports.** The
      offset imports point at `./buffers` (curve25519 local
      memory layout). The offset constant NAMES are preserved
      so the algorithm code compiles unchanged.
- [ ] **Permitted deviation 2: variant strip.** SHA-384,
      SHA-512/224, and SHA-512/256 are stripped. Ed25519 uses
      only SHA-512.
- [ ] **Permitted deviation 3: `sha512UpdateBytes` helper.** A
      module-internal helper appended at the bottom of the file
      loops `memory.copy` and `sha512Update` in 128-byte chunks
      for the Ed25519 hot path where input pieces live at
      arbitrary memory offsets.
- [ ] **Permitted deviation 4: header comment.** The header
      comment carries the source-pin commit and the deviation
      list for future re-diffs. No other delta is permitted.
- [ ] **ABI invisibility.** `sha512Init`, `sha512Update`,
      `sha512Final`, and `sha512UpdateBytes` are NOT re-exported
      from `index.ts`. The curve25519 ABI surfaces no `sha512*`
      function.

---

## Constant-Time Discipline

Per RFC 8032 §6, Security Considerations, and standard EdDSA
implementation discipline.

- [ ] **Scalar reduce64 binary division.** `scalarReduce64` runs
      a bit-by-bit binary division with a fixed 255-iteration
      loop. The mask-driven `ctSubL33` (conditional subtract of
      L extended to 33 bytes) and `ctLessThan32` (constant-time
      32-byte compare) helpers carry no branches on byte values.
- [ ] **L_LE byte-14 regression test.**
      `test/unit/ed25519/scalar_reduce64.test.ts` exercises a
      BigInt-oracle cross-check on randomized 64-byte inputs to
      catch L_LE transcription errors. An earlier draft of
      `scalar.ts` had `L_LE[14] = 0x4D` instead of the spec
      value `0xDE` (RFC 8032 §5.1, Ed25519); the regression
      catches that and any future transcription drift.
- [ ] **Edwards point ops branch-free on secret data.**
      `edPointDouble`, `edPointAdd`, `edPointSub`, `edPointMul`,
      and `edPointMulBase` use only straight-line field
      arithmetic plus `feCondSwap` for the ladder branch.
      `feCondSwap` is mask-driven, no conditional jump on a
      secret bit.
- [ ] **Ladder loop count fixed.** `edPointMul` runs a 256-bit
      ladder with no early termination. The operation set per
      bit is independent of the scalar bit value.
- [ ] **Verify decompose aggregation.** `edPointDecompress`
      aggregates its success flag across the failure paths and
      returns it at the end of the function. The early branches
      that detect each spec-defined failure mode write into the
      same accumulator rather than returning early at the
      WASM-internal level.
- [ ] **Public-data branches documented.** Branches on the loop
      counter `i` in `lByte(i)`, on the dom2 F=1 byte and the
      |C| byte in `dom2Update`, and on the SHA-512 round number
      in the message schedule index are all public values. No
      branch reads a secret bit.

---

## dom2 Binding for Prehash Mode

Per RFC 8032 §5.1.7, signature verification, Ed25519ph wraps
both SHA-512 inputs (the r-hash and the k-hash) in
`dom2(F=1, C)`. The library binds ctx through dom2 only; pure
Ed25519 omits dom2 entirely (RFC 8032 §5.1, Ed25519, "the empty
string for F=0 without context").

- [ ] **dom2 prefix string.** `loadDom2Prefix(dst)` writes the
      32-byte ASCII constant `'SigEd25519 no Ed25519 collisions'`
      byte-by-byte with per-byte spec-glyph comments. The
      `buffers.ts` source is auditable against the spec text.
- [ ] **F=1 phflag for Ed25519ph.** `dom2Update` writes
      `F = 1` at `SHA512_INPUT_OFFSET + 32` and `|C|` at
      `SHA512_INPUT_OFFSET + 33`, then calls
      `sha512Update(34)`. The 34-byte header always fits in
      the 128-byte SHA-512 input staging slot.
- [ ] **Pure mode does NOT call dom2Update.** `ed25519Sign` and
      `ed25519Verify` build the SHA-512 inputs directly without
      the dom2 prefix. The prehash entries (`ed25519SignPrehashed`,
      `ed25519VerifyPrehashed`) call `dom2Update` before the
      `prefix || digest` and `R || pk || digest` inputs.
- [ ] **Context length bound.** `ed25519SignPrehashed` aborts via
      `unreachable` if `ctxLen > 255`; `ed25519VerifyPrehashed`
      returns 0 in the same case. The 255 ceiling matches the
      RFC 8032 §5.1, Ed25519, single-octet `|C|` encoding.
- [ ] **Effective ctx through the suite layer.**
      `Ed25519PreHashSuite` builds the effective ctx as
      `lengthPrefix(suite.ctxDomain) || lengthPrefix(user_ctx)`
      via `buildEffectiveCtx` and passes the result to
      `ed25519SignPrehashed` as the WASM ctx parameter. The
      suite ctxDomain is `'ed25519-prehash-envelope-v3'`,
      14 bytes UTF-8.

---

## Wipe Coverage

Per AGENTS.md "Wipe discipline". Every Ed25519 path zeroes
secret-derived state on the way out.

- [ ] **WASM wipe at end of every export.** `ed25519Keygen`,
      `ed25519Sign`, `ed25519Verify`, `ed25519SignPrehashed`,
      and `ed25519VerifyPrehashed` each end with `wipeAll()`,
      which is byte-equivalent to `wipeBuffers` and zeroes the
      mutable region from `MUTABLE_START` to `BUFFER_END`.
- [ ] **Early-failure wipes.** Each `unreachable` / `return 0`
      path inside the high-level exports calls `wipeAll()`
      first. Decompose failure, scalar non-canonical, ctxLen
      out of range, and the pk-fault check all clear before
      exiting.
- [ ] **TypeScript I/O staging wipe.** The TS wrapper's
      `ioWipe(mx)` helper zeroes the staging region above
      `BUFFER_END` to the end of linear memory. Every method's
      `finally` runs `ioWipe(mx)` followed by `mx.wipeBuffers()`.
- [ ] **`dispose()` idempotent.** `Ed25519.dispose` runs both
      wipes inside a `try / catch {}` so multiple calls are
      safe even after the module instance has been torn down.

---

## Suite-Layer Integration

Per `src/ts/sign/suites/ed25519.ts` and the [signaturesuite.md
Ed25519 suites](./signaturesuite.md#ed25519-suites) section.

- [ ] **Pure suite rejects user_ctx.** `Ed25519Suite` (format
      byte `0x01`) throws `SigningError('sig-ctx-unsupported',
      ...)` on any non-empty user_ctx in `sign` or `verify`. The
      error message routes callers to `Ed25519PreHashSuite` for
      context-bound signatures. The suite's `ctxDomain` is set
      to `'ed25519-envelope-v3'` for `formatName` / display but
      is never bound into the signature.
- [ ] **Prehash suite binds effective ctx through dom2.**
      `Ed25519PreHashSuite` (format byte `0x11`) builds
      `effective_ctx = buildEffectiveCtx(ctxDomain, user_ctx)`
      and passes it to `Ed25519.signPrehashed` /
      `Ed25519.verifyPrehashed`, which forwards it as the WASM
      ctx parameter consumed by `dom2Update`.
- [ ] **Prehash algorithm pinned to sha-512.** `prehashSize: 64`
      and `prehashAlgorithm: 'sha-512'` are constants; the
      message-taking sign and verify paths route through
      `sha512OneShot(msg)` from `src/ts/sign/hasher.ts`, which
      drives the sha2 WASM module. The streaming path uses
      `SHA512Stream` from the sha2 module via
      `createRunningHash('sha-512')`.
- [ ] **`wasmModules` advertised correctly.** `Ed25519Suite`
      lists `['curve25519']`. `Ed25519PreHashSuite` lists
      `['curve25519', 'sha2']` because the TS-side SHA-512 used
      by the message-taking and streaming paths drives the
      sha2 module. The curve25519-embedded SHA-512 covers
      dom2 prefixing inside the WASM and is not exposed at the
      ABI; sha2 is purely a TS-layer dependency.
- [ ] **Per-call WASM lifecycle.** Each suite method instantiates
      a fresh `Ed25519` inside a `try / finally { dispose() }`
      block. No suite-level long-lived instance is held.
- [ ] **Fault-injection defence inherited.** The suite layer
      calls `Ed25519.sign(sk, pk, M)` with `pk` re-derived from
      sk via `keygenDerand`; the WASM then re-derives pk a
      second time and aborts on mismatch. Two redundant
      derivations defend against fault injection between the
      `keygenDerand` call and the `sign` call.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [ed25519](./ed25519.md) | Ed25519 public API reference |
| [asm_curve25519](./asm_curve25519.md) | curve25519 WASM module reference |
| [x25519_audit](./x25519_audit.md) | Companion X25519 audit on the same WASM module |
| [signaturesuite](./signaturesuite.md) | `Ed25519Suite` / `Ed25519PreHashSuite` consts, envelope wire format |
| [audits](./audits.md) | Project audit index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |