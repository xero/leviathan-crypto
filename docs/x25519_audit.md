<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### X25519 Cryptographic Audit

Audit of the `leviathan-crypto` X25519 implementation
(AssemblyScript) against RFC 7748 (Elliptic Curves for Security)
§5, The X25519 and X448 Functions, and §6, Diffie-Hellman.
Verified against RFC 7748 §6.1, Curve25519 (Alice/Bob test
vectors), plus the iter=1 and iter=1000 chain records from RFC
7748 §5.

> ### Table of Contents
> - [Clamping per RFC 7748](#clamping-per-rfc-7748)
> - [Constant-Time Montgomery Ladder](#constant-time-montgomery-ladder)
> - [High-Bit Masking on Peer pk](#high-bit-masking-on-peer-pk)
> - [All-Zero Rejection at the TS Layer](#all-zero-rejection-at-the-ts-layer)
> - [Iterated Test Coverage](#iterated-test-coverage)
> - [Wipe Coverage](#wipe-coverage)
> - [Cross-References](#cross-references)

| Meta | Description |
| --- | --- |
| Target: | `leviathan-crypto` WebAssembly implementation (AssemblyScript) |
| Spec: | RFC 7748 §5, The X25519 and X448 Functions, plus §6, Diffie-Hellman, and §6.1, Curve25519, security considerations |
| Parameter sets: | X25519 only (single-variant) |
| Test vectors: | RFC 7748 §6.1, Curve25519, Alice/Bob plus RFC 7748 §5 iter=1 and iter=1000 chain records |
| Source files: | `src/asm/curve25519/x25519.ts`, `src/asm/curve25519/montgomery.ts`, `src/asm/curve25519/scalar.ts`, `src/ts/x25519/index.ts` |

---

## Clamping per RFC 7748

Per RFC 7748 §5, The X25519 and X448 Functions: "decodeScalar25519
clears the lower three bits, clears the highest bit, and sets the
second highest bit." The library clamps the scalar internally on
every call.

- [ ] **`scalarClamp` correctness.** `scalarClamp(out, src)`
      writes `out[0] = src[0] & 0xF8`, `out[31] = (src[31] &
      0x7F) | 0x40`, and copies bytes 1..30 verbatim. Output
      buffer is distinct from input; the caller's sk bytes are
      preserved.
- [ ] **Idempotent.** Running `scalarClamp` on an already-clamped
      scalar produces the same bytes. The bit-pattern check is
      asserted in `test/unit/x25519/scalar_clamp.test.ts`.
- [ ] **sk semantics opaque random bytes.** The X25519 surface
      treats `sk` as "any 32 random bytes" per RFC 7748 §5; the
      WASM does not surface a "clamped sk" type. `X25519KeyPair`
      stores the unclamped form so round-tripping a key through
      external storage preserves byte-equality.
- [ ] **Per-call clamping in `x25519Keygen` and `x25519DH`.**
      Both WASM exports run `scalarClamp(X25519_SCALAR_CLAMP,
      skOff)` as their first operation. The substrate ladder
      always sees the clamped form regardless of the caller's
      sk bytes.

---

## Constant-Time Montgomery Ladder

Per RFC 7748 §5, The X25519 and X448 Functions. The ladder must
run a fixed number of iterations and must not branch on secret
scalar bits.

- [ ] **Fixed loop count.** `x25519Ladder` in `montgomery.ts`
      runs exactly 255 iterations regardless of scalar value.
      The high bit of the scalar (bit 254 after clamping) is
      always 1, so the loop processes bits 254 down to 0 with no
      data-dependent termination.
- [ ] **`feCondSwap` mask-driven.** The conditional swap of
      `(x2:z2)` and `(x3:z3)` based on the current scalar bit
      uses `feCondSwap(a, b, mask)`, which XOR-swaps under a
      mask. No conditional jump reads the scalar bit.
- [ ] **No branches on secret bits.** The ladder step `a, aa,
      b, bb, e, c, d, da, cb` arithmetic uses straight-line
      field operations (`feAdd`, `feSub`, `feMul`, `feSqr`,
      `feMul121666`). No comparison against a secret bit.
- [ ] **Final conditional swap.** After the loop, one more
      `feCondSwap` driven by the bit-254 mask restores the
      canonical position. The output is `(x2:z2)`; the wrapper
      computes `x2 / z2 = x2 * feInv(z2)` and `feToBytes` the
      result.

---

## High-Bit Masking on Peer pk

Per RFC 7748 §5, The X25519 and X448 Functions: "implementations
MUST mask the most significant bit in the final byte" of the
input u-coordinate before decoding to a field element. The
library applies this internally rather than at the API boundary.

- [ ] **`feFromBytes` masks bit 255.** `montgomery.ts`'s call to
      `feFromBytes` reads the encoded u-coord and clears bit
      255 of byte 31 before constructing the radix-2^51 limbs.
      Asserted in `test/unit/x25519/fe_from_bytes_mask.test.ts`.
- [ ] **Callers do NOT pre-mask.** `X25519.dh` passes `peerPk`
      byte-for-byte to the WASM. The TS-layer `validatePublicKey`
      performs only a length check (32 bytes); no value-level
      check runs.
- [ ] **Non-canonical encodings pass through.** A peer pk with
      `u >= p` after the bit-255 mask is reduced mod p inside
      `feFromBytes`. RFC 7748 §5 accepts this posture, and
      Curve25519's twist security covers the non-curve case.

---

## All-Zero Rejection at the TS Layer

Per RFC 7748 §6.1, Curve25519, contributory-behaviour discussion.
A small-order peer pk produces an all-zero shared u-coordinate
that carries no contributory entropy from the local secret.
The TypeScript layer rejects with `KeyAgreementError`; the WASM
does NOT filter at the substrate level.

- [ ] **Constant-time accumulator scan.** `X25519.dh` runs a
      32-iteration OR-accumulate loop across the shared-secret
      bytes with no early exit on the first non-zero byte. The
      conditional that throws fires only after the full
      accumulator is computed.
- [ ] **`KeyAgreementError` thrown on all-zero.** When the
      accumulator is zero, the wrapper wipes the shared buffer
      and throws `KeyAgreementError` with the message
      `'leviathan-crypto: X25519 shared secret is all-zero (peer
      public key is a small-order point)'`.
- [ ] **WASM is filter-free.** `x25519DH` in
      `src/asm/curve25519/x25519.ts` writes the shared
      u-coordinate to the caller's slot regardless of whether it
      is all-zero. This matches the x25519-dalek posture and
      preserves WASM-vs-oracle byte agreement on any test record
      that exercises a small-order peer pk.
- [ ] **No fault-injection cross-check.** Unlike `ed25519Sign`,
      `x25519Keygen` has no caller-supplied pk to cross-check
      and `x25519DH`'s peerPk is genuinely external (the other
      party's actual choice). The all-zero rejection is the
      only protocol-level filter at the X25519 boundary.
- [ ] **Vector compatibility.** Any future test record that
      exercises a small-order peer pk verifies byte-for-byte at
      the WASM boundary; the TS-layer rejection is the public
      API contract. `test/unit/x25519/all_zero_reject.test.ts`
      uses the eight canonical small-order u-coordinates from
      RFC 7748 §6.1, Curve25519, and confirms each produces an
      all-zero shared secret at the WASM level and a
      `KeyAgreementError` at the TS level.

---

## Iterated Test Coverage

Per RFC 7748 §5, The X25519 and X448 Functions. The
chain-iteration vectors exercise the same scalar arithmetic and
ladder loop under repeated composition.

- [ ] **Alice/Bob vectors, RFC 7748 §6.1.** The §6.1,
      Curve25519, end-to-end DH vectors run in
      `test/unit/x25519/rfc7748_§6_1.test.ts`. Both Alice and
      Bob compute the same shared u-coordinate byte-for-byte.
- [ ] **iter=1 record, RFC 7748 §5.** The first iteration of
      the §5 chain (`k = u = 09 00 00 ... 00`, expected
      `0x422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079`)
      runs in `test/unit/x25519/iterated.test.ts`.
- [ ] **iter=1000 record, RFC 7748 §5.** The 1000-iteration
      chain (`k`, `u` updated per iteration, expected
      `0x684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51`)
      runs in `test/unit/x25519/iterated.test.ts`. The runtime
      is comfortably under the unit-group timeout.
- [ ] **iter=1000000 deferred.** The 1,000,000-iteration record
      from RFC 7748 §5 is out of scope for the CI suite per
      `vector_audit.md`. The 1000-iteration record exercises
      the same code paths; the 1M record provides additional
      defence against rare aliasing bugs and is left to manual
      verification on demand.

---

## Wipe Coverage

Per AGENTS.md "Wipe discipline". X25519 owns less secret state
than Ed25519 (only the clamped scalar and the shared secret),
so the wipe path is correspondingly simpler.

- [ ] **Per-call WASM wipe.** `x25519Keygen` and `x25519DH` end
      with `wipeX25519()`, which zeroes `X25519_SCALAR_CLAMP`
      (the only secret intermediate the substrate owns).
      Caller-provided buffers are not touched.
- [ ] **Module-level wipe covers the same slot.** The TS
      wrapper's `dispose()` calls `wipeBuffers()`, which zeroes
      the full mutable region from `MUTABLE_START` to
      `BUFFER_END`. `X25519_SCALAR_CLAMP` sits inside that range
      and gets cleared by the sweep.
- [ ] **TypeScript I/O staging wipe.** The TS wrapper's
      `ioWipe(mx)` helper zeroes the staging region above
      `BUFFER_END` (sk slot, pk slot, peer-pk slot,
      shared-secret slot). Every method's `finally` runs
      `ioWipe(mx)` followed by `mx.wipeBuffers()`.
- [ ] **Wipe on all-zero rejection.** `X25519.dh` wipes the
      shared buffer before throwing `KeyAgreementError`. The
      all-zero buffer that triggered rejection does not linger
      on the JavaScript heap.
- [ ] **`dispose()` idempotent.** `X25519.dispose` runs both
      wipes inside a `try / catch {}` so multiple calls are
      safe even after the module instance has been torn down.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [x25519](./x25519.md) | X25519 public API reference |
| [asm_curve25519](./asm_curve25519.md) | curve25519 WASM module reference |
| [ed25519_audit](./ed25519_audit.md) | Companion Ed25519 audit on the same WASM module |
| [audits](./audits.md) | Project audit index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |