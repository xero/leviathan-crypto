<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### `curve25519` WASM Module Reference

This low-level reference details the curve25519 AssemblyScript
source and WASM exports, intended for those auditing,
contributing to, or building against the raw module. **Most
consumers should instead use the TypeScript wrappers,
[Ed25519](./ed25519.md) and [X25519](./x25519.md).**

> ### Table of Contents
> - [Overview](#overview)
> - [Buffer Layout](#buffer-layout)
> - [Module Identity](#module-identity)
> - [Memory Wiping](#memory-wiping)
> - [Source Files](#source-files)
> - [API Reference](#api-reference)
> - [Constant-time Posture](#constant-time-posture)
> - [Cross-references](#cross-references)

---

## Overview

`curve25519.wasm` is the substrate for two consumer-facing
primitives, Ed25519 (RFC 8032, Edwards-Curve Digital Signature
Algorithm) and X25519 (RFC 7748, Elliptic Curves for Security),
in a single WebAssembly binary compiled from AssemblyScript.
The module hosts the field arithmetic over GF(2^255-19), the
edwards25519 point operations in extended coordinates, the
Montgomery ladder for Curve25519, the scalar arithmetic mod L,
the point compression and decompression, and an embedded
SHA-512 used by the Ed25519 hash chain.

Key properties of this implementation:

**Static memory only.** All buffers are fixed offsets in linear
memory. The AssemblyScript compiler reserves offsets 0..4095 for
its data segment; mutable regions start at offset 4096
(`MUTABLE_START`) and end at offset 7836 (`BUFFER_END`). Total
memory is 2 pages (131072 bytes), with the mutable footprint
under 4 KB and the remainder reserved for the TypeScript layer's
I/O staging region.

**Scalar (no v128).** Curve25519 ships without WebAssembly SIMD.
The dalek-cryptography parallel-formulas approach (eprint
2018/098) pairs the independent field multiplications of the
Hisil-Wong-Carter-Dawson extended-coords Edwards addition onto
2-way SIMD lanes, but that approach only pays off with a native
paired 64x64 to 128 multiply. AssemblyScript's v128 instruction
set does not expose one; the closest primitive is
`i64x2.extmul_low_i32x4` / `extmul_high_i32x4` (paired 32x32 to
64), and synthesising paired 64x64 to 128 from it requires a
4-piece split plus carry-tracking via XOR-flip and signed
compare (no `i64x2` unsigned compare). The emulated path is not
measurably faster than two sequential scalar `feMul` calls, so
the module ships scalar. See the header comment in
`src/asm/curve25519/index.ts` for the full analysis.

**Radix-2^51 field representation.** A field element is 5 i64
limbs at radix 2^51 per RFC 8032 §5.1, Ed25519, requiring 40
bytes per field element. An Edwards point in extended
coordinates `(X:Y:Z:T)` is 4 field elements, 160 bytes total. A
scalar is 32 bytes little-endian.

**Embedded SHA-512.** The Ed25519 hash chain runs through an
internal SHA-512 ported verbatim from
`src/asm/sha2/sha512.ts`. The embedded copy lets every signing
operation stay inside a single WASM call rather than crossing
the JavaScript / WASM boundary 6 to 12 times per signature for
sha2 module orchestration. The ABI does NOT surface the SHA-512
exports; they are module-internal helpers only. See [Source
Files](#source-files) for the diff-disciplined deviation list.

**No protocol logic in the substrate.** The TASK-B field /
Edwards / ladder / scalar primitives are pure mathematical
operations on linear-memory offsets. The Ed25519 protocol
(RFC 8032 §5.1.5, key generation, through §5.1.7, signature
verification) and the X25519 protocol (RFC 7748 §6,
Diffie-Hellman) live in `ed25519.ts` and `x25519.ts`, both
compiled into the same binary.

---

## Buffer Layout

Defined in `src/asm/curve25519/buffers.ts`. All offsets in bytes
from base 0.

```
Offset    Size     Region
─────────────────────────────────────────────────────────────────────
0..4095   4096     AS data segment (reserved)
4096      640      FIELD_TMP        (16 × 40-byte scratch field elements)
4736      640      POINT_TMP        (4 × 160-byte scratch Edwards points)
5376      480      LADDER_TMP       (12 × 40-byte X25519 ladder scratch)
5856      80       ACC              (column accumulator for radix-2^51 mul)
5936      64       SHA512_H         (SHA-512 state H0..H7)
6000      128      SHA512_BLOCK     (SHA-512 block accumulator)
6128      640      SHA512_W         (SHA-512 message schedule W[0..79])
6768      64       SHA512_OUT       (SHA-512 digest output)
6832      128      SHA512_INPUT     (SHA-512 user-input staging, one block)
6960      4        SHA512_PARTIAL   (u32 partial block length)
6964      8        SHA512_TOTAL     (u64 total bytes hashed)
6972      32       ED25519_SCALAR_A (clamped scalar a)
7004      32       ED25519_PREFIX   (signing prefix h[32..64])
7036      32       ED25519_R_SCALAR (per-signature r mod L)
7068      32       ED25519_K_SCALAR (challenge k mod L)
7100      32       ED25519_PK_CHECK (derived pk for fault check)
7132      160      ED25519_POINT_A  (A = [a]B or decompressed pk)
7292      160      ED25519_POINT_R  (R = [r]B or decompressed R)
7452      160      ED25519_POINT_TMP1
7612      160      ED25519_POINT_TMP2
7772      32       X25519_SCALAR_CLAMP (clamped X25519 scalar)
7804      32       BASEPOINT_U      (Curve25519 basepoint u-coord, RFC 7748 §4.1)
BUFFER_END = 7836 (< 65536 = 1 page; module sized at 2 pages for the
                   TypeScript layer's I/O staging region above)
```

Constants (basepoint B, curve constants d and 2d, a24 = 121665,
curve order L) are NOT stored in mutable linear memory. They
live as `@inline const` u64 limb values in `field.ts`,
`montgomery.ts`, and `scalar.ts` and are materialized into
caller-provided offsets via loader helpers (`edPointBasepoint`,
`loadD`, `loadTwoD`, `loadSqrtM1`, `loadBasepointU`,
`loadDom2Prefix`).

The TypeScript layer claims the region above `BUFFER_END` up to
the end of linear memory as I/O staging for caller-supplied
inputs (seed, sk, pk, message, sig, digest, ctx) and outputs
(pk, sig, shared secret). The WASM never reads or writes that
region; the wrapper owns it and wipes it explicitly.

---

## Module Identity

```typescript
function getModuleId(): i32      // returns 8
function getMemoryPages(): i32   // returns 2
```

Module ID 8 in the AsmModule registry. The 11th WASM binary in
the library after ct, serpent, chacha20, aes, sha2, sha3,
blake3, kyber, mldsa, and slhdsa.

---

## Memory Wiping

```typescript
function wipeBuffers(): void
```

`memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)`,
zeroes the entire mutable region in a single pass. Covers every
substrate scratch slot, the SHA-512 state, the Ed25519 scratch
(clamped scalar a, signing prefix, r, k, pk-check, and the four
extended-coord points), and the X25519 clamped-scalar slot plus
the basepoint u staging.

The AS data segment at offsets 0..4095 is NOT wiped. It holds
no mutable state.

Two finer-grained internal helpers run inside individual
high-level functions:

- `ed25519.ts` calls `wipeAll()` on every public-export return
  path (success and early-failure abort). `wipeAll` is byte-
  equivalent to the module-level `wipeBuffers`; the duplication
  avoids a circular import.
- `x25519.ts` calls `wipeX25519()` after `x25519Keygen` and
  `x25519DH`, which zeroes only `X25519_SCALAR_CLAMP` (the
  single secret intermediate this module owns). The broader
  `wipeBuffers` sweep covers the same slot at instance teardown.

The TypeScript wrappers call `wipeBuffers()` in `Ed25519.dispose`
and `X25519.dispose`, plus on every public-method `finally`. The
TS layer separately wipes its own I/O staging region above
`BUFFER_END`, which `wipeBuffers` does not touch.

---

## Source Files

| File             | Contents                                                                                                            |
|------------------|---------------------------------------------------------------------------------------------------------------------|
| `buffers.ts`     | Static buffer offsets, `wipeBuffers`, module identity getters, `loadBasepointU` and `loadDom2Prefix` ASCII helpers. |
| `field.ts`       | Field arithmetic over GF(2^255-19) at radix 2^51: add, sub, neg, mul, sqr, mul121666, inv, pow_(p-5)/8, fromBytes, toBytes, isZero, isNegative, condSwap, condNeg, plus the d / 2d / sqrt-(-1) loader helpers. |
| `edwards.ts`     | edwards25519 point ops in extended coordinates: zero, basepoint, double, add, sub, equal, onCurve, mul (variable-base), mulBase (fixed-base via the basepoint table). |
| `compress.ts`    | Point compression (RFC 8032 §5.1.2, encoding) and strict-canonical decompression (rejects y >= p and off-curve points). |
| `montgomery.ts`  | The X25519 Montgomery ladder, `x25519Ladder(out, scalar, u)`. Per RFC 7748 §5, The X25519 and X448 Functions, `feFromBytes` masks bit 255 of the encoded u-coord internally. |
| `scalar.ts`      | Scalar arithmetic mod L: clamp (RFC 7748 §5), isCanonical (s < L), reduce (32-byte input), reduce64 (64-byte input), add, mulAdd. |
| `sha512.ts`      | Embedded SHA-512 ported verbatim from `src/asm/sha2/sha512.ts` at commit `3ffe9044873c6b253ca872b9333c8db84327aad1`. Module-internal; not surfaced at the WASM ABI. |
| `ed25519.ts`     | Ed25519 protocol: `ed25519Keygen`, `ed25519Sign`, `ed25519Verify`, `ed25519SignPrehashed`, `ed25519VerifyPrehashed`. Drives sha512 and the substrate. |
| `x25519.ts`      | X25519 protocol: `x25519Keygen`, `x25519DH`. Drives the ladder with internal clamping. |
| `index.ts`       | Public exports re-exposed from the files above. |

The embedded SHA-512 in `sha512.ts` permits four well-defined
deviations from the canonical source:

1. Buffer-offset imports rewritten to `./buffers` (curve25519
   local memory layout). The offset constant NAMES are
   preserved (`SHA512_H_OFFSET`, `SHA512_BLOCK_OFFSET`, etc.) so
   the algorithm code compiles unchanged.
2. The SHA-384, SHA-512/224, and SHA-512/256 variants are
   stripped. Ed25519 uses only SHA-512 (RFC 8032 §5.1, Ed25519);
   the truncated variants are dead code in this module.
3. A module-internal `sha512UpdateBytes(src, len)` helper is
   appended for the Ed25519 hot path, where input pieces (seed,
   prefix, message, R, pk, digest, dom2 prefix) live at
   arbitrary memory offsets. It loops `memory.copy` plus
   `sha512Update` in 128-byte chunks.
4. The header comment carries the source-pin commit so future
   auditors can re-diff. Cite via
   `diff src/asm/sha2/sha512.ts src/asm/curve25519/sha512.ts`,
   ignoring the buffer-import lines.

No other delta is permitted. The embedded SHA-512 is the same
algorithm running in the sha2 module, just at different offsets.

---

## API Reference

### Buffer-introspection getters

```typescript
function getModuleId():           i32
function getMemoryPages():        i32
function getFieldTmpOffset():     i32
function getFieldTmpStride():     i32
function getPointTmpOffset():     i32
function getPointTmpStride():     i32
function getLadderTmpOffset():    i32
function getLadderTmpStride():    i32
```

Read-only layout helpers exposed for the TypeScript layer's
assertion checks and for any consumer that wants to address the
substrate scratch directly.

### Field arithmetic

```typescript
function feAdd(out, a, b):         void   // out = a + b (mod 2p)
function feSub(out, a, b):         void   // out = a - b (mod 2p)
function feNeg(out, a):            void   // out = -a (mod 2p)
function feMul(out, a, b):         void   // out = a * b (mod p), radix-2^51
function feSqr(out, a):            void   // out = a^2 (mod p)
function feInv(out, a):            void   // out = a^(-1) (mod p) via Fermat
function feMul121666(out, a):      void   // out = a * 121665 (X25519 a24 ladder step)
function feFromBytes(out, src):    void   // 32 LE bytes → field element, masks bit 255
function feToBytes(out, src):      void   // field element → 32 LE bytes (canonical)
function feIsZero(a):              i32    // 1 iff a ≡ 0 (mod p)
function feIsNegative(a):          i32    // 1 iff low bit of canonical form is 1
function feCondSwap(a, b, swap):   void   // CT swap when swap = 1
function feCondNeg(out, a, neg):   void   // CT negate when neg = 1
```

All field operations operate on 40-byte slots (5 i64 limbs).
The `feInv` implementation uses an addition chain over Fermat's
exponent `p - 2`; `feSqr` is invoked roughly 250 times per
inversion. Field operations never branch on input limb values.

### Edwards points

```typescript
function edPointZero(out):            void   // identity point (0:1:1:0)
function edPointBasepoint(out):       void   // standard basepoint B
function edPointDouble(out, a):       void   // out = [2]a
function edPointAdd(out, a, b):       void   // out = a + b (extended coords)
function edPointSub(out, a, b):       void   // out = a - b
function edPointEqual(a, b):          i32    // 1 iff a = b (projective equality)
function edPointOnCurve(p):           i32    // 1 iff p satisfies the curve eqn
function edPointMul(out, scalar, p):  void   // out = [scalar] * p, CT ladder
function edPointMulBase(out, scalar): void   // out = [scalar] * B
```

Points are 160-byte slots holding `(X:Y:Z:T)` extended
coordinates. `edPointMul` runs a 256-bit-fixed Montgomery
ladder with `feCondSwap` for the conditional branch; the loop
count and per-bit operation set are independent of scalar
value.

### Point compression

```typescript
function edPointCompress(out, p):     void   // p → 32-byte encoded form
function edPointDecompress(out, src): i32    // 0 on failure (non-canonical /
                                             // off-curve / x=0 with sign=1)
```

`edPointDecompress` returns 0 on every spec-defined failure
(non-canonical y >= p in the encoded form, off-curve, the
RFC 8032 §5.1.3, Decoding, step 4 edge case for x = 0 with the
sign bit set). The TypeScript wrapper passes that 0 through as
`verify` returning `false`.

### X25519 Montgomery ladder

```typescript
function x25519Ladder(out, scalar, u): void
```

Per RFC 7748 §5, The X25519 and X448 Functions. The scalar
argument is the CLAMPED scalar (callers run `scalarClamp`
beforehand). The u-coord is masked internally via `feFromBytes`.

### Scalar arithmetic

```typescript
function scalarClamp(out, src):           void   // RFC 7748 §5 clamping
function scalarIsCanonical(s):            i32    // 1 iff s < L
function scalarReduce(out, src):          void   // out = src mod L, src ≤ L²
function scalarReduce64(out, src):        void   // out = src mod L, src = 64 LE bytes
function scalarAdd(out, a, b):            void   // out = a + b mod L
function scalarMulAdd(out, a, b, c):      void   // out = a * b + c mod L
```

`scalarReduce64` uses bit-by-bit binary division with a fixed
255-iteration loop and mask-driven helpers `ctSubL33` and
`ctLessThan32`. The L constant `L_LE` is the byte-for-byte
encoding of `L = 2^252 + 27742317777372353535851937790883648493`
from RFC 8032 §5.1, Ed25519; see [Constant-time
Posture](#constant-time-posture) for the L_LE regression-test
note.

### Ed25519 protocol

```typescript
function ed25519Keygen(seedOff, pkOff):                                    void
function ed25519Sign(seedOff, pkOff, msgOff, msgLen, sigOff):              void
function ed25519Verify(pkOff, msgOff, msgLen, sigOff):                     i32
function ed25519SignPrehashed(seedOff, pkOff, digestOff,
                              ctxOff, ctxLen, sigOff):                     void
function ed25519VerifyPrehashed(pkOff, digestOff,
                                ctxOff, ctxLen, sigOff):                   i32
```

The high-level Ed25519 entry points. `ed25519Sign` and
`ed25519SignPrehashed` accept the caller-supplied pk, re-derive
pk from seed internally, and abort via `unreachable` on
mismatch (the fault-injection defence documented in
[ed25519.md](./ed25519.md#fault-injection-defense)).
`ed25519Verify` and `ed25519VerifyPrehashed` return 1 on
success, 0 on every signature failure mode. Every export wipes
the mutable region on the way out.

### X25519 protocol

```typescript
function x25519Keygen(skOff, pkOff):              void
function x25519DH(skOff, peerPkOff, sharedOff):   void
```

Both clamp the caller's secret internally on every call. The
all-zero shared-secret rejection lives at the TypeScript layer
in `X25519.dh`, not here; see
[x25519.md](./x25519.md#all-zero-rejection) for the rationale.

### Buffer wipe

```typescript
function wipeBuffers(): void
```

Zeroes the mutable region from `MUTABLE_START` to `BUFFER_END`.
See [Memory Wiping](#memory-wiping).

---

## Constant-time Posture

**Field arithmetic.** `feAdd`, `feSub`, `feNeg`, `feMul`,
`feSqr`, `feMul121666`, `feFromBytes`, `feToBytes`, and the
helpers operate on i64 limbs via straight-line arithmetic with
no comparisons against secret values. `feCondSwap` and
`feCondNeg` use mask-driven selects rather than branches.

**Edwards point operations.** `edPointDouble`, `edPointAdd`,
`edPointSub`, `edPointEqual`, and `edPointMul` use only
straight-line field arithmetic plus `feCondSwap`. `edPointMul`
runs a fixed 256-bit ladder; the per-bit operation set is
identical regardless of scalar value. `edPointDecompress`
aggregates its success flag across the failure paths and
returns it at the end of the function, so no early branch
discriminates a non-canonical y encoding from an off-curve
point at the call boundary.

**Montgomery ladder.** `x25519Ladder` runs 255 iterations
unconditionally; `feCondSwap` driven by a mask of the current
scalar bit picks `(x2:z2)` or `(x3:z3)` for the ladder step.
No branch reads a secret bit.

**Scalar reduction.** `scalarReduce64` is the most subtle
constant-time path. It runs a fixed-count bit-by-bit binary
division with mask-driven `ctSubL33` (subtract L extended to 33
bytes if the bit budget permits) and `ctLessThan32` (compare 32
bytes), neither of which branches on byte values. The L_LE
constant lives in `scalar.ts` as a byte table; an earlier
implementation transcribed byte 14 as `0x4D` instead of `0xDE`
(the spec value from RFC 8032 §5.1, Ed25519), which
`test/unit/ed25519/scalar_reduce64.test.ts` catches via a
BigInt-oracle cross-check on randomized inputs. Future
transcription errors hit the same regression.

**Ed25519 verify.** `ed25519Verify` and
`ed25519VerifyPrehashed` do not short-circuit on the early
failure paths in a way that reveals attacker-relevant
information. Each early return wipes the mutable region before
exiting; the public values that drive the verify chain (pk, R,
s, message) are not secret, so a timing observer cannot
distinguish "off-curve pk" from "wrong signature equation"
beyond what the spec itself reveals. The library's posture
matches the standard EdDSA implementation discipline.

**Public-data branches are documented.** The L_LE constant's
`lByte(i)` access chain branches on the loop counter `i` (a
public value, not secret). The `dom2Update` helper writes the
F=1 byte and the |C| byte at fixed offsets, both public. The
SHA-512 message schedule indexes message words by round number,
again public.

**No constant-time guarantees on speculative-execution or
microarchitectural side channels.** Per [Architecture, Where
defense ends](./architecture.md#where-defense-ends), the
library does not defend against cache-timing, branch-prediction,
or speculative-execution leaks at the hardware level. Those are
the runtime's and the CPU's responsibility.

---

## Cross-references

- [ed25519.md](./ed25519.md), Ed25519 TypeScript API reference.
- [x25519.md](./x25519.md), X25519 TypeScript API reference.
- [ed25519_audit.md](./ed25519_audit.md), Ed25519 audit checklist.
- [x25519_audit.md](./x25519_audit.md), X25519 audit checklist.
- [architecture.md](./architecture.md), module structure, init contract,
  buffer-layout overview.
- [asm_sha2.md](./asm_sha2.md), sha2 module reference (the SHA-512 in
  `sha512.ts` is a verbatim port from this module's `sha512.ts`).
- [signaturesuite.md](./signaturesuite.md#ed25519-suites), envelope
  wire format and the `Ed25519Suite` / `Ed25519PreHashSuite` consts.
