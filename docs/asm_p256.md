<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### `p256` WASM Module Reference

This low-level reference details the p256 AssemblyScript source and
WASM exports, intended for those auditing, contributing to, or
building against the raw module. The TypeScript wrappers for
ECDSA-P256 are documented separately in [ecdsa-p256.md](./ecdsa-p256.md);
this document covers the substrate only.

> ### Table of Contents
> - [Overview](#overview)
> - [Buffer Layout](#buffer-layout)
> - [Module Identity](#module-identity)
> - [Memory Wiping](#memory-wiping)
> - [Source Files](#source-files)
> - [Implementation deep dives](#implementation-deep-dives)
> - [API Reference](#api-reference)
> - [Constant-time Posture](#constant-time-posture)
> - [Cross-References](#cross-references)

---

## Overview

`p256.wasm` is the substrate for ECDSA over NIST P-256 (the curve
specified in SP 800-186 §3.2.1.3, FIPS 186-5 §6). The module hosts
the field arithmetic over GF(p256), the short-Weierstrass projective
point operations using the Renes-Costello-Batina 2016 complete
addition formulas, scalar arithmetic mod n (the base point order),
constant-time scalar multiplication, an embedded SHA-256 +
HMAC-SHA-256 driving RFC 6979 deterministic nonce derivation (with
the hedged-by-default variant from
`draft-irtf-cfrg-det-sigs-with-noise-05`), and the ECDSA sign /
verify entry points.

Key properties of this implementation:

**Static memory only.** All buffers are fixed offsets in linear
memory. The AssemblyScript compiler reserves offsets 0..4095 for its
data segment; mutable regions start at offset 4096 (`MUTABLE_START`)
and end at offset 7054 (`BUFFER_END`). Total memory is 3 pages
(196608 bytes), with the mutable footprint under 3 KB and the
remainder available headroom.

**Scalar (no v128).** P-256 ships without WebAssembly SIMD. The
Solinas reduction (HMV Algorithm 2.27) is a fixed sequence of nine
limb-shuffling terms; lane packing buys nothing because every term
touches a different subset of source limbs. The posture is the same
as curve25519: scalar over SIMD where SIMD does not measurably help.

**8 × u32 saturated field representation.** A field element is 8
u32 limbs at radix 2^32, saturated, totalling 32 bytes per element.
This choice maps directly to SP 800-186 §3.2.1.3 (P-256 prime hex
words) and lets the Solinas reduction follow Hankerson-Menezes-
Vanstone "Guide to Elliptic Curve Cryptography" §2.4.1, Algorithm
2.27 byte-for-byte. The prime's special-form bit positions (96, 192,
224, 256) all fall on limb boundaries, keeping the reduction recipe
auditable line-by-line.

**Non-Montgomery domain.** Inputs and outputs are in the natural
field domain. RustCrypto's `p256` uses a Montgomery representation
for performance; leviathan-crypto deliberately stays outside
Montgomery to keep the field-arithmetic audit story symmetric with
curve25519's non-Montgomery posture, and to keep `feFromBytes` /
`feToBytes` as simple big-endian byte conversions rather than
Montgomery transforms.

**Embedded SHA-256 + HMAC-SHA-256.** The RFC 6979 §3.2 K derivation
runs through internal hash primitives ported verbatim from
`src/asm/sha2/sha256.ts` and `src/asm/sha2/hmac.ts`. The embedded
copies let every signing operation stay inside a single WASM call
rather than crossing the JavaScript / WASM boundary many times per
HMAC chain iteration. The ABI does NOT surface the SHA-256 / HMAC
exports; they are module-internal helpers only.

**Projective short-Weierstrass coordinates.** Points are stored as
`(X : Y : Z)` triples (96 bytes per point) and operated on via the
complete addition formulas from
[Renes-Costello-Batina 2016 (eprint 2015/1060)](https://eprint.iacr.org/2015/1060),
Algorithm 4 (unified add) and Algorithm 6 (dedicated double for
a = -3). Both formulas are complete: they correctly handle the
identity, P = Q, and P = -Q without branches.

**No protocol logic in the substrate above ECDSA.** The field /
scalar / point primitives are pure mathematical operations on
linear-memory offsets. The ECDSA protocol (FIPS 186-5 §6.4 / §6.5)
lives in `ecdsa.ts` compiled into the same binary; higher-level
suite composition (DER, envelope, ctx-binding) is a TypeScript-layer
concern not present in the substrate.

---

## Buffer Layout

Defined in `src/asm/p256/buffers.ts`. All offsets in bytes from
base 0.

```
Offset    Size     Region
─────────────────────────────────────────────────────────────────────
0..4095   4096     AS data segment (reserved)
4096      32       MUL_INT_LO       (low half of mul intermediate)
4128      32       MUL_INT_HI       (high half)
4160      1024     FIELD_TMP        (32 × 32-byte scratch field elements;
                                    slots 0..15 reserved for field.ts
                                    internals, slots 16..31 for point.ts
                                    and other FE-scratch callers)
5184      768      POINT_TMP        (8 × 96-byte scratch projective points)
5952      256      SCALAR_TMP       (8 × 32-byte scratch scalars)
6208      32       HMAC_DRBG_K      (RFC 6979 §3.2 / SP 800-90A K state)
6240      32       HMAC_DRBG_V      (RFC 6979 §3.2 / SP 800-90A V state)
6272      64       ECDSA_SIG_TMP    (raw r || s scratch)
6336      33       ECDSA_PK_CHECK   (compressed-pk fault-check scratch)
6369      33       ECDSA_PK_INPUT   (caller-supplied compressed-pk copy)
6402      32       ECDSA_MSG_HASH   (caller-supplied SHA-256(M))
6434      32       SHA256_H         (SHA-256 state H0..H7)
6466      64       SHA256_BLOCK     (SHA-256 block accumulator)
6530      256      SHA256_W         (SHA-256 message schedule W[0..63])
6786      32       SHA256_OUT       (SHA-256 digest output)
6818      64       SHA256_INPUT     (SHA-256 user-input staging)
6882      4        SHA256_PARTIAL   (u32 partial-block length)
6886      8        SHA256_TOTAL     (u64 total bytes hashed)
6894      64       HMAC256_IPAD     (K' XOR 0x36)
6958      64       HMAC256_OPAD     (K' XOR 0x5C)
7022      32       HMAC256_INNER    (inner hash saved by hmacFinal)
BUFFER_END = 7054 (< 65536 = 1 page; module sized at 3 pages for headroom)
```

Curve parameters (the prime `p`, the curve constant `b`, the
basepoint coordinates `Gx`, `Gy`, and the curve order `n`) are NOT
stored in mutable linear memory. They live as `@inline const u32`
or `@inline const u8` values in `field.ts`, `scalar.ts`, and
`point.ts`. Inlining via the AS data segment would risk the segment
moving across builds and breaking the buffer-layout audit, per the
locked decision recorded in `buffers.ts`.

---

## Module Identity

```
getModuleId():        i32   // 9 (ct=0, serpent=0, chacha20=1, aes=1,
                            //    sha2=2, sha3=3, blake3=4, kyber=5,
                            //    mldsa=6, slhdsa=7, curve25519=8)
getMemoryPages():     i32   // current WASM linear-memory page count
```

The module ID is informational; the cipher modules collide on the
low IDs (ct=0, serpent=0 etc.). The TypeScript loader does not use
the ID as a unique key.

---

## Memory Wiping

```
wipeBuffers():        void
```

Zeros every byte from `MUTABLE_START` (4096) to `BUFFER_END` (7054),
clearing all scratch field elements, scratch points, scratch
scalars, HMAC_DRBG K / V state, embedded SHA-256 streaming state,
and ECDSA fault-check buffers. The AS data segment at offsets
0..4095 is preserved.

Per AGENTS.md §"Wipe discipline", every public ECDSA entry point
calls this internally on the success path AND on every early return
or trap. The TypeScript layer's `dispose()` should also call
`wipeBuffers()` for defence in depth; the substrate's own clean-up
already covers the secret-bearing scratch.

---

## Source Files

| File | Role |
|------|------|
| `buffers.ts` | Static linear-memory layout, region offsets, `MUTABLE_START` / `BUFFER_END` |
| `field.ts` | GF(p256) field arithmetic with HMV §2.4.1 Algorithm 2.27 Solinas reduction |
| `scalar.ts` | Scalar arithmetic mod n (curve order), strict-S helpers, RFC 6979 § "bits2octets" |
| `point.ts` | Projective points, Renes-Costello-Batina 2016 Algorithm 4 (add) + Algorithm 6 (double) |
| `scalar_mult.ts` | Constant-time variable-base + fixed-base scalar multiplication |
| `sha256.ts` | SHA-256 verbatim port from `src/asm/sha2/sha256.ts` (RFC 6979 dependency) |
| `hmac_sha256.ts` | HMAC-SHA-256 verbatim port from `src/asm/sha2/hmac.ts` |
| `rfc6979.ts` | RFC 6979 §3.2 deterministic + draft-irtf-cfrg-det-sigs-with-noise-05 hedged K |
| `ecdsa.ts` | FIPS 186-5 §6.4 sign / §6.5 verify / §A.4 keygen entry points |
| `index.ts` | Public export barrel + `wipeBuffers()` |

Both `sha256.ts` and `hmac_sha256.ts` are byte-equivalent to the
corresponding sha2 module files modulo buffer-offset imports.
Deviation list:

1. Buffer offset imports rewritten to `./buffers` (p256 local memory
   layout). Offset constant NAMES preserved.
2. SHA-224 IV constants and entry points stripped (ECDSA-P256 +
   SHA-256 only).
3. Module-internal `sha256UpdateBytes(src, len)` appended for chunked
   updates over arbitrary memory offsets, used by the RFC 6979
   K-derivation hot path.

These files are NOT re-exported from `index.ts`. They are
substrate-internal: the public ABI exposes ECDSA sign / verify
only, mirroring the curve25519 sha512 posture.

---

## Implementation deep dives

### feInv chain

`feInv(a) = a^(p - 2) mod p` per Fermat's little theorem. The
exponent is public:

```
p - 2 = 2^256 - 2^224 + 2^192 + 2^96 - 3
```

per SP 800-186 §3.2.1.3.

The implementation runs a constant-time square-and-multiply scan
from MSB to LSB of `p - 2`. Each step always squares and always
multiplies into a scratch slot; a mask-driven select copies the
product back into the accumulator only when the exponent bit is
set. Total cost is 256 squarings plus 256 multiplications per call.

A shorter addition chain exists: roughly 14 multiplications plus
the same 256 squarings, following the RustCrypto `p256` recipe
that decomposes the exponent into nested chunks.

| Step | Definition           | Exponent       |
|------|----------------------|----------------|
| z2   | `a^2`                | `a^2`          |
| z3   | `z2 * a`             | `a^3`          |
| z6   | `z3^(2^3) * z3`      | `a^(2^6 - 1)`  |
| z12  | `z6^(2^6) * z6`      | `a^(2^12 - 1)` |
| z15  | `z12^(2^3) * z3`     | `a^(2^15 - 1)` |
| z30  | `z15^(2^15) * z15`   | `a^(2^30 - 1)` |

The substrate ships the binary scan instead. Every step is
verifiable line-by-line against the hex form of `p` from
SP 800-186 §3.2.1.3, and the cost difference is dwarfed by the
call rate at the suite layer; `feInv` runs once per `pointAffinify`
and once per scalar inversion in the verify path.

The exponent loads into a 32-byte scratch slot (`FIELD_TMP[4]`) in
little-endian limb form. `limb[0]` ends in `0xFFFFFFFD` because
`p mod 2^32 = 0xFFFFFFFF` and `p - 2` subtracts 2 from the LSB
without borrow.

### feSqrt exponent

`feSqrt(a) = a^((p + 1) / 4) mod p`, the standard square-root
candidate for primes `p ≡ 3 (mod 4)`. P-256's prime ends in
`...FFFFFFFF`, so `p mod 4 = 3`.

Derivation from SP 800-186 §3.2.1.3:

```
p          = 2^256 - 2^224 + 2^192 + 2^96 - 1
p + 1      = 2^256 - 2^224 + 2^192 + 2^96
(p + 1)/4  = 2^254 - 2^222 + 2^190 + 2^94
```

Expand `2^254 - 2^222 = 2^222 * (2^32 - 1)` to get bits 222..253 set.
Add `2^190` for bit 190; add `2^94` for bit 94. The bit set of
`(p + 1) / 4` is `{94, 190} ∪ {222..253}`.

The internal little-endian 8 × u32 limb form (`limb[i]` holds bits
`32i .. 32i + 31`):

| limb | value        | bits contributed |
|------|--------------|------------------|
| 0    | `0x00000000` | -                |
| 1    | `0x00000000` | -                |
| 2    | `0x40000000` | bit 94           |
| 3    | `0x00000000` | -                |
| 4    | `0x00000000` | -                |
| 5    | `0x40000000` | bit 190          |
| 6    | `0xC0000000` | bits 222, 223    |
| 7    | `0x3FFFFFFF` | bits 224..253    |

The 32-byte big-endian encoding cross-checks against external test
vectors:

```
3FFFFFFF C0000000 40000000 00000000 00000000 00000000 00000000 00000000
```

The implementation runs the same constant-time square-and-multiply
scan as [`feInv`](#feinv-chain), MSB to LSB, over this 256-bit
exponent.

> [!CAUTION]
> Quadratic non-residue inputs produce a candidate that does not
> square back to the input. Callers (point decompression) must
> verify by squaring.

### SIMD posture

Parallel to
[curve25519's SIMD posture](./asm_curve25519.md#simd-posture).

The P-256 substrate ships scalar. The WASM binary emits no v128
instructions.

The HMV §2.4.1 Algorithm 2.27 Solinas reduction is a fixed sequence
of nine 8-limb terms summed and subtracted into a 9-limb
accumulator. Each term touches a different subset of source limbs,
so lane packing buys nothing; there is no four-wide independent
multiply structure for v128 to exploit, and the reduction phase
itself is sequential.

AssemblyScript's `i64x2.extmul_low_i32x4` / `extmul_high_i32x4`
(paired `32 × 32 → 64`) does not pay off over scalar `i64.mul` for
the 256-bit Solinas reduction. The scalar-vs-extmul tradeoff is the
same one described in
[curve25519's SIMD posture](./asm_curve25519.md#simd-posture).
P-256 lands in the same scalar bucket.

### Representation choice

Complements the "8 × u32 saturated field representation" bullet in
[Overview](#overview).

Field elements are 8 × u32 limbs at radix `2^32`, saturated. Inputs
and outputs cross the WASM boundary in 32-byte big-endian form
(FIPS 186-5 §6, SEC1 §2.3.3 and §2.3.6). `feFromBytes` and
`feToBytes` are simple radix conversions, not Montgomery transforms.

The prime's special-form bit positions per SP 800-186 §3.2.1.3 all
fall on limb boundaries:

| bit | limb |
|-----|------|
| 96  | 3    |
| 192 | 6    |
| 224 | 7    |
| 256 | 8 (carry) |

That alignment keeps the HMV §2.4.1 Algorithm 2.27 Solinas reduction
recipe auditable line-by-line against the published table.

**Non-Montgomery posture is locked.** RustCrypto's `p256` uses a
Montgomery representation for performance. leviathan-crypto stays
outside Montgomery for two reasons:

- Keep the field-arithmetic audit story symmetric with curve25519,
  which is also non-Montgomery.
- Keep `feFromBytes` and `feToBytes` as direct radix conversions
  rather than `R^-1` / `R` transforms.

Cost is a single reduction per `feMul` rather than a Montgomery
REDC. The benefit is that every limb value in WASM linear memory
at any point in execution is directly interpretable as the
natural-domain field element.

### Verify timing

`ecdsaVerify` is not constant-time across its reject branches. Each
gate (`r, s ∈ [1, n - 1]`, low-S, pk decompression, on-curve
check, signature equation) early-returns on failure, so the
wall-clock cost of a reject reveals which gate fired.

This is intentional. Every input to `ecdsaVerify` (`pk`, `msgHash`,
`sig`) is public, attacker-observable on the wire, and not derived
from any secret state held by this library. A timing channel
between the gates discloses nothing the attacker cannot already
see.

The library's constant-time discipline applies only to operations
on secret inputs:

- `d`, the private scalar.
- `k` and `k^{-1}`, the per-call nonce.
- HMAC-DRBG `(K, V)` state from RFC 6979 §3.2.

Verify inputs do not qualify, so they do not constrain the gate
structure. FIPS 186-5 §6.5, §6.5.2, and §6.5.3 specify the gates
themselves; the spec does not impose a timing requirement on them.

### Aliasing gotchas

Several `point.ts` helpers operate on caller-supplied output pointers
that may legally alias the function's own scratch slots. Choice of
scratch slot is a correctness gate, not a performance one.

| Function       | Internal scratch        | Aliasing rule                              |
|----------------|-------------------------|--------------------------------------------|
| `pointAffinify`| `zInv` in `POINT_TMP[7]`| Caller may pass `outX = FIELD_TMP[k]`; `zInv` must NOT share a `FIELD_TMP` slot. |
| `pointCompress`| `xAff`, `yAff` in `FIELD_TMP[16..17]` (`XX`, `YY`)| Must NOT alias `TMP1` / `TMP2`; those are reserved for `pointAffinify`'s `zInv` write. |

> [!CAUTION]
> The aliasing rules above are correctness-load-bearing. A wrong
> scratch slot produces silently incorrect outputs, not a trap or
> a verify failure, because the intermediate corruption stays
> inside well-formed field elements.

**`pointAffinify` zInv slot.** `pointAffinify(p, outX, outY)` inverts
`Z` once and then runs two `feMul` calls:

```
zInv = Z^{-1}
outX = X * zInv
outY = Y * zInv
```

`zInv` must live in `POINT_TMP` slot 7 (the `Z_OUT` alias), not in
any `FIELD_TMP` slot. If `zInv` shared a `FIELD_TMP` slot, a caller
passing `outX = FIELD_TMP[k]` would let the first `feMul` overwrite
`zInv` before the second `feMul` reads it, silently producing
`outY = Y * X * zInv` instead of `Y * zInv`. `POINT_TMP` slot 7 is
reserved for `pointAdd` / `pointDouble` internal staging;
`pointAffinify` does not call those, so re-using it is safe.

**`pointCompress` xAff / yAff slots.** `pointCompress` writes `xAff`
and `yAff` into `FIELD_TMP` slots 16 and 17 (`XX` and `YY`). These
slots do not alias the `TMP1` slot that `pointAffinify` uses for
`zInv`. Picking `TMP1` or `TMP2` here would alias `zInv` and
silently corrupt `yAff`: `pointAffinify`'s second `feMul` would read
`zInv` from a slot the first `feMul` had already overwritten.

---

## API Reference

### Field arithmetic

All operations are constant-time, mask-driven where conditionals
appear, and produce canonical-reduced 8 × u32 limb outputs.
`feFromBytes` / `feToBytes` use big-endian byte order per FIPS
186-5 / SEC1 §2.3.5 conventions; the internal limb form is
little-endian (limb[0] is the LSB).

```
feAdd(out, a, b):             out = a + b (mod p)
feSub(out, a, b):             out = a - b (mod p)
feNeg(out, a):                out = -a (mod p)
feMul(out, a, b):             out = a * b (mod p)
feSqr(out, a):                out = a^2 (mod p)
feInv(out, a):                out = a^(-1) (mod p) via Fermat's little theorem
feSqrt(out, a):               out = a^((p+1)/4) (mod p); valid sqrt iff a is QR
feFromBytes(out, src32):      decode 32 BE bytes to limbs
feToBytes(out, src):          encode limbs as 32 BE bytes
loadB(dst):                   write the SEC P-256 curve constant b to dst (8 LE limbs)
feIsZero(a):                  i32 - 1 if a == 0, 0 otherwise
feIsEqual(a, b):              i32 - 1 if a == b, 0 otherwise
feIsOdd(a):                   i32 - LSB of canonical encoding (SEC1 parity bit)
feIsCanonical(a):             i32 - 1 if a < p, 0 otherwise (strict-decode gate)
feCondSwap(a, b, swap):       conditional XOR-mask swap
feCondNeg(out, a, neg):       out = (neg ? -a : a) (mod p)
```

### Scalar arithmetic (mod n)

All operations are constant-time. Byte order is big-endian (FIPS
186-5 §6 wire form). The mod-n reductions use bit-by-bit binary
division, mirroring `curve25519`'s scalar.ts pattern with `n`
substituted for `L`.

```
scalarFromBytes(out, src):    copy 32 BE bytes (no validation)
scalarToBytes(out, src):      copy 32 BE bytes
scalarIsCanonical(s):         i32 - 1 if s ∈ [0, n), 0 otherwise
scalarIsZero(s):              i32 - 1 if s == 0, 0 otherwise
scalarIsHighS(s):             i32 - 1 if s > n/2 (low-S enforcement check)
scalarReduce(out, src32):     out = src mod n
scalarReduce64(out, src64):   out = src mod n (64-byte BE input)
scalarAdd(out, a, b):         out = (a + b) mod n
scalarSub(out, a, b):         out = (a - b) mod n
scalarMul(out, a, b):         out = (a * b) mod n
scalarNegate(out, a):         out = (n - a) mod n
scalarInv(out, a):            out = a^(-1) mod n via Bernstein-Yang
                              safegcd, 743 divsteps (eprint 2019/266
                              §11). Constant-time over secret a.
                              See p256_perf.md §Change 4.
```

### Projective points + complete addition

```
pointZero(out):               write the identity element (0:1:0)
pointBasepoint(out):          write G from SP 800-186 §3.2.1.3
pointAdd(out, p, q):          out = p + q (RCB 2016 Algorithm 4, a = -3)
pointDouble(out, p):          out = 2p (RCB 2016 Algorithm 6, a = -3)
pointSub(out, p, q):          out = p - q (negate q then add)
pointNegate(out, p):          out = -p (X : -Y : Z)
pointEqual(p, q):             i32 - 1 if projective-equivalent
pointOnCurve(p):              i32 - 1 if Y² Z = X³ - 3 X Z² + b Z³
pointAffinify(p, outX, outY): write affine x = X / Z, y = Y / Z
pointCompress(out, p):        write 33-byte SEC1 §2.3.3 compressed form
pointDecompress(out, src):    i32 - 1 on success, 0 on invalid input
                              (rejects prefix not in {0x02, 0x03},
                              non-canonical x >= p via feIsCanonical,
                              and y² quadratic non-residue)
```

### Scalar multiplication

```
pointMul(scalar, p, out):              out = [scalar] p
                                       (variable-base, const-time)
pointMulBase(scalar, out):             out = [scalar] G
                                       (fixed-base, const-time)
pointMulDoubleVerify(u1, u2, Q, out):  out = [u1] G + [u2] Q
                                       (Strauss-Shamir, verify-only)
```

`pointMul` and `pointMulBase` use constant-time double-and-add-always
over the RCB complete-addition substrate. The scalar is consumed
MSB-first; each bit drives one `pointDouble` and one masked
`pointAdd`. No branches on secret scalar bits.

`pointMulDoubleVerify` is the Strauss-Shamir simultaneous double scalar
multiplication: a single 256-iteration ladder that shares one
`pointDouble` per bit across both scalars and conditionally adds one of
four precomputed combinations `{O, Q, G, G+Q}` based on the bit pair
`(u1_bit, u2_bit)`. NOT constant-time across the bit-pair selector;
verify is documented non-CT (see [§Verify timing](#verify-timing)) and
ECDSA verify inputs are public on the wire, so the four-entry table is
indexed by PUBLIC bits and remains outside the architectural prohibition
on secret-bit-indexed tables. The function is called once per
`ecdsaVerify` invocation and replaces the prior
`pointMulBase(u1) + pointMul(u2, Q) + pointAdd` triplet. See
[p256_perf.md](./p256_perf.md#change-2-strauss-shamir-verify) for the
bench delta.

### RFC 6979 K derivation

```
deriveKDeterministic(d, msgHash, kOut):
    RFC 6979 §3.2 verbatim. Reproduces RFC §A.2.5 expected k values
    byte-for-byte. Inputs d, msgHash are 32 BE bytes; kOut writes
    32 BE bytes ∈ [1, n-1].

deriveKHedged(d, msgHash, rnd, kOut):
    draft-irtf-cfrg-det-sigs-with-noise-05 §4 hedged variant. Per
    the draft's intentional domain-separation, rnd = all-zero is
    NOT byte-equivalent to the deterministic path.
```

### ECDSA high-level operations

```
ecdsaKeygen(seedOff, pkOff):
    d = seed mod n (FIPS 186-5 §A.4.2 testing-candidates with a
    single candidate; traps if seed mod n == 0). pk = [d]G
    compressed per SEC1 §2.3.3 (33 bytes at pkOff).

ecdsaSign(skOff, pkOff, msgHashOff, rndOff, sigOff):
    FIPS 186-5 §6.4 sign with hedged-or-deterministic K:
       rnd all-zero  → RFC 6979 §3.2 deterministic
       rnd otherwise → draft-irtf-cfrg-det-sigs-with-noise-05 hedged
    Always normalises s to low-S per RFC 6979 §3.5. Re-derives pk
    via [d]G post-sign and compares to caller's pkOff byte-for-byte;
    mismatch wipes the mutable region and traps via `unreachable`,
    mirroring the Ed25519 fault-injection defence.
    Output: 64 bytes raw r || s at sigOff.

ecdsaSignInternalPk(skOff, msgHashOff, rndOff, sigOff):
    Suite-only entry. Derives pk internally and skips the fault-
    injection cross-check, saving one fixed-base scalar mult.
    Mirrors `ed25519SignInternalPk`.

ecdsaVerify(pkOff, msgHashOff, sigOff): i32
    FIPS 186-5 §6.5 verify with the strict-S posture. Returns 1
    on accept, 0 on any reject path: pk decompression failure,
    pk is the identity, r ∉ [1, n-1] or s ∉ [1, n-1], s > n/2
    (high-S strict-gate), or the signature equation r ≡ x(u1*G +
    u2*Q) mod n fails.
```

---

## Constant-time Posture

Every operation that consumes secret-bearing data (the scalar d,
the per-call nonce k, the HMAC_DRBG K / V state, intermediate
scalar mult points) runs a fixed-length loop with mask-driven
conditional selects. No branches on secret bytes, no early returns,
no table lookups indexed by secret bits.

Specific dispatchers that branch on PUBLIC (non-secret) inputs:

- `ecdsaSign` branches on `isAllZero32(rnd)` to choose deterministic
  vs hedged K derivation. `rnd` is caller-supplied entropy with a
  public mode-selection role; the branch leaks the dispatcher
  choice, not any secret-key bits.
- `ecdsaVerify` is wholly public; constant-time is not a security
  requirement but the substrate maintains it anyway for
  implementation simplicity.
- `pointDecompress` returns 0/1 based on a prefix byte and curve-
  equation residue check. Both are public.

---

## Cross-References

| Document | Role |
|----------|------|
| [index](./README.md) | Project Documentation index |
| [asm_imports.md](./asm_imports.md) | Per-module AssemblyScript import dependency graphs |
| [`test-suite.md`](./test-suite.md) | Test counts and per-file gates |
| [`asm_curve25519.md`](./asm_curve25519.md) | Sister-module substrate reference (pattern source) |
| [`SP 800-186 §3.2.1.3`](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) | P-256 parameter definitions (p, n, a, b, Gx, Gy) |
| [`FIPS 186-5 §6`](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) | ECDSA signature scheme |
| [`RFC 6979`](https://www.rfc-editor.org/rfc/rfc6979) | Deterministic ECDSA |
| [`draft-irtf-cfrg-det-sigs-with-noise-05`](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-det-sigs-with-noise-05) | Hedged-deterministic K |
| [`Hankerson-Menezes-Vanstone §2.4.1, Algorithm 2.27`](https://link.springer.com/book/10.1007/b97644) | P-256 Solinas reduction |
| [`Renes-Costello-Batina 2016 (eprint 2015/1060)`](https://eprint.iacr.org/2015/1060) | Complete addition formulas |
| [`SEC1 v2.0`](https://www.secg.org/sec1-v2.pdf) | Point encoding (compressed / uncompressed) |
