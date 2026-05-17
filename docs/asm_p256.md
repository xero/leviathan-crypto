<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### `p256` WASM Module Reference

This low-level reference details the p256 AssemblyScript source and
WASM exports, intended for those auditing, contributing to, or
building against the raw module. The TypeScript wrappers for
ECDSA-P256 ship in a later phase of work; this document covers the
substrate only.

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
feIsZero(a):                  i32 - 1 if a == 0, 0 otherwise
feIsEqual(a, b):              i32 - 1 if a == b, 0 otherwise
feIsOdd(a):                   i32 - LSB of canonical encoding (SEC1 parity bit)
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
scalarInv(out, a):            out = a^(-1) mod n via Fermat
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
```

### Scalar multiplication

```
pointMul(scalar, p, out):     out = [scalar] p (variable-base, const-time)
pointMulBase(scalar, out):    out = [scalar] G (fixed-base, const-time)
```

Both use constant-time double-and-add-always over the RCB complete-
addition substrate. The scalar is consumed MSB-first; each bit
drives one `pointDouble` and one masked `pointAdd`. No branches on
secret scalar bits.

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

## Cross-references

| Document | Role |
|----------|------|
| `docs/architecture.md` | Repo-wide architecture, module table, init API |
| `docs/test-suite.md` | Test counts and per-file gates |
| `docs/asm_curve25519.md` | Sister-module substrate reference (pattern source) |
| `SP 800-186 §3.2.1.3` | P-256 parameter definitions (p, n, a, b, Gx, Gy) |
| `FIPS 186-5 §6` | ECDSA signature scheme |
| `RFC 6979` | Deterministic ECDSA |
| `draft-irtf-cfrg-det-sigs-with-noise-05` | Hedged-deterministic K |
| `Hankerson-Menezes-Vanstone §2.4.1, Algorithm 2.27` | P-256 Solinas reduction |
| `Renes-Costello-Batina 2016 (eprint 2015/1060)` | Complete addition formulas |
| `SEC1 v2.0` | Point encoding (compressed / uncompressed) |
