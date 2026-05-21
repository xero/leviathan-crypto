<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### `mldsa` ML-DSA WASM Module Reference

This low-level reference details the ML-DSA AssemblyScript source and WASM
exports, intended for those auditing, contributing to, or building against
the raw module. **Most consumers should instead use the
[TypeScript wrapper](./mldsa.md).**

> ### Table of Contents
> - [Overview](#overview)
> - [Buffer Layout](#buffer-layout)
> - [Module Identity](#module-identity)
> - [Memory Wiping](#memory-wiping)
> - [Source Files](#source-files)
> - [API Reference](#api-reference)
> - [Constant-time Posture](#constant-time-posture)

---

## Overview

This module implements the polynomial-arithmetic, encoding, sampling, and
rounding primitives needed for ML-DSA (FIPS 204), as a standalone
WebAssembly binary compiled from AssemblyScript. ML-DSA is the NIST
post-quantum signature standard published as FIPS 204; the underlying scheme
is Dilithium.

The implementation is `(k, ℓ)`-parameterized: a single `mldsa.wasm` serves
all three FIPS 204 parameter sets (44/65/87). The TypeScript wrapper
selects the parameter set per call by passing `k` and `ℓ` (and other
runtime parameters) as arguments to the polyvec/encoding kernels.

| Parameter Set | k | ℓ | η | NIST Security |
|---------------|---|---|---|---------------|
| ML-DSA-44     | 4 | 4 | 2 | Category 2    |
| ML-DSA-65     | 6 | 5 | 4 | Category 3    |
| ML-DSA-87     | 8 | 7 | 2 | Category 5    |

Key properties of this implementation:

**Static memory only.** All buffers are fixed offsets in linear memory.
The AS compiler places the `zetas` `StaticArray<i32>` (256 × 4 B = 1024 B)
in the data segment at low memory; mutable regions start at offset 4096.
No `memory.grow()`, no heap allocation. Total memory: 4 pages (256 KiB).

**SIMD by default for NTT and poly arithmetic.** `ntt`, `invntt`,
`poly_add`, `poly_sub`, `poly_reduce`, `poly_caddq`, and
`poly_pointwise_montgomery` resolve to SIMD implementations (4-lane i32×4
butterflies / lane-parallel arithmetic). Scalar variants are exported as
`*_scalar` for cross-checks. Some kernels (`poly_freeze`, `poly_chknorm`,
the encoding/sampling/rounding paths) remain scalar, see CT-posture
notes per file.

**i32 coefficients.** ML-DSA's prime `q = 2²³ − 2¹³ + 1 = 8380417` does
not fit in i16, so polynomials are stored as 256 × i32 = 1024 bytes each.
Compare to kyber, where i16 suffices.

**No protocol-level logic in WASM.** Algorithm 6 (KeyGen), Algorithm 7
(Sign), Algorithm 8 (Verify) are all TS-orchestrated. The WASM module
exports the kernels these algorithms compose: matrix expansion,
rejection sampling, polynomial multiplication, rounding, encoding.

---

## Buffer Layout

Defined in `src/asm/mldsa/buffers.ts`. All offsets in bytes from base 0.

```
Offset    Size      Region
─────────────────────────────────────────────────────────────────────
0..4095   4096      AS data segment (zetas table, 256 × i32 = 1024 B)
4096      8192      POLY_SLOTS    (8 × 1024, POLY_SLOT_0..7 scratch polys)
12288     65536     MATRIX_SLOT   (matrix Â, k×ℓ max = 8×8 polys × 1024)
77824     65536     POLYVEC_SLOTS (8 × 8192, POLYVEC_SLOT_0..7, k=8 max)
143360    128       SEED_OFFSET   (ρ ‖ ρ′ ‖ K, H(ξ‖k‖ℓ, 128) lands here)
143488    64        TR_OFFSET     (tr = H(pk, 64))
143552    64        MSG_REP_OFFSET (μ, message representative)
143616    64        C_TILDE_OFFSET (signature commitment hash, ≤ λ/4)
143680    64        (alignment / reserved)
143744    2624      PK_OFFSET     (≥ 2592 for ML-DSA-87)
146368    4928      SK_OFFSET     (≥ 4896 for ML-DSA-87)
151296    4736      SIG_OFFSET    (≥ 4627 for ML-DSA-87)
156032    8192      XOF_PRF_OFFSET (SHAKE squeeze landing zone)
164224..262143      reserved (97920 bytes free)
```

`POLY_SLOT_7` is reserved as scratch by `polyvec_pointwise_acc_montgomery`
(the inner-product helper). Callers MUST NOT pass `POLY_SLOT_7` as the
result, matrix row, or vector argument to that function or to its caller
`polyvec_matrix_pointwise_montgomery`.

`MATRIX_SLOT` is rounded up to 8 × 8 = 64 polys for clean addressing
even though no parameter set uses k = ℓ = 8 simultaneously (ML-DSA-87
is k=8, ℓ=7 = 56 polys). Row-major: row i column j sits at
`MATRIX_SLOT + (i · ℓ + j) · 1024`.

---

## Module Identity

```typescript
function getModuleId(): i32     // returns 6
function getMemoryPages(): i32  // returns 4
```

---

## Memory Wiping

```typescript
function wipeBuffers(): void
```

`memory.fill(4096, 0, 160128)`, zeroes the entire mutable region in one
pass. Covers all poly slots, the matrix slot, polyvec slots, byte buffers
(seed/tr/μ/c̃/pk/sk/sig), and the XOF/PRF scratch.

The `zetas` data segment (offsets 0-4095) is not wiped. It is a
compile-time constant.

The TypeScript wrapper calls `wipeBuffers()` in `MlDsaBase.dispose()`.
Per-op secret residue is also wiped at the end of each public method;
`wipeBuffers()` is the broader sweep at instance teardown.

---

## Source Files

| File              | Contents                                                                                             |
|-------------------|------------------------------------------------------------------------------------------------------|
| `buffers.ts`      | Static buffer offsets, `wipeBuffers`, module identity getters.                                       |
| `params.ts`       | Ring-level constants: `Q`, `N`, `D`, `QINV`, `F_MONT`, `BARRETT_V`. (k/ℓ/η/τ/etc. are TS-side.)      |
| `reduce.ts`       | `montgomery_reduce`, `barrett_reduce`, `fqmul`, FIPS 204 Algorithm 49 + §2.3.                       |
| `ntt.ts`          | Scalar NTT/INTT (FIPS 204 Algorithms 41/42), zetas table, `BitRev8`.                                 |
| `ntt_simd.ts`     | SIMD NTT/INTT, 4-lane i32 butterflies. Public `ntt`/`invntt` resolve to SIMD.                       |
| `poly.ts`         | Scalar `poly_add/sub/reduce/caddq/pointwise_montgomery`, `poly_freeze`, `poly_chknorm`, `poly_tomont`.|
| `poly_simd.ts`    | SIMD-vectorised counterparts. Public `poly_add/sub/...` resolve to SIMD.                             |
| `polyvec.ts`      | k-/ℓ-iterated polyvec wrappers + matrix-vector multiply + rounding wrappers + hint popcount.         |
| `encoding.ts`     | `simple_bit_pack/unpack` (Alg 16/18), `bit_pack/unpack` (Alg 17/19), `hint_bit_pack/unpack` (Alg 20/21). |
| `rounding.ts`     | `power2round`, `decompose`, `highbits`, `lowbits`, `make_hint`, `use_hint` (FIPS 204 Algs 35-40).    |
| `sampling.ts`     | `rej_ntt_poly` (Alg 30), `rej_bounded_poly` (Alg 31), `sample_in_ball` (Alg 29).                     |
| `index.ts`        | Public exports re-exposed from the files above.                                                      |

---

## API Reference

### Buffer offset getters

`getPolySlotBase`, `getPolySlotSize`, `getPolySlot0..7`,
`getMatrixSlot`, `getMatrixSlotSize`,
`getPolyvecSlotBase`, `getPolyvecSlotSize`, `getPolyvecSlot0..7`,
`getSeedOffset`, `getTrOffset`, `getMsgRepOffset`, `getCTildeOffset`,
`getPkOffset`, `getSkOffset`, `getSigOffset`, `getXofPrfOffset`.

### Reduction

```typescript
function montgomery_reduce(a: i64): i32   // a · 2⁻³² mod q (centered)
function barrett_reduce(a: i32): i32       // centered Barrett, |output| < q/2
function fqmul(a: i32, b: i32): i32        // = montgomery_reduce(a · b)
```

### NTT

```typescript
function ntt(polyOff: i32): void           // FIPS 204 Algorithm 41 (SIMD)
function invntt(polyOff: i32): void        // FIPS 204 Algorithm 42 (SIMD)
function ntt_scalar(polyOff: i32): void    // scalar reference
function invntt_scalar(polyOff: i32): void // scalar reference
function getZeta(i: i32): i32              // zetas[i] (Montgomery form)
function getZetasOffset(): i32             // byte offset of zetas[0]
function BitRev8(m: i32): i32              // FIPS 204 Algorithm 43
```

### Polynomial arithmetic

```typescript
function poly_add(rOff, aOff, bOff): void                // c = a + b (SIMD)
function poly_sub(rOff, aOff, bOff): void                // c = a − b (SIMD)
function poly_reduce(polyOff): void                       // centered Barrett (SIMD)
function poly_caddq(polyOff): void                        // centered → [0, q-1] (SIMD)
function poly_pointwise_montgomery(rOff, aOff, bOff): void // c[i] = MR(a[i]·b[i]) (SIMD)
function poly_freeze(polyOff): void                       // canonicalise to [0, q-1]
function poly_chknorm(polyOff, bound): i32                // 1 iff |w_i| ≥ bound
function poly_tomont(polyOff): void                       // p[i] ← p[i]·R mod q
```

Scalar counterparts: `poly_add_scalar`, `poly_sub_scalar`,
`poly_reduce_scalar`, `poly_caddq_scalar`,
`poly_pointwise_montgomery_scalar`.

### Polyvec wrappers

`polyvec_add/sub/reduce/caddq/freeze/tomont/ntt/invntt`,
`polyvec_pointwise_montgomery`, `polyvec_pointwise_acc_montgomery`,
`polyvec_matrix_pointwise_montgomery`,
`polyvec_chknorm`, `polyvec_power2round`, `polyvec_decompose`,
`polyvec_highbits`, `polyvec_lowbits`, `polyvec_make_hint` (returns
popcount), `polyvec_use_hint`.

### Encoding

```typescript
function simple_bit_pack(rByteOff, polyOff, bitlen): void   // Alg 16
function bit_pack(rByteOff, polyOff, a, b): void             // Alg 17
function simple_bit_unpack(polyOff, vByteOff, bitlen): void  // Alg 18
function bit_unpack(polyOff, vByteOff, a, b): void           // Alg 19
function hint_bit_pack(rByteOff, hPvOff, k, omega): void     // Alg 20
function hint_bit_unpack(hPvOff, vByteOff, k, omega): i32    // Alg 21 (-1 on malformed)
```

`hint_bit_unpack` returns −1 on any of the three SUF-CMA-critical
malformed-input cases (FIPS 204 §D.3 / Alg 21 lines 4, 9, 17).

### Rounding

```typescript
function power2round(r1Off, r0Off, aOff): void                  // Alg 35
function decompose(r1Off, r0Off, aOff, gamma2): void            // Alg 36
function highbits(rOff, aOff, gamma2): void                     // Alg 37
function lowbits(rOff, aOff, gamma2): void                      // Alg 38
function make_hint(hOff, zOff, rOff, gamma2): void              // Alg 39
function use_hint(rOff, hOff, aOff, gamma2): void               // Alg 40
```

All rounding kernels expect canonical-residue inputs in [0, q−1].
Apply `polyvec_caddq` (or `poly_caddq`) before calling these on any
polyvec/poly that may carry centered residues.

### Sampling

```typescript
function rej_ntt_poly(polyOff, ctrStart, bufOff, bufLen): i32       // Alg 30
function rej_bounded_poly(polyOff, ctrStart, bufOff, bufLen, eta): i32 // Alg 31
function sample_in_ball(polyOff, signsOff, posBytesOff, posBytesLen, tau, startI): i32 // Alg 29
```

All three are resumable: callers feed XOF blocks one at a time and
accumulate `ctrStart` until N=256 coefficients are accepted (or τ for
`sample_in_ball`). The loop body is data-dependent on the public XOF
output stream, see CT-posture notes.

---

## Constant-time Posture

**Coefficient arithmetic.** `montgomery_reduce`, `barrett_reduce`, and
`fqmul` are branch-free: only integer +, −, ×, and shift on input
operands, no comparisons against secret values. The SIMD paths use
`v128` intrinsics with no lane-conditional operations.

**Rejection sampling.** `rej_ntt_poly` operates on bytes from the public
seed ρ; data-dependent branching here leaks nothing about secret values
(the matrix Â is a public output of ExpandA). `rej_bounded_poly`
operates on bytes from the secret seed ρ′, but the acceptance rate is
uniform over each input byte regardless of seed value, the per-byte
branch leaks only public information about ρ′-derived bytes the SHAKE
output happens to land on. The Dilithium reference makes the same
trade-off; FIPS 204 §7.3 endorses it.

**SampleInBall.** Branches on bytes derived from c̃, the signature
commitment hash. c̃ is published in the signature and reconstructable by
the verifier, branching here reveals only public information.

**Norm check.** `poly_chknorm` short-circuits on the first
over-bound coefficient. The leak is the same observable rejection
restart pattern that ML-DSA's signing loop already exposes: signer
re-runs the loop on bound failure, attacker observes restart timing.
Documented in source.

**Decode.** `bit_unpack` and `simple_bit_unpack` read public bytes
linearly with no data-dependent branches.

**Memory wipes.** `wipeBuffers()` issues a single bulk `memory.fill`
covering the entire mutable region.

All constant-time properties in this section are algorithm-level. See
[architecture.md §Where defense ends](./architecture.md#where-defense-ends)
for the hardware-level disclaim.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [mldsa.md](./mldsa.md) | `MlDsa44`, `MlDsa65`, `MlDsa87`: ML-DSA digital signatures (FIPS 204), pure mode and HashML-DSA |
| [mldsa_audit.md](./mldsa_audit.md) | ML-DSA FIPS 204 prehashed-input surface audit |
| [asm_imports.md](./asm_imports.md) | Per-module AssemblyScript import dependency graphs |
