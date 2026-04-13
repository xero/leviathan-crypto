# `kyber` ML-KEM WASM Module Reference

> [!IMPORTANT]
> This low-level reference details the Kyber AssemblyScript source and WASM
> exports, intended for those auditing, contributing to, or building against
> the raw module. Most consumers, however, should instead use the TypeScript
> wrapper classes (see the [TypeScript API reference](./kyber.md) or the
> higher-level [`Seal` and `SealStream` using `kybersuite` AEAD
> guide](./aead.md#kybersuite)).

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Buffer Layout](#buffer-layout)
> - [Internal Architecture](#internal-architecture)
> - [Error Conditions](#error-conditions)

---

## Overview

This module implements ML-KEM (Module-Lattice-Based Key-Encapsulation
Mechanism) as a standalone WebAssembly binary compiled from AssemblyScript.
ML-KEM is the NIST post-quantum KEM standard, published as FIPS 203. The
underlying scheme is Kyber: a structured-lattice KEM based on the hardness of
the Module Learning With Errors (M-LWE) problem.

The implementation is k-parameterized, supporting all three FIPS 203 parameter
sets from a single binary. You select the parameter set at the TypeScript layer
by passing the appropriate k value; the WASM module contains the full
arithmetic for all variants.

| Parameter Set | k | Security Category |
|---------------|---|-------------------|
| ML-KEM-512    | 2 | Category 1        |
| ML-KEM-768    | 3 | Category 3        |
| ML-KEM-1024   | 4 | Category 5        |

Key properties of this implementation:

**k-parameterized design.** A single `kyber.wasm` serves all three parameter
sets. Every buffer is sized for k=4 (the largest variant). Poly and polyvec
slot pools provide scratch space for up to 10 polynomials and 8 polynomial
vectors simultaneously.

**Static memory only.** All buffers are fixed offsets in linear memory. The AS
compiler places the zetas `StaticArray<i16>` in the data segment at low memory
(offsets 0-4095). Mutable regions start at offset 4096. No `memory.grow()`, no
heap allocation.

**SIMD by default for NTT and poly arithmetic.** When built with `--enable
simd`, the public exports for `ntt`, `invntt`, `poly_add`, `poly_sub`,
`poly_reduce`, `poly_ntt`, and `poly_invntt` all resolve to SIMD
implementations. Scalar variants are retained and exported as `ntt_scalar` and
`invntt_scalar` for use by the test suite. Serialization, compression, and
`poly_basemul_montgomery` remain scalar.

**Decaps sequencing contract.** `PK_BUFFER`, `SK_BUFFER`, `CT_BUFFER`, and
`CT_PRIME_BUFFER` are contiguous at k=4. The IND-CPA decrypt path (consuming
`SK_BUFFER` via `polyvec_frombytes`) must complete before the re-encrypt path
(consuming `PK_BUFFER`). Do not interleave decrypt and encrypt calls across the
same WASM instance.

**No IND-CPA keygen or encaps/decaps primitives in WASM.** The module exports
arithmetic, serialization, sampling, and constant-time utilities. The
TypeScript wrapper (`MlKem512`, `MlKem768`, `MlKem1024`) orchestrates the full
KEM protocols: it calls SHA-3 via `sha3.wasm`, drives the XOF/PRF output, seeds
the buffers, and sequences the WASM calls. No protocol-level logic runs inside
`kyber.wasm`.

---

## Security Notes

See [ML-KEM implementation audit](./kyber_audit.md) for algorithm correctness verifications.

### Constant-time coefficient arithmetic

All modular arithmetic (`montgomery_reduce`, `barrett_reduce`, and `fqmul`)
use only integer add, subtract, multiply, and shift. No branches on
coefficient values, or data-dependent memory access. The NTT butterfly loop
indexes are fully determined by the layer and group structure of the transform,
independent of the polynomial coefficients.

The SIMD paths in `ntt_simd.ts` and `poly_simd.ts` maintain the same
constant-time properties. Each `fqmul_8x` computes Montgomery reduction using
`i16x8.mul`, `i32x4.extmul_*`, and `i32x4.shr_s`. The result is computed
unconditionally for all 8 lanes. No lane-conditional operations.

---

### CBD noise sampling

`cbd2` and `cbd3` derive noise coefficients from PRF output bytes using
popcount-style bit interleaving and subtraction. The operations are exclusively
bitwise and arithmetic on public random bytes. No branches on coefficient
values, no secret-dependent access patterns.

---

### Rejection sampling is not constant-time

`rej_uniform` (SampleNTT) branches on whether a 12-bit candidate value is less
than q. This is intentional and safe. Rejection sampling operates on XOF output
derived from the public seed `rho`, which generates the public matrix A. The
seed is not secret; the timing variation reveals nothing about private key
material.

---

### Decaps oracle prevention

The KEM decapsulate path is protected against decryption failure oracles by two
constant-time primitives.

`ct_verify` compares the re-encrypted ciphertext `ct_prime` with the received
ciphertext `ct` using XOR-accumulate with no early return. It returns 0 if they
match and 1 otherwise. No branch occurs on any byte of either buffer.

`ct_cmov` conditionally replaces the shared secret with a pseudorandom
rejection value if the comparison fails. It uses a mask computed as `-b` (all
1-bits when b=1, all 0-bits when b=0) and applies `r ^= mask & (r ^ x)`
byte-by-byte. No branch occurs on `b` or on any data byte. This implements the
Fujisaki-Okamoto transform's implicit rejection step.

> [!WARNING]
> The TypeScript wrapper must call `ct_verify` and `ct_cmov` unconditionally on
> every decapsulate path, even when decryption completes without error.
> Skipping either call, or branching on their results before calling both,
> reintroduces a timing oracle.

---

### Memory wiping

`wipeBuffers()` zeroes the entire mutable region with a single
`memory.fill(4096, 0, 29344)`. This covers all poly slots, polyvec slots, byte
buffers (seed, message, pk, sk, ct, ct_prime), the XOF/PRF buffer, and the
polynomial accumulator scratch area. The call completes in one pass.

The zetas `StaticArray<i16>` in the data segment (offsets 0-4095) is not wiped.
It is a compile-time constant and contains no secret data.

The TypeScript wrapper must call `wipeBuffers()` in its `dispose()` method. Key
material loaded into `SK_BUFFER` and decapsulated shared secrets held in
`MSG_BUFFER` must not persist in WASM linear memory after an operation
completes.

---

### FIPS 203 §7.2 modulus check

`polyvec_modulus_check` validates that every coefficient in a decoded
public-key polynomial vector satisfies `c < q`. FIPS 203 §7.2 requires this
check on the encapsulation key before use. The check runs constant-time over
all k×256 coefficients using an OR-accumulator with no early exit. It returns 0
if all coefficients are in range and 1 if any are not. The TypeScript wrapper
calls this during `MlKem*.importEk()`.

---

## API Reference

All exported functions are re-exported through `src/asm/kyber/index.ts`. The
SIMD-capable build exports all functions below.

### Module identity

```typescript
function getModuleId(): i32
```
Returns `5`. Module identifier for the init system.

```typescript
function getMemoryPages(): i32
```
Returns the current WASM linear memory size in 64KB pages (expected: 3).

---

### Buffer offset getters

These return fixed byte offsets into linear memory. The TypeScript layer uses
them to locate input and output regions.

#### Poly slots

Ten 512-byte scratch polynomials (256 × i16). The TypeScript wrapper uses these
as working registers during keygen, encaps, and decaps.

| Function | Returns | Description |
|---|---|---|
| `getPolySlotBase(): i32` | 4096 | Base of the poly slot pool |
| `getPolySlotSize(): i32` | 512 | Bytes per poly slot (256 × i16) |
| `getPolySlot0(): i32` | 4096 | Poly slot 0 |
| `getPolySlot1(): i32` | 4608 | Poly slot 1 |
| `getPolySlot2(): i32` | 5120 | Poly slot 2 |
| `getPolySlot3(): i32` | 5632 | Poly slot 3 |
| `getPolySlot4(): i32` | 6144 | Poly slot 4 |
| `getPolySlot5(): i32` | 6656 | Poly slot 5 |
| `getPolySlot6(): i32` | 7168 | Poly slot 6 |
| `getPolySlot7(): i32` | 7680 | Poly slot 7 |
| `getPolySlot8(): i32` | 8192 | Poly slot 8 |
| `getPolySlot9(): i32` | 8704 | Poly slot 9 |

#### Polyvec slots

Eight 2048-byte scratch polyvecs (4 × 512 bytes, accommodating k=4). The
TypeScript wrapper selects the appropriate number of polyvec slots for the
active parameter set.

| Function | Returns | Description |
|---|---|---|
| `getPolyvecSlotBase(): i32` | 9216 | Base of the polyvec slot pool |
| `getPolyvecSlotSize(): i32` | 2048 | Bytes per polyvec slot (k=4 max) |
| `getPolyvecSlot0(): i32` | 9216 | Polyvec slot 0 |
| `getPolyvecSlot1(): i32` | 11264 | Polyvec slot 1 |
| `getPolyvecSlot2(): i32` | 13312 | Polyvec slot 2 |
| `getPolyvecSlot3(): i32` | 15360 | Polyvec slot 3 |
| `getPolyvecSlot4(): i32` | 17408 | Polyvec slot 4 |
| `getPolyvecSlot5(): i32` | 19456 | Polyvec slot 5 |
| `getPolyvecSlot6(): i32` | 21504 | Polyvec slot 6 |
| `getPolyvecSlot7(): i32` | 23552 | Polyvec slot 7 |

#### Byte buffers

| Function | Returns | Description |
|---|---|---|
| `getSeedOffset(): i32` | 25600 | 32-byte seed buffer (rho, sigma, etc.) |
| `getMsgOffset(): i32` | 25632 | 32-byte message / shared secret buffer |
| `getPkOffset(): i32` | 25664 | Public key: k×384 polyvec bytes + 32-byte seed (1568B at k=4) |
| `getSkOffset(): i32` | 27232 | Secret key: k×384 polyvec bytes (1536B at k=4) |
| `getCtOffset(): i32` | 28768 | Ciphertext: polyvec compress + poly compress (1568B at k=4) |
| `getCtPrimeOffset(): i32` | 30336 | Decaps re-encrypt ciphertext for ct_verify comparison (1568B at k=4) |
| `getXofPrfOffset(): i32` | 31904 | 1024-byte XOF/PRF output buffer (rejection sampling and noise) |

---

### NTT and arithmetic

#### `getZetasOffset(): i32`

Returns the byte offset of `zetas[0]` in WASM linear memory. The zetas table
holds 128 NTT twiddle factors, each a centered i16 in the Montgomery domain.
The test suite uses this to independently verify the table values.

#### `getZeta(i: i32): i16`

Returns `zetas[i]`. Used by Gate 3 test vectors to confirm the twiddle factor
table against the reference.

#### `ntt(polyOffset: i32): void`

In-place forward NTT. FIPS 203 Algorithm 9. Input in standard order, output in
bit-reversed order. This export resolves to the SIMD implementation
(`ntt_simd`) in the SIMD build. SIMD layers handle `len = 128, 64, 32, 16, 8`
(8 butterflies per v128 iteration); a scalar tail handles `len = 4, 2`.

#### `ntt_scalar(polyOffset: i32): void`

Scalar forward NTT. Same algorithm as `ntt`, but entirely scalar. Exported for
use by the test suite to cross-check the SIMD path.

#### `invntt(polyOffset: i32): void`

In-place inverse NTT. FIPS 203 Algorithm 10. Input in bit-reversed order,
output in standard order. Includes multiplication by the Montgomery factor `f =
1441 = mont²/128 mod q`. This export resolves to the SIMD implementation
(`invntt_simd`) in the SIMD build. Scalar tail runs first (`len = 2, 4`), then
SIMD layers (`len = 8` through `128`), then a final SIMD pass for the `f`
multiplication.

#### `invntt_scalar(polyOffset: i32): void`

Scalar inverse NTT. Exported for test cross-check.

#### `basemul(rOffset: i32, aOffset: i32, bOffset: i32, zetaIdx: i32): void`

Multiplication in `Z_q[X]/(X² - ζ)`. FIPS 203 §4.3. Computes `r[0..1] = a[0..1]
× b[0..1]` in the quadratic extension, using the twiddle factor at
`zetas[zetaIdx]` for the `+ζ` term. Called by `poly_basemul_montgomery` for
each of the 128 coefficient pairs.

#### `montgomery_reduce(a: i32): i16`

Montgomery reduction. FIPS 203 §4.5. Given `a` in `{-q·2^15, ..., q·2^15 - 1}`,
returns `a·R⁻¹ mod q` where `R = 2^16`. Result in `{-(q-1), ..., q-1}`. Inlined
at all call sites.

#### `barrett_reduce(a: i16): i16`

Centered Barrett reduction. Returns a representative in `[-(q-1)/2, (q-1)/2]`
using the precomputed multiplier `v = 20159` and shift 26. Inlined at all call
sites.

#### `fqmul(a: i16, b: i16): i16`

Multiplication in `Z_q` via Montgomery reduction. Returns `a·b·R⁻¹ mod q`.
Inlined at all call sites.

---

### Polynomial operations

All polynomial functions take byte offsets into WASM linear memory. A
polynomial is 256 × i16 = 512 bytes.

#### `poly_tobytes(rOffset: i32, polyOffset: i32): void`

Serialize a polynomial to 384 bytes using 12-bit packing. FIPS 203
ByteEncode_12 (Algorithm 4, d=12). Two coefficients pack into three bytes. The
function adds q to any negative coefficient before packing, mapping the signed
range to unsigned.

#### `poly_frombytes(polyOffset: i32, aOffset: i32): void`

Deserialize 384 bytes to a polynomial. FIPS 203 ByteDecode_12 (Algorithm 5,
d=12). Writes each 12-bit value directly as a centered i16 coefficient.

#### `poly_compress(rOffset: i32, polyOffset: i32, dv: i32): void`

Compress and serialize a polynomial. Applies FIPS 203 Compress_dv then
ByteEncode_dv. Division-free multiply-shift replaces the division by q.

- `dv=4` — used by ML-KEM-512 and ML-KEM-768. Packs 8 coefficients into 4 bytes (4 bits each). Output: 128 bytes.
- `dv=5` — used by ML-KEM-1024. Packs 8 coefficients into 5 bytes (5 bits each). Output: 160 bytes.

#### `poly_decompress(polyOffset: i32, aOffset: i32, dv: i32): void`

Deserialize and decompress a polynomial. Applies FIPS 203 ByteDecode_dv then
Decompress_dv. Uses `round(x × q / 2^dv)` rounding arithmetic.

- `dv=4` — reads 128 bytes.
- `dv=5` — reads 160 bytes.

#### `poly_frommsg(polyOffset: i32, msgOffset: i32): void`

Convert a 32-byte message to a polynomial. FIPS 203 ByteDecode_1 then
Decompress_1. Each bit maps to either 0 or `⌈q/2⌉ = 1665`. Uses a constant-time
mask (`-bit & HALF_Q`) with no branch on the secret bit value.

#### `poly_tomsg(msgOffset: i32, polyOffset: i32): void`

Convert a polynomial to a 32-byte message. FIPS 203 Compress_1 then
ByteEncode_1. Uses a division-free multiply-shift to round each coefficient to
the nearest bit. No branch on coefficient values.

#### `poly_tomont(polyOffset: i32): void`

Convert all 256 coefficients to the Montgomery domain by multiplying by `R² mod
q = 1353`. The result is `coeff × R mod q`. Called on the secret key polynomial
vectors before NTT-domain multiplication.

#### `poly_basemul_montgomery(rOffset: i32, aOffset: i32, bOffset: i32): void`

Pointwise multiplication in the NTT domain. FIPS 203 §4.3. Calls `basemul` with
`+zetas[64+i]` for coefficient pairs `(4i, 4i+1)` and an inline negated-zeta
variant for pairs `(4i+2, 4i+3)`, for i in `0..63`. Used for the inner products
in matrix-vector multiplication.

#### `poly_getnoise(polyOffset: i32, bufOffset: i32, eta: i32): void`

Sample a centered binomial noise polynomial from PRF output. FIPS 203
SamplePolyCBD_η.

- `eta=2` — calls `cbd2`. Input: 128 bytes.
- `eta=3` — calls `cbd3`. Input: 192 bytes.

#### `poly_add(rOffset: i32, aOffset: i32, bOffset: i32): void`

Pointwise coefficient addition. No modular reduction. This export resolves to
the SIMD implementation (`poly_add_simd`) in the SIMD build; 32 v128 iterations
over 256 × i16.

#### `poly_sub(rOffset: i32, aOffset: i32, bOffset: i32): void`

Pointwise coefficient subtraction. No modular reduction. Resolves to
`poly_sub_simd` in the SIMD build.

#### `poly_reduce(polyOffset: i32): void`

Centered Barrett reduction on all 256 coefficients. Result in `[-(q-1)/2,
(q-1)/2]`. Resolves to `poly_reduce_simd` in the SIMD build; 32 v128 iterations
using `barrett_reduce_8x`.

#### `poly_ntt(polyOffset: i32): void`

Forward NTT followed by Barrett reduction. FIPS 203 Algorithm 9. Resolves to
`poly_ntt_simd` in the SIMD build.

#### `poly_invntt(polyOffset: i32): void`

Inverse NTT including the Montgomery factor `f = 1441`. FIPS 203 Algorithm 10.
Resolves to `poly_invntt_simd` in the SIMD build.

---

### Polyvec operations

A polyvec is a vector of k polynomials stored contiguously: k × 512 bytes. All
polyvec functions take a `k` parameter to operate on the correct number of
polynomials for the active parameter set.

#### `polyvec_tobytes(rOffset: i32, pvOffset: i32, k: i32): void`

Serialize all k polynomials. Calls `poly_tobytes` for each, writing k × 384 = k
× `POLY_BYTES` bytes.

#### `polyvec_frombytes(pvOffset: i32, aOffset: i32, k: i32): void`

Deserialize k × 384 bytes into k polynomials. Calls `poly_frombytes` for each.

#### `polyvec_compress(rOffset: i32, pvOffset: i32, k: i32, du: i32): void`

Compress and serialize a polyvec. FIPS 203 k × Compress_du + ByteEncode_du.
Uses 64-bit multiply for higher precision. The output size depends on both k
and du.

- `du=10` — used by ML-KEM-512 and ML-KEM-768. Output: k × 320 bytes.
- `du=11` — used by ML-KEM-1024. Output: k × 352 bytes.

#### `polyvec_decompress(pvOffset: i32, aOffset: i32, k: i32, du: i32): void`

Decompress a serialized polyvec. FIPS 203 k × ByteDecode_du then Decompress_du.

- `du=10` — reads k × 320 bytes.
- `du=11` — reads k × 352 bytes.

#### `polyvec_ntt(pvOffset: i32, k: i32): void`

Apply forward NTT to all k polynomials. Calls `poly_ntt` (SIMD) for each.

#### `polyvec_invntt(pvOffset: i32, k: i32): void`

Apply inverse NTT to all k polynomials. Calls `poly_invntt` (SIMD) for each.

#### `polyvec_reduce(pvOffset: i32, k: i32): void`

Apply centered Barrett reduction to all k polynomials. Calls `poly_reduce` (SIMD) for each.

#### `polyvec_add(rOffset: i32, aOffset: i32, bOffset: i32, k: i32): void`

Pointwise addition of two polyvecs. Calls `poly_add` (SIMD) for each of the k polynomials.

#### `polyvec_basemul_acc_montgomery(rOffset: i32, aOffset: i32, bOffset: i32, k: i32): void`

NTT-domain inner product: `r = Σ_{i=0}^{k-1} a[i]·b[i]`, then Barrett-reduce.
Implements the matrix-vector and dot-product steps in the IND-CPA encrypt and
decrypt paths. Uses `POLY_ACC_BUFFER` (offset 32928) as a scratch polynomial
for the accumulation loop; the result is accumulated into the polynomial at
`rOffset`.

#### `polyvec_modulus_check(pvOffset: i32, k: i32): i32`

FIPS 203 §7.2 modulus check. Scans all k × 256 coefficients and returns 0 if
every coefficient satisfies `c < q`, or 1 if any coefficient fails.
Constant-time over the full input using an OR-accumulator with no early exit.
The TypeScript wrapper calls this during encapsulation-key import.

---

### Sampling

#### `rej_uniform(polyOffset: i32, ctrStart: i32, bufOffset: i32, buflen: i32): i32`

Rejection sampling. FIPS 203 §4.2.1 Algorithm 6 (SampleNTT inner loop).
Extracts 12-bit candidates from the XOF byte buffer in 3-byte groups. Accepts a
candidate if it is less than q and writes it to the polynomial at `polyOffset +
ctrStart`. Returns the number of coefficients written.

- **polyOffset**: output polynomial (256 × i16)
- **ctrStart**: starting coefficient index (0 to 255); allows resumption after a partial XOF block
- **bufOffset**: input XOF output bytes
- **buflen**: input buffer length in bytes
- **Returns**: number of new coefficients written (0 to 256 - ctrStart)

The TypeScript layer calls this in a loop, refilling `XOF_PRF_BUFFER` with
additional XOF output until 256 coefficients are accepted.

> [!NOTE]
> `rej_uniform` branches on whether a candidate is less than q. This is safe
> because it operates exclusively on public XOF output derived from the public
> seed `rho`. Timing variation in rejection sampling reveals nothing about
> private key material.

---

### Constant-time utilities

#### `ct_verify(aOffset: i32, bOffset: i32, len: i32): i32`

Constant-time byte array comparison. XOR-accumulates all differences with no
early return. Returns 0 if the arrays are equal, 1 if they differ in any byte.
Used in KEM decapsulate to compare the re-encrypted ciphertext against the
received ciphertext.

#### `ct_cmov(rOffset: i32, xOffset: i32, len: i32, b: i32): void`

Constant-time conditional move. If `b == 1`, copies `x` into `r`. If `b == 0`,
leaves `r` unchanged. Uses `mask = -b` (all 1-bits when b=1, all 0-bits when
b=0) with `r[i] ^= mask & (r[i] ^ x[i])`. No branch on `b` or on any data byte.

**Precondition:** `b` must be exactly 0 or 1. Any other value produces undefined behavior.

---

### `wipeBuffers(): void`

Zeroes all mutable memory with a single `memory.fill(4096, 0, 29344)`. Covers
poly slots, polyvec slots, byte buffers, the XOF/PRF buffer, and the poly
accumulator scratch area. Does not touch the data segment (offsets 0-4095,
which holds the read-only zetas table).

The TypeScript wrapper calls this in `dispose()`. Call it after every keygen,
encapsulate, or decapsulate operation to prevent key material and intermediate
state from persisting in linear memory.

---

## Buffer Layout

The data segment (offsets 0-4095) is placed by the AssemblyScript compiler and
holds the zetas `StaticArray<i16>`. Its exact position within that range is
runtime-determined; use `getZetasOffset()` to locate it. All mutable buffers
start at offset 4096.

| Offset | Size (bytes) | Name | Description |
|---|---|---|---|
| 0 | 4096 | _(AS data segment)_ | Compiler-placed data; contains zetas (128 × i16). Read-only at runtime. |
| 4096 | 5120 | `POLY_SLOTS` | 10 × 512B scratch polynomials (10 × 256 × i16) |
| 9216 | 16384 | `POLYVEC_SLOTS` | 8 × 2048B scratch polyvecs (sized for k=4 max) |
| 25600 | 32 | `SEED_BUFFER` | 32-byte seed (rho, sigma, or other) |
| 25632 | 32 | `MSG_BUFFER` | 32-byte message or decapsulated shared secret |
| 25664 | 1568 | `PK_BUFFER` | Public key: k×384 polyvec bytes + 32-byte seed (1568B at k=4) |
| 27232 | 1536 | `SK_BUFFER` | Secret key: k×384 polyvec bytes (1536B at k=4) |
| 28768 | 1568 | `CT_BUFFER` | Ciphertext: polyvec compress + poly compress (1568B at k=4) |
| 30336 | 1568 | `CT_PRIME_BUFFER` | Decaps re-encrypted ciphertext for `ct_verify` comparison |
| 31904 | 1024 | `XOF_PRF_BUFFER` | XOF/PRF output for rejection sampling and noise generation |
| 32928 | 512 | `POLY_ACC_BUFFER` | Internal scratch polynomial for `polyvec_basemul_acc_montgomery` |
| 33440 | | END | Total mutable: 29344 bytes. Total module footprint < 196608 (3 pages). |

**Key and ciphertext sizing by parameter set.** The buffers are allocated for
k=4. Smaller parameter sets use only a prefix of each buffer.

| Buffer | k=2 (ML-KEM-512) | k=3 (ML-KEM-768) | k=4 (ML-KEM-1024) |
|---|---|---|---|
| `PK_BUFFER` used | 800 B | 1184 B | 1568 B |
| `SK_BUFFER` used | 768 B | 1152 B | 1536 B |
| `CT_BUFFER` used | 768 B | 1088 B | 1568 B |

**Sequencing constraint.** `PK_BUFFER`, `SK_BUFFER`, `CT_BUFFER`, and
`CT_PRIME_BUFFER` are contiguous. The decaps path reads `SK_BUFFER` via
`polyvec_frombytes` before the re-encrypt step reads `PK_BUFFER`. These
operations must not be interleaved across a single WASM instance.

---

## Internal Architecture

The module compiles twelve AssemblyScript source files into a single
`kyber.wasm` binary.

### `params.ts`

Mathematical constants for FIPS 203. No logic, no imports. All values are
`const` exports consumed throughout the module.

Key constants: `Q = 3329`, `N = 256`, `POLY_BYTES = 384`, `QINV = -3327` (q⁻¹
mod 2^16), `MONT = -1044` (centered Montgomery factor), `BARRETT_V = 20159`,
`BARRETT_SHIFT = 26`, `HALF_Q = 1665` (⌈q/2⌉). Also exports multiply-shift
sequences for compression to 4, 5, 10, and 11 bits, replacing division by q in
Compress_d.

---

### `buffers.ts`

Static memory layout and offset getters. Defines all poly slot, polyvec slot,
and byte buffer offsets as `i32` constants, exports them via getter functions,
and implements `wipeBuffers()`. No algorithm logic.

---

### `reduce.ts`

The three fundamental modular arithmetic operations, all marked `@inline`:

**`montgomery_reduce`.** Given a product `a = x·y` in `{-q·2^15, ...,
q·2^15-1}`, computes `t = (i16)(a × QINV)` to isolate the low 16 bits of `a ×
QINV` in `Z/2^16Z`, then returns `(a - t×q) >> 16`. The result is `a·R⁻¹ mod q`
where `R = 2^16`.

**`barrett_reduce`.** Centered Barrett reduction using `round(a/q) ≈ (v×a +
2^25) >> 26` where `v = ⌊(2^26 + q/2)/q⌋ = 20159`. Returns a result in
`[-(q-1)/2, (q-1)/2]`.

**`fqmul`.** Multiplies two i16 values and applies `montgomery_reduce` to the
i32 product.

---

### `ntt.ts`

The 128-entry zetas table and scalar NTT implementation.

**Zetas table.** A `StaticArray<i16>` of 128 twiddle factors: `zetas[i] = MONT
× 17^{BitRev7(i)} mod q`, centered to `[-(q-1)/2, (q-1)/2]`. 17 is the
primitive 256th root of unity in `Z_3329`. The table is placed in the AS data
segment at compile time; use `getZetasOffset()` and `getZeta(i)` to inspect it
from outside the module.

**`ntt`.** Loop-driven forward NTT. Outer loop halves `len` from 128 down to 2
(7 layers). Inner loop runs the Cooley-Tukey butterfly: `t = zeta ×
coeff[j+len]`, `coeff[j+len] = coeff[j] - t`, `coeff[j] = coeff[j] + t`. Uses
`fqmul` for the twiddle multiplication.

**`invntt`.** Loop-driven inverse NTT. Outer loop doubles `len` from 2 up to
128. Gentleman-Sande (decimation-in-frequency) butterfly: `t = coeff[j]`,
`coeff[j] = barrett_reduce(t + coeff[j+len])`, `coeff[j+len] = zeta ×
(coeff[j+len] - t)`. Final pass multiplies all coefficients by `f = 1441 =
mont²/128 mod q` to cancel the R^7 Montgomery accumulation across 7 layers.

**`basemul`.** Degree-1 polynomial multiplication in `Z_q[X]/(X² - ζ)`. Reads a
two-coefficient pair from each of the three offsets, computes `r[0] =
a[1]×b[1]×ζ + a[0]×b[0]` and `r[1] = a[0]×b[1] + a[1]×b[0]` using `fqmul`, and
writes the result.

---

### `ntt_simd.ts`

SIMD forward and inverse NTT using WASM v128. Both functions take the byte
offset of a 256 × i16 polynomial and process it in-place.

**`fqmul_8x`.** 8-wide Montgomery reduction. Computes full i32 products via
`i32x4.extmul_low/high_i16x8_s`, computes `t = a × b × QINV mod 2^16` entirely
in i16 arithmetic using `i16x8.mul` (the ring property `low16(a×b×QINV) =
low16(a × low16(b×QINV))` holds in Z/2^16Z), sign-extends `t` to i32, subtracts
`t×q` from the full product, and right-shifts by 16. Results are narrowed back
to i16x8 via `i16x8.narrow_i32x4_s`.

**`barrett_reduce_8x`.** 8-wide Barrett reduction. Widens to i32x4, applies
`(v×a + 2^25) >> 26` via multiply and shift, subtracts `t×q`, and narrows back
to i16x8.

**`ntt_simd`.** SIMD layers cover `len = 128, 64, 32, 16, 8`, processing 8
butterflies per iteration with `v128.load`, `fqmul_8x`, `i16x8.add`,
`i16x8.sub`, and `v128.store`. A scalar tail handles `len = 4, 2` using `fqmul`
and `barrett_reduce` from `reduce.ts`.

**`invntt_simd`.** Scalar tail first (`len = 2, 4`), then SIMD layers (`len =
8` through `128`), then a final 32-iteration SIMD pass for the `f = 1441`
scaling step.

---

### `poly.ts`

All polynomial operations that remain scalar: serialization, compression,
message encoding, arithmetic, and NTT wrappers.

**Serialization.** `poly_tobytes` packs 128 pairs of 12-bit coefficients into
384 bytes. Negative values are mapped positive by adding q when the sign bit is
set. `poly_frombytes` reverses this, writing raw 12-bit values as i16
coefficients.

**Compression.** `poly_compress` uses the precomputed multiply-shift sequences
from `params.ts` for exact division-free rounding. The `dv=4` path produces 128
bytes (4 bits per coefficient); the `dv=5` path produces 160 bytes (5 bits per
coefficient). `poly_decompress` applies `round(x × q / 2^dv)` using integer
arithmetic.

**Message encoding.** `poly_frommsg` uses a constant-time mask `(-bit) &
HALF_Q` to map each message bit to 0 or 1665 without branching. `poly_tomsg`
uses the same compress-1 multiply-shift as `poly_compress`, extracting the low
bit after scaling.

**Arithmetic.** `poly_add` and `poly_sub` iterate over 256 coefficients.
`poly_reduce` applies `barrett_reduce` to each. `poly_tomont` multiplies each
coefficient by `1353 = 2^32 mod q` via `montgomery_reduce`.

**NTT wrappers.** `poly_ntt` calls `ntt` then `poly_reduce`. `poly_invntt`
calls `invntt` directly (the scaling factor is already included).

**`poly_basemul_montgomery`.** Iterates over 64 coefficient-pair groups. For
each group `i`, the first pair uses `basemul` with `+zetas[64+i]`; the second
pair uses an inline negated-zeta variant that computes `a[0]×b[0] -
a[1]×b[1]×zeta` for `r[0]` (linearity of Montgomery reduction:
`montgomery_reduce(x × (-z)) = -montgomery_reduce(x × z)`).

**`poly_getnoise`.** Dispatches to `cbd2` (η=2) or `cbd3` (η=3).

---

### `poly_simd.ts`

SIMD variants for the five poly operations that benefit from vectorization. All
process 256 × i16 in 32 iterations of 8 coefficients each.

**`poly_add_simd` / `poly_sub_simd`.** Use `i16x8.add` / `i16x8.sub` with
`v128.load` and `v128.store`. No reduction.

**`poly_reduce_simd`.** Applies `barrett_reduce_8x` (from `ntt_simd.ts`) to
each 16-byte block.

**`poly_ntt_simd` / `poly_invntt_simd`.** Wrappers around `ntt_simd` /
`invntt_simd` followed by `poly_reduce_simd` for the forward path.

`polyvec.ts` imports these via aliased imports (`poly_add_simd as poly_add`,
etc.), so polyvec-level operations always use the SIMD path.

---

### `polyvec.ts`

Vector-of-polynomials operations parameterized by k. Imports the SIMD poly
operations under their public names, making all add, reduce, NTT, and
inverse-NTT operations SIMD-backed. Serialization and `poly_basemul_montgomery`
come from `poly.ts` and remain scalar.

**Serialization / compression.** `polyvec_tobytes` and `polyvec_frombytes` loop
over k polynomials. `polyvec_compress` and `polyvec_decompress` handle `du=10`
(4 coefficients into 5 bytes) and `du=11` (8 coefficients into 11 bytes) using
64-bit multiply-shift arithmetic for the higher-precision compression.

**`polyvec_basemul_acc_montgomery`.** Computes the NTT-domain inner product `r
= Σ a[i]·b[i]`. The first polynomial product writes directly to `rOffset`;
subsequent products use `POLY_ACC_BUFFER` as scratch and accumulate into
`rOffset` via `poly_add`. A final `poly_reduce` brings all coefficients into
range.

**`polyvec_modulus_check`.** Iterates over k × 256 coefficients using an
OR-accumulator. Returns the OR of all sign bits of `(Q - 1 - c)`: any
coefficient at or above q produces a negative value and sets the result to 1.

---

### `cbd.ts`

Centered binomial distribution sampling from PRF output.

**`cbd2`.** η=2. Processes 4 PRF bytes at a time into 8 coefficients. Uses the
identity `popcount(a) - popcount(b)` via bit-interleaving: `d = (t &
0x55555555) + ((t >> 1) & 0x55555555)`, then extracts pairs of 2-bit values.
Each coefficient is `a - b` where `a, b ∈ {0, 1, 2}`. Samples 256 coefficients
from 128 bytes.

**`cbd3`.** η=3. Processes 3 PRF bytes at a time into 4 coefficients. Uses `d =
(t & M) + ((t >> 1) & M) + ((t >> 2) & M)` where `M = 0x00249249` (the period-3
bit mask). Extracts pairs of 3-bit values. Each coefficient is `a - b` where
`a, b ∈ {0, 1, 2, 3}`. Samples 256 coefficients from 192 bytes.

---

### `sampling.ts`

Uniform rejection sampling for matrix A coefficient generation. `rej_uniform`
implements the inner loop of FIPS 203 §4.2.1 Algorithm 6 (SampleNTT). Each
3-byte group yields two 12-bit candidates; candidates below q are accepted. The
function returns after either filling the polynomial or exhausting the input
buffer, allowing the TypeScript layer to refill the buffer and call again.

---

### `verify.ts`

Constant-time comparison and conditional copy for FO transform decaps.

**`ct_verify`.** XOR-accumulates differences across all `len` bytes into a
single u8. Converts to a 0/1 result via `(-r) >> 63` on a u64, avoiding any
comparison or branch on the accumulated value.

**`ct_cmov`.** Derives a byte mask from the condition bit, applies it per-byte
with `r ^ (mask & (r ^ x))`. The mask is 0xFF...FF when b=1 and 0x00...00 when
b=0.

---

### `index.ts`

Re-exports the full public API. The key aliasing decisions:

- `ntt` and `invntt` resolve to the SIMD implementations from `ntt_simd.ts`.
  The scalar implementations are also exported as `ntt_scalar` and
  `invntt_scalar`.
- `poly_add`, `poly_sub`, `poly_reduce`, `poly_ntt`, and `poly_invntt` resolve
  to the SIMD implementations from `poly_simd.ts`.
- All other exports (`poly_tobytes`, `poly_frombytes`, `poly_compress`,
  `poly_decompress`, `poly_frommsg`, `poly_tomsg`, `poly_tomont`,
  `poly_basemul_montgomery`, `poly_getnoise`, all polyvec functions,
  `rej_uniform`, `ct_verify`, `ct_cmov`) come directly from their respective
  source files.

---

### Dependency graph

```
params.ts
  ^  ^  ^  ^  ^  ^
  |  |  |  |  |  |
  | reduce.ts  |  |  sampling.ts
  |  ^  ^      |  |
  |  |  |      |  |
  | ntt.ts  buffers.ts
  |  ^  ^       ^
  |  |  |       |
  | ntt_simd.ts |
  |  ^  ^       |
  |  |  |       |
  | poly.ts     |
  |  ^  ^       |
  |  |  |       |
  | cbd.ts      |
  |      \      |
  |   poly_simd.ts
  |        ^
  |        |
  +---polyvec.ts
            \
             +-- verify.ts
                    \
                  index.ts (re-exports all)
```

---

## Error Conditions

The kyber WASM module has no explicit error return codes. Every function
assumes its inputs are valid. The TypeScript wrapper (`MlKem512`, `MlKem768`,
`MlKem1024`) enforces all preconditions before calling into WASM.

| Function | Implicit precondition | Enforced by |
|---|---|---|
| `poly_compress(dv)` | `dv` is 4 or 5 | TypeScript wrapper |
| `poly_decompress(dv)` | `dv` is 4 or 5 | TypeScript wrapper |
| `polyvec_compress(du)` | `du` is 10 or 11 | TypeScript wrapper |
| `polyvec_decompress(du)` | `du` is 10 or 11 | TypeScript wrapper |
| `poly_getnoise(eta)` | `eta` is 2 or 3 | TypeScript wrapper |
| `ct_cmov(b)` | `b` is exactly 0 or 1 | TypeScript wrapper |
| `rej_uniform` | `bufOffset + buflen` is within linear memory | TypeScript wrapper |
| All poly/polyvec | Offsets are within linear memory and do not overlap | TypeScript wrapper |

`polyvec_modulus_check` and `ct_verify` return meaningful values (0 or 1) and have no precondition failures.

> [!NOTE]
> Passing an invalid `dv` or `du` to compress/decompress does not trap, so the else branch runs with unintended parameters. The TypeScript wrapper validates these at construction time and never passes invalid values.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [kyber](./kyber.md) | TypeScript wrapper classes (`MlKem512`, `MlKem768`, `MlKem1024`, `KyberSuite`) |
| [kyber_audit](./kyber_audit.md) | ML-KEM implementation audit |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [asm_chacha](./asm_chacha.md) | ChaCha20-Poly1305 WASM module (companion KEM + AEAD cipher) |
| [asm_sha3](./asm_sha3.md) | SHA-3 WASM module (used for XOF and PRF operations in ML-KEM keygen, encaps, and decaps) |
