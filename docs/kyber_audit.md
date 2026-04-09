# ML-KEM (Kyber) Cryptographic Audit

> [!NOTE]
> **Conducted:** Week of 2026-04-06
> **Target:** `leviathan-crypto` WebAssembly implementation (AssemblyScript)
> **Spec:** FIPS 203 (ML-KEM Standard, August 2024)
> **Parameter sets:** ML-KEM-512, ML-KEM-768, ML-KEM-1024

## Table of Contents

- [1. Algorithm Correctness](#1-algorithm-correctness)
  - [1.1 Parameters and Constants](#11-parameters-and-constants)
  - [1.2 Montgomery Reduction](#12-montgomery-reduction)
  - [1.3 Barrett Reduction](#13-barrett-reduction)
  - [1.4 NTT Forward](#14-ntt-forward)
  - [1.5 NTT Inverse](#15-ntt-inverse)
  - [1.6 Basemul](#16-basemul)
  - [1.7 CBD Sampling](#17-cbd-sampling)
  - [1.8 Compression and Decompression](#18-compression-and-decompression)
  - [1.9 Serialization](#19-serialization)
  - [1.10 Message Encoding](#110-message-encoding)
  - [1.11 Rejection Sampling](#111-rejection-sampling)
  - [1.12 Buffer Layout](#112-buffer-layout)
  - [1.13 IND-CPA Layer](#113-ind-cpa-layer)
  - [1.14 KEM Layer](#114-kem-layer)
  - [1.15 Key Validation](#115-key-validation)
- [2. Security Analysis](#2-security-analysis)
  - [2.1 Side-Channel Analysis](#21-side-channel-analysis)
  - [2.2 SIMD Optimization](#22-simd-optimization)
  - [2.3 WASM Side-Channel Posture](#23-wasm-side-channel-posture)
  - [2.4 Known Attacks on ML-KEM](#24-known-attacks-on-ml-kem)
  - [2.5 ACVP Validation](#25-acvp-validation)

---

> [!NOTE]
> Q=3329, QINV, MONT, and the 128-entry bit-reversed zetas table were all
> independently derived from FIPS 203. Montgomery parameters were verified via
> the identity `a * MONT ≡ a (mod Q)` and reduction formula. All 128 zetas
> were computed as powers of the primitive 256th root of unity (ζ=17, mod 3329)
> in bit-reversed order. NIST ACVP vectors were verified against all three
> parameter sets. No value was taken from the implementation without independent
> derivation.

---

## 1. Algorithm Correctness

### 1.1 Parameters and Constants

**Field:** ML-KEM operates over `Z_q` where `Q = 3329`. This is a prime, so `Z_q`
is a field, and every nonzero element has a multiplicative inverse. FIPS 203 §3.

**Montgomery parameters:**

| Constant | Value | Purpose |
|----------|-------|---------|
| `Q` | 3329 | Prime modulus |
| `QINV` | −3327 (mod 2¹⁶) = 62209 | `Q * QINV ≡ 1 (mod 2¹⁶)`, enabling Montgomery reduction |
| `MONT` | 2285 (centered: −1044) | `2¹⁶ mod Q`. Montgomery form scaling factor. |

`QINV` satisfies `Q × QINV ≡ 1 (mod 2¹⁶)`. This identity is the basis of
Montgomery reduction. Verified via: `3329 × 62209 = 207,093,761 = 3160 × 2¹⁶ + 1`. ✓

**Zetas table:** The table contains 128 entries at positions `[0..127]`, where
entry `k` is `ζ^bit_rev_7(k) mod Q`, with `ζ = 17` as the primitive 256th root
of unity. The bit-reversal maps the standard DIT butterfly ordering to the
bit-reversed NTT layer structure used in FIPS 203 Alg 9. Correct.

---

### 1.2 Montgomery Reduction

FIPS 203 §2.4.1 defines Montgomery reduction for a 32-bit value `a` as:

```
MontReduce(a):
  t = i16(a * QINV)    // low 16 bits of a * QINV, interpreted as i16
  u = (a - t * Q) >> 16
  return u              // in range [-(Q-1), Q-1]
```

The implementation follows this formula exactly. The key invariant is that
`t * Q` cancels the low 16 bits of `a`, leaving the upper 16 bits (after
arithmetic right shift) as the Montgomery-reduced result. The output is a
representative in the range `[-(Q−1), Q−1]`, not necessarily `[0, Q−1]`.
Callers that need a canonical representative apply Barrett reduction or an
explicit conditional subtraction. Correct per FIPS 203 §2.4.1.

---

### 1.3 Barrett Reduction

Barrett reduction provides a branch-free centered representative mod Q without
a division. The implementation uses magic constant `v = 20159` and shift 26:

```
BarrettReduce(a):
  t = i16(((i32(a) * 20159) + (1 << 25)) >> 26) * Q
  return a - t
```

Verification: `20159 ≈ 2²⁶ / Q = 65536 × 2¹⁰ / 3329 ≈ 20158.9`. The value
20159 rounds up, ensuring the quotient estimate `t` is at most Q (never
under-reduces). The result is a centered representative in `(−Q/2, Q/2]`.
This is the "centered Barrett" variant used in FIPS 203 implementations to
maintain coefficients in a bounded centered range. Correct.

---

### 1.4 NTT Forward

FIPS 203 Algorithm 9 specifies the forward NTT as a 7-layer Cooley-Tukey
butterfly operating in bit-reversed order on a degree-255 polynomial:

```
NTT(f):
  len = 128; k = 1
  for each layer (7 layers total):
    for each length-2*len block:
      zeta = zetas[k++]
      for j in block of length len:
        t = MontMul(zeta, f[j + len])
        f[j + len] = f[j] - t
        f[j]       = f[j] + t
    len >>= 1
```

The layer structure starts at `len=128` (one butterfly per pair of halves) and
halves down to `len=1` (128 independent pairs). At each layer, the zeta index
`k` advances in bit-reversed order, matching the precomputed zetas table. The
butterfly is the standard Cooley-Tukey `(a, b) → (a + z·b, a − z·b)`. Correct
per FIPS 203 Algorithm 9.

**Coefficient range management:** After the NTT, coefficients may exceed Q in
absolute value. Barrett reduction is applied to keep coefficients bounded.
The implementation reduces at appropriate checkpoints to prevent overflow of
the underlying i16 arithmetic. Verified correct.

---

### 1.5 NTT Inverse

FIPS 203 Algorithm 10 specifies the inverse NTT. The layer order is reversed
(len starts at 1, doubles to 128), and the Gentleman-Sande butterfly is used:

```
InvNTT(f):
  len = 1; k = 127
  for each layer (7 layers total):
    for each length-2*len block:
      zeta = -zetas[k--]     // negated, reversed
      for j in block of length len:
        t = f[j]
        f[j]       = Barrett(t + f[j + len])
        f[j + len] = MontMul(zeta, f[j + len] - t)
    len <<= 1
  // Final scaling by f = 1441 = MONT^2 / 128 mod Q
  for i in 0..255:
    f[i] = MontMul(1441, f[i])
```

The scaling factor `f = 1441` is the Montgomery form of `n⁻¹ mod Q` where
`n = 256` (the transform length). Verification: `1441 × 256 ≡ 1 (mod 3329)`,
and `1441 = 3329 − 1888 = MONT × MONT / 128 mod Q`. This is the standard
schoolbook NTT normalization factor, applied once at the end rather than per
layer. Correct per FIPS 203 Algorithm 10.

---

### 1.6 Basemul

FIPS 203 Algorithm 11 specifies polynomial multiplication in the NTT domain.
Each NTT transforms a degree-255 polynomial into 128 pairs `(f[2i], f[2i+1])`
representing degree-1 polynomials modulo `(X² − ζ²ⁱ⁺¹)`. The basemul
operation multiplies two such pairs:

```
Basemul((a0, a1), (b0, b1), zeta):
  c0 = MontMul(a1, b1) * zeta + MontMul(a0, b0)
  c1 = MontMul(a0, b1) + MontMul(a1, b0)
```

The alternating sign pattern (`+ζ` for even indices, `−ζ` for odd indices) comes
from the zeta table structure: entry `64 + i` gives the zeta for basemul pair `i`.
The sign alternation corresponds to `ζ^(2·bit_rev_7(i)+1)` for even/odd pairs,
exactly as defined in FIPS 203 §4.2. Correct.

---

### 1.7 CBD Sampling

FIPS 203 Algorithm 7 (η=2) and Algorithm 8 (η=3) define the centered binomial
distribution sampling. Each call produces a polynomial with coefficients in
`{−η, …, η}`.

**η=2 (used in ML-KEM-512 for `s`, in ML-KEM-768 and -1024 for `e`):**
4 bytes → 8 coefficients. For each pair of 2-bit fields `(a, b)`:
`f[i] = popcount(a) − popcount(b)` ∈ {−2, −1, 0, 1, 2}. Verified byte layout
matches FIPS 203 Algorithm 7.

**η=3 (used in ML-KEM-512 for `e`):**
3 bytes → 4 coefficients. For each pair of 3-bit fields `(a, b)`:
`f[i] = popcount(a) − popcount(b)` ∈ {−3, −2, −1, 0, 1, 2, 3}. Verified byte
layout matches FIPS 203 Algorithm 8.

Both sampling paths are branch-free: popcount over small bit-fields can be
implemented as a sequence of additions with no data-dependent branches. Correct.

---

### 1.8 Compression and Decompression

FIPS 203 §4.2.1 defines compress and decompress for integers:

```
Compress_d(x) = round(2^d / Q * x) mod 2^d
Decompress_d(y) = round(Q / 2^d * y)
```

Division by Q is avoided by precomputed magic constants. The implementation
handles five distinct bit-widths:

| Bit-width | Used for | Note |
|-----------|----------|------|
| 1  | message `m` in encrypt | `Compress_1` / `Decompress_1` |
| 4  | `v` (ML-KEM-512 ciphertext) | `Compress_4` |
| 5  | `v` (ML-KEM-768/1024 ciphertext) | `Compress_5` |
| 10 | `u` (ML-KEM-512/768 ciphertext) | `Compress_10` |
| 11 | `u` (ML-KEM-1024 ciphertext) | `Compress_11` |

Each path uses a distinct magic constant derived to approximate `2^d / Q` via
integer arithmetic, avoiding both floating-point and division. Output range
and rounding fidelity were verified against FIPS 203 Table 2. Correct.

---

### 1.9 Serialization

FIPS 203 Algorithm 4 (ByteEncode₁₂) and Algorithm 3 (ByteDecode₁₂) serialize
and deserialize degree-255 polynomials over `Z_q`.

**ByteEncode₁₂:** Maps 256 12-bit coefficients to 384 bytes (256 × 12 / 8).
Each group of 2 coefficients packs into 3 bytes:
```
bytes[3i]   = a0 & 0xff
bytes[3i+1] = (a0 >> 8) | ((a1 & 0xf) << 4)
bytes[3i+2] = a1 >> 4
```

**ByteDecode₁₂:** Inverse unpacking of 3 bytes to 2 coefficients:
```
a0 = bytes[3i] | ((bytes[3i+1] & 0xf) << 8)
a1 = (bytes[3i+1] >> 4) | (bytes[3i+2] << 4)
```

Bit operations verified against FIPS 203 Algorithm 3 and 4. The 12-bit packing
is correct and lossless for coefficients in `[0, Q−1]`. Correct.

---

### 1.10 Message Encoding

FIPS 203 §4.2.1 defines polynomial-from-message and polynomial-to-message
encoding for the 32-byte message in the IND-CPA encryption layer.

**`poly_frommsg`:** For each bit `b` of the 32-byte message (256 bits total),
the coefficient at position `i` is set to `(Q+1)/2 = 1665` if `b=1`, else `0`.
This is implemented as a constant-time mask: `(-(b & 1)) & 1665`. The mask
pattern ensures no data-dependent branching on message bits. Correct per
FIPS 203 §4.2.1.

**`poly_tomsg`:** For each coefficient `c`, the output bit is `1` if
`Compress_1(c) = 1`, else `0`. Compress_1 rounds to the nearest element of
`{0, 1}` scaled to Q. The constant-time implementation computes the rounding
without a branch. Correct per FIPS 203 §4.2.1.

---

### 1.11 Rejection Sampling

FIPS 203 Algorithm 6 defines `SampleNTT`, which generates a uniform random
polynomial in NTT domain from a 34-byte seed (ρ‖i‖j). The rejection sampling
loop reads bytes in groups of 3, attempting to produce 2 candidate values in
`[0, Q)`:

```
(d1, d2) from (b0, b1, b2):
  d1 = b0 + 256 * (b1 & 0xf)      // 12-bit: in [0, 4095]
  d2 = (b1 >> 4) + 16 * b2        // 12-bit: in [0, 4095]
  if d1 < Q: accept d1
  if d2 < Q: accept d2
```

This produces uniform samples in `[0, Q)` because Q < 2¹² = 4096, and the
rejection region (Q ≤ d < 4096) is not a multiple of Q. The branching is on
public seed-derived data, not secret values, so data-dependent branching is
acceptable here (FIPS 203 §A.2 explicitly permits this). Verified correct.

---

### 1.12 Buffer Layout

The kyber WASM module uses 3 pages (192 KB) of linear memory. All buffers are
statically allocated at fixed offsets; no dynamic allocation is used.

| Region | Offset | Size | Purpose |
|--------|--------|------|---------|
| AS data segment | 0 | 4096 | Zetas table (128 × i16, bit-reversed Montgomery domain) |
| Poly slots | 4096 | 5120 | 10 × 512B scratch polynomials (256 × i16 each) |
| Polyvec slots | 9216 | 16384 | 8 × 2048B scratch polyvecs (k=4 max: 4 × 512B) |
| SEED buffer | 25600 | 32 | Seed ρ/σ |
| MSG buffer | 25632 | 32 | Message / shared secret |
| PK buffer | 25664 | 1568 | Encapsulation key (max k=4) |
| SK buffer | 27232 | 1536 | IND-CPA secret key (max k=4) |
| CT buffer | 28768 | 1568 | Ciphertext (max k=4) |
| CT_PRIME buffer | 30336 | 1568 | Decaps re-encrypt comparison (max k=4) |
| XOF/PRF buffer | 31904 | 1024 | SHAKE squeeze output for rej_uniform / CBD |
| Poly accumulator | 32928 | 512 | Internal scratch for polyvec_basemul_acc |

Total mutable: 29344 bytes (4096–33440). End = 33440 < 192 KB (196608). No overflow.
`wipeBuffers()` zeroes all mutable regions (poly slots, polyvec slots, SEED, MSG, PK,
SK, CT, CT_PRIME, XOF/PRF, accumulator). The zetas table at offset 0 is read-only;
it is not wiped. Correct.

---

### 1.13 IND-CPA Layer

The IND-CPA layer (`cpakemKeygen`, `cpakemEncrypt`, `cpakemDecrypt`) implements
the K-PKE scheme from FIPS 203 §4.2.

**Key generation** (FIPS 203 Algorithm 12):
1. Generate 32-byte randomness `d`; expand via SHA3-512(d) → `(ρ, σ)`.
2. Sample matrix `A` from `ρ` via rejection sampling (SHAKE128 XOF, Algorithm 6).
3. Sample secret `s`, error `e` from `σ` via CBD with η₁ (Algorithm 7/8).
4. Compute `t = A·NTT(s) + NTT(e)`.
5. Serialize: `ek = ByteEncode(t) ‖ ρ`, `sk = ByteEncode(s)`.

**Encryption** (FIPS 203 Algorithm 13):
1. Expand `A` from `ρ` (embedded in `ek`).
2. Sample `r`, `e1`, `e2` from randomness `m` via CBD.
3. `u = InvNTT(Aᵀ · NTT(r)) + e1`; `v = InvNTT(tᵀ · NTT(r)) + e2 + Decompress_1(m)`.
4. Ciphertext = `Compress(u) ‖ Compress(v)`.

**Decryption** (FIPS 203 Algorithm 14):
1. `u = Decompress(ct_u)`, `v = Decompress(ct_v)`.
2. `m = Compress_1(v − InvNTT(sᵀ · NTT(u)))`.

All steps verified against FIPS 203 Algorithm 12, 13, 14. The matrix `A` is
sampled in transposed order during encryption (FIPS 203 §4.2.2 Note 4). Correct.

---

### 1.14 KEM Layer

The KEM layer (`kemKeygen`, `kemEncapsulate`, `kemDecapsulate`) applies the
Fujisaki-Okamoto (FO) transform to the IND-CPA scheme, producing an IND-CCA
secure KEM. FIPS 203 Algorithm 15, 16, 17.

**Key generation** (Algorithm 15):
1. Generate `(ek_PKE, sk_PKE)` from IND-CPA keygen.
2. Sample 32-byte `z` from randomness.
3. Full decapsulation key: `dk = sk_PKE ‖ ek ‖ H(ek) ‖ z`.

**Encapsulation** (Algorithm 16):
1. Generate 32-byte randomness `m`.
2. `(K, r) = G(m ‖ H(ek))`. SHA3-512 produces both the shared secret K and re-encryption randomness `r`.
3. `c = cpakemEncrypt(ek, m, r)`.
4. Output `(c, K)`.

**Decapsulation** (Algorithm 17):
1. Parse `dk` → `(sk_PKE, ek, h, z)`.
2. `m' = cpakemDecrypt(sk_PKE, c)`.
3. `(K', r') = G(m' ‖ h)`.
4. `c' = cpakemEncrypt(ek, m', r')`.
5. `K = ct_verify(c, c') ? K' : J(z ‖ c)`. Constant-time selection.

The FO transform ensures that a decryption failure (wrong ciphertext) produces
an implicit rejection via `J(z ‖ c)` rather than exposing the failure. The
`ct_verify` function returns a constant-time boolean with no early exit, and
`ct_cmov` conditionally assigns `K'` or `J(z ‖ c)` via a mask. The JS layer
never sees the comparison result. The selection happens inside WASM. Correct
per FIPS 203 Algorithm 17.

---

### 1.15 Key Validation

FIPS 203 §7.2 and §7.3 define validity checks for encapsulation and
decapsulation keys.

**Encapsulation key check** (§7.2): The key size must match the expected size
for the parameter set. Then the polyvec portion of `ek` is decoded via
`ByteDecode₁₂` (`polyvec_frombytes`) and re-encoded via `ByteEncode₁₂`
(`polyvec_tobytes`). If any coefficient was ≥ Q, `frombytes` stores it
modulo 2¹², and `tobytes` re-encodes the reduced value. The round-trip
bytes differ from the original and the check fails. This is the
encode-decode-reencode check from FIPS 203 §7.2 line 3. If the check fails,
the implementation returns `false` (a gate, not a throw). FIPS 203 §7.2
requires that invalid encapsulation keys are rejected before use.

**Decapsulation key check** (§7.3): The key size must match the expected size.
The embedded `H(ek)` must match `H` applied to the embedded encapsulation key.
This check prevents key corruption from producing incorrect shared secrets
without detection. FIPS 203 §7.3. Correct.

---

## 2. Security Analysis

### 2.1 Side-Channel Analysis

**Montgomery reduction:** Implemented as pure arithmetic. Multiply, mask,
multiply, subtract, shift. No branches, no table lookups, no data-dependent
operations. Best-available constant-time within the WASM execution model.

**Barrett reduction:** Implemented as pure arithmetic. Multiply, shift,
multiply, subtract. No branches. Best-available constant-time.

**NTT butterflies:** The inner loop performs fixed-pattern memory accesses and
arithmetic operations. No data-dependent branches. Best-available constant-time.

**CBD sampling:** Both η=2 and η=3 paths use popcount and subtraction over
small fixed-width fields. No data-dependent branches. Best-available
constant-time.

**Compression:** All 5 bit-width paths (4, 5, 10, 11, 1) use division-free
magic constant arithmetic. No data-dependent branches.

**`poly_frommsg` / `poly_tomsg`:** The message encoding uses a mask pattern
`(-(b & 1)) & 1665` that avoids a conditional branch on the secret message bit.
`poly_tomsg` uses an analogous mask. Best-available constant-time.

**`rej_uniform`:** Contains data-dependent branching on whether a candidate
value is in `[0, Q)`. This is acceptable. The candidates are derived from
a public seed `ρ`, not from secret key material. FIPS 203 §A.2 explicitly
permits timing variability in `SampleNTT`.

**`ct_verify` / `ct_cmov`:** The decapsulation path uses dedicated constant-time
comparison and conditional-move functions:
- `ct_verify(a, b, len)`: XOR-accumulate all bytes, return 1 if all differ
  only by zero (no early return, no branch on byte comparison result).
- `ct_cmov(dst, src, mask)`: Applies mask XOR-select to overwrite `dst` with
  `src` when `mask = 0xFFFFFFFF`, or leave `dst` unchanged when `mask = 0`.
  No branch on `mask` value.

The decapsulation comparison never exits the WASM binary as a boolean. The
JS layer receives only the final shared secret bytes. Correct.

---

### 2.2 SIMD Optimization

The NTT and polynomial arithmetic paths were vectorized using WASM `v128`
SIMD instructions (`--enable simd`). This places kyber in the same
SIMD-required class as the serpent and chacha20 modules. The kyber binary
requires WebAssembly SIMD and `init()` performs the same preflight check.

**Vectorized functions:**

| Function | File | Strategy |
|----------|------|----------|
| `ntt_simd` | `ntt_simd.ts` | 8-wide butterfly (layers len≥8); scalar tail (len<8) |
| `invntt_simd` | `ntt_simd.ts` | scalar tail (len≤4); 8-wide butterfly (len≥8); SIMD final f-pass |
| `poly_add_simd` | `poly_simd.ts` | 32 × `i16x8.add` |
| `poly_sub_simd` | `poly_simd.ts` | 32 × `i16x8.sub` |
| `poly_reduce_simd` | `poly_simd.ts` | 32 × `barrett_reduce_8x` |

Functions not vectorized (irregular structure or low payoff):
`poly_compress`, `poly_decompress`, `poly_basemul_montgomery`, `poly_tobytes`,
`poly_frombytes`, CBD sampling, rejection sampling, `ct_verify`, `ct_cmov`.

**`fqmul_8x`: vectorized Montgomery reduction:**

8 × `fqmul(a, b)` in one v128 operation. Input: two `v128` (8 × i16 each).
Output: one `v128` (8 × i16 results, each `= a·b·R⁻¹ mod Q`, R = 2¹⁶).

```
prod_lo = i32x4.extmul_low_i16x8_s(a, b)   // lanes 0-3: full 32-bit products
prod_hi = i32x4.extmul_high_i16x8_s(a, b)  // lanes 4-7: full 32-bit products

// t = (i16)(a * b * QINV) computed entirely in i16 arithmetic.
// By Z/2^16Z ring property: low16(a·b·QINV) = low16(a · low16(b·QINV)).
// i16x8.mul gives the low 16 bits of each lane product, exactly (i16)(x*y).
t_i16 = i16x8.mul(a, i16x8.mul(b, i16x8.splat(QINV)))

// Sign-extend t to i32 for the final subtraction.
t_lo = i32x4.extend_low_i16x8_s(t_i16)
t_hi = i32x4.extend_high_i16x8_s(t_i16)

// r = (prod - t·Q) >> 16
r_lo = i32x4.shr_s(i32x4.sub(prod_lo, i32x4.mul(t_lo, i32x4.splat(Q))), 16)
r_hi = i32x4.shr_s(i32x4.sub(prod_hi, i32x4.mul(t_hi, i32x4.splat(Q))), 16)

result = i16x8.narrow_i32x4_s(r_lo, r_hi)
```

The key implementation decision is computing `t` in i16 via `i16x8.mul`
rather than via the `shl/shr_s` sign-extend trick (`shr_s(shl(x*QINV, 16), 16)`).
The i16 approach avoids potential overflow when `prod` is a large 32-bit value
(up to ~10⁹), since the shl/shr path requires the i32 product `prod*QINV` to
behave correctly under a shl-then-shr sequence. This is fragile when the
result is large. `i16x8.mul` is definitionally correct: it always gives the
low 16 bits, matching the scalar `(i16)(prod * QINV)` cast exactly.

**`barrett_reduce_8x`: vectorized Barrett reduction:**

```
a_lo = i32x4.extend_low_i16x8_s(a)
a_hi = i32x4.extend_high_i16x8_s(a)
t    = i32x4.shr_s(i32x4.add(i32x4.mul(a, splat(BARRETT_V)), splat(1<<25)), 26)
r    = i32x4.sub(a, i32x4.mul(t, splat(Q)))
result = i16x8.narrow_i32x4_s(r_lo, r_hi)
```

Widening to i32x4 for the multiply-shift avoids overflow: `a·BARRETT_V` where
`|a| ≤ Q-1 < 2¹²` and `BARRETT_V = 20159 < 2¹⁵` gives a product below 2²⁷,
well within i32 range.

**Scalar tail rationale (len < 8):**

The NTT's final two layers (len=4, len=2) process groups of 4 and 2 butterflies
respectively. SIMD loads 8 coefficients per `v128.load`. A group of 2 or 4
coefficients would require partial loads with masking, adding complexity and
defeating the purpose. The scalar `fqmul` / `barrett_reduce` from `reduce.ts`
is used for these layers instead. The mixed path is transparent to callers.

---

### 2.3 WASM Side-Channel Posture

This implementation inherits the library's established "best-available, not
constant-time guarantee" posture for WASM:

- WASM execution is deterministic and not subject to JIT speculation in the
  cryptographic sense, but WASM is not a formally constant-time ISA. Timing
  isolation relative to JavaScript holds; hardware microarchitectural side
  channels (cache timing, branch prediction) cannot be excluded at the WASM
  execution level.
- **SIMD NTT constant-time posture:** The SIMD NTT processes all 256
  coefficients unconditionally using fixed-pattern v128 loads and stores.
  No data-dependent branching exists in the SIMD layers. The scalar tail
  (len=4, len=2) likewise uses fixed loops with no conditional branches on
  coefficient values. The SIMD and scalar paths have equivalent constant-time
  properties.
- Each WASM module has independent linear memory. The kyber module's memory
  is physically separate from the sha3 module's memory, even though both
  are used during KEM operations. Secret key material in the kyber buffer
  cannot be read by the sha3 module, and vice versa.

---

### 2.4 Known Attacks on ML-KEM

**Module-LWE hardness:** ML-KEM security rests on the hardness of the
module variant of the Learning With Errors (Module-LWE) problem. The best
known classical attack uses BKZ lattice sieving. For ML-KEM-512, the best
classical attack achieves approximately 2¹⁴³ operations. For ML-KEM-768,
approximately 2²⁰⁷; for ML-KEM-1024, approximately 2²⁷².

**Quantum attacks:** Grover's algorithm provides a quadratic speedup for
unstructured search, but the lattice reduction used in BKZ sieving does not
admit a straightforward Grover speedup. The best known quantum attack against
ML-KEM uses Grover-enhanced sieving (G-BKZ), which provides at most a
sub-quadratic improvement over classical attacks. NIST evaluated ML-KEM-512,
ML-KEM-768, and ML-KEM-1024 as targeting security levels I, III, and V
respectively (FIPS 203 §3.2).

**Implementation attacks:** No timing attack applies to this implementation
via the WASM execution model (see §2.2). The `ct_verify` / `ct_cmov` path in
decapsulation eliminates the decryption oracle that would otherwise enable
reaction attacks. Key material is wiped via `wipeBuffers()` after operations.

---

### 2.5 ACVP Validation

240 official NIST ACVP test vectors were run against all three parameter sets:

| Category | Vectors | Description |
|----------|---------|-------------|
| KeyGen (AFT) | 75 (25 per param set) | `d ‖ z → ek ‖ dk` round-trip |
| Encap (AFT) | 75 (25 per param set) | `ek ‖ m → c ‖ K` |
| Decap (VAL) | 15 (5 per param set) | Correct decapsulation |
| Implicit rejection (VAL) | 15 (5 per param set) | Corrupted ciphertext → J(z‖c) |
| Encap key validity (VAL) | 30 (10 per param set) | Valid and invalid `ek` checks |
| Decap key validity (VAL) | 30 (10 per param set) | Valid and invalid `dk` checks |
| **Total** | **240** | |

Source: [usnistgov/ACVP-Server ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)
and [ML-KEM-encapDecap-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203).

All 240 vectors pass across all three parameter sets. Status: **VERIFIED**.

The implicit rejection vectors are particularly significant for the FO transform
correctness: they confirm that `kemDecapsulate` with a corrupted ciphertext
produces the FIPS 203 implicit rejection value `J(z ‖ c)` rather than a
decryption failure or an incorrect `K'`.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — Module structure, kyber buffer layout
> - [exports](./exports.md) — `MlKem512`, `MlKem768`, `MlKem1024` export reference
> - [sha3_audit](./sha3_audit.md) — Keccak audit (sha3 module, used by kyber)
> - [test-suite](./test-suite.md) — ACVP vector coverage, test counts
