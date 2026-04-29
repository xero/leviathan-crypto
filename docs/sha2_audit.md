# SHA-2 Cryptographic Audit

> [!NOTE]
> Cryptographic audit of the `leviathan-crypto` WebAssembly SHA-2 implementation (AssemblyScript) against FIPS 180-4, covering SHA-224, SHA-256, SHA-384, and SHA-512. Conducted week of 2026-03-25.

> ### Table of Contents
> - [1. Algorithm Correctness](#1-algorithm-correctness)
>   - [1.1 Rotation and Shift Operations](#11-rotation-and-shift-operations)
>   - [1.2 Logical Functions (Ch, Maj, Sigma, sigma)](#12-logical-functions-ch-maj-sigma-sigma)
>   - [1.3 Constants](#13-constants)
>   - [1.4 Padding](#14-padding)
>   - [1.5 Message Schedule](#15-message-schedule)
>   - [1.6 Compression Function](#16-compression-function)
>   - [1.7 Truncated Variants (SHA-224, SHA-384)](#17-truncated-variants-sha-224-sha-384)
>   - [1.8 Buffer Layout and Memory Safety](#18-buffer-layout-and-memory-safety)
>   - [1.9 TypeScript Wrapper Layer](#19-typescript-wrapper-layer)
>   - [1.10 HMAC-SHA256 / HMAC-SHA512 / HMAC-SHA384](#110-hmac-sha256--hmac-sha512--hmac-sha384)
>   - [1.11 HKDF-SHA256 / HKDF-SHA512](#111-hkdf-sha256--hkdf-sha512)
>   - [1.12 NIST Test Vectors](#112-nist-test-vectors)
> - [2. Security Analysis](#2-security-analysis)
>   - [2.1 Side-Channel Analysis](#21-side-channel-analysis)
>   - [2.2 Known Attacks on SHA-256 / SHA-512](#22-known-attacks-on-sha-256--sha-512)
>   - [2.3 Usage Context in leviathan-crypto](#23-usage-context-in-leviathan-crypto)

---

> [!NOTE]
> All SHA-256 and SHA-512 constants (K values, initial hash values) were independently
> verified by computing the fractional parts of square roots / cube roots of primes
> using high-precision (50-digit) decimal arithmetic. NIST test vectors were verified
> against Python `hashlib`. No value was taken from the implementation or from
> any planning document without independent derivation.

---

## 1. Algorithm Correctness

### 1.1 Rotation and Shift Operations

**SHA-256** (`sha256.ts:149–152`): We use AssemblyScript's built-in `rotr<i32>()`, which compiles directly to the WASM `i32.rotr` instruction—a single CPU instruction on all modern architectures. No manual shift-or patterns.

- `rotr<i32>(x, n)`: right rotation. Equivalent to `(x >>> n) | (x << (32 - n))`.
- `x >>> n`: logical (unsigned) right shift (WASM `i32.shr_u`).

**SHA-512** (`sha512.ts:172`): AssemblyScript has no built-in `rotr<i64>()`, so we define `rotr64(x, n)` as `(x >>> n) | (x << (64 - n))` using i64 operands. This manual form compiles to efficient WASM i64 shift/or instructions.

- `x >>> n` on i64: logical right shift (WASM `i64.shr_u`).

**Wraparound:** SHA-256 arithmetic is on `i32`, which wraps natively at 2^32 in WASM with no masking. SHA-512 uses `i64`, wrapping natively at 2^64. Both are correct per FIPS 180-4 §2.2.1.

---

### 1.2 Logical Functions (Ch, Maj, Sigma, sigma)

**SHA-256 functions** (`sha256.ts:147–152`):

| Function | FIPS 180-4 §4.1.2 | Implementation | Match |
|----------|-------------------|----------------|-------|
| Ch(x,y,z) | `(x & y) ^ (~x & z)` | `(x & y) ^ (~x & z)` | Exact |
| Maj(x,y,z) | `(x & y) ^ (x & z) ^ (y & z)` | `(x & y) ^ (x & z) ^ (y & z)` | Exact |
| Sigma0(x) | `ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)` | `rotr<i32>(x, 2) ^ rotr<i32>(x, 13) ^ rotr<i32>(x, 22)` | Exact |
| Sigma1(x) | `ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)` | `rotr<i32>(x, 6) ^ rotr<i32>(x, 11) ^ rotr<i32>(x, 25)` | Exact |
| sigma0(x) | `ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)` | `rotr<i32>(x, 7) ^ rotr<i32>(x, 18) ^ (x >>> 3)` | Exact |
| sigma1(x) | `ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)` | `rotr<i32>(x, 17) ^ rotr<i32>(x, 19) ^ (x >>> 10)` | Exact |

**SHA-512 functions** (`sha512.ts:175–184`):

| Function | FIPS 180-4 §4.1.3 | Implementation | Match |
|----------|-------------------|----------------|-------|
| Ch512(e,f,g) | `(e & f) ^ (~e & g)` | `(e & f) ^ (~e & g)` | Exact |
| Maj512(a,b,c) | `(a & b) ^ (a & c) ^ (b & c)` | `(a & b) ^ (a & c) ^ (b & c)` | Exact |
| Sigma0_512(x) | `ROTR^28(x) ^ ROTR^34(x) ^ ROTR^39(x)` | `rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)` | Exact |
| Sigma1_512(x) | `ROTR^14(x) ^ ROTR^18(x) ^ ROTR^41(x)` | `rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)` | Exact |
| sigma0_512(x) | `ROTR^1(x) ^ ROTR^8(x) ^ SHR^7(x)` | `rotr64(x, 1) ^ rotr64(x, 8) ^ (x >>> 7)` | Exact |
| sigma1_512(x) | `ROTR^19(x) ^ ROTR^61(x) ^ SHR^6(x)` | `rotr64(x, 19) ^ rotr64(x, 61) ^ (x >>> 6)` | Exact |

All rotation amounts are correct. SHA-256 and SHA-512 use different rotation constants—a detail that's easy to miss when copying between implementations. We define separate function sets for each variant. The code includes a prominent warning (`sha512.ts:170`): "DO NOT copy from SHA-256. The rotation constants are different."

> [!NOTE]
> All six SHA-256 functions and all six SHA-512 functions are marked `@inline`.
> This instructs the AssemblyScript compiler to inline them at all call sites,
> eliminating function-call overhead in the compression loop.

---

### 1.3 Constants

#### SHA-256 Round Constants K[0..63]

All 64 SHA-256 K constants (`sha256.ts:58–121`) were independently verified by computing `floor(frac(cbrt(prime[t])) * 2^32)` for the first 64 primes using Python floating-point arithmetic. Every value matches FIPS 180-4 §4.2.2 exactly.

Spot check (first 8):

| Index | FIPS 180-4 | Implementation | Match |
|-------|-----------|----------------|-------|
| K0 | `0x428a2f98` | `0x428a2f98` | Yes |
| K1 | `0x71374491` | `0x71374491` | Yes |
| K7 | `0xab1c5ed5` | `0xab1c5ed5` | Yes |
| K54 | `0x5b9cca4f` | `0x5b9cca4f` | Yes |
| K63 | `0xc67178f2` | `0xc67178f2` | Yes |

> [!NOTE]
> K54 carries an explicit audit comment (`sha256.ts:112`): the leviathan TypeScript
> reference implementation's `dist/sha256.js` contained `0xe34d799b` for K[54]. An
> incorrect value. The WASM implementation has the correct value `0x5b9cca4f`.
> See `leviathan/docs/SHA256_AUDIT.md` for the forensic record.

The `kAt()` function (`sha256.ts:124–143`) returns constants via a switch statement with a `default: return K63` fallback. This is correct. The compression loop calls `kAt(t)` for `t = 0..63`, and the default case handles `t = 63`.

#### SHA-512 Round Constants K[0..79]

All 80 SHA-512 K constants (`sha512.ts:57–136`) were independently verified by computing `floor(frac(cbrt(prime[t])) * 2^64)` using Python `Decimal` with 50-digit precision. Every value matches FIPS 180-4 §4.2.3 exactly.

Spot check:

| Index | Independently computed | Implementation | Match |
|-------|----------------------|----------------|-------|
| K0 | `0x428a2f98d728ae22` | `0x428a2f98d728ae22` | Yes |
| K54 | `0x5b9cca4f7763e373` | `0x5b9cca4f7763e373` | Yes |
| K79 | `0x6c44198c4a475817` | `0x6c44198c4a475817` | Yes |

The `kAt512()` function (`sha512.ts:139–162`) mirrors the SHA-256 pattern with `default: return K79`.

#### SHA-256 Initial Hash Values

All 8 SHA-256 IVs (`sha256.ts:225–232`) match FIPS 180-4 §5.3.3 exactly:

| | FIPS 180-4 | Implementation | Match |
|---|-----------|----------------|-------|
| H0 | `0x6a09e667` | `0x6a09e667` | Yes |
| H1 | `0xbb67ae85` | `0xbb67ae85` | Yes |
| H2 | `0x3c6ef372` | `0x3c6ef372` | Yes |
| H3 | `0xa54ff53a` | `0xa54ff53a` | Yes |
| H4 | `0x510e527f` | `0x510e527f` | Yes |
| H5 | `0x9b05688c` | `0x9b05688c` | Yes |
| H6 | `0x1f83d9ab` | `0x1f83d9ab` | Yes |
| H7 | `0x5be0cd19` | `0x5be0cd19` | Yes |

Verified by computing `floor(frac(sqrt(prime[i])) * 2^32)` for primes 2, 3, 5, 7, 11, 13, 17, 19.

#### SHA-512 Initial Hash Values

All 8 SHA-512 IVs (`sha512.ts:265–272`) match FIPS 180-4 §5.3.5 exactly:

| | FIPS 180-4 | Implementation | Match |
|---|-----------|----------------|-------|
| H0 | `0x6a09e667f3bcc908` | `0x6a09e667f3bcc908` | Yes |
| H1 | `0xbb67ae8584caa73b` | `0xbb67ae8584caa73b` | Yes |
| H2 | `0x3c6ef372fe94f82b` | `0x3c6ef372fe94f82b` | Yes |
| H3 | `0xa54ff53a5f1d36f1` | `0xa54ff53a5f1d36f1` | Yes |
| H4 | `0x510e527fade682d1` | `0x510e527fade682d1` | Yes |
| H5 | `0x9b05688c2b3e6c1f` | `0x9b05688c2b3e6c1f` | Yes |
| H6 | `0x1f83d9abfb41bd6b` | `0x1f83d9abfb41bd6b` | Yes |
| H7 | `0x5be0cd19137e2179` | `0x5be0cd19137e2179` | Yes |

Verified by computing `floor(frac(sqrt(prime[i])) * 2^64)` with 50-digit Decimal precision.

#### SHA-384 Initial Hash Values

All 8 SHA-384 IVs (`sha512.ts:275–282`) match FIPS 180-4 §5.3.4 exactly:

| | FIPS 180-4 | Implementation | Match |
|---|-----------|----------------|-------|
| H0 | `0xcbbb9d5dc1059ed8` | `0xcbbb9d5dc1059ed8` | Yes |
| H1 | `0x629a292a367cd507` | `0x629a292a367cd507` | Yes |
| H2 | `0x9159015a3070dd17` | `0x9159015a3070dd17` | Yes |
| H3 | `0x152fecd8f70e5939` | `0x152fecd8f70e5939` | Yes |
| H4 | `0x67332667ffc00b31` | `0x67332667ffc00b31` | Yes |
| H5 | `0x8eb44a8768581511` | `0x8eb44a8768581511` | Yes |
| H6 | `0xdb0c2e0d64f98fa7` | `0xdb0c2e0d64f98fa7` | Yes |
| H7 | `0x47b5481dbefa4fa4` | `0x47b5481dbefa4fa4` | Yes |

Verified by computing `floor(frac(sqrt(prime[i])) * 2^64)` for primes 23, 29, 31, 37, 41, 43, 47, 53 (the 9th through 16th primes). Note: SHA-384 IVs are the **full 64-bit** values from these primes, **not** related to the SHA-224 truncation pattern.

#### SHA-224 Initial Hash Values

The implementation does not include a separate SHA-224 variant. The reference lists the SHA-224 IVs:

```
h0 = 0xc1059ed8    h1 = 0x367cd507
h2 = 0x3070dd17    h3 = 0xf70e5939
h4 = 0xffc00b31    h5 = 0x68581511
h6 = 0x64f98fa7    h7 = 0xbefa4fa4
```

These are the **second (low) 32 bits** of the SHA-384 IVs, verified independently. SHA-224 is not implemented in leviathan-crypto; this section is included for completeness only.

---

### 1.4 Padding

**SHA-256 padding** (`sha256.ts:282–312`, `sha256Final()`):

| Step | FIPS 180-4 §5.1.1 | Implementation | Match |
|------|-------------------|----------------|-------|
| Append 0x80 | Append bit "1" after message | `store<u8>(SHA256_BLOCK_OFFSET + partial, 0x80)` | Yes |
| Zero fill | k zero bits s.t. L+1+k ≡ 448 (mod 512) | `memory.fill(..., 0, 56 - partial)` | Yes |
| Two-block case | If partial > 56, compress and start new block | `if (partial > 56) { ... compress ... partial = 0 }` | Yes |
| Length field | 64-bit big-endian bit count at bytes [56..63] | `bitLen = totalBytes << 3; store32be(..., 56, hi); store32be(..., 60, lo)` | Yes |

The two-block threshold is correct: after appending 0x80, if `partial > 56`, there is no room for the 8-byte length field in the remaining bytes [partial..63]. The implementation zeros the rest, compresses, then starts a fresh block with the length field.

The `totalBytes` counter is stored as `i64` (`SHA256_TOTAL_OFFSET`, 8 bytes), supporting messages up to 2^64 bytes. The bit-length is computed as `totalBytes << 3` (i64 shift), then split into high and low 32-bit words for big-endian storage. This correctly handles messages longer than 2^32 bytes.

**SHA-512 padding** (`sha512.ts:349–381`, `sha512Final()`):

| Step | FIPS 180-4 §5.1.2 | Implementation | Match |
|------|-------------------|----------------|-------|
| Append 0x80 | Append bit "1" | `store<u8>(SHA512_BLOCK_OFFSET + partial, 0x80)` | Yes |
| Zero fill | k zero bits s.t. L+1+k ≡ 896 (mod 1024) | `memory.fill(..., 0, 112 - partial)` | Yes |
| Two-block case | If partial > 112 | `if (partial > 112) { ... sha512Compress() ... partial = 0 }` | Yes |
| Length field | 128-bit big-endian bit count at bytes [112..127] | `bitsHi = totalBytes >>> 61; bitsLo = totalBytes << 3` | Yes |

The 128-bit length field is split into two 64-bit words: `bitsHi` captures the top 3 bits of the byte count (the bits that overflow when multiplying by 8), and `bitsLo` is the byte count left-shifted by 3. The `>>> 61` is an unsigned right shift, which is correct for extracting the high bits.

**Edge cases:**

- Empty message: `partial = 0` → append 0x80 at byte 0 → `partial = 1` → not > 56 (SHA-256) / not > 112 (SHA-512) → zero fill → length field = 0 → single-block compress. Correct.
- 55-byte SHA-256 message: `partial = 55` → append 0x80 at byte 55 → `partial = 56` → not > 56 → `memory.fill(..., 0, 56 - 56)` (zero bytes) → length field at [56..63]. Single block. Correct.
- 56-byte SHA-256 message: `partial = 56` → append 0x80 at byte 56 → `partial = 57` → 57 > 56 → compress, new block, length field. Two blocks. Correct.

---

### 1.5 Message Schedule

**SHA-256** (`sha256.ts:182–191`):

```
for t = 0 to 15:   W[t] = load32be(blockOffset, t*4)
for t = 16 to 63:  W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
```

This matches FIPS 180-4 §6.2.2 exactly. The schedule words are loaded as big-endian 32-bit values via `load32be()`, and expanded using the sigma0/sigma1 functions verified in §1.2. Addition is mod 2^32 by native i32 arithmetic.

The schedule is stored in `SHA256_W_OFFSET` (256 bytes = 64 × 4 bytes) using big-endian encoding via `store32be()`/`load32be()`. This is consistent. Every access to the schedule goes through the same big-endian helpers.

**SHA-512** (`sha512.ts:222–231`):

```
for t = 0 to 15:   W[t] = load64be(SHA512_BLOCK_OFFSET, t*8)
for t = 16 to 79:  W[t] = sigma1_512(W[t-2]) + W[t-7] + sigma0_512(W[t-15]) + W[t-16]
```

Matches FIPS 180-4 §6.4.2 exactly. Uses 64-bit operations, 80 rounds, and `load64be()`/`store64be()` for consistent big-endian storage. The schedule lives in `SHA512_W_OFFSET` (640 bytes = 80 × 8 bytes).

---

### 1.6 Compression Function

**SHA-256** (`sha256.ts:180–219`):

The compression function implements FIPS 180-4 §6.2.2 steps 2–4:

Step 2: initialize working variables (`sha256.ts:194–201`):
```
a,b,c,d,e,f,g,h = load32be(SHA256_H_OFFSET, 0..28)
```
All 8 state words loaded from H buffer in big-endian format. Correct.

Step 3: 64 rounds (`sha256.ts:204–209`):

| Spec | Implementation | Match |
|------|----------------|-------|
| `T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]` | `T1 = h + bSig1(e) + Ch(e,f,g) + kAt(t) + load32be(SHA256_W_OFFSET, t*4)` | Yes |
| `T2 = Sigma0(a) + Maj(a,b,c)` | `T2 = bSig0(a) + Maj(a,b,c)` | Yes |
| `h=g; g=f; f=e; e=d+T1` | `h=g; g=f; f=e; e=d+T1` | Yes |
| `d=c; c=b; b=a; a=T1+T2` | `d=c; c=b; b=a; a=T1+T2` | Yes |

The 8-variable rotation is identical to the spec. The round count is hardcoded to 64 (`for (let t = 0; t < 64; t++)`).

Step 4: add-back (`sha256.ts:212–219`):
```
H[i] = H[i] + working_variable  (for i = 0..7)
```
Each state word is loaded from `SHA256_H_OFFSET`, added to the corresponding working variable, and stored back. Addition is mod 2^32 by i32 arithmetic. Correct.

**SHA-512** (`sha512.ts:220–260`):

Structurally identical to SHA-256, with the following differences:

- 64-bit operands (i64) throughout
- 80 rounds (`for (let t = 0; t < 80; t++)`)
- Uses `Sigma0_512`/`Sigma1_512`/`sigma0_512`/`sigma1_512`/`Ch512`/`Maj512`
- State at `SHA512_H_OFFSET`, schedule at `SHA512_W_OFFSET`
- `load64be()`/`store64be()` for memory access

All verified to match FIPS 180-4 §6.4. The round count of 80 is hardcoded.

---

### 1.7 Truncated Variants (SHA-224, SHA-384)

**SHA-384** (`sha512.ts:386–391`):

`sha384Final()` simply calls `sha512Final()`. The SHA-384 digest is the first 48 bytes (6 of 8 64-bit words) at `SHA512_OUT_OFFSET`. The TypeScript wrapper (`src/ts/sha2/index.ts:153`) reads only the first 48 bytes:

```typescript
return mem.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 48);
```

This is correct: SHA-384 uses the same compression as SHA-512, with different IVs (verified in §1.3) and truncated output. The truncation happens **after** the full compression completes. No early truncation.

The `sha384Init()` function (`sha512.ts:312–315`) loads SHA-384-specific IVs via `loadIVs()`. These IVs are **distinct** from SHA-512's IVs, independently verified in §1.3.

**SHA-224**: Not implemented. The codebase provides SHA-256, SHA-384, and SHA-512 only. This is a design choice, not a deficiency; SHA-224 is rarely needed in modern applications.

---

### 1.8 Buffer Layout and Memory Safety

The SHA-2 WASM module uses static buffer allocation in linear memory (`buffers.ts`):

| Offset | Size | Name | Purpose |
|--------|------|------|---------|
| 0 | 32 | SHA256_H | Hash state H0..H7 (8 × i32) |
| 32 | 64 | SHA256_BLOCK | Block accumulator |
| 96 | 256 | SHA256_W | Message schedule W[0..63] (64 × i32) |
| 352 | 32 | SHA256_OUT | Digest output |
| 384 | 64 | SHA256_INPUT | User input staging |
| 448 | 4 | SHA256_PARTIAL | Partial block byte count (i32) |
| 452 | 8 | SHA256_TOTAL | Total bytes hashed (i64) |
| 460 | 64 | HMAC256_IPAD | K' XOR 0x36 |
| 524 | 64 | HMAC256_OPAD | K' XOR 0x5c |
| 588 | 32 | HMAC256_INNER | Inner hash for HMAC outer pass |
| 620 | 64 | SHA512_H | Hash state H0..H7 (8 × i64) |
| 684 | 128 | SHA512_BLOCK | Block accumulator |
| 812 | 640 | SHA512_W | Message schedule W[0..79] (80 × i64) |
| 1452 | 64 | SHA512_OUT | Digest output |
| 1516 | 128 | SHA512_INPUT | User input staging |
| 1644 | 4 | SHA512_PARTIAL | Partial block byte count (i32) |
| 1648 | 8 | SHA512_TOTAL | Total bytes hashed (i64) |
| 1656 | 128 | HMAC512_IPAD | K' XOR 0x36 |
| 1784 | 128 | HMAC512_OPAD | K' XOR 0x5c |
| 1912 | 64 | HMAC512_INNER | Inner hash for HMAC outer pass |

Total: **1976 bytes**. No gaps, no overlaps. All buffers are contiguous and tightly packed. The layout was verified programmatically: each buffer starts exactly where the previous one ends.

**No aliasing:** The message schedule W[] and hash state H[] occupy distinct, non-overlapping regions (SHA256_W at offset 96 vs SHA256_H at offset 0; SHA512_W at offset 812 vs SHA512_H at offset 620). No aliasing is possible.

**No dynamic allocation:** `memory.grow()` is never called. All offsets are compile-time constants exported from `buffers.ts`.

**Endianness conversions:** Both SHA-256 and SHA-512 store and load all multi-byte values in big-endian format using manual byte-level `load<u8>`/`store<u8>` helpers (`load32be`, `store32be`, `load64be`, `store64be`). This is consistent throughout. There are no mixed-endianness bugs. The helpers are correct:

- `load32be`: loads 4 bytes, shifts into MSB-first order. Correct.
- `store32be`: extracts bytes via `>>> 24/16/8/0`, masks with `& 0xff`. Correct.
- `store64be` (`sha512.ts:202–212`): uses arithmetic right shift (`>>`) instead of logical (`>>>`), but casts to `u8`. The low 8 bits are identical regardless of sign extension. Functionally correct.

**`wipeBuffers()`** (`index.ts:42`): `memory.fill(0, 0, 1976)`. Zeros the entire 1976-byte buffer region. This covers all hash state, schedule, HMAC key material, ipad/opad, and intermediate values. Correct and complete.

---

### 1.9 TypeScript Wrapper Layer

The TypeScript classes in `src/ts/sha2/index.ts` provide the public API.

**init() gate:** Every class constructor calls `getExports()` → `getInstance('sha2')`, which throws if the `sha2` module has not been loaded via `init(['sha2'])`. No class can be used before initialization. Correct.

**Input handling: `feedHash()`** (`index.ts:86–96`):

```typescript
function feedHash(x, msg, inputOff, chunkSize, updateFn) {
    const mem = new Uint8Array(x.memory.buffer);
    let pos = 0;
    while (pos < msg.length) {
        const n = Math.min(msg.length - pos, chunkSize);
        mem.set(msg.subarray(pos, pos + n), inputOff);
        updateFn(n);
        pos += n;
    }
}
```

This correctly chunks arbitrarily-large messages into `chunkSize`-byte segments (64 for SHA-256, 128 for SHA-512) and feeds each to the WASM `update()` function. The WASM streaming API handles partial-block accumulation internally.

**Output is a copy:** All hash/HMAC methods use `mem.slice()` (not `mem.subarray()`) to return the digest. `slice()` creates an independent copy. The returned `Uint8Array` does not alias WASM linear memory. If WASM memory is later zeroed by `dispose()` or overwritten by another operation, the caller's digest is unaffected. Correct.

**dispose():** Every class calls `this.x.wipeBuffers()`, which zeros all 1976 bytes of SHA-2 module memory. Correct.

**SHA256 class** (`index.ts:100–117`): Calls `sha256Init()`, feeds via `feedHash(..., 64, sha256Update)`, calls `sha256Final()`, returns 32 bytes from `SHA256_OUT_OFFSET`. Correct.

**SHA512 class** (`index.ts:121–138`): Same pattern with 128-byte chunks, returns 64 bytes. Correct.

**SHA384 class** (`index.ts:140–159`): Uses `sha384Init()`, feeds via `sha512Update` (SHA-384 shares SHA-512 buffers), calls `sha384Final()`, returns **48 bytes**. Correct. This is the truncated output per FIPS 180-4 §6.5.

---

### 1.10 HMAC-SHA256 / HMAC-SHA512 / HMAC-SHA384

**HMAC-SHA256** (`hmac.ts`):

The implementation follows RFC 2104 exactly:

```
HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
```

`hmac256Init(keyLen)` (`hmac.ts:63–79`):
1. Reads key from `SHA256_INPUT_OFFSET[0..keyLen-1]`
2. XORs each key byte with `0x36` → `HMAC256_IPAD_OFFSET`, with `0x5c` → `HMAC256_OPAD_OFFSET`
3. Zero-pads: remaining bytes get `0x36` / `0x5c` (equivalent to `0x00 XOR ipad/opad`)
4. Calls `sha256Init()` + feeds the 64-byte ipad block to start the inner hash

`hmac256Final()` (`hmac.ts:88–101`):
1. Finalizes inner hash → `SHA256_OUT_OFFSET`
2. Saves inner hash to `HMAC256_INNER_OFFSET` (prevents overwrite by step 3)
3. Starts outer hash: `sha256Init()` + feeds 64-byte opad block
4. Feeds 32-byte inner hash
5. Finalizes → `SHA256_OUT_OFFSET` contains the 32-byte HMAC tag

**HMAC-SHA512** (`hmac512.ts:71–109`): Same structure with 128-byte block size, SHA-512 hash, 64-byte inner hash. Correct.

**HMAC-SHA384** (`hmac512.ts:119–156`): Uses SHA-384 init/final (distinct IVs), but 128-byte block size (same as SHA-512). Inner hash is **48 bytes**. The implementation copies only 48 bytes at `hmac384Final()` step 2 (`memory.copy(HMAC512_INNER_OFFSET, SHA512_OUT_OFFSET, 48)`). The outer hash feeds this 48-byte value. Output is 48 bytes. Correct per RFC 2104 with SHA-384.

**Long key handling (TypeScript layer):** The `HMAC_SHA256` class (`index.ts:169–186`) pre-hashes keys > 64 bytes via `sha256Init`/`feedHash`/`sha256Final` before calling `hmac256Init(32)`. RFC 2104 §3: "If the length of K > B, then first hash K using H and then use the resulting L-byte string." Correct. `HMAC_SHA512` uses the 128-byte threshold with SHA-512 pre-hash. `HMAC_SHA384` uses the 128-byte threshold with SHA-384 pre-hash. All correct.

---

### 1.11 HKDF-SHA256 / HKDF-SHA512

Both HKDF classes (`hkdf.ts`) implement RFC 5869 as pure TypeScript composition over the HMAC classes.

**HKDF-SHA256** (`hkdf.ts:31–75`):

- **Extract** (§2.2): `PRK = HMAC-SHA256(salt, IKM)`. If salt is null or empty, defaults to `new Uint8Array(32)` (32 zero bytes). Correct. RFC 5869 §2.1: "if not provided, [salt] is set to a string of HashLen zeros."
- **Expand** (§2.3): Iterates `T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)` for `i = 1..N`, where `N = ceil(L/32)`. Validates PRK is 32 bytes, length is 1..255*32. Correct.

**HKDF-SHA512** (`hkdf.ts:79–123`): Same structure with 64-byte hash length, 64-byte default salt, PRK must be 64 bytes, max length 255*64. Correct.

Both classes delegate to the already-verified HMAC implementations. No cryptographic computation occurs in the HKDF TypeScript code. Only concatenation and loop control.

---

### 1.12 NIST Test Vectors

All variants verified against NIST FIPS 180-4 known-answer test vectors
and Python `hashlib`:

| Variant | Input | Expected digest (hex) | Pass |
|---------|-------|-----------------------|------|
| SHA-256 | `""` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Yes |
| SHA-256 | `"abc"` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | Yes |
| SHA-256 | `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` | Yes |
| SHA-512 | `""` (empty) | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` | Yes |
| SHA-512 | `"abc"` | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f` | Yes |
| SHA-384 | `"abc"` | `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7` | Yes |

---

## 2. Security Analysis

### 2.1 Side-Channel Analysis

| Component | Implementation | Constant-Time? |
|-----------|---------------|----------------|
| Ch, Maj | AND/XOR/NOT via WASM i32/i64 ops | Yes |
| Sigma, sigma | `rotr` + XOR + SHR | Yes |
| Message schedule expansion | Fixed loop, no data-dependent branches | Yes |
| Compression rounds | Fixed 64/80 iterations, no early exit | Yes |
| Padding | Branch on partial count (public) | N/A (not secret) |
| HMAC ipad/opad | Byte-by-byte XOR, fixed loop bounds | Yes |

SHA-2 uses only add, rotate, XOR, AND, OR, and NOT operations. **No table lookups.** Unlike AES, there are no S-boxes that would create cache-timing side channels. The entire compression function is a fixed sequence of arithmetic operations with no data-dependent branches.

**WASM execution model:** As noted in the [Serpent audit](./serpent_audit.md#21-side-channel-analysis), WASM integer operations (`i32.and`, `i32.xor`, `i32.rotr`, `i64.add`, etc.) have fixed-width semantics compiled ahead-of-time. JIT speculative optimizations do not apply to WASM. The uniform, branch-free compression loop provides constant-time properties that are as strong as a browser execution environment can offer.

**No data-dependent branches in the compression loop:** The SHA-256 compression (`sha256.ts:204–209`) runs exactly 64 iterations unconditionally. The SHA-512 compression (`sha512.ts:244–249`) runs exactly 80 iterations. No iteration is skipped or short-circuited based on data values.

> [!NOTE]
> SHA-2 is not used for key material directly in leviathan-crypto. It serves as
> the hash function inside HMAC and HKDF. Side-channel concerns are therefore
> inherited by those constructions, but HMAC adds no new timing-variable operations
> beyond the underlying hash.

---

### 2.2 Known Attacks on SHA-256 / SHA-512

#### Length Extension Attacks

SHA-256 and SHA-512 are vulnerable to length extension: given `H(m)` and `len(m)`, an attacker can compute `H(m || padding || m')` without knowing `m`. This is a structural property of the Merkle-Damgard construction, not an implementation bug.

**Assessment for leviathan-crypto:** The codebase **never** uses raw SHA-256/SHA-512 for MAC purposes (see §2.3). All authentication tags are computed via HMAC, which is immune to length extension by construction (`HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))`. The outer hash prevents extension of the inner hash.

The one usage of raw SHA-256 outside HMAC is in Fortuna (`src/ts/fortuna.ts`), which uses it for internal state chaining (`SHA256(genKey || seed)` and `SHA256(poolHash || id || data)`). These are not MAC constructions. The hash inputs and outputs are internal state; the library never exposes them to an attacker. The Fortuna design (Ferguson & Schneier) deliberately uses raw SHA-256 for this purpose.

**Verdict: No length extension vulnerability exists in any externally-observable construction.**

#### Collision Resistance

Best known collision attack on full SHA-256: **none practical**. The best theoretical result reaches approximately 38 of 64 rounds (Mendel et al., 2011). Full 64-round SHA-256 retains a **26-round security margin** against collision attacks, providing the full 128-bit collision resistance expected of a 256-bit hash.

SHA-512: no collision attack beyond birthday-bound complexity (2^256) is known for the full 80 rounds.

#### Preimage Resistance

Best known preimage attack on SHA-256: 52 of 64 rounds (Aoki & Sasaki, 2009) with 2^251.7 complexity. No practical threat. Full SHA-256 provides the expected 256-bit preimage resistance.

SHA-512: best known preimage attacks reach fewer rounds with even higher complexity. No practical concern.

#### SHA-384 Truncation Security

SHA-384 truncates SHA-512's output from 512 to 384 bits. Truncation does not reduce collision resistance below the output length: SHA-384 provides 192-bit collision resistance (birthday bound on 384-bit output). This exceeds any practical attack threshold. SHA-384 also uses distinct IVs from SHA-512 (verified in §1.3), ensuring that `SHA384(m) != truncate(SHA512(m))`. Domain separation is maintained.

---

### 2.3 Usage Context in leviathan-crypto

A comprehensive search of the codebase identified all SHA-2 usage outside the core SHA-2 module:

| Component | SHA-2 Usage | Construction | Secure? |
|-----------|-------------|--------------|---------|
| `SerpentSeal` | HMAC-SHA256(macKey, iv\|\|ct) | Encrypt-then-MAC | Yes |
| `SerpentCipher` | HMAC-SHA256(mac_key, counterNonce\|\|aad\|\|ct) + HKDF-SHA256 | Streaming AEAD (CBC+HMAC) | Yes |
| `XChaCha20Cipher` | HKDF-SHA256 for stream key derivation | KDF | Yes |
| `SealStreamPool` | HKDF-SHA256 for key derivation | KDF | Yes |
| `Fortuna` | Raw SHA-256 for internal state | CSPRNG state chaining | Yes (by design) |

**Key findings:**

1. **No raw SHA-2 used for MAC.** The library computes every authentication tag via HMAC-SHA256 or HMAC-SHA512. Length extension is not a concern.

2. **No key reuse across constructions.** SerpentSeal splits its 64-byte key into a 32-byte encryption key and a 32-byte MAC key. SerpentCipher uses HKDF to derive separate keys (enc_key, mac_key, iv_key). No context shares a key for both hashing and another purpose.

3. **Fortuna's raw SHA-256 usage is by design.** The CSPRNG uses `SHA256(genKey || seed)` for rekeying and `SHA256(poolHash || id || data)` for pool chaining. These follow the published Fortuna specification (Ferguson & Schneier, "Practical Cryptography"). The hash outputs are internal state, never exposed to callers. An attacker cannot mount a length extension attack because they never see the intermediate hash values.

4. **HKDF usage is correct.** Both HKDF-SHA256 and HKDF-SHA512 follow RFC 5869 with proper extract-then-expand. The extract step uses HMAC (not raw hash), so salt+IKM processing is immune to length extension.

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [sha3_audit](./sha3_audit.md) | SHA-3 companion audit (independent construction) |
| [hmac_audit](./hmac_audit.md) | HMAC-SHA256 builds on SHA-256 |
| [hkdf_audit](./hkdf_audit.md) | HKDF-SHA256 builds on HMAC-SHA256 |
| [serpent_audit](./serpent_audit.md) | uses HMAC-SHA256 in SerpentCipher |
| [chacha_audit](./chacha_audit.md) | XChaCha20-Poly1305 companion audit |

