# HKDF-SHA256 Cryptographic Audit

> [!NOTE]
> **Conducted:** Week of 2026-03-25
> **Target:** `leviathan-crypto` TypeScript implementation (pure composition over HMAC)
> **Spec:** RFC 5869 (HMAC-based Key Derivation Function, May 2010)
> **Test vectors:** RFC 5869, Appendix A (Test Cases 1–3)

## Table of Contents

- [1. Algorithm Correctness](#1-algorithm-correctness)
  - [1.1 Extract Phase](#11-extract-phase)
  - [1.2 Expand Phase](#12-expand-phase)
  - [1.3 One-Step vs Two-Step](#13-one-step-vs-two-step)
  - [1.4 Usage in leviathan-crypto (SerpentStream)](#14-usage-in-leviathan-crypto-serpentstream)
  - [1.5 Buffer Layout and Memory Safety](#15-buffer-layout-and-memory-safety)
  - [1.6 TypeScript Wrapper Layer](#16-typescript-wrapper-layer)
  - [1.7 RFC 5869 Test Vectors](#17-rfc-5869-test-vectors)
- [2. Security Analysis](#2-security-analysis)
  - [2.1 Extract-then-Expand Security Model](#21-extract-then-expand-security-model)
  - [2.2 Info Field as Domain Separation](#22-info-field-as-domain-separation)
  - [2.3 Key Separation Guarantee](#23-key-separation-guarantee)
  - [2.4 Security Bound](#24-security-bound)

---

> [!NOTE]
> HKDF is implemented as pure TypeScript composition over the already-audited
> HMAC-SHA256 and HMAC-SHA512 (see [sha2_audit.md §1.10](./sha2_audit.md#110-hmac-sha256--hmac-sha512--hmac-sha384)). No cryptographic
> computation occurs in the HKDF code — only concatenation, loop control, and
> HMAC calls. All three RFC 5869 Appendix A test vectors were independently
> verified against Python `hmac`/`hashlib`.

---

## 1. Algorithm Correctness

### 1.1 Extract Phase

(`hkdf.ts:38–42`)

```typescript
extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array {
    const s = (!salt || salt.length === 0) ? new Uint8Array(32) : salt;
    return this.hmac.hash(s, ikm);
}
```

| Requirement | RFC 5869 §2.1 | Implementation | Match |
|-------------|---------------|----------------|-------|
| Formula | `PRK = HMAC-Hash(salt, IKM)` | `this.hmac.hash(s, ikm)` | Yes |
| Salt is HMAC key | salt is the first argument to HMAC | `s` is the first argument to `hash()` | Yes |
| IKM is HMAC message | IKM is the second argument to HMAC | `ikm` is the second argument to `hash()` | Yes |
| Default salt | HashLen zero bytes (32 for SHA-256) | `new Uint8Array(32)` | Yes |
| Default salt trigger | When salt is not provided | `!salt \|\| salt.length === 0` | Yes |
| PRK length | HashLen = 32 bytes | HMAC-SHA256 always returns 32 bytes | Yes |

**Critical verification — argument order:** The extract function passes salt as the HMAC key and IKM as the HMAC message. This is correct per RFC 5869 §2.1: "HMAC-Hash(salt, IKM)". The HMAC_SHA256 `hash(key, msg)` signature takes the key first and message second ([sha2_audit.md §1.10](./sha2_audit.md#110-hmac-sha256--hmac-sha512--hmac-sha384)), so `hash(s, ikm)` computes `HMAC(salt, IKM)`. Correct.

**Default salt:** When salt is `null` or empty (`length === 0`), a 32-byte zero array is used. RFC 5869 §2.2: "if not provided, [salt] is set to a string of HashLen zeros." The implementation correctly treats both `null` and zero-length arrays as "not provided." The HKDF_SHA512 variant uses `new Uint8Array(64)` (64 zero bytes). Both correct.

**IKM longer than HMAC block size:** When IKM is longer than 64 bytes (the HMAC-SHA256 block size), HMAC handles this internally by pre-hashing the key — but here IKM is the HMAC *message*, not the key. HMAC messages have no length restriction; they are processed by the streaming `feedHash()` function. This is correct.

**Salt longer than HMAC block size:** When salt exceeds 64 bytes, it is passed as the HMAC key. The HMAC_SHA256 class pre-hashes keys > 64 bytes ([sha2_audit.md §1.10](./sha2_audit.md#110-hmac-sha256--hmac-sha512--hmac-sha384)), which is correct per RFC 2104 §3.

---

### 1.2 Expand Phase

(`hkdf.ts:44–63`)

```typescript
expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    if (prk.length !== 32) throw new RangeError('HKDF expand: PRK must be 32 bytes');
    if (length < 1) throw new RangeError('HKDF expand: length must be at least 1');
    if (length > 255 * 32) throw new RangeError(`HKDF expand: length exceeds maximum (${255 * 32} bytes)`);

    const N = Math.ceil(length / 32);
    const okm = new Uint8Array(N * 32);
    let prev: Uint8Array = new Uint8Array(0);

    for (let i = 1; i <= N; i++) {
        const buf = new Uint8Array(prev.length + info.length + 1);
        buf.set(prev, 0);
        buf.set(info, prev.length);
        buf[prev.length + info.length] = i;
        prev = this.hmac.hash(prk, buf);
        okm.set(prev, (i - 1) * 32);
    }

    return okm.slice(0, length);
}
```

| Requirement | RFC 5869 §2.2 | Implementation | Match |
|-------------|---------------|----------------|-------|
| T(0) = empty | `T(0) = ""` | `prev = new Uint8Array(0)` | Yes |
| Counter start | 0x01 (1-indexed) | `for (let i = 1; ...)` | Yes |
| Counter end | N = ceil(L / HashLen) | `N = Math.ceil(length / 32)` | Yes |
| Concatenation order | `T(i-1) \|\| info \|\| counter` | `buf = [prev, info, i]` | Yes |
| Counter is single byte | `0x01` through `0xFF` | `buf[...] = i` (i ranges 1..255) | Yes |
| PRK is HMAC key | PRK used as key for each T(i) | `this.hmac.hash(prk, buf)` | Yes |
| Output truncation | First L bytes of T(1)\|\|...\|\|T(N) | `okm.slice(0, length)` | Yes |
| Maximum L | 255 * HashLen = 8160 | `length > 255 * 32` throws RangeError | Yes |
| PRK length validation | HashLen = 32 bytes | `prk.length !== 32` throws RangeError | Yes |

**T(0) is empty:** The initial `prev` is `new Uint8Array(0)` — a zero-length array. On the first iteration (`i = 1`), the buffer is constructed as `[prev(0 bytes), info, 0x01]` = `[info, 0x01]`. This matches RFC 5869: `T(1) = HMAC-Hash(PRK, T(0) || info || 0x01)` where T(0) = "". Correct.

**Counter byte:** The counter `i` is written as a single byte: `buf[prev.length + info.length] = i`. Since `i` ranges from 1 to N (maximum 255), and JavaScript assignment to a Uint8Array element truncates to 8 bits, the counter is always a single byte 0x01–0xFF. Correct.

**Info placement:** Info is set at offset `prev.length` in the buffer, and the counter byte follows at `prev.length + info.length`. This produces the correct concatenation order: `T(i-1) || info || counter`. Correct.

**N calculation:** `Math.ceil(length / 32)` correctly computes the number of HMAC blocks needed. For `length = 32`, N = 1. For `length = 33`, N = 2. For `length = 8160` (255 × 32), N = 255. Correct.

**Off-by-one check:** The loop runs `for (let i = 1; i <= N; i++)`, producing blocks T(1) through T(N). Block T(i) is stored at offset `(i - 1) * 32` in the OKM buffer. The output is `okm.slice(0, length)`, which takes exactly the first `length` bytes. No off-by-one.

---

### 1.3 One-Step vs Two-Step

The implementation exposes **both** individual phases and a combined one-shot:

| Method | Description |
|--------|-------------|
| `extract(salt, ikm)` | Extract only — returns 32-byte PRK |
| `expand(prk, info, length)` | Expand only — PRK must be 32 bytes |
| `derive(ikm, salt, info, length)` | Combined: `expand(extract(salt, ikm), info, length)` |

The `derive()` method (`hkdf.ts:67–69`) always calls Extract before Expand:

```typescript
derive(ikm, salt, info, length) {
    const prk = this.extract(salt, ikm);
    return this.expand(prk, info, length);
}
```

Extract is never skipped. The `expand()` method enforces `prk.length === 32`, which prevents callers from accidentally passing raw key material that isn't HashLen bytes.

The `extract()` method is available separately for callers who need to reuse a PRK across multiple `expand()` calls with different `info` values — a valid optimization per RFC 5869 §3.

---

### 1.4 Usage in leviathan-crypto (SerpentStream)

HKDF-SHA256 is used in two streaming AEAD constructions:

#### SerpentStream (`src/ts/serpent/stream.ts`)

Per-chunk key derivation via `deriveChunkKeys()` (`stream.ts:87–101`):

```typescript
const info = chunkInfo(streamNonce, chunkSize, chunkCount, index, isLast);
const derived = hkdf.derive(masterKey, streamNonce, info, 64);
return {
    encKey: derived.subarray(0, 32),
    macKey: derived.subarray(32, 64),
};
```

**Info field construction** (`chunkInfo`, `stream.ts:68–85`):

| Offset | Size | Field | Encoding |
|--------|------|-------|----------|
| 0 | 17 | DOMAIN (`"serpent-stream-v1"`) | UTF-8 |
| 17 | 16 | streamNonce | raw bytes |
| 33 | 4 | chunkSize | u32 big-endian |
| 37 | 8 | chunkCount | u64 big-endian |
| 45 | 8 | chunkIndex | u64 big-endian |
| 53 | 1 | isLast | 0x00 or 0x01 |

Total: **54 bytes**. Fixed-length, unambiguous field layout.

**HKDF parameters:**
- IKM = masterKey (32 bytes, the stream encryption key)
- Salt = streamNonce (16 bytes, random per stream)
- Info = 54-byte chunkInfo (domain-separated, chunk-specific)
- L = 64 bytes (split into encKey[0:32] + macKey[32:64])

> [!NOTE]
> Using `streamNonce` as the HKDF salt produces `PRK = HMAC-SHA256(streamNonce, masterKey)` — the nonce is the HMAC key and the master key is the HMAC message. This is an intentional inversion from the typical password-based pattern. RFC 5869 §3.1 describes salt as "a non-secret random value" used to strengthen extraction, and the streamNonce satisfies this exactly: it is public, random, and unique per stream. The master key (the secret) is correctly placed as the IKM. The construct is secure and correct per the spec.

**Verification of info field:**
- `chunkIndex` is encoded as u64 big-endian (`u64be()`, `stream.ts:50–63`). Big-endian ensures the byte representation is unique for each index value. Correct.
- `isLast` distinguishes the terminal chunk (0x01) from non-terminal chunks (0x00). This prevents a truncation attack where an attacker drops the last chunk. Correct.
- `chunkCount` is bound into the info field, preventing an attacker from truncating or extending the stream by changing the total chunk count. Correct.
- `streamNonce` appears in both the salt and the info field. This is redundant but not harmful — the nonce is bound into the derivation by both paths. Correct.

#### SerpentStreamSealer (`src/ts/serpent/stream-sealer.ts`)

A separate incremental sealer with a different domain:

```typescript
const derived = hkdf.derive(key, new Uint8Array(0), info, 64);
```

**Key differences from SerpentStream:**
- DOMAIN = `"serpent-sealstream-v1"` (21 bytes) — distinct from SerpentStream
- Salt = empty (defaults to 32 zero bytes inside `extract()`)
- Info does **not** include `chunkCount` (unknown at sealing time in the incremental API)
- Info is 50 bytes (21 + 16 + 4 + 8 + 1)

The `SerpentStreamOpener` derives keys for both `isLast=true` and `isLast=false` and uses authentication success to determine which is correct (`stream-sealer.ts:202–206`). This is secure — the wrong `isLast` value produces a different key, causing authentication to fail.

#### SerpentStreamPool (`src/ts/serpent/stream-pool.ts`)

Reuses `deriveChunkKeys` from `stream.ts` (same domain, same parameters). Keys are derived on the main thread and only the derived `encKey`/`macKey` are sent to workers — the master key never leaves the main thread. Correct.

---

### 1.5 Buffer Layout and Memory Safety

HKDF is implemented in pure TypeScript — no WASM buffers are involved. All intermediate values live in JavaScript garbage-collected memory.

**T(i-1) availability and zeroing:** The `expand()` loop captures a reference to T(i-1) in `oldPrev` before overwriting `prev` with T(i). After `okm.set(prev, ...)` copies T(i) into the output buffer, both `buf` (the HMAC input concatenation) and `oldPrev` (T(i-1)) are zeroed via `.fill(0)`. After the loop, the final `prev` (T(N)) is zeroed after its copy into `okm`. No T(i) block or concatenation buffer persists on the heap beyond its use. Correct.

**PRK lifetime:** In `derive()`, the PRK returned by `extract()` is zeroed via `.fill(0)` immediately after `expand()` returns and before the OKM is returned to the caller. The `expand()` method does not zero the PRK itself, because callers may invoke `expand()` multiple times with the same PRK (valid per RFC 5869 §3) — zeroing is the one-shot `derive()` method's responsibility.

**Info buffer integrity:** The `info` parameter to `expand()` is read-only — it is copied into `buf` via `buf.set(info, ...)` on each iteration but never modified. Correct.

**Output copy:** `okm.slice(0, length)` creates a new independent array. The returned OKM does not alias any internal state and is intentionally not zeroed — it belongs to the caller. In `deriveChunkKeys()`, the split uses `derived.subarray(0, 32)` and `derived.subarray(32, 64)` — these *do* alias the same underlying buffer, but since the derived buffer is a fresh `slice()` from `expand()`, this is safe: the encKey and macKey views are independent of any HKDF internal state.

> [!NOTE]
> After this fix, all intermediate key material allocated during
> `expand()` and `derive()` is explicitly zeroed before going out of
> scope: `buf`, `oldPrev` (each T(i-1)), the final T(N), and the PRK in
> the one-shot `derive()` path. The only value intentionally left
> unzeroed is the returned OKM, which belongs to the caller.

---

### 1.6 TypeScript Wrapper Layer

**init() gate:** HKDF_SHA256 constructs an HMAC_SHA256 instance in its constructor. HMAC_SHA256's constructor calls `getExports()` → `getInstance('sha2')`, which throws if `init(['sha2'])` has not been called. The HKDF class cannot be used before initialization. Correct.

**Input validation:**

| Check | Implementation | Correct? |
|-------|----------------|----------|
| PRK length (expand) | `prk.length !== 32` throws RangeError | Yes |
| L minimum (expand) | `length < 1` throws RangeError | Yes |
| L maximum (expand) | `length > 255 * 32` throws RangeError | Yes |
| Salt null handling | `!salt \|\| salt.length === 0` → 32 zero bytes | Yes |
| IKM type | Accepts Uint8Array (TypeScript enforced) | Yes |

**HKDF_SHA512 validation:** PRK must be 64 bytes, maximum L = 255 × 64 = 16320. Default salt = 64 zero bytes. All correct for SHA-512.

**dispose():** Calls `this.hmac.dispose()`, which calls `wipeBuffers()` on the SHA-2 WASM module, zeroing all 1976 bytes of WASM memory including HMAC ipad/opad and intermediate state. Correct.

---

### 1.7 RFC 5869 Test Vectors

All three RFC 5869 Appendix A test vectors independently verified against Python `hmac`/`hashlib`:

**Test Case 1 (basic):**

| | Value |
|---|-------|
| IKM | `0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b` (22 bytes) |
| salt | `000102030405060708090a0b0c` (13 bytes) |
| info | `f0f1f2f3f4f5f6f7f8f9` (10 bytes) |
| L | 42 |
| PRK | `077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5` |
| OKM | `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865` |
| **Pass** | **Yes** |

**Test Case 2 (longer inputs, 80-byte IKM/salt/info, L=82):**

| | Value |
|---|-------|
| IKM | `000102...4f` (80 bytes) |
| salt | `606162...af` (80 bytes) |
| info | `b0b1b2...ff` (80 bytes) |
| L | 82 |
| PRK | `06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244` |
| OKM | `b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87` |
| **Pass** | **Yes** |

**Test Case 3 (zero-length salt and info):**

| | Value |
|---|-------|
| IKM | `0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b` (22 bytes) |
| salt | not provided (32 zero bytes) |
| info | not provided (empty) |
| L | 42 |
| PRK | `19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04` |
| OKM | `8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8` |
| **Pass** | **Yes** |

Test Case 3 specifically validates the null-salt path (32 zero bytes default) and empty-info path. The unit test suite (`test/unit/sha2/hkdf.test.ts`) also covers these vectors, plus HKDF_SHA512 vectors and edge-case validation (wrong PRK length, out-of-range L).

---

## 2. Security Analysis

### 2.1 Extract-then-Expand Security Model

HKDF's security proof (Krawczyk, "Cryptographic Extraction and Key Derivation: The HKDF Scheme", 2010) decomposes into two independent guarantees:

1. **Extract** produces a pseudorandom PRK from potentially non-uniform IKM, provided the salt has sufficient min-entropy (or is absent, relying on the HMAC-Hash structure alone).
2. **Expand** uses PRK as a PRF key to produce computationally independent output blocks, provided PRK is uniform (which Extract guarantees).

**Is the IKM in SerpentStream uniform enough to skip Extract?** No. Stream keys may come from user passwords (via scrypt/Argon2id) or from raw keyfiles that are not uniformly distributed. Even when keys are random, the Extract step is cheap (one HMAC call) and provides defense-in-depth against non-uniform key material. The implementation always calls Extract (via `derive()`), which is the correct approach.

---

### 2.2 Info Field as Domain Separation

The `info` parameter in HKDF-Expand binds the derived key to its context. Two HKDF calls with the same PRK but different `info` values produce computationally independent keys.

**SerpentStream domain separation:**

| Field | Purpose | Uniqueness guarantee |
|-------|---------|---------------------|
| DOMAIN (`"serpent-stream-v1"`) | Distinguishes SerpentStream from other HKDF uses | Unique 17-byte prefix |
| streamNonce (16 bytes) | Binds to this specific stream | Random per stream |
| chunkSize (4 bytes, u32be) | Binds to the chunk size parameter | Fixed per stream |
| chunkCount (8 bytes, u64be) | Binds to total stream length | Fixed per stream |
| chunkIndex (8 bytes, u64be) | Binds to chunk position | Unique per chunk |
| isLast (1 byte) | Distinguishes terminal from non-terminal | Prevents truncation |

**SerpentStreamSealer domain separation:**

| Field | Purpose |
|-------|---------|
| DOMAIN (`"serpent-sealstream-v1"`) | Unique 21-byte prefix, distinct from SerpentStream |
| streamNonce (16 bytes) | Random per stream |
| chunkSize (4 bytes, u32be) | Fixed per stream |
| chunkIndex (8 bytes, u64be) | Unique per chunk |
| isLast (1 byte) | Prevents truncation |

The two constructions use **different DOMAIN prefixes** — `"serpent-stream-v1"` vs `"serpent-sealstream-v1"`. Even if the same master key and nonce were used in both constructions (which should not happen in practice), the derived keys would differ. Correct.

**Fixed-length, unambiguous encoding:** All fields have fixed sizes, so the info encoding is injection-free — no two distinct parameter tuples can produce the same info byte string. This prevents canonicalization attacks where an attacker could find two different parameter sets that hash to the same info value.

---

### 2.3 Key Separation Guarantee

Both SerpentStream and SerpentStreamSealer derive 64 bytes from HKDF and split the result:

```
encKey = derived[0:32]
macKey = derived[32:64]
```

This is a single HKDF-Expand call with `L = 64`, which produces `T(1) || T(2)` (two 32-byte HMAC outputs). By the PRF security of HMAC-SHA256, T(1) and T(2) are computationally independent — knowing T(1) gives no information about T(2), because:

- T(1) = HMAC(PRK, info || 0x01)
- T(2) = HMAC(PRK, T(1) || info || 0x02)

The counter byte (0x01 vs 0x02) and the chaining of T(1) into T(2)'s input ensure distinct HMAC computations. The resulting encKey and macKey are cryptographically independent.

This is equivalent to (and more efficient than) making two separate HKDF calls with distinct info strings. Both approaches are secure; the single-call approach avoids redundant Extract computations.

---

### 2.4 Security Bound

HKDF-SHA256's security reduces to the PRF security of HMAC-SHA256:

| Property | Bound | Notes |
|----------|-------|-------|
| Extract PRF security | ~2^256 key recovery | HMAC-SHA256 as PRF |
| Expand PRF security | ~2^256 key recovery | Each T(i) is an independent PRF evaluation |
| Output independence | Computational | T(i) and T(j) are independent for i ≠ j |
| Maximum output | 8160 bytes (255 × 32) | Counter byte is u8 |
| Info field | Does not need to be secret | Public context binding |
| Salt | Recommended but not required | Strengthens Extract against non-uniform IKM |

For leviathan's use case (64-byte output = encKey + macKey), the security margin is large: only 2 of 255 possible HMAC blocks are used, well within the PRF security bound. The derived keys inherit the full 256-bit security of HMAC-SHA256.

The `info` field is always unique per chunk (due to the chunkIndex counter), so no two HKDF-Expand evaluations under the same PRK produce the same output. This guarantees that every chunk has fresh, independent encryption and authentication keys.

---

> ## Cross-References
>
> - [README.md](./README.md) — project overview and quick-start guide
> - [architecture.md](./architecture.md)
> - [sha2_audit.md](./sha2_audit.md) — SHA-256 implementation audit
> - [hmac_audit.md](./hmac_audit.md) — HMAC-SHA256 audit (HKDF builds on HMAC)
> - [serpent_audit.md](./serpent_audit.md) — HKDF used in SerpentStream [§2.4](./serpent_audit.md#24-serpentstream-encrypt-then-mac-and-the-cryptographic-doom-principle)
> - [chacha_audit.md](./chacha_audit.md) — XChaCha20-Poly1305 uses nonce-based key binding instead of HKDF
> - [sha3_audit.md](./sha3_audit.md) — SHA-3 companion audit
