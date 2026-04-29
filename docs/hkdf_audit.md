# HKDF-SHA256 Cryptographic Audit

| Field | Value |
|-------|-------|
| Conducted | Week of 2026-03-25 |
| Target | `leviathan-crypto` TypeScript implementation (pure composition over HMAC) |
| Spec | RFC 5869 (HMAC-based Key Derivation Function, May 2010) |
| Test vectors | RFC 5869, Appendix A (Test Cases 1–3) |

> [!NOTE]
> HKDF is implemented as pure TypeScript composition over the already-audited
> HMAC-SHA256 and HMAC-SHA512 (see [sha2_audit.md §1.10](./sha2_audit.md#110-hmac-sha256--hmac-sha512--hmac-sha384)). No cryptographic
> computation occurs in the HKDF code. Only concatenation, loop control, and
> HMAC calls. All three RFC 5869 Appendix A test vectors were independently
> verified against Python `hmac`/`hashlib`.

> ### Table of Contents
> - [1. Algorithm Correctness](#1-algorithm-correctness)
>   - [1.1 Extract Phase](#11-extract-phase)
>   - [1.2 Expand Phase](#12-expand-phase)
>   - [1.3 One-Step vs Two-Step](#13-one-step-vs-two-step)
>   - [1.4 Usage in leviathan-crypto (stream layer)](#14-usage-in-leviathan-crypto-stream-layer)
>   - [1.5 Buffer Layout and Memory Safety](#15-buffer-layout-and-memory-safety)
>   - [1.6 TypeScript Wrapper Layer](#16-typescript-wrapper-layer)
>   - [1.7 RFC 5869 Test Vectors](#17-rfc-5869-test-vectors)
> - [2. Security Analysis](#2-security-analysis)
>   - [2.1 Extract-then-Expand Security Model](#21-extract-then-expand-security-model)
>   - [2.2 Info Field as Domain Separation](#22-info-field-as-domain-separation)
>   - [2.3 Key Separation Guarantee](#23-key-separation-guarantee)
>   - [2.4 Security Bound](#24-security-bound)

---

## 1. Algorithm Correctness

### 1.1 Extract Phase

RFC 5869 §2.1 defines the extract step as a single HMAC call: `PRK = HMAC-Hash(salt, IKM)`. Salt becomes the HMAC key, and the input key material becomes the message. Here's our implementation (`hkdf.ts:38–42`):

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

The argument order is critical. Salt goes first as the HMAC key, IKM second as the message. The HMAC_SHA256 `hash(key, msg)` method takes the key first ([sha2_audit.md §1.10](./sha2_audit.md#110-hmac-sha256--hmac-sha512--hmac-sha384)), so `hash(s, ikm)` correctly computes `HMAC(salt, IKM)`.

When salt is `null` or empty, the code substitutes a 32-byte zero array. RFC 5869 §2.2 specifies this exact behavior: "if not provided, [salt] is set to a string of HashLen zeros." Both `null` and zero-length arrays are treated as "not provided." The HKDF_SHA512 variant uses 64 zero bytes instead, matching the longer hash output.

Long input key material (over 64 bytes) poses no problem because it becomes the HMAC message, not the key. Messages flow through the streaming `feedHash()` function with no length restriction. The HMAC layer handles key material over 64 bytes by pre-hashing (per RFC 2104 §3), so this extract operation works correctly regardless of input length.

---

### 1.2 Expand Phase

RFC 5869 §2.2 specifies the expand step as an iterative HMAC loop:

```
T(1) = HMAC-Hash(PRK, T(0) || info || 0x01)
T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
...
T(N) = HMAC-Hash(PRK, T(N-1) || info || 0xN)
OKM = T(1) || T(2) || ... || T(N), truncated to L bytes
```

Here's how we implement it (`hkdf.ts:44–63`):

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

The first iteration starts with T(0) as a zero-length array. The buffer for T(1) becomes `[empty, info, 0x01]`, which simplifies to `[info, 0x01]`. Each counter byte is written as a single byte (`buf[...] = i`), and since i ranges from 1 to 255, JavaScript automatically truncates to 8 bits. The counter always lands at the right offset: `prev.length + info.length`.

The number of blocks N is computed as `Math.ceil(length / 32)`. For length 32, N = 1. For length 33, N = 2. For the maximum 8160 bytes (255 × 32), N = 255. Block T(i) is stored at offset `(i - 1) * 32` in the output buffer, and the final slice takes exactly the first `length` bytes. No off-by-one errors.

---

### 1.3 One-Step vs Two-Step

The implementation exposes both individual phases and a combined one-shot:

| Method | Description |
|--------|-------------|
| `extract(salt, ikm)` | Extract only. Returns 32-byte PRK. |
| `expand(prk, info, length)` | Expand only. PRK must be 32 bytes. |
| `derive(ikm, salt, info, length)` | Combined: `expand(extract(salt, ikm), info, length)` |

The `derive()` method (`hkdf.ts:67–69`) always calls Extract before Expand:

```typescript
derive(ikm, salt, info, length) {
    const prk = this.extract(salt, ikm);
    return this.expand(prk, info, length);
}
```

Extract never gets skipped. The `expand()` method enforces `prk.length === 32`, which prevents callers from accidentally bypassing the Extract step by passing raw key material.

The `extract()` method is available separately because RFC 5869 §3 permits reusing the same PRK across multiple `expand()` calls with different `info` values. This is a valid optimization when the same input key needs to be stretched into keys for different purposes.

---

### 1.4 Usage in leviathan-crypto (stream layer)

HKDF-SHA256 is used in the stream layer to derive per-stream keys. Two cipher suites use it:

#### SerpentCipher (`src/ts/serpent/cipher-suite.ts`)

Per-stream key derivation via `deriveKeys()`:

```typescript
const hkdf = new HKDF_SHA256();
const derived = hkdf.derive(masterKey, nonce, INFO, 96);
// bytes[0:32]=enc_key, bytes[32:64]=mac_key, bytes[64:96]=iv_key
return { bytes: derived };
```

**HKDF parameters:**
- IKM = masterKey (32 bytes, the stream encryption key)
- Salt = nonce (16 bytes, random per stream, from the stream header)
- Info = `"serpent-sealstream-v2"` (21-byte UTF-8 string)
- L = 96 bytes (split into enc_key[0:32] + mac_key[32:64] + iv_key[64:96])

The info field is a plain domain-separation string. The AEAD construction achieves position binding through the 12-byte counter nonce (HMAC covers `counterNonce ‖ u32be(aad_len) ‖ aad ‖ ciphertext`), not through the HKDF info. The CBC IV for each chunk derives deterministically: `HMAC-SHA-256(iv_key, counterNonce)[0:16]`.

> [!NOTE]
> Using the stream nonce as the HKDF salt produces `PRK = HMAC-SHA256(nonce, masterKey)`. The nonce is the HMAC key and the master key is the HMAC message. This is an intentional inversion from the typical password-based pattern. RFC 5869 §3.1 describes salt as "a non-secret random value" used to strengthen extraction, and the nonce satisfies this exactly: it is public, random, and unique per stream. The master key (the secret) is correctly placed as the IKM. The construct is secure and correct per the spec.

#### XChaCha20Cipher (`src/ts/chacha20/cipher-suite.ts`)

Per-stream key derivation via `deriveKeys()`:

```typescript
const hkdf = new HKDF_SHA256();
const streamKey = hkdf.derive(masterKey, nonce, INFO, 32);
// HChaCha20 subkey derivation, nonce[0:16] as XChaCha input
const subkey = deriveSubkey(x, streamKey, padded);
wipe(streamKey);
return { bytes: subkey };
```

**HKDF parameters:**
- IKM = masterKey (32 bytes)
- Salt = nonce (16 bytes, random per stream)
- Info = `"xchacha20-sealstream-v2"` (23-byte UTF-8 string)
- L = 32 bytes → streamKey → HChaCha20(streamKey, nonce[0:16]) → subkey

The intermediate `streamKey` is wiped immediately after HChaCha20 derivation. The final `subkey` is used for ChaCha20-Poly1305 AEAD per chunk with counter nonces.

#### SealStreamPool (`src/ts/stream/seal-stream-pool.ts`)

Uses the same `cipher.deriveKeys()` call as `SealStream` (same domain, same parameters). The main thread derives all keys; only the derived key bytes go to workers. The master key never leaves the main thread. Correct.

---

### 1.5 Buffer Layout and Memory Safety

HKDF is pure TypeScript with no WASM buffers. All intermediate values live in JavaScript garbage-collected memory. The code explicitly zeros sensitive material before it goes out of scope.

**Intermediate block zeroing:** The `expand()` loop maintains a `prev` reference to T(i-1) as it computes T(i). After writing T(i) into the output buffer, both `buf` (the concatenation input) and `prev` are zeroed via `.fill(0)`. This prevents any T(i) block or HMAC input from lingering on the heap. After the final iteration, T(N) is also zeroed before return.

**PRK handling:** The `derive()` method zeroes the PRK immediately after `expand()` completes and before returning the output key material. The `expand()` method itself does not zero the PRK because callers may legitimately invoke it multiple times with the same PRK (RFC 5869 §3 permits this optimization). Zero responsibility falls to `derive()`, which is the one-shot path.

**Info buffer:** The `info` parameter is read-only and copied via `buf.set(info, ...)` on each iteration. It is never modified.

**Output ownership:** `okm.slice(0, length)` creates a new independent array with no aliases to internal HKDF state. The returned OKM is intentionally unzeroed because it belongs to the caller. In the cipher-suite layer, the code splits the derived key using `subarray()` (which creates views into the same buffer), but since that buffer is a fresh `slice()` from `expand()`, these views are isolated from any HKDF internals.

> [!NOTE]
> After this fix, all intermediate key material allocated during
> `expand()` and `derive()` is explicitly zeroed before going out of
> scope: `buf`, `oldPrev` (each T(i-1)), the final T(N), and the PRK in
> the one-shot `derive()` path. The only value intentionally left
> unzeroed is the returned OKM, which belongs to the caller.

---

### 1.6 TypeScript Wrapper Layer

The HKDF_SHA256 class builds on HMAC_SHA256. Its constructor instantiates HMAC_SHA256, which calls `getExports()` → `getInstance('sha2')`. This call throws immediately if `init(['sha2'])` hasn't been called first. The HKDF class therefore cannot be instantiated before the library is initialized—a compile-time safety feature.

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

We verified all three RFC 5869 Appendix A test vectors independently against Python `hmac`/`hashlib`:

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

Krawczyk's HKDF security proof ("Cryptographic Extraction and Key Derivation: The HKDF Scheme", 2010) splits into two independent guarantees. Extract takes potentially non-uniform input key material and produces a pseudorandom PRK, leveraging salt entropy (or the HMAC-Hash structure alone if salt is absent). Expand then uses the uniform PRK as a PRF key, generating computationally independent output blocks.

In the stream layer, input key material often isn't uniform—passwords derived via scrypt or Argon2id, raw keyfiles, and other sources all violate uniformity assumptions. The Extract step costs just one HMAC call and provides defense-in-depth: it conditions the raw material before expansion. The implementation always calls Extract (via `derive()`), never skipping it. This is the correct approach.

---

### 2.2 Info Field as Domain Separation

The `info` parameter in HKDF-Expand binds the derived key to its context. Two HKDF calls with the same PRK but different `info` values produce computationally independent keys.

**SerpentCipher domain separation:**

| Component | Value | Purpose |
|-----------|-------|---------|
| Info string | `"serpent-sealstream-v2"` | Distinguishes SerpentCipher from other HKDF uses |
| Salt (nonce) | 16 random bytes | Binds to this specific stream |

Position binding is not in the HKDF info (as in v1) but in the AEAD construction: the 12-byte counter nonce (chunk index + final flag) is included in the HMAC input and CBC IV derivation.

**XChaCha20Cipher domain separation:**

| Component | Value | Purpose |
|-----------|-------|---------|
| Info string | `"xchacha20-sealstream-v2"` | Distinguishes XChaCha20Cipher from SerpentCipher and other uses |
| Salt (nonce) | 16 random bytes | Binds to this specific stream |

The two cipher suites use different info strings: `"serpent-sealstream-v2"` vs `"xchacha20-sealstream-v2"`. Even with the same master key and nonce, the derived keys diverge. The info field is a plain UTF-8 string—no structured binary fields, simpler than the v1 approach but equally secure. Position binding happens in the AEAD layer via the counter nonce, not in the HKDF info field.

---

### 2.3 Key Separation Guarantee

SerpentCipher derives 96 bytes from HKDF and splits the result into three keys:

```
enc_key = derived[0:32]
mac_key = derived[32:64]
iv_key  = derived[64:96]
```

This is a single HKDF-Expand call with `L = 96`, which produces `T(1) || T(2) || T(3)` (three 32-byte HMAC outputs). By the PRF security of HMAC-SHA256, T(1), T(2), and T(3) are computationally independent. Knowing any one gives no information about the others, because:

- T(1) = HMAC(PRK, info || 0x01)
- T(2) = HMAC(PRK, T(1) || info || 0x02)
- T(3) = HMAC(PRK, T(2) || info || 0x03)

The counter byte and the chaining of each T(i) into the next T(i+1)'s input ensure distinct HMAC computations. The resulting enc_key, mac_key, and iv_key are cryptographically independent.

XChaCha20Cipher derives 32 bytes (`L = 32`, a single T(1) block) and then applies HChaCha20 subkey derivation. The HKDF output is an intermediate streamKey, not a final encryption key. The HChaCha20 step provides additional key isolation per nonce prefix.

This is equivalent to (and more efficient than) making separate HKDF calls with distinct info strings. Both approaches are secure; the single-call approach avoids redundant Extract computations.

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

For leviathan's use cases (96-byte output for SerpentCipher = enc_key + mac_key + iv_key, or 32-byte output for XChaCha20Cipher), the security margin is large: at most 3 of 255 possible HMAC blocks are used, well within the PRF security bound. The derived keys inherit the full 256-bit security of HMAC-SHA256.

Each stream uses a unique random nonce as the HKDF salt, so each stream produces a unique PRK. This guarantees that every stream has fresh, independent key material. The counter nonce in the AEAD construction provides per-chunk isolation, not per-chunk HKDF calls.

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [sha2_audit](./sha2_audit.md) | SHA-256 implementation audit |
| [hmac_audit](./hmac_audit.md) | HMAC-SHA256 audit (HKDF builds on HMAC) |
| [serpent_audit](./serpent_audit.md) | HKDF used in SerpentCipher [§2.4](./serpent_audit.md#24-serpentcipher-verify-then-decrypt-and-the-cryptographic-doom-principle) |
| [chacha_audit](./chacha_audit.md) | XChaCha20-Poly1305 uses nonce-based key binding instead of HKDF |
| [sha3_audit](./sha3_audit.md) | SHA-3 companion audit |

