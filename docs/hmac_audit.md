# HMAC-SHA256 Cryptographic Audit

> [!NOTE]
> **Conducted:** Week of 2026-03-25
> **Target:** `leviathan-crypto` WebAssembly implementation (AssemblyScript)
> **Spec:** RFC 2104 (HMAC, February 1997)
>           FIPS 198-1 (The Keyed-Hash MAC, July 2008)
> **Test vectors:** RFC 4231

## Table of Contents

- [1. Algorithm Correctness](#1-algorithm-correctness)
  - [1.1 Key Processing](#11-key-processing)
  - [1.2 ipad and opad Constants](#12-ipad-and-opad-constants)
  - [1.3 Inner and Outer Hash](#13-inner-and-outer-hash)
  - [1.4 Test Vector Verification](#14-test-vector-verification)
  - [1.5 Buffer Layout and Memory Safety](#15-buffer-layout-and-memory-safety)
  - [1.6 TypeScript Wrapper Layer](#16-typescript-wrapper-layer)
- [2. Security Analysis](#2-security-analysis)
  - [2.1 Length Extension Immunity](#21-length-extension-immunity)
  - [2.2 Security Bound](#22-security-bound)
  - [2.3 Key Size Recommendations](#23-key-size-recommendations)
  - [2.4 Usage Context in leviathan-crypto](#24-usage-context-in-leviathan-crypto)

---

> [!NOTE]
> **Prerequisite:** The SHA-256 implementation has been audited separately
> in [sha2_audit.md](./sha2_audit.md). This audit treats SHA-256 as a verified
> black box and focuses exclusively on the HMAC construction layered on top.

---

## 1. Algorithm Correctness

### 1.1 Key Processing

The HMAC key processing is split across two layers:

**TypeScript layer** (`src/ts/sha2/index.ts:169–186`, `HMAC_SHA256.hash`):

```typescript
let k = key;
if (k.length > 64) {
    this.x.sha256Init();
    feedHash(this.x, k, this.x.getSha256InputOffset(), 64, this.x.sha256Update);
    this.x.sha256Final();
    k = mem.slice(this.x.getSha256OutOffset(), this.x.getSha256OutOffset() + 32);
}
mem.set(k, this.x.getSha256InputOffset());
this.x.hmac256Init(k.length);
```

**WASM layer** (`src/asm/sha2/hmac.ts:63–79`, `hmac256Init`):

```
for i = 0..keyLen-1:   ipad[i] = K[i] ^ 0x36;  opad[i] = K[i] ^ 0x5c
for i = keyLen..63:    ipad[i] = 0x36;           opad[i] = 0x5c
```

| Key length | RFC 2104 §3 requirement | Implementation |
|-----------|------------------------|----------------|
| `len(K) > B` (> 64) | `K' = H(K)`, then zero-pad to B | TypeScript pre-hashes to 32 bytes via `sha256Init/Update/Final`, passes 32-byte result to `hmac256Init(32)` |
| `len(K) < B` (< 64) | Zero-pad K to B bytes | `hmac256Init` loop: `keyLen..63` set to `0x00 ^ ipad = 0x36` and `0x00 ^ opad = 0x5c` |
| `len(K) == B` (== 64) | Use as-is | `hmac256Init(64)` — padding loop range `64..63` is empty, no modification |
| `len(K) == L` (== 32) | Zero-pad to B (not hashed — 32 < 64) | TypeScript: `32 > 64` is false, skip hashing. `hmac256Init(32)` — pads bytes 32–63 |

The edge case of `len(K) == L` (32 bytes, the hash output length) is handled correctly: the key is shorter than B, so it is zero-padded without hashing. This matches RFC 2104 §3 precisely.

> [!NOTE]
> The long-key path (`len(K) > 64`) is handled entirely in TypeScript, not in WASM. The `hmac256Init` WASM function has a `keyLen ≤ 64` precondition — the `SHA256_INPUT_OFFSET` buffer is only 64 bytes. The TypeScript wrapper enforces this by pre-hashing long keys before calling the WASM layer. This is documented in `hmac.ts:47–49`.

---

### 1.2 ipad and opad Constants

The ipad and opad values are applied in `hmac256Init` (`hmac.ts:66–74`):

| Constant | RFC 2104 §2 | Implementation |
|----------|-------------|----------------|
| ipad | `0x36` repeated B times | `kb ^ 0x36` for key bytes; `0x36` for pad bytes (`hmac.ts:68, 72`) |
| opad | `0x5c` repeated B times | `kb ^ 0x5c` for key bytes; `0x5c` for pad bytes (`hmac.ts:69, 73`) |

The values `0x36` and `0x5c` are correct. They are applied across the full 64-byte (B) key block — both loops together cover indices `0` through `63`, producing 64 bytes each for `HMAC256_IPAD_OFFSET` and `HMAC256_OPAD_OFFSET`.

The pad-byte branch (`hmac.ts:72–73`) writes `0x36` and `0x5c` directly. This is equivalent to `0x00 ^ 0x36 = 0x36` and `0x00 ^ 0x5c = 0x5c`, since the zero-padded key bytes are 0x00. The optimization avoids an unnecessary XOR with zero.

---

### 1.3 Inner and Outer Hash

**Inner hash:** `H((K' ^ ipad) || message)`

`hmac256Init` (`hmac.ts:76–78`):
```
sha256Init()                                              // reset SHA-256 state
memory.copy(SHA256_INPUT_OFFSET, HMAC256_IPAD_OFFSET, 64) // copy ipad key block
sha256Update(64)                                           // process ipad block
```

After `hmac256Init`, the SHA-256 state contains the intermediate hash of the 64-byte ipad block. The caller then feeds message data via `hmac256Update`, which passes through directly to `sha256Update` (`hmac.ts:83–85`).

**Outer hash:** `H((K' ^ opad) || inner_hash)`

`hmac256Final` (`hmac.ts:88–101`):
```
sha256Final()                                                // finalize inner hash → SHA256_OUT_OFFSET
memory.copy(HMAC256_INNER_OFFSET, SHA256_OUT_OFFSET, 32)     // save inner hash (32 bytes)
sha256Init()                                                  // reset for outer hash
memory.copy(SHA256_INPUT_OFFSET, HMAC256_OPAD_OFFSET, 64)    // copy opad key block
sha256Update(64)                                              // process opad block
memory.copy(SHA256_INPUT_OFFSET, HMAC256_INNER_OFFSET, 32)   // load inner hash
sha256Update(32)                                              // process inner hash
sha256Final()                                                 // finalize outer hash → SHA256_OUT_OFFSET
```

The outer hash processes exactly `B + L = 64 + 32 = 96` bytes:
- 64 bytes: `K' ^ opad` (the opad key block)
- 32 bytes: the inner hash output

This matches the RFC 2104 §2 definition exactly.

> [!NOTE]
> Step 2 (`memory.copy` to `HMAC256_INNER_OFFSET`) is essential — `sha256Init()` in step 3 clears the SHA-256 hash state at `SHA256_H_OFFSET`, and `sha256Final()` writes its output to `SHA256_OUT_OFFSET`. Without saving the inner hash to a separate buffer first, the outer hash setup would overwrite it. The implementation correctly uses `HMAC256_INNER_OFFSET` (a dedicated 32-byte buffer at offset 588) as temporary storage.

**No accidental truncation or extension:** The inner hash is always 32 bytes (the output of `sha256Final`), and the outer hash always processes exactly those 32 bytes. The `memory.copy` operations use explicit lengths (32 bytes) — no variable-length copies that could silently truncate or extend.

---

### 1.4 Test Vector Verification

All test vectors are sourced from RFC 4231 §4. The implementation passes all vectors including the key-longer-than-block edge case:

| Test Case | Key | Message | Expected HMAC-SHA256 | Status |
|-----------|-----|---------|---------------------|--------|
| TC1 (§4.2) — short key | `0x0b` × 20 | "Hi There" | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` | PASS |
| TC2 (§4.3) — key shorter than block | "Jefe" (4 bytes) | "what do ya want for nothing?" | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964a86910` | PASS |
| TC3 (§4.4) — data longer than block | `0xaa` × 20 | `0xdd` × 50 | `773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe` | PASS |
| TC4 (§4.5) — combined lengths | `0102030405060708090a0b0c0d0e0f10111213141516171819` (25 bytes) | `0xcd` × 50 | `82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b` | PASS |
| TC5 (§4.6) — truncation (not used) | `0x0c` × 20 | "Test With Truncation" | `a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c` | PASS |
| **TC6 (§4.7) — key longer than block** | `0xaa` × 131 | "Test Using Larger Than Block-Size Key - Hash Key First" | `60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54` | **PASS** |
| TC7 (§4.8) — key longer than block + long data | `0xaa` × 131 | "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." | `9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2` | PASS |

TC6 is the most commonly broken edge case — it requires the key to be pre-hashed with SHA-256 before the HMAC construction. TC7 exercises the same long-key path *and* a multi-block message simultaneously, making it the most comprehensive single vector. The TypeScript wrapper's `k.length > 64` guard (`index.ts:172`) correctly triggers SHA-256 pre-hashing, producing a 32-byte derived key that is then zero-padded to 64 bytes by `hmac256Init`.

The test suite (`test/unit/sha2/hmac.test.ts`) runs all seven HMAC-SHA256 vectors plus a cross-check vector generated from the leviathan TypeScript reference implementation. Gate test 5 is HMAC-SHA256 TC1 (`hmac.test.ts:45–53`).

---

### 1.5 Buffer Layout and Memory Safety

The HMAC-SHA256 buffers reside in the SHA-2 WASM module's linear memory (`src/asm/sha2/buffers.ts`):

| Offset | Size | Name | Purpose |
|--------|------|------|---------|
| 384 | 64 | `SHA256_INPUT_OFFSET` | Key staging (hmac256Init) / message staging (hmac256Update) |
| 460 | 64 | `HMAC256_IPAD_OFFSET` | `K' ^ ipad` — inner key material |
| 524 | 64 | `HMAC256_OPAD_OFFSET` | `K' ^ opad` — outer key material |
| 588 | 32 | `HMAC256_INNER_OFFSET` | Inner hash saved before outer pass |
| 352 | 32 | `SHA256_OUT_OFFSET` | Final HMAC output (shared with SHA-256 digest output) |
| 0 | 32 | `SHA256_H_OFFSET` | SHA-256 hash state H0–H7 (shared, overwritten per pass) |

**No aliasing between inner and outer hash states:** The inner hash result is saved to `HMAC256_INNER_OFFSET` (offset 588) before `sha256Init()` resets `SHA256_H_OFFSET` (offset 0) for the outer pass. These buffers are 588 bytes apart with no overlap.

**Buffer non-overlap verification:**

| Buffer | Start | End | Next buffer start |
|--------|-------|-----|-------------------|
| `SHA256_INPUT_OFFSET` | 384 | 447 | `SHA256_PARTIAL_OFFSET` = 448 |
| `HMAC256_IPAD_OFFSET` | 460 | 523 | `HMAC256_OPAD_OFFSET` = 524 |
| `HMAC256_OPAD_OFFSET` | 524 | 587 | `HMAC256_INNER_OFFSET` = 588 |
| `HMAC256_INNER_OFFSET` | 588 | 619 | `SHA512_H_OFFSET` = 620 |

All buffers are contiguous and non-overlapping.

**Key material wiping:** `wipeBuffers()` (`src/asm/sha2/index.ts:41–43`) performs `memory.fill(0, 0, 1976)`, which zeroes the entire SHA-2 module memory from offset 0 to 1975. This covers all HMAC buffers including:
- `HMAC256_IPAD_OFFSET` (K' ^ ipad — contains key-derived material)
- `HMAC256_OPAD_OFFSET` (K' ^ opad — contains key-derived material)
- `HMAC256_INNER_OFFSET` (inner hash — derived from key)
- `SHA256_INPUT_OFFSET` (may contain key bytes during `hmac256Init`)
- `SHA256_H_OFFSET` (hash state — contains key-dependent intermediate values)

> [!NOTE]
> The `wipeBuffers` implementation uses a single `memory.fill(0, 0, 1976)` call rather than individually zeroing each buffer. This is correct and sufficient — it zeroes the entire module memory, which is a superset of all sensitive buffers. There are no buffers that live outside the 0–1975 byte range.

**Stack-allocated vs heap-allocated:** All buffers are static offsets in WASM linear memory. There is no heap allocation (`memory.grow()` is not used). No intermediate values are stored in local variables that could leak to WASM shadow stack — all accumulator state lives in the fixed-offset buffers.

---

### 1.6 TypeScript Wrapper Layer

`HMAC_SHA256` (`src/ts/sha2/index.ts:163–191`):

**`init()` gate:** The constructor calls `getExports()` → `getInstance('sha2')`, which throws if `init('sha2')` has not been called. No class silently auto-initializes.

**Input validation:** The `hash(key, msg)` method accepts arbitrary-length `Uint8Array` inputs for both key and message. There is no minimum key length enforced — this is discussed in [§2.3](#23-key-size-recommendations). The long-key path (`k.length > 64`) is validated by the TypeScript guard.

**Message feeding:** The `feedHash` helper (`index.ts:86–96`) writes message data to `SHA256_INPUT_OFFSET` in 64-byte chunks, calling `hmac256Update` for each chunk. The `Math.min(msg.length - pos, 64)` bound ensures no write exceeds the 64-byte staging buffer.

**Output:** `out.slice(...)` creates a copy of the 32 bytes at `SHA256_OUT_OFFSET`. The `.slice()` call returns an independent `Uint8Array` — the caller cannot observe subsequent WASM memory writes. The output is always exactly 32 bytes (HMAC-SHA256 output length L).

**`dispose()`:** Calls `this.x.wipeBuffers()`, which zeroes all SHA-2 module memory including all HMAC key-derived material.

---

## 2. Security Analysis

### 2.1 Length Extension Immunity

SHA-256 is vulnerable to length extension attacks: given `H(m)` and `len(m)`, an attacker can compute `H(m || padding || m')` without knowing `m`. This is because SHA-256's Merkle-Damgard construction exposes the internal state in the digest output.

HMAC is specifically designed to be immune to this attack. The outer hash wraps the inner hash output:

```
HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
```

An attacker who knows `HMAC(K, m)` knows the output of the outer hash, but:
1. The outer hash input is `(K' ^ opad) || inner_hash` — the attacker does not know `K' ^ opad`.
2. Even if the attacker could extend the outer hash, they would need to produce `H((K' ^ ipad) || m || padding || m')` for the inner hash — but they don't know the inner hash's input prefix `K' ^ ipad`.
3. The two-layer structure ensures that extending either hash requires knowledge of `K'`.

**Structural verification:** In the implementation, the outer hash input is constructed as:
```
memory.copy(SHA256_INPUT_OFFSET, HMAC256_OPAD_OFFSET, 64)   // K' ^ opad
sha256Update(64)
memory.copy(SHA256_INPUT_OFFSET, HMAC256_INNER_OFFSET, 32)  // inner hash
sha256Update(32)
sha256Final()
```

The outer hash processes exactly `opad_block || inner_hash` — there is no mechanism to extend this input from outside the function. The `hmac256Final` function is not a streaming API that accepts additional data between the opad block and the inner hash. Length extension immunity holds structurally.

---

### 2.2 Security Bound

HMAC security rests on two pillars (Bellare, Canetti, Krawczyk 1996; Bellare 2006):

1. **PRF security:** HMAC-SHA256 is a secure PRF if the SHA-256 compression function is a PRF. Under this assumption, the advantage of any adversary in distinguishing HMAC-SHA256 from a random function is negligible.

2. **MAC security (forgery resistance):** An adversary making `q` queries of total length `l` blocks can forge with probability at most:

$$\epsilon_{\text{forge}} \leq \frac{q^2}{2^{256}} + \epsilon_{\text{PRF}}(q, l)$$

The `q^2 / 2^{256}` term comes from the birthday bound on the outer hash. For any practical query volume, this is negligible.

**Concrete bounds:**
- **Key recovery:** 2^256 (brute force against the 256-bit key space when `len(K) ≥ 32`)
- **Forgery:** Approximately 2^128 security (limited by SHA-256's collision resistance)
- **Distinguishing from random:** 2^256 (PRF bound, assuming SHA-256 compression function is a PRF)

These bounds assume the key is uniformly random and at least L = 32 bytes.

---

### 2.3 Key Size Recommendations

| Key length | Security implication | RFC 2104 guidance |
|-----------|---------------------|-------------------|
| `< L` (< 32 bytes) | Security degrades below 128-bit forgery resistance | "The key for HMAC can be of any length. However, less than L bytes is strongly discouraged" (§3) |
| `= L` (32 bytes) | Full 128-bit forgery resistance, 256-bit key recovery | Recommended minimum |
| `> L, ≤ B` (33–64 bytes) | No additional security (key space is 256 bits regardless) | Acceptable — zero-padded to B |
| `> B` (> 64 bytes) | Effective key reduced to `H(K)` = 32 bytes | "Keys longer than B bytes are first hashed using H" (§3) |

**API enforcement:** leviathan-crypto does **not** enforce a minimum key length at the API level. `HMAC_SHA256.hash()` accepts keys of any length including zero bytes. This is a deliberate design choice — the library is a low-level cryptographic primitive, and key length enforcement is the caller's responsibility.

> [!NOTE]
> Using a key longer than 64 bytes does not improve security — the key is pre-hashed to 32 bytes. Applications that derive HMAC keys from HKDF or similar KDFs should target 32-byte output, not longer.

---

### 2.4 Usage Context in leviathan-crypto

HMAC-SHA256 is used as a building block in three contexts within leviathan-crypto:

#### SerpentSeal (Encrypt-then-MAC)

`SerpentSeal` (`src/ts/serpent/seal.ts:25–73`) uses SerpentCBC + HMAC-SHA256 in Encrypt-then-MAC configuration:

```typescript
const encKey = key.subarray(0, 32);   // first 32 bytes — Serpent encryption key
const macKey = key.subarray(32, 64);  // last 32 bytes — HMAC-SHA256 key
```

The 64-byte caller-supplied key is split into separate encryption and MAC keys (`seal.ts:46–47`). This is correct key separation — the encryption and MAC operations use independent keys derived from disjoint portions of the input.

The MAC covers `IV || ciphertext` (`seal.ts:51`), not just ciphertext. This binds the IV to the authentication tag, preventing IV substitution attacks.

On decrypt, the tag is verified before decryption (`seal.ts:65–67`) — correct Encrypt-then-MAC order.

#### SerpentStream (CTR + HMAC + HKDF)

`SerpentStream` (`src/ts/serpent/stream.ts`) uses HKDF-SHA256 to derive per-chunk `encKey` and `macKey` from a master key:

```typescript
function deriveChunkKeys(hkdf, masterKey, streamNonce, index) {
    const derived = hkdf.deriveKey(masterKey, info, 64);
    return { encKey: derived.subarray(0, 32), macKey: derived.subarray(32, 64) };
}
```

Each chunk gets independent encryption and MAC keys derived from `(masterKey, streamNonce, chunkIndex)`. This provides:
- **Key separation:** `encKey` and `macKey` are derived from disjoint portions of the HKDF output
- **Per-chunk isolation:** Compromising one chunk's keys does not reveal other chunks' keys
- **Position binding:** The chunk index is part of the HKDF info, binding each key pair to its position

#### HKDF-SHA256

`HKDF_SHA256` uses HMAC-SHA256 as both the extract and expand PRFs (RFC 5869). The HMAC implementation's correctness is a prerequisite for HKDF's security — covered in the separate [hkdf_audit.md](./hkdf_audit.md).

**Assessment:** Key separation is correctly implemented in all usage contexts. The encryption key and MAC key are always derived from independent key material, either by splitting a longer key or by HKDF derivation with distinct info strings.

---

## Cross-References

- [README.md](../README.md)
- [architecture.md](./architecture.md)
- [sha2_audit.md](./sha2_audit.md) — SHA-256 implementation audit (HMAC builds on SHA-256)
- [hkdf_audit.md](./hkdf_audit.md) — HKDF builds on HMAC-SHA256
- [serpent_audit.md](./serpent_audit.md) — HMAC-SHA256 used in SerpentStream [§2.4](./serpent_audit.md#24-serpentstream-encrypt-then-mac-and-the-cryptographic-doom-principle)
- [chacha_audit.md](./chacha_audit.md) — XChaCha20-Poly1305 uses a different MAC (Poly1305)
- [sha3_audit.md](./sha3_audit.md) — SHA-3 companion audit
