<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### XChaCha20-Poly1305 Cryptographic Audit

Full correctness and security audit of the `leviathan-crypto` XChaCha20-Poly1305 WebAssembly implementation (AssemblyScript) against RFC 8439 and draft-irtf-cfrg-xchacha-03.

> ### Table of Contents
> - [1. Algorithm Correctness](#1-algorithm-correctness)
>   - [1.1 Quarter Round](#11-quarter-round)
>   - [1.2 Block Function](#12-block-function)
>   - [1.3 Counter and Nonce Handling](#13-counter-and-nonce-handling)
>   - [1.4 Poly1305](#14-poly1305)
>   - [1.5 Poly1305 Key Generation](#15-poly1305-key-generation)
>   - [1.6 HChaCha20 / XChaCha20 Nonce Extension](#16-hchacha20--xchacha20-nonce-extension)
>   - [1.7 AEAD Construction](#17-aead-construction)
>   - [1.8 Buffer Layout and Memory Safety](#18-buffer-layout-and-memory-safety)
>   - [1.9 TypeScript Wrapper Layer](#19-typescript-wrapper-layer)
> - [2. Security Analysis](#2-security-analysis)
>   - [2.1 Side-Channel Analysis](#21-side-channel-analysis)
>   - [2.2 Known Attacks on ChaCha20](#22-known-attacks-on-chacha20)
>   - [2.3 Stream Composition](#23-stream-composition)

| Meta | Description |
| --- | --- |
| Conducted: | Week of 2026-03-25 |
| Target: | `leviathan-crypto` WebAssembly implementation (AssemblyScript) |
| Spec: | RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols, June 2018); draft-irtf-cfrg-xchacha-03 (XChaCha20 nonce-extension construction) |
| Test vectors: | RFC 8439 §A (ChaCha20, Poly1305, ChaCha20-Poly1305); draft-irtf-cfrg-xchacha-03 §A.3 (HChaCha20, XChaCha20-Poly1305) |

---

## 1. Algorithm Correctness

### 1.1 Quarter Round

RFC 8439 §2.1 specifies the quarter round: four ARX operations (add, rotate, XOR) on four 32-bit words. Our implementation (`src/asm/chacha20/chacha20.ts:64–79`) loads those words from WASM linear memory and applies the same operations:

| Step | RFC 8439 §2.1 | leviathan-crypto (`qr`) |
|------|---------------|------------------------|
| 1 | `a += b; d ^= a; d <<<= 16` | `av += bv; dv ^= av; dv = rotl32(dv, 16)` |
| 2 | `c += d; b ^= c; b <<<= 12` | `cv += dv; bv ^= cv; bv = rotl32(bv, 12)` |
| 3 | `a += b; d ^= a; d <<<= 8`  | `av += bv; dv ^= av; dv = rotl32(dv, 8)` |
| 4 | `c += d; b ^= c; b <<<= 7`  | `cv += dv; bv ^= cv; bv = rotl32(bv, 7)` |

Rotation amounts match exactly: 16, 12, 8, 7. The `rotl32` helper (`chacha20.ts:57–59`) does `(x << n) | (x >>> (32 - n))`, a pattern AssemblyScript compiles directly to WASM's `i32.rotl`—a single fixed-latency instruction on all modern architectures. No emulation, no variable-cost sequences.

> [!NOTE]
> The `@inline` annotation ensures `qr` and `rotl32` inline, eliminating call overhead. The quarter round becomes a straight-line sequence of `i32.add`, `i32.xor`, and `i32.rotl` instructions in the emitted WASM. No branches, no function calls.

The double round function (`chacha20.ts:85–96`) applies the quarter round with the correct column and diagonal index patterns from RFC §2.2:

```
Column:   QR(0,4, 8,12)  QR(1,5, 9,13)  QR(2,6,10,14)  QR(3,7,11,15)
Diagonal: QR(0,5,10,15)  QR(1,6,11,12)  QR(2,7, 8,13)  QR(3,4, 9,14)
```

All eight index quadruples match the RFC specification.

**Test vector verification:** RFC 8439 §2.2.1 block function test vector passes (`test/unit/chacha20/chacha20.test.ts:46–59`).

---

### 1.2 Block Function

RFC 8439 §2.3 specifies the block function in three steps. Our implementation (`chacha20.ts:101–113`) follows it exactly:

1. **Copy:** `memory.copy(CHACHA_BLOCK_OFFSET, CHACHA_STATE_OFFSET, 64)`. Copy the 64-byte state to a working buffer.
2. **Rounds:** 10 iterations of `doubleRound(CHACHA_BLOCK_OFFSET)`. That's 20 rounds total.
3. **Add-back:** Add each of the 16 initial state words back into the working buffer (`chacha20.ts:108–112`).

The add-back step is mandatory. Without it, the block function loses PRF properties and ChaCha20 becomes invertible. Each of the 16 words gets added back independently.

**State initialization** happens in `chachaLoadKey` (`chacha20.ts:117–138`). RFC 8439 §2.3 specifies which words go where:

| Word | RFC 8439 §2.3 | Implementation |
|------|---------------|----------------|
| 0–3 | `0x61707865 0x3320646e 0x79622d32 0x6b206574` | `store<u32>(s+0, C0)` ... `store<u32>(s+12, C3)` |
| 4–11 | 256-bit key (8 × u32, LE) | `load<u32>(KEY_OFFSET + i*4)` loop |
| 12 | Counter (u32) | `load<u32>(CHACHA_CTR_OFFSET)` |
| 13–15 | 96-bit nonce (3 × u32, LE) | `load<u32>(CHACHA_NONCE_OFFSET + i*4)` loop |

Those four constants spell "expand 32-byte k" in ASCII. The hex values `0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574` match the RFC exactly (`chacha20.ts:49–52`).

> [!NOTE]
> WASM linear memory is little-endian by specification. AssemblyScript's `load<u32>` and `store<u32>` perform native LE access with no byte-swapping. This matches ChaCha20's LE-throughout design.

**Test vector verification:** RFC 8439 §2.2.1 keystream output at counter=1 matches (`test/vectors/chacha20.ts:30–43`). RFC 8439 §2.4.2 sunscreen encryption vector (114 bytes) passes (`test/unit/chacha20/chacha20.test.ts:62–76`).

---

### 1.3 Counter and Nonce Handling

RFC 8439 specifies how counter and nonce are laid out and managed. Here's our implementation:

| Property | RFC 8439 | Implementation |
|----------|----------|----------------|
| Counter width | 32-bit | `u32` at `CHACHA_STATE_OFFSET + 48` |
| Counter start (encryption) | 1 | `chachaResetCounter()` sets to 1 (`chacha20.ts:146–147`) |
| Counter start (Poly1305 keygen) | 0 | `chachaGenPolyKey()` writes 0 directly (`chacha20.ts:182`) |
| Nonce width (ChaCha20) | 96-bit | 12 bytes at `CHACHA_NONCE_OFFSET` |
| Nonce width (XChaCha20) | 192-bit | 24 bytes at `XCHACHA_NONCE_OFFSET` |

Counter increment happens in `chachaEncryptChunk` (`chacha20.ts:166–168`). After each 64-byte keystream block, we increment the counter by 1 and write it to both the state buffer (word 12) and the counter buffer (`CHACHA_CTR_OFFSET`). The increment is a simple `u32` addition that wraps silently at 2^32 after 256 GB of keystream per nonce. The RFC leaves overflow undefined; our u32 wrap is consistent with the 32-bit counter design.

For XChaCha20, the 24-byte nonce is split:
- Bytes 0–15 → HChaCha20 subkey derivation
- Bytes 16–23 → inner 12-byte nonce (zero-padded to `0x00000000 || nonce[16..23]`)

The inner nonce construction (`ops.ts:155–159`) correctly places the 8 bytes at offset 4 of a zeroed 12-byte array.

---

### 1.4 Poly1305

Poly1305 (`src/asm/chacha20/poly1305.ts`) uses a radix-2^26 representation with five `u64` limbs. These live in WASM linear memory at three offsets: `POLY_H_OFFSET` for the accumulator, `POLY_R_OFFSET` for the clamped key, and `POLY_RS_OFFSET` for precomputed 5×r values.

#### r Clamping (RFC 8439 §2.5)

RFC 8439 §2.5 specifies r clamping to prevent certain algebraic attacks. `polyInit` (`poly1305.ts:90–131`) applies the clamping mask `0x0ffffffc0ffffffc0ffffffc0fffffff`:

| Byte | RFC mask | Implementation (`polyInit` lines 94–100) |
|------|----------|-------------------------------------------|
| r[3] | `& 0x0f` | `store<u8>(k+3, load<u8>(k+3) & 15)` |
| r[4] | `& 0xfc` | `store<u8>(k+4, load<u8>(k+4) & 252)` |
| r[7] | `& 0x0f` | `store<u8>(k+7, load<u8>(k+7) & 15)` |
| r[8] | `& 0xfc` | `store<u8>(k+8, load<u8>(k+8) & 252)` |
| r[11] | `& 0x0f` | `store<u8>(k+11, load<u8>(k+11) & 15)` |
| r[12] | `& 0xfc` | `store<u8>(k+12, load<u8>(k+12) & 252)` |
| r[15] | `& 0x0f` | `store<u8>(k+15, load<u8>(k+15) & 15)` |

All 7 clamped bytes match the RFC specification exactly. The remaining bytes are unclamped (mask `0xff`), which is correct.

#### 130-bit Accumulation

`absorbBlock` (`poly1305.ts:43–87`) implements `h = (h + n) * r mod (2^130 − 5)`:

1. **Input splitting:** 16-byte block → 5 × 26-bit limbs via overlapping `load<u32>` reads with right-shifts (`poly1305.ts:44–48`). The `hibit` parameter sets bit 128 for full blocks (`u64(1) << 24` in limb 4) or 0 for partial blocks.

2. **Multiplication:** Schoolbook 5×5 multiply with reduction. Terms where index sums exceed 4 (contributing to bits ≥ 130) are pre-multiplied by 5 via the `POLY_RS_OFFSET` precomputed values (`s1 = 5*r1`, etc.), implementing the identity `2^130 ≡ 5 (mod 2^130 − 5)` (`poly1305.ts:68–72`).

3. **Carry propagation** (`poly1305.ts:75–81`): cascading right-shift by 26, with wrap-around `h0 += c * 5` after `d4`, followed by one final carry from `h0` to `h1`. This maintains the invariant that each limb fits in 26 bits after absorption.

#### 0x01 Padding

For partial final blocks (`polyFinal`, `poly1305.ts:170–174`):
```
memory.fill(POLY_BUF_OFFSET + bufLen, 0, 16 - bufLen)  // zero remaining bytes
store<u8>(POLY_BUF_OFFSET + bufLen, 1)                  // append 0x01 at bufLen
absorbBlock(POLY_BUF_OFFSET, 0)                         // hibit=0 for partial
```

The implementation places the 0x01 byte at byte position `bufLen` (the first byte after the last data byte), not always at byte 16. This matches the RFC requirement: "pad the one-indexed 01 byte right after the input." The `hibit=0` parameter ensures bit 128 is not set for partial blocks.

#### Final Reduction and Tag

`polyFinal` (`poly1305.ts:176–218`):

1. **Full carry propagation** (lines 183–187): ensures all limbs are in [0, 2^26).
2. **Conditional subtraction of p** (lines 189–200): computes `g = h + 5`. If `g ≥ 2^130` (i.e., `g4 >> 26 ≠ 0`), then `h ≥ p`, so the result is `g mod 2^130`. The selection is constant-time via `mask = 0 - (g4 >> 26)` and bitwise `(h & ~mask) | (g & mask)`.
3. **Reassembly** (lines 202–203): 5 limbs → two `u64` values (lo: bits 0–63, hi: bits 64–127).
4. **Add s** (lines 205–214): `s` is the second 16 bytes of the one-time key. Full 128-bit addition with carry: `rlo = lo + slo; carry = (rlo < lo); rhi = hi + shi + carry`.
5. **Tag output** (lines 216–217): stored as two `u64` LE values at `POLY_TAG_OFFSET`.

**Test vector verification:** All 7 Poly1305 test vectors pass:

| Vector | Source | Description |
|--------|--------|-------------|
| Gate | RFC §2.5.2 | "Cryptographic Forum Research Group" (34 bytes) |
| TV#1 | RFC §A.3 | All-zero key and 64-byte message → zero tag |
| TV#2 | RFC §A.3 | r=0, 375-byte message → tag equals s |
| TV#3 | RFC §A.3 | s=0, r-only key, 375-byte message |
| TV#4 | RFC §A.3 | Jabberwocky (127 bytes) |
| TV#5 | RFC §A.3 | h reaches p. Modular reduction edge case. |
| TV#6 | RFC §A.3 | h + s overflows 128-bit. Carry discarded. |

TV#5 and TV#6 specifically exercise the modular reduction and 128-bit overflow paths.

---

### 1.5 Poly1305 Key Generation

`chachaGenPolyKey` (`chacha20.ts:181–185`):

```
store<u32>(CHACHA_STATE_OFFSET + 48, 0)            // set counter to 0
block()                                              // generate keystream block
memory.copy(POLY_KEY_OFFSET, CHACHA_BLOCK_OFFSET, 32)  // first 256 bits
```

The function directly writes 0 to state word 12 (the counter), bypassing the `chachaSetCounter` helper. This is functionally correct. The counter value is set before the block function runs, and the first 32 bytes of the output are copied to the Poly1305 key buffer.

| Property | RFC 8439 §2.6 | Implementation |
|----------|---------------|----------------|
| Counter value | 0 | `store<u32>(CHACHA_STATE_OFFSET + 48, 0)` |
| Output bytes | first 256 bits (32 bytes) | `memory.copy(..., 32)` |

**Test vector verification:** RFC 8439 §2.6.2 Poly1305 key generation vector passes (`test/unit/chacha20/poly1305.test.ts:64–79`).

---

### 1.6 HChaCha20 / XChaCha20 Nonce Extension

`hchacha20` (`chacha20.ts:190–213`) implements HChaCha20 per draft-irtf-cfrg-xchacha §2.1:

**State layout:**
| Words | Content | Implementation |
|-------|---------|----------------|
| 0–3 | Constants | `store<u32>(s + {0,4,8,12}, C{0,1,2,3})` |
| 4–11 | 256-bit key | `load<u32>(KEY_OFFSET + i*4)` loop |
| 12–15 | First 16 bytes of 24-byte nonce | `load<u32>(XCHACHA_NONCE_OFFSET + i*4)` loop |

> [!NOTE]
> Unlike the standard ChaCha20 block function, words 12–15 contain the nonce prefix rather than counter + nonce.

**Critical differences from `block()`:**

| Property | `block()` | `hchacha20()` |
|----------|-----------|---------------|
| Operates on | Copy of state (`CHACHA_BLOCK_OFFSET`) | State directly (`CHACHA_STATE_OFFSET`) |
| Add-back of initial state | Yes (lines 108–112) | **No.** Rounds modify state in place. |
| Output | Full 64 bytes (serialized state) | Words [0–3] ++ [12–15] only (32 bytes) |

The implementation (`chacha20.ts:205`) runs `doubleRound(s)` directly on the state buffer, modifying the state in place. After 10 double rounds, it extracts the output from words 0–3 and 12–15 (`chacha20.ts:209–212`), yielding 32 bytes written to `XCHACHA_SUBKEY_OFFSET`.

The XChaCha20 construction in the TypeScript layer (`ops.ts:145–159`):

```typescript
// HChaCha20 subkey from key + nonce[0..15]
const subkey = deriveSubkey(x, key, nonce);

// Inner nonce: 0x00000000 || nonce[16..23]
const inner = innerNonce(nonce);
```

| Property | Spec | Implementation |
|----------|------|----------------|
| Subkey derivation input | `nonce[0..15]` (16 bytes) | `nonce.subarray(0, 16)` → `XCHACHA_NONCE_OFFSET` |
| Inner nonce bytes 0–3 | `0x00000000` | `new Uint8Array(12)`, zero-initialized |
| Inner nonce bytes 4–11 | `nonce[16..23]` | `n.set(nonce.subarray(16, 24), 4)` |

**Test vector verification:** HChaCha20 subkey derivation vector from draft §A.3.1 passes (`test/unit/chacha20/xchacha20.test.ts:55–71`). Full XChaCha20-Poly1305 AEAD vector from draft §A.3.2 passes (`test/unit/chacha20/xchacha20.test.ts:88–103`).

---

### 1.7 AEAD Construction

The AEAD construction lives in `src/ts/chacha20/ops.ts` and implements RFC 8439 §2.8 via two functions: `aeadEncrypt` (lines 41–93) and `aeadDecrypt` (lines 96–140).

**Encrypt path (`aeadEncrypt`):**

RFC 8439 §2.8 specifies the encryption sequence. Here's how we implement it:

| Step | RFC 8439 §2.8 | Implementation (ops.ts) |
|------|---------------|-------------------------|
| 1a. Load key + generate OTK | `poly1305_key_gen(key, nonce)` at counter=0 | `chachaLoadKey()` loads key and nonce; `chachaGenPolyKey()` sets counter=0 and runs the block function, copying the first 32 bytes to `POLY_KEY_OFFSET` |
| 1b. Init MAC | Initialize Poly1305 with OTK | `polyInit()` |
| 3. MAC AAD | Feed AAD and pad to 16-byte blocks | `polyFeed(x, aad)` plus zero padding |
| 4. Encrypt | ChaCha20 at counter=1 | `chachaSetCounter(1); chachaLoadKey(); chachaEncryptChunk(len)` |
| 5. MAC ciphertext | Feed ciphertext and pad | `polyFeed(x, ciphertext)` plus zero padding |
| 6. MAC lengths | Two u64le values: len(AAD) and len(CT) | `polyFeed(x, lenBlock(aad.length, plaintext.length))` |
| 7. Finalize | Produce tag | `polyFinal()` and read 16 bytes from `POLY_TAG_OFFSET` |

The `lenBlock` helper (`ops.ts:25–36`) encodes lengths as u64le. It writes the low 32 bits explicitly (4 bytes per length) and relies on `new Uint8Array(16)` zero-initialization for the high 32 bits. This is correct for all inputs within the 65,536-byte chunk limit. The high 4 bytes would be zero regardless.

**pad16 computation** (`ops.ts:66–67`):
```typescript
const aadPad = (16 - aad.length % 16) % 16;
```
The double-modulo pattern produces 0 when the length is already a multiple of 16, matching the RFC's pad16 definition.

**Decrypt path (`aeadDecrypt`):**

The decrypt path enforces verify-then-decrypt order. No plaintext leaves this function until authentication succeeds.

1. Compute the expected tag over (AAD + padding + ciphertext + padding + lengths)
2. Compare the received tag against the expected tag using `constantTimeEqual` (`utils.ts:135–140`)
3. Only if the tags match, decrypt the ciphertext

```typescript
if (!constantTimeEqual(expectedTag, tag))
    throw new Error('ChaCha20Poly1305: authentication failed');
```

On tag mismatch, we throw immediately without producing or returning any plaintext. This prevents the cryptographic doom principle—the AEAD never processes unauthenticated ciphertext.

**Tag comparison** (`constantTimeEqual`, `utils.ts`). At audit time the function shipped as a JS implementation:
```typescript
let diff = 0;
for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
return diff === 0;
```
XOR-accumulate pattern with no early return. The loop always executes all 16 iterations.

> [!NOTE]
> Post-audit, this comparison was moved into a dedicated WASM SIMD
> module (v128 XOR-accumulate with branch-free reduction). The JS path
> was removed; the function now throws a branded error on runtimes
> without WebAssembly SIMD. The constant-time property of the audited
> verification is preserved and strengthened. See
> [asm_ct.md](./asm_ct.md).

**XChaCha20-Poly1305 layer** (`ops.ts:164–194`):

`xcEncrypt` and `xcDecrypt` wrap the inner AEAD:
1. Derive subkey via HChaCha20 (`deriveSubkey`)
2. Construct inner 12-byte nonce (`innerNonce`)
3. Delegate to `aeadEncrypt`/`aeadDecrypt` with the subkey and inner nonce

`xcEncrypt` returns `ciphertext || tag` as a single `Uint8Array`. `xcDecrypt` splits the input at `length - 16` to extract the ciphertext and tag, then passes both to `aeadDecrypt`.

**Test vector verification:** RFC 8439 §2.8.2 "sunscreen" AEAD vector passes for both encrypt and decrypt (`test/unit/chacha20/chacha20poly1305.test.ts:55–68`). XChaCha20-Poly1305 draft §A.3.2 vector passes (`test/unit/chacha20/xchacha20.test.ts:88–103`).

---

### 1.8 Buffer Layout and Memory Safety

The ChaCha20 WASM module uses static buffer allocation in linear memory (`src/asm/chacha20/buffers.ts`):

| Offset | Size | Name | Purpose |
|--------|------|------|---------|
| 0 | 32 | KEY_BUFFER | 256-bit ChaCha20 key |
| 32 | 12 | CHACHA_NONCE_BUFFER | 96-bit nonce (3 × u32, LE) |
| 44 | 4 | CHACHA_CTR_BUFFER | u32 block counter |
| 48 | 64 | CHACHA_BLOCK_BUFFER | Keystream block output |
| 112 | 64 | CHACHA_STATE_BUFFER | 16 × u32 working state |
| 176 | 65,536 | CHUNK_PT_BUFFER | Streaming plaintext |
| 65,712 | 65,536 | CHUNK_CT_BUFFER | Streaming ciphertext |
| 131,248 | 32 | POLY_KEY_BUFFER | One-time key r\|\|s |
| 131,280 | 64 | POLY_MSG_BUFFER | Message staging (≤64 bytes per polyUpdate) |
| 131,344 | 16 | POLY_BUF_BUFFER | Partial block accumulator |
| 131,360 | 4 | POLY_BUF_LEN_BUFFER | Bytes in partial block |
| 131,364 | 16 | POLY_TAG_BUFFER | 16-byte output MAC tag |
| 131,380 | 40 | POLY_H_BUFFER | Accumulator h (5 × u64) |
| 131,420 | 40 | POLY_R_BUFFER | Clamped r (5 × u64) |
| 131,460 | 32 | POLY_RS_BUFFER | Precomputed 5×r[1..4] (4 × u64) |
| 131,492 | 16 | POLY_S_BUFFER | s pad (4 × u32) |
| 131,508 | 24 | XCHACHA_NONCE_BUFFER | Full 24-byte XChaCha20 nonce |
| 131,532 | 32 | XCHACHA_SUBKEY_BUFFER | HChaCha20 subkey output |

Total: 131,564 bytes < 196,608 (3 × 64KB pages). No dynamic allocation (`memory.grow()` is not used). All offsets are compile-time constants. Buffer regions are contiguous and non-overlapping, verified by monotonically increasing offsets with no gaps or overlaps.

**`wipeBuffers()`** (`wipe.ts:39–65`) zeroes all 18 buffer regions. Every buffer containing key material (KEY, CHACHA_STATE words 4–11, POLY_KEY, POLY_R, POLY_RS, POLY_S, XCHACHA_SUBKEY), intermediate state (CHACHA_BLOCK, POLY_H, POLY_BUF), and data buffers (CHUNK_PT, CHUNK_CT) is explicitly wiped. No sensitive material persists after `dispose()`.

**Post-auth-fail hygiene.** `aeadDecrypt` (`src/ts/chacha20/ops.ts`) verifies the tag before producing any plaintext. On `constantTimeEqual` mismatch, the TypeScript layer explicitly zeroes three regions in WASM linear memory before throwing `AuthenticationError`, without waiting for `wipeBuffers()` at `dispose()`:

| Region | Offset | Size | Why |
|--------|--------|------|-----|
| `CHUNK_CT_BUFFER` | 65,712 | 65,536 | Defense-in-depth — decrypt runs only on tag match, so no plaintext lands here on failure, but the buffer is still wiped to cover any residual content from a prior op on the same instance |
| `CHACHA_BLOCK_BUFFER` | 48 | 64 | Holds the keystream block generated by `chachaGenPolyKey` for this (key, nonce) pair |
| `POLY_KEY_BUFFER` | 131,248 | 32 | `chachaGenPolyKey` copies `CHACHA_BLOCK[0..32]` here as the Poly1305 one-time subkey — outside the `CHACHA_BLOCK` range, so wiping the block source does not cover this copy |

Under strict single-use, the instance is locked after the throw (`ChaCha20Poly1305` / `XChaCha20Poly1305` flip to the single-use terminal state), so the next chacha op on this instance is not possible. The explicit wipes close the window between the throw and `dispose()` (or the next op on a different instance that would overwrite these regions organically). `POLY_TAG_BUFFER` is intentionally left alone — the tag is a public MAC output, not key material.

**`.subarray()` vs `.slice()` usage:**
- **Output from WASM:** The code uses `.slice()` consistently to copy data out of WASM memory (`ops.ts:77`, `ops.ts:90`, `ops.ts:139`, `ops.ts:151`). This creates an independent copy, safe against the WASM memory buffer being detached or reused.
- **Input views:** Input data views use `.subarray()` (`ops.ts:19`, `ops.ts:148`, `ops.ts:157`, `ops.ts:189–190`). The code immediately copies these views into WASM memory via `mem.set()`, so the view lifetime is bounded. No view crosses a `postMessage` boundary within the core library.

> [!NOTE]
> This note references the v1 `XChaCha20Poly1305Pool` (`chacha20/pool.ts`).
> The v2 equivalent is `SealStreamPool` (`stream/seal-stream-pool.ts`) with
> cipher-specific workers (`chacha20/pool-worker.ts`, `serpent/pool-worker.ts`),
> spawned from blob URLs over IIFE source bundled at lib build time.
>
> The `XChaCha20Poly1305Pool` worker pool (`pool.ts`) uses `Transferable` buffer transfer when dispatching to workers. Input buffers are neutered after dispatch. The worker receives ownership of the `ArrayBuffer`, deserializes its own copy into WASM memory, and returns a new `ArrayBuffer` with the result. This avoids the [`.subarray()` + `postMessage` hazard that caused the 2.8TB memcpy](./serpent_audit.md#18-buffer-layout-and-memory-safety) in the Serpent worker pool.

---

### 1.9 TypeScript Wrapper Layer

TypeScript classes in `src/ts/chacha20/index.ts` form the public API. They never perform cryptographic computation; they orchestrate the WASM layer.

**`init()` gate:** All classes call `getExports()` (lines 41–43), which calls `getInstance('chacha20')`. If the module hasn't been loaded via `init('chacha20')` or `chacha20Init()`, the call throws immediately. No class auto-initializes on first use.

**Input validation:** Each class validates parameters before calling WASM:

| Class | Parameter | Validation |
|-------|-----------|------------|
| `ChaCha20` | key | `key.length !== 32` → `RangeError` |
| `ChaCha20` | nonce | `nonce.length !== 12` → `RangeError` |
| `ChaCha20Poly1305` | key | `key.length !== 32` → `RangeError` |
| `ChaCha20Poly1305` | nonce | `nonce.length !== 12` → `RangeError` |
| `ChaCha20Poly1305` | tag (decrypt) | `tag.length !== 16` → `RangeError` |
| `XChaCha20Poly1305` | key | `key.length !== 32` → `RangeError` |
| `XChaCha20Poly1305` | nonce | `nonce.length !== 24` → `RangeError` |
| `XChaCha20Poly1305` | ciphertext (decrypt) | `ciphertext.length < 16` → `RangeError` |
| `Poly1305` | key | `key.length !== 32` → `RangeError` |

**Error handling:** On authentication failure, both `ChaCha20Poly1305.decrypt()` and `XChaCha20Poly1305.decrypt()` throw `Error('ChaCha20Poly1305: authentication failed')`. They never return null or produce partial plaintext. This enforces verify-then-decrypt order.

**`dispose()`:** All classes call `this.x.wipeBuffers()` in `dispose()`, which zeros all WASM memory. Key material and intermediate state don't persist after the instance is disposed.

The TypeScript layer writes inputs to WASM memory, calls WASM exports, and reads outputs, never implementing algorithm logic.

---

## 2. Security Analysis

### 2.1 Side-Channel Analysis

We designed every component for constant-time operation:

| Component | Implementation | Constant-Time? |
|-----------|---------------|----------------|
| ChaCha20 quarter round | `i32.add`, `i32.xor`, `i32.rotl` | Yes |
| Block function (10 double-rounds) | Fixed 20 iterations, no conditional branches on state | Yes |
| Counter increment | `u32` addition, no early exit | Yes |
| Poly1305 absorbBlock | Schoolbook multiply with fixed carry chain | Yes |
| Poly1305 final reduction | Mask-select (no branch) for conditional subtraction | Yes |
| Poly1305 tag comparison | XOR-accumulate loop with no early return | Yes |
| HChaCha20 | 20 fixed rounds, no add-back step | Yes |

**ChaCha20's ARX design.** It uses only add, rotate, and XOR on 32-bit words. No lookups, no data-dependent memory access, no conditionals. This architecture is inherently immune to cache-timing side channels.

**WASM timing guarantees.** The WASM `i32.rotl` instruction runs in fixed time on all modern architectures. Unlike JavaScript bitwise operators (which go through the JIT's polymorphic type system), WASM `i32` is always a 32-bit integer. No type specialization, no timing variation. The WASM module compiles ahead-of-time via the engine's optimizing compiler (V8's Liftoff → TurboFan, SpiderMonkey's Cranelift), so JIT speculations don't apply.

**Poly1305 arithmetic.** The radix-2^26 multiplication in `absorbBlock` (`poly1305.ts:68–72`) and carry propagation (lines 75–81) are straight-line code with no data-dependent branches. Modular reduction multiplies carries by 5, a fixed-cost operation regardless of the accumulator value. The final conditional subtraction in `polyFinal` (lines 189–200) uses bitwise mask selection instead of a branch, avoiding any timing dependence on whether h >= p.

**Counter increment:** Unlike the Serpent CTR mode counter (which has an early-exit carry propagation), the ChaCha20 counter is a simple `u32` addition (`chacha20.ts:166`). A single 32-bit add has no timing variation. This is a side-channel advantage over the Serpent implementation.

---

### 2.2 Known Attacks on ChaCha20

#### Differential Cryptanalysis on Reduced Rounds

**Best result:** 7-round distinguisher by Shi et al. (2012), requiring 2^23 chosen plaintexts. Choudhuri and Maitra (2016) achieved marginal improvements on 7-round differential-linear attacks. No distinguisher beyond 7 rounds of ChaCha20 is known.

Full 20-round ChaCha20 has a **13-round security margin** against the best known distinguisher. The round count is hardcoded in `chacha20.ts:104` (`for (let i = 0; i < 10; i++)`. That is 10 double rounds = 20 rounds). There is no parameter, configuration, or conditional logic to reduce the round count.

**Verdict: NOT APPLICABLE. 13-round security margin.**

#### Related-Key Attacks

ChaCha20 provides no related-key security guarantees by design. The construction relies on the key being uniformly random and independent across sessions.

In leviathan-crypto, the AEAD API accepts an externally-supplied key. The `XChaCha20Poly1305` class does not derive subkeys from a master key (that responsibility falls to the application layer, e.g., scrypt or HKDF in the [cli demo](https://github.com/xero/leviathan-demos/cli)). The HChaCha20 subkey derivation uses a different nonce for each message, so even with a fixed master key, the per-message subkeys are independent.

**Assessment:** The API does not create related-key exposure. Key management is the caller's responsibility, and the library's documentation (`CLAUDE.md`, `docs/chacha20.md`) correctly specifies 32-byte random keys.

#### Nonce Reuse

Nonce reuse under the same key is catastrophic for ChaCha20-Poly1305:

1. **Keystream reuse:** Two messages encrypted with the same (key, nonce) pair produce the same keystream. XORing the two ciphertexts yields the XOR of the two plaintexts. This is a classic two-time-pad attack.
2. **Poly1305 key reuse:** Counter=0 produces the same one-time key for both messages. With two (message, tag) pairs under the same Poly1305 key, the attacker can recover `r` via algebraic methods, enabling forgery of arbitrary messages.

**XChaCha20 mitigates nonce collision via 192-bit nonces.** Birthday bound analysis:
- With 192-bit random nonces, collision probability reaches 50% after 2^96 messages.
- At 1 billion messages per second, reaching 2^96 messages takes approximately 2.5 × 10^18 years.
- This is approximately 180 million times the age of the universe.

For comparison, ChaCha20's 96-bit nonce has a birthday bound of 2^48, about 2.8 × 10^14 messages. With random nonces, this can be reached in practical scenarios, which is why XChaCha20 is the recommended variant.

**Assessment:** XChaCha20's 192-bit nonce makes random nonce collision negligibly improbable. The library correctly defaults to `XChaCha20Poly1305` as the recommended AEAD.

#### Multi-Key Attacks

No known practical multi-key attack exists for 20-round ChaCha20. The best known generic multi-key attack has complexity 2^256 / K where K is the number of keys. This is the trivial bound that applies to any cipher.

**Verdict: NOT APPLICABLE.**

#### Poly1305 Forgery Bound

The forgery probability for Poly1305 is bounded by:

$$P_{\text{forgery}} \leq \frac{\lceil l/16 \rceil}{2^{106}}$$

where l is the message length in bytes (the bound uses the number of 16-byte blocks).

| Message size | Blocks (l/16) | Forgery probability |
|-------------|---------------|---------------------|
| 64 bytes | 4 | 4 / 2^106 ≈ 2^{-104} |
| 1 KB | 64 | 2^6 / 2^106 = 2^{-100} |
| 64 KB (max chunk) | 4,096 | 2^12 / 2^106 = 2^{-94} |
| 1 MB | 65,536 | 2^16 / 2^106 = 2^{-90} |

Even for the maximum single-chunk size of 65,536 bytes, the forgery probability is 2^{-94}, well below any practical attack threshold. For comparison, the NIST-recommended minimum security level is 2^{-32} for collision resistance; Poly1305 exceeds this by 62 bits even at maximum chunk size.

---

### 2.3 Stream Composition

The `SealStream` / `OpenStream` streaming layer uses ChaCha20-Poly1305 AEAD as a per-chunk cipher via `XChaCha20Cipher`
(`src/ts/chacha20/cipher-suite.ts`). The streaming composition (key derivation, nonce construction, wire format, pool workers, and the relationship to the Rogaway STREAM construction) has been audited separately in [stream_audit.md](./stream_audit.md).

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [serpent_audit](./serpent_audit.md) | Serpent-256 companion audit; comparison in [§2.3](./chacha_audit.md#23-aead-security-properties) |
| [sha2_audit](./sha2_audit.md) | SHA-256 / HMAC-SHA256 audit |
| [sha3_audit](./sha3_audit.md) | SHA-3 companion audit |
| [hmac_audit](./hmac_audit.md) | HMAC-SHA256 audit (used in SerpentCipher, not ChaCha) |
| [hkdf_audit](./hkdf_audit.md) | HKDF audit (used in stream layer key derivation) |
| [chacha20](./chacha20.md) | TypeScript API documentation |
| [asm_chacha](./asm_chacha.md) | WASM implementation details |

