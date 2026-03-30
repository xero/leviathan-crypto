# XChaCha20-Poly1305 Cryptographic Audit

> [!NOTE]
> **Conducted:** Week of 2026-03-25
> **Target:** `leviathan-crypto` WebAssembly implementation (AssemblyScript)
> **Spec:** RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols, June 2018)
>           XChaCha20 extension (draft-irtf-cfrg-xchacha-03)

## Table of Contents

- [1. Algorithm Correctness](#1-algorithm-correctness)
  - [1.1 Quarter Round](#11-quarter-round)
  - [1.2 Block Function](#12-block-function)
  - [1.3 Counter and Nonce Handling](#13-counter-and-nonce-handling)
  - [1.4 Poly1305](#14-poly1305)
  - [1.5 Poly1305 Key Generation](#15-poly1305-key-generation)
  - [1.6 HChaCha20 / XChaCha20 Nonce Extension](#16-hchacha20--xchacha20-nonce-extension)
  - [1.7 AEAD Construction](#17-aead-construction)
  - [1.8 Buffer Layout and Memory Safety](#18-buffer-layout-and-memory-safety)
  - [1.9 TypeScript Wrapper Layer](#19-typescript-wrapper-layer)
- [2. Security Analysis](#2-security-analysis)
  - [2.1 Side-Channel Analysis](#21-side-channel-analysis)
  - [2.2 Known Attacks on ChaCha20](#22-known-attacks-on-chacha20)
  - [2.3 AEAD Security Properties](#23-aead-security-properties)
  - [2.4 ChaChaStream: Nonce Construction and Chunk Binding](#24-chachastream-nonce-construction-and-chunk-binding)

---

## 1. Algorithm Correctness

### 1.1 Quarter Round

The quarter round (`src/asm/chacha20/chacha20.ts:64–79`) implements four ARX operations on four 32-bit words loaded from WASM linear memory at computed offsets:

| Step | RFC 8439 §2.1 | leviathan-crypto (`qr`) |
|------|---------------|------------------------|
| 1 | `a += b; d ^= a; d <<<= 16` | `av += bv; dv ^= av; dv = rotl32(dv, 16)` |
| 2 | `c += d; b ^= c; b <<<= 12` | `cv += dv; bv ^= cv; bv = rotl32(bv, 12)` |
| 3 | `a += b; d ^= a; d <<<= 8`  | `av += bv; dv ^= av; dv = rotl32(dv, 8)` |
| 4 | `c += d; b ^= c; b <<<= 7`  | `cv += dv; bv ^= cv; bv = rotl32(bv, 7)` |

Rotation amounts match the RFC exactly: **16, 12, 8, 7**, in that order.

The `rotl32` helper (`chacha20.ts:57–59`) is `(x << n) | (x >>> (32 - n))`. AssemblyScript compiles this pattern to the WASM `i32.rotl` instruction — a single fixed-latency CPU instruction on all modern architectures.

> [!NOTE]
> The `@inline` annotation on `qr` and `rotl32` ensures the compiler inlines these functions, eliminating call overhead. The entire quarter round becomes a straight-line sequence of `i32.add`, `i32.xor`, and `i32.rotl` instructions in the emitted WASM — no function calls, no branches.

The double round function (`chacha20.ts:85–96`) applies the quarter round with the correct column and diagonal index patterns from RFC §2.2:

```
Column:   QR(0,4, 8,12)  QR(1,5, 9,13)  QR(2,6,10,14)  QR(3,7,11,15)
Diagonal: QR(0,5,10,15)  QR(1,6,11,12)  QR(2,7, 8,13)  QR(3,4, 9,14)
```

All eight index quadruples match the RFC specification.

**Test vector verification:** RFC 8439 §2.2.1 block function test vector passes (`test/unit/chacha20/chacha20.test.ts:46–59`).

---

### 1.2 Block Function

The block function (`chacha20.ts:101–113`) implements RFC 8439 §2.3:

1. **Copy:** `memory.copy(CHACHA_BLOCK_OFFSET, CHACHA_STATE_OFFSET, 64)` — copies the 64-byte state to a working buffer.
2. **Rounds:** 10 iterations of `doubleRound(CHACHA_BLOCK_OFFSET)` — 20 rounds total.
3. **Add-back:** Word-by-word `u32` addition of the initial state back into the working buffer (`chacha20.ts:108–112`).

The add-back step is critical — without it, the block function would not be invertible, and ChaCha20 would not be a PRF. The implementation correctly adds each of the 16 words independently.

**State initialization** (`chachaLoadKey`, `chacha20.ts:117–138`):

| Word | RFC 8439 §2.3 | Implementation |
|------|---------------|----------------|
| 0–3 | `0x61707865 0x3320646e 0x79622d32 0x6b206574` | `store<u32>(s+0, C0)` ... `store<u32>(s+12, C3)` |
| 4–11 | 256-bit key (8 × u32, LE) | `load<u32>(KEY_OFFSET + i*4)` loop |
| 12 | Counter (u32) | `load<u32>(CHACHA_CTR_OFFSET)` |
| 13–15 | 96-bit nonce (3 × u32, LE) | `load<u32>(CHACHA_NONCE_OFFSET + i*4)` loop |

The four constants spell "expand 32-byte k" in ASCII. The hex values `0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574` match the RFC exactly (`chacha20.ts:49–52`).

> [!NOTE]
> WASM linear memory is little-endian by specification. `load<u32>` and `store<u32>` in AssemblyScript perform native LE access — no byte-swapping is needed. This matches ChaCha20's LE-throughout convention.

**Test vector verification:** RFC 8439 §2.2.1 keystream output at counter=1 matches (`test/vectors/chacha20.ts:30–43`). RFC 8439 §2.4.2 sunscreen encryption vector (114 bytes) passes (`test/unit/chacha20/chacha20.test.ts:62–76`).

---

### 1.3 Counter and Nonce Handling

| Property | RFC 8439 | Implementation |
|----------|----------|----------------|
| Counter width | 32-bit | `u32` — `store<u32>(CHACHA_STATE_OFFSET + 48, ...)` |
| Counter start (encryption) | 1 | `chachaResetCounter()` sets 1 (`chacha20.ts:146–147`) |
| Counter start (Poly1305 keygen) | 0 | `chachaGenPolyKey()` writes 0 directly (`chacha20.ts:182`) |
| Nonce width (ChaCha20) | 96-bit | 12-byte buffer at `CHACHA_NONCE_OFFSET` |
| Nonce width (XChaCha20) | 192-bit | 24-byte buffer at `XCHACHA_NONCE_OFFSET` |

Counter increment occurs in `chachaEncryptChunk` (`chacha20.ts:166–168`): after each 64-byte keystream block, the counter is incremented by 1 and written to both the state buffer (word 12) and the counter buffer (`CHACHA_CTR_OFFSET`). The increment is a simple `u32` addition, which will silently wrap at 2^32 (after 256 GB of keystream per nonce). The RFC defines this overflow as undefined behavior; the implementation's u32 wrap is consistent with the 32-bit counter specification.

For XChaCha20, the 24-byte nonce is split:
- Bytes 0–15 → HChaCha20 subkey derivation
- Bytes 16–23 → inner 12-byte nonce (zero-padded to `0x00000000 || nonce[16..23]`)

The inner nonce construction (`ops.ts:155–159`) correctly places the 8 bytes at offset 4 of a zeroed 12-byte array.

---

### 1.4 Poly1305

The Poly1305 implementation (`src/asm/chacha20/poly1305.ts`) uses a radix-2^26 representation with 5 × `u64` limbs, stored in WASM linear memory at `POLY_H_OFFSET` (accumulator), `POLY_R_OFFSET` (clamped key), and `POLY_RS_OFFSET` (precomputed 5×r values).

#### r Clamping (RFC 8439 §2.5)

`polyInit` (`poly1305.ts:90–131`) applies the clamping mask `0x0ffffffc0ffffffc0ffffffc0fffffff`:

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

The 0x01 byte is placed at byte position `bufLen` (the first byte after the last data byte), not always at byte 16. This matches the RFC requirement: "pad the one-indexed 01 byte right after the input." The `hibit=0` parameter ensures bit 128 is not set for partial blocks.

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
| TV#5 | RFC §A.3 | h reaches p — modular reduction edge case |
| TV#6 | RFC §A.3 | h + s overflows 128-bit — carry discarded |

TV#5 and TV#6 specifically exercise the modular reduction and 128-bit overflow paths.

---

### 1.5 Poly1305 Key Generation

`chachaGenPolyKey` (`chacha20.ts:181–185`):

```
store<u32>(CHACHA_STATE_OFFSET + 48, 0)            // set counter to 0
block()                                              // generate keystream block
memory.copy(POLY_KEY_OFFSET, CHACHA_BLOCK_OFFSET, 32)  // first 256 bits
```

The function directly writes 0 to state word 12 (the counter), bypassing the `chachaSetCounter` helper. This is functionally correct — the counter value is set before the block function runs, and the first 32 bytes of the output are copied to the Poly1305 key buffer.

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

Note: unlike the standard ChaCha20 block function, words 12–15 contain the nonce prefix rather than counter + nonce.

**Critical differences from `block()`:**

| Property | `block()` | `hchacha20()` |
|----------|-----------|---------------|
| Operates on | Copy of state (`CHACHA_BLOCK_OFFSET`) | State directly (`CHACHA_STATE_OFFSET`) |
| Add-back of initial state | Yes (lines 108–112) | **No** — rounds modify state in place |
| Output | Full 64 bytes (serialized state) | Words [0–3] ++ [12–15] only (32 bytes) |

The implementation (`chacha20.ts:205`) runs `doubleRound(s)` directly on the state buffer — the state is modified in place. After 10 double rounds, the output is extracted from words 0–3 and 12–15 (`chacha20.ts:209–212`), yielding 32 bytes written to `XCHACHA_SUBKEY_OFFSET`.

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
| Inner nonce bytes 0–3 | `0x00000000` | `new Uint8Array(12)` — zero-initialized |
| Inner nonce bytes 4–11 | `nonce[16..23]` | `n.set(nonce.subarray(16, 24), 4)` |

**Test vector verification:** HChaCha20 subkey derivation vector from draft §A.3.1 passes (`test/unit/chacha20/xchacha20.test.ts:55–71`). Full XChaCha20-Poly1305 AEAD vector from draft §A.3.2 passes (`test/unit/chacha20/xchacha20.test.ts:88–103`).

---

### 1.7 AEAD Construction

The AEAD construction (`src/ts/chacha20/ops.ts`) implements RFC 8439 §2.8 in two functions: `aeadEncrypt` (lines 41–93) and `aeadDecrypt` (lines 96–140).

**Encrypt path (`aeadEncrypt`):**

| Step | RFC 8439 §2.8 | Implementation (ops.ts) |
|------|---------------|-------------------------|
| 1a. Load key + generate OTK | `poly1305_key_gen(key, nonce)` counter=0 | `chachaLoadKey()` loads key and nonce into state. `chachaGenPolyKey()` sets counter=0 internally and runs the block function, copying the first 32 bytes to `POLY_KEY_OFFSET`. |
| 1b. Init MAC | Initialize Poly1305 with otk | `polyInit()` |
| 3. MAC AAD | Feed AAD + pad16(AAD) | `polyFeed(x, aad)` + zero padding |
| 4. Encrypt | `chacha20_encrypt(key, 1, nonce, pt)` | `chachaSetCounter(1); chachaLoadKey(); chachaEncryptChunk(len)` |
| 5. MAC ciphertext | Feed CT + pad16(CT) | `polyFeed(x, ciphertext)` + zero padding |
| 6. MAC lengths | `len(AAD)_u64le \|\| len(CT)_u64le` | `polyFeed(x, lenBlock(aad.length, plaintext.length))` |
| 7. Finalize | `tag = polyFinal()` | `polyFinal()` → read 16 bytes from `POLY_TAG_OFFSET` |

The `lenBlock` helper (`ops.ts:25–36`) encodes lengths as u64le. It writes the low 32 bits explicitly (4 bytes per length) and relies on `new Uint8Array(16)` zero-initialization for the high 32 bits. This is correct for all inputs within the 65,536-byte chunk limit — the high 4 bytes would be zero regardless.

**pad16 computation** (`ops.ts:66–67`):
```typescript
const aadPad = (16 - aad.length % 16) % 16;
```
The double-modulo pattern produces 0 when the length is already a multiple of 16, matching the RFC's pad16 definition.

**Decrypt path (`aeadDecrypt`):**

The decrypt path follows verify-then-decrypt order:
1. Compute expected tag over (AAD + padding + ciphertext + padding + lengths)
2. Constant-time tag comparison via `constantTimeEqual` (`utils.ts:135–140`)
3. **Only after authentication succeeds**: decrypt the ciphertext

```typescript
if (!constantTimeEqual(expectedTag, tag))
    throw new Error('ChaCha20Poly1305: authentication failed');
```

Plaintext is never produced or returned on authentication failure. This prevents the cryptographic doom principle — the AEAD never processes unauthenticated ciphertext.

**Tag comparison** (`constantTimeEqual`, `utils.ts:135–140`):
```typescript
let diff = 0;
for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
return diff === 0;
```
XOR-accumulate pattern with no early return. The loop always executes all 16 iterations.

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

Total: 131,564 bytes < 196,608 (3 × 64KB pages). No dynamic allocation (`memory.grow()` is not used). All offsets are compile-time constants. Buffer regions are contiguous and non-overlapping — verified by monotonically increasing offsets with no gaps or overlaps.

**`wipeBuffers()`** (`wipe.ts:39–65`) zeroes all 18 buffer regions. Every buffer containing key material (KEY, CHACHA_STATE words 4–11, POLY_KEY, POLY_R, POLY_RS, POLY_S, XCHACHA_SUBKEY), intermediate state (CHACHA_BLOCK, POLY_H, POLY_BUF), and data buffers (CHUNK_PT, CHUNK_CT) is explicitly wiped. No sensitive material persists after `dispose()`.

**`.subarray()` vs `.slice()` usage:**
- **Output from WASM:** `.slice()` is used consistently to copy data out of WASM memory (`ops.ts:77`, `ops.ts:90`, `ops.ts:139`, `ops.ts:151`). This creates an independent copy — safe against the WASM memory buffer being detached or reused.
- **Input views:** `.subarray()` is used for input data views (`ops.ts:19`, `ops.ts:148`, `ops.ts:157`, `ops.ts:189–190`). These views are immediately copied into WASM memory via `mem.set()`, so the view lifetime is bounded. No view crosses a `postMessage` boundary within the core library.

> [!NOTE]
> The `XChaCha20Poly1305Pool` worker pool (`pool.ts`) uses `Transferable` buffer transfer when dispatching to workers — input buffers are neutered after dispatch. The worker receives ownership of the `ArrayBuffer`, deserializes its own copy into WASM memory, and returns a new `ArrayBuffer` with the result. This avoids the [`.subarray()` + `postMessage` hazard that caused the 2.8TB memcpy](./serpent_audit.md#18-buffer-layout-and-memory-safety) in the Serpent worker pool.

---

### 1.9 TypeScript Wrapper Layer

The TypeScript classes (`src/ts/chacha20/index.ts`) provide the public API.

**`init()` gate:** All classes call `getExports()` (line 41–43) which calls `getInstance('chacha20')`. If the module has not been loaded via `init('chacha20')` or `chacha20Init()`, this throws immediately. No class silently auto-initializes.

**Input validation:**

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

**Error handling on authentication failure:**
- `ChaCha20Poly1305.decrypt()` and `XChaCha20Poly1305.decrypt()` throw `Error('ChaCha20Poly1305: authentication failed')` — never return null.
- Plaintext is never produced on failure (verify-then-decrypt order in `aeadDecrypt`).

**`dispose()`:** All classes call `this.x.wipeBuffers()` in `dispose()`, zeroing all WASM memory.

The TypeScript layer performs no cryptographic computation. It writes inputs to WASM memory, calls WASM exports, and reads outputs. This matches the architecture contract in `AGENTS.md`.

---

## 2. Security Analysis

### 2.1 Side-Channel Analysis

| Component | Implementation | Constant-Time? |
|-----------|---------------|----------------|
| ChaCha20 quarter round | `i32.add`, `i32.xor`, `i32.rotl` | Yes |
| Block function (10 double-rounds) | Fixed iteration count, no branches on state | Yes |
| Counter increment | `u32` addition, no early exit | Yes |
| Poly1305 absorbBlock | Schoolbook multiply + carry chain | Yes |
| Poly1305 final reduction | Mask-select conditional subtraction | Yes |
| Poly1305 tag comparison | XOR-accumulate (`constantTimeEqual`) | Yes |
| HChaCha20 | Same round structure as block(), no add-back | Yes |

**ChaCha20 is an ARX cipher** — all operations are add, rotate, and XOR on 32-bit words. There are no lookup tables, no data-dependent memory accesses, and no data-dependent branches anywhere in the implementation. This is architecturally immune to cache-timing side channels.

**WASM timing guarantees:** The WASM `i32.rotl` instruction is a fixed-latency operation on all modern CPU architectures. Unlike JavaScript where bitwise operators operate through the JIT's polymorphic integer representation, WASM `i32` is always a 32-bit integer — there is no speculative type specialization that could create timing variation. The WASM module is compiled ahead-of-time by the engine's optimizing compiler (V8 Liftoff → TurboFan, SpiderMonkey Cranelift), and the JIT's speculative optimizations do not apply.

**Poly1305 field arithmetic:** The radix-2^26 multiplication in `absorbBlock` (`poly1305.ts:68–72`) and carry propagation (lines 75–81) are straight-line code with no data-dependent branches. The modular reduction wraps carries via multiplication by 5, which is a fixed-cost operation regardless of the accumulator value. The final conditional subtraction in `polyFinal` (lines 189–200) uses bitwise mask selection rather than a branch.

**Counter increment:** Unlike the Serpent CTR mode counter (which has an early-exit carry propagation), the ChaCha20 counter is a simple `u32` addition (`chacha20.ts:166`). A single 32-bit add has no timing variation. This is a side-channel advantage over the Serpent implementation.

---

### 2.2 Known Attacks on ChaCha20

#### Differential Cryptanalysis on Reduced Rounds

**Best result:** 7-round distinguisher by Shi et al. (2012), requiring 2^23 chosen plaintexts. Choudhuri and Maitra (2016) achieved marginal improvements on 7-round differential-linear attacks. No distinguisher beyond 7 rounds of ChaCha20 is known.

Full 20-round ChaCha20 has a **13-round security margin** against the best known distinguisher. The round count is hardcoded in `chacha20.ts:104` (`for (let i = 0; i < 10; i++)` — 10 double rounds = 20 rounds). There is no parameter, configuration, or conditional logic to reduce the round count.

**Verdict: NOT APPLICABLE — 13-round security margin.**

#### Related-Key Attacks

ChaCha20 provides no related-key security guarantees by design. The construction relies on the key being uniformly random and independent across sessions.

In leviathan-crypto, the AEAD API accepts an externally-supplied key. The `XChaCha20Poly1305` class does not derive subkeys from a master key (that responsibility falls to the application layer, e.g., scrypt or HKDF in the lvthncli demo). The HChaCha20 subkey derivation uses a different nonce for each message, so even with a fixed master key, the per-message subkeys are independent.

**Assessment:** The API does not create related-key exposure. Key management is the caller's responsibility, and the library's documentation (`CLAUDE.md`, `docs/chacha20.md`) correctly specifies 32-byte random keys.

#### Nonce Reuse

Nonce reuse under the same key is catastrophic for ChaCha20-Poly1305:

1. **Keystream reuse:** Two messages encrypted with the same (key, nonce) pair produce the same keystream. XORing the two ciphertexts yields the XOR of the two plaintexts — a classic two-time-pad attack.
2. **Poly1305 key reuse:** Counter=0 produces the same one-time key for both messages. With two (message, tag) pairs under the same Poly1305 key, the attacker can recover `r` via algebraic methods, enabling forgery of arbitrary messages.

**XChaCha20 mitigates nonce collision via 192-bit nonces.** Birthday bound analysis:
- With 192-bit random nonces, collision probability reaches 50% after 2^96 messages.
- At 1 billion messages per second, reaching 2^96 messages takes approximately 2.5 × 10^18 years.
- This is approximately 180 million times the age of the universe.

For comparison, ChaCha20's 96-bit nonce has a birthday bound of 2^48 — about 2.8 × 10^14 messages. With random nonces, this can be reached in practical scenarios, which is why XChaCha20 is the recommended variant.

**Assessment:** XChaCha20's 192-bit nonce makes random nonce collision negligibly improbable. The library correctly defaults to `XChaCha20Poly1305` as the recommended AEAD.

#### Multi-Key Attacks

No known practical multi-key attack exists for 20-round ChaCha20. The best known generic multi-key attack has complexity 2^256 / K where K is the number of keys — this is the trivial bound that applies to any cipher.

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

Even for the maximum single-chunk size of 65,536 bytes, the forgery probability is 2^{-94} — well below any practical attack threshold. For comparison, the NIST-recommended minimum security level is 2^{-32} for collision resistance; Poly1305 exceeds this by 62 bits even at maximum chunk size.

---

### 2.3 AEAD Security Properties

The ChaCha20-Poly1305 AEAD construction provides:

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Confidentiality** | Ciphertext indistinguishable from random | ChaCha20 is a PRF; keystream XOR hides plaintext |
| **Integrity** | Any bit flip in ciphertext or AAD causes tag failure | Poly1305 MAC covers padded AAD + padded CT + lengths |
| **Authenticity** | Forgery requires breaking Poly1305 | Forgery bound: ⌈l/16⌉/2^{106} per message |
| **Associated data** | AAD authenticated but not encrypted | AAD fed to Poly1305 before ciphertext |

**Nonce misuse behavior:** If the same (key, nonce) pair is used twice:
- ChaCha20 keystream is reused → XOR of plaintexts is revealed (confidentiality loss)
- Poly1305 one-time key is reused → algebraic recovery of `r` enables forgery (authenticity loss)
- However, nonce reuse does not directly enable plaintext recovery from the ciphertext alone — an attacker needs a second ciphertext under the same nonce to exploit the two-time-pad

This is not nonce-misuse resistant (unlike AES-SIV or AEGIS). The library mitigates this risk by defaulting to XChaCha20 with 192-bit nonces, where random generation is safe (see §2.2).

**Comparison to [SerpentStream Encrypt-then-MAC](./serpent_audit.md#24-serpentstream-encrypt-then-mac-and-the-cryptographic-doom-principle):**

| Property | ChaCha20-Poly1305 | SerpentStream (CTR + HMAC-SHA256) |
|----------|-------------------|-----------------------------------|
| Construction | Native AEAD | Composed EtM |
| MAC security | 2^{-106} (Poly1305, information-theoretic) | 2^{-128} (HMAC-SHA256, computational) |
| Side-channel resistance | ARX — no tables, no cache timing | Boolean circuit S-boxes — also no tables |
| Nonce handling | 192-bit (XChaCha20) — safe for random | 128-bit CTR — safe for sequential |
| Key derivation per chunk | Not needed (nonce binding) | HKDF-SHA256 per chunk |
| Tag size | 16 bytes | 32 bytes |
| WASM modules required | 1 (chacha20.wasm) | 2 (serpent.wasm + sha2.wasm) |

ChaCha20-Poly1305 is a simpler construction with fewer moving parts. Poly1305's forgery bound is information-theoretic (unconditional) rather than computational, though the bound is weaker than HMAC-SHA256's. For the message sizes supported by leviathan-crypto (≤ 64KB per AEAD operation), both constructions provide equivalent practical security.

SerpentStream's HKDF-based per-chunk key derivation provides domain separation at the key level; ChaCha20-Poly1305 achieves equivalent separation through the nonce. The HChaCha20 subkey derivation in XChaCha20 provides additional key isolation — each distinct nonce prefix produces an independent subkey.

**Assessment:** Both constructions are secure for their intended use cases. ChaCha20-Poly1305 is the simpler and more widely analyzed construction; SerpentStream provides a marginally higher MAC security bound at the cost of greater complexity.

---

### 2.4 ChaChaStream: Nonce Construction and Chunk Binding

The `lvthncli-chacha` demo (`demos/lvthncli-chacha/src/pool.ts:26–33`) constructs per-chunk nonces for XChaCha20-Poly1305:

```
xcnonce(24) = streamNonce(16) || u64be(chunkIndex)(8)
```

| Byte range | Content | Source |
|------------|---------|--------|
| 0–15 | `streamNonce` | `crypto.getRandomValues(new Uint8Array(16))` |
| 16–23 | `u64be(chunkIndex)` | Sequential index (0, 1, 2, ...) |

This 24-byte nonce is fed to `XChaCha20Poly1305`, which internally splits it:
- Bytes 0–15 → HChaCha20 subkey derivation (same for all chunks in a stream, since `streamNonce` is fixed per message)
- Bytes 16–23 → inner 12-byte nonce (`0x00000000 || u64be(index)`)

**Chunk reordering prevention:** The chunk index is encoded directly in the nonce. Reordering chunks changes the nonce used for decryption, which causes authentication failure. This is inherent to the AEAD — no additional binding mechanism is needed.

Unlike SerpentStream, which uses HKDF-SHA256 to derive per-chunk encryption and MAC keys (two derivations per chunk), ChaCha20-Poly1305 relies solely on the nonce for chunk position binding. This is sufficient because:

1. XChaCha20 is an AEAD — nonce uniqueness guarantees both confidentiality and authenticity.
2. HChaCha20 provides subkey isolation — even if an attacker controls part of the nonce, the subkey derivation prevents related-key attacks.
3. The inner nonce contains the chunk index, preventing keystream or Poly1305 key reuse across chunks.

**Stream nonce entropy:** 16 bytes from `crypto.getRandomValues` provides 128 bits of entropy. Birthday collision across streams (different messages) reaches 50% after 2^64 streams — approximately 18 billion billion messages. Combined with the chunk index, the full 24-byte nonce has no practical collision risk.

**Duplicate chunk index prevention:** The encryption loop in `pool.ts` iterates sequentially (`for i = 0; i < chunkCount; i++`), making duplicate indices structurally impossible in normal operation. There is no explicit runtime check for duplicate indices, but the sequential loop structure provides a static guarantee.

**Comparison to SerpentStream HKDF position-binding:**

| Property | ChaCha20 nonce-binding | SerpentStream HKDF-binding |
|----------|----------------------|---------------------------|
| Mechanism | Nonce contains chunk index | HKDF derives per-chunk key from (master, index) |
| Derivation cost | Zero (nonce concatenation) | 2 × HKDF-SHA256 per chunk |
| Key isolation | HChaCha20 subkey (same for all chunks) | Independent key per chunk |
| Reordering protection | AEAD auth failure | MAC verification failure |

Both approaches provide equivalent chunk-binding security. The ChaCha20 approach is more efficient (no per-chunk key derivation) while the SerpentStream approach provides stronger key isolation between chunks.

---

> ## Cross-References
>
> - [README.md](./README.md) — project overview and quick-start guide
> - [architecture.md](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [serpent_audit.md](./serpent_audit.md) — Serpent-256 companion audit; comparison in [§2.3](./chacha_audit.md#23-aead-security-properties)
> - [sha2_audit.md](./sha2_audit.md) — SHA-256 / HMAC-SHA256 audit
> - [sha3_audit.md](./sha3_audit.md) — SHA-3 companion audit
> - [hmac_audit.md](./hmac_audit.md) — HMAC-SHA256 audit (used in SerpentStream, not ChaCha)
> - [hkdf_audit.md](./hkdf_audit.md) — HKDF audit (used in SerpentStream, not ChaCha)
> - [chacha20.md](./chacha20.md) — TypeScript API documentation
> - [asm_chacha.md](./asm_chacha.md) — WASM implementation details
