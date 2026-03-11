# ChaCha20/Poly1305 WASM Reference

> [!NOTE]
> ChaCha20/Poly1305 WASM module (AssemblyScript -> `chacha.wasm`)

## Overview

This module implements the full ChaCha20-Poly1305 AEAD family in a single
WASM binary with shared linear memory:

- **ChaCha20** stream cipher (RFC 8439 S2.3-S2.4) -- 256-bit key, 96-bit nonce,
  32-bit block counter, 20 rounds (10 double rounds of column + diagonal
  quarter-rounds).
- **Poly1305** one-time MAC (RFC 8439 S2.5) -- authenticates arbitrary-length
  messages under a 256-bit one-time key (r || s). Uses a radix-2^26
  representation with u64 limbs for accumulation.
- **ChaCha20-Poly1305 AEAD** (RFC 8439 S2.8) -- the TypeScript layer composes
  `chachaGenPolyKey` + `chachaEncryptChunk` + `polyInit`/`polyUpdate`/`polyFinal`
  to produce authenticated ciphertext. The WASM module provides the primitives;
  the TS wrapper orchestrates the AEAD construction.
- **HChaCha20** subkey derivation (draft-irtf-cfrg-xchacha S2.1) -- extracts a
  256-bit subkey from a 256-bit key and 128-bit nonce prefix. Used by XChaCha20
  to extend the nonce space to 192 bits.

All cryptographic computation runs in WASM. The TypeScript layer writes inputs
to linear memory, calls exported functions, and reads outputs. It never
implements algorithm logic.

---

## Security Notes

**Constant-time by construction.** ChaCha20's quarter-round uses only ARX
operations (add, rotate, XOR). There are no table lookups, no secret-dependent
branches, and no variable-time multiplications. This makes ChaCha20 inherently
resistant to cache-timing side channels -- the same property that motivated its
adoption in TLS 1.3 as the non-AES cipher suite.

**Poly1305 accumulator arithmetic.** The Poly1305 implementation uses a
radix-2^26 limb representation stored in u64 words. Multiplication is schoolbook
over five limbs with reduction modulo p = 2^130 - 5. The u64 intermediate
products avoid overflow without needing multi-precision carries during the
multiply step. The final reduction in `polyFinal` uses a constant-time
conditional select (mask-and-OR) to choose between h and h - p, avoiding
branching on secret-derived values.

**Nonce reuse is catastrophic.** For standard ChaCha20 (96-bit nonce), reusing
a (key, nonce) pair leaks the XOR of two plaintexts and completely breaks
Poly1305 authentication. With a 96-bit nonce, random nonce generation has a
non-negligible collision probability after ~2^48 messages under the same key.
If random nonces are required, use XChaCha20-Poly1305 instead.

**XChaCha20 extends nonce to 192 bits.** HChaCha20 derives a per-message subkey
from the first 128 bits of a 192-bit nonce, then ChaCha20 encrypts with the
remaining 64 bits (zero-padded to 96 bits). The 192-bit nonce space makes random
nonce generation safe for up to ~2^96 messages -- effectively unlimited.

**`wipeBuffers()` zeroes all buffer regions.** Every buffer in the module --
keys, nonces, counters, keystream blocks, ChaCha20 state (which contains a copy
of the key in words 4-11), Poly1305 internal state (h, r, 5*r, s), chunk
buffers, and XChaCha20 subkey material -- is overwritten with zeros. The
TypeScript `dispose()` method must call this unconditionally. Key material and
intermediate state must not persist in WASM memory after an operation completes.

**Bare ChaCha20 is unauthenticated.** `chachaEncryptChunk` / `chachaDecryptChunk`
provide confidentiality only. Without Poly1305 authentication, ciphertext is
malleable -- an attacker can flip plaintext bits by flipping ciphertext bits.
Always use ChaCha20-Poly1305 AEAD or pair bare ChaCha20 with HMAC in
Encrypt-then-MAC construction.

---

## API Reference

### Buffer Offset Getters

These functions return fixed i32 offsets into linear memory. The TypeScript layer
uses them to determine where to write inputs and read outputs.

| Function | Returns | Description |
|---|---|---|
| `getModuleId(): i32` | `1` | Unique module identifier |
| `getKeyOffset(): i32` | `0` | 256-bit ChaCha20 key (32 bytes) |
| `getChachaNonceOffset(): i32` | `32` | 96-bit nonce (12 bytes, 3 x u32 LE) |
| `getChachaCtrOffset(): i32` | `44` | Block counter (u32) |
| `getChachaBlockOffset(): i32` | `48` | Keystream block output (64 bytes) |
| `getChachaStateOffset(): i32` | `112` | 16 x u32 initial state (64 bytes) |
| `getChunkPtOffset(): i32` | `176` | Plaintext chunk buffer (64 KB) |
| `getChunkCtOffset(): i32` | `65712` | Ciphertext chunk buffer (64 KB) |
| `getChunkSize(): i32` | `65536` | Max chunk size in bytes |
| `getPolyKeyOffset(): i32` | `131248` | Poly1305 one-time key r\|\|s (32 bytes) |
| `getPolyMsgOffset(): i32` | `131280` | Message staging buffer (64 bytes) |
| `getPolyBufOffset(): i32` | `131344` | Partial-block accumulator (16 bytes) |
| `getPolyBufLenOffset(): i32` | `131360` | Bytes in partial block (u32) |
| `getPolyTagOffset(): i32` | `131364` | Output MAC tag (16 bytes) |
| `getPolyHOffset(): i32` | `131380` | Accumulator h (5 x u64, 40 bytes) |
| `getPolyROffset(): i32` | `131420` | Clamped r (5 x u64, 40 bytes) |
| `getPolyRsOffset(): i32` | `131460` | Precomputed 5*r[1..4] (4 x u64, 32 bytes) |
| `getPolySOffset(): i32` | `131492` | s pad (4 x u32, 16 bytes) |
| `getXChaChaNonceOffset(): i32` | `131508` | Full 24-byte XChaCha20 nonce |
| `getXChaChaSubkeyOffset(): i32` | `131532` | HChaCha20 output subkey (32 bytes) |
| `getMemoryPages(): i32` | (runtime) | Current WASM linear memory size in pages |

### ChaCha20 Functions

#### `chachaLoadKey(): void`

Builds the 16-word ChaCha20 state matrix from the current contents of the key,
nonce, and counter buffers (RFC 8439 S2.3):

```
State layout (16 x u32):
	words  0-3:   constants ("expand 32-byte k")
	words  4-11:  key (from KEY_OFFSET, 8 x u32 LE)
	word   12:    counter (from CHACHA_CTR_OFFSET)
	words  13-15: nonce (from CHACHA_NONCE_OFFSET, 3 x u32 LE)
```

**Precondition:** Write the 32-byte key to `KEY_OFFSET`, the 12-byte nonce to
`CHACHA_NONCE_OFFSET`, and the 4-byte counter to `CHACHA_CTR_OFFSET` before
calling.

#### `chachaSetCounter(ctr: u32): void`

Sets both the counter buffer (`CHACHA_CTR_OFFSET`) and word 12 of the state
matrix to `ctr`. Use this to seek to an arbitrary block position within a stream.

#### `chachaResetCounter(): void`

Resets the counter to 1 (the standard initial counter value for encryption per
RFC 8439 S2.4). Calls `chachaSetCounter(1)` internally.

#### `chachaEncryptChunk(len: i32): i32`

Encrypts `len` bytes of plaintext from `CHUNK_PT_OFFSET` into ciphertext at
`CHUNK_CT_OFFSET`. Processes data in 64-byte keystream blocks. The block counter
auto-increments after each block.

- **Input:** `len` bytes at `CHUNK_PT_OFFSET` (1 <= len <= 65536)
- **Output:** `len` bytes at `CHUNK_CT_OFFSET`
- **Returns:** `len` on success, `-1` if len is out of range
- **Side effect:** Block counter advances by `ceil(len / 64)` blocks. Both the
  state matrix (word 12) and `CHACHA_CTR_OFFSET` are updated.

**Precondition:** Call `chachaLoadKey()` first to initialize the state matrix.

#### `chachaDecryptChunk(len: i32): i32`

Alias for `chachaEncryptChunk` -- ChaCha20 is a stream cipher; encryption and
decryption are identical (XOR with keystream). Reads from `CHUNK_PT_OFFSET`,
writes to `CHUNK_CT_OFFSET`.

#### `chachaGenPolyKey(): void`

Generates the one-time Poly1305 key by running ChaCha20 with counter = 0
(RFC 8439 S2.6). Sets state word 12 to 0, generates one keystream block, and
copies the first 32 bytes to `POLY_KEY_OFFSET`.

**Precondition:** The state matrix must already contain the correct key and nonce
(call `chachaLoadKey()` first). The counter value in the state is overwritten
to 0 for this operation.

> [!IMPORTANT]
> This consumes block 0. After calling `chachaGenPolyKey()`, set the
> counter to 1 before encrypting plaintext to avoid keystream reuse.

#### `hchacha20(): void`

HChaCha20 subkey derivation (draft-irtf-cfrg-xchacha S2.1). Computes a 256-bit
subkey from the key at `KEY_OFFSET` and the first 16 bytes of the nonce at
`XCHACHA_NONCE_OFFSET`.

The state is initialized as:
```
	words  0-3:   constants ("expand 32-byte k")
	words  4-11:  key (from KEY_OFFSET)
	words  12-15: first 16 bytes of XChaCha20 nonce (from XCHACHA_NONCE_OFFSET)
```

After 10 double rounds, the output is words 0-3 and 12-15 of the working state
(NOT added back to the initial state -- this is the key difference from the
standard ChaCha20 block function). The 32-byte result is written to
`XCHACHA_SUBKEY_OFFSET`.

**Usage in XChaCha20:** The TypeScript wrapper calls `hchacha20()` to derive the
subkey, copies it to `KEY_OFFSET`, constructs the inner 96-bit nonce from bytes
16-23 of the original 24-byte nonce (zero-padded to 12 bytes), then proceeds
with standard ChaCha20-Poly1305.

### Poly1305 Functions

#### `polyInit(): void`

Initializes Poly1305 state from the 32-byte one-time key at `POLY_KEY_OFFSET`
(RFC 8439 S2.5).

1. **Clamps r** (first 16 bytes): clears bits 4,5,6,7 of bytes 3,7,11,15 and
   bits 0,1 of bytes 4,8,12. This restricts r to the required form for
   Poly1305 security.
2. **Decomposes r** into 5 radix-2^26 limbs stored at `POLY_R_OFFSET`.
3. **Precomputes 5*r[1..4]** at `POLY_RS_OFFSET` (used in the multiplication
   step for modular reduction).
4. **Copies s** (bytes 16-31 of the key) to `POLY_S_OFFSET`.
5. **Zeroes** the accumulator h, partial-block buffer, and partial-block length.

**Precondition:** Write the 32-byte one-time key to `POLY_KEY_OFFSET`. For AEAD,
this is produced by `chachaGenPolyKey()`.

> [!WARNING]
> `polyInit()` clamps r in-place at `POLY_KEY_OFFSET`. The first 16
> bytes of the key buffer are modified.

#### `polyUpdate(len: i32): void`

Feeds `len` bytes from `POLY_MSG_OFFSET` into the Poly1305 accumulator.

- Handles partial blocks: data shorter than 16 bytes is buffered at
  `POLY_BUF_OFFSET`. When the buffer reaches 16 bytes, it is absorbed.
- Full 16-byte blocks are absorbed directly from `POLY_MSG_OFFSET`.
- Full blocks set the high bit (2^128) before absorption; partial blocks do not
  (the high bit is applied only in `polyFinal`'s padding step).
- **Input:** `len` bytes at `POLY_MSG_OFFSET` (max 64 bytes per call, matching
  the staging buffer size)
- If `len <= 0`, returns immediately (no-op).

Can be called multiple times to process a message incrementally.

#### `polyFinal(): void`

Finalizes the Poly1305 tag and writes it to `POLY_TAG_OFFSET` (16 bytes).

1. If there is a partial block in the buffer, pads it with a 0x01 byte followed
   by zeros and absorbs it with hibit = 0 (RFC 8439 S2.5.1).
2. Performs a full carry chain on h to normalize all limbs.
3. Computes the conditional subtraction: if h >= p, reduces to h - p. Uses a
   constant-time mask-and-select (no branching on secret values).
4. Recombines the 5 limbs into two u64 halves (lo, hi).
5. Adds the s pad: `tag = (h + s) mod 2^128`.
6. Stores the 16-byte tag at `POLY_TAG_OFFSET` in little-endian.

### Wipe Function

#### `wipeBuffers(): void`

Zeroes every buffer region in the module via `memory.fill()`. Covers:

- ChaCha20: key (32B), nonce (12B), counter (4B), keystream block (64B),
  state matrix (64B)
- Chunk buffers: plaintext (64KB), ciphertext (64KB)
- Poly1305: one-time key (32B), message staging (64B), partial block (16B),
  partial block length (4B), tag (16B), accumulator h (40B), clamped r (40B),
  precomputed 5*r (32B), s pad (16B)
- XChaCha20: nonce (24B), subkey (32B)

Must be called by the TypeScript `dispose()` method to prevent key material from
persisting in WASM linear memory.

---

## Buffer Layout

All offsets are byte offsets from the start of linear memory (offset 0). The
module's total memory footprint is 131,564 bytes (< 3 x 64KB pages = 192KB).

| Offset | Size (bytes) | Name | Description |
|---|---|---|---|
| 0 | 32 | `KEY_BUFFER` | ChaCha20 256-bit key |
| 32 | 12 | `CHACHA_NONCE_BUFFER` | 96-bit nonce (3 x u32, LE) |
| 44 | 4 | `CHACHA_CTR_BUFFER` | u32 block counter |
| 48 | 64 | `CHACHA_BLOCK_BUFFER` | 64-byte keystream block output |
| 112 | 64 | `CHACHA_STATE_BUFFER` | 16 x u32 initial state matrix |
| 176 | 65,536 | `CHUNK_PT_BUFFER` | Streaming plaintext input |
| 65,712 | 65,536 | `CHUNK_CT_BUFFER` | Streaming ciphertext output |
| 131,248 | 32 | `POLY_KEY_BUFFER` | One-time Poly1305 key (r \|\| s) |
| 131,280 | 64 | `POLY_MSG_BUFFER` | Message staging (<= 64 bytes per `polyUpdate`) |
| 131,344 | 16 | `POLY_BUF_BUFFER` | Partial-block accumulator |
| 131,360 | 4 | `POLY_BUF_LEN_BUFFER` | Bytes in partial block (u32) |
| 131,364 | 16 | `POLY_TAG_BUFFER` | 16-byte output MAC tag |
| 131,380 | 40 | `POLY_H_BUFFER` | Accumulator h (5 x u64 limbs) |
| 131,420 | 40 | `POLY_R_BUFFER` | Clamped r (5 x u64 limbs) |
| 131,460 | 32 | `POLY_RS_BUFFER` | Precomputed 5*r[1..4] (4 x u64) |
| 131,492 | 16 | `POLY_S_BUFFER` | s pad (4 x u32) |
| 131,508 | 24 | `XCHACHA_NONCE_BUFFER` | Full 24-byte XChaCha20 nonce |
| 131,532 | 32 | `XCHACHA_SUBKEY_BUFFER` | HChaCha20 output subkey |
| 131,564 | -- | END | Total < 192,608 (3 pages) |

---

## Internal Architecture

The module is composed of four source files compiled into a single `chacha.wasm`
binary:

### `buffers.ts` -- Static Memory Layout

Defines all buffer offsets as `i32` constants starting at offset 0. Exports
getter functions for each offset so the TypeScript layer can query them at
runtime without hardcoding addresses. Also exports `getModuleId()` (returns 1)
and `getMemoryPages()` (returns `memory.size()`).

No dynamic allocation. No `memory.grow()`. The layout is fixed at compile time.

### `chacha20.ts` -- ChaCha20 Stream Cipher + HChaCha20

Implements from RFC 8439 directly:

- **`rotl32`** -- left rotation (inlined). ChaCha20 uses left rotation
  exclusively, unlike some other ARX constructions.
- **`qr`** (quarter-round, RFC 8439 S2.1) -- the fundamental ChaCha20 operation.
  Four ARX steps with rotations of 16, 12, 8, 7 bits. Operates on four u32
  words at computed offsets in the state buffer.
- **`doubleRound`** -- one column round (indices 0,4,8,12 / 1,5,9,13 / 2,6,10,14
  / 3,7,11,15) followed by one diagonal round (0,5,10,15 / 1,6,11,12 / 2,7,8,13
  / 3,4,9,14). Applied 10 times for 20 total rounds.
- **`block`** -- the ChaCha20 block function (RFC 8439 S2.3). Copies state to
  the block buffer, applies 10 double rounds, then adds the original state back
  word-by-word. Produces one 64-byte keystream block.
- **`chachaEncryptChunk`** -- streaming encryption. Iterates over the plaintext
  in 64-byte blocks, XORing each byte with the corresponding keystream byte.
  Auto-increments the counter after each block.
- **`chachaGenPolyKey`** -- generates the one-time Poly1305 key by running ChaCha20
  with counter = 0 (RFC 8439 S2.6).
- **`hchacha20`** -- HChaCha20 (draft-irtf-cfrg-xchacha S2.1). Same as the block
  function but (a) uses the first 16 bytes of the XChaCha20 nonce as words 12-15
  instead of counter + nonce, and (b) outputs words 0-3 and 12-15 of the
  post-round state WITHOUT adding back the initial state.

### `poly1305.ts` -- Poly1305 MAC

Implements from RFC 8439 S2.5:

- **Radix-2^26 representation.** Both r and h are stored as 5 limbs of up to
  26 bits each, packed into u64 words. This allows the schoolbook multiplication
  to use u64 arithmetic without overflow -- the maximum intermediate product is
  ~2^52 * 5, well within u64 range.
- **`absorbBlock`** (internal) -- absorbs one 16-byte block into the accumulator.
  Decomposes the block into 5 radix-2^26 limbs, adds to h, multiplies by r
  using the identity `h[i] * r[j] mod p = h[i] * (5 * r[j])` for wrapped
  indices (since p = 2^130 - 5), and performs a carry chain to normalize.
- **`polyInit`** -- clamps r per RFC 8439 S2.5 (certain bits must be zero for
  security), decomposes r and s into limb form, precomputes 5*r[1..4], and
  zeroes the accumulator.
- **`polyUpdate`** -- feeds message bytes through the accumulator. Handles
  partial blocks by buffering at `POLY_BUF_OFFSET`. Full 16-byte blocks set
  the 2^128 high bit before absorption.
- **`polyFinal`** -- pads and absorbs any remaining partial block (with 0x01
  byte and hibit = 0), normalizes h via a full carry chain, performs the
  constant-time conditional reduction mod p, and adds the s pad to produce the
  final 16-byte tag.

### `wipe.ts` -- Buffer Zeroing

Single exported function `wipeBuffers()` that calls `memory.fill(offset, 0, size)`
for every buffer region. Covers key material, nonces, state, intermediate
computations, chunk buffers, and XChaCha20 subkey. Called by the TypeScript
`dispose()` method.

### Dependency Graph

```
buffers.ts
	^           ^           ^
	|           |           |
chacha20.ts   poly1305.ts   wipe.ts
	|           |           |
	+-----------+-----------+
	            |
	         index.ts (re-exports all)
```

`chacha20.ts` and `poly1305.ts` are independent of each other -- they both import
only from `buffers.ts`. The AEAD composition (calling `chachaGenPolyKey` then
feeding ciphertext through `polyUpdate`) happens in the TypeScript layer, not in
the WASM module. `wipe.ts` imports buffer offsets from `buffers.ts` and has no
dependency on either algorithm implementation.

---

## Error Conditions

| Function | Condition | Behavior |
|---|---|---|
| `chachaEncryptChunk(len)` | `len <= 0` or `len > 65536` | Returns `-1` |
| `chachaDecryptChunk(len)` | Same as above (alias) | Returns `-1` |
| `polyUpdate(len)` | `len <= 0` | No-op (returns immediately) |
| All other functions | -- | No error returns; preconditions are the caller's responsibility |

**Implicit constraints enforced by the TypeScript layer:**

- Keys must be exactly 32 bytes (256-bit).
- ChaCha20 nonces must be exactly 12 bytes (96-bit).
- XChaCha20 nonces must be exactly 24 bytes (192-bit).
- `polyUpdate` staging buffer is 64 bytes; the TS wrapper must not write more
  than 64 bytes per call.
- The block counter is u32; a single (key, nonce) pair supports at most 2^32
  blocks = 256 GB of keystream. Exceeding this wraps the counter to 0, which
  produces keystream reuse.

---

## Cross-References

- [README.md](./README.md)
- [architecture.md](./architecture.md)
- [chacha20.md](./chacha20.md): TypeScript wrapper classes (`ChaCha20`,
  `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`)
- [asm_serpent.md](./asm_serpent.md): Alternative symmetric cipher (Serpent WASM
  module)
