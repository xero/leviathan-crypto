# Serpent-256 WASM Module Reference

> [!NOTE]
> Serpent-256 WASM module (AssemblyScript -> `serpent.wasm`)

## Overview

This module implements the Serpent-256 block cipher as a standalone WebAssembly
binary compiled from AssemblyScript. Serpent is the Anderson/Biham/Knudsen AES
submission (1998) -- a 32-round SP-network with 128-bit blocks and 128/192/256-bit
keys. It placed second in the AES competition, chosen by designers who explicitly
prioritized security margin over throughput.

Key properties of this implementation:

- **Bitslice S-boxes**: all eight forward and inverse S-boxes are Boolean circuits
  (AND/OR/XOR/NOT only). No lookup tables, no data-dependent memory access.
- **Static memory only**: all buffers are fixed offsets in linear memory. No
  `memory.grow()`, no dynamic allocation.
- **32 hardcoded rounds**: round count is a structural constant, not configurable.
  No reduced-round risk.
- **Two cipher variants**: a loop-driven core (`serpent.ts`) and an auto-generated
  fully-unrolled variant (`serpent_unrolled.ts`) that enables V8 TurboFan register
  promotion.
- **Block modes**: CTR (counter) and CBC (cipher block chaining) operate on 64KB
  chunks via the unrolled variant.
- **ECB block ops**: single-block encrypt/decrypt for use by higher-level
  constructions (e.g., Fortuna CSPRNG generator).

---

## Security Notes

### Constant-time S-boxes

The S-boxes (`sb0`-`sb7`, `si0`-`si7`) use exclusively `&`, `|`, `^`, `~`
on i32 registers. No memory is indexed by secret data. This is constant-time by
construction -- the execution path and memory access pattern are identical
regardless of input values. WASM i32 operations provide stronger timing
guarantees than JavaScript bitwise operators, which may be JIT-compiled with
varying instruction selection.

### Linear transform and key schedule

The linear transform (`lk`/`kl`) uses only rotations (`rotl`), XOR, and shift --
all data-independent. The key schedule (`loadKey`) similarly uses only arithmetic
and bitwise ops on the prekey buffer. No secret-dependent branches anywhere in the
cipher core.

### CTR counter increment

`incrementCounter()` has a minor timing leak: the carry-propagation loop exits
early when no carry occurs (`if (b < 256) break`). This is acceptable because the
counter value is not secret -- it is derived from the (public) nonce and block
position. An observer who learns the counter value gains no information about the
key or plaintext.

### CBC mode is unauthenticated

CBC provides confidentiality only. Without a MAC, it is vulnerable to padding
oracle attacks, bit-flipping, and chosen-ciphertext manipulation. Always pair with
HMAC (Encrypt-then-MAC) or use `XChaCha20Poly1305` instead. PKCS7 padding
validation in the TypeScript wrapper uses constant-time XOR-accumulate comparison
to mitigate timing-based padding oracles, but the fundamental lack of
authentication remains.

### Memory wiping

`wipeBuffers()` zeroes all sensitive regions: key material, subkeys, working
registers, plaintext/ciphertext chunks, nonce, counter, and CBC IV. The TypeScript
wrapper calls this in `dispose()`. Key material does not persist in WASM linear
memory after an operation completes.

### Round count

The round count (32) is a structural constant embedded in the loop bounds and
unrolled code. There is no parameter to reduce it. The best known mathematical
attack reaches 12 of 32 rounds (multidimensional linear cryptanalysis, 2011),
leaving a 20-round security margin. See
[serpent_reference.md](./serpent_reference.md) for the full attack landscape.

---

## API Reference

All exported functions are re-exported through `src/asm/serpent/index.ts`. The
public WASM API is:

### Buffer offset getters

These return the byte offset of each buffer region in linear memory. The
TypeScript wrapper uses them to write inputs and read outputs.

```typescript
function getModuleId(): i32
```
Returns `0`. Module identifier for the init system.

```typescript
function getKeyOffset(): i32       // 0
function getBlockPtOffset(): i32   // 32
function getBlockCtOffset(): i32   // 48
function getNonceOffset(): i32     // 64
function getCounterOffset(): i32   // 80
function getSubkeyOffset(): i32    // 96
function getChunkPtOffset(): i32   // 624
function getChunkCtOffset(): i32   // 66160
function getWorkOffset(): i32      // 131696
function getCbcIvOffset(): i32     // 131716
```
Each returns the fixed byte offset for that buffer. Values shown as comments.

```typescript
function getChunkSize(): i32       // 65536
```
Returns the maximum chunk size in bytes (64KB).

```typescript
function getMemoryPages(): i32
```
Returns the current WASM linear memory size in 64KB pages (expected: 3).

### Key loading

```typescript
function loadKey(keyLen: i32): i32
```
Reads `keyLen` bytes from `KEY_BUFFER` (offset 0), pads to 256 bits per the Serpent
spec (append 1-bit, then zeros), and expands the full key schedule into
`SUBKEY_BUFFER` (33 x 128-bit subkeys = 132 words = 528 bytes).

- **keyLen**: 16, 24, or 32 (128/192/256-bit key)
- **Returns**: `0` on success, `-1` if `keyLen` is not 16, 24, or 32

The key schedule applies the affine recurrence with `phi = 0x9E3779B9` to generate
132 prekey words, then derives 33 round subkeys through the S-box layer. Byte
ordering follows the Serpent reference implementation (reverse-copy, then LE repack).

Must be called before any encrypt/decrypt operation.

### Block operations (ECB)

```typescript
function encryptBlock(): void
```
Encrypts a single 128-bit block. Reads 16 bytes from `BLOCK_PT_BUFFER` (offset 32),
writes 16 bytes to `BLOCK_CT_BUFFER` (offset 48). Uses the fully-unrolled variant
internally. `loadKey()` must have been called first.

Byte ordering: plaintext bytes are reversed and loaded as 4 LE 32-bit words
(big-endian external format). Ciphertext is stored back in big-endian byte order.

```typescript
function decryptBlock(): void
```
Decrypts a single 128-bit block. Reads 16 bytes from `BLOCK_CT_BUFFER` (offset 48),
writes 16 bytes to `BLOCK_PT_BUFFER` (offset 32). Same byte-ordering conventions as
`encryptBlock`.

> [!NOTE]
> `index.ts` exports the unrolled variants as `encryptBlock`/`decryptBlock`
> (the loop-driven versions in `serpent.ts` are not exported, they exist as the
> reference implementation).

### CTR mode

```typescript
function resetCounter(): void
```
Copies `NONCE_BUFFER` (16 bytes at offset 64) to `COUNTER_BUFFER` (offset 80). The
nonce *is* the initial counter value -- no zeroing occurs. Call this before the
first `encryptChunk`/`decryptChunk` for a new message.

```typescript
function setCounter(lo: i64, hi: i64): void
```
Sets the 128-bit counter to an absolute value. `lo` is bytes 0-7 (little-endian),
`hi` is bytes 8-15. Used by worker pools to position each worker at a non-overlapping
counter range without calling `resetCounter()`.

```typescript
function encryptChunk(chunkLen: i32): i32
```
CTR-encrypts `chunkLen` bytes from `CHUNK_PT_BUFFER` (offset 624) to
`CHUNK_CT_BUFFER` (offset 66160). Handles partial final blocks (1-15 bytes)
natively -- no padding required.

- **chunkLen**: 1 to 65536
- **Returns**: `chunkLen` on success, `-1` if `chunkLen <= 0` or `chunkLen > 65536`

Counter is incremented after each 16-byte block (128-bit LE increment, LSB at
byte 0). Counter state persists across calls for streaming.

```typescript
function decryptChunk(chunkLen: i32): i32
```
Identical to `encryptChunk` -- CTR mode is symmetric. Reads from `CHUNK_PT_BUFFER`,
writes to `CHUNK_CT_BUFFER`. Same parameters and return values.

### CBC mode

```typescript
function cbcEncryptChunk(len: i32): i32
```
CBC-encrypts `len` bytes from `CHUNK_PT_BUFFER` to `CHUNK_CT_BUFFER`.

- **len**: must be a positive multiple of 16, at most 65536
- **Returns**: `len` on success, `-1` if `len` is invalid

Chaining: `C[i] = Encrypt(P[i] XOR C[i-1])`, where `C[-1]` is the IV stored at
`CBC_IV_BUFFER` (offset 131716). The IV buffer is updated to the last ciphertext
block on return, enabling streaming across multiple chunk calls.

PKCS7 padding is the caller's responsibility (applied in the TypeScript wrapper).

```typescript
function cbcDecryptChunk(len: i32): i32
```
CBC-decrypts `len` bytes from `CHUNK_CT_BUFFER` to `CHUNK_PT_BUFFER`.

- **len**: must be a positive multiple of 16, at most 65536
- **Returns**: `len` on success, `-1` if `len` is invalid

Chaining: `P[i] = Decrypt(C[i]) XOR C[i-1]`. The IV buffer is updated to the last
ciphertext block on return.

### Cleanup

```typescript
function wipeBuffers(): void
```
Zeroes all sensitive memory regions:

| Region | Offset | Size |
|--------|--------|------|
| KEY_BUFFER | 0 | 32 |
| BLOCK_PT_BUFFER | 32 | 16 |
| BLOCK_CT_BUFFER | 48 | 16 |
| NONCE_BUFFER | 64 | 16 |
| COUNTER_BUFFER | 80 | 16 |
| SUBKEY_BUFFER | 96 | 528 |
| CHUNK_PT_BUFFER | 624 | 65536 |
| CHUNK_CT_BUFFER | 66160 | 65536 |
| WORK_BUFFER | 131696 | 20 |
| CBC_IV_BUFFER | 131716 | 16 |

Must be called when done with the cipher (the TypeScript wrapper calls this in
`dispose()`).

---

## Buffer Layout

All buffers are static, starting at offset 0. Total footprint: 131732 bytes
(< 192KB = 3 x 64KB pages, with 64876 bytes spare).

| Offset | Size (bytes) | Name | Purpose |
|--------|-------------|------|---------|
| 0 | 32 | `KEY_BUFFER` | Raw key input (padded to 32 for all key sizes) |
| 32 | 16 | `BLOCK_PT_BUFFER` | Single-block plaintext (ECB input / CBC scratch) |
| 48 | 16 | `BLOCK_CT_BUFFER` | Single-block ciphertext (ECB output / CTR keystream) |
| 64 | 16 | `NONCE_BUFFER` | CTR nonce (initial counter value) |
| 80 | 16 | `COUNTER_BUFFER` | 128-bit LE counter (CTR mode state) |
| 96 | 528 | `SUBKEY_BUFFER` | Expanded subkeys: 33 rounds x 4 words x 4 bytes |
| 624 | 65536 | `CHUNK_PT_BUFFER` | Bulk plaintext input (CTR/CBC) |
| 66160 | 65536 | `CHUNK_CT_BUFFER` | Bulk ciphertext output (CTR/CBC) |
| 131696 | 20 | `WORK_BUFFER` | 5 x i32 working registers for S-box computation |
| 131716 | 16 | `CBC_IV_BUFFER` | CBC chaining value (IV, then last CT block) |
| 131732 | -- | `END` | Total < 196608 (3 pages) |

The `SUBKEY_BUFFER` holds 132 i32 words during key expansion, then the final 33 x 4
round subkeys. The `WORK_BUFFER` holds 5 working registers (r0-r4) used by the
S-box Boolean circuits -- these are effectively the cipher's "CPU registers" in
linear memory.

---

## Internal Architecture

### buffers.ts

Defines the static memory layout as `i32` constants and getter functions. No logic
-- pure layout declaration. All other modules import offsets from here.

### serpent.ts

The core cipher implementation, ported independently from the Serpent AES submission
spec. Contains:

- **Working register helpers** (`rget`/`rset`): inline functions that load/store
  i32 values at `WORK_OFFSET + (i << 2)`. These are the cipher's virtual registers.
- **S-boxes** (`sb0`-`sb7`): 8 forward S-box Boolean circuits. Each takes 5 slot
  indices into the working registers. Operations are exclusively `&`, `|`, `^`, `~`
  on `rget`/`rset` values.
- **Inverse S-boxes** (`si0`-`si7`): 8 inverse S-box circuits for decryption.
- **EC/DC/KC constants**: encoded 5-slot permutations for each round. Each constant
  encodes a permutation via `(m%5, m%7, m%11, m%13, m%17)` -- all five values are
  guaranteed to be in {0,1,2,3,4} and distinct. `ec` drives encryption rounds, `dc`
  drives decryption rounds, `kc` drives key schedule S-box application.
- **keyXor**: XORs 4 working registers with a round subkey.
- **lk** (Linear transform + Key XOR): the forward LT
  (rotl-13, rotl-3, XOR mixing, rotl-1, rotl-7, XOR mixing, rotl-5, rotl-22)
  followed by subkey XOR. Used in encryption rounds 0-30.
- **kl** (Key XOR + Inverse Linear transform): subkey XOR followed by the inverse
  LT. Used in decryption rounds.
- **Key schedule** (`loadKey`): reverse-copies key bytes, repacks as LE words,
  expands 132 prekey words via the affine recurrence
  (`w_i = rotl(w_{i-8} ^ w_{i-5} ^ w_{i-3} ^ w_{i-1} ^ 0x9E3779B9 ^ i, 11)`),
  then derives 33 round subkeys through S-box application using the `kc` constants.
- **encryptBlock / decryptBlock**: loop-driven implementations (not exported -- used
  as reference).
- **wipeBuffers**: zeroes all sensitive memory.

### serpent_unrolled.ts

Auto-generated (via `bench/generate_unrolled.ts`). All 32 rounds are fully expanded
with hardcoded slot constants (no `ec`/`dc` lookup, no `applyS`/`applySI` dispatch).
This enables V8 TurboFan to resolve every `rget`/`rset` call to a fixed linear
memory address at compile time, promoting the 5 working registers from memory
load/stores to CPU registers.

Exports `encryptBlock_unrolled` and `decryptBlock_unrolled`, which `index.ts`
re-exports as `encryptBlock`/`decryptBlock`. CBC and CTR modes use the unrolled
variant internally.

### cbc.ts

CBC mode encryption and decryption over 64KB chunks. Imports `encryptBlock_unrolled`
and `decryptBlock_unrolled` from the unrolled module.

- Encryption: XORs each plaintext block with the chaining value (IV or previous
  ciphertext), encrypts via `encryptBlock`, writes output, updates IV.
- Decryption: copies ciphertext to block buffer, decrypts, XORs with chaining
  value, updates IV from original ciphertext.
- IV state persists in `CBC_IV_BUFFER` across calls for streaming.
- PKCS7 padding is not handled here -- the TypeScript wrapper applies it.

### ctr.ts

CTR mode encryption/decryption over 64KB chunks. Uses `encryptBlock_unrolled` to
generate keystream blocks.

- `resetCounter()`: copies nonce to counter (nonce *is* the initial counter value).
- `setCounter(lo, hi)`: absolute 128-bit counter positioning for worker pools.
- `incrementCounter()`: 128-bit LE increment with byte-by-byte carry propagation.
- `processBlock()`: encrypts the counter to produce a keystream block, XORs with
  plaintext, increments counter. Handles partial final blocks (1-15 bytes).
- `encryptChunk`/`decryptChunk`: iterate over the chunk in 16-byte blocks.
  `decryptChunk` delegates to `encryptChunk` (CTR is symmetric).

### Dependency graph

```
buffers.ts
    ^
    |
serpent.ts
    ^
    |
serpent_unrolled.ts
    ^        ^
    |        |
  cbc.ts   ctr.ts
    \       /
     \     /
    index.ts  (re-exports public API)
```

---

## Error Conditions

| Function | Error | Return |
|----------|-------|--------|
| `loadKey(keyLen)` | `keyLen` is not 16, 24, or 32 | `-1` |
| `encryptChunk(chunkLen)` | `chunkLen <= 0` or `chunkLen > 65536` | `-1` |
| `decryptChunk(chunkLen)` | `chunkLen <= 0` or `chunkLen > 65536` | `-1` |
| `cbcEncryptChunk(len)` | `len <= 0`, `len > 65536`, or `len % 16 !== 0` | `-1` |
| `cbcDecryptChunk(len)` | `len <= 0`, `len > 65536`, or `len % 16 !== 0` | `-1` |

> [!NOTE]
> `encryptBlock`/`decryptBlock` have no error returns. They assume `loadKey`
> was called successfully and the block buffers contain valid data. The TypeScript
> wrapper enforces these preconditions.

## Cross-References

- [serpent.md](./serpent.md) — TypeScript wrapper classes (`Serpent`, `SerpentCbc`, `SerpentCtr`, `SerpentSeal`, `SerpentStream`)
- [serpent_reference.md](./serpent_reference.md) — algorithm specification, S-box tables, linear transform, and known attacks
- [serpent_audit.md](./serpent_audit.md) — security audit results (algorithm correctness, side-channel analysis)
- [asm_sha2.md](./asm_sha2.md) — SHA-2 WASM module (used together with Serpent via Fortuna CSPRNG)
- [README.md](./README.md) — library documentation index and exports table
- [architecture.md](./architecture.md) — module structure, buffer layouts, and build pipeline
