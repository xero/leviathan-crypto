<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### AES WASM Module Reference

This low-level reference details the AES AssemblyScript source and WASM
exports, intended for those auditing, contributing to, or building against
the raw module. **Most consumers should instead use the [TypeScript wrapper](./aes.md) or the higher-level [AEAD classes](./aead.md).**

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Buffer Layout](#buffer-layout)
> - [Internal Architecture](#internal-architecture)
> - [Error Conditions](#error-conditions)

---

## Overview

This module implements AES-128/192/256 as a standalone WebAssembly binary
compiled from AssemblyScript. The cipher is bitsliced over WASM v128 SIMD
lanes and processes 8 blocks in parallel through a single shared kernel.
Five modes ride on top of that kernel: ECB, CBC, CTR, GCM, and GCM-SIV.

Key properties:

- **Bitsliced 8-block kernel.** One v128 register holds bit `k` from every
  byte across all 8 parallel blocks. Sub-bytes, ShiftRows, MixColumns, and
  AddRoundKey all run as register-only Boolean circuits with no
  data-dependent memory access. Käsper-Schwabe 2009 (CHES) §4.1, §4.3,
  §4.4 + Appendix A.
- **Tower-field S-box.** Forward and inverse S-boxes are computed with
  Canright's GF(2^8) tower-field decomposition (Canright 2005). No S-box
  lookup tables anywhere; the gate-only circuit is constant-time by
  construction. Forward affine constant `0x63`; inverse pre-affine
  constant `0x7E`.
- **Boyar-Peralta 113-gate scalar S-box.** The byte-level key schedule
  uses the Boyar-Peralta straight-line program (32 AND, 81 XOR/XNOR
  gates, depth 27) for `sboxByte` / `sboxWord`. Faster than running the
  bitsliced circuit for the four-byte SubWord step.
- **Equivalent Inverse Cipher decrypt path.** FIPS 197 §5.3.5. The decrypt
  round loop mirrors encrypt, and inverse round keys 1..Nr-1 have
  InvMixColumns pre-applied at key-schedule time so that AddRoundKey
  reuses the existing structure.
- **Static memory only.** All buffers are fixed offsets in linear memory.
  No `memory.grow()`, no dynamic allocation. Total footprint is 202688
  bytes, fitting comfortably in 4 × 64KB pages with 59456 bytes spare.
- **Three different counter encodings.** Standalone CTR uses 128-bit
  big-endian (SP 800-38A §F.5). GCM uses a 96-bit fixed J0 prefix with a
  32-bit big-endian counter at bytes 12..15 (SP 800-38D §6.5). GCM-SIV
  uses a 32-bit little-endian counter at bytes 0..3 with the 12-byte
  nonce at 4..15 (RFC 8452 §4). The three modes share the AES kernel but
  each owns its own counter loop.

Spec citations: NIST FIPS 197 (final update 2023) §5.1, §5.2, §5.3.5,
Appendix B; NIST SP 800-38A §6.2 (CBC), §6.5 (CTR), Appendix B.1
(counter increment); NIST SP 800-38D §6.3 (GF(2^128)), §6.4 (GHASH), §7
(GCM); RFC 8452 §3, §4, Appendix A (POLYVAL, AES-GCM-SIV).

---

## Security Notes

See the [TypeScript wrapper](./aes.md) for usage-level guidance. This
section covers correctness and side-channel posture at the WASM layer.

### Constant-time S-box

The S-box is a Boolean circuit on v128 registers. No memory is indexed by
secret data inside the kernel; the path and the access pattern are
identical regardless of input value. WASM v128 operations provide
stronger timing guarantees than JavaScript bitwise operators, which may
be JIT-compiled with varying instruction selection.

### GHASH multiplier is not cache-line constant-time

`gf128MulH()` uses a 16-entry table indexed by nibbles of the running
state. The state is secret-derived, so the table read is the classic
4-bit-windowed GHASH side-channel surface. Mitigations:

- The table is 256 bytes (one cache line on most modern CPUs).
- The browser sandbox model partially mitigates direct cross-process
  cache observation.
- PCLMULQDQ-style carry-less multiply is not exposed to WebAssembly SIMD,
  so the table-free schoolbook alternative is too slow for production.
- Callers concerned about side-channel leakage should prefer
  `AESGCMSIVCipher` (which uses POLYVAL, same bridge through GHASH but
  the per-message authentication key is derived from the master, not
  fixed).

This is the same posture as BoringSSL, OpenSSL, and RustCrypto on
pre-PCLMULQDQ paths.

### CTR counter increment

`incrementCounter()` propagates carry from byte 15 toward byte 0. The
inner loop has an early-exit when no carry occurs (`if (b < 256) break`).
This is a public-data branch: the counter value is derived from the public
nonce and block position, not from key material. An observer who learns
the counter value gains no information about the key or plaintext.

### CBC and CTR are unauthenticated

Both modes provide confidentiality only. Without a MAC they are
vulnerable to padding-oracle attacks (CBC), bit-flipping, and chosen-
ciphertext manipulation. Always pair with HMAC (Encrypt-then-MAC) or use
[`AESGCMSIVCipher`](./aead.md) instead. The TS wrapper for `AESCbc`
applies a constant-time PKCS7 padding check that mitigates timing-based
padding oracles, but the fundamental lack of authentication remains.

### Memory wiping

`wipeBuffers()` zeroes every buffer declared in `buffers.ts`: master key,
round-key schedule, inverse round keys, bitsliced state, S-box scratch,
key-schedule scratch, atomic and 8-block I/O buffers, chunk buffers,
nonce, counter, CBC IV, GCM hash subkey `H`, J0, GHASH accumulator, tag,
J0E pad, length encoding, scratch, GCTR counter, GF128 table, AAD, and
all SIV state. Key material does not persist in WASM linear memory after
an operation completes.

---

## API Reference

All exported functions are re-exported through `src/asm/aes/index.ts`.

### Buffer offset getters

These return the byte offset of each buffer region in linear memory. The
TypeScript wrapper uses them to write inputs and read outputs.

```typescript
function getModuleId(): i32                  // 1
function getKeyOffset(): i32                 // 0
function getBlockPtOffset(): i32             // 32
function getBlockCtOffset(): i32             // 48
function getBlockPt8xOffset(): i32           // 64
function getBlockCt8xOffset(): i32           // 192
function getRoundKeysOffset(): i32           // 320
function getBitslicedStateOffset(): i32      // 2240
function getCanrightScratchOffset(): i32     // 2368
function getKeyScheduleScratchOffset(): i32  // 3392
function getInvRoundKeysOffset(): i32        // 3648
function getChunkPtOffset(): i32             // 5568
function getChunkCtOffset(): i32             // 71104
function getNrOffset(): i32                  // 136640
function getNonceOffset(): i32               // 136656
function getCounterOffset(): i32             // 136672
function getCbcIvOffset(): i32               // 136688
function getHOffset(): i32                   // 136704
function getJ0Offset(): i32                  // 136720
function getGhashAccOffset(): i32            // 136736
function getTagOffset(): i32                 // 136752
function getGf128TableOffset(): i32          // 136832
function getAadOffset(): i32                 // 137088
function getAadBufferSize(): i32             // 65536
function getPolyvalAuthKeyOffset(): i32      // 202624
function getPolyvalEncKeyOffset(): i32       // 202640
function getSivIcOffset(): i32               // 202672
function getChunkSize(): i32                 // 65536
function getMemoryPages(): i32
```

`getModuleId()` returns `1` (the AES slot in the loader registry; serpent
is `0`). `getMemoryPages()` returns the current WASM linear memory size
in 64 KB pages, expected `4` for AES.

---

### Key loading

```typescript
function loadKey(keyLen: i32): i32
```

Reads `keyLen` bytes from `KEY_BUFFER` (offset 0) and runs the FIPS 197
§5.2 Algorithm 2 key schedule, parameterized on `Nk ∈ {4, 6, 8}`. The
AES-256 extra-SubWord branch fires when `Nk > 6 && i mod Nk == 4`.

Two parallel buffers are populated:

- `ROUND_KEYS_BUFFER` holds the forward round keys, pre-transposed to
  bitsliced form (Käsper-Schwabe §4.5, each round key is 8 × v128 = 128
  bytes so that AddRoundKey is 8 plain v128 XORs).
- `INV_ROUND_KEYS_BUFFER` holds the EqInvCipher inverse round keys: round
  0 and round Nr are copies of the forward keys; rounds 1..Nr-1 have
  InvMixColumns pre-applied (FIPS 197 §5.3.5).

The round count `Nr` (10, 12, or 14) is stored at `NR_OFFSET` and read by
the encrypt/decrypt round loops on every call.

The GCM hash subkey `H = AES_ENC(K, 0^128)` is computed and cached at
`H_OFFSET`, and the `GF128_TABLE` (16 × 16 bytes for the 4-bit windowed
multiplier) is built from `H` here too. Per-loadKey work is amortized
across every subsequent GCM call until the next `loadKey`.

- **keyLen**: 16, 24, or 32 (AES-128 / 192 / 256)
- **Returns**: `0` on success, `-1` if `keyLen` is invalid

Must be called before any encrypt/decrypt operation.

---

### Block operations (ECB)

```typescript
function encryptBlock(): void
function decryptBlock(): void
```

Atomic single-block encrypt/decrypt. Reads from `BLOCK_PT_BUFFER`, writes
to `BLOCK_CT_BUFFER` (encrypt) or vice versa (decrypt). FIPS 197 §5.1
(Algorithm 1) and §5.3.5 (Equivalent Inverse Cipher). Internally
broadcasts the single block across all 8 lanes of the bitsliced kernel
and discards the redundant outputs, the 8-wide kernel is the only
implementation, the atomic exports are convenience wrappers.

```typescript
function encryptBlock_8x(): void
function decryptBlock_8x(): void
```

8-parallel-block encrypt/decrypt. Reads 8 blocks from
`BLOCK_PT_8X_BUFFER` (128 bytes), writes 8 blocks to `BLOCK_CT_8X_BUFFER`
(or vice versa). This is the primary kernel; CTR/CBC/GCM SIMD paths all
call it directly. Inputs and outputs are in plain (non-bitsliced) byte
order; the kernel handles the transpose internally.

```typescript
function transposeRoundTrip(): void
function sboxRoundTrip(): void
function sboxWordExport(...): u32
function singleRound(roundIdx: i32): void
```

Debug-only exports used by gate tests. `transposeRoundTrip` exercises the
8×8 bit transpose forward then inverse and asserts the result is
bit-for-bit identical. `sboxRoundTrip` does the same for the bitsliced
S-box. `sboxWordExport` exposes the Boyar-Peralta scalar SubWord
implementation. `singleRound` runs one forward round at a given index for
spec-vector cross-checking.

---

### CBC mode

```typescript
function cbcEncryptChunk(len: i32): i32
```

CBC-encrypts `len` bytes from `CHUNK_PT_BUFFER` to `CHUNK_CT_BUFFER`.
Scalar loop because each ciphertext block depends on the previous one.

- **len**: a positive multiple of 16, at most 65536
- **Returns**: `len` on success, `-1` if `len` is invalid

Chaining: `C[i] = E_K(P[i] XOR C[i-1])`, where `C[-1]` is the IV at
`CBC_IV_BUFFER`. The IV buffer is updated to the last ciphertext block
on return for streaming across multiple chunk calls.

```typescript
function cbcDecryptChunk(len: i32): i32
function cbcDecryptChunk_simd(len: i32): i32
```

CBC-decrypts `len` bytes from `CHUNK_CT_BUFFER` to `CHUNK_PT_BUFFER`. The
SIMD variant batches 8 blocks per iteration through `decryptBlock_8x`,
falling back to the scalar `cbcDecryptChunk` path for the trailing 1..7
blocks. The TS wrapper always calls `cbcDecryptChunk_simd`.

Same chaining and IV-update semantics as the encrypt path. PKCS7 padding
is the caller's responsibility.

> [!NOTE]
> CBC encryption has no SIMD variant. Each ciphertext block depends on
> the previous one, so blocks cannot be parallelized. Decryption is
> fully parallelizable because all ciphertext blocks are available up
> front.

---

### CTR mode

```typescript
function resetCounter(): void
function setCounter(hi: i64, lo: i64): void
```

`resetCounter()` copies `NONCE_BUFFER` to `COUNTER_BUFFER`, the nonce is
the initial 128-bit counter block. `setCounter(hi, lo)` writes the
counter as two 64-bit big-endian halves; used by worker pools to position
each worker at a non-overlapping range without going through `NONCE_BUFFER`.

```typescript
function encryptChunk(chunkLen: i32): i32
function decryptChunk(chunkLen: i32): i32
function encryptChunk_simd(chunkLen: i32): i32
function decryptChunk_simd(chunkLen: i32): i32
```

CTR-encrypt/decrypt `chunkLen` bytes from `CHUNK_PT_BUFFER` to
`CHUNK_CT_BUFFER`. CTR is symmetric, `decryptChunk` delegates to
`encryptChunk` and `decryptChunk_simd` to `encryptChunk_simd`. The TS
wrapper always calls the SIMD variant.

- **chunkLen**: 1 to 65536
- **Returns**: `chunkLen` on success, `-1` if `chunkLen` is out of range

The counter is 128-bit big-endian (SP 800-38A §F.5). Byte 15 is the
least-significant byte; carry propagates toward byte 0. Counter state
persists across calls for streaming.

The SIMD path generates 8 keystream blocks per iteration through
`encryptBlock_8x`, falling back to scalar for the trailing 1..7 blocks.

---

### GCM mode

```typescript
function gcmStart(ivLen: i32, aadLen: i32): i32
```

Initialize a GCM seal/open call. Derives `J0` from the IV (12-byte fast
path: `J0 = IV || 0x00000001`; other lengths trigger a GHASH-based
derivation pass). Computes `J0E = E_K(J0)` for tag XOR. Resets the GHASH
accumulator. Absorbs `AAD_BUFFER[0..aadLen]` into GHASH. Initializes the
GCTR working counter at `GCM_CB_BUFFER` to `inc_32(J0)`. Resets the
running CT-byte length.

- **ivLen**: 1 to 65536
- **aadLen**: 0 to 65536
- **Returns**: `0` on success, `-1` on invalid lengths

```typescript
function gcmEncryptChunk(srcOff: i32, dstOff: i32, len: i32): i32
```

GCTR-encrypt `len` bytes from `srcOff` to `dstOff`, then absorb the
ciphertext into GHASH and advance the CT-byte counter. The GCTR counter
format is distinct from standalone CTR: the leftmost 96 bits are fixed
from `J0`, the rightmost 32 bits are big-endian and increment per block
(`inc_32`).

- **Returns**: `0` on success, `-1` on length error or 32-bit counter overflow

```typescript
function gcmAbsorbCtChunk(srcOff: i32, len: i32): i32
```

Absorb `len` bytes of ciphertext at `srcOff` into GHASH without
decrypting. Used by the open direction's verify-before-decrypt pass.

```typescript
function gcmDecryptChunk(srcOff: i32, dstOff: i32, len: i32): i32
```

GCTR-decrypt `len` bytes from `srcOff` to `dstOff`. Does not absorb into
GHASH, that work was done by `gcmAbsorbCtChunk` during the verify pass.
The counter must be re-initialized to `inc_32(J0)` first via
`gcmResetCtrToJ0Plus1()`.

```typescript
function gcmResetCtrToJ0Plus1(): void
```

Reset the GCTR working counter to `inc_32(J0)`. Used between the
absorb-CT pass and the decrypt pass for verify-before-decrypt.

```typescript
function gcmFinalize(): void
```

Absorb the final length-encoding block (AAD bit-length || CT bit-length,
both u64 big-endian) into GHASH, XOR the result with `J0E`, and store
the 128-bit tag at `TAG_OFFSET`. The TS layer reads the computed tag and
routes the constant-time compare against the received tag through
`constantTimeEqual` in `src/ts/utils.ts` (the dedicated `ct` WASM
module). No AEAD compares tags inside its own module, library policy.

> [!NOTE]
> Plaintext is bounded by SP 800-38D §5.2.1.1 at `2^36 - 32` bytes per
> (key, IV) pair. The 32-bit GCTR counter spans at most `2^32 - 2`
> increments, each block is 16 bytes, so the maximum is
> `16 · (2^32 - 2) = 2^36 - 32` bytes. `gcmEncryptChunk` rejects when
> the cumulative block count would push the counter past the wrap point.

---

### GHASH

```typescript
function ghashStart(): void
function ghashAbsorbBlock(srcOff: i32): void
function ghashAbsorbWithLen(srcOff: i32, len: i32): void
function ghashFinalize(aadBits: i64, ctBits: i64): void
```

Standalone GHASH primitive (NIST SP 800-38D §6.4). Exported for Gate 12
testing. `ghashStart` zeroes the accumulator. `ghashAbsorbBlock` absorbs
exactly 16 bytes. `ghashAbsorbWithLen` absorbs `len` bytes (full blocks
plus a zero-padded tail if needed). `ghashFinalize` absorbs the final
length-encoding block constructed from `aadBits` and `ctBits` (each as
u64 big-endian).

The accumulator at `GHASH_ACC_BUFFER` is shared with POLYVAL, the two
modes are mutually exclusive at runtime.

---

### GF(2^128) primitives

```typescript
function gf128InitTable(): void
function gf128MulH(): void
function byteReverse16(srcOff: i32, dstOff: i32): void
function mulXGhash(srcOff: i32, dstOff: i32): void
```

`gf128InitTable` builds the 16-entry 4-bit windowed multiply table at
`GF128_TABLE_BUFFER` from `H` at `H_OFFSET`. Convention: bit 3 of the
nibble index → `u^0` coefficient, descending to bit 0 → `u^3`.

`gf128MulH` multiplies the GHASH accumulator at `GHASH_ACC_BUFFER` by `H`
in place using the table.

`byteReverse16` and `mulXGhash` are helpers for the GHASH↔POLYVAL bridge
described in RFC 8452 Appendix A: `byteReverse16` reverses byte order
in a 16-byte string, `mulXGhash` multiplies a 16-byte block by `u` in
the GHASH field.

The reduction polynomial is `u^128 + u^7 + u^2 + u + 1`. Storage
convention (SP 800-38D §6.3): bit 7 (MSB) of byte 0 is the `u^0`
coefficient; bit 0 (LSB) of byte 15 is the `u^127` coefficient.

---

### POLYVAL

```typescript
function polyvalStart(authKeyOff: i32): void
function polyvalAbsorbBlock(srcOff: i32): void
function polyvalAbsorbWithLen(srcOff: i32, len: i32): void
function polyvalFinalize(aadBits: i64, ctBits: i64): void
```

POLYVAL universal hash (RFC 8452 §3, Appendix A). Implemented as a
reflection wrapper around GHASH. Per-call setup byte-reverses the
provided auth key, applies `mulXGhash`, and feeds the result to
`gf128InitTable`. Per-block absorption byte-reverses the input into
GHASH bit convention before XOR-and-multiply. `polyvalFinalize`
byte-reverses the accumulator back to POLYVAL byte order.

The accumulator and table buffers alias the GHASH equivalents; only one
mode can be active at a time.

---

### AES-GCM-SIV

```typescript
function sivDeriveKeys(nonceOff: i32): void
```

RFC 8452 §4 derive_keys. Encrypts 4 (AES-128) or 6 (AES-256) counter
blocks under the already-loaded master key. The counter is a 32-bit
little-endian uint at bytes 0..4 of the input block; bytes 4..16 are the
12-byte nonce read from `nonceOff`. The first 8 bytes of each encrypted
output are concatenated to form `POLYVAL_AUTH_KEY` (16 bytes) and
`POLYVAL_ENC_KEY` (16 or 32 bytes).

```typescript
function sivSeal(aadLen: i32, ptLen: i32): void
```

Loads `POLYVAL_ENC_KEY` as the AES round-key schedule. Runs POLYVAL over
`padded(AAD) || padded(PT) || length-block`. Builds the tag by XORing
the POLYVAL output with the nonce, masking, and AES-encrypting under the
encryption key. SIV-CTR-encrypts `CHUNK_PT_BUFFER` in place. After
return: tag at `TAG_OFFSET`, ciphertext at `CHUNK_PT_OFFSET`.

```typescript
function sivOpen(aadLen: i32, ctLen: i32): void
```

Loads `POLYVAL_ENC_KEY` as the round-key schedule. Builds the initial
CTR block from the provided tag (the TS layer writes it to
`SIV_IC_OFFSET` first). SIV-CTR-decrypts `CHUNK_CT_BUFFER` →
`CHUNK_PT_BUFFER`. Runs POLYVAL over the decrypted plaintext with the
AAD and length block. Builds the EXPECTED tag at `TAG_OFFSET`. Does NOT
compare, the TS layer reads the expected tag and routes the
constant-time compare through `constantTimeEqual`.

```typescript
function sivWipeOnFail(): void
```

Belt-and-suspenders cleanup for the failed-open path. Zeroes everything
that could carry plaintext or auth-key material: full
`CHUNK_PT_BUFFER` (64 KiB), POLYVAL accumulator, derived per-message
keys, the GF128 table built from the auth key, the SIV counter, and the
tag scratch.

> [!NOTE]
> The SIV-CTR counter format is the third distinct counter encoding in
> the module. RFC 8452 §4 puts a 32-bit little-endian counter at bytes
> 0..3 of the 16-byte block, with the 12-byte nonce at bytes 4..15. This
> is materially different from GCM (96-bit fixed prefix + 32-bit big-
> endian counter at bytes 12..15) and from standalone CTR (full 128-bit
> big-endian counter). The three modes share the AES kernel but each
> owns its counter loop.

---

### Buffer wipe

```typescript
function wipeBuffers(): void
```

Zeroes every buffer declared in `buffers.ts`. The TypeScript wrapper
calls this in `dispose()`.

---

## Buffer Layout

All buffers are static, starting at offset 0. Total footprint: 202688
bytes (< 262144 = 4 × 64KB pages, with 59456 bytes spare).

| Offset | Size (bytes) | Name | Purpose |
|--------|-------------|------|---------|
| 0 | 32 | `KEY_BUFFER` | Master key (sized for AES-256) |
| 32 | 16 | `BLOCK_PT_BUFFER` | Atomic 1-block input |
| 48 | 16 | `BLOCK_CT_BUFFER` | Atomic 1-block output |
| 64 | 128 | `BLOCK_PT_8X_BUFFER` | 8 parallel plaintext blocks |
| 192 | 128 | `BLOCK_CT_8X_BUFFER` | 8 parallel ciphertext blocks |
| 320 | 1920 | `ROUND_KEYS_BUFFER` | 15 × 8 × 16 bitsliced forward round keys |
| 2240 | 128 | `BITSLICED_STATE_BUFFER` | 8 × v128 AES state (Käsper-Schwabe layout) |
| 2368 | 1024 | `CANRIGHT_SCRATCH_BUFFER` | 64 v128 scratch slots for the tower-field S-box |
| 3392 | 256 | `KEY_SCHEDULE_SCRATCH_BUFFER` | Byte-level scratch during keyExpansion |
| 3648 | 1920 | `INV_ROUND_KEYS_BUFFER` | EqInvCipher decrypt round keys |
| 5568 | 65536 | `CHUNK_PT_BUFFER` | Bulk plaintext / SIV in-place |
| 71104 | 65536 | `CHUNK_CT_BUFFER` | Bulk ciphertext |
| 136640 | 1 | `NR_BUFFER` | Round count: 10 / 12 / 14 (u8) |
| 136656 | 16 | `NONCE_BUFFER` | CTR initial counter / SIV nonce |
| 136672 | 16 | `COUNTER_BUFFER` | CTR working counter (128-bit big-endian) |
| 136688 | 16 | `CBC_IV_BUFFER` | CBC chaining block |
| 136704 | 16 | `H_BUFFER` | GCM hash subkey `H = E_K(0^128)` |
| 136720 | 16 | `J0_BUFFER` | GCM pre-counter block |
| 136736 | 16 | `GHASH_ACC_BUFFER` | GHASH / POLYVAL running accumulator |
| 136752 | 16 | `TAG_BUFFER` | GCM / GCM-SIV authentication tag scratch |
| 136768 | 16 | `J0E_BUFFER` | `E_K(J0)` pad |
| 136784 | 16 | `GCM_LENS_BUFFER` | AAD/PT bit-length state (two u64 BE) |
| 136800 | 16 | `GCM_SCRATCH_BUFFER` | Partial-block tail scratch |
| 136816 | 16 | `GCM_CB_BUFFER` | GCTR working counter (96-bit fixed + 32-bit BE) |
| 136832 | 256 | `GF128_TABLE_BUFFER` | 4-bit windowed multiply table (16 × 16) |
| 137088 | 65536 | `AAD_BUFFER` | GCM additional authenticated data |
| 202624 | 16 | `POLYVAL_AUTH_KEY_BUFFER` | SIV per-message auth key (RFC 8452 §4) |
| 202640 | 32 | `POLYVAL_ENC_KEY_BUFFER` | SIV per-message encryption key (sized for AES-256) |
| 202672 | 16 | `SIV_IC_BUFFER` | SIV initial counter / scratch for provided tag |
| 202688 | | `END` | Total < 262144 (4 pages) |

Two design notes:

- **Bitsliced round keys are 128 bytes per round, not 16.** Käsper-Schwabe
  §4.5: each AES round key is pre-transposed to bitsliced form so that
  AddRoundKey is 8 plain v128 XORs. The 16 round-key bytes duplicate
  across the 8 parallel blocks (since all 8 blocks share one key
  schedule), then transpose, yielding 8 × v128 = 128 bytes per
  bitsliced round key.
- **`GHASH_ACC_BUFFER` doubles as the POLYVAL accumulator.** GHASH and
  POLYVAL are mutually exclusive at runtime under the atomic AEAD
  pattern. The alias is safe and saves 16 bytes of layout. The
  `GF128_TABLE_BUFFER` is similarly shared.

---

## Internal Architecture

### buffers.ts

Defines the static memory layout as `i32` constants and getter functions.
No logic. Pure layout declaration. All other modules import offsets from
here.

### sbox.ts

Bitsliced AES S-box (forward + inverse) using the Canright tower-field
decomposition. Operates in place on 8 v128 registers in
`BITSLICED_STATE_OFFSET`; sub-results are spilled to
`CANRIGHT_SCRATCH_OFFSET` (64 v128 scratch slots).

The forward circuit is `s = (M·X) · gf256_inv(X⁻¹·a) ⊕ b`, where:

- `X` is the standard-basis representation of the tower basis (Y, Z, W
  tensor products derived from Canright §2.1's basis polynomials)
- `M` is the AES affine matrix
- `b = 0x63` is the AES affine constant (FIPS 197 §5.1.1)

The inverse circuit is `a = X · gf256_inv((X⁻¹·M⁻¹)·s ⊕ X⁻¹·M⁻¹·b)`,
with `X⁻¹·M⁻¹·b = 0x7E` precomputed. The GF(2^8) inversion kernel is
its own inverse and is shared between forward and inverse S-box; only
the front and back basis-change matrices differ.

GF(2^4) operations are Karatsuba-style compositions of GF(2^2)
multiplications. No tables, no data-dependent memory access.

### aes.ts

The core cipher kernel.

**Bit transposition (Käsper-Schwabe §4.1).** A two-stage layered
XOR/shuffle. The byte-shuffle pattern
`[0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15]` is self-inverse and
represents the 4×4 transpose of an AES state square. The 8×8
bit-matrix transpose uses three delta-swap stages with strides
`{4, 2, 1}` and masks `{0x0F, 0x33, 0x55}` (Hacker's Delight §7-2). 92
v128 operations total.

The transpose is its own inverse: `transposeIn` and `transposeOut` share
one implementation modulo source/destination offsets.

**ShiftRows as v128 shuffle (§4.3).** A single `v128.shuffle<i8>` per
register; `InvShiftRows` uses the inverse permutation.

**MixColumns (§4.4 and Appendix A).** Forward MixColumns expressed via
`rl32` / `rl64` byte rotations on the bitsliced state. InvMixColumns is
expressed as bit equations directly, denser than forward, but applied
once per round during decrypt.

**Key schedule.** Unified across `Nk ∈ {4, 6, 8}` (FIPS 197 §5.2
Algorithm 2). The AES-256 extra-SubWord branch fires when
`Nk > 6 && i mod Nk == 4`. Both forward keys and EqInvCipher inverse
keys (with InvMixColumns pre-applied to rounds 1..Nr-1) are built at
`loadKey()` time.

**Boyar-Peralta scalar S-box (`sboxByte` / `sboxWord`).** 113-gate
straight-line program, 32 AND, 81 XOR/XNOR, depth 27. Used by the byte-
level key schedule SubWord step where only 4 bytes need processing (the
bitsliced kernel pays an 8-block transpose tax that is wasted for a
4-byte input).

**Round structure.** Encrypt and decrypt round loops are parameterized
on `Nr` (read from `NR_BUFFER` per call). AddRoundKey is 8 v128 XORs.
SubBytes runs the bitsliced S-box from `sbox.ts`. ShiftRows is a single
`v128.shuffle<i8>` per slice. MixColumns runs the bit equations.

`encryptBlock_8x` and `decryptBlock_8x` are the primary kernels. The
atomic `encryptBlock` / `decryptBlock` wrappers broadcast the single
input across all 8 lanes and discard the duplicates.

### cbc.ts

Scalar CBC encrypt and CBC decrypt. Calls `encryptBlock` /
`decryptBlock`. The IV chains across calls in `CBC_IV_BUFFER`.

### cbc_simd.ts

SIMD CBC decrypt. Batches 8 blocks per iteration through
`decryptBlock_8x`, falling back to scalar `cbcDecryptChunk` for the
trailing 1..7 blocks. CBC encryption has no SIMD variant (sequential
chaining).

### ctr.ts

Scalar CTR mode plus counter management. `resetCounter()` copies
`NONCE_BUFFER` to `COUNTER_BUFFER`. `setCounter(hi, lo)` writes the
counter as two 64-bit big-endian halves. `incrementCounter()` is an
inline 128-bit big-endian increment with byte-by-byte carry propagation.

`processBlock(ptOff, ctOff, len)` encrypts the counter to produce a
keystream block, XORs with `len` plaintext bytes, increments. Handles
partial final blocks (1..15 bytes).

### ctr_simd.ts

SIMD CTR mode. Generates 8 keystream blocks per iteration through
`encryptBlock_8x`, falling back to scalar for the trailing 1..7 blocks.

### ghash.ts

Standalone GHASH primitive. `ghashStart` zeroes the accumulator.
`ghashAbsorbBlock` absorbs 16 bytes via XOR and `gf128MulH`.
`ghashAbsorbWithLen` handles full blocks plus a zero-padded tail.
`ghashFinalize` absorbs the length-encoding block.

### gf128.ts

GF(2^128) primitive: `gf128MulH` (multiply running accumulator by `H`
using the table), `gf128InitTable` (build the table from `H`),
`mulXGhash` (multiply by `u`, used in the POLYVAL setup), and
`byteReverse16` (used in the POLYVAL bridge). Internally also defines
`gf128MulU` and `gf128MulU4` as constant-time helpers.

### gcm.ts

Composes `aes.ts`, `ghash.ts`, and `gf128.ts` into the GCM construction.
`gcmStart` derives `J0`, computes `J0E`, resets GHASH, absorbs AAD, sets
up the GCTR counter. `gcmEncryptChunk` runs GCTR src→dst then absorbs
ciphertext into GHASH. `gcmAbsorbCtChunk` absorbs without decrypting
(for verify-before-decrypt). `gcmDecryptChunk` runs GCTR src→dst without
absorbing. `gcmFinalize` absorbs the length block, XORs with `J0E`, and
stores the tag at `TAG_OFFSET`.

The 12-byte IV fast path sets `J0 = IV || 0x00000001` directly. Any
other length runs a GHASH-based J0 derivation pass over the IV with
zero padding and a length encoding.

### polyval.ts

POLYVAL (RFC 8452 §3, Appendix A) as a reflection wrapper around GHASH.
`polyvalStart(authKeyOff)` byte-reverses the auth key, applies
`mulXGhash`, and feeds the result to `gf128InitTable`.
`polyvalAbsorbBlock` and `polyvalAbsorbWithLen` byte-reverse inputs into
GHASH bit convention before XOR-and-multiply. `polyvalFinalize`
byte-reverses the accumulator back to POLYVAL byte order.

### aes-gcm-siv.ts

RFC 8452 single-shot AEAD. Glues the AES kernel, POLYVAL, the SIV-CTR
counter loop (32-bit little-endian counter at bytes 0..3, 12-byte nonce
at 4..15), and the derive_keys construction. AES-128 and AES-256 only;
RFC 8452 §6 excludes AES-192. Plaintext bounded by `CHUNK_PT_BUFFER`
(64 KiB) per call. `sivWipeOnFail` is a belt-and-suspenders
zeroing path for the failed-open case.

### wipe.ts

`wipeBuffers()` runs 21 `memory.fill` calls covering every buffer in
`buffers.ts`. Called from `dispose()` in the TS wrapper.

### Dependency graph

```
buffers.ts
    ^
    |
sbox.ts <── aes.ts ─────────────────────┐
    |          ^   ^   ^                │
    |          |   |   └── cbc.ts       │
    |          |   └────── ctr.ts ──────│── ctr_simd.ts
    |          └────────── cbc_simd.ts  │
    |                                   │
gf128.ts ─── ghash.ts ─── gcm.ts ───────┘
    │                                    aes-gcm-siv.ts
    └── polyval.ts ─────────────────────┘

                    index.ts  (re-exports public API)
```

---

## Error Conditions

| Function | Error | Return |
|----------|-------|--------|
| `loadKey(keyLen)` | `keyLen` is not 16, 24, or 32 | `-1` |
| `encryptChunk(chunkLen)` / `encryptChunk_simd` / `decryptChunk` / `decryptChunk_simd` | `chunkLen <= 0` or `chunkLen > 65536` | `-1` |
| `cbcEncryptChunk(len)` / `cbcDecryptChunk` / `cbcDecryptChunk_simd` | `len <= 0`, `len > 65536`, or `len % 16 !== 0` | `-1` |
| `gcmStart(ivLen, aadLen)` | `ivLen < 1`, `ivLen > 65536`, or `aadLen > 65536` | `-1` |
| `gcmEncryptChunk` / `gcmDecryptChunk` / `gcmAbsorbCtChunk` | `len < 0` or 32-bit GCTR counter overflow | `-1` |

> [!NOTE]
> `encryptBlock` / `decryptBlock`, the `_8x` variants, and the GHASH /
> POLYVAL / SIV functions have no error returns. They assume `loadKey`
> was called successfully and the input buffers contain valid data. The
> TypeScript wrapper enforces these preconditions.

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [aes](./aes.md) | TypeScript wrapper classes (`AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`, `AESGenerator`, `AESGCMSIVCipher`) |
| [aead](./aead.md) | `Seal`, `SealStream`, `OpenStream`: use `AESGCMSIVCipher` as the suite argument |
| [ciphersuite](./ciphersuite.md) | `AESGCMSIVCipher` reference: format enum, key derivation, commitment binding |
| [asm_sha2](./asm_sha2.md) | SHA-2 WASM module (used together with AES via Fortuna and HKDF) |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
