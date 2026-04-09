# SHA-3 WASM Reference

> [!NOTE]
> This module implements the full SHA-3/SHAKE family (FIPS 202) as an AssemblyScript WASM module (`sha3.wasm`).
>
> See [SHA-3 implementation audit](./sha3_audit.md) for algorithm correctness verifications.

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Buffer Layout](#buffer-layout)
> - [Internal Architecture](#internal-architecture)
> - [Variant Parameters](#variant-parameters)
> - [Error Conditions](#error-conditions)

---

## Overview

This module implements the full SHA-3 family as defined in **FIPS 202** ("SHA-3
Standard: Permutation-Based Hash and Extendable-Output Functions", August 2015).

All six variants share a single core: the **Keccak-f[1600]** permutation operating
on a 5x5 matrix of 64-bit lanes (200 bytes of state). The sponge construction
wraps the permutation into two phases:

1. **Absorb.** Input bytes are XORed into the state, rate bytes at a time, with a permutation call after each full block.
2. **Squeeze.** Output bytes are read from the state after padding and a final permutation.

The six variants differ only in three parameters: the **rate** (how many bytes per
sponge block), the **domain separation byte** (which distinguishes SHA-3 from SHAKE
in the padding), and the **output length**.

**Fixed-output hash functions (FIPS 202 SS6.1):**
- SHA3-224, SHA3-256, SHA3-384, SHA3-512

**Extendable-output functions / XOFs (FIPS 202 SS6.2):**
- SHAKE128, SHAKE256

---

## Security Notes

**No length extension.** Unlike the Merkle-Damgard family (SHA-2), SHA-3's sponge
construction does not leak sufficient internal state to mount length extension
attacks. The capacity portion of the state is never exposed during squeezing.

**Domain separation.** SHA-3 and SHAKE use different domain separation bytes in the
multi-rate padding (FIPS 202 SS6.1-6.2):
- `0x06` for SHA-3 (fixed-output)
- `0x1f` for SHAKE (extendable-output)

This means `SHA3-256(M)` and `SHAKE256(M, 256)` produce different digests even
though both use rate=136. The domain separation byte is XORed into the state during padding, making the two functions cryptographically independent.

**Constant-time permutation.** Keccak-f[1600] uses only bitwise XOR, AND, NOT, and
fixed rotations on 64-bit lanes. There are no data-dependent branches, no table
lookups, and no secret-dependent memory access patterns. The permutation is
constant-time by construction.

**SHAKE output cap.** This implementation squeezes at most one block of output per
`shakeFinal()` call. SHAKE128 output is capped at 168 bytes and SHAKE256
at 136 bytes. For the common use case of deriving a fixed-size key, this is
sufficient. If you need more output than one squeeze block, extend the squeeze loop. This is a known limitation of the v1.0 module.

**`wipeBuffers()`.** Zeroes all 545 bytes of module state: the 200-byte Keccak lane
matrix, the input staging buffer, the output buffer, and the rate/absorbed/dsByte
metadata. The TypeScript wrapper must call this on `dispose()` to prevent key
material or intermediate hash state from persisting in WASM linear memory.

---

## API Reference

All exported functions from `src/asm/sha3/index.ts`:

### Initialization

```typescript
sha3_224Init():  void   // rate=144, dsByte=0x06
sha3_256Init():  void   // rate=136, dsByte=0x06
sha3_384Init():  void   // rate=104, dsByte=0x06
sha3_512Init():  void   // rate=72,  dsByte=0x06
shake128Init():  void   // rate=168, dsByte=0x1f
shake256Init():  void   // rate=136, dsByte=0x1f
```

Each init function zeroes the 200-byte state and the 168-byte input buffer, then
writes the variant-specific rate, absorbed count (0), and domain separation byte
into the metadata slots. Call exactly one init function before absorbing data.

---

### Absorb

```typescript
keccakAbsorb(len: i32): void
```

Absorbs `len` bytes from `INPUT_OFFSET` into the sponge state. Write
input data to `INPUT_OFFSET` before calling this function. Data is XORed into the
state byte-by-byte (FIPS 202 SS4, Algorithm 8). When the absorbed byte count
reaches the rate, Keccak-f[1600] is applied and absorption continues from lane 0.

You can call this multiple times for streaming input; the `ABSORBED` counter tracks the
current position within the rate block across calls.

**Constraint:** `len` must not exceed 168 (the size of the input staging buffer).
For messages longer than 168 bytes, call `keccakAbsorb` in a loop, writing up to
168 bytes to `INPUT_OFFSET` each iteration.

---

### Finalize (fixed-output)

```typescript
sha3_224Final(): void   // writes 28 bytes to OUT_OFFSET
sha3_256Final(): void   // writes 32 bytes to OUT_OFFSET
sha3_384Final(): void   // writes 48 bytes to OUT_OFFSET
sha3_512Final(): void   // writes 64 bytes to OUT_OFFSET
```

Each final function applies multi-rate padding (FIPS 202 SS5.1, pad10*1), runs
the final Keccak-f[1600] permutation, and copies the appropriate number of output
bytes from the state to `OUT_OFFSET`.

Padding consists of two XOR operations:
1. The domain separation byte (`0x06`) is XORed at position `absorbed` in the state.
2. `0x80` is XORed at position `rate - 1` in the state.

If `absorbed == rate - 1`, both XORs hit the same byte.

---

### Finalize (extendable-output)

```typescript
shakeFinal(outLen: i32): void
```

Same as the fixed-output finals, but you specify the output length.

**Constraint:** `outLen` must not exceed the rate of the initialized SHAKE variant
(168 for SHAKE128, 136 for SHAKE256). This implementation performs a single squeeze and does not loop additional permutations for longer output.

---

### Low-level finalize

```typescript
keccakFinal(outLen: i32): void
```

The underlying finalize used by all final functions. Applies padding using
whatever domain separation byte was set during init, permutes, and squeezes
`outLen` bytes. Exported for advanced use cases where you manage variant
parameters directly.

---

### Buffer offset getters

```typescript
getModuleId():       i32   // returns 3 (sha3 module identifier)
getStateOffset():    i32   // returns 0
getRateOffset():     i32   // returns 200
getAbsorbedOffset(): i32   // returns 204
getDsByteOffset():   i32   // returns 208
getInputOffset():    i32   // returns 209
getOutOffset():      i32   // returns 377
getMemoryPages():    i32   // returns current WASM memory size in pages
```

The TypeScript wrapper uses these to locate buffers in WASM linear memory without
hardcoding offsets.

---

### Cleanup

```typescript
wipeBuffers(): void
```

Zeroes all state: the 200-byte lane matrix, 168-byte input buffer, 168-byte output
buffer, and the rate/absorbed/dsByte metadata. Call this when the hash context
is no longer needed.

---

## Buffer Layout

All buffers occupy fixed offsets in WASM linear memory, starting at 0. There is no
dynamic allocation (`memory.grow()` is not used).

| Offset | Size (bytes) | Name | Description |
|--------|-------------|------|-------------|
| 0 | 200 | `KECCAK_STATE` | 25 x u64 lane matrix (5x5, little-endian, `A[x][y]` at `(x + 5y) * 8`) |
| 200 | 4 | `KECCAK_RATE` | u32 rate in bytes (variant-specific: 72-168) |
| 204 | 4 | `KECCAK_ABSORBED` | u32 count of bytes absorbed into the current block |
| 208 | 1 | `KECCAK_DSBYTE` | u8 domain separation byte (`0x06` or `0x1f`) |
| 209 | 168 | `KECCAK_INPUT` | Input staging buffer (max rate = SHAKE128 at 168) |
| 377 | 168 | `KECCAK_OUT` | Output buffer (one full SHAKE128 squeeze block) |
| **545** | | **END** | Total footprint: 545 bytes (well within 3 x 64KB = 192KB) |

The input and output buffers are both sized to 168 bytes, the maximum rate across all variants (SHAKE128). For SHA3-512 (rate=72), only the first 72 bytes of the
input buffer and the first 64 bytes of the output buffer are used.

---

## Internal Architecture

### buffers.ts

Defines the six buffer offset constants and the getter functions that expose them
to the TypeScript layer. The layout is minimal: 545 bytes total, well under the
3-page (192KB) WASM memory allocation.

---

### keccak.ts

Contains all cryptographic logic:

**Keccak-f[1600] permutation** (`keccakF`): 24 rounds, each consisting of five
steps (FIPS 202 SS3.2):

1. **theta** (SS3.2.1): column parity mixing. Computes the XOR of each column, then XORs each lane with the parity of its neighboring columns.
2. **rho** (SS3.2.2): lane rotation. Each of the 25 lanes is rotated left by a fixed offset from the rotation table (FIPS 202 Table 2).
3. **pi** (SS3.2.3): lane permutation. Lanes are rearranged: `B[y][2x+3y] = A[x][y]`.
4. **chi** (SS3.2.4): nonlinear mixing. `A[x] = B[x] XOR (NOT B[x+1] AND B[x+2])`. This is the only nonlinear step and provides the cryptographic strength.
5. **iota** (SS3.2.5): round constant addition. A round-dependent constant is XORed into lane `A[0][0]`. The 24 constants are derived from an LFSR (FIPS 202 SS3.2.5).

The implementation loads all 25 lanes into local variables at the top of `keccakF`
and stores them back at the end. The rho and pi steps are combined into a single
operation using precomputed rotation offsets. The iota step uses an if-else chain
rather than a table load to apply round constants, avoiding any data-dependent memory
access.

**Sponge functions:**

**`keccakInit(rate, dsByte)`**: zeroes state, sets variant parameters.

**`keccakAbsorb(len)`**: XORs input into state, permuting when a full rate block is absorbed. Tracks position via `ABSORBED` counter.

**`keccakFinal(outLen)`**: applies pad10*1 (domain byte at `absorbed`, `0x80` at `rate-1`), permutes, squeezes `outLen` bytes to the output buffer.

---

### index.ts

Pure re-export barrel. Exports all getters from `buffers.ts` and all sponge
functions from `keccak.ts`. No logic.

---

## Variant Parameters

| Variant | Rate (bytes) | Capacity (bytes) | Output (bytes) | DS Byte | Security (bits) |
|---------|-------------|------------------|----------------|---------|-----------------|
| SHA3-224 | 144 | 56 | 28 | `0x06` | 112 |
| SHA3-256 | 136 | 64 | 32 | `0x06` | 128 |
| SHA3-384 | 104 | 96 | 48 | `0x06` | 192 |
| SHA3-512 | 72 | 128 | 64 | `0x06` | 256 |
| SHAKE128 | 168 | 32 | variable (max 168) | `0x1f` | 128 |
| SHAKE256 | 136 | 64 | variable (max 136) | `0x1f` | 256 |

Rate + Capacity = 200 bytes (1600 bits) for all variants. The capacity determines
the security level: collision resistance is `capacity/2` bits, preimage resistance
is `min(output_bits, capacity)` bits (FIPS 202 SS A.1).

---

## Error Conditions

The WASM module itself does not throw exceptions. Constraints are enforced by the
TypeScript wrapper, but callers working directly with the WASM exports must observe:

- **Input length per call:** `keccakAbsorb(len)` reads `len` bytes from
  `INPUT_OFFSET`. If `len > 168`, the read will exceed the input buffer and access
  adjacent memory (the output buffer). The TypeScript wrapper must chunk input into
  168-byte segments.

- **Output length:** `keccakFinal(outLen)` copies `outLen` bytes from state to
  `OUT_OFFSET`. If `outLen` exceeds the rate, the squeeze reads past the rate-portion of the state into the capacity. Those bytes are not meaningful output and the result will be incorrect. For SHA-3 variants, the typed final
  functions (`sha3_256Final`, etc.) enforce correct output lengths. For SHAKE,
  ensure `outLen <= rate`.

- **Init before absorb:** Calling `keccakAbsorb` without a prior init will operate
  on stale or zeroed state with rate=0, causing a tight infinite loop (the absorb
  loop condition `absorbed === rate` is immediately true when rate=0, triggering
  permutations on every byte). Always call an init function first.

- **Single squeeze:** The squeeze phase copies bytes from state after one
  permutation. There is no multi-block squeeze loop. Requesting more than one
  block of SHAKE output requires re-architecting the squeeze, which is outside
  v1.0 scope.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [sha3](./sha3.md) — TypeScript wrapper classes (SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256)
> - [asm_sha2](./asm_sha2.md) — alternative hash family (SHA-2/HMAC WASM module)
> - [sha3_audit.md](./sha3_audit.md) — SHA-3 / Keccak implementation audit
