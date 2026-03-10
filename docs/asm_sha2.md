# asm_sha2.md

> [!NOTE]
> SHA-2 family WASM module (AssemblyScript -> `sha2.wasm`)

## Overview

The `sha2` WASM module implements the SHA-2 hash family and its HMAC
constructions entirely in AssemblyScript, compiled to WebAssembly. All
cryptographic computation runs in WASM linear memory with static buffer
allocation -- no heap, no `memory.grow()`.

Primitives provided:

| Algorithm    | Standard       | Digest Size | Block Size |
|-------------|----------------|-------------|------------|
| SHA-256     | FIPS 180-4 S6.2 | 32 bytes   | 64 bytes   |
| SHA-512     | FIPS 180-4 S6.4 | 64 bytes   | 128 bytes  |
| SHA-384     | FIPS 180-4 S6.5 | 48 bytes   | 128 bytes  |
| HMAC-SHA256 | RFC 2104       | 32 bytes    | 64 bytes   |
| HMAC-SHA512 | RFC 2104       | 64 bytes    | 128 bytes  |
| HMAC-SHA384 | RFC 2104       | 48 bytes    | 128 bytes  |

SHA-384 is SHA-512 with different initial hash values and a truncated
output. It shares all SHA-512 buffers and compression logic -- no
separate implementation exists.

Every primitive supports a streaming API: `init` / `update` / `final`.
The caller writes input bytes to the module's input staging buffer,
calls `update` with the byte count, and repeats until all data has been
fed. Calling `final` applies Merkle-Damgard padding and writes the
digest to the output buffer.

---

## Security Notes

**Collision resistance.** SHA-256 provides 128-bit collision resistance
and 256-bit preimage resistance. SHA-512 provides 256-bit collision
resistance and 512-bit preimage resistance. SHA-384, as a truncation of
SHA-512, provides 192-bit collision resistance.

**Length extension.** SHA-256 and SHA-512 use the Merkle-Damgard
construction and are vulnerable to length extension attacks: given
`H(m)` and `len(m)`, an attacker can compute `H(m || padding || m')`
without knowing `m`. HMAC is not vulnerable to length extension -- the
outer hash step prevents it. If you need to authenticate data, use HMAC,
not a bare hash.

**HMAC key secrecy.** HMAC provides message authentication only if the
key is secret. A leaked HMAC key allows forgery of arbitrary tags. The
key must be at least as long as the hash output (32 bytes for
HMAC-SHA256, 64 bytes for HMAC-SHA512, 48 bytes for HMAC-SHA384) for
full security. Shorter keys reduce the effective security bound.

**Memory hygiene.** `wipeBuffers()` zeroes the entire SHA-2 module
memory region (offsets 0 through 1975), clearing all hash state, HMAC
ipad/opad key material, inner hash intermediates, message schedule
arrays, and digest outputs. The TypeScript wrapper must call
`wipeBuffers()` in its `dispose()` method. Key material and intermediate
state must not persist in WASM memory after an operation completes.

**Constant-time considerations.** The SHA-2 compression function is
data-independent (no branches on message content, no secret-dependent
table lookups). HMAC tag verification in the TypeScript layer must use
constant-time comparison (XOR-accumulate, no early return) to prevent
timing side channels.

---

## API Reference

All exported functions are listed below, grouped by primitive. Every
function operates on fixed offsets in WASM linear memory. The caller
communicates with the module by writing bytes to input buffers and
reading results from output buffers.

### SHA-256

```
sha256Init(): void
```

Initialize SHA-256 state. Loads the eight initial hash values H0..H7
(FIPS 180-4 S5.3.3) into `SHA256_H_OFFSET` and zeroes the partial block
length and total byte counter. Must be called before `sha256Update`.

```
sha256Update(len: i32): void
```

Hash `len` bytes from `SHA256_INPUT_OFFSET` into the running SHA-256
state. `len` must be <= 64 (the size of the input staging buffer). The
caller must write the input bytes to `SHA256_INPUT_OFFSET` before
calling. For messages longer than 64 bytes, loop: write a chunk, call
`sha256Update`, repeat. Internally, bytes accumulate in the 64-byte
block buffer; when a full block is ready, the compression function runs.

```
sha256Final(): void
```

Apply FIPS 180-4 S5.1.1 padding (append `0x80`, zero-pad, append 64-bit
big-endian bit length), compress the final block(s), and write the
32-byte digest to `SHA256_OUT_OFFSET`. If the padding does not fit in
the current block (partial length > 55 after appending `0x80`), an
additional block is compressed.

```
sha256Hash(len: i32): void
```

Convenience function: `sha256Init()` + `sha256Update(len)` +
`sha256Final()` in a single call. Only usable for messages that fit in
the 64-byte input staging buffer (`len` <= 64). Caller writes input to
`SHA256_INPUT_OFFSET`, calls `sha256Hash(len)`, reads the digest from
`SHA256_OUT_OFFSET`.

### SHA-512

```
sha512Init(): void
```

Initialize SHA-512 state. Loads the eight 64-bit initial hash values
(FIPS 180-4 S5.3.5) into `SHA512_H_OFFSET` and zeroes the partial block
length and total byte counter.

```
sha384Init(): void
```

Initialize SHA-384 state. Loads the SHA-384 initial hash values (FIPS
180-4 S5.3.4) into `SHA512_H_OFFSET`. All SHA-512 buffers and
compression logic are shared -- only the IVs differ. Call
`sha384Final()` (not `sha512Final()`) to get the correct 48-byte output.

```
sha512Update(len: i32): void
```

Hash `len` bytes from `SHA512_INPUT_OFFSET` into the running state.
`len` must be <= 128. Used by both SHA-512 and SHA-384 (they share the
same update function and block buffer).

```
sha512Final(): void
```

Apply FIPS 180-4 S5.1.2 padding (append `0x80`, zero-pad, append
128-bit big-endian bit length), compress the final block(s), and write
the 64-byte digest to `SHA512_OUT_OFFSET`. The padding threshold is
byte 112 (if partial > 112 after `0x80`, an extra block is compressed).

```
sha384Final(): void
```

Calls `sha512Final()` internally. The 48-byte SHA-384 digest is the
first 48 bytes of `SHA512_OUT_OFFSET` (the first 6 of 8 64-bit hash
words). The caller must read only bytes [0..47].

### HMAC-SHA256

HMAC construction per RFC 2104: `HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))`.

```
hmac256Init(keyLen: i32): void
```

Write the key (up to 64 bytes) to `SHA256_INPUT_OFFSET` before calling.
Builds the ipad and opad key blocks at `HMAC256_IPAD_OFFSET` and
`HMAC256_OPAD_OFFSET` by XORing the zero-padded key with `0x36` and
`0x5C` respectively (RFC 2104 S3). Then initializes SHA-256 and
processes the 64-byte ipad block as the first block of the inner hash.
After this call, `SHA256_INPUT_OFFSET` is free for message data.

Keys longer than 64 bytes must be pre-hashed: run the key through
`sha256Init`/`sha256Update`/`sha256Final`, copy the 32-byte digest from
`SHA256_OUT_OFFSET` to `SHA256_INPUT_OFFSET`, then call
`hmac256Init(32)`. The TypeScript wrapper handles this automatically.

```
hmac256Update(len: i32): void
```

Write message bytes (up to 64) to `SHA256_INPUT_OFFSET`, then call.
Passes through directly to `sha256Update(len)` -- the inner hash
accumulates the message data.

```
hmac256Final(): void
```

Finalize the inner hash to get `H((K' XOR ipad) || m)`, save the 32-byte
result to `HMAC256_INNER_OFFSET`, then compute the outer hash:
`sha256Init`, process the 64-byte opad block, process the 32-byte inner
hash, `sha256Final`. The 32-byte HMAC tag is written to
`SHA256_OUT_OFFSET`.

### HMAC-SHA512

Same RFC 2104 construction with 128-byte block size and SHA-512 as the
underlying hash.

```
hmac512Init(keyLen: i32): void
```

Write the key (up to 128 bytes) to `SHA512_INPUT_OFFSET` before calling.
Builds ipad/opad at `HMAC512_IPAD_OFFSET`/`HMAC512_OPAD_OFFSET` (128
bytes each). Initializes SHA-512 and processes the ipad block.

Keys longer than 128 bytes must be pre-hashed with SHA-512 by the
TypeScript wrapper, then passed as a 64-byte key.

```
hmac512Update(len: i32): void
```

Write message bytes (up to 128) to `SHA512_INPUT_OFFSET`, then call.
Passes through to `sha512Update(len)`.

```
hmac512Final(): void
```

Finalize the inner SHA-512 hash, save the 64-byte result to
`HMAC512_INNER_OFFSET`, compute the outer hash with the opad block and
inner hash, and write the 64-byte HMAC tag to `SHA512_OUT_OFFSET`.

### HMAC-SHA384

Same structure as HMAC-SHA512 but uses SHA-384 (different IVs, 48-byte
output). Shares all HMAC-SHA512 buffers.

```
hmac384Init(keyLen: i32): void
```

Write the key (up to 128 bytes) to `SHA512_INPUT_OFFSET` before calling.
Builds identical ipad/opad blocks (128-byte block size is the same as
SHA-512). Calls `sha384Init()` instead of `sha512Init()` to load
SHA-384 IVs before processing the ipad block.

```
hmac384Update(len: i32): void
```

Write message bytes (up to 128) to `SHA512_INPUT_OFFSET`, then call.
Passes through to `sha512Update(len)`.

```
hmac384Final(): void
```

Finalize the inner SHA-384 hash, save the 48-byte result to
`HMAC512_INNER_OFFSET`, compute the outer SHA-384 hash with the opad
block and 48-byte inner hash. The 48-byte HMAC-SHA384 tag is written to
`SHA512_OUT_OFFSET[0..47]`.

### Buffer Offset Getters

These functions return the byte offsets of each buffer region. The
TypeScript layer uses them to know where to read/write data in WASM
linear memory.

```
getSha256HOffset():       i32    // 0
getSha256BlockOffset():   i32    // 32
getSha256WOffset():       i32    // 96
getSha256OutOffset():     i32    // 352
getSha256InputOffset():   i32    // 384
getSha256PartialOffset(): i32    // 448
getSha256TotalOffset():   i32    // 452
getHmac256IpadOffset():   i32    // 460
getHmac256OpadOffset():   i32    // 524
getHmac256InnerOffset():  i32    // 588

getSha512HOffset():       i32    // 620
getSha512BlockOffset():   i32    // 684
getSha512WOffset():       i32    // 812
getSha512OutOffset():     i32    // 1452
getSha512InputOffset():   i32    // 1516
getSha512PartialOffset(): i32    // 1644
getSha512TotalOffset():   i32    // 1648
getHmac512IpadOffset():   i32    // 1656
getHmac512OpadOffset():   i32    // 1784
getHmac512InnerOffset():  i32    // 1912
```

### Module Identity and Utilities

```
getModuleId(): i32
```

Returns `2` -- the numeric identifier for the SHA-2 module.

```
getMemoryPages(): i32
```

Returns the current WASM linear memory size in pages (each page is
64 KiB).

```
wipeBuffers(): void
```

Zeroes all 1976 bytes of the SHA-2 module's buffer region (offsets 0
through 1975). Clears hash state, message schedules, key material,
ipad/opad, inner hashes, and digest outputs. Must be called on dispose.

---

## Buffer Layout

All offsets start at byte 0. The SHA-2 module uses a single contiguous
region of 1976 bytes in WASM linear memory. SHA-384 does not have its
own buffers -- it shares all SHA-512 buffers.

### SHA-256 Region (offsets 0 -- 619)

| Buffer                 | Offset | Size      | Purpose                               |
|------------------------|--------|-----------|---------------------------------------|
| `SHA256_H_OFFSET`      | 0      | 32 bytes  | Hash state H0..H7 (eight u32 words)  |
| `SHA256_BLOCK_OFFSET`  | 32     | 64 bytes  | Block accumulator (partial block)     |
| `SHA256_W_OFFSET`      | 96     | 256 bytes | Message schedule W[0..63] (64 u32s)  |
| `SHA256_OUT_OFFSET`    | 352    | 32 bytes  | Digest output / HMAC output           |
| `SHA256_INPUT_OFFSET`  | 384    | 64 bytes  | Input staging (caller writes here)    |
| `SHA256_PARTIAL_OFFSET`| 448    | 4 bytes   | Partial block byte count (u32)        |
| `SHA256_TOTAL_OFFSET`  | 452    | 8 bytes   | Total bytes hashed (u64)              |
| `HMAC256_IPAD_OFFSET`  | 460    | 64 bytes  | K' XOR 0x36 (ipad key block)         |
| `HMAC256_OPAD_OFFSET`  | 524    | 64 bytes  | K' XOR 0x5C (opad key block)         |
| `HMAC256_INNER_OFFSET` | 588    | 32 bytes  | Inner hash intermediate (hmacFinal)   |

### SHA-512 / SHA-384 Region (offsets 620 -- 1975)

| Buffer                 | Offset | Size      | Purpose                               |
|------------------------|--------|-----------|---------------------------------------|
| `SHA512_H_OFFSET`      | 620    | 64 bytes  | Hash state H0..H7 (eight u64 words)  |
| `SHA512_BLOCK_OFFSET`  | 684    | 128 bytes | Block accumulator (partial block)     |
| `SHA512_W_OFFSET`      | 812    | 640 bytes | Message schedule W[0..79] (80 u64s)  |
| `SHA512_OUT_OFFSET`    | 1452   | 64 bytes  | Digest output / HMAC output           |
| `SHA512_INPUT_OFFSET`  | 1516   | 128 bytes | Input staging (caller writes here)    |
| `SHA512_PARTIAL_OFFSET`| 1644   | 4 bytes   | Partial block byte count (u32)        |
| `SHA512_TOTAL_OFFSET`  | 1648   | 8 bytes   | Total bytes hashed (u64)              |
| `HMAC512_IPAD_OFFSET`  | 1656   | 128 bytes | K' XOR 0x36 (ipad key block)         |
| `HMAC512_OPAD_OFFSET`  | 1784   | 128 bytes | K' XOR 0x5C (opad key block)         |
| `HMAC512_INNER_OFFSET` | 1912   | 64 bytes  | Inner hash intermediate (hmacFinal)   |

**Total: 1976 bytes** (well under 1 page of WASM linear memory).

SHA-384 reuses the SHA-512 buffers entirely. The only differences are
the initial hash values loaded by `sha384Init()` and the fact that
callers read only the first 48 bytes of `SHA512_OUT_OFFSET` after
`sha384Final()`.

---

## Internal Architecture

The module consists of five AssemblyScript source files plus a barrel
re-export. Dependency order:

```
buffers.ts  <--  sha256.ts  <--  hmac.ts
            <--  sha512.ts  <--  hmac512.ts
                     |
                  index.ts  (barrel: re-exports all + wipeBuffers)
```

### buffers.ts

Defines the static linear-memory layout as named `i32` constants.
Exports getter functions for each offset so the TypeScript layer can
query buffer positions at runtime. Also exports `getModuleId()` (returns
`2`) and `getMemoryPages()`.

### sha256.ts -- SHA-256 (FIPS 180-4 S6.2)

Implements the complete SHA-256 algorithm:

- **Round constants** K[0..63] (FIPS 180-4 S4.2.2): 64 `i32` constants
  derived from the cube roots of the first 64 primes. Accessed via an
  inlined `kAt(t)` switch table.
- **Functions** (FIPS 180-4 S4.1.2): `Ch(x,y,z)`, `Maj(x,y,z)`,
  big-sigma `bSig0`/`bSig1` (rotation amounts 2/13/22 and 6/11/25),
  small-sigma `sSig0`/`sSig1` (rotation amounts 7/18/SHR3 and
  17/19/SHR10). All `@inline`.
- **Big-endian helpers**: `load32be` and `store32be` for reading/writing
  32-bit words in network byte order from linear memory.
- **Compression**: `compress(blockOffset)` processes one 512-bit block.
  Expands W[0..15] from the block, extends W[16..63] via sigma
  functions, runs 64 rounds, and adds the working variables back into
  the hash state.
- **Initial hash values** H0..H7 (FIPS 180-4 S5.3.3): derived from the
  square roots of the first 8 primes.
- **Streaming API**: `sha256Init` loads IVs and zeroes counters.
  `sha256Update` accumulates bytes in the block buffer and compresses
  when full. `sha256Final` applies S5.1.1 padding (0x80 + zeros +
  64-bit big-endian bit count) and compresses the final block(s).

### sha512.ts -- SHA-512 and SHA-384 (FIPS 180-4 S6.4, S6.5)

Implements SHA-512 with SHA-384 as a variant:

- **Round constants** K[0..79] (FIPS 180-4 S4.2.3): 80 `i64` constants
  derived from the cube roots of the first 80 primes.
- **Functions** (FIPS 180-4 S4.1.3): same structure as SHA-256 but with
  64-bit operands and different rotation amounts.
  Sigma0(28/34/39), Sigma1(14/18/41), sigma0(1/8/SHR7),
  sigma1(19/61/SHR6). These are NOT the same as SHA-256 rotation
  amounts -- the source includes a warning about this.
- **Big-endian helpers**: `load64be` and `store64be` for 64-bit words.
- **Compression**: `sha512Compress()` processes one 1024-bit (128-byte)
  block. Expands W[0..15], extends W[16..79], runs 80 rounds.
- **Initial hash values**: SHA-512 IVs (S5.3.5) and SHA-384 IVs
  (S5.3.4) are separate constant sets. `loadIVs()` is an internal
  helper that stores any set of 8 i64 values into `SHA512_H_OFFSET`.
- **SHA-384 differences**: `sha384Init()` loads SHA-384 IVs.
  `sha384Final()` calls `sha512Final()` -- the caller reads only the
  first 48 bytes of the 64-byte output. There is no separate SHA-384
  compression or update function.
- **Padding** (FIPS 180-4 S5.1.2): 0x80 byte, zero-padding, 128-bit
  big-endian bit length at the end of the final block. The threshold is
  byte 112 (vs. 56 for SHA-256) due to the 16-byte length field.

### hmac.ts -- HMAC-SHA256 (RFC 2104)

Implements HMAC-SHA256 using the inner/outer hash pattern:

```
HMAC(K, m) = SHA256((K' XOR opad) || SHA256((K' XOR ipad) || m))
```

- `hmac256Init(keyLen)`: reads the key from `SHA256_INPUT_OFFSET`,
  XORs each byte with `0x36` (ipad) and `0x5C` (opad), zero-pads to
  64 bytes, stores the results at `HMAC256_IPAD_OFFSET` and
  `HMAC256_OPAD_OFFSET`. Then calls `sha256Init()` and feeds the
  64-byte ipad block as the first block of the inner hash.
- `hmac256Update(len)`: thin wrapper around `sha256Update(len)`.
- `hmac256Final()`: finalizes the inner hash, saves the 32-byte
  digest to `HMAC256_INNER_OFFSET`, then starts a fresh SHA-256 for
  the outer hash -- feeds the 64-byte opad block, then the 32-byte
  inner digest, then finalizes. Result lands at `SHA256_OUT_OFFSET`.

Keys longer than 64 bytes are not handled in WASM. The TypeScript
wrapper pre-hashes long keys with SHA-256 and passes the 32-byte result.

### hmac512.ts -- HMAC-SHA512 and HMAC-SHA384 (RFC 2104)

Same HMAC construction, scaled up:

- **HMAC-SHA512**: 128-byte block size, SHA-512 inner/outer hash,
  64-byte tag. `hmac512Init`/`hmac512Update`/`hmac512Final`.
- **HMAC-SHA384**: 128-byte block size (same as SHA-512), SHA-384
  inner/outer hash, 48-byte tag. `hmac384Init`/`hmac384Update`/
  `hmac384Final`. Uses `sha384Init()`/`sha384Final()` for both
  inner and outer hash phases.

Both variants share `HMAC512_IPAD_OFFSET`, `HMAC512_OPAD_OFFSET`, and
`HMAC512_INNER_OFFSET`. They cannot be used concurrently.

### index.ts -- Barrel re-export + wipeBuffers

Re-exports all public functions from the four implementation files.
Defines `wipeBuffers()` which zeroes all 1976 bytes of module memory
with `memory.fill(0, 0, 1976)`.

---

## Error Conditions

The WASM module itself does not throw exceptions or return error codes.
All constraints are enforced by convention between the AssemblyScript
implementation and the TypeScript wrapper:

- **Input length overflow**: `sha256Update` requires `len` <= 64;
  `sha512Update` requires `len` <= 128. Exceeding these limits writes
  past the input staging buffer, corrupting adjacent memory regions.
  The TypeScript wrapper must chunk messages to respect these bounds.

- **HMAC key length**: `hmac256Init` requires `keyLen` <= 64;
  `hmac512Init` and `hmac384Init` require `keyLen` <= 128. Keys
  exceeding the block size must be pre-hashed by the TypeScript wrapper
  before calling init. Passing an oversized key directly corrupts the
  ipad/opad buffers.

- **Uninitialized state**: calling `update` or `final` without a prior
  `init` operates on whatever bytes happen to be in the hash state
  buffer, producing garbage. The TypeScript wrapper enforces
  initialization order.

- **SHA-384 / SHA-512 confusion**: calling `sha512Final()` after
  `sha384Init()` produces a 64-byte output where only the first 48
  bytes are meaningful (the SHA-384 digest). The remaining 16 bytes are
  valid SHA-512 state words under SHA-384 IVs but are not part of the
  SHA-384 digest. The TypeScript wrapper must read only 48 bytes.

- **Concurrent use**: SHA-384 and SHA-512 share all buffers. They
  cannot be used concurrently (interleaved init/update/final calls).
  Similarly, HMAC-SHA384 and HMAC-SHA512 share buffers and cannot be
  interleaved. SHA-256 and SHA-512 have independent buffer regions and
  can be used concurrently.

- **Memory not wiped**: if `wipeBuffers()` is not called after an
  operation, key material (HMAC keys in ipad/opad buffers),
  intermediate hash state, and message schedule data persist in WASM
  linear memory until overwritten by a subsequent operation or until the
  WASM instance is garbage collected.

---

## Cross-References

- [README.md](./README.md)
- [architecture.md](./architecture.md)
- [sha2.md](./sha2.md): TypeScript wrapper classes (SHA256, SHA384, SHA512, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384)
- [asm_sha3.md](./asm_sha3.md): Alternative hash family (SHA-3 / SHAKE)
- [asm_serpent.md](./asm_serpent.md): Serpent block cipher (used together with SHA-256 in Fortuna CSPRNG)
