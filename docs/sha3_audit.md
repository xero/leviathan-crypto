# SHA-3 / Keccak Cryptographic Audit

> [!NOTE]
> Cryptographic audit of the SHA-3 / Keccak WASM implementation in `leviathan-crypto` against FIPS 202. Covers algorithm correctness for all six variants and a full security analysis.

**Conducted:** Week of 2026-03-25 | **Target:** `leviathan-crypto` AssemblyScript WASM | **Spec:** FIPS 202 (August 2015) | **Variants:** SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256

> ### Table of Contents
> - [1. Algorithm Correctness](#1-algorithm-correctness)
>   - [1.1 State Layout and Lane Indexing](#11-state-layout-and-lane-indexing)
>   - [1.2 Theta](#12-theta)
>   - [1.3 Rho](#13-rho)
>   - [1.4 Rho+Pi (combined)](#14-rhopi-combined)
>   - [1.5 Chi](#15-chi)
>   - [1.6 Iota](#16-iota)
>   - [1.7 Round Count](#17-round-count)
>   - [1.8 Padding and Domain Separation](#18-padding-and-domain-separation)
>   - [1.9 Rate and Capacity per Variant](#19-rate-and-capacity-per-variant)
>   - [1.10 Buffer Layout and Memory Safety](#110-buffer-layout-and-memory-safety)
>   - [1.11 TypeScript Wrapper Layer](#111-typescript-wrapper-layer)
>   - [1.12 NIST Test Vectors](#112-nist-test-vectors)
> - [2. Security Analysis](#2-security-analysis)
>   - [2.1 Side-Channel Analysis](#21-side-channel-analysis)
>   - [2.2 Known Attacks on SHA-3 / Keccak](#22-known-attacks-on-sha-3--keccak)
>   - [2.3 Usage Context in leviathan-crypto](#23-usage-context-in-leviathan-crypto)

---

> [!NOTE]
> All 24 round constants were independently derived via the LFSR algorithm in
> FIPS 202 §3.2.5 (Algorithm 5). All 25 rho rotation offsets were independently
> derived via the path algorithm in FIPS 202 §3.2.2 (Algorithm 2). All 25
> combined rho+pi lane mappings were verified against the pi formula
> `A'[x][y] = A[(x+3y) mod 5][x]`. NIST test vectors were verified against
> Python `hashlib`. No value was taken from the implementation without
> independent derivation.

---

## 1. Algorithm Correctness

### 1.1 State Layout and Lane Indexing

The Keccak state is represented as 25 `i64` words at `STATE_OFFSET` (200 bytes), stored in WASM linear memory. Lane `A[x][y]` is at byte offset `(x + 5y) * 8`, matching FIPS 202 Appendix B.

The implementation (`keccak.ts:86–110`) loads all 25 lanes into local variables at the start of `keccakF()`, using the naming convention `aXY` where X is the x-coordinate and Y is the y-coordinate:

```
a00 = load<i64>(s +   0)    // A[0][0] at offset 0*8 = 0
a10 = load<i64>(s +   8)    // A[1][0] at offset 1*8 = 8
a20 = load<i64>(s +  16)    // A[2][0] at offset 2*8 = 16
...
a01 = load<i64>(s +  40)    // A[0][1] at offset 5*8 = 40
a11 = load<i64>(s +  48)    // A[1][1] at offset 6*8 = 48
...
a44 = load<i64>(s + 192)    // A[4][4] at offset 24*8 = 192
```

The store-back at lines 221–245 uses the same offsets. All 25 loads and 25 stores are consistent with the `x + 5y` indexing convention. Correct.

**Endianness:** WASM linear memory is little-endian. The `load<i64>` and `store<i64>` instructions natively read/write in little-endian order, which matches the Keccak lane convention (FIPS 202 §B.1: "the first bit of the string corresponds to the least significant bit of the lane"). No byte-swapping is needed. Correct.

---

### 1.2 Theta

(`keccak.ts:114–130`)

**Step 1: Column parity C[x]:**

| Spec | Implementation | Match |
|------|----------------|-------|
| `C[0] = A[0,0] ^ A[0,1] ^ A[0,2] ^ A[0,3] ^ A[0,4]` | `c0 = a00 ^ a01 ^ a02 ^ a03 ^ a04` | Yes |
| `C[1] = A[1,0] ^ A[1,1] ^ A[1,2] ^ A[1,3] ^ A[1,4]` | `c1 = a10 ^ a11 ^ a12 ^ a13 ^ a14` | Yes |
| `C[2] = A[2,0] ^ A[2,1] ^ A[2,2] ^ A[2,3] ^ A[2,4]` | `c2 = a20 ^ a21 ^ a22 ^ a23 ^ a24` | Yes |
| `C[3] = A[3,0] ^ A[3,1] ^ A[3,2] ^ A[3,3] ^ A[3,4]` | `c3 = a30 ^ a31 ^ a32 ^ a33 ^ a34` | Yes |
| `C[4] = A[4,0] ^ A[4,1] ^ A[4,2] ^ A[4,3] ^ A[4,4]` | `c4 = a40 ^ a41 ^ a42 ^ a43 ^ a44` | Yes |

Each C[x] XORs all 5 lanes in column x. Correct.

**Step 2: D[x] = C[(x-1) mod 5] ^ ROT(C[(x+1) mod 5], 1):**

| Spec | Implementation | Match |
|------|----------------|-------|
| `D[0] = C[4] ^ ROT(C[1], 1)` | `d0 = c4 ^ rot64(c1, 1)` | Yes |
| `D[1] = C[0] ^ ROT(C[2], 1)` | `d1 = c0 ^ rot64(c2, 1)` | Yes |
| `D[2] = C[1] ^ ROT(C[3], 1)` | `d2 = c1 ^ rot64(c3, 1)` | Yes |
| `D[3] = C[2] ^ ROT(C[4], 1)` | `d3 = c2 ^ rot64(c4, 1)` | Yes |
| `D[4] = C[3] ^ ROT(C[0], 1)` | `d4 = c3 ^ rot64(c0, 1)` | Yes |

All mod-5 indices verified: `(x-1) mod 5` and `(x+1) mod 5` are correct for all x. The rotation amount is 1 bit, applied via `rot64(v, 1)` = `(v << 1) | (v >>> 63)`. Correct.

**Step 3: XOR D[x] into all lanes of column x:**

Lines 126–130 apply `a_X_Y ^= d_X` for all 25 lanes, grouped by column. Each column receives the correct D value. Correct.

---

### 1.3 Rho

(`keccak.ts:69–75`, applied as part of the combined rho+pi step at lines 133–161)

The rotation offset table (`ROT` array, `keccak.ts:69–75`) stores 25 values indexed by `x + 5y`:

| (x,y) | Spec | Implementation (`ROT[x+5y]`) | Match |
|--------|------|------------------------------|-------|
| (0,0) | 0 | 0 | Yes |
| (1,0) | 1 | 1 | Yes |
| (2,0) | 62 | 62 | Yes |
| (3,0) | 28 | 28 | Yes |
| (4,0) | 27 | 27 | Yes |
| (0,1) | 36 | 36 | Yes |
| (1,1) | 44 | 44 | Yes |
| (2,1) | 6 | 6 | Yes |
| (3,1) | 55 | 55 | Yes |
| (4,1) | 20 | 20 | Yes |
| (0,2) | 3 | 3 | Yes |
| (1,2) | 10 | 10 | Yes |
| (2,2) | 43 | 43 | Yes |
| (3,2) | 25 | 25 | Yes |
| (4,2) | 39 | 39 | Yes |
| (0,3) | 41 | 41 | Yes |
| (1,3) | 45 | 45 | Yes |
| (2,3) | 15 | 15 | Yes |
| (3,3) | 21 | 21 | Yes |
| (4,3) | 8 | 8 | Yes |
| (0,4) | 18 | 18 | Yes |
| (1,4) | 2 | 2 | Yes |
| (2,4) | 61 | 61 | Yes |
| (3,4) | 56 | 56 | Yes |
| (4,4) | 14 | 14 | Yes |

All 25 rotation offsets verified by independent derivation via FIPS 202 §3.2.2 Algorithm 2: starting at `(x,y) = (1,0)`, following the path `(x,y) -> (y, (2x+3y) mod 5)` for 24 steps, with rotation amount `(t+1)(t+2)/2 mod 64`. Lane (0,0) has offset 0 (never rotated). Exact match.

The `rot64()` function (`keccak.ts:78–80`) implements left rotation as `(v << n) | (v >>> (64 - n))`. For the special case of `rot64(a00, 0)` (line 133), this produces `(v << 0) | (v >>> 64)`. In WASM, `i64.shr_u` with shift amount 64 yields 0 (shift amounts are taken mod 64 for `i64`), so `rot64(v, 0) = v | 0 = v`. Correct. Lane (0,0) passes through unrotated.

> [!NOTE]
> The `ROT` static array is declared but not directly indexed in the hot path.
> Instead, the combined rho+pi step uses hardcoded rotation amounts for each
> of the 25 lanes (lines 133–161). The `ROT` array serves as a reference for
> auditing; the actual rotations are compile-time constants in the unrolled code.

---

### 1.4 Rho+Pi (combined)

(`keccak.ts:133–161`, combined with rho)

The pi step permutes lanes according to: `A'[x][y] = A[(x + 3y) mod 5][x]`

In the implementation, rho and pi are **combined** into a single step: each `b[x][y]` is computed as `rot64(a[src_x][src_y], offset)` where `(src_x, src_y)` comes from the pi formula and `offset` is the rho rotation for the source lane.

All 25 combined rho+pi assignments were verified programmatically:

| Output | Source lane (pi) | Rho offset | Implementation | Match |
|--------|-----------------|------------|----------------|-------|
| b[0][0] | a[0][0] | 0 | `rot64(a00, 0)` | Yes |
| b[0][1] | a[3][0] | 28 | `rot64(a30, 28)` | Yes |
| b[0][2] | a[1][0] | 1 | `rot64(a10, 1)` | Yes |
| b[0][3] | a[4][0] | 27 | `rot64(a40, 27)` | Yes |
| b[0][4] | a[2][0] | 62 | `rot64(a20, 62)` | Yes |
| b[1][0] | a[1][1] | 44 | `rot64(a11, 44)` | Yes |
| b[1][1] | a[4][1] | 20 | `rot64(a41, 20)` | Yes |
| b[1][2] | a[2][1] | 6 | `rot64(a21, 6)` | Yes |
| b[1][3] | a[0][1] | 36 | `rot64(a01, 36)` | Yes |
| b[1][4] | a[3][1] | 55 | `rot64(a31, 55)` | Yes |
| b[2][0] | a[2][2] | 43 | `rot64(a22, 43)` | Yes |
| b[2][1] | a[0][2] | 3 | `rot64(a02, 3)` | Yes |
| b[2][2] | a[3][2] | 25 | `rot64(a32, 25)` | Yes |
| b[2][3] | a[1][2] | 10 | `rot64(a12, 10)` | Yes |
| b[2][4] | a[4][2] | 39 | `rot64(a42, 39)` | Yes |
| b[3][0] | a[3][3] | 21 | `rot64(a33, 21)` | Yes |
| b[3][1] | a[1][3] | 45 | `rot64(a13, 45)` | Yes |
| b[3][2] | a[4][3] | 8 | `rot64(a43, 8)` | Yes |
| b[3][3] | a[2][3] | 15 | `rot64(a23, 15)` | Yes |
| b[3][4] | a[0][3] | 41 | `rot64(a03, 41)` | Yes |
| b[4][0] | a[4][4] | 14 | `rot64(a44, 14)` | Yes |
| b[4][1] | a[2][4] | 61 | `rot64(a24, 61)` | Yes |
| b[4][2] | a[0][4] | 18 | `rot64(a04, 18)` | Yes |
| b[4][3] | a[3][4] | 56 | `rot64(a34, 56)` | Yes |
| b[4][4] | a[1][4] | 2 | `rot64(a14, 2)` | Yes |

All 25 source lanes, all 25 rotation offsets, and all 25 destination slots match the composition of rho then pi as specified by FIPS 202.

---

### 1.5 Chi

(`keccak.ts:164–192`)

Chi is the only nonlinear step. FIPS 202 §3.2.4 specifies:

```
A'[x][y] = A[x][y] ^ ((~A[(x+1) mod 5][y]) & A[(x+2) mod 5][y])
```

The implementation applies chi row-by-row using the `b[]` temporary state (output of rho+pi):

```
a00 = b00 ^ (~b10 & b20)    // row y=0: x=0, x+1=1, x+2=2
a10 = b10 ^ (~b20 & b30)    // row y=0: x=1, x+1=2, x+2=3
a20 = b20 ^ (~b30 & b40)    // row y=0: x=2, x+1=3, x+2=4
a30 = b30 ^ (~b40 & b00)    // row y=0: x=3, x+1=4, x+2=0
a40 = b40 ^ (~b00 & b10)    // row y=0: x=4, x+1=0, x+2=1
```

This pattern repeats for all 5 rows (y=0 through y=4). Verified for all 25 lanes.

**Critical correctness points:**

1. **NOT is applied before AND:** `~b[x+1] & b[x+2]`, not `~(b[x+1] & b[x+2])`. Verified in every line.

2. **Temporary state prevents read-after-write hazard:** The `b[]` variables hold the pre-chi state from the rho+pi step. The `a[]` variables are being overwritten, but `b[]` is never modified during chi. This means `b[x+1]` and `b[x+2]` always reflect the pre-chi state, even after `a[x]` has been updated. This is the correct approach, equivalent to computing chi into a temporary and then copying back, but more efficient.

3. **Mod-5 wrapping is correct:** For x=3, the implementation reads `b40` (x+1=4) and `b00` (x+2=0 mod 5). For x=4, it reads `b00` (x+1=0 mod 5) and `b10` (x+2=1 mod 5). Correct.

---

### 1.6 Iota

(`keccak.ts:195–218`)

Iota XORs a round constant `RC[round]` into lane A[0][0] only. The implementation uses an if-else chain keyed on the round index:

```
if (round === 0)       { a00 ^= RC0  }
else if (round === 1)  { a00 ^= RC1  }
...
else                   { a00 ^= RC23 }
```

Only `a00` (lane A[0][0]) is modified. Correct per FIPS 202 §3.2.5.

All 24 round constants were independently verified by implementing the LFSR algorithm from FIPS 202 §3.2.5 (Algorithm 5):

| Round | FIPS 202 (LFSR-derived) | Implementation | Match |
|-------|------------------------|----------------|-------|
| 0 | `0x0000000000000001` | `0x0000000000000001` | Yes |
| 1 | `0x0000000000008082` | `0x0000000000008082` | Yes |
| 2 | `0x800000000000808a` | `0x800000000000808a` | Yes |
| 3 | `0x8000000080008000` | `0x8000000080008000` | Yes |
| 4 | `0x000000000000808b` | `0x000000000000808b` | Yes |
| 5 | `0x0000000080000001` | `0x0000000080000001` | Yes |
| 6 | `0x8000000080008081` | `0x8000000080008081` | Yes |
| 7 | `0x8000000000008009` | `0x8000000000008009` | Yes |
| 8 | `0x000000000000008a` | `0x000000000000008a` | Yes |
| 9 | `0x0000000000000088` | `0x0000000000000088` | Yes |
| 10 | `0x0000000080008009` | `0x0000000080008009` | Yes |
| 11 | `0x000000008000000a` | `0x000000008000000a` | Yes |
| 12 | `0x000000008000808b` | `0x000000008000808b` | Yes |
| 13 | `0x800000000000008b` | `0x800000000000008b` | Yes |
| 14 | `0x8000000000008089` | `0x8000000000008089` | Yes |
| 15 | `0x8000000000008003` | `0x8000000000008003` | Yes |
| 16 | `0x8000000000008002` | `0x8000000000008002` | Yes |
| 17 | `0x8000000000000080` | `0x8000000000000080` | Yes |
| 18 | `0x000000000000800a` | `0x000000000000800a` | Yes |
| 19 | `0x800000008000000a` | `0x800000008000000a` | Yes |
| 20 | `0x8000000080008081` | `0x8000000080008081` | Yes |
| 21 | `0x8000000000008080` | `0x8000000000008080` | Yes |
| 22 | `0x0000000080000001` | `0x0000000080000001` | Yes |
| 23 | `0x8000000080008008` | `0x8000000080008008` | Yes |

All 24 round constants match exactly.

---

### 1.7 Round Count

The permutation loop (`keccak.ts:112`):

```typescript
for (let round = 0; round < 24; round++) {
```

Exactly 24 rounds, 0-indexed (round 0 through round 23). This matches FIPS 202: for Keccak-f[1600] (b=1600), the number of rounds is `nr = 12 + 2 * log2(b/25) = 12 + 2 * 6 = 24`.

The round index is used directly for the iota RC lookup. The if-else chain starts at `round === 0` and ends with `else { a00 ^= RC23 }` (the default for round 23). The mapping from round index to RC value is 0-indexed and correct.

The round count is hardcoded. There is no parameter, configuration, or conditional logic to reduce it.

---

### 1.8 Padding and Domain Separation

(`keccak.ts:296–317`, `keccakFinal()`)

**Domain separation bytes:**

| Variant | FIPS 202 | Implementation (`keccakInit` calls) | Match |
|---------|----------|-------------------------------------|-------|
| SHA3-224 | 0x06 | `keccakInit(144, 0x06)` | Yes |
| SHA3-256 | 0x06 | `keccakInit(136, 0x06)` | Yes |
| SHA3-384 | 0x06 | `keccakInit(104, 0x06)` | Yes |
| SHA3-512 | 0x06 | `keccakInit( 72, 0x06)` | Yes |
| SHAKE128 | 0x1f | `keccakInit(168, 0x1f)` | Yes |
| SHAKE256 | 0x1f | `keccakInit(136, 0x1f)` | Yes |

SHA-3 variants use `0x06` (bits `0110` = Keccak domain `01` + pad10*1 `1`). SHAKE variants use `0x1f` (bits `11111` = SHAKE domain `1111` + pad10*1 `1`). Both are correct per FIPS 202 §6.1/§6.2.

**Padding (pad10*1):**

`keccakFinal()` (`keccak.ts:296–317`):

1. XOR the domain separation byte at position `absorbed` in the state:
   ```
   store<u8>(dsAddr, load<u8>(dsAddr) ^ dsByte)
   ```
   This XORs (not overwrites) the domain byte into the state at the current absorption position. Correct. The sponge absorbs by XOR.

2. XOR `0x80` into the **last byte of the rate block**:
   ```
   store<u8>(lastAddr, load<u8>(lastAddr) ^ 0x80)
   ```
   where `lastAddr = STATE_OFFSET + rate - 1`. This sets the final bit of pad10*1, marking the end of the padded message. Correct.

3. Apply `keccakF()`. The final permutation.

4. Squeeze `outLen` bytes from the state to `OUT_OFFSET`.

**Edge case: domain byte and 0x80 at the same position:** If `absorbed == rate - 1` (the message fills all but the last byte of a rate block), then `dsAddr == lastAddr`. In this case, both XORs hit the same byte: `state[rate-1] ^= dsByte; state[rate-1] ^= 0x80`, which is equivalent to `state[rate-1] ^= (dsByte ^ 0x80)`. For SHA-3 (`dsByte = 0x06`), this produces `0x06 ^ 0x80 = 0x86`. This is correct per FIPS 202. The pad10*1 rule specifies that if the domain byte and the closing `1` bit fall in the same byte, they are both XORed in.

**Edge case: message length is a multiple of rate:** If the message length is an exact multiple of rate, then `absorbed == 0` after the last full block is absorbed and permuted. The padding XORs `dsByte` at position 0 and `0x80` at position `rate - 1`, filling an entire padding block. This is correct. A full padding block is always applied, even when the message aligns perfectly with the rate boundary.

**SHAKE padding (`shakePad`):** The `shakePad()` function (`keccak.ts:327–341`) is structurally identical to the padding portion of `keccakFinal()`. It XORs the domain byte and 0x80, then applies `keccakF()`. This correctly sets up the state for the squeeze phase.

---

### 1.9 Rate and Capacity per Variant

| Variant | Rate (bytes) | Rate (bits) | Capacity (bits) | Output (bits) | Implementation | Match |
|---------|-------------|-------------|-----------------|---------------|----------------|-------|
| SHA3-224 | 144 | 1152 | 448 | 224 | `keccakInit(144, 0x06)`, `keccakFinal(28)` | Yes |
| SHA3-256 | 136 | 1088 | 512 | 256 | `keccakInit(136, 0x06)`, `keccakFinal(32)` | Yes |
| SHA3-384 | 104 | 832 | 768 | 384 | `keccakInit(104, 0x06)`, `keccakFinal(48)` | Yes |
| SHA3-512 | 72 | 576 | 1024 | 512 | `keccakInit( 72, 0x06)`, `keccakFinal(64)` | Yes |
| SHAKE128 | 168 | 1344 | 256 | variable | `keccakInit(168, 0x1f)` | Yes |
| SHAKE256 | 136 | 1088 | 512 | variable | `keccakInit(136, 0x1f)` | Yes |

All rates satisfy `rate + capacity = 1600 bits`. All fixed-output variants squeeze exactly `output/8` bytes. SHAKE variants support arbitrary output length via the streaming squeeze API.

---

### 1.10 Buffer Layout and Memory Safety

The SHA-3 WASM module uses static buffer allocation in linear memory (`buffers.ts`):

| Offset | Size | Name | Purpose |
|--------|------|------|---------|
| 0 | 200 | STATE | Keccak state (25 x i64, 5x5 lane matrix) |
| 200 | 4 | RATE | Rate in bytes (variant-specific, i32) |
| 204 | 4 | ABSORBED | Bytes absorbed into current block (i32) |
| 208 | 1 | DSBYTE | Domain separation byte (u8) |
| 209 | 168 | INPUT | Input staging (max rate = SHAKE128 at 168) |
| 377 | 168 | OUT | Output buffer (one SHAKE128 squeeze block) |

Total: **545 bytes**. No gaps, no overlaps. All buffers are contiguous and tightly packed.

**State initialization:** `keccakInit()` (`keccak.ts:249–255`) zeros all 200 bytes of state and 168 bytes of INPUT, resets RATE, ABSORBED, and DSBYTE. The state is fully zeroed before each new hash computation.

**No aliasing:** The state (offset 0–199) and output buffer (offset 377–544) are well-separated. The absorption loop XORs input bytes directly into the state at `STATE_OFFSET + absorbed + i`, which always falls within [0, 199] since `absorbed < rate <= 168 < 200`. No out-of-bounds access is possible.

**Off-by-one check in absorption:** The loop guard `absorbed === rate` triggers a permutation when exactly `rate` bytes have been absorbed. The rate is at most 168 (SHAKE128), and the state is 200 bytes, so the XOR target `STATE_OFFSET + absorbed + i` is always within bounds. After permutation, `absorbed` resets to 0. Correct.

**`wipeBuffers()`** (`keccak.ts:354–361`): Zeros all buffers individually. State (200 bytes), input (168 bytes), output (168 bytes), and the three metadata fields (RATE, ABSORBED, DSBYTE). This covers all 545 bytes of SHA-3 module memory. Complete and correct.

**Input buffer sizing:** The INPUT buffer is 168 bytes, matching the maximum rate (SHAKE128). The TypeScript `absorb()` function chunks messages into 168-byte segments. For variants with smaller rates (e.g., SHA3-512 at 72 bytes), the WASM `keccakAbsorb()` function processes only `rate` bytes per permutation. The extra input buffer space is harmless and never over-indexed.

---

### 1.11 TypeScript Wrapper Layer

The TypeScript classes in `src/ts/sha3/index.ts` provide the public API.

**init() gate:** Every class constructor calls `getExports()` -> `getInstance('sha3')`, which throws if the `sha3` module has not been loaded via `init(['sha3'])`. No class can be used before initialization. Correct.

**Fixed-output hash classes** (SHA3_224, SHA3_256, SHA3_384, SHA3_512):

Each class follows the same pattern:
1. Call variant-specific init (e.g., `sha3_256Init()`)
2. Absorb message via `absorb(x, msg)`. Chunks into 168-byte segments
3. Call variant-specific final (e.g., `sha3_256Final()`)
4. Return `mem.slice(outOffset, outOffset + digestLen)`

Output lengths:
- SHA3_224: 28 bytes (224 bits). Correct.
- SHA3_256: 32 bytes (256 bits). Correct.
- SHA3_384: 48 bytes (384 bits). Correct.
- SHA3_512: 64 bytes (512 bits). Correct.

**Output is a copy:** All classes use `mem.slice()` (not `mem.subarray()`) to return the digest. The returned `Uint8Array` is independent of WASM memory. Correct.

**dispose():** All classes call `this.x.wipeBuffers()`. Correct.

**SHAKE classes** (SHAKE128, SHAKE256):

The SHAKE classes implement the XOF (extendable output function) API with absorb/squeeze semantics:

- `absorb(msg)`: Feeds input. Throws if called after squeeze (enforced by `_squeezing` flag). Correct.
- `squeeze(n)`: On first call, applies `shakePad()` and sets `_squeezing = true`. Then reads output in rate-sized blocks via `shakeSqueezeBlock()`, buffering one block in `_block` on the TypeScript side. Subsequent calls continue from where the previous squeeze left off. Correct.
- `reset()`: Reinitializes for a new hash. Clears `_squeezing`, `_block`, and `_blockPos`. Correct.
- `hash(msg, outputLength)`: One-shot convenience. Reset, absorb, squeeze. Correct.
- `dispose()`: Zeros both `_block` (TypeScript-side buffer) and WASM buffers. Correct.

The SHAKE128 rate is 168 bytes, SHAKE256 rate is 136 bytes, matching the WASM-side configuration. The TypeScript `_block` buffers match these sizes.

**Multi-squeeze correctness:** After `shakePad()`, each call to `shakeSqueezeBlock()` copies `rate` bytes from the state to `OUT_OFFSET`, then applies `keccakF()` to advance the state for the next block. The TypeScript layer buffers one block and serves sub-block requests from the buffer, calling `shakeSqueezeBlock()` only when the buffer is exhausted. This produces a contiguous, correct XOF stream. The boundary case where `squeeze(n)` requests exactly `rate` bytes exhausts the buffer at the last byte, setting `_blockPos === rate`, which triggers a `shakeSqueezeBlock()` call at the start of the next `squeeze()` invocation. Correct continuation behavior.

---

### 1.12 NIST Test Vectors

All variants verified against NIST FIPS 202 known-answer test vectors
and Python `hashlib`:

| Variant | Input | Expected digest (hex) | Pass |
|---------|-------|-----------------------|------|
| SHA3-224 | `""` | `6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7` | Yes |
| SHA3-224 | `"abc"` | `e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf` | Yes |
| SHA3-256 | `""` | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` | Yes |
| SHA3-256 | `"abc"` | `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532` | Yes |
| SHA3-384 | `"abc"` | `ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25` | Yes |
| SHA3-512 | `"abc"` | `b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e393405d6ce1c5f8571a5c4ef7aad62603c2a` | Yes |
| SHAKE128 | `""`, 32 bytes out | `7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26` | Yes |
| SHAKE256 | `""`, 32 bytes out | `46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f` | Yes |

---

## 2. Security Analysis

### 2.1 Side-Channel Analysis

| Component | Implementation | Constant-Time? |
|-----------|---------------|----------------|
| Theta (XOR) | `i64.xor` only | Yes |
| Rho (rotation) | `i64.shl` + `i64.shr_u` + `i64.or` | Yes |
| Pi (permutation) | Register assignment, no memory access | Yes |
| Chi (nonlinear) | `i64.xor`, `i64.and`, NOT (`i64.xor` with -1) | Yes |
| Iota (RC XOR) | `i64.xor` + round-dependent if-else | See below |
| Absorb loop | Byte-by-byte XOR, loop count depends on input length | N/A (public) |
| Padding | Branch on `absorbed` (public metadata) | N/A (not secret) |

**Keccak has no table lookups.** Every operation is a fixed sequence of XOR, AND, NOT, and 64-bit rotation, applied unconditionally to all 25 lanes in every round. There are no data-dependent memory accesses that could leak information via cache-timing.

**The chi step is constant-time by construction.** The nonlinear operation `b[x] ^ (~b[x+1] & b[x+2])` uses only bitwise operators, all of which execute in fixed time on all modern architectures. No branch depends on lane values.

**The iota if-else chain** (`keccak.ts:195–218`) branches on the round counter, not on secret data. The round counter is always 0–23, independent of the hash input. While the if-else chain is technically not constant-time with respect to the round number, the round number is not secret. It is a public loop index. This does not constitute a side-channel vulnerability.

**WASM execution model:** As noted in the [SHA-2](./sha2_audit.md#21-side-channel-analysis) and [Serpent](./serpent_audit.md#21-side-channel-analysis) audits, WASM integer operations have fixed-width semantics compiled ahead-of-time. The entire `keccakF()` function operates on 25 local `i64` variables, all loaded from memory at the start, all stored back at the end. During the 24 rounds, no memory access occurs. This is the optimal constant-time pattern. The permutation is a pure register-to-register computation.

> [!NOTE]
> SHA-3/Keccak is inherently more resistant to cache-timing attacks than most
> cipher constructions. It uses no S-box tables, no key-dependent memory
> lookups, and no data-dependent branches. The entire permutation is a fixed
> sequence of bitwise operations on 25 64-bit words.

---

### 2.2 Known Attacks on SHA-3 / Keccak

#### Preimage and Collision Resistance

| Variant | Collision resistance | Preimage resistance | Output (bits) |
|---------|---------------------|---------------------|---------------|
| SHA3-224 | 2^112 | 2^224 | 224 |
| SHA3-256 | 2^128 | 2^256 | 256 |
| SHA3-384 | 2^192 | 2^384 | 384 |
| SHA3-512 | 2^256 | 2^512 | 512 |
| SHAKE128 | min(2^(d/2), 2^128) | min(2^d, 2^128) | d (variable) |
| SHAKE256 | min(2^(d/2), 2^256) | min(2^d, 2^256) | d (variable) |

No practical attacks exist on any full-round (24-round) SHA-3 variant. The best known distinguishing attack on Keccak-f[1600] reaches **8 of 24 rounds** (Dinur, Dunkelman, Shamir, 2012, zero-sum distinguisher at 8 rounds with 2^1579 complexity). This leaves a **16-round security margin** (67% of the permutation untouched).

For preimage attacks, the best result on reduced-round Keccak is significantly fewer rounds, and all require complexity close to or exceeding the generic bound.

#### Length Extension Immunity

SHA-3 (sponge construction) is **inherently immune to length extension attacks**. Given `SHA3-256(m)`, an attacker cannot compute `SHA3-256(m || m')` without knowing `m`. This is because:

1. The capacity portion of the state (512 bits for SHA3-256) is never directly output.
2. The squeeze phase reads only the rate portion, which cannot reconstruct the full internal state.
3. There is no Merkle-Damgard chaining. The sponge construction does not expose intermediate states.

This is a structural advantage of SHA-3 over SHA-2. In leviathan-crypto, SHA-2 requires HMAC to prevent length extension; SHA-3 does not (though HMAC-SHA3 could still be used for keyed authentication).

**Implementation verification:** After `keccakFinal()` squeezes the output, the full internal state remains in WASM memory at `STATE_OFFSET` until `wipeBuffers()` is called. JavaScript can only access the state through the `memory` buffer. `dispose()` zeros it. The TypeScript API does not expose the raw state at any point. Length extension immunity is preserved.

#### Algebraic Attacks on Chi

Chi (`A'[x] = A[x] ^ (~A[x+1] & A[x+2])`) is the only nonlinear step in Keccak. Its algebraic degree is 2 per round. After 24 rounds, the algebraic degree grows to approximately `2^24`, far beyond any practical algebraic attack threshold. The mixing provided by theta, rho, and pi ensures rapid diffusion, preventing algebraic structure from persisting across rounds.

No algebraic attack on full-round Keccak has been demonstrated.

#### Second-Preimage Resistance

For SHA-3, second-preimage resistance equals preimage resistance: 2^256 for SHA3-256, 2^512 for SHA3-512, etc. The sponge construction does not have a length-extension property that could reduce second-preimage resistance below the generic bound (unlike SHA-2, where long messages theoretically have reduced second-preimage resistance due to the Merkle-Damgard structure, though this is not a practical concern for SHA-2 either).

---

### 2.3 Usage Context in leviathan-crypto

A comprehensive codebase search confirmed that SHA-3 is used **only as a standalone hash/XOF**:

| Component | Usage | Notes |
|-----------|-------|-------|
| `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512` | Standalone hash | Not composed into HMAC or HKDF |
| `SHAKE128`, `SHAKE256` | Standalone XOF | Not composed into HMAC or HKDF |

**SHA-3 is not used in HMAC or HKDF.** All keyed hash constructions in leviathan-crypto use SHA-2:
- HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 (based on SHA-2)
- HKDF-SHA256, HKDF-SHA512 (based on HMAC-SHA2)

This is a reasonable design: SHA-3's length extension immunity makes HMAC unnecessary for SHA-3-based MACs (KMAC would be the native keyed mode). Since leviathan already has a complete HMAC-SHA2 stack and SHA-3 is used only for hashing, the design has no gaps.

**No type confusion between SHA-2 and SHA-3.** The classes are distinctly named (`SHA256` vs `SHA3_256`) and require different `init()` modules (`'sha2'` vs `'sha3'`). They share no buffers, no WASM memory, and no internal state. An application cannot accidentally substitute one for the other. The module gate will throw.

**Dual-algorithm defense.** leviathan-crypto provides both SHA-2 and SHA-3, which are structurally independent:
- SHA-2: Merkle-Damgard construction with ARX-based compression
- SHA-3: Sponge construction with Keccak permutation

A cryptanalytic breakthrough against one family does not imply weakness in the other. Applications requiring defense-in-depth can use both.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [sha2_audit](./sha2_audit.md) — SHA-2 companion audit (independent construction)
> - [hmac_audit](./hmac_audit.md) — HMAC uses SHA-2 (not SHA-3)
> - [hkdf_audit](./hkdf_audit.md) — HKDF uses SHA-2 (not SHA-3)
> - [serpent_audit](./serpent_audit.md) — Serpent implementation audit
> - [chacha_audit](./chacha_audit.md) — XChaCha20-Poly1305 implementation audit
