# Serpent-256 Cryptographic Audit

> [!NOTE]
> **Conducted:** Week of 2026-03-09
> **Target:** `leviathan-crypto` WebAssembly implementation (AssemblyScript)
> **Reference implementations:**
> - Serpent AES submission C code ([`floppy1/serpent-reference.c`](https://github.com/xero/leviathan-crypto/blob/floppy1/serpent-reference.c), Frank Stajano)
> - `leviathan` TypeScript implementation (prior audit baseline)
>
> **Spec:** Serpent AES submission, Anderson/Biham/Knudsen 1998

## Table of Contents

- [1. Algorithm Correctness](#1-algorithm-correctness)
  - [1.1 S-Boxes](#11-s-boxes)
  - [1.2 Linear Transform](#12-linear-transform)
  - [1.3 Key Schedule](#13-key-schedule)
  - [1.4 Round Structure](#14-round-structure)
  - [1.5 Byte Ordering](#15-byte-ordering)
  - [1.6 Unrolled Variant](#16-unrolled-variant)
  - [1.7 Block Modes (CTR, CBC)](#17-block-modes-ctr-cbc)
  - [1.8 Buffer Layout and Memory Safety](#18-buffer-layout-and-memory-safety)
  - [1.9 TypeScript Wrapper Layer](#19-typescript-wrapper-layer)
  - [1.10 EC/DC/KC Magic Constants](#110-ecdckc-magic-constants)
- [2. Security Analysis](#2-security-analysis)
  - [2.1 Side-Channel Analysis](#21-side-channel-analysis)
  - [2.2 Cryptanalytic Attack Papers](#22-cryptanalytic-attack-papers)
    - [Paper 1 — Amplified Boomerang Attacks (FSE 2000)](#paper-1--amplified-boomerang-attacks-fse-2000)
    - [Paper 2 — Chosen-Plaintext Linear Attacks (IET 2013)](#paper-2--chosen-plaintext-linear-attacks-iet-2013)
    - [Paper 3 — Differential-Linear Attack on 12-Round Serpent (FSE 2008)](#paper-3--differential-linear-attack-on-12-round-serpent-fse-2008)
    - [Paper 4 — Linear Cryptanalysis of Reduced Round Serpent (FSE 2001)](#paper-4--linear-cryptanalysis-of-reduced-round-serpent-fse-2001)
    - [Paper 5 — The Rectangle Attack (EUROCRYPT 2001)](#paper-5--the-rectangle-attack-eurocrypt-2001)
    - [Consolidated Verdict Table](#consolidated-verdict-table)
    - [Final Assessment](#final-assessment)
  - [2.3 Biclique Cryptanalysis (Full 32-Round)](#23-biclique-cryptanalysis-full-32-round)
  - [2.4 SerpentStream: Encrypt-then-MAC and the Cryptographic Doom Principle](#24-serpentstream-encrypt-then-mac-and-the-cryptographic-doom-principle)
    - [Background](#background)
    - [Tool Validation and Formula Corrections](#tool-validation-and-formula-corrections)
    - [Optimization Search Results](#optimization-search-results)
    - [Key Index Pair Search — Structural Constraints](#key-index-pair-search--structural-constraints)
    - [Best Known Result](#best-known-result)
    - [Structural Conclusions](#structural-conclusions)
    - [Assessment](#assessment)

---

> [!NOTE]
> A complete mirror of the AES submission floppy1 package is preserved on the
> [`floppy1`](https://github.com/xero/leviathan-crypto/tree/floppy1) branch,
> including the original test vectors, reference implementation, and S-box
> tables. Also included is the `ctr_harness` we developed for CTR mode vector
> generation, a self-generated tool with no external authority.

---

## 1. Algorithm Correctness

### 1.1 S-Boxes

leviathan-crypto implements all 8 forward S-boxes (`sb0`–`sb7`) and 8 inverse S-boxes (`si0`–`si7`) as Boolean logic circuits in AssemblyScript (`src/asm/serpent/serpent.ts:86–233`). Each function operates on 5 working register slots via `rget`/`rset` helpers that read/write fixed offsets in WASM linear memory. The operations are exclusively `&`, `|`, `^`, and `~` — no table lookups, no data-dependent branches.

The Boolean expansions are equivalent to the 4-bit to 4-bit lookup tables in the reference C implementation (`serpent-reference.c`, `SBox[8][16]` and `SBoxInverse[8][16]`). The reference S-box tables are:

```
S0: { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 }
S1: {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 }
S2: { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 }
S3: { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 }
S4: { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 }
S5: {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 }
S6: { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 }
S7: { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 }
```

Correctness is established by the full test-vector suite: KAT, S-box entry tests (ecb_tbl), NESSIE vectors, and Monte Carlo tests all pass.

---

### 1.2 Linear Transform

The `lk` function (`serpent.ts:272–294`) implements the forward linear transform (LT) combined with the next round's key XOR. The 10-step bitslice LT matches the spec exactly:

| Step | Spec | leviathan-crypto (`lk`) |
|------|------|------------------------|
| 1 | X₀ = X₀ <<< 13 | `rset(a, rotl<i32>(rget(a), 13))` |
| 2 | X₂ = X₂ <<< 3 | `rset(c, rotl<i32>(rget(c), 3))` |
| 3 | X₁ = X₁ ^ X₀ ^ X₂ | `rset(b, rget(b) ^ rget(a))` ... `rset(b, rget(b) ^ rget(c))` |
| 4 | X₃ = X₃ ^ X₂ ^ (X₀ << 3) | `rset(e, rget(a) << 3)` ... `rset(d, rget(d) ^ rget(c))` ... `rset(d, rget(d) ^ rget(e))` |
| 5 | X₁ = X₁ <<< 1 | `rset(b, rotl<i32>(rget(b), 1))` |
| 6 | X₃ = X₃ <<< 7 | `rset(d, rotl<i32>(rget(d), 7))` |
| 7 | X₀ = X₀ ^ X₁ ^ X₃ | `rset(a, rget(a) ^ rget(b))` ... `rset(a, rget(a) ^ rget(d))` |
| 8 | X₂ = X₂ ^ X₃ ^ (X₁ << 7) | `rset(e, rget(e) << 7)` ... `rset(c, rget(c) ^ rget(d))` ... `rset(c, rget(c) ^ rget(e))` |
| 9 | X₀ = X₀ <<< 5 | `rset(a, rotl<i32>(rget(a), 5))` |
| 10 | X₂ = X₂ <<< 22 | `rset(c, rotl<i32>(rget(c), 22))` |

All rotation amounts match the spec: 13, 3, 1, 7, 5, 22 for the forward transform.

The `kl` function (`serpent.ts:297–319`) implements the inverse linear transform with correct inverse rotations:

| Forward | Inverse | Verify: (fwd + inv) mod 32 |
|---------|---------|---------------------------|
| ROTL(13) | ROTL(19) | 13 + 19 = 32 |
| ROTL(3) | ROTL(29) | 3 + 29 = 32 |
| ROTL(1) | ROTL(31) | 1 + 31 = 32 |
| ROTL(7) | ROTL(25) | 7 + 25 = 32 |
| ROTL(5) | ROTL(27) | 5 + 27 = 32 |
| ROTL(22) | ROTL(10) | 22 + 10 = 32 |

> [!NOTE]
> In the WASM implementation, `rotl<i32>` is an AssemblyScript built-in that compiles to the WASM `i32.rotl` instruction — a single CPU instruction on all modern architectures. The TypeScript version required a manual `rotW` function with masking (`& this.wMax`) to preserve 32-bit arithmetic in JavaScript; the WASM version does not need this because `i32` is natively 32-bit.

### 1.3 Key Schedule

`loadKey` (`serpent.ts:350–408`) implements the full Serpent key schedule:

**Key loading and padding** (lines 351–372):
1. Validates key length (16, 24, or 32 bytes) — returns -1 on invalid length.
2. Zeros the 132-word subkey buffer.
3. Sets the padding bit: `store<i32>(SUBKEY_OFFSET + keyLen * 4, 1)` — this places a `1` at word position `keyLen`, matching the reference C `shortToLongKey()` which sets `key[bitsInShortKey/BITS_PER_WORD] |= 1`.
4. Reverse-copies key bytes: `key[k] = input[keyLen - k - 1]` — this is the AES submission byte ordering convention (see [1.5 Byte Ordering](#15-byte-ordering)).
5. Repacks 8 groups of 4 byte-valued words into 8 little-endian uint32 words.

**Prekey expansion** (lines 383–392):
```
w[i] = (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9E3779B9 ^ i) <<< 11
```

The implementation uses a sliding-window approach with 5 working registers `r[0..4]` and a `keyIt` helper that reads from `SUBKEY_OFFSET + a*4` and XORs with `rget(b)`, `rget(c)`, `rget(d)`, `0x9e3779b9`, and `i`, then applies `rotl<i32>(..., 11)`. The iteration pattern — two keyIt calls per loop iteration before the break check, then three more — produces the same 132-word sequence as the reference C `makeSubkeysBitslice()` function.

Reference C (`serpent-reference.c`, `makeSubkeysBitslice`):
```c
w[i] = rotateLeft(w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i, 11)
```

The golden ratio constant `φ = 0x9E3779B9` matches in both implementations.

**Subkey derivation** (lines 395–405):

Round keys are derived by applying bitslice S-boxes to groups of 4 prekey words. The S-box selection follows `S_{(3-n) mod 8}` per the spec:
- K₃₂ uses S₃, K₃₁ uses S₄, K₃₀ uses S₅, ..., cycling through all 8 S-boxes.

The implementation iterates from `ri=128` down to `ri=0` (K₃₂ down to K₀), using `kc(n)` to encode the register slot permutations and `rj` starting at 3 to select the S-box (`rj % 8`).

Reference C applies S-boxes via nibble extraction and scatter: for each of the 32 nibble positions across 4 words, extract the nibble, apply `S[whichS]`, and scatter back. The WASM bitslice approach applies the same S-box to all 32 bits simultaneously via Boolean circuits — mathematically equivalent, confirmed by test vectors.

---

### 1.4 Round Structure

**Encryption** (`serpent.ts:414–450`):

```
Load PT (byte-reverse) → K(0) XOR → 32 rounds → K(32) XOR → Store CT (byte-reverse)
```

Round structure for `n = 0..31`:
- Rounds 0–30: `S[n % 8]` → `LK` (linear transform + K(n+1) XOR)
- Round 31: `S[31 % 8] = S[7]` → `K(32)` XOR (no linear transform)

This matches the spec exactly. The reference C `encryptGivenKHat()`:
- Rounds 0–30: XOR K̂ᵢ, Ŝ(i), LT
- Round 31: XOR K̂₃₁, Ŝ(31), XOR K̂₃₂ (no LT)

**Decryption** (`serpent.ts:456–490`):

```
Load CT (byte-reverse) → K(32) XOR → 32 inverse rounds → K(0) XOR → Store PT (byte-reverse)
```

Inverse round structure for `n = 0..31`:
- Round 0 (first decryption round): `SI[7]` → `KL` (inverse LT + K(31) XOR)
- Rounds 1–30: `SI[7 - n%8]` → `KL` (inverse LT + K(32-n) XOR)
- Round 31 (last decryption round): `SI[0]` → `K(0)` XOR (no inverse LT)

The inverse S-box selection `SI[7 - n%8]` correctly reverses the forward order: SI7, SI6, SI5, SI4, SI3, SI2, SI1, SI0, SI7, SI6, ...

The final K(0) XOR in decryption uses slots `(2, 3, 1, 4)` — not the default `(0, 1, 2, 3)` — because the last inverse S-box (SI0) leaves its output in a non-standard register arrangement. The plaintext is stored from registers `r[4, 1, 3, 2]`. This is the correct slot permutation for the decrypt path, as determined by the DC constant encoding.

---

### 1.5 Byte Ordering

leviathan-crypto uses the **original Serpent AES submission byte ordering**:

**Input loading** (encrypt, `serpent.ts:418–422`):
```
r[0] = bytes[15..12] as LE uint32  (MSW of reversed block)
r[1] = bytes[11..8]  as LE uint32
r[2] = bytes[7..4]   as LE uint32
r[3] = bytes[3..0]   as LE uint32  (LSW of reversed block)
```

**Output storing** (encrypt, `serpent.ts:441–449`):
```
ct[0..3]   = r[3] as BE bytes
ct[4..7]   = r[2] as BE bytes
ct[8..11]  = r[1] as BE bytes
ct[12..15] = r[0] as BE bytes
```

This is **not** the NESSIE convention. NESSIE test vectors require word-reversal and byte-swap preprocessing before comparison, which the NESSIE test harness handles. The AES submission vectors (`floppy4/`) work directly with this convention.

**Key loading** (`serpent.ts:361–362`):
```
key[k] = input_byte[keyLen - k - 1]
```

Key bytes are reversed before packing as LE uint32 words. This matches the reference C `makeUserKeyFromKeyMaterial()` function, which processes hex digits in the same reversed order.

---

### 1.6 Unrolled Variant

`serpent_unrolled.ts` is auto-generated (`bun bench/generate_unrolled.ts`) and contains fully unrolled versions of `encryptBlock` and `decryptBlock`. All 32 rounds are expanded with hardcoded slot indices (the EC/DC constant values pre-resolved at generation time).

The unrolled variant:
- Imports `sb0`–`sb7`, `si0`–`si7`, `lk`, `kl`, `keyXor` from `serpent.ts` — same functions, not copies.
- Uses identical byte-reversal load/store logic.
- Round 31 correctly skips the linear transform in both encrypt and decrypt.
- The S-box and slot assignments in each expanded round match the values that the loop-based version would produce via EC/DC lookup.

This is the version called by CTR and CBC modes (`index.ts` re-exports `encryptBlock_unrolled` as `encryptBlock`). The design intent is to enable V8 TurboFan alias analysis to promote working registers from WASM linear memory to CPU registers, since all slot indices are compile-time constants.

---

### 1.7 Block Modes (CTR, CBC)

**CTR mode** (`ctr.ts`):

- Counter format: 128-bit little-endian, byte 0 is LSB.
- `resetCounter()`: copies NONCE buffer to COUNTER buffer (nonce = initial counter value).
- `incrementCounter()`: LE byte-by-byte increment with carry propagation. Early-exit on no carry — this is a minor timing leak (see [2.1](#21-side-channel-analysis)).
- `processBlock()`: copies counter to BLOCK_PT, encrypts, XORs keystream with plaintext. Supports partial final blocks (1–16 bytes).
- `setCounter(lo, hi)`: absolute 128-bit counter positioning for worker pool parallelism.

**CBC mode** (`cbc.ts`):

- `cbcEncryptChunk()`: C[i] = Encrypt(P[i] XOR C[i-1]), C[-1] = IV. Requires `len` to be a positive multiple of 16.
- `cbcDecryptChunk()`: P[i] = Decrypt(C[i]) XOR C[i-1]. Reads from CHUNK_CT (original ciphertext is preserved — decryptBlock writes to BLOCK_PT, not CHUNK_CT).
- Chaining block (CBC_IV_OFFSET) is updated in-place after each chunk.
- PKCS7 padding is handled in the TypeScript wrapper, not in WASM.

Both modes delegate to `encryptBlock_unrolled` / `decryptBlock_unrolled`.

---

### 1.8 Buffer Layout and Memory Safety

The Serpent WASM module uses static buffer allocation in linear memory (`buffers.ts`):

| Offset | Size | Name | Purpose |
|--------|------|------|---------|
| 0 | 32 | KEY_BUFFER | Raw key bytes (padded to 32) |
| 32 | 16 | BLOCK_PT_BUFFER | Single-block plaintext |
| 48 | 16 | BLOCK_CT_BUFFER | Single-block ciphertext |
| 64 | 16 | NONCE_BUFFER | CTR nonce |
| 80 | 16 | COUNTER_BUFFER | 128-bit LE counter |
| 96 | 528 | SUBKEY_BUFFER | 33 subkeys × 4 words × 4 bytes |
| 624 | 65,536 | CHUNK_PT_BUFFER | Streaming plaintext |
| 66,160 | 65,536 | CHUNK_CT_BUFFER | Streaming ciphertext |
| 131,696 | 20 | WORK_BUFFER | 5 × i32 working registers |
| 131,716 | 16 | CBC_IV_BUFFER | CBC chaining block |

Total: 131,732 bytes < 196,608 (3 × 64KB pages).

No dynamic allocation (`memory.grow()`) is used. All offsets are compile-time constants. Buffer regions do not overlap. The WORK_BUFFER (5 registers) is placed after the large chunk buffers to avoid any possibility of chunk data overwriting working state.

`wipeBuffers()` (`serpent.ts:495–506`) zeros all buffers: KEY (32B), BLOCK_PT (16B), BLOCK_CT (16B), NONCE (16B), COUNTER (16B), SUBKEY (528B), WORK (20B), CHUNK_PT (64KB), CHUNK_CT (64KB), CBC_IV (16B). This covers all sensitive material including key material and intermediate state.

---

### 1.9 TypeScript Wrapper Layer

The TypeScript classes (`src/ts/serpent/index.ts`) provide the public API:

**`Serpent`**: ECB-level operations. Validates key length (16/24/32), copies key to WASM memory, calls `loadKey()`. `encryptBlock()`/`decryptBlock()` validate 16-byte block size. `dispose()` calls `wipeBuffers()`.

**`SerpentCtr`**: CTR mode streaming. `beginEncrypt(key, nonce)` validates key and 16-byte nonce, loads key and resets counter. `encryptChunk()` validates chunk ≤ CHUNK_SIZE. `decryptChunk()` delegates to `encryptChunk()` (CTR is symmetric). JSDoc carries authentication warning.

**`SerpentCbc`**: CBC mode with PKCS7. `encrypt()` applies `pkcs7Pad()` in TypeScript, processes in 64KB chunks via WASM. `decrypt()` validates ciphertext is a non-zero multiple of 16, processes chunks, then applies `pkcs7Strip()`. JSDoc carries authentication warning.

**PKCS7 validation** (`pkcs7Strip`, lines 145–157): Uses constant-time XOR-accumulate validation — all padding bytes are checked against the expected pad value, and the result is accumulated into a `bad` flag without early return. This prevents timing oracles in CBC padding validation.

The TypeScript layer performs no cryptographic computation. It writes inputs to WASM memory, calls WASM exports, and reads outputs. This is the correct architecture per `ARCHITECTURE.md`.

---

### 1.10 EC/DC/KC Magic Constants

The EC (encrypt), DC (decrypt), and KC (key schedule) constants encode 5-slot register permutations as magic integers. For each round `n`, the constant `m = EC[n]` determines working register assignments via `m%5, m%7, m%11, m%13, m%17`, which must produce all five distinct indices {0,1,2,3,4}.

In the WASM implementation, these are switch statements (`serpent.ts:30–80`) rather than the TypeScript version's `Uint32Array` lookup tables. The values are identical:

```
EC[0] = 44255, EC[1] = 61867, EC[2] = 45034, ...
DC[0] = 44255, DC[1] = 60896, DC[2] = 28835, ...
KC[0] = 7788,  KC[1] = 63716, KC[2] = 84032, ...
```

**These constants cannot be verified by static inspection.** If any constant is wrong, the register shuffle will corrupt data silently without obvious structure. The intermediate-value tests (`ecb_iv.txt`) are specifically designed to catch such errors round by round, and the full test suite confirms correctness empirically.

The unrolled variant (`serpent_unrolled.ts`) pre-resolves all EC/DC values at generation time, expanding the slot indices directly into each round's function call arguments. This eliminates the switch dispatch at runtime and is a pure optimization — the mathematical result is identical.

---

## 2. Security Analysis

### 2.1 Side-Channel Analysis

| Component | Implementation | Constant-Time? |
|-----------|---------------|----------------|
| S-boxes | Boolean logic (AND/OR/XOR/NOT) via WASM `i32` ops | Yes |
| Linear transform | `i32.rotl` + XOR | Yes |
| Key schedule | Fixed operations, no branches on key data | Yes |
| CBC XOR | Byte-by-byte XOR | Yes |
| CTR counter increment | Carry-propagation loop with early exit | No (minor) |
| PKCS7 padding validation | XOR-accumulate, no early return | Yes |

**S-box timing safety:** The bitslice Boolean circuit S-boxes are constant-time by construction. All 8 forward and 8 inverse S-boxes use only `&`, `|`, `^`, `~` on `i32` values in WASM. Every bit is processed unconditionally on every call. No lookup tables, no data-dependent branches, no data-dependent memory access patterns.

**WASM vs JavaScript timing guarantees:** The prior TypeScript audit noted that JavaScript's bitwise operators (`|`, `&`, `^`, `~`) map to CPU integer instructions on modern V8/SpiderMonkey but the JS spec does not guarantee constant-time execution. The WASM implementation substantially improves this situation:

- WASM integer operations (`i32.and`, `i32.or`, `i32.xor`, `i32.rotl`) have well-defined, fixed-width semantics.
- WASM modules are compiled ahead-of-time by the engine's optimizing compiler (V8 Liftoff → TurboFan, SpiderMonkey Cranelift). The JIT's speculative optimizations — type guards, inline caches, deoptimization — do not apply to WASM.
- WASM's `i32` type is always 32-bit; there is no polymorphic integer representation that the engine might specialize differently based on observed values.
- The structured control flow of WASM (no computed gotos, no dynamic dispatch within the S-box circuits) leaves no optimization surface for speculative execution to exploit.

While WASM does not carry a formal constant-time guarantee in its specification (the spec defines semantics, not timing), the practical constant-time properties are significantly stronger than JavaScript. The uniform, branch-free, fixed-width integer operations in the S-box circuits are as close to constant-time as a browser execution environment can provide without native code.

**CTR counter increment** (`ctr.ts:33–40`): The 128-bit LE counter increment uses an early-exit `break` when no carry occurs. This leaks the carry-propagation depth, which correlates with the counter value. The counter value is not secret in CTR mode (it is either derived from a nonce or is itself the nonce incremented by a public block index), so this is a low-severity concern. A fully constant-time increment (always iterating all 16 bytes) would be marginally cleaner but is not a security requirement.

---

### 2.2 Cryptanalytic Attack Papers

Every attack examined across 5 academic papers targets reduced-round Serpent. The minimum security margin across all papers is 20 rounds (32 − 12), and the best attack provides only ~6.6 bits of advantage over brute force on 12 rounds. The leviathan-crypto WASM implementation makes it structurally impossible to invoke fewer than 32 rounds — the round count is hardcoded in both the loop-based (`serpent.ts:430–435`) and unrolled (`serpent_unrolled.ts`) implementations, with no parameter, configuration, or conditional logic to reduce it.

---

#### Paper 1 — Amplified Boomerang Attacks (FSE 2000)

**Authors:** John Kelsey, Tadayoshi Kohno, Bruce Schneier
**Published:** FSE 2000, LNCS 1978, pp. 75-93

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Amplified boomerang distinguisher | 7 | Chosen-plaintext | 2^113 | < brute force | Distinguisher |
| Amplified boomerang key recovery | 8 | Chosen-plaintext | 2^113 | 2^179 | Key recovery (68 subkey bits) |

**Core technique:** The cipher is split into two halves: E₀ (rounds 1–4) and E₁ (rounds 5–7). A 4-round differential with probability 2^{−31} and a 3-round differential with probability 2^{−16} are combined via the amplified boomerang framework. Differences spread rapidly through Serpent's linear transform — the authors state: "differences spread out, so that it is possible to find reasonably good characteristics for three or four rounds at a time, but not for larger numbers of rounds."

**Analysis:** The best result reaches 8 rounds with a **24-round security margin**. The attack exploits algebraic properties of the S-boxes and linear transform that are inherent to the Serpent design — not implementation-specific. The WASM implementation faithfully reproduces these components. The authors explicitly confirm: "this attack does not threaten the full 32-round Serpent."

**Verdict: NOT APPLICABLE — 24-round security margin.**

---

#### Paper 2 — Chosen-Plaintext Linear Attacks (IET 2013)

**Authors:** Jialin Huang, Xuejia Lai
**Published:** IET Information Security, Vol. 7, Iss. 4, pp. 293-299, 2013

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Single linear (all keys) | 10 | Chosen-plaintext | 2^92 | 2^84.68 | Key recovery |
| Single linear (192/256-bit) | 10 | Chosen-plaintext | 2^80 | 2^180.68 | Key recovery |
| Multidimensional linear | 10 | Chosen-plaintext | 2^88 | 2^84.07 | Key recovery |
| Multidimensional linear | 11 | Chosen-plaintext | 2^116 | 2^144 | Key recovery |
| Experimental validation | 5 | Chosen-plaintext | ~2^20 | Trivial | Key recovery (12 bits) |

**Core technique:** By fixing specific S-box inputs in the first round of a linear approximation, inactive S-boxes have correlation exactly ±1 instead of 2^{−1}, boosting the overall approximation correlation. This reduces data complexity by up to 2^22 for single-approximation attacks and dramatically reduces time complexity for multidimensional attacks.

**Analysis:** The best result reaches 11 rounds. The 9-round approximation has correlation 2^{−54}; extending to 32 rounds would push the bias below 2^{−64}, where data requirements exceed the 2^{128} codebook. Full 32-round Serpent retains a **21-round security margin**. The S-boxes (`serpent.ts:86–157`) are the standard Serpent S-boxes — the linear approximation properties exploited are inherent to the truth tables.

**Verdict: NOT APPLICABLE — 21-round security margin.**

---

#### Paper 3 — Differential-Linear Attack on 12-Round Serpent (FSE 2008)

**Authors:** Orr Dunkelman, Sebastiaan Indesteege, Nathan Keller
**Published:** FSE 2008

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Improved differential-linear | 11 | Chosen-plaintext | 2^121.8 | 2^135.7 | Key recovery |
| Inverted differential-linear | 11 | Chosen-ciphertext | 2^113.7 | 2^137.7 | Key recovery |
| **12-round differential-linear** | **12** | **Chosen-plaintext** | **2^123.5** | **2^249.4** | **Key recovery** |
| Improved 10-round (128-bit) | 10 | Chosen-plaintext | 2^97.2 | 2^128 | Key recovery |
| Related-key (modified Serpent) | 32* | Related-key CP | 2^125 | Negligible | Distinguisher |

*\*Targets a non-standard Serpent variant with key schedule constants removed.*

**Core technique:** A 9-round differential-linear approximation combining a 3-round truncated differential (probability 2^{−6}) with a 6-round linear approximation (bias 2^{−27}). The 12-round attack extends by prepending one round with 2^112 subkey guesses.

**The 12-round result is the best classical attack across all papers examined.** At 2^249.4 time complexity vs. 2^256 brute force, it provides only ~6.6 bits of advantage — a purely certificational result. The progression from 11 to 12 rounds required an increase of 2^113.7 in time complexity.

**Related-key attack (Section 5):** Exploits a rotation property requiring removal of the `0x9e3779b9 ^ i` constants from the key schedule. leviathan-crypto's key schedule (`serpent.ts:324–325`) includes these constants via the `keyIt` helper: `rotl<i32>(... ^ 0x9e3779b9 ^ i, 11)`. This attack is entirely inapplicable.

**Analysis:** The 12-round attack covers only 12 of 32 rounds, leaving a **20-round security margin**. The time complexity is within ~6.6 bits of brute force at 12 rounds — extending to 13 rounds would push complexity well beyond 2^256.

**Verdict: NOT APPLICABLE — 20-round security margin.**

---

#### Paper 4 — Linear Cryptanalysis of Reduced Round Serpent (FSE 2001)

**Authors:** Eli Biham, Orr Dunkelman, Nathan Keller
**Published:** FSE 2001, LNCS 2355, pp. 16-27

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| 9-round linear approximation | 9 | Known-plaintext | N/A | N/A | Approximation |
| 10-round key recovery | 10 | Known-plaintext | 2^118 | 2^89 | Key recovery |
| 11-round key recovery (192/256) | 11 | Known-plaintext | 2^118 | 2^187 | Key recovery |

**Core technique:** Systematic search for linear approximations identified a 9-round approximation with bias 2^{−52} (39 active S-boxes) — 4–8x stronger than the bounds claimed by the Serpent designers. The authors note: "there is a huge distance between a 9-round approximation and attacking 32 rounds, or even 16 rounds of Serpent."

**Analysis:** The bias progression shows roughly 5–13 bits of degradation per additional round. A 32-round approximation would have bias far below 2^{−128}, requiring more data than the 2^{128} codebook. Full 32-round Serpent retains a **21-round security margin**. The 11-round attack's memory requirement of 2^{193} bits is astronomically beyond any physical storage.

**Verdict: NOT APPLICABLE — 21-round security margin.**

---

#### Paper 5 — The Rectangle Attack (EUROCRYPT 2001)

**Authors:** Eli Biham, Orr Dunkelman, Nathan Keller
**Published:** EUROCRYPT 2001, LNCS 2045, pp. 340-357

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Differential attack (all keys) | 7 | Chosen-plaintext | 2^84 | 2^85 | Key recovery |
| Differential attack (256-bit) | 8 | Chosen-plaintext | 2^84 | 2^213 | Key recovery |
| Rectangle attack (256-bit) | 10 | Chosen-plaintext | 2^126.8 | 2^207.4 | Key recovery |

**Core technique:** The rectangle attack decomposes the cipher into two halves and counts over all intermediate differences at the boundary, replacing single-characteristic probability with sums of squared differential probabilities. The paper proves the best 3-round differential characteristic has probability 2^{−15} (7 active S-boxes), confirming the S-boxes are well-designed against differential attack.

**Analysis:** The best result covers 10 rounds. The 6-round differential at the core has probability 2^{−93}. Each additional round adds at least 2^{−15} probability degradation. Full 32-round Serpent retains a **22-round security margin**.

**Verdict: NOT APPLICABLE — 22-round security margin.**

---

#### Consolidated Verdict Table

| Paper | Best Attack (Rounds) | Security Margin | Time Complexity | Verdict |
|-------|---------------------|-----------------|-----------------|---------|
| Amplified Boomerang (FSE 2000) | 8 | 24 rounds | 2^179 | NOT APPLICABLE |
| Chosen-Plaintext Linear (IET 2013) | 11 | 21 rounds | 2^144 | NOT APPLICABLE |
| **Differential-Linear (FSE 2008)** | **12** | **20 rounds** | **2^249.4** | **NOT APPLICABLE** |
| Linear Cryptanalysis (FSE 2001) | 11 | 21 rounds | 2^187 | NOT APPLICABLE |
| Rectangle Attack (EUROCRYPT 2001) | 10 | 22 rounds | 2^207.4 | NOT APPLICABLE |

**Minimum security margin across all papers: 20 rounds (62.5% of the cipher untouched)**
**Best classical attack advantage over brute force: ~6.6 bits (differential-linear on 12 rounds)**

---

#### Final Assessment

Every attack in this corpus shares one fundamental limitation: they work only on reduced-round Serpent. The best result — the 12-round differential-linear attack (Dunkelman, Indesteege, Keller, 2008) — achieves a time complexity of 2^249.4, which is barely distinguishable from the 2^256 brute-force bound. Each additional round costs exponentially more: the jump from 11 to 12 rounds alone required a 2^113.7x increase in time complexity. Extending to 13 rounds would push the attack beyond brute force.

The remaining 20 rounds represent an exponential barrier that no known cryptanalytic technique can bridge. The Serpent designers chose 32 rounds specifically to provide this defense-in-depth, roughly doubling the rounds needed for security at the time of design.

**leviathan-crypto's round count is not configurable.** The loop-based implementation (`serpent.ts:430–435`) runs from `n=0` to `n>=31` with no configurable parameter. The unrolled implementation (`serpent_unrolled.ts`) has all 32 rounds expanded at code-generation time. The key schedule generates all 33 subkeys (K₀–K₃₂) unconditionally. Both CTR and CBC modes delegate to the same full 32-round block cipher. There is no API to request reduced-round encryption.

**Residual concern — unauthenticated modes:** Neither CBC nor CTR mode provides integrity or authentication. Chosen-ciphertext attacks (padding oracles, bit-flipping) are a more realistic threat than any reduced-round algebraic attack. The TypeScript wrapper includes JSDoc warnings on both `SerpentCtr` and `SerpentCbc` directing users to pair with HMAC-SHA256 (Encrypt-then-MAC) or use `XChaCha20Poly1305` instead. The PKCS7 padding validation uses constant-time XOR-accumulate comparison, mitigating padding oracle attacks at the validation level.

---

### 2.3 Biclique Cryptanalysis (Full 32-Round)

The following section incorporates independent research conducted against the leviathan Serpent-256 implementation using the BicliqueFinder tool. The full research document is available at [github.com/xero/BicliqueFinder](https://github.com/xero/BicliqueFinder).

#### Background

Biclique cryptanalysis is the only known technique that applies to the full 32-round Serpent-256. Unlike the reduced-round attacks in Section 2.2, biclique attacks cover the entire cipher by exploiting key-related structures. The best published biclique attack on Serpent-256 (Menezes et al. 2020) achieved 2^{255.21} time complexity with 2^{88} data complexity — only ~0.8 bits better than brute-force key search.

A separate biclique construction using generator sets (de Carvalho & Kowada) achieved 2^{255.39} time with 2^{4} data complexity — a different tradeoff with substantially lower data requirements.

#### Tool Validation and Formula Corrections

The BicliqueFinder Java tool was validated against both published papers. Initial comparison revealed a ~1.2-bit shortfall in time complexity, traced to four bugs in the tool's complexity computation:

| Bug | Description |
|-----|-------------|
| 1 | Method dispatch always routed to FUTURE cipher formula, not Serpent |
| 2 | Hardcoded S-box denominator of 160 (FUTURE's total) instead of cipher-specific value |
| 3 | `getNUM_SBOXES_TOTAL()` dimensional error: 4480 instead of correct 2080 |
| 4 | Hardcoded biclique dimension instead of deriving from differential count |

The correct S-box denominator of 2080 was independently derived from two sources: the Serpent specification (32 rounds × 32 nibbles = 1024 state S-boxes + 33 groups × 32 nibbles = 1056 key schedule S-boxes) and the reference C implementation. After patching, both published attacks were reproduced to within ±0.01 bits.

A hand calculation of the dim-4 attack's complexity components verified the published 2^{255.21} result:

| Component | Value |
|-----------|-------|
| C_biclique | 2^{2.00} |
| C_precomp | 2^{3.807} |
| C_recomp | 2^{7.006} |
| C_falsepos | 2^{0.00} |
| **Per-group** | **2^{7.205}** |
| **Total** | **2^{255.205}** (vs. published 2^{255.21} — 0.005-bit agreement) |

C_recomp dominates at 87% of per-group cost.

#### Optimization Search Results

With the corrected tool, systematic search was conducted across three parameter dimensions:

**Variable v position search:** 2,912 candidates (91 states × 32 nibbles) were tested with the generator-set biclique (delta K31 n6, nabla K18 n11, states #91–#96). Every candidate produced an independent biclique (100% independence rate). Late-state positions (states 61–90) consistently outperformed earlier ones due to less diffusion between v and the biclique boundary.

**Multi-nibble v optimization:** At the best single-nibble position (state 66, nibble 8), combining nibbles 8+9 (|v| = 8 bits) eliminated the false-positive term entirely: C_falsepos dropped from 2^{4.00} to 2^{0.00}. Adding nibble 9 increased C_recomp by only +0.04 bits (23 additional S-boxes), because nibbles 8 and 9 occupy the same byte and share most of their diffusion path.

**Joint biclique nibble search:** 16,384 configurations (64 delta × 64 nabla nibbles × 4 v positions) were evaluated. The best result was delta nibble 0 (byte 0, high nibble of K31), nabla nibble 13, v = state 66 nibbles 8+9, yielding 2^{255.20}. Delta nibble 0 activates fewer S-boxes in the recomputation phase due to favorable key schedule propagation.

Phase 2 improvement summary:

| Step | Configuration | Time | Data |
|------|--------------|------|------|
| Paper published | K31/K18, d6/n11, v=s75n31 | 2^{255.39} | 2^{4} |
| Better v position | K31/K18, d6/n11, v=s66n8+9 | 2^{255.21} | 2^{4} |
| Better biclique nibbles | K31/K18, d0/n13, v=s66n8+9 | 2^{255.20} | 2^{4} |

#### Key Index Pair Search — Structural Constraints

The search was broadened to test whether delta key indices other than K31 could yield better results. Three parallel searches tested K29, K30, and K31 delta pairs against all valid nabla pairs, totaling 1,327,104 evaluations in 6.7 hours of compute time.

**Independence rates:**

| Delta Key Index | Independent / Total | Rate |
|----------------|-------------------|------|
| K29 | 14,512 / 106,496 | 13.6% |
| K30 | 85,808 / 110,592 | 77.6% |
| K31 | 89,200 / 114,688 | 77.8% |

K29's dramatically lower rate reflects greater key schedule distance: differences introduced at K29 propagate through 2 extra recurrence steps, creating more S-box conflicts between delta and nabla differentials.

**Data complexity — the single most important finding:**

| Delta Key Index | Min Data | Max Data | % with data = 2^{4} |
|----------------|----------|----------|---------------------|
| K29 | 2^{56} | 2^{80} | 0% |
| K30 | 2^{16} | 2^{40} | 0% |
| K31 | 2^{4} | 2^{4} | 100% |

Data complexity decreases monotonically as the delta key index moves closer to ciphertext: each step closer removes one key schedule propagation step. K31/K32 are the subkeys applied directly in the biclique states — no propagation is needed, and data complexity is at the theoretical minimum. No delta key index other than K31 achieves data complexity within practical reach.

**Nabla pair landscape:** K17/K18 is universally optimal across all three delta indices. The time complexity curve follows a symmetric U-shape centered on K17. The paper's choice of K18 was near-optimal — K17 outperforms it by 8 recomputation S-boxes (a new finding not in the published papers).

#### Best Known Result

| Parameter | Value |
|-----------|-------|
| Delta | K31, nibble 0 (0xf0 mask) |
| Nabla | K17, nibble 10 (0x0f mask) |
| v | state 66, nibbles 8+9 |
| Time | **2^{255.19}** |
| Data | 2^{4} |
| Recomp | 1,041 / 2,080 |

Complete improvement chain:

| Step | Configuration | Time | Improvement |
|------|--------------|------|-------------|
| Paper published | K31/K18, d6/n11, s75n31 | 2^{255.39} | — |
| Better v | K31/K18, d6/n11, s66n8+9 | 2^{255.21} | −0.18 bits |
| Better biclique | K31/K18, d0/n13, s66n8+9 | 2^{255.20} | −0.01 bits |
| Better nabla pair | K31/K17, d0/n10, s66n8+9 | 2^{255.19} | −0.01 bits |
| **Total** | | | **−0.20 bits** |

#### Structural Conclusions

1. **K31 is uniquely necessary — not just optimal.** The data complexity progression from K29 (min 2^{56}) through K30 (min 2^{16}) to K31 (fixed 2^{4}) demonstrates a monotonic structural constraint tied to the biclique construction. Each key schedule step between the delta key index and the biclique states introduces active S-boxes that demand exponentially more chosen plaintexts. The paper's choice of K31 was not arbitrary — it is the only viable option.

2. **K17 outperforms K18 as the nabla pair.** This is a new finding not present in the published papers. K17 produces 8 fewer recomputation S-boxes than K18 at the optimal biclique configuration. The universal optimality of K17/K18 across all three delta indices, with the separation |delta−17| increasing by exactly 1 per index step (12, 13, 14), points to a fixed structural feature of the Serpent key schedule where the recurrence `w[i] = (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ i) <<< 11` produces optimal cancellation properties when the nabla difference enters at K17.

3. **The time-data tradeoff moving away from ciphertext is never favorable.** K29 achieves 2^{255.13} time complexity (better than K31's 2^{255.19} by 0.06 bits) but requires 2^{56} data — a gap that renders the time improvement meaningless. Each step away from ciphertext trades a marginal time improvement for an exponential data complexity increase.

#### Assessment

The best biclique attack on full 32-round Serpent-256 achieves 2^{255.19} time complexity with 2^{4} data complexity. This provides less than 1 bit of advantage over exhaustive key search (2^{256}). The attack is purely certificational — it demonstrates a theoretical distinction from an ideal 256-bit cipher but has zero practical impact on security.

To contextualize the scale: 2^{255.19} operations at 10^{18} operations per second (beyond any current or foreseeable hardware) would require approximately 10^{58} years — roughly 10^{48} times the age of the universe. The biclique attack reduces this by a factor of less than 2, which does not change the conclusion that brute-force key search against Serpent-256 is computationally infeasible.

The leviathan-crypto implementation is not affected by this attack in any way that a code change could address. The biclique structure exploits inherent algebraic properties of the Serpent S-boxes and key schedule — properties that are identical in any correct implementation.

---

### 2.4 SerpentStream: Encrypt-then-MAC and the Cryptographic Doom Principle

The Cryptographic Doom Principle (Duong, 2011): *if you have to perform any cryptographic operation before verifying the MAC on a message you've received, it will somehow inevitably lead to doom.* The canonical counter-examples are the SSL/TLS padding oracle (Vaudenay 2002) and the SSH plaintext recovery attack — both consequences of MAC-then-encrypt designs where decryption must run before the MAC can be checked, giving an attacker a decryption oracle through observable error behavior.

Section 2.2 identified unauthenticated modes as the primary residual concern for raw `SerpentCtr` and `SerpentCbc`. `SerpentStream` addresses this by composing `SerpentCtr` with `HMAC_SHA256` in strict Encrypt-then-MAC order, per chunk.

#### Seal path (encrypt)

```
plaintext → SerpentCtr.encryptChunk(encKey) → ciphertext → HMAC_SHA256(macKey, ciphertext) → ciphertext ‖ tag
```

The HMAC is computed over the ciphertext, not the plaintext. The tag covers exactly what travels on the wire.

#### Open path (decrypt)

```typescript
const ciphertext   = wire.subarray(0, wire.length - 32);
const tag          = wire.subarray(wire.length - 32);
const expectedTag  = hmac.hash(macKey, ciphertext);
if (!constantTimeEqual(tag, expectedTag))
    throw new Error('SerpentStream: authentication failed');
ctr.beginEncrypt(encKey, ZERO_IV);
return ctr.encryptChunk(ciphertext);   // ← only reached after MAC clears
```

`ctr.encryptChunk` is never called before `constantTimeEqual` returns `true`. There is no code path — no early return, no fallthrough, no branch — that produces plaintext from a chunk that has not passed its MAC. This is the doom principle enforced structurally, not by convention.

The `constantTimeEqual` comparison itself (utils.ts: XOR-accumulate over all 32 bytes, no early exit) prevents a timing oracle on the tag. An attacker cannot distinguish a one-byte tag mismatch from a 32-byte mismatch by measuring response latency.

#### Per-chunk key derivation and position binding

Each chunk's `encKey` and `macKey` are derived independently via `HKDF_SHA256`, with an `info` field that encodes the full chunk context:

```
info = DOMAIN (17 bytes) ‖ streamNonce (16 bytes) ‖ chunkSize (4 bytes)
     ‖ chunkCount (8 bytes) ‖ chunkIndex (8 bytes) ‖ isLast (1 byte)
```

This construction means that a chunk's MAC is bound to its position in its stream. A chunk transplanted from a different stream (different `streamNonce`), a different position (different `chunkIndex`), or misrepresented as terminal or non-terminal (different `isLast`) will fail MAC verification before any decryption runs. The SSH plaintext recovery attack works by feeding an arbitrary ciphertext block to a recipient who decrypts the first four bytes and interprets them as a length — an operation taken before MAC verification. SerpentStream has no equivalent: there is no length field inside the encrypted payload, chunk boundaries are determined externally by the caller, and every byte of every chunk is MAC-verified before any of it is decrypted.

#### Comparison with the SSL padding oracle

The SSL/TLS vulnerability arises because the MAC covers the plaintext (MAC-then-encrypt), so the MAC cannot be checked until after decryption and padding removal. An attacker who can elicit different error responses for padding errors versus MAC errors gains a byte-at-a-time decryption oracle. SerpentStream's MAC covers the ciphertext. Padding does not exist — CTR mode requires no padding. The only error condition reachable before decryption is MAC failure, and MAC failure always produces the same `Error('SerpentStream: authentication failed')` with no observable timing difference.

#### Verdict

`SerpentStream` satisfies the Cryptographic Doom Principle by construction. MAC verification is the unconditional gate on the open path; decryption is unreachable until that gate clears. Per-chunk HKDF key derivation with position-bound info extends this guarantee to stream integrity: reordering, truncation, and cross-stream substitution are all detected at the MAC layer before any plaintext is produced.

---

> ## Cross-References
>
> - [README.md](./README.md) — project overview and quick-start guide
> - [architecture.md](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [sha2_audit.md](./sha2_audit.md) — SHA-256 / SHA-512 / SHA-384 implementation audit
> - [sha3_audit.md](./sha3_audit.md) — SHA-3 / Keccak implementation audit
> - [hmac_audit.md](./hmac_audit.md) — HMAC-SHA256 audit (used in SerpentStream)
> - [hkdf_audit.md](./hkdf_audit.md) — HKDF-SHA256 audit (used in SerpentStream)
> - [chacha_audit.md](./chacha_audit.md) — XChaCha20-Poly1305 implementation audit
> - [serpent.md](./serpent.md) — TypeScript API for Serpent-256
> - [asm_serpent.md](./asm_serpent.md) — WASM implementation details
> - [serpent_reference.md](./serpent_reference.md) — algorithm specification and known attacks
