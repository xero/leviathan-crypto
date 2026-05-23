<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### `slhdsa` SLH-DSA WASM Module Reference

This low-level reference details the SLH-DSA AssemblyScript source and WASM
exports, intended for those auditing, contributing to, or building against
the raw module. **Most consumers should instead use the
[TypeScript wrapper](./slhdsa.md).**

> ### Table of Contents
> - [Overview](#overview)
> - [Buffer Layout](#buffer-layout)
> - [Module Identity](#module-identity)
> - [Memory Wiping](#memory-wiping)
> - [Source Files](#source-files)
> - [API Reference](#api-reference)
> - [Constant-time Posture](#constant-time-posture)

---

## Overview

This module implements SLH-DSA (FIPS 205, Stateless Hash-Based Digital
Signature Standard) as a standalone WebAssembly binary compiled from
AssemblyScript. SLH-DSA is the NIST post-quantum signature standard for
the hash-based family; the underlying scheme is SPHINCS+.

The implementation is parameter-set-selected at runtime. A single
`slhdsa.wasm` serves all three SHAKE-family fast variants
(128f/192f/256f); the TypeScript wrapper picks the active set by calling
`slhSetParams128f` / `slhSetParams192f` / `slhSetParams256f` before each
operation, and the WASM reads `(n, m, paramSet)` from the PARAMS slot.

| Parameter Set | n  | h  | d  | h′ | k  | a | m  | NIST Security |
|---------------|----|----|----|----|----|---|----|---------------|
| SLH-DSA-128f  | 16 | 66 | 22 | 3  | 33 | 6 | 34 | Category 1    |
| SLH-DSA-192f  | 24 | 66 | 22 | 3  | 33 | 8 | 42 | Category 3    |
| SLH-DSA-256f  | 32 | 68 | 17 | 4  | 35 | 9 | 49 | Category 5    |

| Parameter Set | pkBytes | skBytes | sigBytes |
|---------------|---------|---------|----------|
| SLH-DSA-128f  | 32      | 64      | 17088    |
| SLH-DSA-192f  | 48      | 96      | 35664    |
| SLH-DSA-256f  | 64      | 128     | 49856    |

Slow variants (128s/192s/256s) and the SHA-2 family from FIPS 205 §11.2
Table 5 are out of scope.

Key properties of this implementation:

**Static memory only.** All buffers are fixed offsets in linear memory.
No `memory.grow()`, no heap allocation. Total memory: 2 pages (128 KiB).

**Scalar only.** SLH-DSA's hot path is SHAKE256 absorb/squeeze plus
fixed 32-byte ADRS encodes. There is no polynomial arithmetic, so no
SIMD-vectorised counterparts ship with this module. The Keccak-f[1600]
permutation is the scalar 24-round reference implementation.

**Embedded Keccak.** The SHAKE128/SHAKE256 sponge state lives in
SCRATCH, not in a cross-linked `sha3.wasm`. Per the module-ownership
rule, each parameter set instantiates its own copy. The sub-layout
mirrors `src/asm/sha3/buffers.ts` so the verbatim port stays readable
side-by-side with the sha3 source.

**Algorithm composition in WASM.** Unlike `mldsa.wasm`, the top-level
FIPS 205 §9 entry points (Algorithms 18/19/20: `slhKeygenInternal`,
`slhSignInternal`, `slhVerifyInternal`) are implemented inside the
module. The TS layer marshals `INPUT` and reads `OUT`; the algorithm
itself, including WOTS+/FORS/XMSS/hypertree composition, runs in WASM.

---

## Buffer Layout

Defined in `src/asm/slhdsa/buffers.ts`. All offsets in bytes from base 0.

```
Offset    Size      Region        Purpose
─────────────────────────────────────────────────────────────────────
0x00000   60 KB     INPUT         sk ‖ M ‖ opt_rand (sign);
                                  pk ‖ M ‖ sig (verify);
                                  SK.seed ‖ SK.prf ‖ PK.seed (keygen)
0x0F000   52 KB     OUT           signature output (49856 max for 256f
                                  plus slack); SK ‖ PK for keygen
0x1C000   4 KB      STATE         ADRS scratch, PARAMS slot, WOTS+/FORS/
                                  XMSS/hypertree working buffers
0x1D000   8 KB      SCRATCH       Embedded Keccak sponge state and stage
                                  buffers
0x1F000   END       124 KB total, fits in 2 WASM pages (128 KB)
```

ACVP messages reach 8 KB; the 256f verify worst case is
`pk (64) + M (8192) + sig (49856) = 58112` bytes, leaving ~2.4 KB of
slack inside INPUT.

### STATE sub-layout

```
Offset (from STATE_OFFSET)    Size    Region
─────────────────────────────────────────────────────────────────────
+0                            32      ADRS canonical scratch
+32                           16      PARAMS slot (n, m, paramSet, reserved)
+64..+3071                    3008    WOTS+ / FORS working buffers
+3072..+3391                  320     XMSS pair-stack buffer
+3392..+3423                  32      HT_ROOT_OFFSET (layer-to-layer XMSS root)
+3424..+3471                  48      SLH_DIGEST_OFFSET (H_msg output, m ≤ 49)
+3472..+3503                  32      SLH_PK_FORS_OFFSET (FORS public key, n ≤ 32)
```

The PARAMS slot is populated by `slhSetParams{128f,192f,256f}`. Layout:

```
+0  i32  n          security parameter, bytes
+4  i32  m          Hmsg output length, bytes
+8  i32  paramSet   0 = 128f, 1 = 192f, 2 = 256f
+12 i32  reserved
```

`h`, `d`, `h′`, `k`, and `a` are not stored; the WOTS+/FORS/XMSS/
hypertree modules each look them up from `paramSet` per FIPS 205 §11.1
Table 2.

### SCRATCH sub-layout (embedded Keccak sponge)

Mirrors `src/asm/sha3/buffers.ts`. Private to `keccak.ts` and
`hashes.ts`; nothing outside this module reads it.

```
Offset (from SCRATCH_OFFSET)  Size    Region
─────────────────────────────────────────────────────────────────────
+0                            200     Keccak-f[1600] lane state (25 × u64)
+200                          4       rate
+204                          4       absorbed (bytes buffered in state)
+208                          4       dsbyte (domain separation: 0x1f for SHAKE)
+209..+255                    47      alignment slack
+256                          168     input staging (sized for SHAKE128 rate)
+424                          168     output staging (one squeeze block)
```

168 + 424 = 592 bytes used inside SCRATCH; the remaining ~7.4 KB is free
for hash-family scratch when WOTS+/FORS/XMSS/hypertree compose.

### I/O layouts per entry point

```
slhKeygenInternal():
  INPUT = SK.seed (n) ‖ SK.prf (n) ‖ PK.seed (n)                (3·n bytes)
  OUT   = SK (4·n) ‖ PK (2·n)                                   (6·n bytes)
  SK    = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root                  (§9.1 Fig 15)
  PK    = PK.seed ‖ PK.root                                     (§9.1 Fig 16)

slhSignInternal(msgLen):
  INPUT = SK (4·n) ‖ M (msgLen) ‖ opt_rand (n)
  OUT   = SIG (sigBytes)
  SIG   = R (n) ‖ SIG_FORS (k·(a+1)·n) ‖ SIG_HT ((h + d·len)·n)

slhVerifyInternal(msgLen):
  INPUT = PK (2·n) ‖ M (msgLen) ‖ SIG (sigBytes)
  return 1 if verify ok, else 0
```

`opt_rand` is whatever the caller wrote: random `n` bytes for hedged
signing, PK.seed for the deterministic variant (FIPS 205 §9.2 line 2),
or caller-chosen for derand (CAVP / ACVP). The WASM does not inspect
its contents.

---

## Module Identity

```typescript
function getModuleId(): i32     // returns 7
function getMemoryPages(): i32  // returns memory.size() (= 2)
```

---

## Memory Wiping

```typescript
function wipeBuffers(): void
```

Zeroes OUT, STATE, and SCRATCH in that order. INPUT is caller-supplied
material so the library does not own its zeroing; the TS wrapper wipes
its own input buffers per the universal hygiene rule.

The TypeScript wrapper calls `wipeBuffers()` in `SlhDsaBase.dispose()`.
Per-op secret residue is also wiped at the end of each public method;
`wipeBuffers()` is the broader sweep at instance teardown.

---

## Source Files

| File           | Contents                                                                                              |
|----------------|-------------------------------------------------------------------------------------------------------|
| `buffers.ts`   | Static buffer offsets, PARAMS slot, parameter-set selectors, `wipeBuffers`, module identity getters.  |
| `params.ts`    | Per-set numeric constants from FIPS 205 §11.1 Table 2 (n, h, d, h′, k, a, m, sizes).                  |
| `address.ts`   | 32-byte ADRS struct (FIPS 205 §4.2 Fig 2), big-endian field accessors, type-tag constants.            |
| `keccak.ts`    | Embedded Keccak-f[1600] permutation, SHAKE128/SHAKE256 sponge (FIPS 202 §3, §6.2).                    |
| `hashes.ts`    | FIPS 205 §11.2 tweakable hash family: F, H, T_ℓ, PRF, PRFmsg, Hmsg, plus raw `slhShake256`.           |
| `wots.ts`      | WOTS+ chain, key gen, sign, verify (FIPS 205 §5 Algorithms 4-7).                                      |
| `fors.ts`      | FORS sk-gen, node, sign, pk-from-sig (FIPS 205 §8 Algorithms 14-17).                                  |
| `xmss.ts`      | XMSS node, sign, pk-from-sig (FIPS 205 §6 Algorithms 9-11).                                           |
| `hypertree.ts` | Hypertree sign and verify (FIPS 205 §7 Algorithms 12-13).                                             |
| `slh.ts`       | Top-level §9 entry points: keygen, sign, verify (Algorithms 18-20).                                   |
| `index.ts`     | Public exports re-exposed from the files above, plus `_test*` fixtures for layer-level unit tests.    |

---

## API Reference

### Buffer offset getters

`getInputOffset`, `getOutOffset`, `getStateOffset`, `getScratchOffset`,
`getAdrsOffset`, `getParamsOffset`.

### Parameter-set selectors

```typescript
function slhSetParams128f(): void   // n=16, m=34
function slhSetParams192f(): void   // n=24, m=42
function slhSetParams256f(): void   // n=32, m=49
function getParamN():   i32         // current n
function getParamM():   i32         // current m
function getParamSet(): i32         // 0 = 128f, 1 = 192f, 2 = 256f
```

Callers must invoke a selector before any algorithm function. The
PARAMS slot is read by every hash and every per-layer dimension lookup.

### ADRS struct

Type tags (FIPS 205 §4.2 Algorithm 14):

```
ADRS_WOTS_HASH = 0   ADRS_FORS_TREE  = 3   ADRS_FORS_PRF = 6
ADRS_WOTS_PK   = 1   ADRS_FORS_ROOTS = 4
ADRS_TREE      = 2   ADRS_WOTS_PRF   = 5
```

```typescript
function adrsClear(adrs: i32): void
function adrsCopy(dst: i32, src: i32): void

function adrsSetLayerAddress(adrs: i32, layer: i32): void
function adrsGetLayerAddress(adrs: i32): i32

function adrsSetTreeAddr(adrs: i32, treeHi: u32, treeMid: u32, treeLo: u32): void
function adrsGetTreeHi(adrs:  i32): u32
function adrsGetTreeMid(adrs: i32): u32
function adrsGetTreeLo(adrs:  i32): u32

function adrsSetType(adrs: i32, typ: i32): void
function adrsGetType(adrs: i32): i32

function adrsSetKeyPairAddress(adrs: i32, kp: u32): void
function adrsGetKeyPairAddress(adrs: i32): u32

function adrsSetChainAddress(adrs: i32, chain: u32): void
function adrsGetChainAddress(adrs: i32): u32

function adrsSetHashAddress(adrs: i32, h: u32): void
function adrsGetHashAddress(adrs: i32): u32

function adrsSetTreeHeight(adrs: i32, height: u32): void
function adrsGetTreeHeight(adrs: i32): u32

function adrsSetTreeIndex(adrs: i32, index: u32): void
function adrsGetTreeIndex(adrs: i32): u32
```

`ADRS_BYTES = 32`. All integer fields are written most-significant-byte
first per FIPS 205 §4.2. The tree address is a 12-byte big-endian
integer split across three u32 limbs because AssemblyScript's u64 is
not first-class in all hosts.

### Hash family (FIPS 205 §11.2 Table 4)

```typescript
function slhHashF(outPtr, pkSeedPtr, adrsPtr, m1Ptr): void
function slhHashH(outPtr, pkSeedPtr, adrsPtr, m2Ptr): void
function slhHashTl(outPtr, pkSeedPtr, adrsPtr, mPtr, mLen): void
function slhPRF(outPtr, pkSeedPtr, skSeedPtr, adrsPtr): void
function slhPRFmsg(outPtr, skPrfPtr, optRandPtr, mPtr, mLen): void
function slhHmsg(outPtr, rPtr, pkSeedPtr, pkRootPtr, mPtr, mLen): void
function slhShake256(outPtr, outLen, inPtr, inLen): void
```

F, H, T_ℓ, and PRF collapse into one internal `tweakableHash` routine
because the byte pattern is the same shape: `PK.seed ‖ ADRS ‖ tail`.
Output length is `n` bytes (read from the PARAMS slot). `Hmsg` output
length is `m` bytes.

### Raw Keccak / SHAKE primitives

```typescript
function shake128Init(): void                          // rate 168, dsbyte 0x1f
function shake256Init(): void                          // rate 136, dsbyte 0x1f
function keccakAbsorb(len: i32): void                  // absorb from KECCAK_INPUT_OFFSET
function keccakAbsorbAt(srcPtr: i32, len: i32): void   // absorb from arbitrary ptr
function keccakSqueezeTo(dstPtr: i32, outLen: i32): void
function shakeFinal(outLen: i32): void                 // pad + squeeze to KECCAK_OUT_OFFSET
```

Exposed for parity with `sha3.wasm` so substrate gate tests can drive
SHAKE directly. Higher-level callers prefer the §11.2 hash family above.

### Top-level §9 entry points

```typescript
function slhKeygenInternal(): void                     // FIPS 205 §9.1 Algorithm 18
function slhSignInternal(msgLen: i32): void            // FIPS 205 §9.2 Algorithm 19
function slhVerifyInternal(msgLen: i32): i32           // FIPS 205 §9.3 Algorithm 20
```

`slhVerifyInternal` returns 1 on success, 0 on failure. The length
check on Algorithm 20 line 1 is the caller's responsibility; the TS
layer presents `sig` as a `Uint8Array` of length `sigBytes` and the
WASM layout assumes that contract holds.

### Test-only exports

Layer-level entry points for `slhdsa-wots.test.ts`,
`slhdsa-fors.test.ts`, `slhdsa-xmss.test.ts`, and
`slhdsa-hypertree.test.ts` ship under the `_test*` prefix:

```
_testWotsChain, _testWotsPkGen, _testWotsSign, _testWotsPkFromSig
_testForsSkGen, _testForsNode, _testForsSign, _testForsPkFromSig
_testXmssNode,  _testXmssSign, _testXmssPkFromSig
_testHtSign,    _testHtVerify
_testBase2b, _testWotsLen, _testWotsLen1, _testForsK, _testForsA,
_testXmssHPrime, _testHtD, _testHtHPrime
_testWotsTmpOffset, _testWotsSkOffset, _testWotsMsgOffset,
_testForsRootsOffset, _testForsLeafOffset, _testForsPairBase,
_testXmssPairBase, _testHtRootOffset
```

These are NOT part of the consumer-facing `SlhDsaExports` interface.
Consumers drive WOTS+/FORS/XMSS/hypertree only through
`slhSignInternal` and `slhVerifyInternal`. The underscore prefix
follows the codebase convention for module-internal exports.

---

## Constant-time Posture

**Hash family.** Every tweakable hash, every PRF call, and every Hmsg /
PRFmsg call routes through the SHAKE256 sponge. The Keccak-f[1600]
permutation is a fixed sequence of XOR / AND / NOT / rotate on 64-bit
lanes with no data-dependent branching and no memory access keyed by
secret state.

**Hypertree comparison.** `htVerify` runs the PK.root equality check
in constant time. The verifier surface is branch-free on the
secret-equivalence path.

**Address encoding.** All `adrsSet*` writes go byte-by-byte in
big-endian order regardless of host endianness. No conditional stores,
no data-dependent shifts.

**WOTS+ chain.** `wotsChain` advances the chain by a public step count
derived from the FORS-signed `md` digest, which is itself a public
function of the signature `R` and message. The per-iteration F-call
sequence is determined entirely by public inputs.

**FORS / XMSS.** Authentication-path expansion (`forsPkFromSig`,
`xmssPkFromSig`) walks indices derived from `md` and `idx_tree` /
`idx_leaf`, all of which are public per the FIPS 205 signature format.
Tree-node hashing uses the same branch-free tweakable hash above.

**Memory wipes.** `wipeBuffers()` issues three bulk `memory.fill`
calls covering OUT, STATE, and SCRATCH. INPUT is owned by the caller
and wiped by the TS wrapper after each operation.

All constant-time properties in this section are algorithm-level. See
[architecture.md §Where defense ends](./architecture.md#where-defense-ends)
for the hardware-level disclaim.

---

## Cross-References

| Document | Role |
|----------|------|
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [asm_imports.md](./asm_imports.md) | Per-module AssemblyScript import dependency graphs |
| [slhdsa_audit.md](./slhdsa_audit.md) | SLH-DSA FIPS 205 implementation audit, including PQ-only hybrid factory invariants |
| [slhdsa.md](./slhdsa.md) | `SlhDsa128f`, `SlhDsa192f`, `SlhDsa256f`: SLH-DSA hash-based signatures (FIPS 205), pure mode and HashSLH-DSA |
