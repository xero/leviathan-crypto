<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### `blake3` BLAKE3 WASM Module Reference

This low-level reference details the BLAKE3 AssemblyScript source and
WASM exports, intended for those auditing, contributing to, or building
against the raw module. **Most consumers should instead use the
[TypeScript wrapper](./blake3.md).**

> ### Table of Contents
> - [Overview](#overview)
> - [Module Identity](#module-identity)
> - [Buffer Layout](#buffer-layout)
> - [SIMD Dispatch Strategy](#simd-dispatch-strategy)
> - [Memory Wiping](#memory-wiping)
> - [Source Files](#source-files)
> - [WASM Exports](#wasm-exports)
> - [Test-Only Exports](#test-only-exports)
> - [Independence Claim](#independence-claim)

---

## Overview

The `blake3` module implements the BLAKE3 hash family in AssemblyScript,
covering BLAKE3 §2.2 (single-block compression with the G quarter-round
and the message permutation), §2.3 (the three modes: `hash`,
`keyed_hash`, `derive_key`), §2.4 (chunk chaining values + single-chunk
root case), §2.5 (parent node chaining values + root parent), §2.6
(extendable output), and §5.3 (SIMD lane-parallel compression).

Key properties of this implementation:

**SIMD-only.** Two compression kernels ship: a v128-internal
`compress` for single-block work and a v128-external lane-parallel
`compress4` for batches of four independent blocks. No scalar fallback
exists. The module joins serpent, chacha20, aes, kyber, and mldsa in
the v128-required tier.

**Static memory only.** All buffers are fixed offsets in linear memory.
The AssemblyScript compiler places SIGMA-table-style data in the
data segment at low memory; mutable regions start at `MUTABLE_START =
4096`. Total memory: 2 pages (131072 bytes).

**Three modes, one machine.** Default-mode hash, keyed_hash, and
derive_key share the same chunk / tree code. The modes differ only in
the starting chaining value (loaded into `MODE_CV`) and the
mode-flag bits (held in `MODE_FLAGS` and OR'd onto every compress).
The §2.3 `KEYED_HASH` and `DERIVE_KEY_*` flags are set by the
top-level entry points before any chunk / tree work fires.

**Root snapshot for XOF.** Both the single-chunk §2.4 root path and the
multi-chunk §2.5 root path snapshot the root-compress input into the
`ROOT_STATE_*` slots immediately before firing the root compress.
Subsequent §2.6 XOF squeezes re-fire the root compress with an
incremented counter against that snapshot. The TS `BLAKE3OutputReader`
drives this via the `squeezeXofBlock` export.

**Tree-mode internals gated for test use.** The `_testChunkCV`,
`_testParentCV`, and `_testDeriveContextCV` exports exist for the
tree-internals unit tests and the
`src/ts/merkle/blake3-tree.ts` Merkle-tree substrate. They are NOT part
of the consumer-facing `Blake3Exports` interface; consumers compute
chunk / parent CVs only via the top-level hash / hashKeyed / deriveKey
entries.

---

## Module Identity

```typescript
function getModuleId(): i32      // returns 4
function getMemoryPages(): i32   // current WASM linear-memory page count (2 pages, 131072 bytes, at module init)
```

---

## Buffer Layout

Defined in `src/asm/blake3/buffers.ts`. All offsets in bytes from base 0.

```
Offset    Size    Region
─────────────────────────────────────────────────────────────────────
0..4095   4096    AS data segment (SIGMA-style tables, read-only)
4096      4096    INPUT_STAGING       (4 chunks × 1024 bytes, vestigial)
8192      1024    OUTPUT_STAGING      (XOF reader, 16 root compressions)
9216        32    CV                  (working 8-word chaining value)
9248        64    MSG                 (16-word message block input)
9312         8    COUNTER             (u64 chunk index, lo at +0, hi at +4)
9320         4    BLOCK_LEN           (u32 bytes in current block)
9324         4    FLAGS               (u32 domain-separation bitfield)
9328        64    COMPRESS_OUT        (full 64-byte output; first 32 = next CV)
9392        32    KEYED_KEY           (KEYED_HASH 32-byte key, §2.3)
9424        32    DERIVE_CV           (DERIVE_KEY context CV stage, §2.3)
9456     15552    LEVEL_QUEUES        (54 × 9 × 32, §2.5 queue-per-level)
25008      216    LEVEL_COUNTS        (54 × 4, one i32 count per level)
25224      128    COMPRESS4_CV_IN     (4 × 32)
25352      256    COMPRESS4_MSG_IN    (4 × 64)
25608       32    COMPRESS4_CTR_IN    (4 × 8)
25640      256    COMPRESS4_OUT       (4 × 64)
25896       16    COMPRESS4_BLEN_IN   (4 × 4, BLAKE3 §2.2 b)
25912        4    COMPRESS4_FLAGS_IN  (1 × 4, shared across lanes)
25916       32    MODE_CV             (chunkInit start CV / parent compress key)
25948        8    CHUNK_INDEX         (u64 §2.4 chunk counter)
25956        4    CHUNK_BLOCKS        (i32 blocks compressed in current chunk)
25960        4    CHUNK_PENDING_LEN   (i32 1-block lookahead length)
25964       64    CHUNK_PENDING_BLOCK (1-block lookahead buffer)
26028       64    TREE_PARENT_BLOCK   (left || right concat for finalize)
26092       32    CHUNK_CV_SCRATCH    (32-byte chunk CV between finalize / push)
26124       64    ROOT_OUT_SCRATCH    (64-byte root compress output staging)
26188        4    MODE_FLAGS          (mode-flag bits OR'd onto every compress)
26192       32    CONTEXT_CV          (derive_key pass-1 output CV, §2.3)
26224       32    ROOT_STATE_CV       (XOF: snapshot of root-compress CV)
26256       64    ROOT_STATE_MSG      (XOF: snapshot of root-compress msg block)
26320        4    ROOT_STATE_BLEN     (XOF: snapshot of root-compress block_len)
26324        4    ROOT_STATE_FLAGS    (XOF: snapshot of root-compress flags)
BUFFER_END = 26328
```

Total mutable region: 22232 bytes from `MUTABLE_START = 4096` to
`BUFFER_END = 26328`. The 2-page (131072 byte) module sizing leaves
post-`BUFFER_END` space for the TS layer's per-call input scratch
(`INPUT_SCRATCH_OFF = 27648`, max 103424 bytes), which is how
`src/ts/blake3/index.ts` stages caller inputs without disturbing the
module's own buffers.

`LEVEL_QUEUES` replaces the prior count-trailing-zeros (ctz)
`SUBTREE_STACK` region. Each level L of the BLAKE3 §5.1.2 54-level
tree maintains a small queue of pending CVs at offset
`LEVEL_QUEUES_OFFSET + L * LEVEL_QUEUE_STRIDE` (stride 288 = 9 × 32);
the i32 count of pending entries is at `LEVEL_COUNTS_OFFSET + L * 4`.
The 9-entry-per-level width absorbs the worst-case finalize-time
carry transient (BLAKE3 §2.5, see `tree.ts` file header).

`ROOT_STATE_*` captures the root-compress input the moment before the
root compress fires. Two code paths populate it: the single-chunk
§2.4 root path in `chunk.ts:chunkFinalize`, and the multi-chunk §2.5 path
in `tree.ts:treeFinalizeRoot`. The `squeezeXofBlock` export and the
internal XOF squeeze loop in `hashCore` both re-fire the root compress
from this snapshot.

---

## SIMD Dispatch Strategy

Two compression kernels are exported, with parallel correctness:

**`compress` (v128-internal).** A single-block compress where the four
state rows are each held in one v128 register, with column G_0..G_3
running all four columns in parallel via one v128 op per state-update
step. Diagonal G_4..G_7 are made columnar by per-row lane rotations,
then the same column pipeline runs and the rotations are undone. This
is the workhorse path: the chunk machine fires `compress` for every
block, and the tree merge fires `compress` for every parent.

**`compress4` (v128-external).** A lane-parallel compress that runs
four independent compressions in parallel, with lane K of every v128
op corresponding to compress operation K. Each of the 16 state words
is its own v128 holding lane K of compress K. No within-register
shuffles for the diagonal phase (each lane is its own state), and the
σ message permutation operates as whole-register renames between
rounds. All four lanes share a single flags value.

**When `compress4` is invoked.** Two production hot paths drive
`compress4`:

Chunk-level dispatch (BLAKE3 §2.4, multi-chunk inputs). The chunk
pipeline batches 4 full chunks at a time through `compress4` for
inputs ≥ 4096 bytes. Each batch runs 16 lane-parallel compress
operations (one per block position 0..15), with lane K processing
chunk K's block-by-block CV chain. Counters stay constant per lane
within a batch (BLAKE3 §2.4 chunk counter is per chunk, not per
block); CHUNK_START on block 0 and CHUNK_END on block 15 fire as
shared flag bits across all four lanes (BLAKE3 §5.3 SIMD). The dispatch
driver in `hashCore` (`src/asm/blake3/index.ts`) drains the largest
multiple of 4 full chunks via `chunkBatch4`
(`src/asm/blake3/chunk_simd.ts`); trailing full chunks (fewer than
4 remaining) and the partial last chunk fall back to single-chunk
`compress` calls in `chunk.ts`.

Parent-level dispatch (BLAKE3 §2.5, queue-per-level discipline in
`tree.ts`). Each tree level maintains a queue of pending CVs sized
for 9 entries to absorb finalize-time carry overflows; when a level's
queue reaches 8 during push, `parentBatch4`
(`src/asm/blake3/tree_simd.ts`) batches 4 parent merges via
`compress4`. The 4 outputs propagate to the next level's queue,
possibly cascading further batches. Finalize walks the queues
bottom-up using single-pair `compress` calls (residual merges and
the §2.5 ROOT compress; ROOT-flag bookkeeping is simplest with
single-pair semantics). With both chunk-level and parent-level
dispatch live, every multi-chunk hash drives all of its
parallelizable compresses through the v128-external SIMD kernel.

The substrate test `blake3-compress4-equiv` continues to assert
lane K's `compress4` output equals `compress` on the same inputs;
the chunk-dispatch test `blake3-compress4-dispatch` (test-only WASM
counter on `chunkBatch4` invocations) and the parent-dispatch test
`blake3-parent-dispatch` (test-only WASM counter on `parentBatch4`
invocations) confirm the production hot paths actually fire the
kernel rather than silently falling through.

**No `compress8` ships.** WebAssembly SIMD is fixed at 128-bit
vectors. A `compress8` over two v128 lanes per state word would
double the register pressure without doubling the parallelism (the
G function would still need to thread eight 32-bit state words across
two physical registers). The deferred optimization is noted in the
audit doc and may revisit when wide-SIMD WebAssembly lands.

**No scalar path.** `init()` rejects the `blake3` slot when SIMD is
unavailable, identical to serpent, chacha20, aes, kyber, and mldsa.
No fallback ships and none is planned.

---

## Memory Wiping

```typescript
function wipeBuffers(): void
```

`memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)`, zeros the
entire mutable region in one pass. Covers `INPUT_STAGING`,
`OUTPUT_STAGING`, the working compress slots (CV / MSG / COUNTER /
BLOCK_LEN / FLAGS / COMPRESS_OUT), `KEYED_KEY`, `DERIVE_CV`, the §2.5
`LEVEL_QUEUES` and `LEVEL_COUNTS` regions, the compress4 staging
buffers, the chunk-state slots, the tree-state slots
(`TREE_PARENT_BLOCK` / `CHUNK_CV_SCRATCH` / `ROOT_OUT_SCRATCH`),
`CONTEXT_CV`, and the `ROOT_STATE_*` snapshot.

The AS data segment at offsets 0..4095 is not wiped. It is read-only
constant data.

The TypeScript wrapper calls `wipeBuffers()` on every public method's
`finally` block (one-shot paths) and on `dispose()` / `finalize()`
(streaming paths). Per-call secret residue is wiped before the next
call rather than relying solely on instance teardown.

---

## Source Files

| File                  | Contents                                                                                                                |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `buffers.ts`          | Static buffer offsets, `MUTABLE_START` / `BUFFER_END`, module identity getters.                                          |
| `flags.ts`            | BLAKE3 §2.2 Table 3 domain-separation flag constants.                                                                   |
| `compress.ts`         | v128-internal `compress` (single block), BLAKE3 IV constants, SIGMA permutation table.                                   |
| `compress_simd.ts`    | v128-external lane-parallel `compress4`.                                                                                |
| `chunk.ts`            | §2.4 chunk state machine: `chunkInit`, `chunkUpdate`, `chunkFinalize` with one-block lookahead for `CHUNK_END` handling. |
| `chunk_simd.ts`       | 4-chunk batched chunk pipeline `chunkBatch4`: drives `compress4` directly for 4 contiguous full chunks. Multi-chunk hot path. |
| `tree.ts`             | §2.5 queue-per-level tree assembly + root finalization: `treeInit`, `treePushChunk`, `treeFinalizeRoot` with single-pair finalize. |
| `tree_simd.ts`        | 4-parent batched tree-merge pipeline `parentBatch4`: drives `compress4` for 4 sibling parent merges at one tree level. Parent-level hot path. |
| `index.ts`            | Public exports + top-level `hash` / `hashKeyed` / `deriveKey` entries + `squeezeXofBlock` + `wipeBuffers` + test exports. |

---

## WASM Exports

### Buffer offset getters

`getInputStagingOffset`, `getOutputStagingOffset`, `getCvOffset`,
`getMsgOffset`, `getCounterOffset`, `getBlockLenOffset`,
`getFlagsOffset`, `getCompressOutOffset`, `getKeyedKeyOffset`,
`getDeriveCvOffset`, `getCompress4CvInOffset`,
`getCompress4MsgInOffset`, `getCompress4CtrInOffset`,
`getCompress4OutOffset`, `getCompress4BlenInOffset`,
`getCompress4FlagsInOffset`, `getModeCvOffset`. All return `i32`.

### Flag constants

`FLAG_CHUNK_START` (1), `FLAG_CHUNK_END` (2), `FLAG_PARENT` (4),
`FLAG_ROOT` (8), `FLAG_KEYED_HASH` (16), `FLAG_DERIVE_KEY_CONTEXT`
(32), `FLAG_DERIVE_KEY_MATERIAL` (64). BLAKE3 §2.2 Table 3. Each is
a power of two so the bits OR together into the §2.2 `d` input.

### BLAKE3 IV constants

`BLAKE3_IV0` .. `BLAKE3_IV7`. BLAKE3 §2.2 Table 1. Bit-identical to
the SHA-256 initial hash values per FIPS 180-4 §5.3.3 (BLAKE3
inherits the BLAKE2s setup, which inherits the SHA-256 IV).

### Compression primitives

```typescript
function compress(
    cvOff:     i32,    // 32-byte input chaining value
    blockOff:  i32,    // 64-byte message block
    counterLo: u32,    // BLAKE3 §2.2 `t` low word
    counterHi: u32,    // BLAKE3 §2.2 `t` high word
    blockLen:  u32,    // BLAKE3 §2.2 `b`
    flags:     u32,    // BLAKE3 §2.2 `d`
    outOff:    i32,    // full 64-byte output (first 32 = next CV)
): void

function compress4(): void  // reads from COMPRESS4_* staging, writes COMPRESS4_OUT
```

`compress` writes its full 64-byte output (the §2.2 feed-forward),
which is the canonical XOF output for the root compress. The first
32 bytes are the next CV consumed by chunk / parent assembly.

`compress4` operates entirely through the `COMPRESS4_*` staging
buffers: the caller writes four CVs / msg blocks / counters / blens
to `COMPRESS4_CV_IN` / `COMPRESS4_MSG_IN` / `COMPRESS4_CTR_IN` /
`COMPRESS4_BLEN_IN`, writes the shared flags word to
`COMPRESS4_FLAGS_IN`, and reads the four 64-byte outputs from
`COMPRESS4_OUT` at offsets 0, 64, 128, 192.

### Chunk surface (§2.4)

```typescript
function chunkInit(chunkIndex: u64): void
function chunkUpdate(blockOff: i32, blockLen: i32): void
function chunkFinalize(outCvOff: i32, isRootSoloChunk: i32): void
```

`chunkInit` resets the chunk machine to `MODE_CV` as the starting CV
and `chunkIndex` as the §2.4 counter `t`. `chunkUpdate` keeps a
one-block lookahead so each compress can carry the correct §2.4 flag
(`CHUNK_START` only on the first compress; `CHUNK_END` only on the
final compress) without the caller having to identify the last block
in advance. `chunkFinalize` compresses the buffered final block with
`CHUNK_END`, optionally adds `ROOT` for the §2.4 single-chunk root case,
and writes the 32-byte chunk CV to `outCvOff`.

### Tree surface (§2.5)

```typescript
function treeInit(): void
function treePushChunk(chunkCvOff: i32): void
function treeFinalizeRoot(outOff: i32): void
```

`treeInit` zeroes all 54 `LEVEL_COUNTS` slots. Queue contents
themselves do not need clearing here; unread slots past a level's
count are never consumed, and `wipeBuffers()` covers the queue
region on dispose. The tree depth is bounded at 54 per BLAKE3 §5.1.2
(the theoretical 2^64-byte input limit).

`treePushChunk` appends the chunk CV to level 0's queue and cascades
upward: while a level's queue reaches 8 entries, `parentBatch4`
batches 4 parent merges in parallel through `compress4`, the level's
count resets to 0, and the next level's count grows by 4. The
cascade continues as long as upper levels also reach 8 pending.

`treeFinalizeRoot` walks the level queues bottom-up. At each level
it pair-compresses while count ≥ 2 (emit to the next level's queue
tail); a residual single CV carries up unchanged. The FINAL merge
(when `remainingMerges == 1`, where `remainingMerges = totalCvs - 1`
at the start of finalize) carries the §2.5 ROOT flag and writes its
full 64-byte output to `outOff`. The root compress input is
snapshotted into `ROOT_STATE_*` immediately before firing, so
subsequent `squeezeXofBlock` calls can re-fire with an incremented
counter.

### Top-level hash entries

```typescript
function hash(
    inputOff: i32, inputLen: i32,
    outOff:   i32, outLen:   i32,
): void

function hashKeyed(
    keyOff:   i32,
    inputOff: i32, inputLen: i32,
    outOff:   i32, outLen:   i32,
): void

function deriveKey(
    contextOff:  i32, contextLen:  i32,
    materialOff: i32, materialLen: i32,
    outOff:      i32, outLen:      i32,
): void
```

Each entry drives the full chunk / tree pipeline. The mode bit is set
in `MODE_FLAGS` before any chunk / tree work fires: zero for `hash`,
`FLAG_KEYED_HASH` for `hashKeyed`, and `FLAG_DERIVE_KEY_CONTEXT` /
`FLAG_DERIVE_KEY_MATERIAL` for the two `deriveKey` passes. The
starting `MODE_CV` is the BLAKE3 IV (hash / derive_key pass 1), the
32 key bytes (keyed_hash), or the pass-1 context CV (derive_key pass
2). For `outLen > 64` the entry squeezes additional 64-byte XOF
blocks from `ROOT_STATE_*` via `squeezeRootBlock` until `outLen`
bytes are written.

### XOF squeeze entry (§2.6)

```typescript
function squeezeXofBlock(counterLo: u32, counterHi: u32, outOff: i32): void
```

Re-fires the root compress from the `ROOT_STATE_*` snapshot with the
supplied counter and writes the full 64-byte output to `outOff`.
Counter 0 is consumed by the initial root compress fired inside
`hash` / `hashKeyed` / `deriveKey`, so the first squeeze call should
pass counter = 1.

The caller must have completed a `hash` / `hashKeyed` / `deriveKey`
on the current module instance before calling `squeezeXofBlock`.
Calling without a prior hash, or after `wipeBuffers()`, yields
meaningless bytes (the snapshot is zero or stale). The TS
`BLAKE3OutputReader` enforces the contract by running the hash in
its constructor and squeezing incrementally from this entry.

### Buffer hygiene

```typescript
function wipeBuffers(): void
```

Zeros the entire mutable region (`MUTABLE_START` to `BUFFER_END`).
See [Memory Wiping](#memory-wiping).

---

## Test-Only Exports

The following exports are NOT part of the consumer-facing
`Blake3Exports` interface. They are wired exclusively for the
`test/unit/blake3/blake3-tree-internals.test.ts` test fixture and the
`src/ts/merkle/blake3-tree.ts` Merkle-tree substrate,
which casts `Blake3Exports & Blake3TestExports` inside the
merkle module. Tests obtain these via
`test/unit/blake3/helpers.ts`. The underscore prefix follows the
codebase convention for module-internal exports (matching slhdsa's
`_test*` namespace).

```typescript
function _testChunkCV(
    inputOff:   i32, inputLen:   i32,
    chunkIndex: u64,
    startCvOff: i32, modeFlags:  u32,
    outCvOff:   i32,
): void

function _testParentCV(
    leftCvOff:  i32, rightCvOff: i32,
    startCvOff: i32, modeFlags:  u32,
    isRoot:     bool,
    outCvOff:   i32,
): void

function _testDeriveContextCV(
    contextOff: i32, contextLen: i32,
    outCcvOff:  i32,
): void
```

`_testChunkCV` drives the §2.4 chunk pipeline for one chunk at
`chunkIndex` with a caller-specified starting CV and mode flags,
emitting the 32-byte chunk CV without applying `ROOT`. Useful for
asserting that a single non-final chunk in a multi-chunk input
produces the expected CV.

`_testParentCV` composes a parent compress over two child CVs.
When `isRoot` is true the compress carries `PARENT | ROOT`,
`ROOT_STATE_*` is populated, and the first 32 bytes of the §2.5 root
output are written to `outCvOff`; otherwise a plain `PARENT` compress
emits the 32-byte parent CV.

`_testDeriveContextCV` runs BLAKE3 §2.3 derive_key pass 1 in isolation: hashes
the context bytes with starting CV = IV and `DERIVE_KEY_CONTEXT`,
writes the 32-byte context_chain_value to `outCcvOff`.

---

## Independence Claim

This module is implemented from the BLAKE3 specification directly,
not ported from the reference implementation. The independence claim
matches the library's per-module discipline (AGENTS.md §Ground Rules
#4): each AssemblyScript primitive derives from the published spec
without referring to an existing implementation, so cross-checks
against a reference codebase become a genuine correctness signal
rather than a tautology.

The Rust verifier under `scripts/verify-vectors/` cross-checks BLAKE3
output against the `blake3` RustCrypto crate for large-input regimes
(1 KiB to 16 MiB) and the upstream 35-case test corpus. The Rust
verifier shares zero code with the AssemblyScript stack and uses a
pinned Rust toolchain plus a pinned `Cargo.lock`. See
[vector_audit.md](./vector_audit.md) for the verifier coverage model.
