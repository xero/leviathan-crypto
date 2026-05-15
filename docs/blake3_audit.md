<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### BLAKE3 Cryptographic Audit

Audit of the `leviathan-crypto` WebAssembly BLAKE3 implementation
(AssemblyScript) against the BLAKE3 specification, covering the
v128-internal `compress`, the v128-external `compress4`, the §2.4
chunk machine, the §2.5 tree assembly + root finalize, the §2.6 XOF
squeeze, and the §2.3 keyed_hash and derive_key modes. Every
checkbox is falsifiable by reading the cited file and confirming the
invariant against the spec reference (and, where noted, against the
RustCrypto `blake3` crate, which is consulted only after the
round-trip gate passes per AGENTS.md §Ground Rules #4).

> ### Table of Contents
> - [Buffer Layout (`src/asm/blake3/buffers.ts`)](#buffer-layout-srcasmblake3buffersts)
> - [Flags (`src/asm/blake3/flags.ts`)](#flags-srcasmblake3flagsts)
> - [Compression, v128-internal (`src/asm/blake3/compress.ts`)](#compression-v128-internal-srcasmblake3compressts)
> - [Compression, v128-external (`src/asm/blake3/compress_simd.ts`)](#compression-v128-external-srcasmblake3compress_simdts)
> - [Chunk Machine (`src/asm/blake3/chunk.ts`)](#chunk-machine-srcasmblake3chunkts)
> - [Subtree Stack and Root (`src/asm/blake3/tree.ts`)](#subtree-stack-and-root-srcasmblake3treets)
> - [Top-level Entries (`src/asm/blake3/index.ts`)](#top-level-entries-srcasmblake3indexts)
> - [TS Validation (`src/ts/blake3/validate.ts`)](#ts-validation-srctsblake3validatets)
> - [TS Public Surface (`src/ts/blake3/index.ts`)](#ts-public-surface-srctsblake3indexts)
> - [Memory Hygiene](#memory-hygiene)
> - [Constant-Time Considerations](#constant-time-considerations)
> - [Side Channels](#side-channels)
> - [Test Coverage](#test-coverage)
> - [Open Audit Items](#open-audit-items)
> - [Cross-References](#cross-references)

| Meta              | Description                                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------- |
| Target:           | `leviathan-crypto` WebAssembly implementation (AssemblyScript)                                                |
| Spec:             | BLAKE3, one function, fast everywhere (O'Connor / Aumasson / Neves / Wilcox-O'Hearn, 2020-01-09)              |
| Modes:            | `hash`, `keyed_hash`, `derive_key` (BLAKE3 §2.3 Modes); XOF output via §2.6 Extendable Output                  |
| Test vectors:     | Upstream 35-case corpus (pin `ae3e8e6b3a5ae3190ca5d62820789b17886a0038`) + RustCrypto `blake3 = "=1.8.5"` oracle |
| Independence:     | Implemented from the BLAKE3 specification directly, no port from the reference implementation                  |

---

## Buffer Layout (`src/asm/blake3/buffers.ts`)

- [ ] `MUTABLE_START = 4096` reserves the AS data segment for SIGMA-style read-only tables.
- [ ] `BUFFER_END = 26328` matches the running total of every region declared in the file. Fits inside 1 page (65536 bytes); module is sized at 2 pages (131072 bytes) for slack.
- [ ] `INPUT_STAGING` (4096..8191) is at least `4 × 1024` for compress4 batching (kept vestigial; chunk_simd reads directly from caller scratch).
- [ ] `OUTPUT_STAGING` (8192..9215) is at least 1024 bytes for one-shot XOF reads.
- [ ] Working compress slots are pinned: `CV` at 9216 (32 B), `MSG` at 9248 (64 B), `COUNTER` at 9312 (8 B), `BLOCK_LEN` at 9320 (4 B), `FLAGS` at 9324 (4 B), `COMPRESS_OUT` at 9328 (64 B).
- [ ] `KEYED_KEY` (9392) holds the §2.3 keyed_hash 32-byte key; `DERIVE_CV` (9424) is a derive_key staging slot.
- [ ] `LEVEL_QUEUES` (9456..25007) is 54 × 9 × 32 bytes, matching the BLAKE3 §5.1.2 depth bound (54 levels) with a 9-entry width per level absorbing the finalize-time carry transient. Queue for level L starts at `LEVEL_QUEUES_OFFSET + L * LEVEL_QUEUE_STRIDE` with `LEVEL_QUEUE_STRIDE = 288` bytes.
- [ ] `LEVEL_COUNTS` (25008..25223) is 54 × 4 bytes, one i32 count per level (number of pending CVs currently held in that level's queue).
- [ ] `COMPRESS4_*` slots (25224..25915) are 4-wide arrays matching the lane-parallel layout (used by both `chunkBatch4` and `parentBatch4`).
- [ ] `MODE_CV` (25916, 32 B) is the per-mode starting CV slot read by `chunkInit` and parent compresses.
- [ ] Chunk-state slots `CHUNK_INDEX` / `CHUNK_BLOCKS` / `CHUNK_PENDING_LEN` / `CHUNK_PENDING_BLOCK` (25948..26027) hold the §2.4 chunk-machine state.
- [ ] Tree-state slots `TREE_PARENT_BLOCK` / `CHUNK_CV_SCRATCH` / `ROOT_OUT_SCRATCH` (26028..26187) hold the §2.5 single-pair finalize staging and the §2.5 root output.
- [ ] `MODE_FLAGS` (26188, 4 B) holds the OR-onto-every-compress mode bits; zero for hash, `FLAG_KEYED_HASH` for keyed_hash, `FLAG_DERIVE_KEY_CONTEXT` / `FLAG_DERIVE_KEY_MATERIAL` for the two derive_key passes.
- [ ] `CONTEXT_CV` (26192, 32 B) holds the §2.3 derive_key pass-1 output between the two passes.
- [ ] `ROOT_STATE_*` (26224..26327) capture the root-compress input snapshot for §2.6 XOF squeezes.
- [ ] `getModuleId()` returns 4 (distinct from every other module).
- [ ] `getMemoryPages()` returns 2.

## Flags (`src/asm/blake3/flags.ts`)

- [ ] `FLAG_CHUNK_START = 1` (2^0), BLAKE3 §2.2 Table 3.
- [ ] `FLAG_CHUNK_END = 2` (2^1).
- [ ] `FLAG_PARENT = 4` (2^2).
- [ ] `FLAG_ROOT = 8` (2^3).
- [ ] `FLAG_KEYED_HASH = 16` (2^4).
- [ ] `FLAG_DERIVE_KEY_CONTEXT = 32` (2^5).
- [ ] `FLAG_DERIVE_KEY_MATERIAL = 64` (2^6).
- [ ] All flags are powers of two; they may be ORed into the §2.2 `d` field without overlap.

## Compression, v128-internal (`src/asm/blake3/compress.ts`)

- [ ] `BLAKE3_IV0..7` match BLAKE3 §2.2 Table 1 (identical to FIPS 180-4 §5.3.3 SHA-256 IV).
- [ ] `SIGMA` permutation `[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]` matches BLAKE3 §2.2 Table 2.
- [ ] Compress runs exactly 7 rounds (§2.2 round count).
- [ ] G function rotations are R1=16, R2=12, R3=8, R4=7 in that order, matching BLAKE3 §2.2.
- [ ] Initial state layout: `row0 = h0..h3`, `row1 = h4..h7`, `row2 = IV0..IV3`, `row3 = (counterLo, counterHi, blockLen, flags)`. Matches §2.2 `v0..v15`.
- [ ] Column G runs four G calls in parallel via one v128 op per state-update step; diagonal G is made columnar by per-row lane rotations, then the rotations are undone after the G calls fire.
- [ ] Between rounds 0..5 the message is permuted via `m'[i] = m[SIGMA[i]]`; the permutation is NOT applied after round 6 (the final round), per BLAKE3 §2.2.
- [ ] Feed-forward output writes the full 64 bytes: bytes 0..31 are `(v_0..v_7) XOR (v_8..v_15)`, and bytes 32..63 are `(v_8..v_15) XOR (h_0..h_7)`. Matches BLAKE3 §2.2.
- [ ] When `blockOff != MSG_OFFSET` the caller's block is staged into `MSG_OFFSET` so the round-wise permutation does not mutate the caller's buffer.

## Compression, v128-external (`src/asm/blake3/compress_simd.ts`)

- [ ] `compress4` reads four CVs / msg blocks / counters / blens from the `COMPRESS4_*` staging buffers and writes four 64-byte outputs to `COMPRESS4_OUT` at lane-deinterleaved offsets (lane K at K × 64).
- [ ] Lane K's CV occupies `COMPRESS4_CV_IN + K × 32` for 32 bytes; the lane-K state words v0..v7 are gathered from the K-th 32-byte slot.
- [ ] Lane K's message block occupies `COMPRESS4_MSG_IN + K × 64` for 64 bytes; the lane-K message words m0..m15 are gathered from the K-th 64-byte slot.
- [ ] Lane K's counter occupies `COMPRESS4_CTR_IN + K × 8` (lo at +0, hi at +4); `v12`, `v13` are gathered as `[ctrLo_0, ctrLo_1, ctrLo_2, ctrLo_3]` and `[ctrHi_0, ctrHi_1, ctrHi_2, ctrHi_3]`.
- [ ] Lane K's block_len occupies `COMPRESS4_BLEN_IN + K × 4`; `v14` is gathered as `[blen_0, blen_1, blen_2, blen_3]`.
- [ ] The flags word at `COMPRESS4_FLAGS_IN` is splatted across all four lanes of `v15`; all four lanes share the same flags value per BLAKE3 §2.2 (the `d` input) lane-parallelized per §5.3.
- [ ] The 7-round permutation E(m, v) runs identically per-lane to `compress`, with G rotations R1=16, R2=12, R3=8, R4=7.
- [ ] SIGMA permutation is applied as whole-register renames between rounds (no within-register shuffles); the rename schedule encodes `[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]`, identical to `compress`.
- [ ] Feed-forward output matches `compress`: lane K's bytes K × 64 .. K × 64 + 63 are bit-identical to a `compress` call against lane K's inputs.
- [ ] `compress4` output is bit-equivalent to 4 × `compress` over the same inputs (asserted by `test/unit/blake3/blake3-compress4-equiv.test.ts`).
- [ ] Chunk-level dispatch to `compress4` is wired into `hashCore` (`src/asm/blake3/index.ts`): for multi-chunk inputs the largest multiple of 4 full chunks runs through `chunkBatch4` (`src/asm/blake3/chunk_simd.ts`), with trailing full chunks and the partial last chunk falling back to the §2.4 single-chunk path. Asserted by `test/unit/blake3/blake3-compress4-dispatch.test.ts` (test-only WASM counter on `chunkBatch4` invocations).
- [ ] Parent-level dispatch to `compress4` is wired into `treePushChunk` via the queue-per-level discipline (BLAKE3 §2.5): each tree level maintains a queue of pending CVs and batches 4 parent merges via `parentBatch4` (`src/asm/blake3/tree_simd.ts`) when the queue reaches 8 entries. Finalize uses `compress` (single-pair) for residual merges and the ROOT compress. Asserted by `test/unit/blake3/blake3-parent-dispatch.test.ts` (test-only WASM counter on `parentBatch4` invocations).

## Chunk Machine (`src/asm/blake3/chunk.ts`)

- [ ] `chunkInit(chunkIndex)` copies `MODE_CV` into `CV` (the working chunk CV starts from the mode CV per BLAKE3 §2.4).
- [ ] `chunkInit` writes `chunkIndex` to `CHUNK_INDEX` as a u64; every compress within the chunk uses this value as the counter.
- [ ] `chunkInit` resets `CHUNK_BLOCKS`, `CHUNK_PENDING_LEN`, and `CHUNK_PENDING_BLOCK` so an empty-input chunk (no `chunkUpdate` before `chunkFinalize`) compresses the canonical 64-zero block with `block_len = 0` (§2.4 single-chunk root case).
- [ ] `chunkUpdate(blockOff, blockLen)` first compresses the previously buffered block as a non-final block when one is pending, then stashes the new block in `CHUNK_PENDING_BLOCK` for the next call or for `chunkFinalize` to consume.
- [ ] When `blockLen < 64` the remainder of `CHUNK_PENDING_BLOCK` is zero-padded; the final block byte count is preserved in `CHUNK_PENDING_LEN` for the eventual finalize.
- [ ] `chunkFinalize(outCv, isRootSoloChunk)` compresses the buffered block with `CHUNK_END`; when `isRootSoloChunk` is true, the compress also carries `ROOT` (§2.4 single-chunk root case).
- [ ] `compressPending` OR's `MODE_FLAGS` onto every compress so keyed_hash (`FLAG_KEYED_HASH`) and derive_key (`FLAG_DERIVE_KEY_CONTEXT` / `FLAG_DERIVE_KEY_MATERIAL`) flag bits are carried on every chunk compress.
- [ ] `CHUNK_START` is set on the compress when `CHUNK_BLOCKS == 0`, i.e. the first compress of the chunk.
- [ ] When `isRootSoloChunk` is true, the §2.4 single-chunk root compress input (`CV`, `CHUNK_PENDING_BLOCK`, `pendingLen`, `flags`) is snapshotted into `ROOT_STATE_*` immediately before the compress fires, enabling §2.6 XOF squeezes to re-fire from the snapshot.
- [ ] After every compress, the first 32 bytes of `COMPRESS_OUT` are copied into `CV` as the new chunk CV; `CHUNK_BLOCKS` is incremented; `CHUNK_PENDING_LEN` is reset to 0.

## Subtree Stack and Root (`src/asm/blake3/tree.ts`)

The §2.5 tree-assembly machinery uses a queue-per-level discipline:
each of the BLAKE3 §5.1.2 54 tree levels maintains a small queue of
pending CVs in `LEVEL_QUEUES`. At push time, when a level's queue
reaches 8 entries, `parentBatch4` (`src/asm/blake3/tree_simd.ts`)
batches 4 parent merges in parallel through the v128-external
`compress4` kernel and the 4 outputs propagate to the next level's
queue. Finalize walks the queues bottom-up using single-pair
`compress` calls for residual merges and the §2.5 ROOT compress.
ROOT is exclusive (§2.5) and lives on a single compress invocation,
which is why finalize never batches: ROOT-flag bookkeeping is
simplest with single-pair semantics.

- [ ] `treeInit()` zeroes all 54 entries of `LEVEL_COUNTS`. Queue contents themselves do not need zeroing here: unread slots past a level's count are never consumed, and `wipeBuffers()` covers the queues on dispose.
- [ ] `treePushChunk(chunkCv)` appends the new chunk CV to level-0's queue and cascades upward: while `count[L] >= 8`, fires `parentBatch4(queue[L], queue[L+1] + count[L+1] * 32)`, zeroes `count[L]`, and adds 4 to `count[L+1]`. The chunk counter is consumed inside chunk.ts for the §2.4 `t` field; the queue-per-level discipline only needs per-level counts.
- [ ] Each `parentBatch4` invocation runs four §2.5 parent compresses in parallel via `compress4`: CV input = `MODE_CV` splatted across all 4 lanes, msg input = left || right (64 bytes per lane), counter = 0 (shared), block_len = 64 (shared), flags = `FLAG_PARENT | MODE_FLAGS` (shared). Per BLAKE3 §2.5 each parent compress at one level is independent of the others, so the batched output is bit-equivalent to four sequential `compress` calls.
- [ ] Push-time batches fire when a level's count reaches exactly 8 (never higher); after batching the count resets to 0 and the next level's count grows by 4. The cascade continues as long as upper levels also reach 8 pending. Loop terminates naturally at `MAX_LEVEL - 1`; the BLAKE3 §5.1.2 input-size bound (≤ 2^64 bytes) ensures the cascade does not exceed 54 levels with valid inputs.
- [ ] `treeFinalizeRoot(outOff)` computes `totalCvs` as the sum of all `count[L]`, sets `remainingMerges = totalCvs - 1`, and walks levels 0..MAX_LEVEL-1. At each level it pair-compresses while `count[L] >= 2` (emit to `queue[L+1]` tail; the FINAL merge with `remainingMerges == 1` writes to `outOff` and carries the §2.5 ROOT flag). A residual single CV (`count[L] == 1` after the pair loop) carries up to `queue[L+1]` with no merge consumed.
- [ ] The 9-entry-per-level queue width (`LEVEL_QUEUE_STRIDE = 288`) covers the transient peak of 8 entries (post-push 4 from a prior batch plus 4 finalize-time emissions: 3 pair-emits plus 1 carry from the level below) with 1 slot of headroom for alignment and future tightening. Levels L ≥ 1 reach count 0 or 4 at push-end (pushes add +4 and batches fire at exactly 8), so the peak write offset during finalize is index 7.
- [ ] During the root merge (`remainingMerges == 1`) `ROOT_STATE_*` is populated with `MODE_CV`, `TREE_PARENT_BLOCK`, `blockLen = 64`, and the final flags (`PARENT | ROOT | MODE_FLAGS`). Subsequent `squeezeXofBlock` calls re-fire the root compress from this snapshot per BLAKE3 §2.5.
- [ ] The root merge writes the full 64 bytes directly to the caller-supplied `outOff`; non-root merges write 32-byte parent CVs into the destination queue tail.
- [ ] After finalize, every `LEVEL_COUNTS` slot is reset to 0 so a follow-up hash on the same module instance starts clean (the dispose-time `wipeBuffers()` is the broader sweep).

## Top-level Entries (`src/asm/blake3/index.ts`)

- [ ] `hash(inputOff, inputLen, outOff, outLen)` loads the BLAKE3 IV into `MODE_CV` (BLAKE3 §2.2 Table 1) and sets `MODE_FLAGS = 0` before invoking `hashCore`.
- [ ] `hashKeyed(keyOff, ...)` copies 32 bytes from `keyOff` into `MODE_CV` (the §2.3 keyed_hash starting CV is the key, byte-for-byte; WASM little-endian matches the §2.3 u32 LE word interpretation) and sets `MODE_FLAGS = FLAG_KEYED_HASH`.
- [ ] `deriveKey(contextOff, contextLen, materialOff, materialLen, outOff, outLen)` runs the two §2.3 derive_key passes:
   - Pass 1: `MODE_CV = IV`, `MODE_FLAGS = FLAG_DERIVE_KEY_CONTEXT`, `hashCore(context, ..., CONTEXT_CV, 32)`.
   - Pass 2: `MODE_CV = CONTEXT_CV`, `MODE_FLAGS = FLAG_DERIVE_KEY_MATERIAL`, `hashCore(material, ..., outOff, outLen)`.
- [ ] After pass 2 `deriveKey` zeros `CONTEXT_CV` (32 B) so the derived intermediate does not linger between successive `deriveKey` invocations on the same module instance.
- [ ] `hashCore(inputOff, inputLen, outOff, writeLen)` takes the single-chunk path when `inputLen ≤ 1024` (§2.4 single-chunk root): one chunk init, sequential `chunkUpdate` blocks of up to 64 bytes, `chunkFinalize(..., isRootSoloChunk = true)`. ROOT lives on the chunk's final compress.
- [ ] The single-chunk path mirrors `COMPRESS_OUT[0..63]` to `ROOT_OUT_SCRATCH` so the first-block emit path is uniform across single-chunk and multi-chunk inputs.
- [ ] `hashCore` takes the multi-chunk path when `inputLen > 1024`: `treeInit`, then loop emitting `chunkInit` / `chunkUpdate` × N / `chunkFinalize(..., false)` followed by `treePushChunk(...)`. The chunk counter is advanced from 0; the §2.4 `t` for compress K is `chunkIdx` at the K-th chunk.
- [ ] After the chunk loop the multi-chunk path fires `treeFinalizeRoot(ROOT_OUT_SCRATCH)`, which writes the 64-byte root output to scratch.
- [ ] For `writeLen > 64` the loop fires `squeezeRootBlock(counter, ROOT_OUT_SCRATCH)` with counter = 1, 2, ... and copies up to 64 bytes per iteration into the output region. Per BLAKE3 §2.6 the root counter increments for each additional output block; counter 0 is consumed by the initial root compress.
- [ ] `squeezeXofBlock(counterLo, counterHi, outOff)` re-fires the root compress from `ROOT_STATE_*` and writes 64 bytes to `outOff`. The export is gated for the TS `BLAKE3OutputReader` and exercised through it.

## TS Validation (`src/ts/blake3/validate.ts`)

- [ ] `validateKey(key)` throws `TypeError` when `key` is not a `Uint8Array`.
- [ ] `validateKey(key)` throws `RangeError` when `key.length !== 32`; the error message names the actual length received.
- [ ] `validateContext(context)` accepts `string` (UTF-8 encoded here) or `Uint8Array` (passed through). Other types throw `TypeError`.
- [ ] `validateContext(context)` throws `RangeError` on an empty context (string `''` or zero-length `Uint8Array`); per BLAKE3 §2.3 an empty context defeats the domain-separation property.
- [ ] `validateContext(context)` does NOT impose an upper-cap on context length. Caller-trust without hard caps matches xero's substrate-code preference; a long context is a design smell but not a spec violation.
- [ ] `validateOutputLen(outLen)` throws `RangeError` when `outLen` is non-number, non-finite, non-integer, NaN, or `Infinity`.
- [ ] `validateOutputLen(outLen)` throws `RangeError` when `outLen < 1`.
- [ ] `validateOutputLen(outLen)` does NOT cap the per-call output. The caller-facing one-shot ceiling of 1024 bytes is enforced separately in `src/ts/blake3/index.ts` so the validator stays usable for the streaming-XOF read path too.

## TS Public Surface (`src/ts/blake3/index.ts`)

- [ ] `BLAKE3.hash(msg, outLen?)`, `BLAKE3KeyedHash.hash(key, msg, outLen?)`, and `BLAKE3DeriveKey.derive(context, material, outLen?)` each call `_assertNotOwned('blake3')` before any WASM access.
- [ ] Each one-shot method validates its caller inputs (type / size) before staging anything to WASM memory.
- [ ] Each one-shot method enforces the 1024-byte one-shot output ceiling (`OUTPUT_STAGING_SIZE`) and throws `tooBigForOneShotError` for larger requests; the error message routes the caller to `finalizeXof()` and `BLAKE3OutputReader.read(n)`.
- [ ] Each one-shot method enforces the per-call input ceiling of 114688 bytes (`INPUT_SCRATCH_MAX`) via `stageInput`; the error message routes the caller to the streaming surface.
- [ ] `oneShotHash` wipes the input scratch region in its `finally` and calls `x.wipeBuffers()` on the way out.
- [ ] `oneShotKeyedHash` zeros the 32-byte `KEYED_KEY` slot in `finally` in addition to the input wipe and `wipeBuffers()`.
- [ ] `oneShotDeriveKey` zeros the contiguous `[ctxOff, matOff + materialLen)` region in `finally` (covers both the context and material staging) plus `wipeBuffers()`.
- [ ] `BLAKE3Stream`, `BLAKE3KeyedHashStream`, and `BLAKE3DeriveKeyStream` all acquire `_acquireModule('blake3')` in their constructor and release it on `dispose()` / `finalize()` / `finalizeXof()` (via the transfer path).
- [ ] Each streaming class throws on `update()` after `finalize()` / `finalizeXof()` and on any method call against a disposed instance.
- [ ] Each streaming class enforces the running-length cap (`INPUT_SCRATCH_MAX = 114688`) via `StreamState.pushChunk`. The error names the per-call WASM input scratch size and routes the caller.
- [ ] `BLAKE3KeyedHashStream` keeps a defensive 32-byte copy of the key; the caller's key buffer is untouched and the instance-owned copy is wiped on `dispose()` / `finalize()` / on transfer to a `BLAKE3OutputReader`.
- [ ] `BLAKE3DeriveKeyStream` encodes the context once at construction (via `validateContext`) and reuses it for every subsequent operation; finalizing the stream re-stages `ctx || material` into the input scratch in that order, matching the §2.3 derive_key two-pass driver in `deriveKey`.
- [ ] `finalizeXof()` transfers the module exclusivity token from the streaming instance to the new `BLAKE3OutputReader` without releasing-then-reacquiring, so no race opens between streams.
- [ ] `BLAKE3OutputReader.read(n)` validates `n` via `validateOutputLen`, populates the WASM-side `ROOT_STATE_*` snapshot on its first call by running the underlying hash entry, and squeezes additional 64-byte blocks via `squeezeXofBlock` with an incrementing counter (starting at 1, since counter 0 was consumed by the snapshot-population call).
- [ ] `BLAKE3OutputReader._populate` does NOT call `wipeBuffers()` (which would clobber `ROOT_STATE_*`); it wipes the input scratch and the output staging slot for that one block, and the reader owns module exclusivity for its lifetime so no other instance can clobber the snapshot.
- [ ] `BLAKE3OutputReader.dispose()` wipes `_blockBuf`, the instance key copy if present, calls `x.wipeBuffers()`, and releases module exclusivity.
- [ ] `BLAKE3Hash.digest(msg)` calls `_assertNotOwned('blake3')`, runs a one-shot 32-byte hash, and returns the bytes. No state, no exclusivity hold.
- [ ] All `dispose()` paths are idempotent and never throw (the inner `wipeBuffers()` call is wrapped in `try / catch {}` where the lifecycle is teardown-safe).

## Memory Hygiene

`wipeBuffers()` zeroes every mutable region of the BLAKE3 WASM module
in one pass (`memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)`),
covering the regions below. The TS wrapper's `dispose()` paths call
`wipeBuffers()`, and one-shot methods call it on every `finally`.

- [ ] `INPUT_STAGING` (caller input residue) is zeroed.
- [ ] `OUTPUT_STAGING` (XOF / one-shot output staging) is zeroed.
- [ ] Working compress slots (`CV` / `MSG` / `COUNTER` / `BLOCK_LEN` / `FLAGS` / `COMPRESS_OUT`) are zeroed.
- [ ] `KEYED_KEY` (32-byte §2.3 keyed_hash key) is zeroed.
- [ ] `DERIVE_CV` (derive_key intermediate stage) is zeroed.
- [ ] `LEVEL_QUEUES` (54 × 9 × 32 bytes of per-level pending CVs) is zeroed.
- [ ] `LEVEL_COUNTS` (54 × 4 bytes of per-level i32 counts) is zeroed.
- [ ] `COMPRESS4_*` staging buffers (CV / MSG / CTR / OUT / BLEN / FLAGS) are zeroed.
- [ ] Chunk-state slots (`CHUNK_INDEX` / `CHUNK_BLOCKS` / `CHUNK_PENDING_LEN` / `CHUNK_PENDING_BLOCK`) are zeroed.
- [ ] Tree-state slots (`TREE_PARENT_BLOCK` / `CHUNK_CV_SCRATCH` / `ROOT_OUT_SCRATCH`) are zeroed.
- [ ] `MODE_CV` (per-mode starting CV; holds key bytes in keyed_hash mode and context CV in derive_key pass 2) is zeroed.
- [ ] `MODE_FLAGS` is zeroed.
- [ ] `CONTEXT_CV` (derive_key pass-1 output) is zeroed; additionally, `deriveKey` explicitly zeroes this slot between successive invocations even when `wipeBuffers()` is not called between them.
- [ ] `ROOT_STATE_*` (XOF snapshot) is zeroed.
- [ ] The AS data segment (offsets 0..MUTABLE_START-1) is NOT wiped. It holds the SIGMA-style read-only tables.
- [ ] Per-class `dispose()` wipe coverage is asserted in `test/unit/blake3/blake3-wipe.test.ts`.

## Constant-Time Considerations

- [ ] BLAKE3's compress is straight-line ARX over a fixed schedule. No conditional branches inside the compression rounds; no key-indexed memory accesses; no secret-dependent loop bounds.
- [ ] `keyed_hash` mode loads the 32-byte key directly into the chunk machine's starting CV (`MODE_CV`). The key bytes are XOR-mixed and added into the state on every round but never select a code path or memory index.
- [ ] `derive_key` mode loads the context bytes through the same chunk pipeline as ordinary input bytes; no branch reads the context as a secret.
- [ ] The chunk machine's one-block lookahead branches on `pendingLen > 0`, which is purely a function of public structure (how many `chunkUpdate` calls have fired and with what `blockLen`). Not secret-derived.
- [ ] The tree-mode queue-per-level cascade branches on `count[L] >= 8` (push) and `count[L] >= 2` (finalize), which are functions of `totalChunks` (the public input length divided by 1024) only. Not secret-derived.
- [ ] The §2.6 XOF squeeze loop branches on the requested output length, which is a public, caller-specified value.

## Side Channels

- [ ] **Timing side channels.** BLAKE3 has no key-dependent branches and no key-indexed table lookups by algorithm design. Timing equalization at the CPU level is out of scope for v3 hashing modules, consistent with the sha2 / sha3 stance. The published BLAKE3 / BLAKE2 cryptanalysis literature does not report timing-side-channel weaknesses in the ARX round structure.
- [ ] **Cache side channels.** No data-dependent table lookups exist in the compress kernel. The SIGMA table is indexed by the round number (a public loop counter), not by secret data. The `BLAKE3_IV*` constants are inlined into the source.
- [ ] **Power and EM.** Out of scope per [architecture.md §Where defense ends](./architecture.md#where-defense-ends).
- [ ] **Fault attacks.** Out of scope for v3 hashing modules.

## Test Coverage

- [ ] `test/unit/blake3/blake3-compress.test.ts` covers the v128-internal `compress` against a single-block KAT (the gate, BLAKE3 §2.2 empty-input compression).
- [ ] `test/unit/blake3/blake3-kat.test.ts` covers all 35 records of the upstream BLAKE3 KAT corpus for default-mode `hash` (asserts first 32 bytes of the upstream `hashHex`).
- [ ] `test/unit/blake3/blake3-compress4-equiv.test.ts` cross-checks `compress4` output against 4 × `compress` over randomized inputs (64+ iterations) and asserts byte-for-byte equality across all four lanes.
- [ ] `test/unit/blake3/blake3-compress4-dispatch.test.ts` asserts `hashCore` actually dispatches multi-chunk inputs (≥ 4096 bytes) through `chunkBatch4`, with exact-count assertions for representative sizes and KAT regression on every upstream record with `inputLen >= 4096`.
- [ ] `test/unit/blake3/blake3-parent-dispatch.test.ts` asserts `treePushChunk` actually dispatches parent merges through `parentBatch4` for inputs producing ≥ 8 chunks (queue-per-level cascade), with exact-count assertions at 4096 / 7168 / 8192 / 16384 / 32768 / 65536 byte inputs and KAT regression on every upstream record with `inputLen >= 8192`.
- [ ] `test/unit/blake3/blake3-keyed-hash.test.ts` covers `hashKeyed` against all 35 upstream KAT records using the upstream test key, asserting the first 32 bytes of `keyedHashHex`.
- [ ] `test/unit/blake3/blake3-derive-key.test.ts` covers `deriveKey` against all 35 upstream KAT records using the upstream test context string, asserting the first 32 bytes of `deriveKeyHex`.
- [ ] `test/unit/blake3/blake3-surface.test.ts` covers the TS public surface for the three one-shot classes (`BLAKE3`, `BLAKE3KeyedHash`, `BLAKE3DeriveKey`) including the `BLAKE3Hash` Fortuna const round-trip.
- [ ] `test/unit/blake3/blake3-tree-internals.test.ts` drives the `_testChunkCV`, `_testParentCV`, and `_testDeriveContextCV` exports against a curated corpus of single-chunk / multi-chunk / power-of-2 / non-power-of-2 inputs across all three modes.
- [ ] `test/unit/blake3/blake3-streaming.test.ts` covers streaming-vs-one-shot equivalence across 10+ size regimes for `BLAKE3Stream`, `BLAKE3KeyedHashStream`, and `BLAKE3DeriveKeyStream`, plus the streaming lifecycle (update-after-finalize, double-dispose, dispose-while-reader-live).
- [ ] `test/unit/blake3/blake3-xof.test.ts` covers full 131-byte XOF assertions across all 105 corpus records (35 × 3 modes) via `BLAKE3OutputReader`, including reads that cross the 64-byte block boundary.
- [ ] `test/unit/blake3/blake3-large-input.test.ts` cross-checks `BLAKE3.hash`, `BLAKE3KeyedHash.hash`, and `BLAKE3DeriveKey.derive` against a Rust oracle (RustCrypto `blake3 = "=1.8.5"`) for input sizes spanning 1 KiB to 16 MiB; the expected hex values are precomputed by `scripts/verify-vectors/` and pinned in `test/vectors/`.
- [ ] `test/unit/blake3/blake3-wipe.test.ts` asserts that every public `dispose()` and one-shot `finally` path zeroes the regions covered in the [Memory Hygiene](#memory-hygiene) section.
- [ ] `test/unit/blake3/blake3-validation.test.ts` covers every validate.ts throw path: bad key length / type, empty context, bad context type, bad outLen (negative, zero, NaN, Infinity, non-integer), oversize input, oversize one-shot output, post-finalize update, double-dispose, exclusivity guard violations.

## Open Audit Items

- **Verified streaming output.** Bao verified streaming (a BLAKE3 §6
  proof-system extension) is not implemented in this phase. Deferred to
  Phase 7 alongside the `src/ts/merkle/blake3-log.ts` log-proof
  substrate, which will consume `_testChunkCV` / `_testParentCV`.

- **OutputReader seek.** The `BLAKE3OutputReader` reads sequentially
  forward. BLAKE3 §2.6 allows arbitrary seek into the XOF stream by
  re-firing the root compress with a target counter, but the reader's
  public surface does not expose seek. Deferred; consumers that need
  random-access XOF can dispose the reader and re-finalize the
  underlying stream.

- **`compress8`.** Deferred. WebAssembly SIMD is fixed at 128-bit
  vectors; a `compress8` over two physical registers per state word
  would double the register pressure without doubling the parallelism.
  Revisit when wide-SIMD WebAssembly lands.

---

## Cross-References

| Document                                  | Description                                                                  |
| ----------------------------------------- | ---------------------------------------------------------------------------- |
| [blake3](./blake3.md)                     | BLAKE3 TypeScript API reference.                                              |
| [asm_blake3](./asm_blake3.md)             | BLAKE3 WASM module reference: buffer layout, exports, SIMD dispatch.          |
| [architecture](./architecture.md)         | Module structure, init contract, and the cross-module overview.               |
| [vector_audit](./vector_audit.md)         | Test-vector tier classification and verifier coverage.                        |
| [audits](./audits.md)                     | Project audit index.                                                          |
| [BLAKE3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) | The BLAKE3 specification.                       |
