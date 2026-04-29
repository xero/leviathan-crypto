# `ct` Constant-Time Comparison WASM Module Reference

> [!IMPORTANT]
> This low-level reference details the constant-time byte array
> equality source and WASM exports, intended for those auditing, contributing
> to, or building against the raw module. Most consumers, however, should
> instead use the [TypeScript API](./utils.md#constanttimeequal).

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Memory Layout](#memory-layout)
> - [Internal Architecture](#internal-architecture)
> - [Error Conditions](#error-conditions)

---

## Overview

This module implements constant-time byte array comparison as a standalone WASM binary compiled from a single AssemblyScript source file. It is the backend for `constantTimeEqual` in `utils.ts`.

The module is deliberately minimal. It exports one function and the linear memory it operates on. It has no named buffer slots, no module ID, no `wipeBuffers` — nothing beyond the comparison primitive itself.

Key properties:

**Zero-copy by design.** The module has no internal staging buffers. `compare` takes caller-specified byte offsets directly into linear memory and reads from those positions without duplicating any data. The caller decides the layout; the module performs the comparison in-place.

**No init gate.** This module does not register with the library's `init()` system and does not require an `await`. It compiles and instantiates synchronously via `new WebAssembly.Module(buf)` and `new WebAssembly.Instance(mod)` on first use, cached for subsequent calls.

**SIMD-only.** The binary uses `v128` operations throughout. If `hasSIMD()` returns false, or if compilation fails, the first call to `constantTimeEqual` throws a branded error. There is no scalar WASM variant and no JavaScript fallback.

**Embedded binary.** The compiled WASM bytes are embedded directly in `ct-wasm.ts` as a `Uint8Array`. No file fetch or separate asset load is needed.

**Caller zeroes memory.** After every comparison, the TypeScript wrapper zeroes both input regions via `mem.fill(0, 0, a.length * 2)` in a `finally` block. The module itself does not wipe.

---

## Security Notes

### WASM SIMD constant-time

JS engines can speculatively optimize XOR-accumulate loops in ways that introduce timing variation. V8 and SpiderMonkey may branch-predict or short-circuit bit operations under JIT when they determine that the accumulated value cannot change the outcome. WASM v128 operations do not go through the same scalar JIT passes. The compilation from AssemblyScript source is structurally branch-free: no `br_if` or conditional paths operate on data values; every byte difference accumulates unconditionally into the `v128` or scalar `diff` accumulators; the final zero-test is a branch-free arithmetic reduction.

---

### Length check is not constant-time

`constantTimeEqual` returns false immediately if `a.length !== b.length`. Length is treated as non-secret in all protocols this library implements. The length of a ciphertext, MAC tag, or encoded key is determined by the algorithm and is known to both parties before any secret data is exchanged. If your use case requires hiding array length, you must pad before calling.

---

### Memory zeroing

The TypeScript wrapper zeroes both input regions after every call, including calls that throw. The `finally` block runs `mem.fill(0, 0, a.length * 2)` unconditionally. Key material written into WASM linear memory does not persist past the end of the comparison.

The module itself exports no wipe function. Zeroing is the caller's responsibility; the wrapper handles it correctly.

---

### Return value convention

`compare` returns 1 if the arrays are equal and 0 if they differ. This is the inverse of `ct_verify` in `kyber.wasm`, which returns 0 for equal and 1 for any difference. Do not mix up the two conventions.

---

## API Reference

The module exports two symbols.

### `compare(aOff: i32, bOff: i32, len: i32): i32`

Compares `len` bytes at `aOff` against `len` bytes at `bOff` in WASM linear memory.

- **aOff**: byte offset of the first array
- **bOff**: byte offset of the second array
- **len**: number of bytes to compare
- **Returns**: 1 if all `len` bytes are equal, 0 if any byte differs

The comparison runs in two phases. The SIMD loop processes 16-byte blocks via `v128.xor` and `v128.or` accumulation. A scalar tail handles any remaining bytes. Both phases accumulate differences without branching on data values. The final zero-test is branch-free.

**Preconditions:**
- `aOff + len` must not exceed the linear memory size
- `bOff + len` must not exceed the linear memory size
- `aOff` and `bOff` must not overlap

The TypeScript wrapper enforces all three by layout: it places `a` at offset 0 and `b` at offset `a.length`, making overlap impossible and bounds trivially satisfied.

### `memory`

The exported `WebAssembly.Memory` instance. One page (64KB). The TypeScript wrapper holds a reference as `_ctMem` and writes input arrays into it before calling `compare`.

---

## Memory Layout

The module allocates one page (65536 bytes) of linear memory. The layout is entirely caller-determined; no offsets are hardcoded in the WASM binary itself.

The TypeScript wrapper uses this convention:

| Region | Offset | Size | Content |
|---|---|---|---|
| Array `a` | 0 | `a.length` | First comparison input |
| Array `b` | `a.length` | `a.length` | Second comparison input |
| _(unused)_ | `a.length × 2` | remainder | Zeroed |

Both arrays are placed adjacently starting at offset 0. `compare` is called with `aOff = 0`, `bOff = a.length`, `len = a.length`. After the call, the wrapper zeroes bytes 0 through `a.length * 2`.

The maximum supported input length per side is `CT_MAX_BYTES = 32768` — half the page. In practice the largest comparison in this library is a 32-byte HMAC-SHA-256 tag.

> [!NOTE]
> Because `compare` takes arbitrary offsets, any caller with direct access to the WASM memory can pass different offsets and compare data already resident in linear memory at any position, with no copy at all. The TypeScript wrapper always uses offset 0 as a convenience, but the WASM function places no constraint on where the data lives.

---

## Internal Architecture

The module is a single AssemblyScript file (`src/asm/ct/index.ts`) compiled to a WASM binary embedded in `src/ts/ct-wasm.ts`.

### Algorithm

The comparison runs in three stages.

**Stage 1 — SIMD accumulation.** For each aligned 16-byte block, the loop computes `acc = v128.or(acc, v128.xor(a_block, b_block))`. The accumulator starts as `i8x16.splat(0)`. After all full blocks, any byte difference anywhere in the input sets one or more bits in `acc`. The loop iterates exactly `⌊len / 16⌋` times with no data-dependent branching.

**Stage 2 — Scalar tail.** The remaining `len mod 16` bytes (0 to 15) are processed byte-by-byte: `diff |= load<u8>(aOff + i) ^ load<u8>(bOff + i)`. These accumulate into a 64-bit `diff` integer.

**Stage 3 — Reduction and zero-test.** The v128 accumulator is reduced to a scalar by extracting both i64x2 lanes and OR-ing them into `diff`:
```
diff |= i64x2.extract_lane(acc, 0) | i64x2.extract_lane(acc, 1)
```
Any nonzero byte in the SIMD accumulator survives into a nonzero `diff`. The zero-test then applies the identity `(diff | -diff) >> 63`, which arithmetic-shifts the sign bit of `(diff | -diff)` across the full 64-bit word. `(diff | -diff)` has its sign bit set if and only if `diff != 0`; the shift produces -1 (all bits set) for any nonzero input and 0 for zero. Inverting and masking to the low bit gives `1` for equal and `0` for not:
```
return <i32>(~((diff | -diff) >> 63)) & 1
```

No branch occurs on `diff`, on any lane of `acc`, or on any input byte at any point in the function.

### Instantiation model

`_initCt()` in `utils.ts` handles lazy one-time setup:

1. Returns early if already initialized (`_ctInit` flag).
2. Throws a branded error if `hasSIMD()` is false and caches the error; all subsequent calls re-throw the cached error without retry. The module requires SIMD and has no scalar fallback.
3. Slices the embedded `CT_WASM` byte array to produce an `ArrayBuffer`.
4. Calls `new WebAssembly.Module(buf)` synchronously.
5. Calls `new WebAssembly.Instance(mod)` synchronously.
6. Caches `exports.memory` and `exports.compare`.

The entire path is synchronous. No promise, no `await`, no worker. If SIMD detection fails or either WASM step throws, `_initCt` caches a branded `leviathan-crypto: ct WASM module failed to instantiate: <cause>` error and re-throws on every subsequent call.

`_ctResetForTesting()` clears all cached state, including any cached initialization error, allowing the test suite to force re-instantiation across describe blocks.

---

## Error Conditions

The WASM function itself has no error returns. Out-of-bounds memory access traps the WASM instance (standard WASM behavior), but the TypeScript wrapper prevents this by construction.

| Condition | Behavior |
|---|---|
| `a.length !== b.length` | Returns false before touching WASM. Length check is not constant-time. |
| `a.length > CT_MAX_BYTES` | Throws `RangeError` before touching WASM. |
| SIMD unavailable at init time | Throws `Error: leviathan-crypto: constantTimeEqual requires WebAssembly SIMD — this runtime does not support it`. Cached; subsequent calls re-throw. |
| WASM compile or instantiate throws | Throws `Error: leviathan-crypto: ct WASM module failed to instantiate: <cause>`. Cached; subsequent calls re-throw. |
| WASM memory access out of bounds | Would trap — prevented by the fixed layout enforced in `constantTimeEqual`. |

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [utils](./utils.md) | `constantTimeEqual`, `hasSIMD`, and other utility exports |
| [architecture](./architecture.md) | architecture overview, module relationships, and build pipeline |
| [asm_kyber](./asm_kyber.md) | `ct_verify` and `ct_cmov` in the kyber WASM module (note the inverted return convention) |
| [asm_chacha](./asm_chacha.md) | ChaCha20-Poly1305 WASM module (uses `constantTimeEqual` for tag verification in the TypeScript wrapper) |
