<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### BLAKE3: Fast Tree-Mode Cryptographic Hash, Keyed Hash, and KDF

A SIMD-only BLAKE3 binding covering all three modes from the BLAKE3
specification (§2.3 Modes): `hash`, `keyed_hash`, and `derive_key`.
Each mode ships as a one-shot class and a streaming class with an XOF
reader (§2.6 Extendable Output). A stateless `HashFn` const plugs
BLAKE3-256 into the Fortuna substrate.

> ### Table of Contents
> - [Overview](#overview)
> - [Module Init](#module-init)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Usage Examples](#usage-examples)
> - [Error Conditions](#error-conditions)
> - [Dispatch coverage](#dispatch-coverage)
> - [Cross-References](#cross-references)

---

## Overview

BLAKE3 is a tree-mode cryptographic hash function published in 2020 by
Aumasson, Neves, Wilcox-O'Hearn, and Williamson. It descends from BLAKE2
through Bao's Merkle-tree mode and supersedes the BLAKE2 family for new
designs. Three modes share one chunk / tree machine, differing only in
the starting chaining value and the per-compress mode-flag bits.

leviathan ships BLAKE3 as an independent WASM module (`blake3.wasm`)
sitting alongside `sha2.wasm` and `sha3.wasm` in the hash tier. The
module is SIMD-only: a v128-internal `compress1` for single-block work,
and a v128-external lane-parallel `compress4` for batches of four
independent compressions. No scalar fallback ships; runtimes without
WebAssembly SIMD fail loudly at `init()`.

This binding covers:

- **Default-mode hash (§2.3 `hash`).** `BLAKE3`, `BLAKE3Stream`. Variable-
  length XOF output via the §2.6 root-compress squeeze.
- **Keyed hash (§2.3 `keyed_hash`).** `BLAKE3KeyedHash`,
  `BLAKE3KeyedHashStream`. The 32-byte key seeds the chunk machine in
  place of the IV.
- **derive_key (§2.3 `derive_key`).** `BLAKE3DeriveKey`,
  `BLAKE3DeriveKeyStream`. Two-pass KDF with a domain-separating context
  string.
- **XOF reader.** `BLAKE3OutputReader` for unbounded XOF reads.
- **Fortuna HashFn.** `BLAKE3Hash` const for use as a Fortuna accumulator
  hash.

BLAKE3 is not a NIST-approved primitive. The library ships it as a
performance-tier hash for transcripts, content-addressed storage, and
KDF-style work where the cryptanalytic posture of BLAKE2 / BLAKE3 is
acceptable. Use SHA-2 or SHA-3 when an approved primitive is mandated.

---

## Module Init

```typescript
import { init }       from 'leviathan-crypto'
import { blake3Wasm } from 'leviathan-crypto/blake3/embedded'

await init({ blake3: blake3Wasm })
```

BLAKE3 has no module dependencies. The binding does not touch `sha2`,
`sha3`, or any other module. Pure-BLAKE3 work needs only the `blake3`
slot.

For tree-shakeable imports the `leviathan-crypto/blake3` subpath exports
a standalone init function:

```typescript
import { blake3Init } from 'leviathan-crypto/blake3'
import { blake3Wasm } from 'leviathan-crypto/blake3/embedded'

await blake3Init(blake3Wasm)
```

`blake3Init(source)` initializes only the blake3 WASM binary. Calling
any `BLAKE3*` class before `blake3` is initialized throws a clear error
naming the missing module.

BLAKE3 requires WebAssembly SIMD. Runtimes without SIMD support throw at
`init()` time, identical to the serpent, chacha20, aes, kyber, and mldsa
modules. There is no scalar fallback.

---

## Security Notes

> [!CAUTION]
> BLAKE3 is not a NIST-approved primitive. Do not use it where a
> regulator, audit standard, or protocol spec mandates SHA-2 or SHA-3.
> Reach for `SHA256`, `SHA512`, or the SHA-3 family in those contexts.

> [!IMPORTANT]
> `keyed_hash` requires a 32-byte key, BLAKE3 §2.3 Modes. The key is loaded
> directly as the starting chaining value with no internal derivation
> or stretching, so the key must already be uniformly random and at
> least 256 bits of entropy. Passwords and other low-entropy material
> need a password-hashing KDF (Argon2id) first.

> [!IMPORTANT]
> `derive_key` context strings should be compile-time-constant per
> application, BLAKE3 §2.3 Modes. Runtime-variable contexts defeat the domain
> separation the mode is designed to provide. The library validates
> that the context is non-empty but does not (and cannot) check that
> it is hardcoded.

> [!CAUTION]
> `BLAKE3OutputReader` holds exclusive access to the `blake3` module
> for its full lifetime. Other BLAKE3 classes will throw on
> construction until the reader is disposed. Read the bytes you need,
> then call `dispose()` promptly.

> [!IMPORTANT]
> The one-shot per-call output ceiling is 1024 bytes (the WASM
> OUTPUT_STAGING region). For larger XOF reads, use `finalizeXof()`
> on a streaming class and pull bytes from the returned
> `BLAKE3OutputReader`. Per-call input is capped at 114688 bytes; for
> larger inputs use the streaming surface.

> [!NOTE]
> BLAKE3's compress is straight-line ARX over a fixed message schedule,
> so it has no key-dependent branches and no key-indexed table lookups.
> The construction is algorithm-level constant-time at the same level
> as ChaCha20. See [architecture.md §Where defense ends](./architecture.md#where-defense-ends)
> for hardware-level scope.

---

## API Reference

### `BLAKE3`

One-shot default-mode hash, BLAKE3 §2.3 Modes (`hash`). No module exclusivity (each
call acquires and releases internally).

| Method                              | Returns      | Notes                                                                     |
| ----------------------------------- | ------------ | ------------------------------------------------------------------------- |
| `hash(msg, outLen?)`                | `Uint8Array` | `outLen` defaults to 32. One-shot ceiling: 1024 bytes per call.           |
| `dispose()`                         | `void`       | Defence-in-depth wipe. Idempotent. Never throws.                          |

### `BLAKE3Stream`

Streaming default-mode hash, BLAKE3 §2.3 Modes (`hash`). Holds the `blake3` module
exclusivity token from construction until `finalize()` / `finalizeXof()`
/ `dispose()`.

| Method                              | Returns                | Notes                                                                                           |
| ----------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------- |
| `update(chunk)`                     | `this`                 | Buffers `chunk` for the eventual finalize. Throws on chunk after finalize.                     |
| `finalize(outLen?)`                 | `Uint8Array`           | Default `outLen = 32`. One-shot ceiling: 1024 bytes. Disposes the instance.                    |
| `finalizeXof()`                     | `BLAKE3OutputReader`   | Transfers module exclusivity to the reader for unbounded XOF reads.                            |
| `dispose()`                         | `void`                 | Releases module exclusivity, wipes scratch. Idempotent.                                         |

### `BLAKE3KeyedHash`

One-shot keyed_hash, BLAKE3 §2.3 Modes.

| Method                              | Returns      | Notes                                                                     |
| ----------------------------------- | ------------ | ------------------------------------------------------------------------- |
| `hash(key, msg, outLen?)`           | `Uint8Array` | `key` must be exactly 32 bytes. `outLen` defaults to 32, ceiling 1024.    |
| `dispose()`                         | `void`       | Defence-in-depth wipe. Idempotent. Never throws.                          |

### `BLAKE3KeyedHashStream`

Streaming keyed_hash, BLAKE3 §2.3 Modes. The 32-byte key is bound at
construction and copied into instance-owned storage; the caller's key
buffer is left untouched. Holds module exclusivity until finalize /
dispose.

| Method                              | Returns                | Notes                                                                                          |
| ----------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------- |
| `constructor(key)`                  | `BLAKE3KeyedHashStream`| `key` must be exactly 32 bytes.                                                                |
| `update(chunk)`                     | `this`                 | Buffers `chunk` for the eventual finalize.                                                     |
| `finalize(outLen?)`                 | `Uint8Array`           | Default `outLen = 32`. Wipes the instance key on the way out.                                  |
| `finalizeXof()`                     | `BLAKE3OutputReader`   | Transfers module exclusivity and a key copy to the reader.                                     |
| `dispose()`                         | `void`                 | Wipes the instance key, releases module exclusivity. Idempotent.                               |

### `BLAKE3DeriveKey`

One-shot derive_key, BLAKE3 §2.3 Modes.

| Method                              | Returns      | Notes                                                                                  |
| ----------------------------------- | ------------ | -------------------------------------------------------------------------------------- |
| `derive(context, material, outLen?)`| `Uint8Array` | `context` is a string (UTF-8 encoded) or `Uint8Array`. Non-empty required. Ceiling 1024. |
| `dispose()`                         | `void`       | Defence-in-depth wipe. Idempotent. Never throws.                                       |

### `BLAKE3DeriveKeyStream`

Streaming derive_key, BLAKE3 §2.3 Modes. Context is bound at construction and
encoded once; `update()` streams the material; `finalize()` runs the
two-pass derive.

| Method                              | Returns                | Notes                                                                                          |
| ----------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------- |
| `constructor(context)`              | `BLAKE3DeriveKeyStream`| `context` is a string or `Uint8Array`. Non-empty required.                                      |
| `update(chunk)`                     | `this`                 | Buffers material chunks for finalize.                                                          |
| `finalize(outLen?)`                 | `Uint8Array`           | Default `outLen = 32`. Disposes the instance.                                                  |
| `finalizeXof()`                     | `BLAKE3OutputReader`   | Transfers module exclusivity to the reader for unbounded derive-key XOF reads.                 |
| `dispose()`                         | `void`                 | Releases module exclusivity, wipes scratch. Idempotent.                                         |

### `BLAKE3OutputReader`

XOF reader, BLAKE3 §2.6 Extendable Output. Constructed by `finalizeXof()` on any
streaming class. Holds module exclusivity until `dispose()`. Cannot be
constructed directly by consumer code.

| Method                              | Returns       | Notes                                                                                            |
| ----------------------------------- | ------------- | ------------------------------------------------------------------------------------------------ |
| `read(nBytes)`                      | `Uint8Array`  | Sequential reads pull the next `nBytes` from the XOF stream. Reads can cross 64-byte boundaries. |
| `dispose()`                         | `void`        | Wipes the block cache and any stored key, releases module exclusivity. Idempotent.               |

### `BLAKE3Hash`

Stateless BLAKE3-256 `HashFn` const. Shape mirrors `SHA256Hash` and
`SHA3_256Hash`: 32-byte fixed output, single WASM module dependency
(`['blake3']`), one-shot `digest(msg)`. Pluggable into the Fortuna
`HashFn` slot.

| Field / Method                      | Value / Returns | Notes                                                                                  |
| ----------------------------------- | --------------- | -------------------------------------------------------------------------------------- |
| `outputSize`                        | `32`            | BLAKE3 default output length.                                                          |
| `wasmModules`                       | `['blake3']`    | Required init slot.                                                                    |
| `digest(msg)`                       | `Uint8Array`    | 32-byte BLAKE3 hash. No exclusivity hold; safe to call from `Fortuna` reseed paths.    |

### `blake3Init`

Standalone tree-shakeable init for the `blake3` module.

| Signature                           | Notes                                                                              |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| `blake3Init(source: WasmSource)`    | Initializes only the `blake3` WASM binary. Idempotent. Throws if SIMD unavailable. |

---

## Usage Examples

### `BLAKE3`, default-mode hash

```typescript
import { init, BLAKE3 } from 'leviathan-crypto'
import { blake3Wasm }   from 'leviathan-crypto/blake3/embedded'

await init({ blake3: blake3Wasm })

const h      = new BLAKE3()
const digest = h.hash(new TextEncoder().encode('hello world'))   // 32 bytes
h.dispose()
```

### `BLAKE3Stream`, streaming hash

```typescript
import { init, BLAKE3Stream } from 'leviathan-crypto'
import { blake3Wasm }         from 'leviathan-crypto/blake3/embedded'

await init({ blake3: blake3Wasm })

const s = new BLAKE3Stream()
s.update(chunkA).update(chunkB).update(chunkC)
const digest = s.finalize()   // 32 bytes by default; disposes the stream
```

### `BLAKE3KeyedHash`, MAC

```typescript
import { init, BLAKE3KeyedHash, randomBytes } from 'leviathan-crypto'
import { blake3Wasm } from 'leviathan-crypto/blake3/embedded'

await init({ blake3: blake3Wasm })

const key = randomBytes(32)
const mac = new BLAKE3KeyedHash()
const tag = mac.hash(key, message)
mac.dispose()
```

### `BLAKE3DeriveKey`, application KDF

```typescript
import { init, BLAKE3DeriveKey } from 'leviathan-crypto'
import { blake3Wasm }            from 'leviathan-crypto/blake3/embedded'

await init({ blake3: blake3Wasm })

// Context string is a hardcoded application constant per BLAKE3 §2.3.
const CONTEXT = '2026-05 example.app session keys v1'

const kdf       = new BLAKE3DeriveKey()
const sessionKey = kdf.derive(CONTEXT, sharedSecret, 32)
kdf.dispose()
```

### `BLAKE3Stream` + `BLAKE3OutputReader`, unbounded XOF

```typescript
import { init, BLAKE3Stream } from 'leviathan-crypto'
import { blake3Wasm }         from 'leviathan-crypto/blake3/embedded'

await init({ blake3: blake3Wasm })

const s = new BLAKE3Stream()
s.update(transcript)
const reader = s.finalizeXof()
try {
    const head = reader.read(64)
    const tail = reader.read(4096)
    // ... continue reading as needed
} finally {
    reader.dispose()
}
```

### `BLAKE3Hash` with `Fortuna`

```typescript
import { init, Fortuna, BLAKE3Hash, SerpentGenerator } from 'leviathan-crypto'
import { blake3Wasm }  from 'leviathan-crypto/blake3/embedded'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await init({ blake3: blake3Wasm, serpent: serpentWasm })

const rng = await Fortuna.create({
    generator: new SerpentGenerator(),
    hash:      BLAKE3Hash,
})
const bytes = rng.get(64)
```

---

## Error Conditions

| Condition                                                  | Method(s)                                                                | Thrown                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `init({ blake3 })` not called                              | All `BLAKE3*` constructors and `BLAKE3Hash.digest`                       | `Error: leviathan-crypto: call init({ blake3: ... }) before using BLAKE3 classes`            |
| Another instance holds module exclusivity                  | All `BLAKE3*` non-stream methods                                         | `Error: leviathan-crypto: another stateful instance is using the 'blake3' WASM module ...`   |
| Non-`Uint8Array` message                                   | `BLAKE3.hash`, `BLAKE3KeyedHash.hash`, `BLAKE3DeriveKey.derive`          | `TypeError: leviathan-crypto: blake3 message must be a Uint8Array`                            |
| Wrong-size key                                             | `BLAKE3KeyedHash.hash`, `BLAKE3KeyedHashStream` constructor              | `RangeError: leviathan-crypto: blake3 key must be 32 bytes (got N)`                          |
| Non-`Uint8Array` key                                       | `BLAKE3KeyedHash.hash`, `BLAKE3KeyedHashStream` constructor              | `TypeError: leviathan-crypto: blake3 key must be a Uint8Array`                                |
| Bad context type                                           | `BLAKE3DeriveKey.derive`, `BLAKE3DeriveKeyStream` constructor            | `TypeError: leviathan-crypto: blake3 derive_key context must be a string or Uint8Array`      |
| Empty context                                              | `BLAKE3DeriveKey.derive`, `BLAKE3DeriveKeyStream` constructor            | `RangeError: ... blake3 derive_key context must be non-empty ...`                            |
| `outLen` non-integer, negative, zero, NaN, Infinity        | All `hash` / `derive` / `finalize` / `read`                              | `RangeError: leviathan-crypto: blake3 outLen must be a finite integer (got X)` / `... >= 1`  |
| `outLen` > 1024 (one-shot ceiling)                         | All `hash` / `derive` / `finalize`                                       | `RangeError: ... blake3 outLen N exceeds the per-call output staging size (1024 bytes) ...`  |
| Input length > 114688 (one-shot scratch ceiling)           | All one-shot and streaming-with-buffered-input paths                     | `RangeError: ... blake3 input length N exceeds the per-call WASM input scratch ...`          |
| Non-`Uint8Array` chunk                                     | `BLAKE3Stream.update` and the keyed / derive equivalents                 | `TypeError: BLAKE3 stream: chunk must be a Uint8Array`                                       |
| `update()` after `finalize()` / `finalizeXof()`            | All `BLAKE3*Stream.update`                                               | `Error: BLAKE3 stream: update() after finalize/finalizeXof`                                  |
| Any method on a disposed stream                            | All `BLAKE3*Stream` methods                                              | `Error: BLAKE3Stream: instance has been disposed` (or `BLAKE3KeyedHashStream` / `BLAKE3DeriveKeyStream` equivalent) |
| Any method on a disposed reader                            | `BLAKE3OutputReader.read`                                                | `Error: BLAKE3OutputReader: instance has been disposed`                                       |

---

## Dispatch coverage

The BLAKE3 SIMD hot paths (`compress4` driving chunk-level and
parent-level batches) carry dispatch-coverage tests that confirm the
kernel actually fires for inputs that should hit it, not just
KAT-equivalence on small inputs.

### Tree-level (parent merge) dispatch

`test/unit/blake3/blake3-parent-dispatch.test.ts` proves the
multi-chunk hash hot path drives parent merges through the
v128-external `compress4` kernel (via `parentBatch4` in
`src/asm/blake3/tree_simd.ts`) for inputs producing >= 8 chunks.

The queue-per-level discipline in `src/asm/blake3/tree.ts` defers
push-time merges: a chunk CV lands in level 0's queue, and when a
level's queue reaches 8 entries `parentBatch4` batches 4 parent
merges in parallel. The 4 outputs propagate to the next level's
queue, possibly cascading further batches at upper levels.

The WASM module carries a test-only `parentBatch4` invocation counter
held as a WASM global, not in linear memory, so `wipeBuffers()` does
not clear it. Each exact-count assertion resets the counter, fires a
hash, and verifies the counter equals the predicted cascade depth for
that input size.

Predicted cascade per input size (chunks = ceil(inputLen / 1024)):

| Input bytes | Chunks | Batches | Where |
|---|---|---|---|
| 4096  | 4  | 0  | count[0] stays <= 7 |
| 7168  | 7  | 0  | count[0] stays <= 7 |
| 8192  | 8  | 1  | L=0 (push 8 cascades to count[1]=4) |
| 16384 | 16 | 3  | 2 at L=0 (pushes 8 and 16), 1 at L=1 when count[1] reaches 8 |
| 32768 | 32 | 7  | 4 at L=0, 2 at L=1, 1 at L=2 |
| 65536 | 64 | 15 | 8 at L=0, 4 at L=1, 2 at L=2, 1 at L=3 |

A KAT regression over every upstream corpus record with
`inputLen >= 8192` confirms the queue-per-level discipline produces
byte-identical output to the prior ctz-stack implementation. The
BLAKE3 §2.5 reorganisation changes WHEN merges happen, not WHAT they
compute, so KAT regression is the bit-correctness gate.

### Chunk-level dispatch

`test/unit/blake3/blake3-compress4-dispatch.test.ts` proves the
multi-chunk hash hot path in `hashCore` (`src/asm/blake3/index.ts`)
actually dispatches 4-chunk batches through the v128-external
`compress4` kernel for inputs >= 4096 bytes, rather than silently
falling through to the per-block single-chunk path.

The WASM module carries a test-only `chunkBatch4` invocation counter
held as a WASM global, not in linear memory, so `wipeBuffers()` does
not clear it. Each assertion resets the counter, fires a hash, and
verifies the counter reflects the expected number of 4-chunk batches.

A KAT regression over every upstream corpus record with
`inputLen >= 4096` confirms the dispatch produces bit-identical output
to the previous single-chunk implementation. The 35-case KAT corpus
is already gated by `test/unit/blake3/blake3-kat.test.ts`; the
explicit subset here makes the dispatched-via-compress4 coverage
legible.

### compress4 equivalence

`test/unit/blake3/blake3-compress4-equiv.test.ts` is the
bit-equivalence gate between `compress4` and four sequential
`compress` calls. `compress4` (v128-external SIMD, lane K = compress
operation K) must be bit-identical to four sequential `compress`
calls on the same inputs.

Equivalence is checked across deterministic randomised inputs from a
fixed seed across 64 iterations, exercising independently distributed
CV, message, counter, block_len, and flag values.

If `compress` has already passed its BLAKE3 §2.2 gate against the
BLAKE3 KAT (`test/unit/blake3/blake3-compress.test.ts`), matching
`compress4` to it under random inputs establishes `compress4`'s
correctness without embedding additional cryptographic values in this
file.

---

## Cross-References

| Document                                | Description                                                                  |
| --------------------------------------- | ---------------------------------------------------------------------------- |
| [asm_blake3](./asm_blake3.md)           | BLAKE3 WASM module reference: buffer layout, exports, SIMD dispatch.         |
| [blake3_audit](./blake3_audit.md)       | BLAKE3 implementation audit checklist.                                       |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [lexicon](./lexicon.md)                 | BLAKE3 vocabulary: chunk, CV, XOF, subtree, mode flags.                       |
| [fortuna](./fortuna.md)                 | Pluggable `HashFn` slot that accepts `BLAKE3Hash`.                            |
| [BLAKE3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) | The BLAKE3 specification.                       |
