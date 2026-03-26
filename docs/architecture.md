# Leviathan Crypto Library Architecture

> [!NOTE]
> - Version: 1.0.0
> - Package: `leviathan-crypto` (npm, unscoped)
> - Status: v1.0.0 - all four WASM modules (Serpent, ChaCha20, SHA-2, SHA-3) implemented.
> - Supersedes: `leviathan` (TypeScript reference) and `leviathan-wasm` (WASM primitives),
> both of which remain unchanged as development references.

## Vision

`leviathan-crypto` is a strictly-typed, audited WebAssembly cryptography library for
the web. It combines two previously separate efforts:

- **leviathan:**  developer-friendly TypeScript API, strict types, audited against specs
  and known-answer test vectors
- **leviathan-wasm:**  AssemblyScript WASM implementation of the same primitives,
  running outside the JavaScript JIT for predictable execution and practical
  constant-time guarantees

The unified library exposes the TypeScript API from leviathan, backed by the WASM
execution engine from leviathan-wasm. Developers get ergonomic, well-typed classes.
The runtime gets deterministic cryptographic computation outside the JIT.

**The fundamental insight:** JavaScript engines provide no formal constant-time
guarantees for arbitrary code. WASM execution is deterministic and not subject to
JIT speculation. For a cryptography library, this distinction matters. The TypeScript
layer handles API ergonomics; the WASM layer handles all cryptographic computation.

---

## Scope (v1.0)

### In scope

| Module | Primitives |
|--------|-----------|
| `serpent` | Serpent-256 block cipher: ECB, CTR mode, CBC mode |
| `serpent` + `sha2` | `SerpentSeal` (Serpent-CBC + HMAC-SHA256), `SerpentStream` / `SerpentStreamPool` (chunked AEAD), `SerpentStreamSealer` / `SerpentStreamOpener` (incremental streaming AEAD) |
| `chacha20` | ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD |
| `sha2` | SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, HKDF-SHA256, HKDF-SHA512 |
| `sha3` | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 (XOFs, multi-squeeze) |

Pure TypeScript utilities (encoding helpers, random generation, format converters)
ship alongside the WASM-backed primitives with no `init()` dependency.

### Auxiliary tier (not part of `Module` union)

- **`Fortuna`:** CSPRNG requiring two core modules (`serpent` + `sha2`).
  Initialized via the standard `init()` gate.

---

## Repository Structure

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/repo-structure.svg" alt="Repo Structure" width="800">

```
leviathan-crypto/
├── src/
│   ├── asm/                        ← AssemblyScript (compiles to .wasm)
│   │   ├── serpent/
│   │   │   ├── index.ts            ← asc entry point → serpent.wasm
│   │   │   ├── serpent.ts          ← block function + key schedule
│   │   │   ├── serpent_unrolled.ts ← unrolled S-boxes and round functions
│   │   │   ├── cbc.ts              ← CBC mode
│   │   │   ├── ctr.ts              ← CTR mode
│   │   │   └── buffers.ts          ← static buffer layout + offset getters
│   │   ├── chacha/
│   │   │   ├── index.ts            ← asc entry point → chacha.wasm
│   │   │   ├── chacha20.ts
│   │   │   ├── poly1305.ts
│   │   │   ├── wipe.ts
│   │   │   └── buffers.ts
│   │   ├── sha2/
│   │   │   ├── index.ts            ← asc entry point → sha2.wasm
│   │   │   ├── sha256.ts
│   │   │   ├── sha512.ts
│   │   │   ├── hmac.ts
│   │   │   ├── hmac512.ts
│   │   │   └── buffers.ts
│   │   └── sha3/
│   │       ├── index.ts            ← asc entry point → sha3.wasm
│   │       ├── keccak.ts
│   │       └── buffers.ts
│   └── ts/                         ← TypeScript (public API)
│       ├── init.ts                 ← initModule() : WASM loading and module cache
│       ├── loader.ts               ← embedded / streaming / manual loading logic
│       ├── types.ts                ← Hash, KeyedHash, Blockcipher, Streamcipher, AEAD
│       ├── utils.ts                ← encoding, wipe, xor, concat, randomBytes
│       ├── fortuna.ts              ← Fortuna CSPRNG (requires serpent + sha2)
│       ├── embedded/               ← generated base64 files (gitignored, build artifact)
│       │   ├── serpent.ts
│       │   ├── chacha.ts
│       │   ├── sha2.ts
│       │   └── sha3.ts
│       ├── serpent/
│       │   ├── index.ts            ← serpentInit() + Serpent, SerpentCtr, SerpentCbc
│       │   ├── seal.ts             ← SerpentSeal (Serpent-CBC + HMAC-SHA256)
│       │   ├── stream.ts           ← SerpentStream (chunked one-shot AEAD)
│       │   ├── stream-pool.ts      ← SerpentStreamPool (Worker-based parallel AEAD)
│       │   ├── stream-sealer.ts    ← SerpentStreamSealer / SerpentStreamOpener (incremental AEAD)
│       │   ├── stream.worker.ts    ← Web Worker entry point for SerpentStreamPool
│       │   └── types.ts
│       ├── chacha20/
│       │   ├── index.ts            ← chacha20Init() + ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305
│       │   ├── pool.ts             ← XChaCha20Poly1305Pool + PoolOpts
│       │   ├── pool.worker.ts      ← Web Worker entry point (compiled to pool.worker.js; not a subpath export)
│       │   └── types.ts
│       ├── sha2/
│       │   ├── index.ts            ← sha2Init() + SHA256, SHA512, SHA384, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384, HKDF_SHA256, HKDF_SHA512
│       │   └── types.ts
│       ├── sha3/
│       │   ├── index.ts            ← sha3Init() + SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
│       │   └── types.ts
│       └── index.ts                ← root barrel : dispatching init() + re-exports everything
├── test/
│   ├── unit/                       ← Vitest (JS target, fast iteration)
│   │   ├── serpent/
│   │   ├── chacha20/
│   │   ├── sha2/
│   │   ├── sha3/
│   │   └── init.test.ts
│   ├── e2e/                        ← Playwright (WASM target, cross-browser)
│   └── vectors/                    ← test vector files (read-only reference data)
├── build/                          ← WASM build output (gitignored)
├── dist/                           ← npm publish output (gitignored)
├── docs/                           ← project documentation
├── scripts/
│   ├── embed-wasm.ts               ← reads build/*.wasm, generates src/ts/embedded/*.ts
│   ├── build-asm.js                ← orchestrates AssemblyScript compilation
│   ├── gen-seal-vectors.ts         ← generates KAT vectors for SerpentSeal / SerpentStream
│   └── gen-sealstream-vectors.ts   ← generates KAT vectors for SerpentStreamSealer / Opener
├── package.json
├── asconfig.json                   ← four AssemblyScript entry points
├── tsconfig.json
├── vitest.config.ts
└── playwright.config.ts
```

---

## Architecture: TypeScript over WASM

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/arch-layers.svg" alt="Architecture Layers" width="800">

> [!NOTE]
> The TypeScript layer never implements cryptographic algorithms. It handles the
> JS/WASM boundary: writing inputs into WASM linear memory, calling exported
> functions, reading outputs back. All algorithm logic lives in AssemblyScript.
>
> The exception is the Tier 2 composition layer: `SerpentSeal`, `SerpentStream`,
> `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, and `HKDF`.
> These are pure TypeScript, they compose the WASM-backed Tier 1 primitives
> (Serpent-CBC, HMAC-SHA256, HKDF-SHA256) without adding new algorithm logic.

---

## Four Independent WASM Modules

Each primitive family compiles to its own `.wasm` binary. Modules are fully
independent, separate linear memories, separate buffer layouts, no shared state.

| Module | Binary | Primitives |
|--------|--------|------------|
| `serpent` | `serpent.wasm` | Serpent-256 block cipher: ECB, CTR mode, CBC mode |
| `chacha20` | `chacha.wasm` | ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD |
| `sha2` | `sha2.wasm` | SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 |
| `sha3` | `sha3.wasm` | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |

**Benefits:**
1. **Size:** consumers who only use Serpent don't load the SHA-3 binary
2. **Isolation:** key material in `serpent.wasm` memory cannot bleed into
   `sha3.wasm` memory even in theory

Each module's buffer layout starts at offset 0 and is defined in its own
`buffers.ts`. Buffer layouts are fully independent across modules.

### Module contents

**`serpent.wasm`**
Serpent-256 block cipher. Key schedule, block encrypt, block decrypt. CTR mode
chunked streaming encrypt/decrypt. CBC mode chunked encrypt/decrypt.
Source: `src/asm/serpent/`

The serpent TypeScript module also includes a Tier 2 composition layer built on
top of these WASM primitives: `SerpentSeal` (Serpent-CBC + HMAC-SHA256 AEAD),
`SerpentStream` (chunked one-shot AEAD), `SerpentStreamPool` (Worker-based
parallel AEAD), and `SerpentStreamSealer` / `SerpentStreamOpener` (incremental
streaming AEAD). All Tier 2 classes use HKDF-SHA256 for per-chunk key derivation
and require both `serpent` and `sha2` to be initialized.

**`chacha.wasm`**
ChaCha20 stream cipher (RFC 8439). Poly1305 MAC (RFC 8439 §2.5). ChaCha20-Poly1305
AEAD (RFC 8439 §2.8). XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha).
HChaCha20 subkey derivation.
Source: `src/asm/chacha/`

The chacha20 TypeScript module also includes `pool.ts` (`XChaCha20Poly1305Pool`)
and `pool.worker.ts`. The worker file compiles to `dist/chacha20/pool.worker.js`
and ships in the package, but it is **not** registered in the `exports` map, it
is an internal file loaded by the pool at runtime, not a public named subpath.

**`sha2.wasm`**
SHA-256 and SHA-512 (FIPS 180-4). SHA-384 (SHA-512 with different IVs, truncated
output, shares all SHA-512 buffers and compress function). HMAC-SHA256,
HMAC-SHA512, HMAC-SHA384 (RFC 2104). HKDF-SHA256 and HKDF-SHA512 (RFC 5869)
are pure TypeScript compositions over HMAC, with no new WASM logic.
Source: `src/asm/sha2/`

**`sha3.wasm`**
Keccak-f[1600] permutation (FIPS 202). SHA3-224, SHA3-256, SHA3-384, SHA3-512.
SHAKE128, SHAKE256 (XOFs, multi-squeeze capable, unbounded output length).
All six variants share one permutation, differing only in rate, domain
separation byte, and output length.
Source: `src/asm/sha3/`

---

## `init()` API

WASM instantiation is async. `init()` is the explicit initialization gate,
it must be called once before any cryptographic class is used. This is honest
about the initialization cost and gives the developer control over when it is paid.

### Signature

```typescript
type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3'
type Mode = 'embedded' | 'streaming' | 'manual'

interface InitOpts {
	wasmUrl?: URL | string
	wasmBinary?: Record<Module, Uint8Array | ArrayBuffer>
}

async function init(
	modules: Module | Module[],
	mode?: Mode,
	opts?: InitOpts
): Promise<void>
```

### Three loading modes

**`'embedded'` (default: zero-config)**
The `.wasm` binary is base64-encoded and inlined in the published package as a
generated TypeScript file (`src/ts/embedded/*.ts`). At runtime, the base64 string
is decoded and passed to `WebAssembly.instantiate()`. Works everywhere with no
bundler configuration. ~33% size overhead from base64 encoding. Cannot use
streaming compilation.

```typescript
await init(['serpent', 'sha3'])
```

**`'streaming'` (performance path)**
Uses `WebAssembly.instantiateStreaming()` for maximum load performance. The
browser compiles the WASM binary while still downloading it. `wasmUrl` is a
base URL, the loader appends the filename (`serpent.wasm`, `chacha.wasm`, etc.).
Requires the `.wasm` files to be served with `Content-Type: application/wasm`.

```typescript
await init(['serpent', 'sha3'], 'streaming', { wasmUrl: '/assets/wasm/' })
// loads: /assets/wasm/serpent.wasm, /assets/wasm/sha3.wasm
```

**`'manual'` (custom loading)**
Caller provides the compiled binary directly as a `Uint8Array` or `ArrayBuffer`.
For environments with custom loading requirements (CDN, service worker cache,
non-standard fetch).

```typescript
await init(['chacha20'], 'manual', {
	wasmBinary: { chacha20: myBuffer }
})
```

### Behavioral contracts

**Idempotent.** Calling `init()` for a module that is already initialized is a
no-op. Safe to call from multiple modules in a codebase.

**Module-scope cache.** The compiled `WebAssembly.Module` for each binary is
cached at module scope after first compilation. All subsequent class instantiations
use `WebAssembly.instantiate(cachedModule)`, fast, no recompilation.

**Error before init.** Calling any cryptographic class before `init()` throws:
```
leviathan-crypto: call init(['<module>']) before using <ClassName>
```

**No lazy auto-init.** Classes never silently call `init()` on first use.
Hidden initialization costs are worse than explicit ones.

**Thread safety.** v1.0 uses a single WASM module instance per binary, single
thread. WASM linear memory is not shared across Workers without `SharedArrayBuffer`
(which requires COOP/COEP headers). Two pool classes provide Worker-based
parallelism: `SerpentStreamPool` (chunked authenticated Serpent encryption) and
`XChaCha20Poly1305Pool` (AEAD). Each pool worker owns its own WASM instances with
isolated linear memory. For other primitives: create one instance per Worker if
Workers are used.

---

## Public API Classes

Names match conventional cryptographic notation.

| Module | Classes |
|--------|---------|
| `serpent` + `sha2` | `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener` |
| `serpent` | `Serpent`, `SerpentCtr`, `SerpentCbc` |
| `chacha20` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Poly1305Pool` |
| `sha2` | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| `sha3` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| `serpent` + `sha2` | `Fortuna` |

HMAC names use underscore separator (`HMAC_SHA256`) matching RFC convention.
SHA-3 names use underscore separator (`SHA3_256`) for readability.

**`Fortuna`** requires `await Fortuna.create()` rather than `new Fortuna()` due
to the async `init()` dependency on two modules. It requires both `serpent` and
`sha2` to be initialized. In Node.js, Fortuna collects additional entropy from
`process.hrtime`, `process.cpuUsage`, `process.memoryUsage`, `os.loadavg`,
and `os.freemem` in addition to `crypto.randomBytes`.

### Usage pattern

All WASM-backed classes follow the same pattern:

```typescript
import { init, SerpentSeal, SHA3_256 } from 'leviathan-crypto'

await init(['serpent', 'sha2', 'sha3'])

const seal = new SerpentSeal()
const ciphertext = seal.encrypt(key, plaintext)  // throws on tamper at decrypt

const hasher = new SHA3_256()
const digest = hasher.hash(message)
```

### Utility exports (no `init()` required)

Pure TypeScript utilities ship alongside the WASM-backed primitives:

| Category | Exports |
|----------|---------|
| Encoding | `hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64` |
| Security | `constantTimeEqual`, `wipe`, `xor` |
| Helpers | `concat`, `randomBytes` |
| Types | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |

---

## Build Pipeline

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/build-pipeline.svg" alt="Architecture Layers" width="1000">

**Step by step:**

1. `npm run build:asm` — AssemblyScript compiler reads `src/asm/*/index.ts`, emits `build/*.wasm`
2. `npm run build:embed` — `scripts/embed-wasm.ts` reads each `.wasm`, writes base64 to `src/ts/embedded/*.ts`
3. `npm run build:ts` — TypeScript compiler emits `dist/`
4. `cp build/*.wasm dist/` — WASM binaries copied for streaming mode consumers
5. At runtime (subpath): `serpent/index.ts:serpentInit()` → `initModule()` → `loadEmbedded(thunk)` → `thunk()` → dynamic-import `embedded/serpent.ts` → decode base64 → `WebAssembly.instantiate` → cache in `init.ts`
6. At runtime (root): `index.ts:init(['serpent', 'sha3'])` → dispatches to each module's init function (`serpentInit`, `sha3Init`) via `Promise.all` → same path as step 5 per module

`src/ts/embedded/` is gitignored, these files are a build artifacts derived from the WASM
binaries. There is one source of truth for each binary: the AssemblyScript source.

---

## Module Relationship Diagrams

### ASM layer — internal import graph

Each WASM module is fully independent. No cross-module imports exist.

**Serpent (`src/asm/serpent/`)**

```
buffers.ts
  <- serpent.ts            (offsets for key, block, subkey, work, CBC IV)
  <- serpent_unrolled.ts   (block offsets, subkey, work)
  <- cbc.ts                (IV, block, chunk offsets)
  <- ctr.ts                (nonce, counter, block, chunk offsets)

serpent.ts
  <- serpent_unrolled.ts   (S-boxes sb0-sb7, si0-si7, lk, kl, keyXor)

serpent_unrolled.ts
  <- cbc.ts                (encryptBlock_unrolled, decryptBlock_unrolled)
  <- ctr.ts                (encryptBlock_unrolled)

index.ts
  re-exports: buffers + serpent + serpent_unrolled + cbc + ctr
```

**ChaCha (`src/asm/chacha/`)**

```
buffers.ts
  <- chacha20.ts           (key, nonce, counter, block, state, poly key, xchacha offsets)
  <- poly1305.ts           (poly key, msg, buf, tag, h, r, rs, s offsets)
  <- wipe.ts               (all buffer offsets, zeroes everything)

index.ts
  re-exports: buffers + chacha20 + poly1305 + wipe
```

**SHA-2 (`src/asm/sha2/`)**

```
buffers.ts
  <- sha256.ts             (H, block, W, out, input, partial, total offsets)
  <- sha512.ts             (H, block, W, out, input, partial, total offsets)
  <- hmac.ts               (SHA-256 input, out, ipad, opad, inner offsets)
  <- hmac512.ts            (SHA-512 input, out, ipad, opad, inner offsets)

sha256.ts
  <- hmac.ts               (sha256Init, sha256Update, sha256Final)

sha512.ts
  <- hmac512.ts            (sha512Init, sha384Init, sha512Update, sha512Final, sha384Final)

index.ts
  re-exports: buffers + sha256 + sha512 + hmac + hmac512
  defines: wipeBuffers() inline
```

**SHA-3 (`src/asm/sha3/`)**

```
buffers.ts
  <- keccak.ts             (state, rate, absorbed, dsbyte, input, out offsets)

index.ts
  re-exports: buffers + keccak
```

### TS layer — internal import graph

```
                                     +---------------------+
                                     |      index.ts       | <- barrel: dispatching init()
                                     |  (public API root)  |    + re-exports everything
                                     +--+--+--+--+--+--+--+
                                        |  |  |  |  |  |
              +-------------------------+  |  |  |  |  +----------------------+
              |           +----------------+  |  |  +----------+              |
              v           v                   v  v             v              v
        serpent/      chacha20/            sha2/  sha3/     fortuna.ts    types.ts
        index.ts      index.ts           index.ts index.ts                utils.ts
          |  |          |  |               |  |    |  |          |
          |  |          |  |               |  |    |  |          +-> init.ts (isInitialized)
          |  |          |  +-> utils.ts    |  |    |  |          +-> serpent/index.ts (Serpent)
          |  |          |  |  (constantTime|  |    |  |          +-> sha2/index.ts (SHA256)
          |  |          |  |   Equal)      |  |    |  |          +-> utils.ts (wipe, concat,
          |  |          |  |               |  |    |  |                       utf8ToBytes)
          |  |          |  +-> chacha20/   |  |    |  |
          |  |          |  |  types.ts     |  |    |  |
          |  |          |  |               |  |    |  |
          |  +----------+--+--+------------+--+----+--+--> init.ts <-- getInstance()
          |             |     |            |       |                    initModule()
          |             |     |            |       |                    isInitialized()
          v             v     v            v       v
   embedded/     embedded/  embedded/  embedded/
   serpent.ts    chacha.ts  sha2.ts    sha3.ts
   (each module owns its own embedded thunk, no cross-module imports)
```

Each module's init function (`serpentInit`, `chacha20Init`, `sha2Init`,
`sha3Init`) calls `initModule()` from `init.ts`, passing its own embedded thunk. `initModule()` delegates to `loadEmbedded(thunk)` in `loader.ts`.
The loader calls the thunk, decodes base64, and instantiates the WASM binary.
`loader.ts` has no knowledge of module names or embedded file paths.

### TS layer — file-by-file imports

| File | Imports from | Symbols |
|------|-------------|---------|
| `init.ts` | *(none)* | — |
| `loader.ts` | `init.ts` | `Module` (type) |
| `types.ts` | *(none)* | — |
| `utils.ts` | *(none)* | — |
| `serpent/types.ts` | *(none)* | — |
| `chacha20/types.ts` | *(none)* | — |
| `sha2/types.ts` | *(none)* | — |
| `sha3/types.ts` | *(none)* | — |
| `serpent/index.ts` | `init.ts`, `embedded/serpent.ts` | `getInstance`, `initModule`, `Mode`, `InitOpts`, `WASM_BASE64` |
| `serpent/seal.ts` | `serpent/index.ts`, `sha2/index.ts`, `utils.ts` | `SerpentCbc`, `HMAC_SHA256`, `concat`, `constantTimeEqual`, `wipe` |
| `serpent/stream.ts` | `serpent/index.ts`, `sha2/index.ts`, `utils.ts` | `SerpentCtr`, `HMAC_SHA256`, `HKDF_SHA256`, `constantTimeEqual`, `concat` |
| `serpent/stream-pool.ts` | `serpent/stream.ts` | `sealChunk`, `openChunk`, `chunkInfo` |
| `serpent/stream-sealer.ts` | `serpent/index.ts`, `sha2/index.ts`, `utils.ts` | `SerpentCbc`, `HMAC_SHA256`, `HKDF_SHA256`, `concat`, `constantTimeEqual`, `wipe` |
| `chacha20/index.ts` | `init.ts`, `utils.ts`, `chacha20/types.ts`, `embedded/chacha.ts` | `getInstance`, `initModule`, `Mode`, `InitOpts`, `constantTimeEqual`, `ChaChaExports`, `WASM_BASE64` |
| `sha2/index.ts` | `init.ts`, `embedded/sha2.ts` | `getInstance`, `initModule`, `Mode`, `InitOpts`, `WASM_BASE64` |
| `sha3/index.ts` | `init.ts`, `embedded/sha3.ts` | `getInstance`, `initModule`, `Mode`, `InitOpts`, `WASM_BASE64` |
| `fortuna.ts` | `init.ts`, `serpent/index.ts`, `sha2/index.ts`, `utils.ts` | `isInitialized`, `Serpent`, `SHA256`, `wipe`/`concat`/`utf8ToBytes` |
| `index.ts` | `serpent/`, `chacha20/`, `sha2/`, `sha3/`, `init.ts`, `fortuna.ts`, `types.ts`, `utils.ts` | `serpentInit`, `chacha20Init`, `sha2Init`, `sha3Init` (from each module), *(all public exports)* |

### TS-to-WASM mapping

Each TS wrapper class maps to one WASM module and specific exported functions.
Tier 2 composition classes (`SerpentSeal`, `SerpentStream*`, `HKDF_*`) are pure
TypeScript, they call Tier 1 classes rather than WASM functions directly.

**serpent/index.ts → asm/serpent/ (Tier 1: direct WASM callers)**

| TS Class | WASM functions called |
|----------|---------------------|
| `Serpent` | `loadKey`, `encryptBlock`, `decryptBlock`, `wipeBuffers` + buffer getters |
| `SerpentCtr` | `loadKey`, `resetCounter`, `setCounter`, `encryptChunk`, `decryptChunk`, `wipeBuffers` + buffer getters |
| `SerpentCbc` | `loadKey`, `cbcEncryptChunk`, `cbcDecryptChunk`, `wipeBuffers` + buffer getters |

**serpent/seal.ts, stream.ts, stream-sealer.ts (Tier 2: pure TS composition)**

| TS Class | Composes |
|----------|---------|
| `SerpentSeal` | `SerpentCbc` + `HMAC_SHA256` |
| `SerpentStream` | `SerpentCtr` + `HMAC_SHA256` + `HKDF_SHA256` |
| `SerpentStreamPool` | `SerpentStream` (via worker) |
| `SerpentStreamSealer` | `SerpentCbc` + `HMAC_SHA256` + `HKDF_SHA256` |
| `SerpentStreamOpener` | `SerpentCbc` + `HMAC_SHA256` + `HKDF_SHA256` |

**chacha20/index.ts → asm/chacha/**

| TS Class | WASM functions called |
|----------|---------------------|
| `ChaCha20` | `chachaLoadKey`, `chachaSetCounter`, `chachaResetCounter`, `chachaEncryptChunk`, `chachaDecryptChunk`, `wipeBuffers` + buffer getters |
| `Poly1305` | `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters |
| `ChaCha20Poly1305` | `chachaLoadKey`, `chachaResetCounter`, `chachaGenPolyKey`, `chachaEncryptChunk`, `chachaDecryptChunk`, `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters |
| `XChaCha20Poly1305` | All of `ChaCha20Poly1305` + `hchacha20` + xchacha buffer getters |

**sha2/index.ts → asm/sha2/**

| TS Class | WASM functions called |
|----------|---------------------|
| `SHA256` | `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters |
| `SHA512` | `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters |
| `SHA384` | `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA256` | `hmac256Init`, `hmac256Update`, `hmac256Final`, `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA512` | `hmac512Init`, `hmac512Update`, `hmac512Final`, `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA384` | `hmac384Init`, `hmac384Update`, `hmac384Final`, `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters |
| `HKDF_SHA256` | Pure TS composition over `HMAC_SHA256` (extract + expand per RFC 5869) |
| `HKDF_SHA512` | Pure TS composition over `HMAC_SHA512` (extract + expand per RFC 5869) |

**sha3/index.ts → asm/sha3/**

| TS Class | WASM functions called |
|----------|---------------------|
| `SHA3_224` | `sha3_224Init`, `keccakAbsorb`, `sha3_224Final`, `wipeBuffers` + buffer getters |
| `SHA3_256` | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters |
| `SHA3_384` | `sha3_384Init`, `keccakAbsorb`, `sha3_384Final`, `wipeBuffers` + buffer getters |
| `SHA3_512` | `sha3_512Init`, `keccakAbsorb`, `sha3_512Final`, `wipeBuffers` + buffer getters |
| `SHAKE128` | `shake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `SHAKE256` | `shake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |

### Cross-module dependencies

| Relationship | Notes |
|-------------|-------|
| `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener` → `serpent` + `sha2` | Tier 2 composition: Serpent-CBC/CTR + HMAC-SHA256 + HKDF-SHA256. Both modules must be initialized. |
| `Fortuna` → `Serpent` + `SHA256` | Only class requiring **two** WASM modules (`serpent` + `sha2`). Uses `Fortuna.create()` static factory instead of `new`. |
| `XChaCha20Poly1305` → `ChaCha20Poly1305` | Pure TS composition — calls `hchacha20()` for subkey derivation, then delegates to `ChaCha20Poly1305`. |
| `HKDF_SHA256`, `HKDF_SHA512` → `HMAC_SHA256`, `HMAC_SHA512` | Pure TS composition — extract and expand steps per RFC 5869. |
| All other classes | Each depends on exactly **one** WASM module. |

### Public API barrel (`src/ts/index.ts`)

The root barrel defines and exports the dispatching `init()` function.
It is the only file that imports all four module-scoped init functions.

| Source | Exports |
|--------|---------|
| *(barrel itself)* | `init` (dispatching function — calls per-module init functions via `Promise.all`) |
| `init.ts` | `Module`, `Mode`, `InitOpts`, `isInitialized`, `_resetForTesting` |
| `serpent/index.ts` | `Serpent`, `SerpentCtr`, `SerpentCbc`, `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `StreamPoolOpts`, `_serpentReady` |
| `chacha20/index.ts` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `_chachaReady` |
| `chacha20/pool.ts` | `XChaCha20Poly1305Pool`, `PoolOpts` |
| `sha2/index.ts` | `SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`, `HKDF_SHA256`, `HKDF_SHA512`, `_sha2Ready` |
| `sha3/index.ts` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, `_sha3Ready` |
| `fortuna.ts` | `Fortuna` |
| `types.ts` | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |
| `utils.ts` | `hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64`, `constantTimeEqual`, `wipe`, `xor`, `concat`, `randomBytes` |

Each subpath export also exports its own module-specific init function for
tree-shakeable loading: `serpentInit(mode?, opts?)`, `chacha20Init(mode?, opts?)`,
`sha2Init(mode?, opts?)`, `sha3Init(mode?, opts?)`.

---

## npm Package

**Subpath exports:**

```json
{
	"exports": {
		".":                  "./dist/index.js",
		"./serpent":          "./dist/serpent/index.js",
		"./chacha20":         "./dist/chacha20/index.js",
		"./chacha20/pool":    "./dist/chacha20/pool.js",
		"./sha2":             "./dist/sha2/index.js",
		"./sha3":             "./dist/sha3/index.js"
	}
}
```

> [!NOTE]
> `dist/chacha20/pool.worker.js` ships in the package but is not in the
> `exports` map. It is an internal Web Worker entry point loaded by
> `XChaCha20Poly1305Pool` at runtime. Do not import it as a named subpath.

The root `.` export re-exports everything. Subpath exports allow bundlers to
tree-shake at the module level, a consumer importing only `./sha3` does not
include the Serpent wrapper classes or their embedded WASM binaries in their
bundle.

**Tree-shaking:** `"sideEffects": false` is set in `package.json`. Each
module's `index.ts` owns its own embedded import thunk. Bundlers that support
tree-shaking (webpack, Rollup, esbuild) can eliminate unused modules and
their embedded WASM binaries from the final bundle.

**Published:** `dist/` only. Contains compiled JS, TypeScript declarations,
and WASM binaries as assets for streaming mode. The embedded base64 is compiled
into the JS, not a separate file.

**Not published:** `src/`, `test/`, `build/`, `scripts/`, `docs/`

---

## Buffer Layouts

All offsets start at 0 per module. Independent linear memory. No offsets are
shared or coordinated across modules.

### Serpent module — 3 pages (192 KB)

Source: `src/asm/serpent/buffers.ts`

| Offset | Size | Name |
|--------|------|------|
| 0 | 32 | `KEY_BUFFER` — key input (padded to 32 bytes for all key sizes) |
| 32 | 16 | `BLOCK_PT_BUFFER` — single block plaintext |
| 48 | 16 | `BLOCK_CT_BUFFER` — single block ciphertext |
| 64 | 16 | `NONCE_BUFFER` — CTR mode nonce |
| 80 | 16 | `COUNTER_BUFFER` — 128-bit little-endian counter |
| 96 | 528 | `SUBKEY_BUFFER` — key schedule output (33 rounds × 4 × 4 bytes) |
| 624 | 65536 | `CHUNK_PT_BUFFER` — streaming plaintext (CTR/CBC) |
| 66160 | 65536 | `CHUNK_CT_BUFFER` — streaming ciphertext (CTR/CBC) |
| 131696 | 20 | `WORK_BUFFER` — 5 × i32 scratch registers (key schedule + S-box/LT rounds) |
| 131716 | 16 | `CBC_IV_BUFFER` — CBC initialization vector / chaining value |
| 131732 | — | END |

`wipeBuffers()` zeroes all 10 buffers (key, block pt/ct, nonce, counter, subkeys, work, chunk pt/ct, CBC IV).

### ChaCha20 module — 3 pages (192 KB)

Source: `src/asm/chacha/buffers.ts`

| Offset | Size | Name |
|--------|------|------|
| 0 | 32 | `KEY_BUFFER` — ChaCha20 256-bit key |
| 32 | 12 | `CHACHA_NONCE_BUFFER` — 96-bit nonce (3 × u32, LE) |
| 44 | 4 | `CHACHA_CTR_BUFFER` — u32 block counter |
| 48 | 64 | `CHACHA_BLOCK_BUFFER` — 64-byte keystream block output |
| 112 | 64 | `CHACHA_STATE_BUFFER` — 16 × u32 initial state |
| 176 | 65536 | `CHUNK_PT_BUFFER` — streaming plaintext |
| 65712 | 65536 | `CHUNK_CT_BUFFER` — streaming ciphertext |
| 131248 | 32 | `POLY_KEY_BUFFER` — one-time key r‖s |
| 131280 | 64 | `POLY_MSG_BUFFER` — message staging (≤ 64 bytes per polyUpdate) |
| 131344 | 16 | `POLY_BUF_BUFFER` — partial block accumulator |
| 131360 | 4 | `POLY_BUF_LEN_BUFFER` — u32 bytes in partial block |
| 131364 | 16 | `POLY_TAG_BUFFER` — 16-byte output MAC tag |
| 131380 | 40 | `POLY_H_BUFFER` — accumulator h: 5 × u64 |
| 131420 | 40 | `POLY_R_BUFFER` — clamped r: 5 × u64 |
| 131460 | 32 | `POLY_RS_BUFFER` — precomputed 5×r[1..4]: 4 × u64 |
| 131492 | 16 | `POLY_S_BUFFER` — s pad: 4 × u32 |
| 131508 | 24 | `XCHACHA_NONCE_BUFFER` — full 24-byte XChaCha20 nonce |
| 131532 | 32 | `XCHACHA_SUBKEY_BUFFER` — HChaCha20 output (key material) |
| 131564 | — | END |

`wipeBuffers()` zeroes all 14 buffer regions (key, chacha nonce/ctr/block/state, chunk pt/ct, poly key/msg/buf/tag/h/r/rs/s, xchacha nonce/subkey).

### SHA-2 module — 3 pages (192 KB)

Source: `src/asm/sha2/buffers.ts`

| Offset | Size | Name |
|--------|------|------|
| 0 | 32 | `SHA256_H` — SHA-256 hash state H0..H7 (8 × u32) |
| 32 | 64 | `SHA256_BLOCK` — SHA-256 block accumulator |
| 96 | 256 | `SHA256_W` — SHA-256 message schedule W[0..63] (64 × u32) |
| 352 | 32 | `SHA256_OUT` — SHA-256 digest output |
| 384 | 64 | `SHA256_INPUT` — SHA-256 user input staging (one block) |
| 448 | 4 | `SHA256_PARTIAL` — u32 partial block length |
| 452 | 8 | `SHA256_TOTAL` — u64 total bytes hashed |
| 460 | 64 | `HMAC256_IPAD` — HMAC-SHA256 K' XOR ipad |
| 524 | 64 | `HMAC256_OPAD` — HMAC-SHA256 K' XOR opad |
| 588 | 32 | `HMAC256_INNER` — HMAC-SHA256 inner hash |
| 620 | 64 | `SHA512_H` — SHA-512 hash state H0..H7 (8 × u64) |
| 684 | 128 | `SHA512_BLOCK` — SHA-512 block accumulator |
| 812 | 640 | `SHA512_W` — SHA-512 message schedule W[0..79] (80 × u64) |
| 1452 | 64 | `SHA512_OUT` — SHA-512 digest output (SHA-384 uses first 48 bytes) |
| 1516 | 128 | `SHA512_INPUT` — SHA-512 user input staging (one block) |
| 1644 | 4 | `SHA512_PARTIAL` — u32 partial block length |
| 1648 | 8 | `SHA512_TOTAL` — u64 total bytes hashed |
| 1656 | 128 | `HMAC512_IPAD` — HMAC-SHA512 K' XOR ipad (128-byte block size) |
| 1784 | 128 | `HMAC512_OPAD` — HMAC-SHA512 K' XOR opad |
| 1912 | 64 | `HMAC512_INNER` — HMAC-SHA512 inner hash |
| 1976 | — | END |

`wipeBuffers()` zeroes all 20 buffer regions (SHA-256 state/block/W/out/input/partial/total, HMAC-256 ipad/opad/inner, SHA-512 state/block/W/out/input/partial/total, HMAC-512 ipad/opad/inner).

### SHA-3 module — 3 pages (192 KB)

Source: `src/asm/sha3/buffers.ts`

| Offset | Size | Name |
|--------|------|------|
| 0 | 200 | `KECCAK_STATE` — 25 × u64 Keccak-f[1600] lane matrix (5×5, row-major x+5y) |
| 200 | 4 | `KECCAK_RATE` — u32 rate in bytes (variant-specific: 72–168) |
| 204 | 4 | `KECCAK_ABSORBED` — u32 bytes absorbed into current block |
| 208 | 1 | `KECCAK_DSBYTE` — u8 domain separation byte (0x06 for SHA-3, 0x1f for SHAKE) |
| 209 | 168 | `KECCAK_INPUT` — input staging buffer (max rate = SHAKE128 at 168 bytes) |
| 377 | 168 | `KECCAK_OUT` — output buffer (one SHAKE128 squeeze block) |
| 545 | — | END |

`wipeBuffers()` zeroes all 6 buffer regions (state, rate, absorbed, dsbyte, input, output).

---

## Test Suite

### Structure

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/test-suite.svg" alt="Test Suite Data Flow Diagram" width="800">

For the full testing methodology and vector corpus, see: [test-suite.md](./test-suite.md)

### Gate discipline

Each primitive family has a gate test, the simplest authoritative vector for
that primitive. The gate must pass before any other tests in that family are
written or run. Gate tests are annotated with a `// GATE` comment.

### `init.test.ts` contracts

- `init()` with each of the three modes loads and caches the module correctly
- Idempotency: second `init()` call for same module is a no-op
- Error before init: clear error thrown for each class before its module is loaded
- Partial init: loading `['serpent']` does not make `sha3` classes available

---

## Correctness Contract

leviathan-crypto must produce byte-identical output to the authoritative
specification for every known test vector. Cross-checks against the leviathan
TypeScript reference and external tools (OpenSSL, Python hashlib, Node.js crypto)
provide additional verification layers.

The test vector corpus in `test/vectors/` is read-only. Integrity is verified via
`SHA256SUMS`, expected values are sourced directly from authoritative references.
They are the immutable truth, and must never be modified to make tests pass.

---

## Known Limitations (v1.0)

- **`SerpentCbc` is unauthenticated**: use `SerpentSeal` for authenticated
  Serpent encryption, or pair `SerpentCbc` with `HMAC_SHA256` (Encrypt-then-MAC)
  if direct CBC access is required.
- **Single-threaded WASM per instance**: one WASM instance per binary per thread.
  `SerpentStreamPool` and `XChaCha20Poly1305Pool` provide Worker-based parallelism
  for their respective AEAD paths; other primitive families remain single-threaded.
- **Max input per WASM call**: chunk-based APIs (CTR, CBC) accept at most 64KB
  per call. Wrappers handle splitting automatically for larger inputs.
- **Browser WASM loading**: streaming mode requires files served with
  `Content-Type: application/wasm`. Embedded mode works everywhere.

---

> ## Cross-References
>
> - [README.md](./README.md) — project overview and quick-start guide
> - [test-suite.md](./test-suite.md) — testing methodology, vector corpus, and gate discipline
> - [init.md](./init.md) — `init()` API, three loading modes, and idempotent behavior
> - [loader.md](./loader.md) — internal WASM binary loading strategies (embedded, streaming, manual)
> - [wasm.md](./wasm.md) — WebAssembly primer: modules, instances, memory, and the init gate
> - [types.md](./types.md) — public TypeScript interfaces (`Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD`)
> - [utils.md](./utils.md) — encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`
> - [serpent.md](./serpent.md) — Serpent-256 TypeScript API (SerpentSeal, SerpentStream, raw modes)
> - [chacha20.md](./chacha20.md) — ChaCha20/Poly1305 TypeScript API and XChaCha20-Poly1305 AEAD
> - [sha2.md](./sha2.md) — SHA-2 hashes, HMAC, and HKDF TypeScript API
> - [sha3.md](./sha3.md) — SHA-3 hashes and SHAKE XOFs TypeScript API
> - [fortuna.md](./fortuna.md) — Fortuna CSPRNG with forward secrecy and entropy pooling
> - [argon2id.md](./argon2id.md) — Argon2id password hashing and key derivation
