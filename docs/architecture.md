# Architecture

> [!NOTE]
> `leviathan-crypto` v2.0 packages five WASM modules (Serpent, ChaCha20, SHA-2, SHA-3, Kyber), generic streaming AEAD via CipherSuite, and worker pool parallelism. It supersedes `leviathan` (TypeScript reference) and `leviathan-wasm` (WASM primitives), both of which remain unchanged as development references.

> ### Table of Contents
> - [Vision](#vision)
> - [Scope](#scope)
> - [Repository Structure](#repository-structure)
> - [Architecture: TypeScript over WASM](#architecture-typescript-over-wasm)
> - [Five Independent WASM Modules](#five-independent-wasm-modules)
> - [init() API](#init-api)
> - [Public API Classes](#public-api-classes)
> - [Build Pipeline](#build-pipeline)
> - [Module Relationship Diagrams](#module-relationship-diagrams)
> - [npm Package](#npm-package)
> - [Buffer Layouts](#buffer-layouts)
> - [Test Suite](#test-suite)
> - [Correctness Contract](#correctness-contract)
> - [Known Limitations](#known-limitations)

---

## Vision

`leviathan-crypto` is a strictly-typed, audited WebAssembly cryptography library for
the web. It combines two previously separate efforts:

**leviathan.** Developer-friendly TypeScript API, strict types, audited against specs and known-answer test vectors.

**leviathan-wasm.** AssemblyScript WASM implementation of the same primitives, running outside the JavaScript JIT for predictable execution and practical constant-time guarantees.

The unified library exposes the TypeScript API from leviathan, backed by the WASM
execution engine from leviathan-wasm. Developers get ergonomic, well-typed classes.
The runtime gets deterministic cryptographic computation outside the JIT.

**The fundamental insight:** JavaScript engines provide no formal constant-time
guarantees for arbitrary code. WASM execution is deterministic and not subject to
JIT speculation. For a cryptography library, this distinction matters. The TypeScript
layer handles API ergonomics; the WASM layer handles all cryptographic computation.

---

## Scope

### In scope

| Module             | Primitives                                                                                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `serpent`          | Serpent-256 block cipher: ECB, CTR mode, CBC mode                                                                       |
| `serpent` + `sha2` | `SerpentCipher` (CipherSuite for STREAM construction: CBC+HMAC-SHA256)                             |
| `chacha20`         | ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD, `XChaCha20Cipher` (CipherSuite for streaming AEAD) |
| `sha2`             | SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, HKDF-SHA256, HKDF-SHA512                              |
| `sha3` / `keccak`  | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 (XOFs, multi-squeeze). `'keccak'` is an alias for `'sha3'`; same binary, same instance slot. |
| `kyber`            | `MlKem512`, `MlKem768`, `MlKem1024`. Requires `sha3` for Keccak sponge operations. |
| `stream`           | `SealStream`, `OpenStream` (cipher-agnostic STREAM construction), `SealStreamPool` (worker-based parallelism)           |

Pure TypeScript utilities (encoding helpers, random generation, format converters)
ship alongside the WASM-backed primitives with no `init()` dependency.

### Auxiliary tier (not part of `Module` union)

- **`Fortuna`:** CSPRNG requiring two core modules (`serpent` + `sha2`).

---

## Repository Structure

```text
leviathan-crypto/
├── .github/
│   └── workflows/              ← CI: build, test-suite, e2e, publish, release, wiki
├── src/
│   ├── asm/                        ← AssemblyScript (compiles to .wasm)
│   │   ├── serpent/
│   │   │   ├── index.ts            ← asc entry point → serpent.wasm
│   │   │   ├── serpent.ts          ← block function + key schedule
│   │   │   ├── serpent_unrolled.ts ← unrolled S-boxes and round functions
│   │   │   ├── serpent_simd.ts     ← SIMD bitsliced block operations
│   │   │   ├── cbc.ts              ← CBC mode
│   │   │   ├── cbc_simd.ts         ← SIMD CBC decrypt
│   │   │   ├── ctr.ts              ← CTR mode
│   │   │   ├── ctr_simd.ts         ← SIMD CTR 4-wide inter-block
│   │   │   └── buffers.ts          ← static buffer layout + offset getters
│   │   ├── chacha20/
│   │   │   ├── index.ts            ← asc entry point → chacha20.wasm
│   │   │   ├── chacha20.ts
│   │   │   ├── chacha20_simd_4x.ts ← SIMD 4-wide inter-block ChaCha20
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
│   │   ├── sha3/
│   │       ├── index.ts            ← asc entry point → sha3.wasm
│   │       ├── keccak.ts
│   │       └── buffers.ts
│   │   ├── ct/
│   │   │   └── index.ts            ← asc entry point → ct.wasm (SIMD constant-time compare)
│   │   └── kyber/
│   │       ├── index.ts            ← asc entry point → kyber.wasm
│   │       ├── ntt.ts              ← NTT/invNTT (scalar reference + zetas table)
│   │       ├── ntt_simd.ts         ← SIMD NTT/invNTT (v128 butterflies, fqmul_8x, barrett_reduce_8x)
│   │       ├── reduce.ts           ← Montgomery/Barrett reduction, fqmul
│   │       ├── poly.ts             ← polynomial serialization, compression, arithmetic, basemul
│   │       ├── poly_simd.ts        ← SIMD poly add/sub/reduce/ntt wrappers
│   │       ├── polyvec.ts          ← k-wide polyvec operations
│   │       ├── cbd.ts              ← centered binomial distribution (η=2, η=3)
│   │       ├── sampling.ts         ← uniform rejection sampling
│   │       ├── verify.ts           ← constant-time compare and conditional move
│   │       ├── params.ts           ← Q, QINV, MONT, Barrett/compression constants
│   │       └── buffers.ts          ← static buffer layout + offset getters
│   └── ts/                         ← TypeScript (public API)
│       ├── init.ts                 ← initModule() : WASM loading and module cache
│       ├── loader.ts               ← loadWasm() / compileWasm() : polymorphic WasmSource dispatch
│       ├── wasm-source.ts          ← WasmSource union type
│       ├── errors.ts               ← AuthenticationError
│       ├── types.ts                ← Hash, KeyedHash, Blockcipher, Streamcipher, AEAD
│       ├── utils.ts                ← encoding, wipe, xor, concat, randomBytes
│       ├── fortuna.ts              ← Fortuna CSPRNG (requires serpent + sha2)
│       ├── embedded/               ← generated gzip+base64 blobs (build artifact, gitignored)
│       │   ├── serpent.ts
│       │   ├── chacha20.ts
│       │   ├── sha2.ts
│       │   └── sha3.ts
│       ├── serpent/
│       │   ├── index.ts            ← serpentInit() + Serpent, SerpentCtr, SerpentCbc
│       │   ├── cipher-suite.ts     ← SerpentCipher (CipherSuite for STREAM construction)
│       │   ├── pool-worker.ts      ← Web Worker for SealStreamPool with SerpentCipher
│       │   ├── embedded.ts         ← re-exports gzip+base64 blob as named export
│       │   └── types.ts
│       ├── chacha20/
│       │   ├── index.ts            ← chacha20Init() + ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305, XChaCha20Cipher
│       │   ├── ops.ts              ← raw AEAD functions shared by classes and pool worker
│       │   ├── cipher-suite.ts     ← XChaCha20Cipher (CipherSuite for STREAM construction)
│       │   ├── pool-worker.ts      ← Web Worker for SealStreamPool with XChaCha20Cipher
│       │   ├── embedded.ts         ← re-exports gzip+base64 blob as named export
│       │   └── types.ts
│       ├── sha2/
│       │   ├── index.ts            ← sha2Init() + SHA256, SHA512, SHA384, HMAC, HKDF
│       │   ├── hkdf.ts             ← HKDF_SHA256, HKDF_SHA512 (pure TS over HMAC)
│       │   ├── embedded.ts         ← re-exports gzip+base64 blob as named export
│       │   └── types.ts
│       ├── sha3/
│       │   ├── index.ts            ← sha3Init() + SHA3_224–512, SHAKE128, SHAKE256
│       │   ├── embedded.ts         ← re-exports gzip+base64 blob as named export
│       │   └── types.ts
│       ├── kyber/
│       │   ├── index.ts            ← kyberInit() + MlKem512, MlKem768, MlKem1024, KyberSuite
│       │   ├── kem.ts              ← Fujisaki-Okamoto transform (keygen, encaps, decaps)
│       │   ├── suite.ts            ← KyberSuite factory (hybrid KEM+AEAD CipherSuite)
│       │   ├── indcpa.ts           ← IND-CPA encrypt/decrypt + matrix generation
│       │   ├── validate.ts         ← key validation (FIPS 203 §7.2, §7.3)
│       │   ├── params.ts           ← parameter sets (MLKEM512, MLKEM768, MLKEM1024)
│       │   ├── types.ts            ← KyberExports, Sha3Exports, KEM API types
│       │   └── embedded.ts         ← re-exports gzip+base64 blob as kyberWasm
│       ├── stream/
│       │   ├── index.ts            ← barrel: Seal, SealStream, OpenStream, SealStreamPool, constants
│       │   ├── seal.ts             ← Seal (static one-shot AEAD)
│       │   ├── seal-stream.ts      ← SealStream (cipher-agnostic streaming encryption)
│       │   ├── open-stream.ts      ← OpenStream (cipher-agnostic streaming decryption)
│       │   ├── seal-stream-pool.ts ← SealStreamPool (worker-based parallel batch)
│       │   ├── header.ts           ← wire format header encode/decode, counter nonce
│       │   ├── constants.ts        ← HEADER_SIZE, CHUNK_MIN/MAX, TAG_DATA/FINAL, FLAG_FRAMED
│       │   └── types.ts            ← CipherSuite, DerivedKeys, SealStreamOpts
│       └── index.ts                ← root barrel : dispatching init() + re-exports everything
├── test/
│   ├── unit/                       ← Vitest (JS target, fast iteration)
│   │   ├── serpent/
│   │   ├── chacha20/
│   │   ├── sha2/
│   │   ├── sha3/
│   │   ├── stream/                 ← SealStream, OpenStream, SealStreamPool tests
│   │   ├── loader/                 ← WasmSource loading tests
│   │   ├── init.test.ts
│   │   ├── errors.test.ts
│   │   ├── fortuna.test.ts
│   │   └── utils.test.ts
│   ├── e2e/                        ← Playwright (WASM target, cross-browser)
│   └── vectors/                    ← test vector files (read-only reference data)
├── scripts/
│   ├── build-asm.js                ← orchestrates AssemblyScript compilation
│   ├── embed-wasm.ts               ← reads build/*.wasm, generates src/ts/embedded/*.ts
│   ├── gen-seal-vectors.ts         ← generates KAT vectors for Seal
│   ├── gen-sealstream-vectors.ts   ← generates KAT vectors for SealStream
│   ├── generate_simd.ts            ← generates SIMD assembly variants
│   ├── gen-changelog.ts            ← changelog generation
│   ├── copy-docs.ts                ← copies docs subset to dist/
│   └── pin-actions.ts              ← pins GitHub Actions to SHA hashes
├── docs/                           ← project documentation + wiki source
├── package.json
├── asconfig.json                   ← four AssemblyScript entry points
├── tsconfig.json
├── vitest.config.ts
├── playwright.config.ts
├── AGENTS.md                       ← ai agent contract
└── SECURITY.md
```

---

## Architecture: TypeScript over WASM

The TypeScript layer never implements cryptographic algorithms. It manages the boundary between JavaScript and WebAssembly by writing inputs into WASM linear memory, calling exported functions, and reading back outputs. All algorithm logic resides within AssemblyScript.

Higher-level classes like `Seal`, `SealStream`, and `SealStreamPool` are pure TypeScript, but they compose WASM-backed primitives (Serpent-CBC, HMAC-SHA256, ChaCha20-Poly1305, and HKDF-SHA256) rather than implementing new cryptographic logic. TypeScript orchestrates, while WASM computes. Pool workers instantiate their own WASM modules and directly call primitives, bypassing the main-thread module cache.

---

## Five Independent WASM Modules

Each primitive family compiles to its own `.wasm` binary. Modules are fully
independent, separate linear memories, separate buffer layouts, no shared state.

| Module | Binary | Primitives |
|--------|--------|------------|
| `serpent` | `serpent.wasm` | Serpent-256 block cipher: ECB, CTR mode, CBC mode |
| `chacha20` | `chacha20.wasm` | ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD |
| `sha2` | `sha2.wasm` | SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 |
| `sha3` | `sha3.wasm` | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
| `kyber` | `kyber.wasm` | ML-KEM polynomial arithmetic: SIMD NTT/invNTT (v128 butterflies with scalar tail), basemul, Montgomery/Barrett, CBD, compress, CT verify/cmov |

**Size.** Consumers who only use Serpent don't load the SHA-3 binary.

**Isolation.** Key material in `serpent.wasm` memory cannot bleed into `sha3.wasm` memory even in theory.

Each module's buffer layout starts at offset 0 and is defined in its own
`buffers.ts`. Buffer layouts are fully independent across modules.

### Module contents

**`serpent.wasm`**
Serpent-256 block cipher. Key schedule, block encrypt, block decrypt. CTR mode
chunked streaming encrypt/decrypt. CBC mode chunked encrypt/decrypt. SIMD
variants for CTR 4-wide inter-block and CBC decrypt parallelism.
Source: `src/asm/serpent/`

The serpent TypeScript module includes `SerpentCipher` (CipherSuite implementation
for the STREAM construction: Serpent-CBC + HMAC-SHA256 with HKDF key derivation).
Requires `serpent` and `sha2` to be initialized.

**`chacha20.wasm`**
ChaCha20 stream cipher (RFC 8439). Poly1305 MAC (RFC 8439 §2.5). ChaCha20-Poly1305
AEAD (RFC 8439 §2.8). XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha).
HChaCha20 subkey derivation. SIMD 4-wide inter-block parallelism.
Source: `src/asm/chacha20/`

The chacha20 TypeScript module includes `XChaCha20Cipher` (CipherSuite implementation
for the STREAM construction: XChaCha20-Poly1305 with HKDF key derivation).
Pool workers are internal, loaded by `SealStreamPool` at runtime, not registered in the package exports map.

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

**`kyber.wasm`**
ML-KEM (FIPS 203) polynomial arithmetic. Montgomery and Barrett reduction,
7-layer NTT and inverse NTT, basemul in Z_q[X]/(X²-ζ), centered binomial
distribution sampling (η=2, η=3), division-free compression/decompression
(all 5 bit-width paths: 4, 5, 10, 11, 1-bit), rejection sampling for matrix
generation, constant-time byte comparison and conditional move. Requires
WebAssembly SIMD (`v128` instructions) for NTT and polynomial arithmetic.
3 pages (192 KB) linear memory with 10 poly slots, 8 polyvec slots, and
dedicated byte buffers for keys/ciphertexts.
Source: `src/asm/kyber/`

The kyber TypeScript module includes `MlKem512`, `MlKem768`, `MlKem1024`
(KEM classes implementing the Fujisaki-Okamoto transform). All require both
`kyber` and `sha3` to be initialized; the sha3 module provides the Keccak sponge (SHAKE128 for matrix gen, SHAKE256 for noise/J function, SHA3-256 for H, SHA3-512 for G).

---

## `init()` API

WASM instantiation is async. `init()` is the initialization gate, call it once before using any cryptographic class. The cost is explicit and the developer controls when it is paid.

### Signature

```typescript
type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3' | 'keccak' | 'kyber'

type WasmSource =
  | string                  // gzip+base64 embedded blob
  | URL                     // fetch + compileStreaming
  | ArrayBuffer             // compile from raw bytes
  | Uint8Array              // compile from raw bytes
  | WebAssembly.Module      // pre-compiled (edge runtimes)
  | Response                // instantiateStreaming
  | Promise<Response>       // deferred fetch

async function init(
  sources: Partial<Record<Module, WasmSource>>,
): Promise<void>
```

The loading strategy is inferred from the source type, so there is no need
for a mode string. Each module also exports its own init function, such as
`serpentInit(source)`, `chacha20Init(source)`, `sha2Init(source)`,
`sha3Init(source)`, `keccakInit(source)`, and `kyberInit(source)`,
enabling tree-shakeable imports.

> [!NOTE]
> **`'keccak'` is an alias for `'sha3'`.** Both names are accepted by `init()`, `initModule()`, `getInstance()`, and `isInitialized()`. They share the same WASM binary and the same instance slot. The alias exists so Kyber/ML-KEM consumers can write `init({ keccak: keccakWasm })` using the semantically correct name for the underlying sponge primitive.

### Embedded subpath exports

Each module provides a `/embedded` subpath that exports the gzip+base64
blob as a ready-to-use `WasmSource`:
```typescript
import { init } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
```

### Behavioral contracts

**Idempotent initialization.** Calling `init()` on an already initialized
module is a no-op. It is safe to call `init()` from multiple locations
within the codebase.

**Module-scope cache.** Each `WebAssembly.Instance` is cached at module
scope after initial instantiation. All subsequent class constructions use
the cached instance with no recompilation.

**Error before initialization.** Invoking any cryptographic class before
calling `init()` throws a clear error prompting the developer to call
`init({ <module>: ... })` first.

**No implicit initialization.** Classes never call `init()` automatically
on first use. Explicit initialization is preferable to hidden costs.

**Thread safety.** The main thread uses a single WASM instance per module.
`SealStreamPool` provides worker-based parallelism. Each pool worker owns
its own WASM instances with isolated linear memory, bypassing the main-thread
cache entirely. For other primitives, create one instance per Worker if
Workers are used.

---

## Public API Classes

Names match conventional cryptographic notation.

| Module | Classes |
|--------|---------|
| `serpent` + `sha2` | `SerpentCipher` |
| `serpent` | `Serpent`, `SerpentCtr`, `SerpentCbc` |
| `chacha20` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher` |
| `sha2` | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| `sha3` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| `kyber` + `sha3` | `MlKem512`, `MlKem768`, `MlKem1024` |
| `kyber` + `sha3` + inner cipher | `KyberSuite` (hybrid KEM+AEAD factory) |
| `stream` | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool` |
| `serpent` + `sha2` | `Fortuna` |

HMAC names use underscore separator (`HMAC_SHA256`) matching RFC convention.
SHA-3 names use underscore separator (`SHA3_256`) for readability.
`SealStream`, `OpenStream`, and `SealStreamPool` are cipher-agnostic; you select the cipher by passing `XChaCha20Cipher` or `SerpentCipher` at construction.

**`Fortuna`** requires `await Fortuna.create()` rather than `new Fortuna()` due
to the async `init()` dependency on two modules.

### Usage pattern

All WASM-backed classes follow the same pattern:
```typescript
import { init, Seal, SerpentCipher, SHA3_256 } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'
import { sha3Wasm }    from 'leviathan-crypto/sha3/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm, sha3: sha3Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)

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

1. `npm run build:asm`: AssemblyScript compiler reads `src/asm/*/index.ts`, emits `build/*.wasm`
2. `npm run build:embed`: `scripts/embed-wasm.ts` reads each `.wasm`, gzip compresses, base64 encodes, writes to `src/ts/embedded/*.ts` and per-module `src/ts/*/embedded.ts`
3. `npm run build:ts`: TypeScript compiler emits `dist/`
4. `cp build/*.wasm dist/`: WASM binaries copied for URL-based consumers
5. At runtime (subpath): `serpentInit(serpentWasm)` → `initModule()` → `loadWasm(source)` → decode gzip+base64 → `WebAssembly.instantiate` → cache in `init.ts`
6. At runtime (root): `init({ serpent: serpentWasm, sha2: sha2Wasm })` → dispatches to each module's init function via `Promise.all` → same path as step 5 per module

`src/ts/embedded/` is gitignored; these files are build artifacts derived from the WASM binaries. There is one source of truth for each binary: the AssemblyScript source.

---

## Module Relationship Diagrams

### ASM layer: internal import graph

Each WASM module is fully independent. No cross-module imports exist.

**Serpent (`src/asm/serpent/`)**
```
buffers.ts
  <- serpent.ts            (offsets for key, block, subkey, work, CBC IV)
  <- serpent_unrolled.ts   (block offsets, subkey, work)
  <- serpent_simd.ts       (SIMD bitsliced block operations)
  <- cbc.ts                (IV, block, chunk offsets)
  <- cbc_simd.ts           (SIMD CBC decrypt)
  <- ctr.ts                (nonce, counter, block, chunk offsets)
  <- ctr_simd.ts           (SIMD CTR 4-wide inter-block)

serpent.ts
  <- serpent_unrolled.ts   (S-boxes sb0-sb7, si0-si7, lk, kl, keyXor)

serpent_unrolled.ts
  <- cbc.ts                (encryptBlock_unrolled, decryptBlock_unrolled)
  <- ctr.ts                (encryptBlock_unrolled)

serpent_simd.ts
  <- cbc_simd.ts           (SIMD block operations)
  <- ctr_simd.ts           (SIMD block operations)

index.ts
  re-exports: buffers + serpent + serpent_unrolled + serpent_simd + cbc + cbc_simd + ctr + ctr_simd
```

**ChaCha (`src/asm/chacha20/`)**
```
buffers.ts
  <- chacha20.ts           (key, nonce, counter, block, state, poly key, xchacha offsets)
  <- chacha20_simd_4x.ts   (SIMD work buffer, chunk offsets)
  <- poly1305.ts           (poly key, msg, buf, tag, h, r, rs, s offsets)
  <- wipe.ts               (all buffer offsets, zeroes everything)

index.ts
  re-exports: buffers + chacha20 + chacha20_simd_4x + poly1305 + wipe
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

**Kyber (`src/asm/kyber/`)**

```
params.ts
  <- reduce.ts             (Q, QINV, BARRETT_V, BARRETT_SHIFT)
  <- poly.ts               (Q, POLY_BYTES, HALF_Q, compression constants)
  <- polyvec.ts            (Q, POLY_BYTES, compression constants)
  <- sampling.ts           (Q)

buffers.ts
  <- polyvec.ts            (POLY_ACC_OFFSET)

reduce.ts
  <- ntt.ts                (fqmul, barrett_reduce)
  <- ntt_simd.ts           (fqmul, barrett_reduce — scalar tail)
  <- poly.ts               (montgomery_reduce, barrett_reduce, fqmul)

ntt.ts
  <- ntt_simd.ts           (getZetasOffset — zetas table pointer)
  <- poly.ts               (ntt, invntt, basemul, getZeta)

ntt_simd.ts
  <- poly_simd.ts          (ntt_simd, invntt_simd, barrett_reduce_8x)

poly.ts
  <- polyvec.ts            (poly_tobytes, poly_frombytes, poly_basemul_montgomery)

poly_simd.ts
  <- polyvec.ts            (poly_add_simd, poly_reduce_simd, poly_ntt_simd, poly_invntt_simd)

cbd.ts
  <- poly.ts               (cbd2, cbd3)

index.ts
  re-exports: buffers + ntt (scalar aliases) + ntt_simd (as ntt/invntt) +
              reduce + poly (scalar serialization/compression/basemul) +
              poly_simd (as poly_add/sub/reduce/ntt/invntt) +
              polyvec + sampling + verify
```

---

### TS layer: internal import graph

```
                                 +---------------------+
                                 |      index.ts       | <- barrel: dispatching init()
                                 |  (public API root)  |    + re-exports everything
                                 +--+--+--+--+--+--+--+
                                    |  |  |  |  |  |
          +-------------------------+  |  |  |  |  +----------------------+
          |           +----------------+  |  |  +----------+              |
          v           v                   v  v             v              v
    serpent/      chacha20/            sha2/  sha3/     fortuna.ts    stream/
    index.ts      index.ts           index.ts index.ts               index.ts
      |             |  |               |       |          |            |
      |             |  +-> ops.ts      |       |          +-> init.ts  |
      |             |                  |       |          +-> serpent/  |
      |             +-> cipher-        |       |          +-> sha2/    +-> seal-stream.ts
      |                 suite.ts       |       |          +-> utils.ts +-> open-stream.ts
      +-> cipher-   |                  |       |                       +-> seal-stream-pool.ts
          suite.ts  +-> pool-          +-> hkdf.ts                    +-> header.ts
      |                 worker.ts                                      +-> constants.ts
      +-> pool-     |                                                 +-> types.ts
          worker.ts |
                    |
All module index.ts files ──────────────────────────> init.ts <── getInstance()
                                                                   initModule()
All */embedded.ts files ──────────────────────────> embedded/*.ts   (gzip+base64 blobs)
```

Each module's init function (`serpentInit`, `chacha20Init`, `sha2Init`,
`sha3Init`, `kyberInit`) calls `initModule()` from `init.ts`, passing a `WasmSource`.
`initModule()` delegates to `loadWasm(source)` in `loader.ts`. The loader
infers the loading strategy from the source type, with no mode string and no knowledge of module names or embedded file paths.

Pool workers (`serpent/pool-worker.ts`, `chacha20/pool-worker.ts`) instantiate
their own WASM modules from pre-compiled `WebAssembly.Module` objects passed
via `postMessage`. They do not use `initModule()` or the main-thread cache.

---

### TS-to-WASM mapping

Each TS wrapper class maps to one WASM module and specific exported functions.
Tier 2 composition classes are pure TypeScript; they call Tier 1 classes rather than WASM functions directly.

**serpent/index.ts → asm/serpent/ (Tier 1: direct WASM callers)**

| TS Class | WASM functions called |
|----------|---------------------|
| `Serpent` | `loadKey`, `encryptBlock`, `decryptBlock`, `wipeBuffers` + buffer getters |
| `SerpentCtr` | `loadKey`, `resetCounter`, `setCounter`, `encryptChunk`, `encryptChunk_simd`, `wipeBuffers` + buffer getters |
| `SerpentCbc` | `loadKey`, `cbcEncryptChunk`, `cbcDecryptChunk`, `cbcDecryptChunk_simd`, `wipeBuffers` + buffer getters |

**chacha20/index.ts → asm/chacha20/ (Tier 1: direct WASM callers)**

| TS Class | WASM functions called |
|----------|---------------------|
| `ChaCha20` | `chachaLoadKey`, `chachaSetCounter`, `chachaEncryptChunk`, `chachaEncryptChunk_simd`, `wipeBuffers` + buffer getters |
| `Poly1305` | `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters |
| `ChaCha20Poly1305` | `chachaLoadKey`, `chachaSetCounter`, `chachaGenPolyKey`, `chachaEncryptChunk`, `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters (via `ops.ts`) |
| `XChaCha20Poly1305` | All of `ChaCha20Poly1305` + `hchacha20` + xchacha buffer getters (via `ops.ts`) |

**sha2/index.ts → asm/sha2/ (Tier 1: direct WASM callers)**

| TS Class | WASM functions called |
|----------|---------------------|
| `SHA256` | `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters |
| `SHA512` | `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters |
| `SHA384` | `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA256` | `hmac256Init`, `hmac256Update`, `hmac256Final`, `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA512` | `hmac512Init`, `hmac512Update`, `hmac512Final`, `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA384` | `hmac384Init`, `hmac384Update`, `hmac384Final`, `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters |

**sha3/index.ts → asm/sha3/ (Tier 1: direct WASM callers)**

| TS Class | WASM functions called |
|----------|---------------------|
| `SHA3_224` | `sha3_224Init`, `keccakAbsorb`, `sha3_224Final`, `wipeBuffers` + buffer getters |
| `SHA3_256` | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters |
| `SHA3_384` | `sha3_384Init`, `keccakAbsorb`, `sha3_384Final`, `wipeBuffers` + buffer getters |
| `SHA3_512` | `sha3_512Init`, `keccakAbsorb`, `sha3_512Final`, `wipeBuffers` + buffer getters |
| `SHAKE128` | `shake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `SHAKE256` | `shake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |

**kyber/index.ts + kyber/kem.ts + kyber/indcpa.ts → asm/kyber/ (Tier 1)**

| TS Class | WASM functions called |
|----------|---------------------|
| `MlKem512`, `MlKem768`, `MlKem1024` | `polyvec_ntt`, `polyvec_invntt`, `polyvec_basemul_acc_montgomery`, `polyvec_add`, `polyvec_reduce`, `polyvec_tobytes`, `polyvec_frombytes`, `polyvec_compress`, `polyvec_decompress`, `poly_ntt`, `poly_invntt`, `poly_tomont`, `poly_add`, `poly_sub`, `poly_reduce`, `poly_basemul_montgomery`, `poly_frommsg`, `poly_tomsg`, `poly_compress`, `poly_decompress`, `poly_getnoise`, `rej_uniform`, `ct_verify`, `ct_cmov`, `wipeBuffers` + buffer getters |

All MlKem classes also call sha3 WASM via `indcpa.ts`: `sha3_256Init`, `sha3_512Init`, `shake128Init`, `shake256Init`, `keccakAbsorb`, `sha3_256Final`, `sha3_512Final`, `shakeFinal`, `shakePad`, `shakeSqueezeBlock`.

**Tier 2: pure TS composition**

| TS Class / Object | Composes |
|--------------------|----------|
| `SerpentCipher` | `SerpentCbc` + `HMAC_SHA256` + `HKDF_SHA256` |
| `XChaCha20Cipher` | `ChaCha20Poly1305` (via `ops.ts`) + `HKDF_SHA256` |
| `Seal` | `SealStream` + `OpenStream` (degenerate single-chunk case) |
| `SealStream` | `CipherSuite` (generic — caller provides cipher) |
| `OpenStream` | `CipherSuite` (generic — caller provides cipher) |
| `SealStreamPool` | `CipherSuite` + `compileWasm()` + Web Workers |
| `HKDF_SHA256` | `HMAC_SHA256` (extract + expand per RFC 5869) |
| `HKDF_SHA512` | `HMAC_SHA512` (extract + expand per RFC 5869) |
| `Fortuna` | `Serpent` + `SHA256` |

---

### Cross-module dependencies

| Relationship | Notes |
|-------------|-------|
| `SerpentCipher` → `serpent` + `sha2` | Tier 2 composition: Serpent-CBC + HMAC-SHA256 + HKDF-SHA256. |
| `XChaCha20Cipher` → `chacha20` + `sha2` | HKDF-SHA256 for key derivation + HChaCha20 + ChaCha20-Poly1305 for per-chunk AEAD. |
| `KyberSuite` → `kyber` + `sha3` + inner cipher | KEM encaps/decaps + HKDF with kemCt binding + inner CipherSuite. |
| `SealStream`, `OpenStream` → depends on cipher | Cipher-agnostic. Module requirements are determined by the `CipherSuite` passed at construction. |
| `SealStreamPool` → depends on cipher | Same module requirements as the cipher, plus `WasmSource` in pool opts for worker compilation. |
| `Fortuna` → `serpent` + `sha2` | Uses `Fortuna.create()` static factory instead of `new`. |
| `MlKem512`, `MlKem768`, `MlKem1024` → `kyber` + `sha3` | Kyber module handles polynomial arithmetic; sha3 provides SHAKE128/256, SHA3-256/512 for G/H/J/matrix gen. |
| `HKDF_SHA256`, `HKDF_SHA512` → `sha2` | Pure TS composition — extract and expand steps per RFC 5869. |
| All other classes | Each depends on exactly **one** WASM module. |

---

### Public API barrel (`src/ts/index.ts`)

The root barrel defines and exports the dispatching `init()` function.
It is the only file that imports all four module-scoped init functions.

| Source | Exports |
|--------|------------|
| *(barrel itself)* | `init` (dispatching function — calls per-module init functions via `Promise.all`) |
| `init.ts` | `Module`, `WasmSource`, `isInitialized`, `_resetForTesting` |
| `errors.ts` | `AuthenticationError` |
| `serpent/index.ts` | `Serpent`, `SerpentCtr`, `SerpentCbc`, `SerpentCipher`, `_serpentReady` |
| `chacha20/index.ts` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher`, `_chachaReady` |
| `sha2/index.ts` | `SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`, `HKDF_SHA256`, `HKDF_SHA512`, `_sha2Ready` |
| `sha3/index.ts` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, `_sha3Ready` |
| `keccak/index.ts` | `keccakInit` + re-exports all sha3 classes (alias subpath) |
| `kyber/index.ts` | `kyberInit`, `KyberSuite`, `MlKem512`, `MlKem768`, `MlKem1024`, `KyberKeyPair`, `KyberEncapsulation`, `KyberParams`, `MLKEM512`, `MLKEM768`, `MLKEM1024` |
| `stream/index.ts` | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, `CipherSuite`, `DerivedKeys`, `SealStreamOpts`, `PoolOpts`, `FLAG_FRAMED`, `TAG_DATA`, `TAG_FINAL`, `HEADER_SIZE`, `CHUNK_MIN`, `CHUNK_MAX` |
| `fortuna.ts` | `Fortuna` |
| `types.ts` | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |
| `utils.ts` | `hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64`, `constantTimeEqual`, `wipe`, `xor`, `concat`, `randomBytes` |

Each subpath export also exports its own module-specific init function for
tree-shakeable loading: `serpentInit(source)`, `chacha20Init(source)`,
`sha2Init(source)`, `sha3Init(source)`, `keccakInit(source)`.

---

## npm Package

**Subpath exports:**
```json
{
  "exports": {
    ".":                     "./dist/index.js",
    "./stream":              "./dist/stream/index.js",
    "./serpent":              "./dist/serpent/index.js",
    "./serpent/embedded":     "./dist/serpent/embedded.js",
    "./chacha20":             "./dist/chacha20/index.js",
    "./chacha20/embedded":    "./dist/chacha20/embedded.js",
    "./sha2":                 "./dist/sha2/index.js",
    "./sha2/embedded":        "./dist/sha2/embedded.js",
    "./sha3":                 "./dist/sha3/index.js",
    "./sha3/embedded":        "./dist/sha3/embedded.js",
    "./keccak":               "./dist/keccak/index.js",
    "./keccak/embedded":      "./dist/keccak/embedded.js",
    "./kyber":                "./dist/kyber/index.js",
    "./kyber/embedded":       "./dist/kyber/embedded.js"
  }
}
```

> [!NOTE]
> Pool worker files (`dist/serpent/pool-worker.js`, `dist/chacha20/pool-worker.js`)
> ship in the package but are not in the `exports` map. They are internal Web
> Worker entry points loaded by `SealStreamPool` at runtime via
> `new URL('./pool-worker.js', import.meta.url)`. Do not import them as named
> subpaths.

The root `.` export re-exports everything. Subpath exports allow bundlers to tree-shake at the module level; a consumer importing only `./sha3` does not include the Serpent wrapper classes or their embedded WASM binaries in their bundle.

The `/embedded` subpaths provide gzip+base64 WASM blobs for zero-config usage. Consumers using URL-based or pre-compiled loading can skip the `/embedded` imports entirely, keeping them out of the bundle.

**Tree-shaking:** `"sideEffects": false` is set in `package.json`. Bundlers that support tree-shaking (webpack, Rollup, esbuild) can eliminate unused modules and their embedded WASM binaries from the final bundle.

**Published.** The npm package includes:

- `dist/`: compiled JS, TypeScript declarations, WASM binaries, pool worker scripts, and a subset of consumer-facing API docs for offline use.
- `CLAUDE.md`: agent-facing project context.
- `SECURITY.md`: vulnerability disclosure policy.

**Not published.** `src/`, `test/`, `build/`, `scripts/`, `docs/`, `.github/`, editor configs.

---

## Buffer Layouts

All offsets start at 0 per module. Independent linear memory. No offsets are
shared or coordinated across modules.

### Serpent module (3 pages, 192 KB)

Source: `src/asm/serpent/buffers.ts`

| Offset | Size | Name |
|--------|------|------|
| 0 | 32 | `KEY_BUFFER` — key input (padded to 32 bytes for all key sizes) |
| 32 | 16 | `BLOCK_PT_BUFFER` — single block plaintext |
| 48 | 16 | `BLOCK_CT_BUFFER` — single block ciphertext |
| 64 | 16 | `NONCE_BUFFER` — CTR mode nonce |
| 80 | 16 | `COUNTER_BUFFER` — 128-bit little-endian counter |
| 96 | 528 | `SUBKEY_BUFFER` — key schedule output (33 rounds × 4 × 4 bytes) |
| 624 | 65552 | `CHUNK_PT_BUFFER` — streaming plaintext (CTR/CBC); +16 from 65536 to fit PKCS7 max overhead |
| 66176 | 65552 | `CHUNK_CT_BUFFER` — streaming ciphertext (CTR/CBC) |
| 131728 | 20 | `WORK_BUFFER` — 5 × i32 scratch registers (key schedule + S-box/LT rounds) |
| 131748 | 16 | `CBC_IV_BUFFER` — CBC initialization vector / chaining value |
| 131856 | — | END |

`wipeBuffers()` zeroes all 10 buffers (key, block pt/ct, nonce, counter, subkeys, work, chunk pt/ct, CBC IV).

### ChaCha20 module (3 pages, 192 KB)

Source: `src/asm/chacha20/buffers.ts`

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
| 131564 | 4 | *(padding for 16-byte SIMD alignment)* |
| 131568 | 256 | `CHACHA_SIMD_WORK_BUFFER` — 4-wide inter-block keystream (4 × 64 bytes) |
| 131824 | — | END |

`wipeBuffers()` zeroes all 15 buffer regions (key, chacha nonce/ctr/block/state, chunk pt/ct, poly key/msg/buf/tag/h/r/rs/s, xchacha nonce/subkey, SIMD work).

### SHA-2 module (3 pages, 192 KB)

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

### SHA-3 module (3 pages, 192 KB)

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

### Kyber module (3 pages, 192 KB)

Source: `src/asm/kyber/`

| Region | Offset | Size | Purpose |
|--------|--------|------|---------|
| AS data segment | 0 | 4096 | Zetas table (128 × i16, bit-reversed Montgomery domain) |
| Poly slots | 4096 | 5120 | 10 × 512B scratch polynomials (256 × i16 each) |
| Polyvec slots | 9216 | 16384 | 8 × 2048B scratch polyvecs (k=4 max: 4 × 512B) |
| SEED buffer | 25600 | 32 | Seed ρ/σ |
| MSG buffer | 25632 | 32 | Message / shared secret |
| PK buffer | 25664 | 1568 | Encapsulation key (max k=4) |
| SK buffer | 27232 | 1536 | IND-CPA secret key (max k=4) |
| CT buffer | 28768 | 1568 | Ciphertext (max k=4) |
| CT_PRIME buffer | 30336 | 1568 | Decaps re-encrypt comparison (max k=4) |
| XOF/PRF buffer | 31904 | 1024 | SHAKE squeeze output for rej_uniform / CBD |
| Poly accumulator | 32928 | 512 | Internal scratch for polyvec_basemul_acc |

Total mutable: 29344 bytes (4096–33440). End = 33440 < 192 KB.

`wipeBuffers()` zeroes all mutable regions (poly slots, polyvec slots, SEED, MSG, PK, SK, CT, CT_PRIME, XOF/PRF, accumulator). The zetas data segment is read-only and is not wiped.

---

## Test Suite

### Structure

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/test-suite.svg" alt="Test Suite Data Flow Diagram" width="800">

For the full testing methodology and vector corpus, see: [test-suite.md](./test-suite.md)

### Gate discipline

Each primitive family has a gate test: the simplest authoritative vector for that primitive. The gate must pass before any other tests in that family are written or run. Gate tests are annotated with a `// GATE` comment.

### `init.test.ts` contracts

- `init()` with each `WasmSource` type loads and caches the module correctly
- Idempotency: second `init()` call for same module is a no-op
- Error before init: clear error thrown for each class before its module is loaded
- Partial init: loading `{ serpent: ... }` does not make `sha3` classes available

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

## Known Limitations

- **`SerpentCbc` is unauthenticated**: use `Seal` with `SerpentCipher` for
  authenticated Serpent encryption, or pair `SerpentCbc` with `HMAC_SHA256`
  (Encrypt-then-MAC) if direct CBC access is required.
- **Single-threaded WASM per instance**: one WASM instance per binary per thread.
  `SealStreamPool` provides Worker-based parallelism for both cipher families;
  other primitives remain single-threaded.
- **Max input per WASM call**: CTR accepts at most 65536 bytes per call; CBC
  accepts at most 65552 bytes (65536 + 16 bytes PKCS7 maximum overhead).
  Wrappers handle splitting automatically for larger inputs.
- **WASM side-channel posture**: WebAssembly implementations offer the best
  available side-channel resistance (branchless, table-free), but lack
  hardware-level constant-time guarantees. For applications where timing
  side channels are a primary threat, a native cryptographic library with
  verified constant-time guarantees will be more appropriate than any
  WASM-based implementation.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [lexicon](./lexicon.md) — Glossary of cryptographic terms
> - [test-suite](./test-suite.md) — testing methodology, vector corpus, and gate discipline
> - [init](./init.md) — `init()` API, `WasmSource`, and idempotent behavior
> - [loader](./loader.md) — internal WASM binary loading strategies
> - [wasm](./wasm.md) — WebAssembly primer: modules, instances, memory, and the init gate
> - [types](./types.md) — public TypeScript interfaces and `CipherSuite`
> - [utils](./utils.md) — encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`
> - [authenticated encryption](./aead.md) — SealStream, OpenStream, SealStreamPool, wire format
> - [serpent](./serpent.md) — Serpent-256 TypeScript API, SerpentCipher
> - [chacha20](./chacha20.md) — ChaCha20/Poly1305 TypeScript API, XChaCha20Cipher
> - [sha2](./sha2.md) — SHA-2 hashes, HMAC, and HKDF TypeScript API
> - [sha3](./sha3.md) — SHA-3 hashes and SHAKE XOFs TypeScript API
> - [fortuna](./fortuna.md) — Fortuna CSPRNG with forward secrecy and entropy pooling
> - [argon2id](./argon2id.md) — Argon2id password hashing and key derivation
