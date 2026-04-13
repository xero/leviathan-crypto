<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Architecture

Overview of Leviathan Crypto's architecture design, comprising six independent WASM modules unified by a misuse-resistant TypeScript API, which delivers both Serpent's paranoia and ChaCha's elegance as a zero-dependency, tree-shakable, post-quantum library.

> ### Table of Contents
>
> - [Vision](#vision)
> - [Scope](#scope)
> - [Repository Structure](#repository-structure)
> - [Architecture: TypeScript over WASM](#architecture-typescript-over-wasm)
> - [Six Independent WASM Modules](#six-independent-wasm-modules)
> - [init() API](#init-api)
> - [Public API Classes](#public-api-classes)
> - [Build Pipeline](#build-pipeline)
> - [Module Relationships](#module-relationships)
> - [npm Package](#npm-package)
> - [Buffer Layouts](#buffer-layouts)
> - [Test Suite](#test-suite)
> - [Correctness Contract](#correctness-contract)
> - [Known Limitations](#known-limitations)

## Vision

`leviathan-crypto` is a post-quantum WASM cryptography library with zero dependencies, tree-shakable, and side-effect free.

**JS is the problem, SIMD WASM is the solution.** JavaScript engines offer no formal constant-time guarantees. JIT compilers optimize based on runtime patterns, which leak secrets through cache access and instruction timing. By contrast, [WebAssembly](https://github.com/xero/leviathan-crypto/wiki/wasm) executes outside the JIT entirely, running compiled bytecode with linear memory you control. No speculative optimization, no value-dependent branches between source and execution.

**WebAssembly is the correctness layer.** All algorithm logic lives in WASM. Six AssemblyScript modules ([`serpent`](https://github.com/xero/leviathan-crypto/wiki/asm_serpent), [`chacha20`](https://github.com/xero/leviathan-crypto/wiki/asm_chacha), [`sha2`](https://github.com/xero/leviathan-crypto/wiki/asm_sha2), [`sha3`](https://github.com/xero/leviathan-crypto/wiki/asm_sha3), [`kyber`](https://github.com/xero/leviathan-crypto/wiki/asm_kyber), and [`ct`](https://github.com/xero/leviathan-crypto/wiki/asm_ct)) compile independently to WASM with SIMD where it pays off. Each module is its own instance with its own linear memory. Within a module, stateful primitives share the instance, and a runtime exclusivity model keeps them from interfering with each other.

**TypeScript is the ergonomics layer.** The strongly-typed public API covers [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal), [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream), [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool), [`Fortuna`](https://github.com/xero/leviathan-crypto/wiki/fortuna), [`HKDF`](https://github.com/xero/leviathan-crypto/wiki/sha2#hkdf_sha256), [`SkippedKeyStore`](https://github.com/xero/leviathan-crypto/wiki/ratchet#skippedkeystore), and others. The design is misuse-resistant by default. Authentication is verify-then-decrypt; key material wipes on dispose; validation runs before any crypto path; one-shot AEADs lock on first call. TypeScript never implements cryptographic algorithms. It orchestrates the WASM layer and enforces best practice through API shape, not convention.

**[Serpent-256](https://github.com/xero/leviathan-crypto/wiki/serpent_reference): maximum paranoia.** 32 rounds of S-boxes in pure Boolean logic with no table lookups. An ouroboros devouring every bit, in every block, through every round.

**[XChaCha20-Poly1305](https://github.com/xero/leviathan-crypto/wiki/chacha_reference): precise elegance.** 20 rounds of add-rotate-XOR, choreography without S-boxes or cache-timing leakage. A dance closing with Poly1305's unconditional forgery bound.

**Two ciphers, one interface.** Both share the [`CipherSuite`](https://github.com/xero/leviathan-crypto/wiki/ciphersuite) shape and slot into [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal), [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream), and [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool) interchangeably. Post-quantum extends the same model, [`KyberSuite`](https://github.com/xero/leviathan-crypto/wiki/ciphersuite#kybersuite) wraps [`MlKem512`](https://github.com/xero/leviathan-crypto/wiki/kyber#parameter-sets), [`MlKem768`](https://github.com/xero/leviathan-crypto/wiki/kyber#parameter-sets), or [`MlKem1024`](https://github.com/xero/leviathan-crypto/wiki/kyber#parameter-sets) around either cipher, and the [SPQR ratchet](https://github.com/xero/leviathan-crypto/wiki/ratchet) builds forward-secret sessions on top.

---

## Scope

**Primitives.** WASM algorithms with their TypeScript wrapper classes.

| Module                        | Algorithms                                                | TypeScript API                                                                                                                                                                                                  |
| ----------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`serpent`](./asm_serpent.md) | Serpent-256 block cipher: ECB, CTR, CBC                   | [`Serpent`](./serpent.md) (cipher class for mode operations)                                                                                                                                                    |
| [`chacha20`](./asm_chacha.md) | ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305 | [`ChaCha20`](./chacha20.md#chacha20), [`Poly1305`](./chacha20.md#poly1305), [`XChaCha20Poly1305`](./chacha20.md#xchacha20poly1305)                                                                                                                  |
| [`sha2`](./asm_sha2.md)       | SHA-256, SHA-384, SHA-512, HMAC variants, HKDF variants   | [`SHA256`](./sha2.md#sha256), [`SHA384`](./sha2.md#sha384), [`SHA512`](./sha2.md#sha512), [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), [`HMAC_SHA512`](./sha2.md#hmac_sha512), [`HKDF_SHA256`](./sha2.md#hkdf_sha256), [`HKDF_SHA512`](./sha2.md#hkdf_sha512) |
| [`sha3`](./asm_sha3.md)       | SHA3-224/256/384/512, SHAKE128, SHAKE256 (XOFs)           | [`SHA3_256`](./sha3.md#sha3_256), [`SHA3_512`](./sha3.md#sha3_512), [`SHAKE256`](./sha3.md#shake256)                                                                                                                                       |
| [`kyber`](./asm_kyber.md)     | MlKem512, MlKem768, MlKem1024                             | [`MlKem512`](./kyber.md#parameter-sets), [`MlKem768`](./kyber.md#parameter-sets), [`MlKem1024`](./kyber.md#parameter-sets)                                                                                                                                   |
| [`ct`](./asm_ct.md)           | Constant-time comparison primitives                       | [`constantTimeEqual`](./utils.md#constanttimeequal)                                                                                                                                                             |


**Cipher Suites.** Composition of WASM modules into complete cipher packages.

| Suite                                 | Composition                          | Use case                            |
| ------------------------------------- | ------------------------------------ | ----------------------------------- |
| [`SerpentCipher`](./ciphersuite.md#serpentcipher)   | `serpent` + `sha2` (CBC+HMAC-SHA256) | Authenticated encryption via STREAM |
| [`XChaCha20Cipher`](./ciphersuite.md#xchacha20cipher) | `chacha20` (XChaCha20-Poly1305 AEAD) | Streaming authenticated encryption  |
| [`KyberSuite`](./ciphersuite.md#kybersuite)      | `kyber` + (any cipher)               | Post-quantum key encapsulation      |

**High-Level Constructs.** Pure TypeScript abstractions over cipher suites.

| API                                                                                                                            | Dependencies                     | Purpose                                      |
| ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------- | -------------------------------------------- |
| [`Seal`](./aead.md#seal) / [`SealStream`](./aead.md#sealstream) / [`SealStreamPool`](./aead.md#sealstreampool)                                                | Any CipherSuite                  | One-shot, streaming, and parallel encryption |
| [`ratchetInit`](./ratchet.md#ratchetinitsk-context), [`KDFChain`](./ratchet.md#kdfchain), [`kemRatchetEncap`](./ratchet.md#kemratchetencapkem-rk-peerek-context)/[`kemRatchetDecap`](./ratchet.md#kemratchetdecapkem-rk-dk-kemct-ownek-context) | `sha2`; `kyber` + `sha3` for KEM | Forward-secret session ratcheting (SPQR)     |
| [`Fortuna`](./fortuna.md)                                                                                                      | Cipher PRF + HashFn              | Cryptographically-secure RNG                 |

**Utilities.** Pure TypeScript helpers, no `init()` dependency.

| Utility                                             | Purpose                                          |
| --------------------------------------------------- | ------------------------------------------------ |
| [`hexToBytes`](./utils.md#hextobytes), [`bytesToHex`](./utils.md#bytestohex)                          | Hex/byte conversions                             |
| [`wipe`](./utils.md#wipe)                                              | Secure memory zeroing                            |
| [`xor`](./utils.md#xor), [`concat`](./utils.md#concat)                                     | Byte operations                                  |
| [`randomBytes`](./utils.md#randombytes)                                       | One-off random byte generation                   |
| [`constantTimeEqual`](./utils.md#constanttimeequal) | Timing-attack resistant comparison (WASM-backed) |

---

## Repository Structure

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/repo-structure.svg" alt="Repo Structure concentric rings diagram" width="600">

Source lives under `src/`, split between AssemblyScript primitives in `src/asm/` and the TypeScript API in `src/ts/`. Tests are in `test/`. Build, codegen, and tooling scripts go in `scripts/`. CI/CD configuration sits in `.github/`. The repository root holds project documentation, package metadata, and tool configs. Each subsection below shows the relevant tree and notes the conventions that apply across files in that tier.

### CI/CD

`.github/` holds GitHub-specific repository configuration: workflow definitions, the CI image build context, and platform metadata. Workflows split along functional lines.

**Merge gate.** `build.yml`, `lint.yml`, `e2e.yml`, `test-suite.yml`. `test-suite.yml` orchestrates the per-domain unit runners (`unit-*.yml`) plus `verify-vectors.yml` for parallel execution and per-domain failure isolation.

**Test vectors.** `verify-vectors.yml` validates the corpus against `SHA256SUMS`.

**Release flow.** Manual `release.yml` bumps the version and creates the tag; the resulting `v*` tag push triggers `publish.yml`, which runs the npm publish with provenance attestations. `npm-remove.yml` is the manual deprecate/unpublish escape hatch.

**Wiki.** `wiki.yml` syncs `docs/` to the GitHub Wiki on every merge to main.

**CI image.** `ci-image.yml` rebuilds the test-runner container from `ci.Dockerfile` whenever the Dockerfile changes.

```
.github/
├── ci.Dockerfile
└── workflows/
    ├── build.yml
    ├── ci-image.yml
    ├── e2e.yml
    ├── lint.yml
    ├── npm-remove.yml
    ├── publish.yml
    ├── release.yml
    ├── test-suite.yml
    ├── unit-chacha20.yml
    ├── unit-core.yml
    ├── unit-hashing.yml
    ├── unit-kyber.yml
    ├── unit-montecarlo-cbc.yml
    ├── unit-montecarlo-ecb.yml
    ├── unit-nessie.yml
    ├── unit-ratchet.yml
    ├── unit-serpent.yml
    ├── unit-stream.yml
    ├── verify-vectors.yml
    └── wiki.yml
```

### Build pipeline

`scripts/` holds the build, codegen, and tooling scripts that produce `dist/` and the test-vector corpus. Three categories.

**Build orchestration.** `build-asm.js` drives AssemblyScript compilation across the six modules. `embed-wasm.ts` produces the gzip+base64 blob for each `.wasm`. `embed-workers.ts` bundles each pool worker into a self-contained IIFE via esbuild. `copy-docs.ts` ships the consumer doc subset into `dist/`. See [Build Pipeline](#build-pipeline) for the full sequence.

**Codegen.** `generate_simd.ts` produces `src/asm/serpent/serpent_simd.ts` from a template by translating S-box gate logic into v128 ops; the generator and its output are both committed and the output is never edited by hand. `gen-seal-vectors.ts`, `gen-sealstream-vectors.ts`, `gen-fortuna-vectors.ts`, and `gen-ratchet-vectors.ts` produce known-answer-test vectors for their respective primitives.

**Tooling.** `gen-changelog.ts` generates `CHANGELOG` entries. `lint-asm.js` lints the AssemblyScript sources. `pin-actions.ts` pins every GitHub Action reference to a SHA, run via `bun pin` after workflow changes.

```
scripts/
├── build-asm.js
├── copy-docs.ts
├── embed-wasm.ts
├── embed-workers.ts
├── gen-changelog.ts
├── gen-fortuna-vectors.ts
├── gen-ratchet-vectors.ts
├── gen-seal-vectors.ts
├── gen-sealstream-vectors.ts
├── generate_simd.ts
├── lint-asm.js
└── pin-actions.ts
```

### AssemblyScript layer

`src/asm/` holds the AssemblyScript sources for each WASM binary. Every subdirectory compiles to its own `.wasm` with fully independent linear memory and no cross-module imports.

**Per-module conventions.** Every module exposes an `index.ts` as the asc entry point; it re-exports the public surface that becomes the WASM exports. Every module except `ct/` has a `buffers.ts` that defines the static memory layout and the offset getters that all other files in that module import. The `ct/` module is intentionally minimal: a single `index.ts` whose layout is implicit in its single 64 KB page.

```
src/asm/
├── chacha20/
│   ├── index.ts
│   ├── chacha20.ts          ← block function (RFC 8439)
│   ├── chacha20_simd_4x.ts  ← SIMD 4-wide inter-block keystream
│   ├── poly1305.ts          ← one-time MAC
│   ├── wipe.ts              ← module-wide buffer zeroizer
│   └── buffers.ts
├── ct/
│   └── index.ts  ← v128 XOR-accumulate constant-time compare
├── kyber/
│   ├── index.ts
│   ├── ntt.ts        ← scalar NTT/invNTT + zetas table
│   ├── ntt_simd.ts   ← v128 NTT butterflies, fqmul_8x, barrett_reduce_8x
│   ├── reduce.ts     ← Montgomery/Barrett reduction, fqmul
│   ├── poly.ts       ← polynomial serialization, compression, basemul
│   ├── poly_simd.ts  ← SIMD poly add/sub/reduce/ntt wrappers
│   ├── polyvec.ts    ← k-wide polyvec operations
│   ├── cbd.ts        ← centered binomial distribution (η=2, η=3)
│   ├── sampling.ts   ← uniform rejection sampling
│   ├── verify.ts     ← constant-time compare and conditional move
│   ├── params.ts     ← Q, QINV, MONT, Barrett/compression constants
│   └── buffers.ts
├── serpent/
│   ├── index.ts
│   ├── serpent.ts           ← block function + key schedule
│   ├── serpent_unrolled.ts  ← unrolled S-boxes and round functions
│   ├── serpent_simd.ts      ← SIMD bitsliced block operations
│   ├── cbc.ts               ← CBC mode
│   ├── cbc_simd.ts          ← SIMD CBC decrypt
│   ├── ctr.ts               ← CTR mode
│   ├── ctr_simd.ts          ← SIMD CTR 4-wide inter-block
│   └── buffers.ts
├── sha2/
│   ├── index.ts
│   ├── sha256.ts
│   ├── sha512.ts   ← shared by SHA-512 and SHA-384
│   ├── hmac.ts     ← HMAC-SHA256
│   ├── hmac512.ts  ← HMAC-SHA512 and HMAC-SHA384
│   └── buffers.ts
└── sha3/
    ├── index.ts
    ├── keccak.ts   ← Keccak-f[1600] permutation, sponge absorb/squeeze
    └── buffers.ts
```

### TypeScript layer

`src/ts/` is the public API layer. Each subdirectory is a published npm subpath; top-level files cover cross-cutting concerns and standalone utilities.

**Subpath conventions.** Every cipher and hash module has an `index.ts` barrel, a `types.ts` for TypeScript-only declarations, and an `embedded.ts` that re-exports its gzip+base64 WASM blob from `src/ts/embedded/`. The `keccak/` alias subpath omits `types.ts` and re-exports sha3's instead. The `ratchet/` and `stream/` modules have no `embedded.ts` because they compose other modules and ship no WASM of their own.

**Cipher modules** (`serpent/`, `chacha20/`) add a `cipher-suite.ts` (the `CipherSuite` implementation for STREAM), a `pool-worker.ts` (Web Worker source for `SealStreamPool`), a `generator.ts` (Fortuna `Generator`), and a `shared-ops.ts` (serpent) or `ops.ts` (chacha20) holding pure primitive functions shared between the cipher-suite and the pool worker.

**Hash modules** (`sha2/`, `sha3/`) add a `hash.ts` (the stateless Fortuna `HashFn`).

**Build artifacts.** `ct-wasm.ts` and the `embedded/` directory hold auto-generated outputs that only exist after `bun run build`. Both are gitignored. `ct-wasm.ts` is the inline raw byte array of the ct WASM module. `embedded/` holds gzip+base64 blobs of each WASM binary (from `scripts/embed-wasm.ts`) and IIFE source strings for each pool worker (from `scripts/embed-workers.ts`).

```
src/ts/
├── chacha20/
│   ├── cipher-suite.ts
│   ├── embedded.ts
│   ├── generator.ts
│   ├── index.ts
│   ├── ops.ts
│   ├── pool-worker.ts
│   └── types.ts
├── ct-wasm.ts      ← gitignored build artifact: raw ct WASM bytes
├── embedded/       ← gitignored build artifacts
│   ├── chacha20-pool-worker.ts  ← ChaCha20 pool-worker IIFE source string
│   ├── chacha20.ts              ← chacha20.wasm gzip+base64 blob
│   ├── kyber.ts                 ← kyber.wasm gzip+base64 blob
│   ├── serpent-pool-worker.ts   ← Serpent pool-worker IIFE source string
│   ├── serpent.ts               ← serpent.wasm gzip+base64 blob
│   ├── sha2.ts                  ← sha2.wasm gzip+base64 blob
│   └── sha3.ts                  ← sha3.wasm gzip+base64 blob
├── errors.ts       ← AuthenticationError
├── fortuna.ts      ← Fortuna CSPRNG (composes pluggable Generator + HashFn)
├── index.ts        ← root barrel + dispatching init()
├── init.ts         ← initModule(), module cache, isInitialized
├── keccak/         ← alias subpath; same WASM and instance slot as sha3
│   ├── embedded.ts
│   └── index.ts
├── kyber/
│   ├── embedded.ts
│   ├── indcpa.ts    ← IND-CPA encrypt/decrypt + matrix generation
│   ├── index.ts
│   ├── kem.ts       ← Fujisaki-Okamoto transform (keygen, encaps, decaps)
│   ├── params.ts    ← MLKEM512, MLKEM768, MLKEM1024 parameter sets
│   ├── suite.ts     ← KyberSuite (hybrid KEM+AEAD CipherSuite factory)
│   ├── types.ts
│   └── validate.ts  ← key validation (FIPS 203 §7.2, §7.3)
├── loader.ts       ← loadWasm()/compileWasm() WasmSource dispatch
├── ratchet/
│   ├── index.ts
│   ├── kdf-chain.ts          ← KDFChain (per-message KDF chain, DR §5.2)
│   ├── ratchet-keypair.ts    ← RatchetKeypair (single-use ek/dk wrapper)
│   ├── root-kdf.ts           ← ratchetInit, kemRatchetEncap, kemRatchetDecap (DR §7.2)
│   ├── skipped-key-store.ts  ← SkippedKeyStore (MKSKIPPED cache, DR §3.2/§3.5)
│   └── types.ts
├── serpent/
│   ├── cipher-suite.ts
│   ├── embedded.ts
│   ├── generator.ts
│   ├── index.ts
│   ├── pool-worker.ts
│   ├── serpent-cbc.ts   ← SerpentCbc (broken out to avoid circular import)
│   ├── shared-ops.ts
│   └── types.ts
├── sha2/
│   ├── embedded.ts
│   ├── hash.ts
│   ├── hkdf.ts      ← HKDF_SHA256, HKDF_SHA512 (pure TS over HMAC)
│   ├── index.ts
│   └── types.ts
├── sha3/
│   ├── embedded.ts
│   ├── hash.ts
│   ├── index.ts
│   └── types.ts
├── stream/
│   ├── constants.ts         ← HEADER_SIZE, CHUNK_MIN/MAX, TAG_DATA/FINAL, FLAG_FRAMED
│   ├── header.ts            ← wire format header encode/decode, counter nonce
│   ├── index.ts
│   ├── open-stream.ts       ← OpenStream (cipher-agnostic streaming decryption)
│   ├── seal-stream-pool.ts  ← SealStreamPool (worker-based parallel batch)
│   ├── seal-stream.ts       ← SealStream (cipher-agnostic streaming encryption)
│   ├── seal.ts              ← Seal (static one-shot AEAD)
│   └── types.ts
├── types.ts        ← shared interfaces: Hash, KeyedHash, Blockcipher, Streamcipher, AEAD, Generator, HashFn
├── utils.ts        ← encoding, wipe, randomBytes, constantTimeEqual, CT_MAX_BYTES, hasSIMD
└── wasm-source.ts  ← WasmSource union type
```

### Tests

`test/` holds three independent categories of files, used by separate workflows.

**Unit tests** (`unit/`) are Vitest suites that compile to a JS target for fast local iteration. The directory mirrors `src/ts/` structure with one folder per module, plus a handful of top-level `.test.ts` files for cross-cutting concerns (init, errors, utils, fortuna). CI splits these by domain via `unit-*.yml` for parallel execution.

**End-to-end tests** (`e2e/`) are Playwright suites that exercise the actual WASM artifacts across V8, SpiderMonkey, and JavaScriptCore. They run after the full build, including pool-worker bundling.

**Test vectors** (`vectors/`) is the immutable known-answer-test corpus. Files are read-only reference data. Some come from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP); others are self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates KAT file integrity against `SHA256SUMS`.

See [test-suite.md](./test-suite.md) for full testing methodology, vector corpus inventory with provenance, and gate discipline.

```
test/
├── e2e/      ← Playwright suites against built WASM in V8, SpiderMonkey, JSC
├── unit/
│   ├── chacha20/
│   ├── ct/
│   ├── errors.test.ts
│   ├── fortuna/
│   ├── fortuna.test.ts
│   ├── helpers.ts
│   ├── init/
│   ├── init.test.ts
│   ├── kyber/
│   ├── loader/
│   ├── ratchet/
│   ├── serpent/
│   ├── sha2/
│   ├── sha3/
│   ├── stream/
│   └── utils.test.ts
└── vectors/  ← KAT corpus; integrity verified against SHA256SUMS
```

### Project files

The repository root holds project documentation, package metadata, and tool configuration. Build artifacts that only exist after `bun run build` are listed at the end.

**Documentation.** `README.md` is the entry point. `SECURITY.md` covers the vulnerability disclosure policy. `AGENTS.md` is the agent contract that governs how AI agents work in the repo. `CHANGELOG` tracks release history and `LICENSE` is MIT. The `docs/` directory holds the full API reference, audits, benchmarks, and architecture notes (this file lives there).

**Package metadata.** `package.json` declares the npm manifest, subpath exports, and scripts. `package-lock.json` and `bun.lock` are the lockfiles for npm and bun respectively; both ship checked in so either tool can install reproducibly.

**Tool configs.** `asconfig.json` configures AssemblyScript compilation. `eslint.config.ts` is the active linter, run via `bun fix`. `playwright.config.ts` and `vitest.config.ts` configure the e2e and unit test runners. `tsconfig.json` is the base TypeScript config; `tsconfig.test.json` and `tsconfig.e2e.json` extend it for the test targets. `tslint.json` is a TSLint config (older format).

**Build artifacts** (gitignored; only exist after `bun run build`). `build/` holds the raw `.wasm` outputs from AssemblyScript compilation. `dist/` is the published npm package contents (compiled JS, declarations, copied WASM, embedded blobs, doc subset).

```
.
├── build/                ← gitignored: .wasm outputs from AS compilation
├── dist/                 ← gitignored: published npm package contents
├── docs/                 ← API reference, audits, benchmarks (this file lives here)
├── README.md
├── SECURITY.md
├── AGENTS.md
├── CHANGELOG
├── LICENSE
├── package.json
├── package-lock.json
├── bun.lock
├── asconfig.json
├── eslint.config.ts
├── playwright.config.ts
├── tsconfig.json
├── tsconfig.e2e.json
├── tsconfig.test.json
├── tslint.json
└── vitest.config.ts
```

---

## Architecture: TypeScript over WASM

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/layers.svg" alt="Typescript Over Wasm layered diagram" width="700">

The TypeScript layer never implements cryptographic algorithms. It manages the boundary between JavaScript and WebAssembly by writing inputs into WASM linear memory, calling exported functions, and reading back outputs. All algorithm logic resides within AssemblyScript.

Higher-level classes like `Seal`, `SealStream`, and `SealStreamPool` are pure TypeScript, but they compose WASM-backed primitives (Serpent-CBC, HMAC-SHA256, ChaCha20-Poly1305, and HKDF-SHA256) rather than implementing new cryptographic logic. TypeScript orchestrates, while WASM computes. Pool workers instantiate their own WASM modules and directly call primitives, bypassing the main-thread module cache.

---

## Six Independent WASM Modules

Each primitive family compiles to its own `.wasm` binary with fully independent linear memory and buffer layouts. No shared state, no cross-module interference. Five of the six modules load through `init()`. The sixth, `ct`, sits outside the public `Module` union and the `init()` gate; it occupies a single 64 KB memory page and lazy-loads on the first call to `constantTimeEqual`. The ct module backs the public `constantTimeEqual` and `CT_MAX_BYTES` exports from the root barrel; neither requires an `init()` call.

|Module|Binary|Primitives|
|---|---|---|
|`serpent`|`serpent.wasm`|Serpent-256 block cipher: ECB, CTR mode, CBC mode|
|`chacha20`|`chacha20.wasm`|ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD|
|`sha2`|`sha2.wasm`|SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512|
|`sha3`|`sha3.wasm`|SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256|
|`kyber`|`kyber.wasm`|ML-KEM polynomial arithmetic: SIMD NTT/invNTT (v128 butterflies with scalar tail), basemul, Montgomery/Barrett, CBD, compress, CT verify/cmov|
|`ct`|`ct.wasm`|SIMD constant-time byte comparison. Backs `constantTimeEqual` and `CT_MAX_BYTES`, lazy-loaded outside `init()`. Single 64 KB page.|

**Size.** Consumers who only use Serpent don't load the SHA-3 binary.

**Isolation.** Key material in `serpent.wasm` memory cannot bleed into `sha3.wasm` memory even in theory.

Each module's buffer layout starts at offset 0 and is defined in its own `buffers.ts`. Buffer layouts are fully independent across modules.

### Module contents

**`serpent.wasm`** implements Serpent-256, a 128-bit block cipher. It handles key scheduling, block encryption and decryption, and both CTR and CBC streaming modes with SIMD variants for inter-block parallelism. See: [Serpent-256 WASM Module Reference](./asm_serpent.md)

[The TypeScript module](./serpent.md) wraps this with `SerpentCipher`, a CipherSuite that combines Serpent-CBC with HMAC-SHA256 and HKDF key derivation for the STREAM construction. Primitive operations (HMAC, CBC, PKCS7 padding) live in `serpent/shared-ops.ts` and are reused by both the main thread and pool workers, guaranteeing byte-identical output and consistent Vaudenay 2002 padding normalization. Requires `serpent` and `sha2` to be initialized.

**`chacha20.wasm`** implements the full ChaCha20-Poly1305 AEAD family per RFC 8439 and draft-irtf-cfrg-xchacha. It includes ChaCha20 stream cipher, Poly1305 one-time MAC, the AEAD construction, HChaCha20 for nonce extension, and SIMD 4-wide inter-block parallelism. See: [ChaCha20/Poly1305 WASM Reference](./asm_chacha.md)

[The TypeScript module](./chacha20.md) exports `XChaCha20Cipher`, a CipherSuite implementation for STREAM using XChaCha20-Poly1305 with HKDF key derivation. Pool workers load internally via `SealStreamPool` at runtime and don't appear in the package exports map.

**`sha2.wasm`** implements SHA-256 and SHA-512 per FIPS 180-4, plus SHA-384 (which reuses SHA-512's buffer and compress function with different IVs and truncation). It also provides HMAC per RFC 2104 for all three variants. HKDF-SHA256 and HKDF-SHA512 (RFC 5869) are pure TypeScript compositions over HMAC with no new WASM logic. See: [SHA-2 WASM Reference](./asm_sha2.md)

**`sha3.wasm`** implements the Keccak-f[1600] permutation per FIPS 202. All SHA3 variants (SHA3-224, SHA3-256, SHA3-384, SHA3-512) and XOF variants (SHAKE128, SHAKE256) share a single permutation, differing only in rate, domain separation byte, and output length. SHAKE supports unbounded multi-squeeze output. See: [SHA-3 WASM Reference](./asm_sha3.md)

**`kyber.wasm`** implements ML-KEM polynomial arithmetic per FIPS 203. It includes Montgomery and Barrett reduction, 7-layer NTT and inverse NTT with SIMD butterflies, basemul in Z_q[X]/(X²-ζ), centered binomial distribution sampling (η=2 and η=3), compression and decompression across all five bit-width paths, rejection sampling for matrix generation, and constant-time byte comparison and conditional move. Requires WebAssembly SIMD (`v128` instructions). Uses 3 memory pages (192 KB) with 10 polynomial slots, 8 polynomial vector slots, and dedicated buffers for keys and ciphertexts. See: [Kyber WASM Reference](./asm_kyber.md)

[The TypeScript module](./kyber.md) exports `MlKem512`, `MlKem768`, and `MlKem1024`—KEM classes implementing the Fujisaki-Okamoto transform. All three require both `kyber` and `sha3` to be initialized; the sha3 module provides the Keccak sponge for matrix generation (SHAKE128), noise sampling (SHAKE256), and finalization (SHA3-256 for H, SHA3-512 for G).

**`ct.wasm`** implements constant-time byte array equality with a single SIMD-only primitive. The module exports `compare(aOff, bOff, len)`, which reads both arrays directly from caller-specified offsets in linear memory and returns 1 if all bytes match, 0 otherwise. Comparison is zero-copy: no internal staging buffers, no buffer slots, no `wipeBuffers` export. The implementation is structurally branch-free. A `v128.xor`/`v128.or` accumulator processes 16-byte blocks, a scalar tail handles any remainder, and the final zero-test is an arithmetic shift, not a conditional. Requires WebAssembly SIMD (`v128` instructions); if the runtime lacks SIMD or compilation fails, the first call throws a branded error. See: [Constant-Time WASM Reference](asm_ct.md)

[The TypeScript module](./utils.md#constanttimeequal) exports `constantTimeEqual` and `CT_MAX_BYTES` from the root barrel. The wrapper instantiates the WASM synchronously on first call and caches it for subsequent calls. It writes both arrays into linear memory, calls `compare`, and zeroes both regions in a `finally` block before returning. `CT_MAX_BYTES` is 32 KB per side; the 64 KB page holds two equal-length inputs.

---

## `init()` API

WASM instantiation is async. [`init()`](./init.md) is the initialization gate, call it once before using any cryptographic class. The cost is explicit and the developer controls when it is paid.

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

The loading strategy is inferred from the source type, so there is no need for a mode string. Each module also exports its own init function, such as `serpentInit(source)`, `chacha20Init(source)`, `sha2Init(source)`, `sha3Init(source)`, `keccakInit(source)`, and `kyberInit(source)`, enabling tree-shakeable imports.

> [!NOTE]
> **`keccak` is an alias for `sha3`.** Both names are accepted by `init()`, `initModule()`, `getInstance()`, and `isInitialized()`. They share the same WASM binary and the same instance slot. The alias exists so Kyber/ML-KEM consumers can write `init({ keccak: keccakWasm })` using the semantically correct name for the underlying sponge primitive.

### Embedded subpath exports

Each module provides a `/embedded` subpath that exports the gzip+base64 blob as a ready-to-use `WasmSource`:

```typescript
import { init } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
```

### Behavioral contracts

**Idempotent initialization.** Calling `init()` on an already initialized module is a no-op. It is safe to call `init()` from multiple locations within the codebase.

**Module-scope cache.** Each `WebAssembly.Instance` is cached at module scope after initial instantiation. All subsequent class constructions use the cached instance with no recompilation.

**Error before initialization.** Invoking any cryptographic class before calling `init()` throws a clear error prompting the developer to call `init({ <module>: ... })` first.

**No implicit initialization.** Classes never call `init()` automatically on first use. Explicit initialization is preferable to hidden costs.

**Thread safety.** The main thread uses a single WASM instance per module. `SealStreamPool` provides worker-based parallelism. Each pool worker is spawned from an IIFE bundled at build time and instantiates its own WASM modules with isolated linear memory, bypassing the main-thread cache entirely. For other primitives, create one instance per Worker if Workers are used.

---

## Public API Classes

| Module                          | Classes                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `serpent` + `sha2`              | `SerpentCipher`                                                                                         |
| `serpent`                       | `Serpent`, `SerpentCtr`, `SerpentCbc`                                                                   |
| `chacha20`                      | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher`                      |
| `sha2`                          | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| `sha3`                          | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`                                  |
| `kyber` + `sha3`                | `MlKem512`, `MlKem768`, `MlKem1024`                                                                     |
| `kyber` + `sha3` + inner cipher | `KyberSuite` (hybrid KEM+AEAD factory)                                                                  |
| `sha2`                          | `ratchetInit`, `KDFChain`, `SkippedKeyStore`                                                            |
| `kyber` + `sha3` + `sha2`       | `kemRatchetEncap`, `kemRatchetDecap`, `RatchetKeypair`                                                  |
| `stream`                        | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`                                                    |
| `serpent` + `sha2`              | `Fortuna` with `SerpentGenerator` + `SHA256Hash`                                                        |
| `serpent` + `sha3`              | `Fortuna` with `SerpentGenerator` + `SHA3_256Hash`                                                      |
| `chacha20` + `sha2`             | `Fortuna` with `ChaCha20Generator` + `SHA256Hash`                                                       |
| `chacha20` + `sha3`             | `Fortuna` with `ChaCha20Generator` + `SHA3_256Hash`                                                     |

>[!NOTE]
> Class Names match conventional cryptographic notation.

 - HMAC names use underscore separator (`HMAC_SHA256`) matching RFC convention.
 - SHA-3 names use underscore separator (`SHA3_256`) for readability.
 -  Ratchet exports are KDF primitives from Signal's Sparse Post-Quantum Ratchet spec; session state, message ordering, and header format remain application concerns.
 - **`Fortuna`** requires `await Fortuna.create({ generator, hash })` rather than `new Fortuna()`. Required modules depend on the generator and hash you pass. See [fortuna.md](./fortuna.md) for valid combinations.
 - `SealStream`, `OpenStream`, and `SealStreamPool` are cipher-agnostic; you select the cipher by passing `XChaCha20Cipher` or `SerpentCipher` at construction.

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

|Category|Exports|
|---|---|
|Encoding|`hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64`|
|Security|`constantTimeEqual`, `CT_MAX_BYTES`, `wipe`, `xor`|
|Helpers|`concat`, `randomBytes`, `hasSIMD`|
|Types|`Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD`|

---

## Build Pipeline

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/build-pipeline.svg" alt="Build Pipeline data flow diagram">

1. `npm run build:asm`: AssemblyScript compiler reads `src/asm/*/index.ts`, emits `build/*.wasm`
2. `npm run build:embed`: `scripts/embed-wasm.ts` reads each `.wasm`, gzip compresses, base64 encodes, writes to `src/ts/embedded/*.ts` and per-module `src/ts/*/embedded.ts`
3. `npm run build:embed-workers`: `scripts/embed-workers.ts` bundles each pool worker into a self-contained IIFE via esbuild and writes the source to `src/ts/embedded/<cipher>-pool-worker.ts` as a string export
4. `npm run build:ts`: TypeScript compiler emits `dist/`
5. `cp build/*.wasm dist/`: WASM binaries copied for URL-based consumers
6. At runtime (subpath): `serpentInit(serpentWasm)` → `initModule()` → `loadWasm(source)` → decode gzip+base64 → `WebAssembly.instantiate` → cache in `init.ts`
7. At runtime (root): `init({ serpent: serpentWasm, sha2: sha2Wasm })` → dispatches to each module's init function via `Promise.all` → same path as step 6 per module

`src/ts/embedded/` is gitignored; these files are build artifacts. The WASM blobs (`<module>.ts`) derive from the AssemblyScript source in `src/asm/`. The pool-worker bundles (`<cipher>-pool-worker.ts`) derive from the worker source in `src/ts/<cipher>/pool-worker.ts`, bundled as a self-contained IIFE by `scripts/embed-workers.ts`.

---

## Module Relationships

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

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/import-graph.svg" alt="TS Layer: internal import graph diagram">

Each module's init function (`serpentInit`, `chacha20Init`, `sha2Init`, `sha3Init`, `kyberInit`) calls `initModule()` from `init.ts`, passing a `WasmSource`. `initModule()` delegates to `loadWasm(source)` in `loader.ts`. The loader infers the loading strategy from the source type, with no mode string and no knowledge of module names or embedded file paths.

Pool workers (`serpent/pool-worker.ts`, `chacha20/pool-worker.ts`) instantiate their own WASM modules from pre-compiled `WebAssembly.Module` objects passed via `postMessage`. They do not use `initModule()` or the main-thread cache. Workers are spawned from blob URLs constructed in `cipher-suite.ts` over an IIFE source string built at lib build time (`src/ts/embedded/<cipher>-pool-worker.ts`). The `pool-worker.ts` file itself is the source the bundler reads, not the runtime spawn entry.

---

### TS-to-WASM mapping

Each TS wrapper class maps to one WASM module and specific exported functions. Tier 2 composition classes are pure TypeScript; they call Tier 1 classes rather than WASM functions directly.

**serpent/index.ts → asm/serpent/ (Tier 1: direct WASM callers)**

|TS Class|WASM functions called|
|---|---|
|`Serpent`|`loadKey`, `encryptBlock`, `decryptBlock`, `wipeBuffers` + buffer getters|
|`SerpentCtr`|`loadKey`, `resetCounter`, `setCounter`, `encryptChunk`, `encryptChunk_simd`, `wipeBuffers` + buffer getters|
|`SerpentCbc`|`loadKey`, `cbcEncryptChunk`, `cbcDecryptChunk`, `cbcDecryptChunk_simd`, `wipeBuffers` + buffer getters|
|`SerpentGenerator`|`loadKey`, `encryptBlock`, `wipeBuffers` + buffer getters|

**chacha20/index.ts → asm/chacha20/ (Tier 1: direct WASM callers)**

|TS Class|WASM functions called|
|---|---|
|`ChaCha20`|`chachaLoadKey`, `chachaSetCounter`, `chachaEncryptChunk`, `chachaEncryptChunk_simd`, `wipeBuffers` + buffer getters|
|`Poly1305`|`polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters|
|`ChaCha20Poly1305`|`chachaLoadKey`, `chachaSetCounter`, `chachaGenPolyKey`, `chachaEncryptChunk`, `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters (via `ops.ts`)|
|`XChaCha20Poly1305`|All of `ChaCha20Poly1305` + `hchacha20` + xchacha buffer getters (via `ops.ts`)|
|`ChaCha20Generator`|`chachaLoadKey`, `chachaSetCounter`, `chachaEncryptChunk_simd`, `wipeBuffers` + buffer getters|

**sha2/index.ts → asm/sha2/ (Tier 1: direct WASM callers)**

|TS Class|WASM functions called|
|---|---|
|`SHA256`|`sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters|
|`SHA512`|`sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters|
|`SHA384`|`sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters|
|`HMAC_SHA256`|`hmac256Init`, `hmac256Update`, `hmac256Final`, `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters|
|`HMAC_SHA512`|`hmac512Init`, `hmac512Update`, `hmac512Final`, `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters|
|`HMAC_SHA384`|`hmac384Init`, `hmac384Update`, `hmac384Final`, `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters|
|`SHA256Hash`|`sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters|

**sha3/index.ts → asm/sha3/ (Tier 1: direct WASM callers)**

|TS Class|WASM functions called|
|---|---|
|`SHA3_224`|`sha3_224Init`, `keccakAbsorb`, `sha3_224Final`, `wipeBuffers` + buffer getters|
|`SHA3_256`|`sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters|
|`SHA3_384`|`sha3_384Init`, `keccakAbsorb`, `sha3_384Final`, `wipeBuffers` + buffer getters|
|`SHA3_512`|`sha3_512Init`, `keccakAbsorb`, `sha3_512Final`, `wipeBuffers` + buffer getters|
|`SHAKE128`|`shake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters|
|`SHAKE256`|`shake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters|
|`SHA3_256Hash`|`sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters|

**kyber/index.ts + kyber/kem.ts + kyber/indcpa.ts → asm/kyber/ (Tier 1)**

|TS Class|WASM functions called|
|---|---|
|`MlKem512`, `MlKem768`, `MlKem1024`|`polyvec_ntt`, `polyvec_invntt`, `polyvec_basemul_acc_montgomery`, `polyvec_add`, `polyvec_reduce`, `polyvec_tobytes`, `polyvec_frombytes`, `polyvec_compress`, `polyvec_decompress`, `poly_ntt`, `poly_invntt`, `poly_tomont`, `poly_add`, `poly_sub`, `poly_reduce`, `poly_basemul_montgomery`, `poly_frommsg`, `poly_tomsg`, `poly_compress`, `poly_decompress`, `poly_getnoise`, `rej_uniform`, `ct_verify`, `ct_cmov`, `wipeBuffers` + buffer getters|

All MlKem classes also call sha3 WASM via `indcpa.ts`: `sha3_256Init`, `sha3_512Init`, `shake128Init`, `shake256Init`, `keccakAbsorb`, `sha3_256Final`, `sha3_512Final`, `shakeFinal`, `shakePad`, `shakeSqueezeBlock`.

**Tier 2: pure TS composition**

|TS Class / Object|Composes|
|---|---|
|`SerpentCipher`|`SerpentCbc` + `HMAC_SHA256` + `HKDF_SHA256`|
|`XChaCha20Cipher`|`ChaCha20Poly1305` (via `ops.ts`) + `HKDF_SHA256`|
|`Seal`|`SealStream` + `OpenStream` (degenerate single-chunk case)|
|`SealStream`|`CipherSuite` (generic — caller provides cipher)|
|`OpenStream`|`CipherSuite` (generic — caller provides cipher)|
|`SealStreamPool`|`CipherSuite` + `compileWasm()` + Web Workers|
|`HKDF_SHA256`|`HMAC_SHA256` (extract + expand per RFC 5869)|
|`HKDF_SHA512`|`HMAC_SHA512` (extract + expand per RFC 5869)|
|`Fortuna`|`Generator` + `HashFn` (any compatible pair: `SerpentGenerator`/`ChaCha20Generator` × `SHA256Hash`/`SHA3_256Hash`)|

---

### Cross-module dependencies

|Relationship|Notes|
|---|---|
|`SerpentCipher` → `serpent` + `sha2`|Tier 2 composition: Serpent-CBC + HMAC-SHA256 + HKDF-SHA256.|
|`XChaCha20Cipher` → `chacha20` + `sha2`|HKDF-SHA256 for key derivation + HChaCha20 + ChaCha20-Poly1305 for per-chunk AEAD.|
|`KyberSuite` → `kyber` + `sha3` + inner cipher|KEM encaps/decaps + HKDF with kemCt binding + inner CipherSuite.|
|`SealStream`, `OpenStream` → depends on cipher|Cipher-agnostic. Module requirements are determined by the `CipherSuite` passed at construction.|
|`SealStreamPool` → depends on cipher|Same module requirements as the cipher, plus `WasmSource` in pool opts for worker compilation.|
|`Fortuna` → cipher module + hash module|Uses `Fortuna.create({ generator, hash })` static factory instead of `new`. Required modules depend on which generator and hash you pass. See [fortuna.md](./fortuna.md).|
|`MlKem512`, `MlKem768`, `MlKem1024` → `kyber` + `sha3`|Kyber module handles polynomial arithmetic; sha3 provides SHAKE128/256, SHA3-256/512 for G/H/J/matrix gen.|
|`HKDF_SHA256`, `HKDF_SHA512` → `sha2`|Pure TS composition — extract and expand steps per RFC 5869.|
|All other classes|Each depends on exactly **one** WASM module.|

---

### Public API barrel (`src/ts/index.ts`)

The root barrel defines and exports the dispatching `init()` function. It is the only file that imports all four module-scoped init functions.

|Source|Exports|
|---|---|
|_(barrel itself)_|`init` (dispatching function — calls per-module init functions via `Promise.all`)|
|`init.ts`|`Module`, `WasmSource`, `isInitialized`|
|`errors.ts`|`AuthenticationError`|
|`serpent/index.ts`|`Serpent`, `SerpentCtr`, `SerpentCbc`, `SerpentCipher`, `_serpentReady`|
|`chacha20/index.ts`|`ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher`, `_chachaReady`|
|`sha2/index.ts`|`SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`, `HKDF_SHA256`, `HKDF_SHA512`, `_sha2Ready`|
|`sha3/index.ts`|`SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, `_sha3Ready`|
|`keccak/index.ts`|`keccakInit` + re-exports all sha3 classes (alias subpath)|
|`kyber/index.ts`|`kyberInit`, `KyberSuite`, `MlKem512`, `MlKem768`, `MlKem1024`, `KyberKeyPair`, `KyberEncapsulation`, `KyberParams`, `MLKEM512`, `MLKEM768`, `MLKEM1024`|
|`stream/index.ts`|`Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, `CipherSuite`, `DerivedKeys`, `SealStreamOpts`, `PoolOpts`, `FLAG_FRAMED`, `TAG_DATA`, `TAG_FINAL`, `HEADER_SIZE`, `CHUNK_MIN`, `CHUNK_MAX`|
|`fortuna.ts`|`Fortuna`|
|`types.ts`|`Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD`, `Generator`, `HashFn`|
|`utils.ts`|`hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64`, `constantTimeEqual`, `CT_MAX_BYTES`, `wipe`, `xor`, `concat`, `randomBytes`, `hasSIMD`|

Each subpath export also exports its own module-specific init function for tree-shakeable loading: `serpentInit(source)`, `chacha20Init(source)`, `sha2Init(source)`, `sha3Init(source)`, `keccakInit(source)`.

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
    "./kyber/embedded":       "./dist/kyber/embedded.js",
   	"./ratchet":              "./dist/ratchet/index.js"
  }
}
```

> [!NOTE]
> Pool worker source files (`dist/serpent/pool-worker.js`, `dist/chacha20/pool-worker.js`) ship in the package but are not in the `exports` map. They are the build inputs from which `scripts/embed-workers.ts` produces the IIFE source strings embedded in `dist/<cipher>/cipher-suite.js` at lib build time. Workers are spawned from those embedded strings via classic blob URLs. Consumers do not import the `pool-worker.js` files directly, and bundlers do not need to chunk them. Strict-CSP consumers (`worker-src 'self'`, no `blob:`) can supply their own URL-based factory by spread-overriding `createPoolWorker` on the cipher object; see [ciphersuite.md](./ciphersuite.md).

The root `.` export re-exports everything. Subpath exports allow bundlers to tree-shake at the module level; a consumer importing only `./sha3` does not include the Serpent wrapper classes or their embedded WASM binaries in their bundle.

The `/embedded` subpaths provide gzip+base64 WASM blobs for zero-config usage. Consumers using URL-based or pre-compiled loading can skip the `/embedded` imports entirely, keeping them out of the bundle.

**Tree-shaking:** `"sideEffects": false` is set in `package.json`. Bundlers that support tree-shaking (webpack, Rollup, esbuild) can eliminate unused modules and their embedded WASM binaries from the final bundle.

**Published.** The npm package includes:

- `dist/`: compiled JS, TypeScript declarations, WASM binaries, pool worker source files (build inputs, not runtime spawn entries; see the NOTE above), and a subset of consumer-facing API docs for offline use.
- `CLAUDE.md`: agent-facing project context.
- `SECURITY.md`: vulnerability disclosure policy.

**Not published.** `src/`, `test/`, `build/`, `scripts/`, `.github/`, editor configs.

---

## Buffer Layouts

All offsets start at 0 per module. Independent linear memory. No offsets are shared or coordinated across modules.

### Serpent module (3 pages, 192 KB)

Source: `src/asm/serpent/buffers.ts`

|Offset|Size|Name|
|---|---|---|
|0|32|`KEY_BUFFER` — key input (padded to 32 bytes for all key sizes)|
|32|16|`BLOCK_PT_BUFFER` — single block plaintext|
|48|16|`BLOCK_CT_BUFFER` — single block ciphertext|
|64|16|`NONCE_BUFFER` — CTR mode nonce|
|80|16|`COUNTER_BUFFER` — 128-bit little-endian counter|
|96|528|`SUBKEY_BUFFER` — key schedule output (33 rounds × 4 × 4 bytes)|
|624|65552|`CHUNK_PT_BUFFER` — streaming plaintext (CTR/CBC); +16 from 65536 to fit PKCS7 max overhead|
|66176|65552|`CHUNK_CT_BUFFER` — streaming ciphertext (CTR/CBC)|
|131728|20|`WORK_BUFFER` — 5 × i32 scratch registers (key schedule + S-box/LT rounds)|
|131748|16|`CBC_IV_BUFFER` — CBC initialization vector / chaining value|
|131856|—|END|

`wipeBuffers()` zeroes all 10 buffers (key, block pt/ct, nonce, counter, subkeys, work, chunk pt/ct, CBC IV).

### ChaCha20 module (3 pages, 192 KB)

Source: `src/asm/chacha20/buffers.ts`

|Offset|Size|Name|
|---|---|---|
|0|32|`KEY_BUFFER` — ChaCha20 256-bit key|
|32|12|`CHACHA_NONCE_BUFFER` — 96-bit nonce (3 × u32, LE)|
|44|4|`CHACHA_CTR_BUFFER` — u32 block counter|
|48|64|`CHACHA_BLOCK_BUFFER` — 64-byte keystream block output|
|112|64|`CHACHA_STATE_BUFFER` — 16 × u32 initial state|
|176|65536|`CHUNK_PT_BUFFER` — streaming plaintext|
|65712|65536|`CHUNK_CT_BUFFER` — streaming ciphertext|
|131248|32|`POLY_KEY_BUFFER` — one-time key r‖s|
|131280|64|`POLY_MSG_BUFFER` — message staging (≤ 64 bytes per polyUpdate)|
|131344|16|`POLY_BUF_BUFFER` — partial block accumulator|
|131360|4|`POLY_BUF_LEN_BUFFER` — u32 bytes in partial block|
|131364|16|`POLY_TAG_BUFFER` — 16-byte output MAC tag|
|131380|40|`POLY_H_BUFFER` — accumulator h: 5 × u64|
|131420|40|`POLY_R_BUFFER` — clamped r: 5 × u64|
|131460|32|`POLY_RS_BUFFER` — precomputed 5×r[1..4]: 4 × u64|
|131492|16|`POLY_S_BUFFER` — s pad: 4 × u32|
|131508|24|`XCHACHA_NONCE_BUFFER` — full 24-byte XChaCha20 nonce|
|131532|32|`XCHACHA_SUBKEY_BUFFER` — HChaCha20 output (key material)|
|131564|4|_(padding for 16-byte SIMD alignment)_|
|131568|256|`CHACHA_SIMD_WORK_BUFFER` — 4-wide inter-block keystream (4 × 64 bytes)|
|131824|—|END|

`wipeBuffers()` zeroes all 15 buffer regions (key, chacha nonce/ctr/block/state, chunk pt/ct, poly key/msg/buf/tag/h/r/rs/s, xchacha nonce/subkey, SIMD work).

### SHA-2 module (3 pages, 192 KB)

Source: `src/asm/sha2/buffers.ts`

|Offset|Size|Name|
|---|---|---|
|0|32|`SHA256_H` — SHA-256 hash state H0..H7 (8 × u32)|
|32|64|`SHA256_BLOCK` — SHA-256 block accumulator|
|96|256|`SHA256_W` — SHA-256 message schedule W[0..63] (64 × u32)|
|352|32|`SHA256_OUT` — SHA-256 digest output|
|384|64|`SHA256_INPUT` — SHA-256 user input staging (one block)|
|448|4|`SHA256_PARTIAL` — u32 partial block length|
|452|8|`SHA256_TOTAL` — u64 total bytes hashed|
|460|64|`HMAC256_IPAD` — HMAC-SHA256 K' XOR ipad|
|524|64|`HMAC256_OPAD` — HMAC-SHA256 K' XOR opad|
|588|32|`HMAC256_INNER` — HMAC-SHA256 inner hash|
|620|64|`SHA512_H` — SHA-512 hash state H0..H7 (8 × u64)|
|684|128|`SHA512_BLOCK` — SHA-512 block accumulator|
|812|640|`SHA512_W` — SHA-512 message schedule W[0..79] (80 × u64)|
|1452|64|`SHA512_OUT` — SHA-512 digest output (SHA-384 uses first 48 bytes)|
|1516|128|`SHA512_INPUT` — SHA-512 user input staging (one block)|
|1644|4|`SHA512_PARTIAL` — u32 partial block length|
|1648|8|`SHA512_TOTAL` — u64 total bytes hashed|
|1656|128|`HMAC512_IPAD` — HMAC-SHA512 K' XOR ipad (128-byte block size)|
|1784|128|`HMAC512_OPAD` — HMAC-SHA512 K' XOR opad|
|1912|64|`HMAC512_INNER` — HMAC-SHA512 inner hash|
|1976|—|END|

`wipeBuffers()` zeroes all 20 buffer regions (SHA-256 state/block/W/out/input/partial/total, HMAC-256 ipad/opad/inner, SHA-512 state/block/W/out/input/partial/total, HMAC-512 ipad/opad/inner).

### SHA-3 module (3 pages, 192 KB)

Source: `src/asm/sha3/buffers.ts`

|Offset|Size|Name|
|---|---|---|
|0|200|`KECCAK_STATE`: 25 × u64 Keccak-f[1600] lane matrix (5×5, row-major x+5y)|
|200|4|`KECCAK_RATE`: u32 rate in bytes (variant-specific: 72–168)|
|204|4|`KECCAK_ABSORBED`: u32 bytes absorbed into current block|
|208|1|`KECCAK_DSBYTE`: u8 domain separation byte (0x06 for SHA-3, 0x1f for SHAKE)|
|209|168|`KECCAK_INPUT`: input staging buffer (max rate = SHAKE128 at 168 bytes)|
|377|168|`KECCAK_OUT`: output buffer (one SHAKE128 squeeze block)|
|545|—|END|

`wipeBuffers()` zeroes all 6 buffer regions (state, rate, absorbed, dsbyte, input, output).

### Kyber module (3 pages, 192 KB)

Source: `src/asm/kyber/`

|Region|Offset|Size|Purpose|
|---|---|---|---|
|AS data segment|0|4096|Zetas table (128 × i16, bit-reversed Montgomery domain)|
|Poly slots|4096|5120|10 × 512B scratch polynomials (256 × i16 each)|
|Polyvec slots|9216|16384|8 × 2048B scratch polyvecs (k=4 max: 4 × 512B)|
|SEED buffer|25600|32|Seed ρ/σ|
|MSG buffer|25632|32|Message / shared secret|
|PK buffer|25664|1568|Encapsulation key (max k=4)|
|SK buffer|27232|1536|IND-CPA secret key (max k=4)|
|CT buffer|28768|1568|Ciphertext (max k=4)|
|CT_PRIME buffer|30336|1568|Decaps re-encrypt comparison (max k=4)|
|XOF/PRF buffer|31904|1024|SHAKE squeeze output for rej_uniform / CBD|
|Poly accumulator|32928|512|Internal scratch for polyvec_basemul_acc|

Total mutable: 29344 bytes (4096–33440). End = 33440 < 192 KB.

`wipeBuffers()` zeroes all mutable regions (poly slots, polyvec slots, SEED, MSG, PK, SK, CT, CT_PRIME, XOF/PRF, accumulator). The zetas data segment is read-only and is not wiped.

---

## Test Suite

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/testing.svg" alt="Test Suite data flow diagram" width="800">

### Structure

For the full testing methodology and vector corpus, see: [test-suite.md](./test-suite.md)

### Gate discipline

**Each primitive family has a gate test:** the simplest authoritative vector for that primitive. The gate must pass before any other tests in that family are written or run. Gate tests are annotated with a `// GATE` comment.

### `init.test.ts` contracts

- `init()` with each `WasmSource` type loads and caches the module correctly
- Idempotency: second `init()` call for same module is a no-op
- Error before init: clear error thrown for each class before its module is loaded
- Partial init: loading `{ serpent: ... }` does not make `sha3` classes available

---

## Correctness Contract

leviathan-crypto must produce byte-identical output to the authoritative specification for every known test vector. Cross-checks against the leviathan TypeScript reference and external tools (OpenSSL, Python hashlib, Node.js crypto) provide additional verification layers.

The vector corpus in `test/vectors/` act as a source of immutable known-answer-test truth. KAT files are reference data from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP, NESSIE) or are self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates integrity against `SHA256SUMS`. See [test-suite.md](./test-suite.md) for the full corpus inventory, provenance, and gate discipline.

---

## Known Limitations

- **`SerpentCbc` is unauthenticated**: use `Seal` with `SerpentCipher` for authenticated Serpent encryption, or pair `SerpentCbc` with `HMAC_SHA256` (Encrypt-then-MAC) if direct CBC access is required.
- **Single-threaded WASM per instance**: one WASM instance per binary per thread. `SealStreamPool` provides Worker-based parallelism for both cipher families; other primitives remain single-threaded.
- **Max input per WASM call**: CTR accepts at most 65536 bytes per call; CBC accepts at most 65552 bytes (65536 + 16 bytes PKCS7 maximum overhead). Wrappers handle splitting automatically for larger inputs.
- **WASM side-channel posture**: WebAssembly implementations offer the best available side-channel resistance (branchless, table-free), but lack hardware-level constant-time guarantees. For applications where timing side channels are a primary threat, a native cryptographic library with verified constant-time guarantees will be more appropriate than any WASM-based implementation.

---

## Cross-References

|Document|Description|
|---|---|
|[index](./README.md)|Project Documentation index|
|[lexicon](./lexicon.md)|Glossary of cryptographic terms|
|[test-suite](./test-suite.md)|testing methodology, vector corpus, and gate discipline|
|[init](./init.md)|`init()` API, `WasmSource`, and idempotent behavior|
|[loader](./loader.md)|internal WASM binary loading strategies|
|[wasm](./wasm.md)|WebAssembly primer: modules, instances, memory, and the init gate|
|[types](./types.md)|public TypeScript interfaces and `CipherSuite`|
|[utils](./utils.md)|encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`|
|[authenticated encryption](./aead.md)|`Seal`, `SealStream`, `OpenStream`: cipher-agnostic AEAD APIs using a `CipherSuite` such as `SerpentCipher` or `XChaCha20Cipher`|
|[serpent](./serpent.md)|Serpent-256 TypeScript API, SerpentCipher|
|[chacha20](./chacha20.md)|ChaCha20/Poly1305 TypeScript API, XChaCha20Cipher|
|[sha2](./sha2.md)|SHA-2 hashes, HMAC, and HKDF TypeScript API|
|[sha3](./sha3.md)|SHA-3 hashes and SHAKE XOFs TypeScript API|
|[fortuna](./fortuna.md)|Fortuna CSPRNG with forward secrecy and entropy pooling|
|[argon2id](./argon2id.md)|Argon2id password hashing and key derivation|
