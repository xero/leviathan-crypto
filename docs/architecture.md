<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Architecture

Overview of Leviathan Crypto's architecture, comprising eight independent WASM modules unified by a misuse-resistant TypeScript API: a Cipher Triptych of Serpent-256, XChaCha20-Poly1305, and AES-256-GCM-SIV, post-quantum ML-KEM key encapsulation and ML-DSA signatures, and a forward-secret ratchet built on Signal's SPQR. Zero-dependency, tree-shakable, side-effect free.

> ### Table of Contents
>
> - [Architectural overview](#architectural-overview)
> - [Scope](#scope)
> - [Repository Structure](#repository-structure)
> - [Eight Independent WASM Modules](#eight-independent-wasm-modules)
> - [init() API](#init-api)
> - [Public API Classes](#public-api-classes)
> - [Build Pipeline](#build-pipeline)
> - [Module Relationships](#module-relationships)
> - [npm Package](#npm-package)
> - [Buffer Layouts](#buffer-layouts)
> - [Test Suite](#test-suite)
> - [Correctness Contract](#correctness-contract)
> - [Cryptanalytic margin](#cryptanalytic-margin)
> - [Constant-time at the algorithm level](#constant-time-at-the-algorithm-level)
>     - [Algorithm choice](#algorithm-choice)
>     - [TS-layer routing](#ts-layer-routing)
>     - [Documented exceptions](#documented-exceptions)
> - [Implementation discipline](#implementation-discipline)
>     - [Agentic development contracts](#agentic-development-contracts)
> - [WebAssembly is the deployment vehicle](#webassembly-is-the-deployment-vehicle)
> - [Threat model](#threat-model)
> - [Defended attacks](#defended-attacks)
>     - [Runtime](#runtime)
>     - [Distribution](#distribution)
> - [Where defense ends](#where-defense-ends)
> - [The honest comparison](#the-honest-comparison)
> - [Known Limitations](#known-limitations)
> - [Cross-References](#cross-references)

---

## Architectural overview

**Zero runtime dependencies.** No npm graph to audit. No supply chain attack surface. Argon2id is the one optional integration, documented separately and consumer-installed. **Tree-shakeable.** Import only what you use. Subpath exports let bundlers exclude everything else. **Side-effect free.** Nothing runs on import. [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) is explicit and asynchronous.

**Cipher Triptych.** Leviathan provides three ciphers. The implementations all use a round structure that runs as a bitsliced Boolean circuit implemented as register-only logic with no S-box lookup tables. Each compiles to an independent v128 SIMD optimized WebAssembly module, with isolated linear memory, preventing cross-module memory access by design. Every operation zeroes key material on exit, including on failure.

**[Serpent-256](https://github.com/xero/leviathan-crypto/wiki/serpent_reference): maximum paranoia.** 32 rounds of eight different 4-bit S-boxes, each bitsliced as a Boolean circuit with no table lookups. An ouroboros devouring every bit, in every block, through every round.

**[XChaCha20-Poly1305](https://github.com/xero/leviathan-crypto/wiki/chacha_reference): precise elegance.** 20 rounds of add-rotate-XOR alternating column and diagonal quarter-rounds, choreography without S-boxes or cache-timing leakage. A dance closing with Poly1305's unconditional forgery bound.

**[AES-256-GCM-SIV](https://github.com/xero/leviathan-crypto/wiki/aes): industry standard, sharpened.** 14 rounds bitsliced into Boolean gates with tower-field S-box with no table lookups. A fresh POLYVAL key per nonce leaves GHASH-key recovery with no target.

**Below the cipher suites sit two hash primitive families:** SHA-2 (SHA-224/256/384/512 and SHA-512/224/256 with HMAC and HKDF variants) and SHA-3 (SHA3-224/256/384/512 and SHAKE128/256). The round permutations are constant-time by algorithm design: pure bit operations with no S-box lookups and no data-dependent branches. SHA-2 powers the seal layer's HKDF key derivation and Serpent's HMAC authentication. SHA-3 is the Keccak sponge ML-KEM and ML-DSA rely on internally. The SHA-512 truncation variants (SHA-512/224, SHA-512/256) and SHA-224 support the twelve HashML-DSA pre-hash functions.

**Above the cipher suites sits a cipher-agnostic AEAD layer:** `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool`. Each takes a `CipherSuite` at construction, and the seal layer handles key derivation, nonce management, and authentication. `Seal` covers one-shot encryption for data that fits in memory. `SealStream` and `OpenStream` handle chunked data too large to buffer. WASM instances are single-threaded by design, so `SealStreamPool` distributes chunks across Web Workers to reach multi-core throughput. Any authentication failure kills the pool. Pending operations reject, workers zero their keys and terminate, and the master copies zero synchronously. No retry, no partial results. All four share one wire format. A `Seal` blob is structurally a single-chunk `SealStream` output, and `OpenStream` decrypts it interchangeably.

**ML-KEM is the post-quantum key encapsulation mechanism.** `KyberSuite` is a fourth `CipherSuite` factory that wraps an ML-KEM parameter set around any of the three ciphers above. The result satisfies the same `CipherSuite` interface and slots into `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` unchanged. ML-KEM is a lattice-based key encapsulation mechanism with three security levels: ML-KEM-512, ML-KEM-768, and ML-KEM-1024. Constant-time comparisons for the Fujisaki-Okamoto transform run within the Kyber WASM module, so secret-derived comparisons never cross to JavaScript. The 32-byte shared secret never crosses the wire. It also derives directly from a SHA-3 output rather than a big-integer encoding, so the leading-zero-trim timing leak that hit TLS-DH(E) (the Raccoon attack) has no structural analog here.

**ML-DSA is the post-quantum signature peer.** `MlDsa44`, `MlDsa65`, and `MlDsa87` are FIPS 204 lattice-based signatures at NIST security categories 2, 3, and 5. The ring arithmetic, NTT, and rejection-sampling kernels are constant-time at the algorithm level, and the c̃ comparison in verify routes through the same SIMD `ct.equal` primitive used elsewhere in the library. Signing is hedged by default. HashML-DSA wraps the same Sign and Verify primitives with a per-function OID DER prefix and a 0x01 domain-separator byte for cross-protocol separation. All FIPS 204 hard checks land at runtime, including the three HintBitUnpack malformed-input checks added in §D.3.

**Fortuna is the library's CSPRNG.** It collects entropy from platform-specific sources (browser input events, timing jitter, Node.js process stats, plus `crypto.getRandomValues()` as a baseline), distributes it across 32 independent pools, and reseeds an internal generator built on a cipher-as-PRF construction. The generator key is replaced after every `get()` call, so state compromise at time T cannot reveal any output produced before T. The primitive pair is pluggable, mirroring `CipherSuite`'s extension-point pattern: any of the three ciphers above plugs into the generator, paired with either SHA-256 or SHA3-256 for hashing.

**Above the seal layer sits the ratchet module:** KDF primitives from Signal's Sparse Post-Quantum Ratchet (SPQR), the post-quantum extension of the Double Ratchet protocol. `ratchetInit` bootstraps the root and chain keys from an out-of-band shared secret. `KDFChain` advances a symmetric chain key and derives per-message keys with forward secrecy. `kemRatchetEncap` and `kemRatchetDecap` perform the ML-KEM ratchet step for post-compromise security. `SkippedKeyStore` caches message keys for out-of-order delivery; cached keys return through a transactional handle that commits on auth success and rolls back on failure, so a garbage ciphertext at a valid counter cannot consume the legitimate message's slot. The store also bounds memory and per-message HKDF work, so a malicious header with a high counter cannot force unbounded derivations. These are primitives, not a full session: state machines, message counters, header format, and epoch orchestration are application concerns. Consumers compose them with their own transport for forward-secret protocols whose needs outgrow one-shot AEAD.

**Alongside the WASM-backed primitives ships a utility tier.** No `init()` call required, every utility function works immediately on import. Pure-TypeScript encoding converters handle hex, base64, and the common byte-format round-trips. `wipe` and `xor` modules cover byte-buffer zeroing and exclusive OR logical operations. The `ct` module is the constant-time path. It carries its own dedicated WebAssembly binary that compiles synchronously, with a zero-copy v128 SIMD XOR-accumulate kernel. `ct.equal()` is the library's recommended path for any equality check on secret material.

**Discipline holds it together.** Every cipher, hash, and KEM derives independently from its authoritative spec, never ported from another implementation. Known-answer test vectors come from spec authors, and cross-checks run against multiple independent reference implementations. The test suite covers unit tests at the primitive level plus end-to-end tests across three browser engines (Chromium, Firefox, WebKit) and Node.js. Detailed reference documentation ships at the [project wiki](https://github.com/xero/leviathan-crypto/wiki).

---

## Scope

**Primitives.** WASM algorithms with their TypeScript wrapper classes.

| Module                        | Algorithms                                                                                                                                                                        | TypeScript API                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`serpent`](./asm_serpent.md) | Serpent-256 block cipher: ECB, CTR, CBC                                                                                                                                           | [`Serpent`](./serpent.md) (cipher class for mode operations)                                                                                                                                                                                                                                                                                                                                               |
| [`chacha20`](./asm_chacha.md) | ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305                                                                                                                         | [`ChaCha20`](./chacha20.md#chacha20), [`Poly1305`](./chacha20.md#poly1305), [`XChaCha20Poly1305`](./chacha20.md#xchacha20poly1305)                                                                                                                                                                                                                                                                         |
| [`aes`](./asm_aes.md)         | AES-128/192/256 block cipher (FIPS 197), CBC, CTR, GCM, GCM-SIV (RFC 8452)                                                                                                        | [`AES`](./aes.md), [`AESCbc`](./aes.md), [`AESCtr`](./aes.md), [`AESGCM`](./aes.md), [`AESGCMSIV`](./aes.md), [`AESGenerator`](./aes.md) (Practical Cryptography §9.4 generator for `Fortuna`)                                                                                                                                                                                                             |
| [`sha2`](./asm_sha2.md)       | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, HMAC variants, HKDF variants                                                                                        | [`SHA224`](./sha2.md#sha224), [`SHA256`](./sha2.md#sha256), [`SHA384`](./sha2.md#sha384), [`SHA512`](./sha2.md#sha512), [`SHA512_224`](./sha2.md#sha512_224), [`SHA512_256`](./sha2.md#sha512_256), [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), [`HMAC_SHA512`](./sha2.md#hmac_sha512), [`HKDF_SHA256`](./sha2.md#hkdf_sha256), [`HKDF_SHA512`](./sha2.md#hkdf_sha512) |
| [`sha3`](./asm_sha3.md)       | SHA3-224/256/384/512, SHAKE128, SHAKE256 (XOFs), cSHAKE128/256, KMAC128/256, KMACXOF128/256 (SP 800-185)                                                                            | [`SHA3_224`](./sha3.md#sha3_224), [`SHA3_256`](./sha3.md#sha3_256), [`SHA3_384`](./sha3.md#sha3_384), [`SHA3_512`](./sha3.md#sha3_512), [`SHAKE128`](./sha3.md#shake128), [`SHAKE256`](./sha3.md#shake256), [`CSHAKE128`](./kmac.md#cshake128), [`CSHAKE256`](./kmac.md#cshake256), [`KMAC128`](./kmac.md#kmac128), [`KMAC256`](./kmac.md#kmac256), [`KMACXOF128`](./kmac.md#kmacxof128), [`KMACXOF256`](./kmac.md#kmacxof256) |
| [`kyber`](./asm_kyber.md)     | ML-KEM polynomial arithmetic (FIPS 203): SIMD NTT, basemul, CBD, compression, FO comparisons                                                                                      | [`MlKem512`](./kyber.md#parameter-sets), [`MlKem768`](./kyber.md#parameter-sets), [`MlKem1024`](./kyber.md#parameter-sets)                                                                                                                                                                                                                                                                                 |
| [`mldsa`](./asm_mldsa.md)     | ML-DSA polynomial arithmetic (FIPS 204): SIMD NTT over q=8380417, rejection sampling, Power2Round, Decompose, MakeHint, HintBitPack/Unpack with §D.3 SUF-CMA checks, SampleInBall | [`MlDsa44`](./mldsa.md), [`MlDsa65`](./mldsa.md), [`MlDsa87`](./mldsa.md) (pure ML-DSA and HashML-DSA across the twelve §5.4.1 pre-hash functions)                                                                                                                                                                                                                                                         |
| [`ct`](./asm_ct.md)           | Constant-time comparison primitives                                                                                                                                               | [`constantTimeEqual`](./utils.md#constanttimeequal)                                                                                                                                                                                                                                                                                                                                                        |


**Cipher Suites.** Composition of WASM modules into complete cipher packages.

| Suite                                                 | Composition                                | Use case                                        |
| ----------------------------------------------------- | ------------------------------------------ | ----------------------------------------------- |
| [`SerpentCipher`](./ciphersuite.md#serpentcipher)     | `serpent` + `sha2` (CBC+HMAC-SHA256)       | Authenticated encryption via STREAM             |
| [`XChaCha20Cipher`](./ciphersuite.md#xchacha20cipher) | `chacha20` (XChaCha20-Poly1305 AEAD)       | Streaming authenticated encryption              |
| [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher) | `aes` + `sha2` (AES-256-GCM-SIV, RFC 8452) | Nonce-misuse-resistant authenticated encryption |
| [`KyberSuite`](./ciphersuite.md#kybersuite)           | `kyber` + (any cipher)                     | Post-quantum key encapsulation                  |


**High-Level Constructs.** Pure TypeScript abstractions over cipher suites.

| API                                                                                                                                                                                                                                             | Dependencies                     | Purpose                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | -------------------------------------------------- |
| [`Seal`](./aead.md#seal) / [`SealStream`](./aead.md#sealstream) / [`OpenStream`](./aead.md#openstream) / [`SealStreamPool`](./aead.md#sealstreampool)                                                                                           | Any CipherSuite                  | One-shot, streaming, decrypting, and parallel AEAD |
| [`ratchetInit`](./ratchet.md#ratchetinitsk-context), [`KDFChain`](./ratchet.md#kdfchain), [`kemRatchetEncap`](./ratchet.md#kemratchetencapkem-rk-peerek-context)/[`kemRatchetDecap`](./ratchet.md#kemratchetdecapkem-rk-dk-kemct-ownek-context) | `sha2`; `kyber` + `sha3` for KEM | Forward-secret session ratcheting (SPQR)           |
| [`Fortuna`](./fortuna.md)                                                                                                                                                                                                                       | Cipher PRF + HashFn              | Cryptographically-secure RNG                       |

**Utilities.** Pure TypeScript helpers, no `init()` dependency.

| Utility                                                                      | Purpose                                          |
| ---------------------------------------------------------------------------- | ------------------------------------------------ |
| [`hexToBytes`](./utils.md#hextobytes), [`bytesToHex`](./utils.md#bytestohex) | Hex/byte conversions                             |
| [`wipe`](./utils.md#wipe)                                                    | Secure memory zeroing                            |
| [`xor`](./utils.md#xor), [`concat`](./utils.md#concat)                       | Byte operations                                  |
| [`randomBytes`](./utils.md#randombytes)                                      | One-off random byte generation                   |
| [`constantTimeEqual`](./utils.md#constanttimeequal)                          | Timing-attack resistant comparison (WASM-backed) |

---

## Repository Structure

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/repo-structure.svg" alt="Repo Structure concentric rings diagram" width="600">

Source lives under `src/`, split between AssemblyScript primitives in `src/asm/` and the TypeScript API in `src/ts/`. Tests are in `test/`. Build, codegen, and tooling scripts go in `scripts/`. CI/CD configuration sits in `.github/`. The repository root holds project documentation, package metadata, and tool configs. Each subsection below shows the relevant tree and notes the conventions that apply across files in that tier.

### CI/CD

`.github/` holds GitHub-specific repository configuration: workflow definitions, the CI image build context, and platform metadata. Workflows split along functional lines.

**Merge gate.** `build.yml`, `lint.yml`, `e2e.yml`, `test-suite.yml`. `test-suite.yml` orchestrates the per-domain unit runners (`unit-*.yml`) plus `verify-vectors.yml` for parallel execution and per-domain failure isolation.

**Test vectors.** `verify-vectors.yml` runs two sequenced jobs. `hashsums` reads `test/vectors/SHA256SUMS` and runs `sha256sum --check` against every pinned vector file, catching accidental edits or supply-chain tampering of the corpus. `rust-verify` depends on `hashsums`, builds the [`scripts/verify-vectors/`](./vector_audit.md) crate with the pinned Rust toolchain (1.95.0) and pinned `Cargo.lock`, and re-derives every Tier 2 KAT byte from RustCrypto primitives that share zero code with leviathan-crypto's WASM stack. The verifier covers ten cipher targets: `xchacha`, `serpent`, `aes-gcm-siv`, `polyval`, `aes`, `aes-cbc`, `aes-ctr`, `aes-gcm`, `mlkem`, and `mldsa`. Cold builds take roughly 60 seconds; cached runs complete in under 15. See [vector_audit.md](./vector_audit.md) for the full tier classification, what the verifier proves, and what it does not.

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
    ├── unit-aes.yml
    ├── unit-aes-montecarlo.yml
    ├── unit-aes-siv.yml
    ├── unit-chacha20.yml
    ├── unit-core.yml
    ├── unit-hashing.yml
    ├── unit-kyber.yml
    ├── unit-mldsa.yml
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

`scripts/` holds the build, codegen, and tooling scripts that produce `dist/` and the test-vector corpus, plus the independent Rust verifier crate. Four categories.

**Build orchestration.** Four top-level dispatchers front the package scripts: `build.ts` (the `bun bake` shorthand and the canonical `bun run build`), `test.ts` (`bun scripts/test.ts <unit|unit:group|e2e|e2e:install|all>`), `lint.ts` (`bun fix` and the canonical `bun run lint`), and `check.ts` (`bun check`, which runs a full build then lint + unit + e2e in parallel). They share a typed dependency DAG (`scripts/lib/build-graph.ts`), a parallel runner with per-task timing and colored output (`scripts/lib/parallel.ts`), the canonical eight-module list (`scripts/lib/modules.ts`), and the per-CI-group test composition (`scripts/lib/test-groups.ts`). Underneath the dispatchers, the step scripts do the actual work: `build-asm.ts` drives AssemblyScript compilation across the eight modules; `embed-wasm.ts` produces the gzip+base64 blob for each `.wasm`; `embed-workers.ts` bundles each pool worker into a self-contained IIFE via esbuild; `copy-docs.ts` ships the consumer doc subset into `dist/`. See [Build Pipeline](#build-pipeline) for the full sequence.

**Codegen.** `generate_simd.ts` produces `src/asm/serpent/serpent_simd.ts` from a template by translating S-box gate logic into v128 ops; the generator and its output are both committed and the output is never edited by hand. `gen-seal-vectors.ts`, `gen-sealstream-vectors.ts`, `gen-fortuna-vectors.ts`, and `gen-ratchet-vectors.ts` produce known-answer-test vectors for their respective primitives.

**Tooling.** `gen-changelog.ts` generates `CHANGELOG` entries. `lint-asm.ts` lints the AssemblyScript sources via `asc --pedantic`. `pin-actions.ts` pins every GitHub Action reference to a SHA, run via `bun pin` after workflow changes.

**Independent verifier.** `verify-vectors/` is a standalone Rust crate that re-runs every Tier 2 KAT against RustCrypto primitives. It builds with a pinned toolchain and pinned dependencies, runs in CI under `verify-vectors.yml`, and shares no code with the leviathan-crypto WASM stack. Provenance details and tier classification live in [vector_audit.md](./vector_audit.md).

```
scripts/
├── build.ts             ← dispatcher · bun bake [target]
├── check.ts             ← dispatcher · bun check (build + lint + unit + e2e)
├── lint.ts              ← dispatcher · bun fix · bun scripts/lint.ts [ts|asm|all]
├── test.ts              ← dispatcher · bun scripts/test.ts [unit|unit:group <name>|e2e|e2e:install|all]
├── build-asm.ts
├── copy-docs.ts
├── embed-wasm.ts
├── embed-workers.ts
├── gen-changelog.ts
├── gen-fortuna-vectors.ts
├── gen-ratchet-vectors.ts
├── gen-seal-vectors.ts
├── gen-sealstream-vectors.ts
├── generate_simd.ts
├── lint-asm.ts
├── pin-actions.ts
├── lib/                 ← shared DAG, parallel runner, module list, test groups
│   ├── build-graph.ts
│   ├── modules.ts
│   ├── parallel.ts
│   └── test-groups.ts
└── verify-vectors/      ← independent Rust verifier (Cargo crate, pinned deps)
    ├── Cargo.lock
    ├── Cargo.toml
    └── src/             ← per-cipher verifiers + parser + primitives
```

### AssemblyScript layer

`src/asm/` holds the AssemblyScript sources for each WASM binary. Every subdirectory compiles to its own `.wasm` with fully independent linear memory and no cross-module imports.

**Per-module conventions.** Every module exposes an `index.ts` as the asc entry point; it re-exports the public surface that becomes the WASM exports. Every module except `ct/` has a `buffers.ts` that defines the static memory layout and the offset getters that all other files in that module import. The `ct/` module is intentionally minimal: a single `index.ts` whose layout is implicit in its single 64 KB page.

```
src/asm/
├── aes/
│   ├── index.ts
│   ├── aes.ts             ← bitsliced AES-128/192/256 encrypt/decrypt (8-block parallel)
│   ├── sbox.ts            ← Canright tower-field S-box (forward + inverse)
│   ├── cbc.ts             ← CBC mode
│   ├── cbc_simd.ts        ← SIMD CBC decrypt
│   ├── ctr.ts             ← CTR mode
│   ├── ctr_simd.ts        ← SIMD CTR 8-wide inter-block
│   ├── gcm.ts             ← AES-GCM AEAD (RFC 5288)
│   ├── ghash.ts           ← GHASH universal hash (SP 800-38D §6.4)
│   ├── gf128.ts           ← GF(2^128) 4-bit windowed multiplier
│   ├── polyval.ts         ← POLYVAL (RFC 8452 §3) via reflected GHASH
│   ├── aes-gcm-siv.ts     ← AES-GCM-SIV AEAD (RFC 8452)
│   ├── wipe.ts            ← module-wide buffer zeroizer
│   └── buffers.ts
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
├── mldsa/
│   ├── index.ts
│   ├── ntt.ts          ← scalar NTT/invNTT for q=8380417 + zetas table
│   ├── ntt_simd.ts     ← v128 i32 NTT butterflies
│   ├── reduce.ts       ← Montgomery/Barrett reduction over q
│   ├── poly.ts         ← polynomial serialization, compression, basemul
│   ├── poly_simd.ts    ← SIMD poly add/sub/reduce wrappers
│   ├── polyvec.ts      ← k/ℓ-wide polyvec operations
│   ├── rounding.ts     ← Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint, HintBitPack/Unpack
│   ├── sampling.ts     ← rej_ntt_poly (matrix Â), rej_bounded_poly (s₁/s₂), SampleInBall
│   ├── encoding.ts     ← bit-pack/unpack at every required width
│   ├── params.ts       ← q, γ₁/γ₂, η, β, τ, ω, λ per parameter set
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

**Cipher modules** (`serpent/`, `chacha20/`, `aes/`) add a `cipher-suite.ts` (the `CipherSuite` implementation for the seal layer), a `pool-worker.ts` (Web Worker source for `SealStreamPool`), a `generator.ts` (Fortuna `Generator`), and a `shared-ops.ts` (serpent) or `ops.ts` (chacha20, aes) holding pure primitive functions shared between the cipher-suite and the pool worker.

**Hash modules** (`sha2/`, `sha3/`) add a `hash.ts` (the stateless Fortuna `HashFn`).

**Signature module** (`mldsa/`) has no `cipher-suite.ts` or `pool-worker.ts` (signing and verification are not AEAD operations). It splits its surface into `keygen.ts`, `sign.ts`, `verify.ts`, `format.ts` (M' construction with domain separator and OID prefix), `hashvariant.ts` (the twelve §5.4.1 pre-hash dispatch), `expand.ts` (ExpandA, ExpandS, ExpandMask, SampleInBall via SHAKE), `validate.ts` (input validation), and `sha3-helpers.ts` (sponge orchestration).

**Shared utilities.** `shared/` holds primitives reused across cipher modules without belonging to any one of them. `pkcs7.ts` is the canonical PKCS#7 padding helper used by Serpent CBC and consumer code.

**Build artifacts.** `ct-wasm.ts` and the `embedded/` directory hold auto-generated outputs that only exist after `bun bake`. Both are gitignored. `ct-wasm.ts` is the inline raw byte array of the ct WASM module. `embedded/` holds gzip+base64 blobs of each WASM binary (from `scripts/embed-wasm.ts`) and IIFE source strings for each pool worker (from `scripts/embed-workers.ts`).

```
src/ts/
├── aes/
│   ├── aes-cbc.ts
│   ├── aes-ctr.ts
│   ├── aes-gcm.ts
│   ├── aes-gcm-siv.ts
│   ├── cipher-suite.ts
│   ├── embedded.ts
│   ├── generator.ts
│   ├── index.ts
│   ├── ops.ts
│   ├── pool-worker.ts
│   └── types.ts
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
│   ├── aes-pool-worker.ts          ← AES pool-worker IIFE source string
│   ├── aes.ts                      ← aes.wasm gzip+base64 blob
│   ├── chacha20-pool-worker.ts     ← ChaCha20 pool-worker IIFE source string
│   ├── chacha20.ts                 ← chacha20.wasm gzip+base64 blob
│   ├── kyber.ts                    ← kyber.wasm gzip+base64 blob
│   ├── mldsa.ts                    ← mldsa.wasm gzip+base64 blob
│   ├── serpent-pool-worker.ts      ← Serpent pool-worker IIFE source string
│   ├── serpent.ts                  ← serpent.wasm gzip+base64 blob
│   ├── sha2.ts                     ← sha2.wasm gzip+base64 blob
│   └── sha3.ts                     ← sha3.wasm gzip+base64 blob
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
├── mldsa/
│   ├── embedded.ts
│   ├── expand.ts        ← ExpandA, ExpandS, ExpandMask, SampleInBall via SHAKE
│   ├── format.ts        ← M' = (0x00 ‖ ctxLen ‖ ctx ‖ M) for pure ML-DSA, OID-prefixed for HashML-DSA
│   ├── hashvariant.ts   ← twelve §5.4.1 pre-hash dispatch (SHA2, SHA3, SHAKE families)
│   ├── index.ts
│   ├── keygen.ts        ← ML-DSA.KeyGen + KeyGen_internal (FIPS 204 §6.1)
│   ├── params.ts        ← MLDSA44, MLDSA65, MLDSA87 parameter sets
│   ├── sha3-helpers.ts  ← sponge absorb/squeeze orchestration shared with verify
│   ├── sign.ts          ← Sign / Sign_internal with hedged + deterministic + derand paths
│   ├── types.ts
│   ├── validate.ts      ← context length, signing key bound, rnd, message validation
│   └── verify.ts        ← Verify / Verify_internal (constant-time c̃ compare)
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
├── shared/
│   └── pkcs7.ts     ← canonical PKCS#7 padding helper (used by Serpent CBC + consumer code)
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

**Test vectors** (`vectors/`) is the immutable known-answer-test corpus. Files are read-only reference data. Some come from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP); others are self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates KAT file integrity against `SHA256SUMS` and re-derives every Tier 2 byte against the [`scripts/verify-vectors/`](./vector_audit.md) Rust crate on every PR.

See [test-suite.md](./test-suite.md) for full testing methodology, vector corpus inventory with provenance, and gate discipline. See [vector_audit.md](./vector_audit.md) for the tier classification and verifier coverage.

```
test/
├── e2e/      ← Playwright suites against built WASM in V8, SpiderMonkey, JSC
├── unit/
│   ├── aes/
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
│   ├── mldsa/
│   ├── ratchet/
│   ├── serpent/
│   ├── sha2/
│   ├── sha3/
│   ├── stream/
│   └── utils.test.ts
└── vectors/  ← KAT corpus; integrity verified against SHA256SUMS + Rust verifier
```

### Project files

The repository root holds project documentation, package metadata, and tool configuration. Build artifacts that only exist after `bun bake` are listed at the end.

**Documentation.** `README.md` is the entry point. `SECURITY.md` covers the vulnerability disclosure policy. `AGENTS.md` is the agent contract that governs how AI agents work in the repo. `CHANGELOG` tracks release history and `LICENSE` is MIT. The `docs/` directory holds the full API reference, audits, benchmarks, and architecture notes (this file lives there).

**Package metadata.** `package.json` declares the npm manifest, subpath exports, and scripts. `package-lock.json` and `bun.lock` are the lockfiles for npm and bun respectively; both ship checked in so either tool can install reproducibly.

**Tool configs.** `asconfig.json` configures AssemblyScript compilation. `eslint.config.ts` is the active linter, run via `bun fix`. `playwright.config.ts` and `vitest.config.ts` configure the e2e and unit test runners. `tsconfig.json` is the base TypeScript config; `tsconfig.test.json` and `tsconfig.e2e.json` extend it for the test targets. `tslint.json` is a TSLint config (older format).

**Build artifacts** (gitignored; only exist after `bun bake`). `build/` holds the raw `.wasm` outputs from AssemblyScript compilation. `dist/` is the published npm package contents (compiled JS, declarations, copied WASM, embedded blobs, doc subset).

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

## Eight Independent WASM Modules

Each primitive family compiles to its own `.wasm` binary with fully independent linear memory and buffer layouts. No shared state, no cross-module interference. Seven of the eight modules load through `init()`. The eighth, `ct`, sits outside the public `Module` union and the `init()` gate; it occupies a single 64 KB memory page and lazy-loads on the first call to `constantTimeEqual`. The ct module backs the public `constantTimeEqual` and `CT_MAX_BYTES` exports from the root barrel; neither requires an `init()` call.

| Module     | Binary          | Primitives                                                                                                                                                                                                                                                                                  |
| ---------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serpent`  | `serpent.wasm`  | Serpent-256 block cipher: ECB, CTR mode, CBC mode                                                                                                                                                                                                                                           |
| `chacha20` | `chacha20.wasm` | ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD                                                                                                                                                                                                                         |
| `aes`      | `aes.wasm`      | AES-128/192/256 block cipher (FIPS 197), CBC, CTR, GCM, GCM-SIV (RFC 8452)                                                                                                                                                                                                                  |
| `sha2`     | `sha2.wasm`     | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512                                                                                                                                                                                         |
| `sha3`     | `sha3.wasm`     | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256                                                                                                                                                                                                                                  |
| `kyber`    | `kyber.wasm`    | ML-KEM polynomial arithmetic: SIMD NTT/invNTT (v128 butterflies with scalar tail), basemul, Montgomery/Barrett, CBD, compress, CT verify/cmov                                                                                                                                               |
| `mldsa`    | `mldsa.wasm`    | ML-DSA polynomial arithmetic: SIMD NTT/invNTT for q=8380417 (v128 i32 butterflies), Montgomery/Barrett over q, rejection sampling (RejNTTPoly, RejBoundedPoly), Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint, HintBitPack/Unpack with the §D.3 SUF-CMA checks, SampleInBall |
| `ct`       | `ct.wasm`       | SIMD constant-time byte comparison. Backs `constantTimeEqual` and `CT_MAX_BYTES`, lazy-loaded outside `init()`. Single 64 KB page.                                                                                                                                                          |

**Size.** Consumers who only use Serpent don't load the SHA-3 binary.

**Isolation.** Key material in `serpent.wasm` memory cannot bleed into `sha3.wasm` memory even in theory.

Each module's buffer layout starts at offset 0 and is defined in its own `buffers.ts`. Buffer layouts are fully independent across modules.

### Module contents

**`serpent.wasm`** implements Serpent-256, a 128-bit block cipher. It handles key scheduling, block encryption and decryption, and both CTR and CBC streaming modes with SIMD variants for inter-block parallelism. See: [Serpent-256 WASM Module Reference](./asm_serpent.md)

[The TypeScript module](./serpent.md) wraps this with `SerpentCipher`, a CipherSuite that combines Serpent-CBC with HMAC-SHA256 and HKDF key derivation for the seal layer. Primitive operations (HMAC, CBC, PKCS7 padding) live in `serpent/shared-ops.ts` and are reused by both the main thread and pool workers, guaranteeing byte-identical output and consistent Vaudenay 2002 padding normalization. Requires `serpent` and `sha2` to be initialized.

**`chacha20.wasm`** implements the full ChaCha20-Poly1305 AEAD family per RFC 8439 and draft-irtf-cfrg-xchacha. It includes ChaCha20 stream cipher, Poly1305 one-time MAC, the AEAD construction, HChaCha20 for nonce extension, and SIMD 4-wide inter-block parallelism. See: [ChaCha20/Poly1305 WASM Reference](./asm_chacha.md)

[The TypeScript module](./chacha20.md) exports `XChaCha20Cipher`, a CipherSuite implementation for the seal layer using XChaCha20-Poly1305 with HKDF key derivation. Pool workers load internally via `SealStreamPool` at runtime and don't appear in the package exports map.

**`aes.wasm`** implements AES-128/192/256 per FIPS 197, plus CBC, CTR, GCM (NIST SP 800-38D), and GCM-SIV (RFC 8452) modes. The block cipher is bitsliced over v128 (8 blocks parallel, Käsper-Schwabe 2009 layout) with the Canright tower-field S-box (CHES 2005) for both forward and inverse paths. Decrypt uses the FIPS 197 §5.3.5 EqInvCipher: round keys 1..Nr-1 have InvMixColumns applied at key-schedule time, so the decrypt round loop reuses the encrypt structure. GHASH (and POLYVAL via the RFC 8452 §3 reflection) uses a 4-bit windowed multiplication table; this is the documented constant-time exception, mitigated by per-message authentication keys in AES-GCM-SIV. See: [AES WASM Reference](./asm_aes.md)

[The TypeScript module](./aes.md) exports `AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`, and `AESGenerator` (the AES-256 ECB counter-mode PRF for Fortuna's pluggable `Generator` slot, restoring the original Practical Cryptography §9.4 spec). The cipher-suite layer adds `AESGCMSIVCipher`, the CipherSuite for the seal layer using AES-256-GCM-SIV with HKDF-SHA-256 key derivation and a 32-byte explicit commitment. Requires `aes` and `sha2` to be initialized.

**`sha2.wasm`** implements the full SHA-2 family per FIPS 180-4: SHA-256, SHA-384, SHA-512 (the three original variants), plus SHA-224 (SHA-256 with different IVs and 28-byte truncation, §6.3), SHA-512/224, and SHA-512/256 (SHA-512 truncation variants per §6.7, required by HashML-DSA FIPS 204 §5.4.1). SHA-384, SHA-512/224, and SHA-512/256 all reuse the SHA-512 buffer and compression logic with distinct IVs. It also provides HMAC per RFC 2104 for SHA-256, SHA-384, and SHA-512. HKDF-SHA256 and HKDF-SHA512 (RFC 5869) are pure TypeScript compositions over HMAC with no new WASM logic. See: [SHA-2 WASM Reference](./asm_sha2.md)

**`sha3.wasm`** implements the Keccak-f[1600] permutation per FIPS 202. All SHA3 variants (SHA3-224, SHA3-256, SHA3-384, SHA3-512) and XOF variants (SHAKE128, SHAKE256) share a single permutation, differing only in rate, domain separation byte, and output length. SHAKE supports unbounded multi-squeeze output. See: [SHA-3 WASM Reference](./asm_sha3.md)

**`kyber.wasm`** implements ML-KEM polynomial arithmetic per FIPS 203. It includes Montgomery and Barrett reduction, 7-layer NTT and inverse NTT with SIMD butterflies, basemul in Z_q[X]/(X²-ζ), centered binomial distribution sampling (η=2 and η=3), compression and decompression across all five bit-width paths, rejection sampling for matrix generation, and constant-time byte comparison and conditional move. Requires WebAssembly SIMD (`v128` instructions). Uses 3 memory pages (192 KB) with 10 polynomial slots, 8 polynomial vector slots, and dedicated buffers for keys and ciphertexts. See: [Kyber WASM Reference](./asm_kyber.md)

[The TypeScript module](./kyber.md) exports `MlKem512`, `MlKem768`, and `MlKem1024`, KEM classes implementing the Fujisaki-Okamoto transform. All three require both `kyber` and `sha3` to be initialized; the sha3 module provides the Keccak sponge for matrix generation (SHAKE128), noise sampling (SHAKE256), and finalization (SHA3-256 for H, SHA3-512 for G).

**`mldsa.wasm`** implements ML-DSA polynomial arithmetic per FIPS 204. It includes Montgomery and Barrett reduction over q = 8380417, an 8-layer SIMD NTT and inverse NTT with v128 i32 butterflies, basemul in T_q, rejection sampling for the public matrix Â (`rej_ntt_poly`) and the secret noise polynomials s₁/s₂ (`rej_bounded_poly`), Power2Round / Decompose / HighBits / LowBits with the parameter-set γ₂, MakeHint / UseHint, HintBitPack and HintBitUnpack with the three SUF-CMA-critical malformed-input checks from FIPS 204 §D.3 (Algorithm 21 lines 4, 9, 17), bit-pack/unpack at every required width, and SampleInBall in resumable form. Requires WebAssembly SIMD (`v128` instructions). Uses 4 memory pages (256 KB) with a matrix slot, eight polynomial vector slots, eight polynomial slots, and dedicated buffers for keys, signatures, and the SHAKE PRF stream. See: [ML-DSA WASM Reference](./asm_mldsa.md)

[The TypeScript module](./mldsa.md) exports `MlDsa44`, `MlDsa65`, and `MlDsa87`, signature classes covering NIST security categories 2, 3, and 5. All three require both `mldsa` and `sha3` to be initialized; HashML-DSA with a SHA-2 family pre-hash additionally requires `sha2`. The sha3 module provides SHAKE128 (matrix expansion via ExpandA), SHAKE256 (noise expansion via ExpandS, masking expansion via ExpandMask, message representative μ, ρ'' derivation, and SampleInBall), and the SHA3-fixed digests for HashML-DSA pre-hash. The sha2 module covers SHA2-{224, 256, 384, 512, 512/224, 512/256} when HashML-DSA selects a SHA-2 pre-hash.

**`ct.wasm`** implements constant-time byte array equality with a single SIMD-only primitive. The module exports `compare(aOff, bOff, len)`, which reads both arrays directly from caller-specified offsets in linear memory and returns 1 if all bytes match, 0 otherwise. Comparison is zero-copy: no internal staging buffers, no buffer slots, no `wipeBuffers` export. The implementation is structurally branch-free. A `v128.xor`/`v128.or` accumulator processes 16-byte blocks, a scalar tail handles any remainder, and the final zero-test is an arithmetic shift, not a conditional. Requires WebAssembly SIMD (`v128` instructions); if the runtime lacks SIMD or compilation fails, the first call throws a branded error. See: [Constant-Time WASM Reference](asm_ct.md)

[The TypeScript module](./utils.md#constanttimeequal) exports `constantTimeEqual` and `CT_MAX_BYTES` from the root barrel. The wrapper instantiates the WASM synchronously on first call and caches it for subsequent calls. It writes both arrays into linear memory, calls `compare`, and zeroes both regions in a `finally` block before returning. `CT_MAX_BYTES` is 32 KB per side; the 64 KB page holds two equal-length inputs.

---

## `init()` API

WASM instantiation is async. [`init()`](./init.md) is the initialization gate, call it once before using any cryptographic class. The cost is explicit and the developer controls when it is paid.

### Signature

```typescript
type Module = 'serpent' | 'chacha20' | 'aes' | 'sha2' | 'sha3' | 'keccak' | 'kyber' | 'mldsa'

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

The loading strategy is inferred from the source type, so there is no need for a mode string. Each module also exports its own init function, such as `serpentInit(source)`, `chacha20Init(source)`, `aesInit(source)`, `sha2Init(source)`, `sha3Init(source)`, `keccakInit(source)`, `kyberInit(source)`, and `mldsaInit(source)`, enabling tree-shakeable imports.

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
| `aes`                           | `AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`                                                        |
| `aes` + `sha2`                  | `AESGCMSIVCipher` (seal-layer CipherSuite, AES-256-GCM-SIV with HKDF-SHA-256)                           |
| `sha2`                          | `SHA256`, `SHA384`, `SHA512`, `SHA224`, `SHA512_224`, `SHA512_256`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| `sha3`                          | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, `CSHAKE128`, `CSHAKE256`, `KMAC128`, `KMAC256`, `KMACXOF128`, `KMACXOF256` |
| `kyber` + `sha3`                | `MlKem512`, `MlKem768`, `MlKem1024`                                                                     |
| `kyber` + `sha3` + inner cipher | `KyberSuite` (hybrid KEM+AEAD factory)                                                                  |
| `mldsa` + `sha3`                | `MlDsa44`, `MlDsa65`, `MlDsa87` (pure ML-DSA + HashML-DSA with SHA-3 / SHAKE pre-hash)                  |
| `mldsa` + `sha3` + `sha2`       | `MlDsa44`, `MlDsa65`, `MlDsa87` (HashML-DSA with a SHA-2 family pre-hash)                               |
| `sha2`                          | `ratchetInit`, `KDFChain`, `SkippedKeyStore`                                                            |
| `kyber` + `sha3` + `sha2`       | `kemRatchetEncap`, `kemRatchetDecap`, `RatchetKeypair`                                                  |
| `stream`                        | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`                                                    |
| `serpent` + `sha2`              | `Fortuna` with `SerpentGenerator` + `SHA256Hash`                                                        |
| `serpent` + `sha3`              | `Fortuna` with `SerpentGenerator` + `SHA3_256Hash`                                                      |
| `chacha20` + `sha2`             | `Fortuna` with `ChaCha20Generator` + `SHA256Hash`                                                       |
| `chacha20` + `sha3`             | `Fortuna` with `ChaCha20Generator` + `SHA3_256Hash`                                                     |
| `aes` + `sha2`                  | `Fortuna` with `AESGenerator` + `SHA256Hash`                                                            |
| `aes` + `sha3`                  | `Fortuna` with `AESGenerator` + `SHA3_256Hash`                                                          |

>[!NOTE]
> Class Names match conventional cryptographic notation.

 - HMAC names use underscore separator (`HMAC_SHA256`) matching RFC convention.
 - SHA-3 names use underscore separator (`SHA3_256`) for readability.
 -  Ratchet exports are KDF primitives from Signal's Sparse Post-Quantum Ratchet spec; session state, message ordering, and header format remain application concerns.
 - **`Fortuna`** requires `await Fortuna.create({ generator, hash })` rather than `new Fortuna()`. Required modules depend on the generator and hash you pass. See [fortuna.md](./fortuna.md) for valid combinations.
 - `SealStream`, `OpenStream`, and `SealStreamPool` are cipher-agnostic; you select the cipher by passing `XChaCha20Cipher`, `SerpentCipher`, or `AESGCMSIVCipher` at construction.

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

The build is orchestrated by `scripts/build.ts`, invoked via `bun bake` (or the canonical alias `bun run build`). The dispatcher walks a typed dependency DAG defined in `scripts/lib/build-graph.ts`, so each target builds only its prerequisites. Run a single target with `bun bake <target>` (e.g. `bun bake asm`, `bun bake ts`); the default target is `all`.

For the developer-facing workflow around these scripts (the iteration loop, single-file test invocation, when to use each shorthand), see [development.md](./development.md). This section documents what the pipeline does; the development doc covers how to use it day to day.

**Build targets and order.**

1. `asm`: AssemblyScript compiler reads each `src/asm/*/index.ts` for the eight modules, emits `build/*.wasm`.
2. `embed`: `scripts/embed-wasm.ts` reads each `.wasm`, gzip compresses, base64 encodes, and writes to `src/ts/embedded/*.ts` and per-module `src/ts/*/embedded.ts`.
3. `embed-workers`: `scripts/embed-workers.ts` bundles each pool worker into a self-contained IIFE via esbuild and writes the source to `src/ts/embedded/<cipher>-pool-worker.ts` as a string export.
4. `ts`: TypeScript compiler emits `dist/`.
5. `wasm-copy`: `build/*.wasm` is copied into `dist/` for URL-based consumers.
6. `claude-md`: `docs/CLAUDE_consumer.md` is copied to the repository root as `CLAUDE.md` for in-package agent guidance.
7. `docs`: `scripts/copy-docs.ts` ships the consumer doc subset into `dist/`.

**Runtime path (after build).**

8. Subpath consumer: `serpentInit(serpentWasm)` → `initModule()` → `loadWasm(source)` → decode gzip+base64 → `WebAssembly.instantiate` → cache in `init.ts`.
9. Root consumer: `init({ serpent: serpentWasm, sha2: sha2Wasm })` → dispatches to each module's init function via `Promise.all` → same path as step 8 per module.

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

**AES (`src/asm/aes/`)**

```
buffers.ts
  <- aes.ts                (key, block PT/CT, 8x parallel blocks, round keys, bitsliced state, scratch, NR, GCM/SIV state)
  <- sbox.ts               (BITSLICED_STATE_OFFSET, CANRIGHT_SCRATCH_OFFSET)
  <- cbc.ts                (key, IV, chunk offsets)
  <- cbc_simd.ts           (SIMD CBC decrypt block offsets)
  <- ctr.ts                (nonce, counter, block, chunk offsets)
  <- ctr_simd.ts           (SIMD CTR 8-wide inter-block)
  <- gcm.ts                (H, J0, GHASH accumulator, AAD, tag, lengths, scratch)
  <- ghash.ts              (GHASH accumulator + scratch)
  <- gf128.ts              (4-bit windowed multiply table)
  <- polyval.ts            (POLYVAL hash subkey + accumulator)
  <- aes-gcm-siv.ts        (POLYVAL auth/enc keys, initial counter)
  <- wipe.ts               (all buffer offsets, zeroes everything)

aes.ts
  <- (block primitives consumed by cbc, ctr, gcm, aes-gcm-siv)

sbox.ts
  <- aes.ts                (sboxBitsliced, invSboxBitsliced)

ghash.ts
  <- gcm.ts                (ghashStart, ghashAbsorb*)

gf128.ts
  <- ghash.ts              (gf128InitTable, gf128MulH)
  <- polyval.ts            (mulXGhash for POLYVAL byte-reversal bridge)

polyval.ts
  <- aes-gcm-siv.ts        (polyvalStart, polyvalAbsorb, polyvalFinalize)

index.ts
  re-exports: buffers + aes + cbc + cbc_simd + ctr + ctr_simd + gcm + ghash + polyval + aes-gcm-siv + wipe
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
  <- ntt_simd.ts           (fqmul, barrett_reduce, scalar tail)
  <- poly.ts               (montgomery_reduce, barrett_reduce, fqmul)

ntt.ts
  <- ntt_simd.ts           (getZetasOffset, zetas table pointer)
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

**ML-DSA (`src/asm/mldsa/`)**

```
params.ts
  <- reduce.ts             (Q=8380417, QINV, MONT, BARRETT constants)
  <- poly.ts               (γ₁/γ₂/η/β/τ/ω/λ per parameter set)
  <- sampling.ts           (matrix Â and noise sampling parameters)
  <- rounding.ts           (γ₂ for Decompose/HighBits/LowBits/MakeHint/UseHint)

buffers.ts
  <- poly.ts, polyvec.ts, sampling.ts, rounding.ts, encoding.ts (slot offsets)

reduce.ts
  <- ntt.ts, ntt_simd.ts, poly.ts (montgomery_reduce, barrett_reduce, fqmul over q)

ntt.ts
  <- ntt_simd.ts, poly.ts (8-layer NTT over T_q, scalar entry points)

ntt_simd.ts
  <- poly_simd.ts (v128 i32 butterflies)

poly.ts, poly_simd.ts
  <- polyvec.ts (k/ℓ-wide wrappers)

rounding.ts
  <- (Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint, HintBitPack/Unpack with §D.3 checks)

sampling.ts
  <- (rej_ntt_poly, rej_bounded_poly, SampleInBall, all consume SHAKE PRF output written into XOF_PRF_OFFSET by host)

encoding.ts
  <- (bit-pack/unpack at every required width: encodeS₁/encodeS₂, encodeT₀/encodeT₁, encodeZ, encodeSig)

index.ts
  re-exports: params + buffers + reduce + ntt + ntt_simd + poly + poly_simd + polyvec + rounding + sampling + encoding
```

---

### TS layer: internal import graph

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/import-graph.svg" alt="TS Layer: internal import graph diagram">

Each module's init function (`serpentInit`, `chacha20Init`, `aesInit`, `sha2Init`, `sha3Init`, `kyberInit`, `mldsaInit`) calls `initModule()` from `init.ts`, passing a `WasmSource`. `initModule()` delegates to `loadWasm(source)` in `loader.ts`. The loader infers the loading strategy from the source type, with no mode string and no knowledge of module names or embedded file paths.

Pool workers (`serpent/pool-worker.ts`, `chacha20/pool-worker.ts`, `aes/pool-worker.ts`) instantiate their own WASM modules from pre-compiled `WebAssembly.Module` objects passed via `postMessage`. They do not use `initModule()` or the main-thread cache. Workers are spawned from blob URLs constructed in `cipher-suite.ts` over an IIFE source string built at lib build time (`src/ts/embedded/<cipher>-pool-worker.ts`). The `pool-worker.ts` file itself is the source the bundler reads, not the runtime spawn entry.

---

### TS-to-WASM mapping

Each TS wrapper class maps to one WASM module and specific exported functions. Tier 2 composition classes are pure TypeScript; they call Tier 1 classes rather than WASM functions directly.

**serpent/index.ts → asm/serpent/ (Tier 1: direct WASM callers)**

| TS Class           | WASM functions called                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `Serpent`          | `loadKey`, `encryptBlock`, `decryptBlock`, `wipeBuffers` + buffer getters                                    |
| `SerpentCtr`       | `loadKey`, `resetCounter`, `setCounter`, `encryptChunk`, `encryptChunk_simd`, `wipeBuffers` + buffer getters |
| `SerpentCbc`       | `loadKey`, `cbcEncryptChunk`, `cbcDecryptChunk`, `cbcDecryptChunk_simd`, `wipeBuffers` + buffer getters      |
| `SerpentGenerator` | `loadKey`, `encryptBlock`, `wipeBuffers` + buffer getters                                                    |

**chacha20/index.ts → asm/chacha20/ (Tier 1: direct WASM callers)**

| TS Class            | WASM functions called                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ChaCha20`          | `chachaLoadKey`, `chachaSetCounter`, `chachaEncryptChunk`, `chachaEncryptChunk_simd`, `wipeBuffers` + buffer getters                                                |
| `Poly1305`          | `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters                                                                                               |
| `ChaCha20Poly1305`  | `chachaLoadKey`, `chachaSetCounter`, `chachaGenPolyKey`, `chachaEncryptChunk`, `polyInit`, `polyUpdate`, `polyFinal`, `wipeBuffers` + buffer getters (via `ops.ts`) |
| `XChaCha20Poly1305` | All of `ChaCha20Poly1305` + `hchacha20` + xchacha buffer getters (via `ops.ts`)                                                                                     |
| `ChaCha20Generator` | `chachaLoadKey`, `chachaSetCounter`, `chachaEncryptChunk_simd`, `wipeBuffers` + buffer getters                                                                      |

**aes/index.ts → asm/aes/ (Tier 1: direct WASM callers)**

| TS Class       | WASM functions called                                                                                                                                    |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AES`          | `loadKey`, `encryptBlock`, `decryptBlock`, `encryptBlock_8x`, `decryptBlock_8x`, `wipeBuffers` + buffer getters                                          |
| `AESCbc`       | `loadKey`, `cbcEncryptChunk`, `cbcDecryptChunk`, `cbcDecryptChunk_simd`, `wipeBuffers` + buffer getters                                                  |
| `AESCtr`       | `loadKey`, `resetCounter`, `setCounter`, `ctrEncryptChunk`, `ctrEncryptChunk_simd`, `wipeBuffers` + buffer getters                                       |
| `AESGCM`       | `loadKey`, `gcmStart`, `gcmAbsorbAad*`, `gcmEncryptChunk`/`gcmDecryptChunk`, `gcmFinalize`, `wipeBuffers` + buffer getters (via `ops.ts`)                |
| `AESGCMSIV`    | `loadKey`, `sivDeriveKeys`, `polyvalStart`, `polyvalAbsorb`, `polyvalFinalize`, `sivEncrypt`/`sivDecrypt`, `wipeBuffers` + buffer getters (via `ops.ts`) |
| `AESGenerator` | `loadKey`, `encryptBlock`, `wipeBuffers` + buffer getters                                                                                                |

**sha2/index.ts → asm/sha2/ (Tier 1: direct WASM callers)**

| TS Class      | WASM functions called                                                                                                       |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `SHA256`      | `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters                                                 |
| `SHA512`      | `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters                                                 |
| `SHA384`      | `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters                                                 |
| `HMAC_SHA256` | `hmac256Init`, `hmac256Update`, `hmac256Final`, `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA512` | `hmac512Init`, `hmac512Update`, `hmac512Final`, `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA384` | `hmac384Init`, `hmac384Update`, `hmac384Final`, `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters |
| `SHA256Hash`  | `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters                                                 |

**sha3/index.ts → asm/sha3/ (Tier 1: direct WASM callers)**

| TS Class       | WASM functions called                                                                           |
| -------------- | ----------------------------------------------------------------------------------------------- |
| `SHA3_224`     | `sha3_224Init`, `keccakAbsorb`, `sha3_224Final`, `wipeBuffers` + buffer getters                 |
| `SHA3_256`     | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters                 |
| `SHA3_384`     | `sha3_384Init`, `keccakAbsorb`, `sha3_384Final`, `wipeBuffers` + buffer getters                 |
| `SHA3_512`     | `sha3_512Init`, `keccakAbsorb`, `sha3_512Final`, `wipeBuffers` + buffer getters                 |
| `SHAKE128`     | `shake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `SHAKE256`     | `shake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `SHA3_256Hash` | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters                 |
| `CSHAKE128`    | `cshake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `CSHAKE256`    | `cshake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMAC128`      | `cshake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMAC256`      | `cshake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMACXOF128`   | `cshake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMACXOF256`   | `cshake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |

**kyber/index.ts + kyber/kem.ts + kyber/indcpa.ts → asm/kyber/ (Tier 1)**

| TS Class                            | WASM functions called                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MlKem512`, `MlKem768`, `MlKem1024` | `polyvec_ntt`, `polyvec_invntt`, `polyvec_basemul_acc_montgomery`, `polyvec_add`, `polyvec_reduce`, `polyvec_tobytes`, `polyvec_frombytes`, `polyvec_compress`, `polyvec_decompress`, `poly_ntt`, `poly_invntt`, `poly_tomont`, `poly_add`, `poly_sub`, `poly_reduce`, `poly_basemul_montgomery`, `poly_frommsg`, `poly_tomsg`, `poly_compress`, `poly_decompress`, `poly_getnoise`, `rej_uniform`, `ct_verify`, `ct_cmov`, `wipeBuffers` + buffer getters |

All MlKem classes also call sha3 WASM via `indcpa.ts`: `sha3_256Init`, `sha3_512Init`, `shake128Init`, `shake256Init`, `keccakAbsorb`, `sha3_256Final`, `sha3_512Final`, `shakeFinal`, `shakePad`, `shakeSqueezeBlock`.

**mldsa/index.ts + mldsa/{keygen,sign,verify}.ts → asm/mldsa/ (Tier 1)**

| TS Class                        | WASM functions called                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MlDsa44`, `MlDsa65`, `MlDsa87` | `rej_ntt_poly`, `rej_bounded_poly`, `sample_in_ball`, `power2round_polyvec`, `decompose_polyvec`, `high_bits_polyvec`, `low_bits_polyvec`, `make_hint_polyvec`, `use_hint_polyvec`, `hint_bit_pack`, `hint_bit_unpack` (returns -1 on §D.3 malformed input), `polyvec_ntt`/`polyvec_invntt`, `polyvec_pointwise_montgomery`, `polyvec_add`/`polyvec_sub`/`polyvec_reduce`, `poly_ntt`/`poly_invntt`/`poly_pointwise_montgomery`, `pack_pk`/`unpack_pk`, `pack_sk`/`unpack_sk`, `pack_sig`/`unpack_sig`, `wipeBuffers` + buffer getters |

All MlDsa classes also call sha3 WASM via `expand.ts` and `sha3-helpers.ts`: SHAKE128 for `ExpandA` (matrix Â), SHAKE256 for `ExpandS`, `ExpandMask`, message representative μ, ρ'' derivation, and `SampleInBall`. HashML-DSA additionally calls sha2 (or sha3) functions for the §5.4.1 pre-hash before formatting M'.

**Tier 2: pure TS composition**

| TS Class / Object | Composes                                                                                                                                |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `SerpentCipher`   | `SerpentCbc` + `HMAC_SHA256` + `HKDF_SHA256`                                                                                            |
| `XChaCha20Cipher` | `ChaCha20Poly1305` (via `ops.ts`) + `HKDF_SHA256`                                                                                       |
| `AESGCMSIVCipher` | `AESGCMSIV` (via `ops.ts`) + `HKDF_SHA256`                                                                                              |
| `Seal`            | `SealStream` + `OpenStream` (degenerate single-chunk case)                                                                              |
| `SealStream`      | `CipherSuite` (generic, caller provides cipher)                                                                                        |
| `OpenStream`      | `CipherSuite` (generic, caller provides cipher)                                                                                        |
| `SealStreamPool`  | `CipherSuite` + `compileWasm()` + Web Workers                                                                                           |
| `HKDF_SHA256`     | `HMAC_SHA256` (extract + expand per RFC 5869)                                                                                           |
| `HKDF_SHA512`     | `HMAC_SHA512` (extract + expand per RFC 5869)                                                                                           |
| `Fortuna`         | `Generator` + `HashFn` (any compatible pair: `SerpentGenerator` / `ChaCha20Generator` / `AESGenerator` × `SHA256Hash` / `SHA3_256Hash`) |

---

### Cross-module dependencies

| Relationship                                                      | Notes                                                                                                                                                                                                       |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SerpentCipher` → `serpent` + `sha2`                              | Tier 2 composition: Serpent-CBC + HMAC-SHA256 + HKDF-SHA256.                                                                                                                                                |
| `XChaCha20Cipher` → `chacha20` + `sha2`                           | HKDF-SHA256 for key derivation + HChaCha20 + ChaCha20-Poly1305 for per-chunk AEAD.                                                                                                                          |
| `AESGCMSIVCipher` → `aes` + `sha2`                                | HKDF-SHA256 for key derivation + AES-256-GCM-SIV per chunk + 32-byte explicit commitment.                                                                                                                   |
| `KyberSuite` → `kyber` + `sha3` + inner cipher                    | KEM encaps/decaps + HKDF with kemCt binding + inner CipherSuite.                                                                                                                                            |
| `SealStream`, `OpenStream` → depends on cipher                    | Cipher-agnostic. Module requirements are determined by the `CipherSuite` passed at construction.                                                                                                            |
| `SealStreamPool` → depends on cipher                              | Same module requirements as the cipher, plus `WasmSource` in pool opts for worker compilation.                                                                                                              |
| `Fortuna` → cipher module + hash module                           | Uses `Fortuna.create({ generator, hash })` static factory instead of `new`. Required modules depend on which generator and hash you pass. See [fortuna.md](./fortuna.md).                                   |
| `MlKem512`, `MlKem768`, `MlKem1024` → `kyber` + `sha3`            | Kyber module handles polynomial arithmetic; sha3 provides SHAKE128/256, SHA3-256/512 for G/H/J/matrix gen.                                                                                                  |
| `MlDsa44`, `MlDsa65`, `MlDsa87` → `mldsa` + `sha3`                | ML-DSA module handles polynomial arithmetic, rounding, and packing; sha3 provides SHAKE128 (ExpandA), SHAKE256 (ExpandS, ExpandMask, μ, ρ'', SampleInBall), and SHA3-fixed digests for HashML-DSA pre-hash. |
| `MlDsa*` (HashML-DSA, SHA-2 pre-hash) → `mldsa` + `sha3` + `sha2` | `sha2` module covers the SHA2-{224, 256, 384, 512, 512/224, 512/256} pre-hash variants from §5.4.1.                                                                                                         |
| `HKDF_SHA256`, `HKDF_SHA512` → `sha2`                             | Pure TS composition, extract and expand steps per RFC 5869.                                                                                                                                                |
| All other classes                                                 | Each depends on exactly **one** WASM module.                                                                                                                                                                |

---

### Public API barrel (`src/ts/index.ts`)

The root barrel defines and exports the dispatching `init()` function. It is the only file that imports all module-scoped init functions.

| Source              | Exports                                                                                                                                                                                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| _(barrel itself)_   | `init` (dispatching function, calls per-module init functions via `Promise.all`)                                                                                                                                                                          |
| `init.ts`           | `Module`, `WasmSource`, `isInitialized`                                                                                                                                                                                                                    |
| `errors.ts`         | `AuthenticationError`                                                                                                                                                                                                                                      |
| `serpent/index.ts`  | `Serpent`, `SerpentCtr`, `SerpentCbc`, `SerpentCipher`, `SerpentGenerator`                                                                                                                                                                                 |
| `chacha20/index.ts` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher`, `ChaCha20Generator`                                                                                                                                                    |
| `aes/index.ts`      | `AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`, `AESGCMSIVCipher`, `AESGenerator`                                                                                                                                                                        |
| `sha2/index.ts`     | `SHA256`, `SHA224`, `SHA512`, `SHA384`, `SHA512_224`, `SHA512_256`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`, `HKDF_SHA256`, `HKDF_SHA512`, `SHA256Hash`                                                                                                |
| `sha3/index.ts`     | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, `SHA3_256Hash`                                                                                                                                                                     |
| `keccak/index.ts`   | `keccakInit` + re-exports all sha3 classes (alias subpath)                                                                                                                                                                                                 |
| `kyber/index.ts`    | `kyberInit`, `KyberSuite`, `MlKem512`, `MlKem768`, `MlKem1024`, `MlKemBase`, `KyberKeyPair`, `KyberEncapsulation`, `KyberParams`, `MLKEM512`, `MLKEM768`, `MLKEM1024`                                                                                      |
| `mldsa/index.ts`    | `mldsaInit`, `MlDsa44`, `MlDsa65`, `MlDsa87`, `MlDsaBase`, `MLDSA44`, `MLDSA65`, `MLDSA87`, `MlDsaKeyPair`, `MlDsaParams`, `PreHashAlgorithm`                                                                                                              |
| `stream/index.ts`   | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, `CipherSuite`, `DerivedKeys`, `SealStreamOpts`, `PoolOpts`, `FLAG_FRAMED`, `TAG_DATA`, `TAG_FINAL`, `HEADER_SIZE`, `CHUNK_MIN`, `CHUNK_MAX`                                                          |
| `ratchet/index.ts`  | `KDFChain`, `ratchetInit`, `ratchetReady`, `kemRatchetEncap`, `kemRatchetDecap`, `SkippedKeyStore`, `RatchetKeypair`, `RatchetInitResult`, `KemEncapResult`, `KemDecapResult`, `MlKemLike`, `RatchetMessageHeader`, `ResolveHandle`, `SkippedKeyStoreOpts` |
| `fortuna.ts`        | `Fortuna`                                                                                                                                                                                                                                                  |
| `types.ts`          | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD`, `Generator`, `HashFn`                                                                                                                                                                          |
| `utils.ts`          | `hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64`, `constantTimeEqual`, `CT_MAX_BYTES`, `wipe`, `xor`, `concat`, `randomBytes`, `hasSIMD`                                                                         |

Each subpath export also exports its own module-specific init function for tree-shakeable loading: `serpentInit(source)`, `chacha20Init(source)`, `aesInit(source)`, `sha2Init(source)`, `sha3Init(source)`, `keccakInit(source)`, `kyberInit(source)`, `mldsaInit(source)`.

`isInitialized(mod)` is also re-exported from every submodule subpath (in addition to the root barrel and `init.ts`), so tree-shake-friendly imports can pick up the readiness probe alongside the cipher classes:

```typescript
import { serpentInit, isInitialized } from 'leviathan-crypto/serpent'
```

---

## npm Package

**Subpath exports:**

```json
{
  "exports": {
    ".":                      "./dist/index.js",
    "./stream":               "./dist/stream/index.js",
    "./serpent":              "./dist/serpent/index.js",
    "./serpent/embedded":     "./dist/serpent/embedded.js",
    "./chacha20":             "./dist/chacha20/index.js",
    "./chacha20/embedded":    "./dist/chacha20/embedded.js",
    "./aes":                  "./dist/aes/index.js",
    "./aes/embedded":         "./dist/aes/embedded.js",
    "./sha2":                 "./dist/sha2/index.js",
    "./sha2/embedded":        "./dist/sha2/embedded.js",
    "./sha3":                 "./dist/sha3/index.js",
    "./sha3/embedded":        "./dist/sha3/embedded.js",
    "./keccak":               "./dist/keccak/index.js",
    "./keccak/embedded":      "./dist/keccak/embedded.js",
    "./kyber":                "./dist/kyber/index.js",
    "./kyber/embedded":       "./dist/kyber/embedded.js",
    "./mldsa":                "./dist/mldsa/index.js",
    "./mldsa/embedded":       "./dist/mldsa/embedded.js",
    "./ratchet":              "./dist/ratchet/index.js"
  }
}
```

> [!NOTE]
> Pool worker source files (`dist/serpent/pool-worker.js`, `dist/chacha20/pool-worker.js`, `dist/aes/pool-worker.js`) ship in the package but are not in the `exports` map. They are the build inputs from which `scripts/embed-workers.ts` produces the IIFE source strings embedded in `dist/<cipher>/cipher-suite.js` at lib build time. Workers are spawned from those embedded strings via classic blob URLs. Consumers do not import the `pool-worker.js` files directly, and bundlers do not need to chunk them. Strict-CSP consumers (`worker-src 'self'`, no `blob:`) can supply their own URL-based factory by spread-overriding `createPoolWorker` on the cipher object; see [ciphersuite.md](./ciphersuite.md).

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

| Offset | Size  | Name                                                                                        |
| ------ | ----- | ------------------------------------------------------------------------------------------- |
| 0      | 32    | `KEY_BUFFER`, key input (padded to 32 bytes for all key sizes)                             |
| 32     | 16    | `BLOCK_PT_BUFFER`, single block plaintext                                                  |
| 48     | 16    | `BLOCK_CT_BUFFER`, single block ciphertext                                                 |
| 64     | 16    | `NONCE_BUFFER`, CTR mode nonce                                                             |
| 80     | 16    | `COUNTER_BUFFER`, 128-bit little-endian counter                                            |
| 96     | 528   | `SUBKEY_BUFFER`, key schedule output (33 rounds × 4 × 4 bytes)                             |
| 624    | 65552 | `CHUNK_PT_BUFFER`, streaming plaintext (CTR/CBC); +16 from 65536 to fit PKCS7 max overhead |
| 66176  | 65552 | `CHUNK_CT_BUFFER`, streaming ciphertext (CTR/CBC)                                          |
| 131728 | 20    | `WORK_BUFFER`, 5 × i32 scratch registers (key schedule + S-box/LT rounds)                  |
| 131748 | 16    | `CBC_IV_BUFFER`, CBC initialization vector / chaining value                                |
| 131856 | -     | END                                                                                         |

`wipeBuffers()` zeroes all 10 buffers (key, block pt/ct, nonce, counter, subkeys, work, chunk pt/ct, CBC IV).

### ChaCha20 module (3 pages, 192 KB)

Source: `src/asm/chacha20/buffers.ts`

| Offset | Size  | Name                                                                    |
| ------ | ----- | ----------------------------------------------------------------------- |
| 0      | 32    | `KEY_BUFFER`, ChaCha20 256-bit key                                     |
| 32     | 12    | `CHACHA_NONCE_BUFFER`, 96-bit nonce (3 × u32, LE)                      |
| 44     | 4     | `CHACHA_CTR_BUFFER`, u32 block counter                                 |
| 48     | 64    | `CHACHA_BLOCK_BUFFER`, 64-byte keystream block output                  |
| 112    | 64    | `CHACHA_STATE_BUFFER`, 16 × u32 initial state                          |
| 176    | 65536 | `CHUNK_PT_BUFFER`, streaming plaintext                                 |
| 65712  | 65536 | `CHUNK_CT_BUFFER`, streaming ciphertext                                |
| 131248 | 32    | `POLY_KEY_BUFFER`, one-time key r‖s                                    |
| 131280 | 64    | `POLY_MSG_BUFFER`, message staging (≤ 64 bytes per polyUpdate)         |
| 131344 | 16    | `POLY_BUF_BUFFER`, partial block accumulator                           |
| 131360 | 4     | `POLY_BUF_LEN_BUFFER`, u32 bytes in partial block                      |
| 131364 | 16    | `POLY_TAG_BUFFER`, 16-byte output MAC tag                              |
| 131380 | 40    | `POLY_H_BUFFER`, accumulator h: 5 × u64                                |
| 131420 | 40    | `POLY_R_BUFFER`, clamped r: 5 × u64                                    |
| 131460 | 32    | `POLY_RS_BUFFER`, precomputed 5×r[1..4]: 4 × u64                       |
| 131492 | 16    | `POLY_S_BUFFER`, s pad: 4 × u32                                        |
| 131508 | 24    | `XCHACHA_NONCE_BUFFER`, full 24-byte XChaCha20 nonce                   |
| 131532 | 32    | `XCHACHA_SUBKEY_BUFFER`, HChaCha20 output (key material)               |
| 131564 | 4     | _(padding for 16-byte SIMD alignment)_                                  |
| 131568 | 256   | `CHACHA_SIMD_WORK_BUFFER`, 4-wide inter-block keystream (4 × 64 bytes) |
| 131824 | -     | END                                                                     |

`wipeBuffers()` zeroes all 15 buffer regions (key, chacha nonce/ctr/block/state, chunk pt/ct, poly key/msg/buf/tag/h/r/rs/s, xchacha nonce/subkey, SIMD work).

### AES module (4 pages, 256 KB)

Source: `src/asm/aes/buffers.ts`

| Offset | Size  | Name                                                                                                                                               |
| ------ | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0      | 32    | `KEY_BUFFER`, AES key (sized for AES-256)                                                                                                         |
| 32     | 16    | `BLOCK_PT_BUFFER`, atomic 1-block plaintext input                                                                                                 |
| 48     | 16    | `BLOCK_CT_BUFFER`, atomic 1-block ciphertext output                                                                                               |
| 64     | 128   | `BLOCK_PT_8X_BUFFER`, 8 parallel plaintext blocks                                                                                                 |
| 192    | 128   | `BLOCK_CT_8X_BUFFER`, 8 parallel ciphertext blocks                                                                                                |
| 320    | 1920  | `ROUND_KEYS_BUFFER`, bitsliced forward (encrypt) round keys (15 rounds × 8 × 16 bytes; AES-128 uses 1408, AES-192 uses 1664, AES-256 uses 1920)   |
| 2240   | 128   | `BITSLICED_STATE_BUFFER`, 8 × v128 AES state in Käsper-Schwabe layout                                                                             |
| 2368   | 1024  | `CANRIGHT_SCRATCH_BUFFER`, ≈64 v128 scratch slots for the tower-field S-box                                                                       |
| 3392   | 256   | `KEY_SCHEDULE_SCRATCH_BUFFER`, byte-level round-key scratch during keyExpansion (240 bytes for AES-256, padded to 256 for v128 alignment)         |
| 3648   | 1920  | `INV_ROUND_KEYS_BUFFER`, EqInvCipher form decrypt round keys (rounds 1..Nr-1 are InvMixColumns(K[r]); rounds 0 and Nr are copies of forward keys) |
| 5568   | 65536 | `CHUNK_PT_BUFFER`, CTR/CBC stream input                                                                                                           |
| 71104  | 65536 | `CHUNK_CT_BUFFER`, CTR/CBC stream output                                                                                                          |
| 136640 | 1     | `NR_BUFFER`, u8 round count (10/12/14), written by keyExpansion, read by encrypt/decrypt                                                          |
| 136656 | 16    | `NONCE_BUFFER`, CTR initial counter value                                                                                                         |
| 136672 | 16    | `COUNTER_BUFFER`, CTR working counter (128-bit LE)                                                                                                |
| 136688 | 16    | `CBC_IV_BUFFER`, CBC chaining block (IV first chunk, last CT block thereafter)                                                                    |
| 136704 | 16    | `H_BUFFER`, GCM hash subkey H = AES_ENC(K, 0¹²⁸), derived once per loadKey                                                                        |
| 136720 | 16    | `J0_BUFFER`, GCM pre-counter block, set per seal/open call                                                                                        |
| 136736 | 16    | `GHASH_ACC_BUFFER`, GHASH running accumulator (also POLYVAL accumulator during AES-GCM-SIV; GHASH and POLYVAL are mutually exclusive at runtime)  |
| 136752 | 16    | `TAG_BUFFER`, computed-tag scratch on seal, comparison target on open                                                                             |
| 136768 | 16    | `J0E_BUFFER`, E(K, J0) pad (XORed with S to form the GCM tag)                                                                                     |
| 136784 | 16    | `GCM_LENS_BUFFER`, running GCM length state (AAD bit-length u64 BE in [0..7], PT/CT bit-length so far u64 BE in [8..15])                          |
| 136800 | 16    | `GCM_SCRATCH_BUFFER`, zero-padded partial-block scratch for GHASH absorption tail                                                                 |
| 136816 | 16    | `GCM_CB_BUFFER`, GCTR working counter (high 96 bits fixed from J0, low 32 bits 32-bit BE incrementing)                                            |
| 136832 | 256   | `GF128_TABLE_BUFFER`, 16 entries × 16 bytes, 4-bit windowed multiply table computed from H once per loadKey                                       |
| 137088 | 65536 | `AAD_BUFFER`, GCM additional authenticated data (single-shot caller writes AAD here before gcmStart)                                              |
| 202624 | 16    | `POLYVAL_AUTH_KEY_BUFFER`, AES-GCM-SIV per-message authentication key derived from KGK by sivDeriveKeys (RFC 8452 §4)                             |
| 202640 | 32    | `POLYVAL_ENC_KEY_BUFFER`, AES-GCM-SIV per-message encryption key (sized for AES-256; AES-128 uses bytes [0..16])                                  |
| 202672 | 16    | `SIV_IC_BUFFER`, SIV initial counter (tag with bit 7 of byte 15 set; first 4 bytes hold the 32-bit LE CTR counter)                                |
| 202688 | -     | END (< 262144 = 4 pages, 59456 bytes spare)                                                                                                        |

`wipeBuffers()` zeroes every mutable region above. Bitsliced round keys are 128 bytes/round (not 16) per Käsper-Schwabe §4.5: each round key is pre-transposed to bitsliced form so that AddRoundKey is 8 plain v128 XORs. The 16 round-key bytes duplicate across the 8 parallel blocks (since all 8 share one schedule), then transpose, yielding 8 × v128 = 128 bytes per bitsliced round key.

### SHA-2 module (3 pages, 192 KB)

Source: `src/asm/sha2/buffers.ts`

| Offset | Size | Name                                                               |
| ------ | ---- | ------------------------------------------------------------------ |
| 0      | 32   | `SHA256_H`, SHA-256 hash state H0..H7 (8 × u32)                   |
| 32     | 64   | `SHA256_BLOCK`, SHA-256 block accumulator                         |
| 96     | 256  | `SHA256_W`, SHA-256 message schedule W[0..63] (64 × u32)          |
| 352    | 32   | `SHA256_OUT`, SHA-256 digest output                               |
| 384    | 64   | `SHA256_INPUT`, SHA-256 user input staging (one block)            |
| 448    | 4    | `SHA256_PARTIAL`, u32 partial block length                        |
| 452    | 8    | `SHA256_TOTAL`, u64 total bytes hashed                            |
| 460    | 64   | `HMAC256_IPAD`, HMAC-SHA256 K' XOR ipad                           |
| 524    | 64   | `HMAC256_OPAD`, HMAC-SHA256 K' XOR opad                           |
| 588    | 32   | `HMAC256_INNER`, HMAC-SHA256 inner hash                           |
| 620    | 64   | `SHA512_H`, SHA-512 hash state H0..H7 (8 × u64)                   |
| 684    | 128  | `SHA512_BLOCK`, SHA-512 block accumulator                         |
| 812    | 640  | `SHA512_W`, SHA-512 message schedule W[0..79] (80 × u64)          |
| 1452   | 64   | `SHA512_OUT`, SHA-512 digest output (SHA-384 uses first 48 bytes) |
| 1516   | 128  | `SHA512_INPUT`, SHA-512 user input staging (one block)            |
| 1644   | 4    | `SHA512_PARTIAL`, u32 partial block length                        |
| 1648   | 8    | `SHA512_TOTAL`, u64 total bytes hashed                            |
| 1656   | 128  | `HMAC512_IPAD`, HMAC-SHA512 K' XOR ipad (128-byte block size)     |
| 1784   | 128  | `HMAC512_OPAD`, HMAC-SHA512 K' XOR opad                           |
| 1912   | 64   | `HMAC512_INNER`, HMAC-SHA512 inner hash                           |
| 1976   | -    | END                                                                |

`wipeBuffers()` zeroes all 20 buffer regions (SHA-256 state/block/W/out/input/partial/total, HMAC-256 ipad/opad/inner, SHA-512 state/block/W/out/input/partial/total, HMAC-512 ipad/opad/inner).

### SHA-3 module (3 pages, 192 KB)

Source: `src/asm/sha3/buffers.ts`

| Offset | Size | Name                                                                        |
| ------ | ---- | --------------------------------------------------------------------------- |
| 0      | 200  | `KECCAK_STATE`: 25 × u64 Keccak-f[1600] lane matrix (5×5, row-major x+5y)   |
| 200    | 4    | `KECCAK_RATE`: u32 rate in bytes (variant-specific: 72-168)                 |
| 204    | 4    | `KECCAK_ABSORBED`: u32 bytes absorbed into current block                    |
| 208    | 1    | `KECCAK_DSBYTE`: u8 domain separation byte (0x06 for SHA-3, 0x1f for SHAKE) |
| 209    | 168  | `KECCAK_INPUT`: input staging buffer (max rate = SHAKE128 at 168 bytes)     |
| 377    | 168  | `KECCAK_OUT`: output buffer (one SHAKE128 squeeze block)                    |
| 545    | -    | END                                                                         |

`wipeBuffers()` zeroes all 6 buffer regions (state, rate, absorbed, dsbyte, input, output).

### Kyber module (3 pages, 192 KB)

Source: `src/asm/kyber/`

| Region           | Offset | Size  | Purpose                                                 |
| ---------------- | ------ | ----- | ------------------------------------------------------- |
| AS data segment  | 0      | 4096  | Zetas table (128 × i16, bit-reversed Montgomery domain) |
| Poly slots       | 4096   | 5120  | 10 × 512B scratch polynomials (256 × i16 each)          |
| Polyvec slots    | 9216   | 16384 | 8 × 2048B scratch polyvecs (k=4 max: 4 × 512B)          |
| SEED buffer      | 25600  | 32    | Seed ρ/σ                                                |
| MSG buffer       | 25632  | 32    | Message / shared secret                                 |
| PK buffer        | 25664  | 1568  | Encapsulation key (max k=4)                             |
| SK buffer        | 27232  | 1536  | IND-CPA secret key (max k=4)                            |
| CT buffer        | 28768  | 1568  | Ciphertext (max k=4)                                    |
| CT_PRIME buffer  | 30336  | 1568  | Decaps re-encrypt comparison (max k=4)                  |
| XOF/PRF buffer   | 31904  | 1024  | SHAKE squeeze output for rej_uniform / CBD              |
| Poly accumulator | 32928  | 512   | Internal scratch for polyvec_basemul_acc                |

Total mutable: 29344 bytes (4096-33440). End = 33440 < 192 KB.

`wipeBuffers()` zeroes all mutable regions (poly slots, polyvec slots, SEED, MSG, PK, SK, CT, CT_PRIME, XOF/PRF, accumulator). The zetas data segment is read-only and is not wiped.

### ML-DSA module (4 pages, 256 KB)

Source: `src/asm/mldsa/buffers.ts`

ML-DSA uses i32 coefficients (FIPS 204 §2.3: q = 8380417 ≈ 2²³ does not fit i16). Polynomial size: 256 × 4 = 1024 bytes. Polyvec size at ML-DSA-87 (max k = ℓ = 8): 8 × 1024 = 8192 bytes. Mutable regions start at 4096; the AS data segment occupies 0..4095 with the zetas StaticArray<i32> (256 × 4 = 1024 bytes used, well within the 4096-byte reserved region).

| Region           | Offset | Size  | Purpose                                                                                                                  |
| ---------------- | ------ | ----- | ------------------------------------------------------------------------------------------------------------------------ |
| AS data segment  | 0      | 4096  | Zetas table (256 × i32, read-only)                                                                                       |
| `POLY_SLOTS`     | 4096   | 8192  | `POLY_SLOT_0..7`, 8 × 1024B scratch polynomials                                                                         |
| `MATRIX_SLOT`    | 12288  | 65536 | Matrix Â region, row-major; sized for ML-DSA-87 (k × ℓ = 8 × 7, rounded to 8 × 8 = 64 polys × 1024 for clean addressing) |
| `POLYVEC_SLOTS`  | 77824  | 65536 | `POLYVEC_SLOT_0..7`, 8 × 8192B scratch polyvecs (k = 8 max)                                                             |
| `SEED_OFFSET`    | 143360 | 128   | `H(ξ ‖ k ‖ ℓ, 128)` lands here: ρ(32) ‖ ρ′(64) ‖ K(32)                                                                   |
| `TR_OFFSET`      | 143488 | 64    | tr = H(pk, 64), public-key digest cached in sk for signing                                                               |
| `MSG_REP_OFFSET` | 143552 | 64    | μ, message representative (FIPS 204 §6.2 / Appendix D.1)                                                                |
| `C_TILDE_OFFSET` | 143616 | 64    | c̃, signature commitment hash (≤ λ/4 max = 64 for λ=256)                                                                |
| _(reserved)_     | 143680 | 64    | alignment / reserved                                                                                                     |
| `PK_OFFSET`      | 143744 | 2624  | Public key (≥ 2592 for ML-DSA-87)                                                                                        |
| `SK_OFFSET`      | 146368 | 4928  | Signing key (≥ 4896 for ML-DSA-87)                                                                                       |
| `SIG_OFFSET`     | 151296 | 4736  | Signature (≥ 4627 for ML-DSA-87)                                                                                         |
| `XOF_PRF_OFFSET` | 156032 | 8192  | SHAKE squeeze landing zone for ExpandA/ExpandS/ExpandMask/SampleInBall                                                   |
| _(reserved)_     | 164224 | 97920 | free for future expansion                                                                                                |

Mutable total: 160128 bytes from offset 4096. `MATRIX_SLOT_SIZE` is rounded up so row stride (ℓ × 1024) supplied by the orchestration layer addresses cleanly under the worst-case ℓ. `wipeBuffers()` zeroes every mutable region above. The zetas data segment is read-only and is not wiped.

---

## Test Suite

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/testing.svg" alt="Test Suite data flow diagram" width="800">

### Structure

For the full testing methodology and vector corpus, see: [test-suite.md](./test-suite.md).

### Gate discipline

**Each primitive family has a gate test:** the simplest authoritative vector for that primitive. The gate must pass before any other tests in that family are written or run. Gate tests are annotated with a `// GATE` comment.

### `init()` contracts

The public `init()` API is gated by [`init.test.ts` and the `init/` test suite](./test-suite.md#unit-tests-vitest), which validate each `WasmSource` type, idempotency, partial-init isolation, alias resolution, pre-init-error contracts, and the internal API surface stripped from `dist/`.

### Independent Rust verifier

The [`scripts/verify-vectors/`](./vector_audit.md) Rust crate is a third verification layer alongside the leviathan TypeScript reference and external tools (OpenSSL, Python hashlib, Node.js crypto). It re-derives every Tier 2 KAT byte from RustCrypto primitives that share zero code with the leviathan-crypto WASM stack, with pinned dependency versions and a pinned Rust toolchain. See [vector_audit.md](./vector_audit.md) for the full tier classification, [what the verifier proves](./vector_audit.md#what-the-verifier-proves), and the [CI integration](./vector_audit.md#ci-integration) covering the workflow DAG, cipher-target inventory, and runtime profile.

---

## Correctness Contract

leviathan-crypto must produce byte-identical output to the authoritative specification for every known test vector. Three independent verification layers cross-check every Tier 2 KAT: the leviathan TypeScript reference (a parallel codebase to the WASM stack), external tools (OpenSSL, Python hashlib, Node.js crypto) for primitives where parallel implementations exist, and the [`scripts/verify-vectors/`](./vector_audit.md) Rust crate, which re-derives every Tier 2 KAT byte from RustCrypto primitives sharing zero code with the WASM stack.

The vector corpus in `test/vectors/` acts as a source of immutable known-answer-test truth. KAT files are reference data from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP, NESSIE) or self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates corpus integrity against `SHA256SUMS` on every run. See [test-suite.md](./test-suite.md) for the full corpus inventory, provenance, and gate discipline. See [vector_audit.md](./vector_audit.md) for the tier classification and verifier coverage.

---

## Cryptanalytic margin

Implementation correctness is one axis; algorithmic strength is another. Each of the three ciphers carries a published cryptanalytic margin against the best known attack on the full construction.

**Serpent-256 is verified at 32 rounds with a wide margin.** The cipher placed second to Rijndael in the AES competition, rated higher on security margin and timing side-channel resistance but lower on 2001-era performance; that gap no longer matters on modern hardware. The best mathematical attack on the full cipher is biclique cryptanalysis at 2²⁵⁵·²¹ time with 2⁸⁸ chosen ciphertexts, less than one bit faster than exhaustive key search. Independent research against this implementation improved the published result by −0.20 bits, confirming no structural weakness beyond what the literature describes ([BicliqueFinder](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)). Reduced-round attacks reach 12 rounds (multidimensional linear), leaving a 20-round security margin, wider than AES-256's. No practical attack on full Serpent-256 is known.

**ChaCha20-Poly1305 has a 13-round margin.** The AEAD is IETF-standardized (RFC 8439) and descends from Salsa20 in the eSTREAM portfolio; it outperforms AES in software on platforms without hardware acceleration. The best published distinguisher reaches 7 of 20 rounds (Shi et al. 2012, differential-linear) and requires infeasible data; nothing further is published. Poly1305 forgery is bounded at ⌈l/16⌉/2¹⁰⁶ per message. XChaCha20's 192-bit nonce shifts the 50% collision boundary to 2⁹⁶ messages, beyond any realistic deployment. ChaCha20 is deployed at scale across TLS 1.3, WireGuard, Signal, and Android full-disk encryption with no known practical weaknesses in the full-round construction.

**AES-256-GCM-SIV has the narrowest published margin of the three** *but remains intact in practice.* The best mathematical attack on the full cipher is biclique cryptanalysis (Bogdanov, Khovratovich, & Rechberger 2011) at 2²⁵⁴·⁴ time with 2⁴⁰ chosen plaintexts, roughly 0.6 bits below exhaustive key search; differential and linear distinguishers bounded by the AES wide-trail strategy do not approach the full 14 rounds. The 2009 Biryukov-Khovratovich related-key boomerang reaches full AES-256 in 2⁹⁹·⁵ time but assumes attacker-chosen key relationships that AEAD use under independent KDF outputs does not provide. GCM-SIV adds nonce-misuse resistance over AES-GCM (RFC 8452, Gueron & Lindell 2015), so under nonce reuse an attacker learns only whether two encryptions shared identical inputs, with no key recovery and no universal forgery. AES is deployed at scale across TLS, IPsec, SSH, and FIPS-validated systems with no known practical weaknesses.

---

## Constant-time at the algorithm level

Three layers compose the library's constant-time posture: primitive algorithm choice, a single TypeScript routing point for secret-data equality, and a small set of named WASM-internal exceptions with published rationale.

### Algorithm choice

**Every primitive is constant-time at the algorithm level.** The same code in C, Rust, or hand-typed assembly would have the same property. WebAssembly does not buy that; the implementation does. Serpent and AES use bitsliced Boolean-circuit S-boxes with no table lookups. ChaCha20's ARX construction (add, rotate, XOR) is branchless by construction. SHA-2 and SHA-3 round functions are pure arithmetic and pure bitwise permutation respectively. ML-KEM extends the same principle to post-quantum: the Fujisaki-Okamoto re-encryption uses dedicated `ct_verify` and `ct_cmov` primitives implemented in the Kyber WASM module that never pass through JavaScript.

### TS-layer routing

**Every secret-data equality check in TypeScript routes through `constantTimeEqual`** from `src/ts/utils.ts`. That function is a thin wrapper over a dedicated SIMD WASM module (`src/asm/ct/`) that does branch-free v128 XOR-accumulate. There is no JavaScript fallback, runtimes without SIMD support throw at init. The routing rule is library-wide: AEAD tag verification (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305), HMAC verification (Serpent's Encrypt-then-MAC), seal-layer key commitment, ML-DSA's c̃ comparison, and ML-KEM's public-key hash check all use the central path. The policy is enforced by comments at every call site (e.g. "no tag compare lives inside the AES module itself, this is library-wide policy for atomic AEADs") so the rule stays visible at the point of enforcement.

### Documented exceptions

Three primitives branch on secret-derived intermediate values. Each is documented at the source with rationale tied to a published spec section.

**GHASH / POLYVAL 4-bit-windowed multiply.** `src/asm/aes/gf128.ts`. The AES-GCM and AES-GCM-SIV authentication backends use a 256-byte 4-bit-windowed multiplication table indexed by secret-derived state. This is the same posture as BoringSSL, OpenSSL, and RustCrypto on hardware without PCLMULQDQ. WebAssembly does not currently expose carry-less multiply, so a fully table-free GHASH or POLYVAL is not implementable in this environment without unacceptable throughput cost. The library documents the leak surface, mitigates it with per-message authentication keys (the POLYVAL key in AES-GCM-SIV derives per nonce from the master, not fixed across the session), and recommends the AEAD `seal` family over the lower-level `AESGCM` primitive.

**ML-DSA `decompose` special-case branch.** `src/asm/mldsa/rounding.ts`. FIPS 204 Algorithm 36 line 3 takes a special-case branch when `a − r0 = q − 1`. The leak is the same statistical signal an attacker already gets from the SHAKE-driven rejection-restart loop in Algorithm 7 signing, each restart changes the SHAKE output and the iteration count is observable through coarser timing channels regardless. Documented per FIPS 204 §3.6.3.

**ML-DSA `poly_chknorm` early-exit.** `src/asm/mldsa/poly.ts`. The norm check (`‖z‖∞ < γ1 − β`, etc., per FIPS 204 §2.3) early-exits on the first coefficient that violates the bound. The leaked iteration count is the same signal already exposed by the rejection-restart pattern in signing, total signing time is observable regardless. Documented per FIPS 204 §2.3 and §3.6.3.

Neither ML-DSA exception is key-revealing. Both reveal statistical patterns the attacker already gets through coarser timing channels intrinsic to the rejection-sampling design.

---

## Implementation discipline

**Every primitive derives independently from its authoritative specification.** FIPS 180-4, FIPS 197, FIPS 202, FIPS 203, RFC 8439, RFC 8452, RFC 2104, RFC 5869, and the original Serpent paper. None is ported from an existing implementation. Published known-answer-test vectors (NIST CAVP, NESSIE, RFC appendices, and ACVP) are immutable. When an implementation produces wrong output, the implementation gets fixed and the vectors stay. New tests do not extend the surface until the existing surface gates green.

**Every primitive family has a gate test.** The gate is the simplest authoritative vector for that primitive, annotated `// GATE` and required to pass before any other test in the family runs. KAT files in `test/vectors/` come from spec authors directly (FIPS, RFC, ACVP, NIST CAVP, NESSIE), or `scripts/gen-*-vectors.ts` generates them as regression vectors. CI validates corpus integrity against SHA256SUMS on every run. Cross-implementation verification works in layers: the `verify-vectors` Rust crate re-runs every KAT against a parallel Rust implementation, leviathan's TypeScript reference provides a second independent codebase, and external tools (OpenSSL, Python hashlib, Node.js crypto) cross-check primitives where parallel implementations exist.

**Memory hygiene.** Every public cryptographic operation wipes its secret-derived scratch on the way out, including failure paths. AEAD authentication failures wipe before the exception propagates. Stateless AEADs are strict single-use; any throw from `encrypt()` terminates the instance. Stateful classes hold an exclusivity token on their backing WASM module. Cross-module operations assert non-ownership of the modules they touch. The high-level API surfaces (`Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, and `KyberSuite`) are authenticated by default with internally-managed nonces. The unauthenticated raw modes ship for power users and are not the recommended entry point.

**All streaming constructions satisfy the _Cryptographic Doom Principle_.** The MAC compare is the unconditional gate into the decrypt path. Serpent and XChaCha20 use verify-then-decrypt. The implementation checks the tag before materializing any plaintext. AES-GCM-SIV uses verify-then-release. The tag is a function of the plaintext, so the SIV construction reconstructs the plaintext in WASM linear memory, then recomputes and compares the tag in constant time. On mismatch, the implementation wipes the WASM-side plaintext before the throw, and only slices the plaintext across the WASM-to-JavaScript boundary after the auth check. In either path, forged ciphertext never reaches the caller as plaintext.

**The seal layer is key-committing across all three suites.** Serpent gets it natively from HMAC-SHA-256. XChaCha20 and AES-GCM-SIV add an explicit 32-byte commitment derived from the master key via HKDF-SHA-256 alongside the encryption key. The library verifies the commitment in constant time before processing any chunk. A wrong key fails fast, ahead of any call to Poly1305 or POLYVAL. The HKDF info string incorporates the full 20-byte header, so tampering with the format enum, framing flag, nonce, or chunk size produces different keys and fails on the first chunk. This closes the Invisible Salamanders attack surface for any higher-level construction built on the seal primitive.

### Agentic development contracts

**All AI-assisted development on this repository operates under a strict agentic contract** defined in [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md). Configs for Claude, GitHub Copilot, OpenHands, Kilo Code, Cursor, Windsurf, and Aider all route to that file as the single source of authority. The contract enforces spec authority over planning documents, immutable test vectors, gate discipline before any test-suite extension, independent algorithm derivation from published standards, and constant-time and wipe requirements for all security-sensitive code paths. The contract explicitly prohibits agents from guessing cryptographic values or resolving spec ambiguities silently.

**Consumer agent guidance.** A `CLAUDE_consumer.md` file ships alongside the library, compressing the API surface, design restrictions, and recommended workflows into a map an AI assistant can use when a consumer asks for help writing or reviewing code that uses leviathan-crypto. It does for consumer-side AI work what `AGENTS.md` does for contributor-side AI work.

---

## WebAssembly is the deployment vehicle

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/layers.svg" alt="Typescript Over Wasm layered diagram" width="700">

The JavaScript runtime compiles WASM bytecode to native machine code through its WASM JIT. V8 uses Liftoff and TurboFan; SpiderMonkey uses Baseline and Cranelift; JavaScriptCore uses BBQ and OMG. *There is no ahead-of-time path in mainstream engines today.*

**What makes the compiled output more predictable than equivalent JavaScript is not the absence of a JIT but the structure of the input.** Typed bytecode has no hidden-class transitions and no SMI/HeapNumber switching. Structured control flow has no computed gotos and no `eval`. There is no polymorphism-driven specialization, no deoptimization, no GC pauses, no string interning, and no shape changes mid-execution. The JS-level timing oracles that motivate constant-time-coding discipline (type guards, deopts, hidden classes, and intern pools) do not exist for WASM. WASM exposes the cipher to the same constant-time-coding discipline that native crypto follows.

**WASM linear memory is a buffer the library owns and wipes at operation boundaries.** JavaScript heap allocations leak copies into intern pools, nursery fragments, and old-space; WASM does not. Each cryptographic module compiles to its own isolated binary with its own linear memory. Code in the SHA-3 module cannot address key material in the Serpent module, even in principle. The only host-side bridge is the TypeScript orchestration layer, which sees inputs and outputs but never raw secret state.

---

## Threat model

The architecture above commits to a specific threat model. Three adversary classes act at different layers, a shared set of trust assumptions underlies all three, and a framing constraint bounds the whole.

**Runtime adversary.** This adversary has full chosen-ciphertext capability at the API surface, runs concurrent JavaScript in the same browser context, and reads WASM linear memory at any operation boundary. The library commits to AEAD confidentiality and integrity under correctly-generated keys, key commitment across all three suites, nonce-misuse resistance for AES-GCM-SIV, per-operation key wipes on success and failure paths, module-isolated linear memory, and forward-secret plus post-compromise primitives for session protocols built on the ratchet. The [defended attacks](#defended-attacks) inventory enumerates the specific threats. CPU-level side channels (Spectre-class, cache-timing on secret-dependent loads, branch prediction, speculative execution), JavaScript heap inspectors (intern pools, eval injection, prototype pollution), and physical access (DPA, EM analysis, fault injection) stay out of scope; [where defense ends](#where-defense-ends) covers the disclaim in detail.

**Construction adversary.** Spec drift enters through contributor mistakes, ported-from-another-implementation errors, or AI-assisted guesses and unstated assumptions. Defenses include independent derivation from authoritative spec, immutable KAT vectors with SHA256SUMS integrity validated in CI, gate discipline before any test-suite extension, cross-implementation verification across the `verify-vectors` Rust crate plus the TypeScript reference plus external tools, and the [agentic development contracts](#agentic-development-contracts) for AI-assisted work.

**Distribution adversary.** Typosquat variants of `leviathan-crypto` on npm could otherwise install attacker-controlled code under a believable name. Decoy packages claim common variants preemptively, ahead of any observed attack; the [defended attacks](#defended-attacks) section describes the mechanism. Compromise of the npm registry itself, and any supply-chain compromise downstream of the registry, stay out of scope.

**Trust assumptions.** Across all three axes the model assumes a faithful WebAssembly runtime, a working CSPRNG, the browser's same-origin and sandbox boundaries, and npm publishing pipeline integrity. Keys must be properly generated; Argon2id, if used, must be consumer-installed. Consumer code must use the API as documented, with the published [wiki](https://github.com/xero/leviathan-crypto/wiki) and supporting documentation.

**Framing constraint.** The whole model lives inside a JavaScript runtime. Side-channel resistance comparable to a native binary with hand-tuned instruction scheduling is not promised; the [honest comparison](#the-honest-comparison) section is explicit about this trade-off.

---

## Defended attacks

The architectural defenses compose into protection against specific named attacks and DoS classes. The inventory below pairs each threat with its mechanism, split between runtime adversaries operating against a deployed instance and distribution adversaries operating on the npm namespace.

### Runtime

**Invisible Salamanders.** AEADs without key commitment allow ciphertexts to authenticate under multiple keys, enabling multi-recipient envelope forgery and similar attacks. The seal layer commits to the key across all three suites, via HMAC-SHA-256 for Serpent and a 32-byte HKDF commitment for XChaCha20 and AES-GCM-SIV.

**Raccoon.** TLS-DH(E)'s leading-zero-trim timing leak exploited a big-integer shared secret encoding. ML-KEM derives its 32-byte shared secret directly from a SHA-3 output, eliminating the structural analog.

**HintBitUnpack malformed-input forgery.** The FIPS 204 IPD draft was vulnerable to a SUF-CMA forgery via crafted hint encodings: an attacker could produce two distinct signature byte strings that both verified under the same `(vk, M, ctx)`. FIPS 204 §D.3 added three malformed-input checks to Algorithm 21 (lines 4, 9, 17). HintBitUnpack returns -1 from WASM on any failure, and `verify` short-circuits to false before any further decoding.

**Cross-protocol signature confusion.** A signature produced under pure ML-DSA could otherwise be replayed against a HashML-DSA verifier on the same key, or vice versa, enabling cross-protocol forgery. FIPS 204 §3.6.4 prefixes M' with 0x00 for pure mode and 0x01 plus the per-function OID DER bytes for HashML-DSA. A `signHash` signature will not verify under `verify` on the same key, regardless of message or context.

**Fault attacks on deterministic signing.** A computational fault during deterministic signature generation can leak partial signing-key state to an attacker who can repeatedly trigger the fault and observe outputs. Hedged signing per FIPS 204 §3.4 mixes 32 fresh RBG bytes into ρ'' on every call, so two signatures over identical inputs differ. The hedged path is the recommended default; `signDeterministic` and `signDerand` ship with the §3.4 caveat documented at the call site.

**Sign-loop denial of service.** Without a bound, ML-DSA's rejection-sampling loop could hang the signing thread on inputs that fail every iteration. The implementation bounds the loop at 1000 iterations (FIPS 204 Appendix C minimum: 814) and throws a deterministic error on exceedance after wiping all scratch via `try/finally`. ρ'' = H(K ‖ rnd ‖ μ) requires K, so an attacker without the signing key cannot bias the iteration count.

**AES-GCM nonce-reuse universal forgery.** Reusing a nonce under AES-GCM exposes the GHASH authentication subkey, enabling tag forgery for every past and future message under the affected key. AES-GCM-SIV derives the POLYVAL authentication key per nonce from the master (RFC 8452 §4), so even a recovered per-message key reveals nothing about other messages.

**T-table cache-timing key recovery.** Software AES with T-table or S-box lookups indexes memory at every round on plaintext XOR key, letting an attacker who shares cache with the encrypt operation recover the key. The bitsliced kernel has no AES tables in linear memory and no key-dependent memory accesses inside SubBytes, ShiftRows, MixColumns, or AddRoundKey.

**Delete-on-retrieval DoS.** Garbage ciphertext at a valid skipped-key counter can consume the legitimate message's cached key. `SkippedKeyStore` returns cached keys through a transactional handle that commits on auth success and rolls back on failure.

**Counter-flood DoS.** A malicious header with a very high counter can force unbounded HKDF derivations on the receiver. `SkippedKeyStore` bounds both memory and per-message HKDF work.

**Backward-seek nonce reuse.** Reusing a consumed counter nonce against new ciphertext exposes plaintext to XOR cancellation. `OpenStream.seek` only moves forward; backward seeks throw rather than reuse the nonce.

**Header tampering.** Tampering with format enum, framing flag, nonce, or chunk size could pass undetected at the format layer. The HKDF info string incorporates the full 20-byte header, so any tampered byte produces different keys and fails the AEAD on the first chunk.

**Cross-stream substitution, reorder, splice, truncation.** These stream-level attacks mix ciphertext between streams or rearrange chunks within a stream. Counter nonces with TAG_DATA/TAG_FINAL final-flag domain separation make all four fail AEAD verification before decryption.

**Pool failure isolation.** A worker-level auth failure could leak partial results back to the caller. `SealStreamPool` kills the pool on the first failure: pending operations reject, workers zero their keys and terminate, and master copies zero synchronously.

**Verify-then-release plaintext leak.** AES-GCM-SIV's tag depends on the plaintext, so the construction must reconstruct plaintext before MAC verification. The implementation reconstructs in WASM linear memory, constant-time compares the tag, and wipes the WASM-side plaintext before any throw, so bytes never cross to JavaScript on auth failure.

### Distribution

**Typosquatting.** Misspellings or punctuation variants of `leviathan-crypto` on npm could otherwise install attacker-controlled code under a believable name. Decoy packages cover common typosquat variants (missing hyphens, character transpositions, and common misspellings); each declares the real `leviathan-crypto` as an optional peer dependency and runs a post-install script that loudly warns the user with the correct package name and install command.

---

## Where defense ends

**WebAssembly is not constant time at the CPU level.** The native code the WASM JIT emits runs on a real CPU with a real branch predictor, real cache hierarchy, and real speculative execution. WebAssembly itself has no language-level constant-time guarantee in its specification; the spec defines semantics, not timing. *WASM does not protect against Spectre-class side channels.*

**The browser sandbox restricts JavaScript-side measurement primitives that an in-page attacker would otherwise use to instrument these channels.** SharedArrayBuffer requires COOP/COEP headers; `performance.now()` is throttled; the cross-origin attacker has limited reach. The channels themselves remain. They are the runtime's and the hardware's responsibility.

**Cycle-equivalent timing across hardware is out of scope.** Different CPUs have different multiply latencies, cache geometries, and speculation behaviors. WASM does not equalize them. Defense against power analysis, electromagnetic emissions, fault injection, or physical device access is not in this library's threat model.

**The defended threat is concrete.** An adversary with read access to WASM linear memory between operations cannot recover key material from previously-completed operations. Authentication failures cannot disclose plaintext to JavaScript callers. Tampered headers, reordered chunks, spliced streams, and cross-stream substitutions fail authentication before decryption. Backward seeks on a decrypting stream throw rather than reuse a consumed counter nonce against new ciphertext. A wrong key under the seal API fails before the AEAD ever runs. Forged ciphertext never returns plaintext bytes to the caller.

**The undefended threats are equally concrete.** JavaScript-side memory disclosure from heap-snapshot exfiltration, eval injection, or prototype pollution is the runtime's responsibility. Host CPU side channels (cache timing on secret-dependent loads, branch prediction, and speculative execution) are the hardware's. Physical device access is the deployment's. Supply chain compromise downstream of the npm registry is the consumer's. None of these is what the library claims to address.

---

## The honest comparison

**leviathan-crypto is for cryptography that runs inside a JavaScript runtime.** Within that constraint, this library offers the strongest posture available: algorithm-level constant-time ciphers, per-operation wipe hygiene, module-isolated linear memory, and predictable JIT-lowered native code.

**But the constraints matter.** The JavaScript runtime is a weaker side-channel environment than a native binary with hand-tuned instruction scheduling, no matter the strength of the cryptographic algorithms used. Leviathan is for pure web deployments. If side-channel resistance is critical to your threat model and you're already shipping native code, a native crypto implementation is a better choice.

*Our cipher choices, implementation discipline, and deployment vehicle compose into leviathan-crypto, a library that ships disciplined cryptography to the browser. Each one alone is not the security claim. Together, they are.*

---

## Known Limitations

- **`SerpentCbc` is unauthenticated.** Use `Seal` with `SerpentCipher` for authenticated Serpent encryption, or pair `SerpentCbc` with `HMAC_SHA256` (Encrypt-then-MAC) if direct CBC access is required.
- **Single-threaded WASM per instance.** One WASM instance per binary per thread. `SealStreamPool` provides Worker-based parallelism for all three cipher families (Serpent, ChaCha20, AES); other primitives remain single-threaded.
- **Max input per WASM call.** CTR accepts at most 65536 bytes per call; CBC accepts at most 65552 bytes (65536 + 16 bytes PKCS7 maximum overhead). Wrappers handle splitting automatically for larger inputs.
- **WASM is not constant time at the CPU level.** Spectre-class side channels, cache-timing on secret-dependent loads, branch prediction, and speculative execution stay outside this library's threat model; they are the runtime's and the hardware's responsibility. See [Where defense ends](#where-defense-ends) for the full disclaim. The one documented constant-time exception inside the algorithm-level layer is the GHASH/POLYVAL 4-bit-windowed multiply table (256 bytes, indexed by secret-derived state) used by AES-GCM and AES-GCM-SIV; this matches the BoringSSL/OpenSSL/RustCrypto posture on hardware without PCLMULQDQ. The library mitigates the leak surface by deriving the POLYVAL authentication key per nonce in AES-GCM-SIV (RFC 8452 §4) and recommends the AEAD `seal` family over the lower-level `AESGCM` primitive.

---

## Cross-References

| Document                                          | Description                                                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [index](./README.md)                              | Project documentation index                                                                            |
| [architectural-stance](./architectural-stance.md) | Architectural posture: defended threats, layer composition, and the framing constraint                 |
| [development](./development.md)                   | Day-to-day developer workflow: build, test, lint commands and the iteration loop                       |
| [lexicon](./lexicon.md)                           | Glossary of cryptographic terms                                                                        |
| [test-suite](./test-suite.md)                     | Testing methodology, vector corpus, and gate discipline                                                |
| [vector_audit](./vector_audit.md)                 | Test-vector tier classification, verifier coverage, and provenance of pinned vectors                   |
| [init](./init.md)                                 | `init()` API, `WasmSource`, and idempotent behavior                                                    |
| [loader](./loader.md)                             | Internal WASM binary loading strategies                                                                |
| [wasm](./wasm.md)                                 | WebAssembly primer: modules, instances, memory, and the init gate                                      |
| [types](./types.md)                               | Public TypeScript interfaces and `CipherSuite`                                                         |
| [utils](./utils.md)                               | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`                                           |
| [authenticated encryption](./aead.md)             | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`: cipher-agnostic AEAD APIs over any `CipherSuite` |
| [ciphersuite](./ciphersuite.md)                   | `CipherSuite` interface, `SerpentCipher`, `XChaCha20Cipher`, `AESGCMSIVCipher`, `KyberSuite`           |
| [serpent](./serpent.md)                           | Serpent-256 TypeScript API, `SerpentCipher`                                                            |
| [chacha20](./chacha20.md)                         | ChaCha20/Poly1305 TypeScript API, `XChaCha20Cipher`                                                    |
| [aes](./aes.md)                                   | AES TypeScript API, `AESGCMSIVCipher`                                                                  |
| [sha2](./sha2.md)                                 | SHA-2 hashes, HMAC, and HKDF TypeScript API                                                            |
| [sha3](./sha3.md)                                 | SHA-3 hashes and SHAKE XOFs TypeScript API                                                             |
| [kyber](./kyber.md)                               | ML-KEM TypeScript API and `KyberSuite`                                                                 |
| [mldsa](./mldsa.md)                               | ML-DSA and HashML-DSA TypeScript API                                                                   |
| [ratchet](./ratchet.md)                           | SPQR ratchet KDF primitives                                                                            |
| [fortuna](./fortuna.md)                           | Fortuna CSPRNG with forward secrecy and entropy pooling                                                |
| [argon2id](./argon2id.md)                         | Argon2id password hashing and key derivation                                                           |
